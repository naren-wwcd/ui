"""SQLite access (aiosqlite): events, alerts, incidents, actions, audit log, simulated system state."""
import asyncio
import hashlib
import json
import time

import aiosqlite

from app import config

_db: aiosqlite.Connection | None = None
_audit_lock = asyncio.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, ts REAL NOT NULL, user TEXT, ip TEXT, country TEXT,
    host TEXT, action TEXT, bytes INTEGER DEFAULT 0, source TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, ts REAL NOT NULL, type TEXT, entity TEXT, user TEXT, ip TEXT, host TEXT,
    evidence_event_ids TEXT,   -- JSON list
    mitre_tactic TEXT, severity TEXT, detail TEXT,
    incident_id TEXT,          -- set once correlation attaches it to an incident
    mitre_technique_id TEXT,
    mitre_technique TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, created_ts REAL, updated_ts REAL, status TEXT, severity TEXT,
    entities TEXT,             -- JSON list
    alert_types TEXT,          -- JSON list
    timeline TEXT,             -- JSON list, ordered by time
    investigation TEXT,        -- JSON: the agent's result
    risk TEXT,                 -- JSON: {score, level, justification, final}
    feedback TEXT              -- JSON: latest analyst decision {label, note, ts}
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY, incident_id TEXT, type TEXT, target TEXT, reason TEXT,
    status TEXT,               -- pending_approval | approved | queued | executing | executed | verified | verification_failed | rejected
    mode TEXT,                 -- auto | approval
    mode_label TEXT,           -- AUTO_EXECUTE | REQUIRES_APPROVAL
    created_ts REAL, decided_ts REAL, decided_by TEXT, result TEXT,
    executor TEXT, claim_time REAL, finish_time REAL,
    verification_status TEXT, verification_detail TEXT, recommended_next_step TEXT,
    claim_id TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, event TEXT,
    action TEXT, incident_id TEXT, action_id TEXT, detail TEXT,
    prev_hash TEXT, hash TEXT
);

-- Analyst decisions on incidents (kept as history; users/ips let the agent find decisions about the same people/IPs).
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, incident_id TEXT, label TEXT, note TEXT,
    users TEXT,                -- JSON list
    ips TEXT                   -- JSON list
);
CREATE INDEX IF NOT EXISTS idx_feedback_ts ON feedback(ts);

-- (alert type, entity) pairs muted by a false_positive decision, until `until_ts`.
CREATE TABLE IF NOT EXISTS suppressions (
    alert_type TEXT, entity TEXT, until_ts REAL, incident_id TEXT, PRIMARY KEY (alert_type, entity)
);

-- Simulated environment state tables
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY, action_id TEXT, reason TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS revoked_sessions (
    user TEXT PRIMARY KEY, action_id TEXT, reason TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY, incident_id TEXT, title TEXT, action_id TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY, target TEXT, message TEXT, action_id TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS disabled_users (
    user TEXT PRIMARY KEY, action_id TEXT, reason TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS isolated_hosts (
    host TEXT PRIMARY KEY, action_id TEXT, reason TEXT, ts REAL
);

-- Simulated "systems" the playbooks change: blocked IPs, disabled users, isolated hosts, tickets...
CREATE TABLE IF NOT EXISTS system_state (
    kind TEXT, target TEXT, ts REAL, action_id TEXT, value TEXT, PRIMARY KEY (kind, target)
);
"""


async def init_db() -> None:
    global _db
    _db = await aiosqlite.connect(config.DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")  # reads don't block writes
    await _db.executescript(SCHEMA)
    # A database created by an earlier step may lack the newer incident columns.
    await _ensure_columns("incidents", {"investigation": "TEXT", "risk": "TEXT", "feedback": "TEXT"})
    await _ensure_columns("alerts", {
        "mitre_technique_id": "TEXT",
        "mitre_technique": "TEXT",
    })
    await _ensure_columns("audit_log", {
        "action": "TEXT",
        "prev_hash": "TEXT",
        "hash": "TEXT",
    })
    await _ensure_columns("actions", {
        "mode_label": "TEXT",
        "executor": "TEXT",
        "claim_time": "REAL",
        "finish_time": "REAL",
        "verification_status": "TEXT",
        "verification_detail": "TEXT",
        "recommended_next_step": "TEXT",
        "claim_id": "TEXT",
    })
    await _db.commit()


async def _ensure_columns(table: str, cols: dict) -> None:
    async with _db.execute(f"PRAGMA table_info({table})") as cur:
        have = {r["name"] for r in await cur.fetchall()}
    for name, typ in cols.items():
        if name not in have:
            await _db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")


async def close_db() -> None:
    if _db:
        await _db.close()


async def _query(sql: str, params=()) -> list[dict]:
    async with _db.execute(sql, tuple(params)) as cur:
        return [dict(r) for r in await cur.fetchall()]


def _stamp(rows: list[dict]) -> list[dict]:
    """Add a readable HH:MM:SS next to each numeric ts (helps the LLM)."""
    for r in rows:
        if "ts" in r:
            r["time"] = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
    return rows


# ---------------- events ----------------
async def insert_event(e: dict) -> bool:
    """Store one event. Returns True if a new row was added (False = duplicate id, ignored)."""
    cur = await _db.execute(
        "INSERT OR IGNORE INTO events (id, ts, user, ip, country, host, action, bytes, source) "
        "VALUES (:id, :ts, :user, :ip, :country, :host, :action, :bytes, :source)", e)
    await _db.commit()
    return cur.rowcount > 0


async def count_events() -> int:
    return (await _query("SELECT COUNT(*) AS n FROM events"))[0]["n"]


async def existing_event_ids(ids) -> set:
    """Which of these event IDs really exist? (Used to validate the agent's citations.)"""
    ids = list(set(ids))
    found: set = set()
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        rows = await _query(f"SELECT id FROM events WHERE id IN ({','.join('?' * len(chunk))})", chunk)
        found |= {r["id"] for r in rows}
    return found


async def user_history(user: str, hours: int = 24) -> dict:
    """Summary of one user's recent activity, for the agent's get_user_history tool."""
    since = time.time() - hours * 3600
    p = (user, since)
    cols = "id, ts, action, bytes, ip, country, host"
    return {
        "user": user, "window_hours": hours,
        "by_action": await _query("SELECT action, COUNT(*) AS n, ROUND(AVG(bytes)) AS avg_bytes FROM events "
                                  "WHERE user=? AND ts>=? GROUP BY action", p),
        "countries": await _query("SELECT country, COUNT(*) AS n FROM events WHERE user=? AND ts>=? "
                                  "GROUP BY country ORDER BY n DESC", p),
        "ips": await _query("SELECT ip, COUNT(*) AS n FROM events WHERE user=? AND ts>=? "
                            "GROUP BY ip ORDER BY n DESC LIMIT 15", p),
        "largest_events": _stamp(await _query(f"SELECT {cols} FROM events WHERE user=? AND ts>=? "
                                              "ORDER BY bytes DESC LIMIT 3", p)),
        "latest_events": _stamp(await _query(f"SELECT {cols} FROM events WHERE user=? AND ts>=? "
                                             "ORDER BY ts DESC LIMIT 10", p)),
    }


async def related_events(entity: str, minutes: int = 60, limit: int = 60) -> dict:
    """Events for an entity ('user:alice', 'ip:1.2.3.4', 'host:web-01', or a bare value) in the last N minutes."""
    since = time.time() - min(max(int(minutes), 1), 240) * 60
    kind, _, val = entity.partition(":")
    if kind in ("user", "ip", "host") and val:        # kind is whitelisted, so safe to put in SQL
        where, params = f"{kind}=?", (val,)
    else:
        where, params = "(user=? OR ip=? OR host=?)", (entity, entity, entity)
    rows = await _query(f"SELECT id, ts, user, ip, country, host, action, bytes, source FROM events "
                        f"WHERE {where} AND ts>=? ORDER BY ts DESC LIMIT ?", (*params, since, limit + 1))
    truncated = len(rows) > limit
    return {"entity": entity, "minutes": minutes, "truncated": truncated,
            "events": _stamp(rows[:limit][::-1])}     # oldest first


# ---------------- alerts ----------------
async def insert_alert(a: dict) -> None:
    await _db.execute(
        "INSERT OR IGNORE INTO alerts (id, ts, type, entity, user, ip, host, evidence_event_ids, "
        "mitre_tactic, severity, detail, incident_id, mitre_technique_id, mitre_technique) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (a["id"], a["ts"], a["type"], a["entity"], a["user"], a["ip"], a["host"],
         json.dumps(a["evidence_event_ids"]), a["mitre_tactic"], a["severity"], a["detail"], None,
         a.get("mitre_technique_id"), a.get("mitre_technique")))
    await _db.commit()


async def link_alerts(incident_id: str, alert_ids: list[str]) -> None:
    await _db.executemany("UPDATE alerts SET incident_id=? WHERE id=?",
                          [(incident_id, aid) for aid in alert_ids])
    await _db.commit()


async def recent_alerts(limit: int = 50) -> list[dict]:
    rows = await _query("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
    for r in rows:
        r["evidence_event_ids"] = json.loads(r["evidence_event_ids"] or "[]")
    return rows


async def alert_counts() -> dict:
    """Alert totals by type and severity (small table; used once at startup to seed the in-memory counters)."""
    return {"by_type": {r["type"]: r["n"] for r in await _query("SELECT type, COUNT(*) AS n FROM alerts GROUP BY type")},
            "by_severity": {r["severity"]: r["n"] for r in
                            await _query("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")}}


# ---------------- incidents ----------------
async def upsert_incident(inc: dict) -> None:
    """Insert a new incident or overwrite the existing row (never creates a duplicate)."""
    dump = lambda v: json.dumps(v) if v is not None else None  # noqa: E731
    await _db.execute(
        "INSERT OR REPLACE INTO incidents (id, created_ts, updated_ts, status, severity, entities, "
        "alert_types, timeline, investigation, risk, feedback) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (inc["id"], inc["created_ts"], inc["updated_ts"], inc["status"], inc["severity"],
         json.dumps(inc["entities"]), json.dumps(inc["alert_types"]), json.dumps(inc["timeline"]),
         dump(inc.get("investigation")), dump(inc.get("risk")), dump(inc.get("feedback"))))
    await _db.commit()


async def load_incidents() -> list[dict]:
    """Rebuild incident dicts from SQLite (called at startup so a restart loses nothing)."""
    out = []
    for r in await _query("SELECT * FROM incidents ORDER BY updated_ts"):
        timeline = json.loads(r["timeline"] or "[]")
        out.append({
            "id": r["id"], "created_ts": r["created_ts"], "updated_ts": r["updated_ts"],
            "status": r["status"], "severity": r["severity"],
            "entities": json.loads(r["entities"] or "[]"), "alert_types": json.loads(r["alert_types"] or "[]"),
            "alert_ids": [t["alert_id"] for t in timeline], "timeline": timeline,
            "investigation": json.loads(r["investigation"]) if r["investigation"] else None,
            "risk": json.loads(r["risk"]) if r["risk"] else None,
            "feedback": json.loads(r["feedback"]) if r["feedback"] else None,
        })
    return out


async def incident_observed(incident_id: str) -> dict:
    """Distinct users / IPs / hosts seen in the incident's alerts (in first-seen order)."""
    rows = await _query("SELECT user, ip, host FROM alerts WHERE incident_id=? ORDER BY ts", (incident_id,))
    out = {"users": [], "ips": [], "hosts": []}
    for r in rows:
        for key, col in (("users", "user"), ("ips", "ip"), ("hosts", "host")):
            if r[col] and r[col] not in out[key]:
                out[key].append(r[col])
    return out


async def worst_alert_host(incident_id: str) -> str | None:
    """Host of the incident's most severe alert (ties: the most recent one). Used by the fallback investigation."""
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    rows = [r for r in await _query("SELECT severity, host, ts FROM alerts WHERE incident_id=?", (incident_id,)) if r["host"]]
    return max(rows, key=lambda r: (rank.get(r["severity"], 0), r["ts"]))["host"] if rows else None


# ---------------- actions / audit / system state ----------------
ACTION_COLUMNS = [
    "id", "incident_id", "type", "target", "reason", "status", "mode", "mode_label",
    "created_ts", "decided_ts", "decided_by", "result", "executor", "claim_time",
    "finish_time", "verification_status", "verification_detail", "recommended_next_step", "claim_id"
]


async def insert_action(a: dict) -> None:
    cols = ACTION_COLUMNS
    placeholders = ",".join(f":{c}" for c in cols)
    col_str = ",".join(cols)
    d = {c: a.get(c) for c in cols}
    await _db.execute(f"INSERT INTO actions ({col_str}) VALUES ({placeholders})", d)
    await _db.commit()


async def get_action(action_id: str) -> dict | None:
    rows = await _query("SELECT * FROM actions WHERE id=?", (action_id,))
    return rows[0] if rows else None


async def get_oldest_queued_action() -> dict | None:
    rows = await _query("SELECT * FROM actions WHERE status='queued' ORDER BY created_ts ASC LIMIT 1")
    return rows[0] if rows else None


async def list_actions(status: str | None = None) -> list[dict]:
    if status:
        return await _query("SELECT * FROM actions WHERE status=? ORDER BY created_ts DESC", (status,))
    return await _query("SELECT * FROM actions ORDER BY created_ts DESC")


async def action_exists(incident_id: str, type_: str, target: str) -> bool:
    return bool(await _query("SELECT 1 FROM actions WHERE incident_id=? AND type=? AND target=?",
                             (incident_id, type_, target)))


async def update_action(action_id: str, **fields) -> None:
    allowed = set(ACTION_COLUMNS) | {"status", "decided_ts", "decided_by", "result"}
    assert set(fields) <= allowed, f"unexpected fields: {set(fields) - allowed}"
    sets = ", ".join(f"{k}=?" for k in fields)
    await _db.execute(f"UPDATE actions SET {sets} WHERE id=?", (*fields.values(), action_id))
    await _db.commit()


async def add_audit(actor: str, event: str, incident_id: str | None = None,
                    action_id: str | None = None, detail: str = "") -> None:
    """Write an entry to the tamper-evident hash-chained audit log.

    Each entry's hash = SHA-256 of (prev_hash + ts + actor + action + detail).
    """
    async with _audit_lock:
        now = time.time()
        last_rows = await _query(
            "SELECT hash FROM audit_log WHERE hash IS NOT NULL AND hash != '' ORDER BY id DESC LIMIT 1"
        )
        prev_hash = last_rows[0]["hash"] if last_rows and last_rows[0].get("hash") else ""
        action_val = event
        payload = f"{prev_hash}{now}{actor}{action_val}{detail}"
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        await _db.execute(
            "INSERT INTO audit_log (ts, actor, event, action, incident_id, action_id, detail, prev_hash, hash) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (now, actor, event, action_val, incident_id, action_id, detail, prev_hash, entry_hash),
        )
        await _db.commit()


async def verify_audit_chain() -> dict:
    """Verify integrity of the tamper-evident hash-chained audit log.

    Recomputes the hash chain and returns:
        {"valid": bool, "entries": int, "first_broken_id": int | None}

    Old rows without hashes start the chain.
    """
    rows = await _query("SELECT * FROM audit_log ORDER BY id ASC")
    expected_prev = ""
    chain_entries = 0
    for r in rows:
        stored_hash = r.get("hash")
        # Old rows without hashes start the chain
        if not stored_hash:
            continue
        chain_entries += 1
        stored_prev = r.get("prev_hash") or ""
        if stored_prev != expected_prev:
            return {"valid": False, "entries": chain_entries, "first_broken_id": r["id"]}

        action_val = r.get("action") or r.get("event") or ""
        payload = f"{stored_prev}{r['ts']}{r['actor']}{action_val}{r['detail']}"
        expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        if stored_hash != expected_hash:
            return {"valid": False, "entries": chain_entries, "first_broken_id": r["id"]}

        expected_prev = stored_hash

    return {"valid": True, "entries": chain_entries, "first_broken_id": None}


# ---------------- simulated environment tables ----------------
async def add_blocked_ip(ip: str, action_id: str = "", reason: str = "") -> None:
    await _db.execute("INSERT OR REPLACE INTO blocked_ips (ip, action_id, reason, ts) VALUES (?,?,?,?)",
                      (ip, action_id, reason, time.time()))
    await _db.commit()


async def is_ip_blocked(ip: str) -> bool:
    rows = await _query("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,))
    return len(rows) > 0


async def remove_blocked_ip(ip: str) -> None:
    await _db.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    await _db.commit()


async def add_revoked_session(user: str, action_id: str = "", reason: str = "") -> None:
    await _db.execute("INSERT OR REPLACE INTO revoked_sessions (user, action_id, reason, ts) VALUES (?,?,?,?)",
                      (user, action_id, reason, time.time()))
    await _db.commit()


async def is_session_revoked(user: str) -> bool:
    rows = await _query("SELECT 1 FROM revoked_sessions WHERE user=?", (user,))
    return len(rows) > 0


async def add_ticket(ticket_id: str, incident_id: str, title: str, action_id: str = "") -> None:
    await _db.execute("INSERT OR REPLACE INTO tickets (id, incident_id, title, action_id, ts) VALUES (?,?,?,?,?)",
                      (ticket_id, incident_id, title, action_id, time.time()))
    await _db.commit()


async def is_ticket_open(target: str, action_id: str = "") -> bool:
    rows = await _query("SELECT 1 FROM tickets WHERE incident_id=? OR id=? OR action_id=?", (target, target, action_id))
    return len(rows) > 0


async def add_notification(notif_id: str, target: str, message: str, action_id: str = "") -> None:
    await _db.execute("INSERT OR REPLACE INTO notifications (id, target, message, action_id, ts) VALUES (?,?,?,?,?)",
                      (notif_id, target, message, action_id, time.time()))
    await _db.commit()


async def is_notification_sent(target: str, action_id: str = "") -> bool:
    rows = await _query("SELECT 1 FROM notifications WHERE target=? OR action_id=? OR id=?", (target, action_id, target))
    return len(rows) > 0


async def add_disabled_user(user: str, action_id: str = "", reason: str = "") -> None:
    await _db.execute("INSERT OR REPLACE INTO disabled_users (user, action_id, reason, ts) VALUES (?,?,?,?)",
                      (user, action_id, reason, time.time()))
    await _db.commit()


async def is_user_disabled(user: str) -> bool:
    rows = await _query("SELECT 1 FROM disabled_users WHERE user=?", (user,))
    return len(rows) > 0


async def add_isolated_host(host: str, action_id: str = "", reason: str = "") -> None:
    await _db.execute("INSERT OR REPLACE INTO isolated_hosts (host, action_id, reason, ts) VALUES (?,?,?,?)",
                      (host, action_id, reason, time.time()))
    await _db.commit()


async def is_host_isolated(host: str) -> bool:
    rows = await _query("SELECT 1 FROM isolated_hosts WHERE host=?", (host,))
    return len(rows) > 0


async def list_audit(limit: int = 50) -> list[dict]:
    return _stamp(await _query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)))


async def set_state(kind: str, target: str, action_id: str, value: str = "") -> None:
    await _db.execute("INSERT OR REPLACE INTO system_state (kind, target, ts, action_id, value) VALUES (?,?,?,?,?)",
                      (kind, target, time.time(), action_id, value))
    await _db.commit()


async def recent_events(limit: int = 60) -> list[dict]:
    """Latest events, oldest first (used for the dashboard's initial snapshot)."""
    return (await _query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)))[::-1]


async def count_pending_actions() -> int:
    return (await _query("SELECT COUNT(*) AS n FROM actions WHERE status='pending_approval'"))[0]["n"]


# ---------------- analyst feedback ----------------
async def add_feedback(incident_id: str, label: str, note: str, users: list, ips: list) -> None:
    await _db.execute("INSERT INTO feedback (ts, incident_id, label, note, users, ips) VALUES (?,?,?,?,?,?)",
                      (time.time(), incident_id, label, note, json.dumps(users), json.dumps(ips)))
    await _db.commit()


async def recent_feedback(users: list, ips: list, limit: int = 3) -> list[dict]:
    """The latest analyst decisions about incidents that involved any of these users / IPs (newest first)."""
    users, ips = set(users), set(ips)
    out = []
    for r in await _query("SELECT * FROM feedback ORDER BY id DESC LIMIT 500"):
        if users & set(json.loads(r["users"] or "[]")) or ips & set(json.loads(r["ips"] or "[]")):
            out.append({"ts": r["ts"], "incident_id": r["incident_id"], "label": r["label"], "note": r["note"]})
            if len(out) >= limit:
                break
    return out


async def add_suppressions(pairs: list, until_ts: float, incident_id: str) -> None:
    await _db.executemany("INSERT OR REPLACE INTO suppressions (alert_type, entity, until_ts, incident_id) VALUES (?,?,?,?)",
                          [(t, e, until_ts, incident_id) for t, e in pairs])
    await _db.commit()


async def clear_suppressions(incident_id: str) -> None:
    await _db.execute("DELETE FROM suppressions WHERE incident_id=?", (incident_id,))
    await _db.commit()


async def load_suppressions() -> dict:
    """Active suppressions as {(alert_type, entity): (until_ts, incident_id)}; expired rows are deleted."""
    now = time.time()
    await _db.execute("DELETE FROM suppressions WHERE until_ts<=?", (now,))
    await _db.commit()
    return {(r["alert_type"], r["entity"]): (r["until_ts"], r["incident_id"])
            for r in await _query("SELECT * FROM suppressions")}
