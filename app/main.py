"""FastAPI app. Starts all background tasks on startup."""
import asyncio
import json
import time
from pathlib import Path
from collections import Counter, deque
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from app import agent, bus, config, correlation, db, detection, response, risk, rpa_interface, verification
from app.producers import attack_injector, cloudtrail_adapter, system_collector, traffic_gen
from app.producers.traffic_gen import USERS

recent_ts: deque = deque()  # arrival times of the last ~5s, for events/sec
_attack_tasks: set = set()  # keep references so running attacks aren't garbage-collected

# ---- in-memory counters for /stats (updated as events/alerts flow through; /stats never scans the events table) ----
_eps_buckets: dict[int, int] = {}                  # unix second -> events that arrived in that second
ip_counts: Counter = Counter()                     # source IP -> events seen since startup
country_counts: Counter = Counter()                # country -> events seen since startup
alert_by_type: Counter = Counter()
alert_by_sev: Counter = Counter()
totals = {"events": 0}                             # stored events (seeded from SQLite at startup)
# (alert type, entity) -> (until_ts, incident_id): muted by an analyst's false_positive decision
suppressed: dict[tuple, tuple] = {}
SEVERITIES = ("low", "medium", "high", "critical")


def normalize(raw: dict) -> dict:
    """Force every event into the one schema {id, ts, user, ip, country, host, action, bytes, source}."""
    return {
        "id": str(raw["id"]),
        "ts": float(raw.get("ts", time.time())),
        "user": raw.get("user"),
        "ip": raw.get("ip"),
        "country": raw.get("country"),
        "host": raw.get("host"),
        "action": raw.get("action", "unknown"),
        "bytes": int(raw.get("bytes", 0)),
        "source": raw.get("source", "unknown"),
    }


def _t(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


async def refresh_risk(inc: dict) -> None:
    """Recompute the deterministic risk score (preliminary until the agent has weighed in)."""
    observed = await db.incident_observed(inc["id"])
    inc["risk"] = risk.score(inc, inc.get("investigation"), observed["hosts"])
    r = inc["risk"]
    await db.add_audit("risk", "risk_scored", inc["id"], None,
                       f"score={r['score']}/100 level={r['level']} ({'final' if r.get('final') else 'preliminary'}): {r['justification']}")


async def after_investigation(inc: dict, result: dict) -> None:
    """Called by the agent when a run finishes: store result, final risk score, then propose actions."""
    inc["investigation"] = result
    await refresh_risk(inc)
    await db.upsert_incident(inc)
    bus.broadcast("incident", inc)
    await db.add_audit("agent", "investigation_completed", inc["id"], None,
                       f"verdict={result['verdict']} confidence={result['confidence']} source={result['source']} "
                       f"validation={result['validation']} tools={result['tool_calls']}")
    r = inc["risk"]
    print(f"[AGENT] {inc['id']} verdict={result['verdict'].upper()} confidence={result['confidence']} "
          f"source={result['source']} ({result['duration_s']}s, {result['tool_calls']} tool calls)")
    print(f"[RISK]  {inc['id']} {r['score']}/100 {r['level'].upper()} - {r['justification']}")
    if inc["status"] == "closed":                      # analyst marked it a false positive while the agent was running
        await db.add_audit("response", "no_actions", inc["id"], None, "incident closed by analyst feedback")
        return
    await response.propose_actions(inc, result)


def _suppression(alert: dict):
    """(until_ts, incident_id) if an analyst muted this (alert type, entity) and it hasn't expired, else None."""
    key = (alert["type"], alert["entity"])
    s = suppressed.get(key)
    if s and s[0] <= time.time():
        del suppressed[key]
        return None
    return s


async def handle_alert(alert: dict) -> None:
    """Alerts are handled inline (they never sit in the droppable queue, so they can't be dropped)."""
    sup = _suppression(alert)
    if sup:                                            # analyst said false positive: audit it, nothing else
        await db.add_audit("system", "alert_suppressed", sup[1], None,
                           f"{alert['type']} {alert['entity']} dropped (analyst false_positive on {sup[1]}, "
                           f"muted until {_t(sup[0])}): {alert['detail']}")
        print(f"[SUPPRESSED] {alert['type']} {alert['entity']} (false_positive on {sup[1]})")
        return
    await db.insert_alert(alert)
    alert_by_type[alert["type"]] += 1
    alert_by_sev[alert["severity"]] += 1
    bus.broadcast("alert", alert)
    await db.add_audit("detection", "alert_detected", alert.get("incident_id"), None,
                       f"{alert['type']} on {alert['entity']} ({alert['severity']}): {alert['detail']}")
    print(f"[ALERT] {_t(alert['ts'])} {alert['severity'].upper():<8} {alert['type']:<20} "
          f"{alert['entity']:<20} {alert['mitre_tactic']} | {alert['detail']}")
    result = correlation.process(alert)
    if result:
        action, inc, escalated = result
        await db.link_alerts(inc["id"], inc["alert_ids"])
        await refresh_risk(inc)
        await db.upsert_incident(inc)
        bus.broadcast("incident", inc)
        await db.add_audit("correlation", f"incident_{action}", inc["id"], None,
                           f"{action} incident {inc['id']} with {len(inc['alert_ids'])} alerts ({'+'.join(inc['alert_types'])}), severity={inc['severity']}")
        print(f"[INCIDENT {action.upper()}] {inc['id']} severity={inc['severity'].upper()} "
              f"risk={inc['risk']['score']} alerts={len(inc['alert_ids'])} types={'+'.join(inc['alert_types'])} "
              f"entities={','.join(inc['entities'])}")
        if escalated:                      # new or escalated incident -> investigate in the background
            agent.trigger(inc, after_investigation)


def _count_event(event: dict) -> None:
    """Update the per-second bucket and the top-IP / top-country counters (distinct keys are capped)."""
    sec = int(time.time())
    _eps_buckets[sec] = _eps_buckets.get(sec, 0) + 1
    for counter, key in ((ip_counts, event["ip"]), (country_counts, event["country"])):
        if key and (key in counter or len(counter) < config.STATS_MAX_KEYS):
            counter[key] += 1


async def ingest_loop() -> None:
    """Consume the queue -> normalize -> store -> print -> detect -> (alerts) correlate."""
    while True:
        raw = await bus.queue.get()
        try:
            event = normalize(raw)
            if await db.insert_event(event):
                totals["events"] += 1
            recent_ts.append(time.monotonic())
            _count_event(event)
            bus.broadcast("event", event)
            if config.PRINT_EVENTS:
                print(f"{_t(event['ts'])} {event['source']:<16} {event['user'] or '-':<6} {event['ip'] or '-':<15} "
                      f"{event['country'] or '--'} {event['host'] or '-':<8} {event['action']:<15} {event['bytes']}B")
            for alert in detection.detect(event):
                await handle_alert(alert)
        except Exception as exc:  # one bad event must never kill the pipeline
            print(f"[ingest error] {exc!r}")


def events_per_second() -> float:
    now = time.monotonic()
    while recent_ts and now - recent_ts[0] > 5:
        recent_ts.popleft()
    return round(len(recent_ts) / 5, 1)


async def stats_loop() -> None:
    """Print a one-line summary every 5 seconds so you can see throughput."""
    while True:
        await asyncio.sleep(5)
        print(f"--- eps={events_per_second()} queue={bus.queue.qsize()} dropped={bus.stats['dropped']} "
              f"stored={await db.count_events()} incidents={len(correlation.incidents)} ---")


def eps_series() -> list[int]:
    """Events per second for the last 60 COMPLETE seconds, oldest first (the in-progress second is left out)."""
    now = int(time.time())
    for k in [k for k in _eps_buckets if k < now - 120]:
        del _eps_buckets[k]
    return [_eps_buckets.get(sec, 0) for sec in range(now - 60, now)]


async def current_stats() -> dict:
    """Used by GET /stats, the WebSocket snapshot and the once-per-second 'stats' broadcast. The first six keys are
    the original ones (same shapes); everything after them is new. Nothing here scans the events table."""
    active = [i for i in correlation.incidents.values() if i["status"] != "closed"]
    return {"eps": events_per_second(), "queue": bus.queue.qsize(), "dropped": bus.stats["dropped"],
            "stored": totals["events"], "incidents": len(correlation.incidents), "clients": len(bus.clients),
            "eps_series": eps_series(),
            "alerts_total": sum(alert_by_type.values()),
            "alerts_by_type": dict(alert_by_type),
            "alerts_by_severity": {s: alert_by_sev.get(s, 0) for s in SEVERITIES},
            "active_incidents": len(active),                       # everything not closed as a false positive
            "incidents_by_severity": {s: sum(1 for i in active if i["severity"] == s) for s in SEVERITIES},
            "top_ips": [{"key": k, "count": n} for k, n in ip_counts.most_common(5)],
            "top_countries": [{"key": k, "count": n} for k, n in country_counts.most_common(5)],
            "pending_actions": await db.count_pending_actions(),
            "rpa_bot_online": rpa_interface.is_bot_online()}


async def stats_broadcast_loop() -> None:
    """Push throughput numbers to dashboards once per second."""
    while True:
        await asyncio.sleep(1)
        if bus.clients:
            bus.broadcast("stats", await current_stats())


async def snapshot() -> dict:
    """Everything a freshly connected dashboard needs to draw itself."""
    return {
        "incidents": sorted(correlation.incidents.values(), key=lambda i: i["updated_ts"], reverse=True),
        "actions": (await db.list_actions())[:100],
        "alerts": await db.recent_alerts(30),
        "events": await db.recent_events(60),
        "investigating": sorted(agent.investigating),
        "stats": await current_stats(),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    saved = await db.load_incidents()
    correlation.load(saved)
    print(f"loaded {len(saved)} incident(s) from SQLite")
    suppressed.clear(); alert_by_type.clear(); alert_by_sev.clear(); ip_counts.clear(); country_counts.clear()
    suppressed.update(await db.load_suppressions())
    counts = await db.alert_counts()
    alert_by_type.update(counts["by_type"]); alert_by_sev.update(counts["by_severity"])
    totals["events"] = await db.count_events()
    print(f"loaded {len(suppressed)} active alert suppression(s)")
    tasks = [asyncio.create_task(c) for c in (ingest_loop(), traffic_gen.run(), stats_loop(), stats_broadcast_loop(),
                                         system_collector.run())]
    yield
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await db.close_db()


app = FastAPI(title="Security Agent", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"eps": events_per_second(), "queue": bus.queue.qsize(), "dropped": bus.stats["dropped"],
            "stored": await db.count_events(), "incidents": len(correlation.incidents),
            "agent_investigating": sorted(agent.investigating)}


@app.get("/stats")
async def stats():
    """Dashboard numbers: events/sec for the last 60 s, alert / incident counts, top IPs and countries, pending actions."""
    return await current_stats()


@app.post("/simulate/attack")
async def simulate_attack(user: str | None = None):
    """Start a multi-stage attack in the background; normal traffic continues. Optional ?user=alice."""
    if user and user not in USERS:
        raise HTTPException(404, f"unknown user '{user}'. Known users: {list(USERS)}")
    plan = attack_injector.plan_attack(user)
    task = asyncio.create_task(attack_injector.run_attack(plan))
    _attack_tasks.add(task)
    task.add_done_callback(_attack_tasks.discard)
    return {"status": "started", **plan}


def _start_task(coro) -> None:
    """Run a scenario in the background; keep a reference so it isn't garbage-collected."""
    task = asyncio.create_task(coro)
    _attack_tasks.add(task)
    task.add_done_callback(_attack_tasks.discard)


@app.post("/simulate/spray")
async def simulate_spray():
    """Password spraying: one IP, one failed login each against 5 users, then one account falls."""
    plan = attack_injector.plan_spray()
    _start_task(attack_injector.run_spray(plan))
    return {"status": "started", **plan}


@app.post("/simulate/cloud-attack")
async def simulate_cloud_attack():
    """Replay data/sample_cloudtrail.json in real time: stolen key -> new access key -> admin policy -> logging
    stopped -> bulk S3 download, surrounded by normal CloudTrail noise."""
    records = cloudtrail_adapter.load_sample()
    events, stats = cloudtrail_adapter.to_events(records)
    _start_task(cloudtrail_adapter.replay(events))
    return {"status": "started", "source": "cloudtrail", **cloudtrail_adapter.sample_meta(records), **stats}


@app.post("/ingest/cloudtrail")
async def ingest_cloudtrail(request: Request, rebase: bool = False):
    """Ingest AWS CloudTrail records: a JSON list, or a CloudTrail file {"Records": [...]}.
    Events keep their eventTime; ?rebase=true shifts them so the newest is 'now' (for old sample files).
    Records already stored (same eventID) are skipped, so re-sending a file is safe."""
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "body must be JSON")
    records = body.get("Records") if isinstance(body, dict) else body
    if not isinstance(records, list):
        raise HTTPException(400, 'send a JSON list of CloudTrail records (or {"Records": [...]})')
    if len(records) > config.INGEST_MAX_RECORDS:
        raise HTTPException(413, f"too many records ({len(records)}); the limit is {config.INGEST_MAX_RECORDS}")
    events, stats = cloudtrail_adapter.to_events(records, rebase=rebase)
    known = await db.existing_event_ids([e["id"] for e in events])
    fresh = [e for e in events if e["id"] not in known]
    for e in fresh:
        await bus.publish(e, droppable=False)          # alerts depend on these, never shed them
    return {**stats, "duplicates_skipped": len(events) - len(fresh), "ingested": len(fresh), "rebased": rebase}


@app.get("/incidents")
async def list_incidents():
    """Current incidents (newest activity first)."""
    return sorted(correlation.incidents.values(), key=lambda i: i["updated_ts"], reverse=True)


class Feedback(BaseModel):
    label: Literal["false_positive", "confirmed"]
    note: str = Field("", max_length=500)


async def record_feedback(inc: dict, label: str, note: str) -> dict:
    """Store an analyst decision. false_positive closes the incident and mutes its (alert type, entity) pairs for
    FEEDBACK_SUPPRESS_S; confirmed marks it confirmed (and lifts mutes an earlier false_positive on it created)."""
    observed = await db.incident_observed(inc["id"])
    now = time.time()
    inc["feedback"] = {"label": label, "note": note, "ts": now}
    if label == "false_positive":
        inc["status"] = "closed"
        pairs = sorted({(t["type"], t["entity"]) for t in inc["timeline"]})
        until = now + config.FEEDBACK_SUPPRESS_S
        for p in pairs:
            suppressed[p] = (until, inc["id"])
        await db.add_suppressions(pairs, until, inc["id"])
        detail = f"false_positive: incident closed, {len(pairs)} (alert type, entity) pair(s) muted for {config.FEEDBACK_SUPPRESS_S}s"
    else:
        inc["status"] = "confirmed"
        for k in [k for k, v in suppressed.items() if v[1] == inc["id"]]:
            del suppressed[k]
        await db.clear_suppressions(inc["id"])
        detail = "confirmed: incident marked confirmed"
    await db.add_feedback(inc["id"], label, note, observed["users"], observed["ips"])
    await db.upsert_incident(inc)
    await db.add_audit("human", "incident_feedback", inc["id"], None, f"{detail}; note={note!r}")
    bus.broadcast("incident", inc)
    print(f"[FEEDBACK] {inc['id']} {label.upper()} status={inc['status']}")
    return inc


@app.post("/incidents/{incident_id}/feedback")
async def incident_feedback(incident_id: str, body: Feedback):
    """Analyst decision: {"label": "false_positive" | "confirmed", "note": "..."}. Unknown label -> 422, unknown incident -> 404."""
    inc = correlation.incidents.get(incident_id)
    if not inc:
        raise HTTPException(404, f"no such incident {incident_id}")
    return await record_feedback(inc, body.label, body.note.strip())


@app.get("/alerts")
async def list_alerts(limit: int = 50):
    """Most recent alerts (newest first), straight from SQLite."""
    return await db.recent_alerts(min(max(limit, 1), 500))


@app.get("/actions")
async def list_actions(status: str | None = None):
    """All response actions; use ?status=pending_approval for the approval queue."""
    return await db.list_actions(status)


@app.post("/actions/{action_id}/approve")
async def approve_action(action_id: str):
    try:
        return await response.approve(action_id)
    except LookupError:
        raise HTTPException(404, f"no such action {action_id}")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@app.post("/actions/{action_id}/reject")
async def reject_action(action_id: str):
    try:
        return await response.reject(action_id)
    except LookupError:
        raise HTTPException(404, f"no such action {action_id}")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@app.post("/actions/{action_id}/retry")
async def retry_action(action_id: str):
    """Re-queue an action after failure or verification failure (audited)."""
    try:
        return await response.retry(action_id)
    except LookupError:
        raise HTTPException(404, f"no such action {action_id}")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@app.get("/audit")
async def audit(limit: int = 50):
    """Audit log, newest first."""
    return await db.list_audit(min(max(limit, 1), 500))


@app.get("/audit/verify")
async def audit_verify():
    """Verify integrity of the tamper-evident hash-chained audit log."""
    return await db.verify_audit_chain()


# ---------------- RPA Queue API ----------------
def _verify_rpa_token(token: str | None) -> None:
    if not token or token != config.RPA_TOKEN:
        raise HTTPException(401, "invalid or missing X-RPA-Token")


@app.get("/rpa/queue/next")
async def rpa_queue_next(request: Request):
    """Claim the oldest queued action atomically."""
    _verify_rpa_token(request.headers.get("X-RPA-Token"))
    item = await rpa_interface.claim_next()
    if not item:
        return Response(status_code=204)
    return item


@app.post("/rpa/actions/{action_id}/claim")
async def rpa_action_claim(action_id: str, request: Request):
    """Claim a specific queued action atomically."""
    _verify_rpa_token(request.headers.get("X-RPA-Token"))
    try:
        return await rpa_interface.claim_action(action_id)
    except LookupError:
        raise HTTPException(404, f"no such action {action_id}")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


class RpaResultBody(BaseModel):
    claim_id: str
    status: Literal["done", "failed"]
    detail: str = ""


@app.post("/rpa/actions/{action_id}/result")
async def rpa_action_result(action_id: str, body: RpaResultBody, request: Request):
    """Submit execution result from external bot and run verification."""
    _verify_rpa_token(request.headers.get("X-RPA-Token"))
    try:
        return await rpa_interface.submit_result(action_id, body.claim_id, body.status, body.detail)
    except LookupError:
        raise HTTPException(404, f"no such action {action_id}")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


# ---------------- Simulated Admin Console ----------------
CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Simulated Admin Console | Sentinel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  body { font-family: 'Plus Jakarta Sans', system-ui, sans-serif; background: #080c16; color: #f8fafc; padding: 24px; max-width: 680px; margin: 0 auto; }
  h1 { font-size: 20px; font-weight: 800; border-bottom: 1px solid #1e2d48; padding-bottom: 8px; margin-top: 10px; color: #f8fafc; }
  .banner { background: #162238; border: 1px solid #6366f1; color: #6366f1; padding: 10px 14px; border-radius: 8px; font-weight: 700; font-size: 12px; text-align: center; letter-spacing: 0.05em; }
  .back-link { display: inline-flex; align-items: center; gap: 6px; color: #06b6d4; text-decoration: none; font-size: 12px; font-weight: 600; margin: 12px 0 6px; }
  .back-link:hover { text-decoration: underline; }
  .card { background: #0f172a; border: 1px solid #1e2d48; border-radius: 8px; padding: 16px; margin-bottom: 14px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
  .card h2 { font-size: 12px; margin: 0 0 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: .06em; font-weight: 700; }
  form { display: flex; gap: 8px; align-items: center; }
  input { background: #162238; color: #f8fafc; border: 1px solid #1e2d48; border-radius: 6px; padding: 8px 12px; flex: 1; font: inherit; font-family: 'JetBrains Mono', monospace; font-size: 12px; outline: none; }
  input:focus { border-color: #6366f1; }
  button { background: #6366f1; color: #ffffff; border: 1px solid #6366f1; border-radius: 6px; padding: 8px 16px; cursor: pointer; font: inherit; font-size: 12px; font-weight: 700; white-space: nowrap; transition: background 0.15s; }
  button:hover { background: #4f46e5; }
  .confirmation { margin: 16px 0; padding: 10px 14px; border-radius: 6px; font-size: 13px; font-weight: 600; display: none; }
  .confirmation.success { display: block; background: rgba(16,185,129,0.15); border: 1px solid #10b981; color: #10b981; }
  .confirmation.error { display: block; background: rgba(244,63,94,0.15); border: 1px solid #f43f5e; color: #f43f5e; }
</style>
</head>
<body>
  <div class="banner">SIMULATED ADMIN CONSOLE - no real systems are changed</div>
  <a href="/#/containment" class="back-link">&larr; Return to Sentinel Operations Platform</a>
  <h1>Simulated Enterprise Administration</h1>
  <div id="confirmation" class="confirmation"></div>

  <div class="card">
    <h2>Firewall Management</h2>
    <form id="form-block" method="POST" action="/console/block-ip">
      <input id="ip" name="ip" placeholder="IP address (e.g. 185.220.101.45)">
      <button id="block" type="submit">Block IP</button>
    </form>
  </div>

  <div class="card">
    <h2>Session Management</h2>
    <form id="form-revoke" method="POST" action="/console/revoke-session">
      <input id="user" name="user" placeholder="Username (e.g. alice)">
      <button id="revoke" type="submit">Revoke Session</button>
    </form>
  </div>

  <div class="card">
    <h2>IT Service Management (Tickets)</h2>
    <form id="form-ticket" method="POST" action="/console/create-ticket">
      <input id="title" name="title" placeholder="Ticket title / incident ref">
      <button id="create" type="submit">Create Ticket</button>
    </form>
  </div>

  <div class="card">
    <h2>SOC Notifications</h2>
    <form id="form-notify" method="POST" action="/console/send-notification">
      <input id="message" name="message" placeholder="Message content">
      <button id="notify" type="submit">Send Notification</button>
    </form>
  </div>

  <div class="card">
    <h2>User Access Management</h2>
    <form id="form-disable" method="POST" action="/console/disable-user">
      <input id="disable-user-input" name="user" placeholder="Username to disable">
      <button id="disable-user" type="submit">Disable User</button>
    </form>
  </div>

  <div class="card">
    <h2>Endpoint Isolation (EDR)</h2>
    <form id="form-isolate" method="POST" action="/console/isolate-host">
      <input id="isolate-host-input" name="host" placeholder="Host to isolate (e.g. web-01)">
      <button id="isolate-host" type="submit">Isolate Host</button>
    </form>
  </div>

<script>
  const conf = document.getElementById("confirmation");
  function showMsg(msg, isErr) {
    conf.textContent = msg;
    conf.className = "confirmation " + (isErr ? "error" : "success");
    conf.style.display = "block";
  }

  async function postForm(endpoint, body) {
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Request failed");
      showMsg(data.message || "Operation confirmed", false);
    } catch(err) {
      showMsg("Error: " + err.message, true);
    }
  }

  document.getElementById("form-block").onsubmit = e => {
    e.preventDefault();
    const val = document.getElementById("ip").value.trim();
    if (val) postForm("/console/block-ip", { ip: val });
  };
  document.getElementById("form-revoke").onsubmit = e => {
    e.preventDefault();
    const val = document.getElementById("user").value.trim();
    if (val) postForm("/console/revoke-session", { user: val });
  };
  document.getElementById("form-ticket").onsubmit = e => {
    e.preventDefault();
    const val = document.getElementById("title").value.trim();
    if (val) postForm("/console/create-ticket", { title: val });
  };
  document.getElementById("form-notify").onsubmit = e => {
    e.preventDefault();
    const val = document.getElementById("message").value.trim();
    if (val) postForm("/console/send-notification", { message: val });
  };
  document.getElementById("form-disable").onsubmit = e => {
    e.preventDefault();
    const val = document.getElementById("disable-user-input").value.trim();
    if (val) postForm("/console/disable-user", { user: val });
  };
  document.getElementById("form-isolate").onsubmit = e => {
    e.preventDefault();
    const val = document.getElementById("isolate-host-input").value.trim();
    if (val) postForm("/console/isolate-host", { host: val });
  };
</script>
</body>
</html>
"""


@app.get("/console")
async def get_console():
    return HTMLResponse(CONSOLE_HTML)


async def _parse_console_request(request: Request) -> dict:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return await request.json()
        except Exception:
            return {}
    elif "form" in content_type:
        try:
            form = await request.form()
            return dict(form)
        except Exception:
            return {}
    try:
        return await request.json()
    except Exception:
        return {}


@app.post("/console/block-ip")
@app.post("/console/block_ip")
async def console_block_ip(request: Request):
    data = await _parse_console_request(request)
    ip = str(data.get("ip") or data.get("target") or "").strip()
    if not ip:
        raise HTTPException(400, "missing 'ip' parameter")
    await db.add_blocked_ip(ip, action_id="console", reason="admin console block")
    await db.set_state("blocked_ip", ip, "console", "admin console block")
    await db.add_audit("console", "console_block_ip", None, None, f"blocked IP {ip}")
    return {"status": "ok", "message": f"IP {ip} blocked in firewall"}


@app.post("/console/revoke-session")
@app.post("/console/revoke_session")
@app.post("/console/revoke_sessions")
async def console_revoke_session(request: Request):
    data = await _parse_console_request(request)
    user = str(data.get("user") or data.get("target") or "").strip()
    if not user:
        raise HTTPException(400, "missing 'user' parameter")
    await db.add_revoked_session(user, action_id="console", reason="admin console revoke")
    await db.set_state("sessions_revoked", user, "console", "admin console revoke")
    await db.add_audit("console", "console_revoke_session", None, None, f"revoked sessions for user {user}")
    return {"status": "ok", "message": f"Sessions revoked for {user}"}


@app.post("/console/create-ticket")
@app.post("/console/open-ticket")
@app.post("/console/ticket")
async def console_create_ticket(request: Request):
    import uuid
    data = await _parse_console_request(request)
    title = str(data.get("title") or data.get("incident_id") or data.get("target") or "Incident").strip()
    tck = "TCK-" + uuid.uuid4().hex[:6].upper()
    await db.add_ticket(tck, title, title, action_id="console")
    await db.set_state("ticket", tck, "console", title)
    await db.add_audit("console", "console_create_ticket", None, None, f"created ticket {tck}: {title}")
    return {"status": "ok", "ticket_id": tck, "message": f"Ticket {tck} created for {title}"}


@app.post("/console/send-notification")
@app.post("/console/notification")
async def console_send_notification(request: Request):
    import uuid
    data = await _parse_console_request(request)
    msg = str(data.get("message") or data.get("text") or "").strip()
    target = str(data.get("target") or "soc").strip()
    if not msg:
        raise HTTPException(400, "missing 'message' parameter")
    nid = "NOTIF-" + uuid.uuid4().hex[:6].upper()
    await db.add_notification(nid, target, msg, action_id="console")
    await db.set_state("notification", nid, "console", msg)
    await db.add_audit("console", "console_send_notification", None, None, f"sent notification {nid}: {msg}")
    return {"status": "ok", "notification_id": nid, "message": f"Notification sent: {msg}"}


@app.post("/console/disable-user")
@app.post("/console/disable_user")
async def console_disable_user(request: Request):
    data = await _parse_console_request(request)
    user = str(data.get("user") or data.get("target") or "").strip()
    if not user:
        raise HTTPException(400, "missing 'user' parameter")
    await db.add_disabled_user(user, action_id="console", reason="admin console disable")
    await db.set_state("disabled_user", user, "console", "admin console disable")
    await db.add_audit("console", "console_disable_user", None, None, f"disabled user {user}")
    return {"status": "ok", "message": f"User {user} disabled"}


@app.post("/console/isolate-host")
@app.post("/console/isolate_host")
async def console_isolate_host(request: Request):
    data = await _parse_console_request(request)
    host = str(data.get("host") or data.get("target") or "").strip()
    if not host:
        raise HTTPException(400, "missing 'host' parameter")
    await db.add_isolated_host(host, action_id="console", reason="admin console isolate")
    await db.set_state("isolated_host", host, "console", "admin console isolate")
    await db.add_audit("console", "console_isolate_host", None, None, f"isolated host {host}")
    return {"status": "ok", "message": f"Host {host} isolated from network"}


@app.get("/")
async def dashboard():
    """The single-page dashboard."""
    return FileResponse(Path(__file__).resolve().parent.parent / "dashboard" / "index.html")


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    """Live updates: a snapshot first, then events / alerts / incidents / actions / agent status / stats."""
    await ws.accept()
    q = bus.register()          # register first so nothing is missed while the snapshot is built
    try:
        await ws.send_text(json.dumps({"type": "snapshot", "data": await snapshot()}, default=str))
        while True:
            await ws.send_text(await q.get())
    except Exception:           # client went away (WebSocketDisconnect or a failed send)
        pass
    finally:
        bus.unregister(q)
