"""Streaming detection: every event is checked as it arrives against in-memory state.
Plain rules, no ML. detect(event) returns a list of alert dicts (usually empty)."""
import time
import uuid
from collections import defaultdict, deque

from app import config, mitre
from app.producers.traffic_gen import USERS

PRIV_ACTIONS = {"sudo", "role_change", "admin_group_add",
                # cloud (see producers/cloudtrail_adapter.py): new access key, admin/inline policy attached
                "iam_create_access_key", "iam_attach_admin_policy", "iam_put_user_policy"}
# Login and privilege events carry tiny byte counts that are not "data transfer"; keep them out
# of the transfer rule and out of the bytes baseline.
NON_DATA_ACTIONS = {"login_failed", "login_success", "cloudtrail_stop_logging"} | PRIV_ACTIONS

# --- in-memory state ---------------------------------------------------------
# Sliding windows of recent failed logins, keyed by ("ip", x) or ("user", x): deque of (ts, event_id)
failed_windows: dict[tuple, deque] = defaultdict(deque)
# Countries each user normally logs in from. Seeded from the traffic generator's USERS, which here
# stands in for an identity directory (IdP / HR system). Unknown users are learned (first country seen).
baseline_countries: dict[str, set] = defaultdict(set, {u: {p["country"]} for u, p in USERS.items()})
# Per-user running average of bytes per DATA event (file/API/download): [sample_count, mean]
baseline_bytes: dict[str, list] = defaultdict(lambda: [0, 0.0])
# Last alert time per (type, key), to avoid alerting on every following event
_last_alert: dict[tuple, float] = {}
# Most recent successful login per user and country: user -> {country: (ts, event_id)} (impossible travel)
last_login: dict[str, dict] = defaultdict(dict)
_travel_alerted: dict[tuple, float] = {}   # (user, country pair) -> ts, so one trip alerts once, not on every later login
# Recent failed logins per source IP: ip -> deque of (ts, user, event_id) (password spraying)
spray_windows: dict[str, deque] = defaultdict(deque)
# Recent CPU spikes / new processes per host: host -> deque of (ts, kind, event_id, process_name) (cryptominer)
miner_windows: dict[str, deque] = defaultdict(deque)


def _cooling(type_: str, keys: list, ts: float) -> bool:
    return any(ts - _last_alert.get((type_, k), -1e18) < config.ALERT_COOLDOWN_S for k in keys)


def _mark(type_: str, keys: list, ts: float) -> None:
    for k in keys:
        _last_alert[(type_, k)] = ts


def _who(e: dict) -> str:
    """Entity label for an event: the user if there is one, else the host (then the ip). Never "user:None"."""
    if e.get("user"):
        return f"user:{e['user']}"
    if e.get("host"):
        return f"host:{e['host']}"
    return f"ip:{e['ip']}" if e.get("ip") else "unknown"


def _user_has_recent_alert(user: str, ts: float) -> bool:
    """True if this user raised any alert inside the correlation window (their activity is not 'normal' now)."""
    key = f"user:{user}"
    return any(k == key and ts - t < config.CORRELATION_WINDOW_S for (_, k), t in _last_alert.items())


def _alert(e: dict, type_: str, entity: str, evidence: list, tactic: str, severity: str, detail: str) -> dict:
    if not entity or entity.endswith(":None"):   # safety net: an empty entity falls back to host / ip
        entity = _who(e)
    m = mitre.get_mitre(type_)
    return {
        "id": uuid.uuid4().hex[:12], "ts": e["ts"], "type": type_, "entity": entity,
        "user": e["user"], "ip": e["ip"], "host": e["host"],
        "evidence_event_ids": evidence,
        "mitre_tactic": tactic or m["formatted_tactic"],
        "mitre_technique_id": m["technique_id"],
        "mitre_technique": m["formatted_technique"],
        "severity": severity,
        "detail": detail, "incident_id": None,  # incident_id is filled in by correlation
    }


# --- rules -------------------------------------------------------------------
def _rule_failed_logins(e: dict):
    """More than N failed logins from one IP (or against one user) within the window."""
    hit = None
    for kind in ("ip", "user"):
        val = e[kind]
        if not val:
            continue
        dq = failed_windows[(kind, val)]
        dq.append((e["ts"], e["id"]))
        while dq and e["ts"] - dq[0][0] > config.FAILED_LOGIN_WINDOW_S:  # slide the window
            dq.popleft()
        if hit is None and len(dq) > config.FAILED_LOGIN_THRESHOLD:
            hit = (kind, val, [i for _, i in dq])
    if not hit:
        return None
    kind, val, ids = hit
    keys = [f"{k}:{e[k]}" for k in ("ip", "user") if e[k]]
    if _cooling("brute_force", keys, e["ts"]):
        return None
    _mark("brute_force", keys, e["ts"])
    return _alert(e, "brute_force", f"{kind}:{val}", ids, "Credential Access (TA0006)", "medium",
                  f"{len(ids)} failed logins for {kind} {val} within {config.FAILED_LOGIN_WINDOW_S}s")


def _rule_new_country(e: dict):
    """Successful login from a country that is not in the user's baseline."""
    user, country = e["user"], e["country"]
    if not user or not country:
        return None
    if user not in baseline_countries:  # unknown user: learn the first country, don't alert
        baseline_countries[user].add(country)
        return None
    if country in baseline_countries[user]:
        return None
    if _cooling("new_country_login", [f"user:{user}"], e["ts"]):
        return None
    _mark("new_country_login", [f"user:{user}"], e["ts"])
    return _alert(e, "new_country_login", f"user:{user}", [e["id"]], "Initial Access (TA0001)", "high",
                  f"login from {country} (baseline: {','.join(sorted(baseline_countries[user]))})")


def _rule_priv_esc(e: dict):
    """sudo / role change / admin group add. If the event has no user, the entity is the host."""
    entity = _who(e)
    if _cooling("privilege_escalation", [entity], e["ts"]):
        return None
    _mark("privilege_escalation", [entity], e["ts"])
    return _alert(e, "privilege_escalation", entity, [e["id"]], "Privilege Escalation (TA0004)", "high",
                  f"{e['action']} by {e['user'] or 'unknown user'} on {e['host']}")


def _rule_data_transfer(e: dict):
    """Bytes far above the user's own average (x multiplier AND above a minimum size)."""
    user, size = e["user"], e["bytes"]
    if not user or size <= 0 or e["action"] in NON_DATA_ACTIONS:
        return None
    n, mean = baseline_bytes[user]
    ref = mean if n >= config.BASELINE_MIN_SAMPLES else config.DEFAULT_BASELINE_BYTES
    if size > max(config.TRANSFER_MULTIPLIER * ref, config.TRANSFER_MIN_BYTES):
        if _cooling("large_data_transfer", [f"user:{user}"], e["ts"]):
            return None
        _mark("large_data_transfer", [f"user:{user}"], e["ts"])
        return _alert(e, "large_data_transfer", f"user:{user}", [e["id"]], "Exfiltration (TA0010)", "critical",
                      f"{size / 1e6:.0f} MB in one event (user average {ref / 1e3:.0f} KB)")
    # Learn ONLY from normal events: not from an unusual country, and not while the user has a fresh alert.
    # (Failed logins / privilege events are already excluded above, large transfers returned earlier.)
    if (e["country"] and user in baseline_countries and e["country"] not in baseline_countries[user]) \
            or _user_has_recent_alert(user, e["ts"]):
        return None
    n = min(n + 1, 500)
    baseline_bytes[user] = [n, mean + (size - mean) / n]
    return None


def _rule_impossible_travel(e: dict):
    """Two successful logins by one user from different countries within IMPOSSIBLE_TRAVEL_WINDOW_S."""
    user, country = e["user"], e["country"]
    if not user or not country:
        return None
    seen = last_login[user]
    for c in [c for c, (ts, _) in seen.items() if e["ts"] - ts > config.IMPOSSIBLE_TRAVEL_WINDOW_S]:
        del seen[c]                                    # too old to matter
    others = [(ts, c, i) for c, (ts, i) in seen.items() if c != country]
    seen[country] = (e["ts"], e["id"])                 # always remember this login
    if not others:
        return None
    prev_ts, prev_c, prev_id = max(others)             # the most recent login from another country
    pair = (user, frozenset((prev_c, country)))
    if e["ts"] - _travel_alerted.get(pair, -1e18) < config.IMPOSSIBLE_TRAVEL_WINDOW_S \
            or _cooling("impossible_travel", [f"user:{user}"], e["ts"]):
        return None
    _travel_alerted[pair] = e["ts"]
    _mark("impossible_travel", [f"user:{user}"], e["ts"])
    gap = max(e["ts"] - prev_ts, 0)
    if gap < 10:
        detail = f"logins from {prev_c} and {country} within seconds"
    else:
        gap_txt = f"{gap:.0f} s" if gap < 120 else f"{gap / 60:.0f} min"
        detail = f"logins from {prev_c} and {country} only {gap_txt} apart"
    return _alert(e, "impossible_travel", f"user:{user}", [prev_id, e["id"]], "Initial Access (TA0001)", "high",
                  detail)


def _rule_password_spraying(e: dict):
    """Failed logins from ONE IP against >= SPRAY_MIN_USERS distinct users within SPRAY_WINDOW_S."""
    ip, user = e["ip"], e["user"]
    if not ip or not user:
        return None
    dq = spray_windows[ip]
    dq.append((e["ts"], user, e["id"]))
    while dq and e["ts"] - dq[0][0] > config.SPRAY_WINDOW_S:
        dq.popleft()
    users = {u for _, u, _ in dq}
    if len(users) < config.SPRAY_MIN_USERS or _cooling("password_spraying", [f"ip:{ip}"], e["ts"]):
        return None
    _mark("password_spraying", [f"ip:{ip}"], e["ts"])
    # user=None on purpose: the alert is about the IP, not about the user whose event happened to cross the threshold.
    return _alert({**e, "user": None}, "password_spraying", f"ip:{ip}", [i for _, _, i in dq],
                  "Credential Access (TA0006)", "medium",
                  f"failed logins from {ip} against {len(users)} different users within {config.SPRAY_WINDOW_S}s")


def _rule_off_hours(e: dict):
    """Successful login outside business hours. LOW severity, off unless OFF_HOURS_ENABLED=true."""
    if not config.OFF_HOURS_ENABLED or not e["user"]:
        return None
    t = time.localtime(e["ts"])                        # server local time
    if t.tm_wday in config.BUSINESS_DAYS and config.BUSINESS_HOURS_START <= t.tm_hour < config.BUSINESS_HOURS_END:
        return None
    if _cooling("off_hours_login", [f"user:{e['user']}"], e["ts"]):
        return None
    _mark("off_hours_login", [f"user:{e['user']}"], e["ts"])
    return _alert(e, "off_hours_login", f"user:{e['user']}", [e["id"]], "Initial Access (TA0001)", "low",
                  f"login at {time.strftime('%a %H:%M', t)}, outside business hours")


def _rule_cryptominer(e: dict):
    """A CPU spike AND a new process on the same host within CRYPTOMINER_WINDOW_S (either order).
    system_collector emits 'cpu_spike:NNpct' when CPU crosses the threshold and 'process_start:<name>' for each new process."""
    host, action = e["host"], e["action"]
    if not host:
        return None
    kind = "cpu" if action.startswith("cpu_spike") else "proc"
    name = action.split(":", 1)[1] if kind == "proc" and ":" in action else ""
    if kind == "proc" and (not name or name.lower() in config.CRYPTOMINER_IGNORE_PROCESSES):
        return None                                    # common short-lived tools never count
    dq = miner_windows[host]
    while dq and e["ts"] - dq[0][0] > config.CRYPTOMINER_WINDOW_S:
        dq.popleft()
    other = [x for x in dq if x[1] != kind]            # the opposite kind of event, newest last
    dq.append((e["ts"], kind, e["id"], name))
    if not other or _cooling("cryptominer", [f"host:{host}"], e["ts"]):
        return None
    _mark("cryptominer", [f"host:{host}"], e["ts"])
    spike_id = e["id"] if kind == "cpu" else other[-1][2]
    proc_id, proc = (e["id"], name) if kind == "proc" else (other[-1][2], other[-1][3])
    return _alert({**e, "user": None, "ip": None}, "cryptominer", f"host:{host}", [spike_id, proc_id],
                  "Impact (TA0040)", "high",
                  f"CPU spike and new process '{proc}' on {host} within {config.CRYPTOMINER_WINDOW_S}s (possible cryptominer)")


def _rule_defense_evasion(e: dict):
    """Audit logging was switched off (CloudTrail StopLogging): attackers do this to hide what comes next."""
    entity = _who(e)
    if _cooling("defense_evasion", [entity], e["ts"]):
        return None
    _mark("defense_evasion", [entity], e["ts"])
    return _alert(e, "defense_evasion", entity, [e["id"]], "Defense Evasion (TA0005)", "high",
                  f"audit logging stopped ({e['host']}) by {e['user'] or 'unknown'}")


def detect(event: dict) -> list[dict]:
    """Run all rules on one event."""
    found = []
    action = event["action"]
    if action == "login_failed":
        found += [_rule_failed_logins(event), _rule_password_spraying(event)]
    elif action == "login_success":
        found += [_rule_new_country(event), _rule_impossible_travel(event), _rule_off_hours(event)]
    elif action in PRIV_ACTIONS:
        found.append(_rule_priv_esc(event))
    elif action == "cloudtrail_stop_logging":
        found.append(_rule_defense_evasion(event))
    elif action.startswith(("cpu_spike", "process_start")):
        found.append(_rule_cryptominer(event))
    found.append(_rule_data_transfer(event))  # applies to every event that carries bytes
    return [a for a in found if a]
