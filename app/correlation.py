"""Live correlation: group alerts by entity (user / ip / host) inside a rolling time window.
2+ DISTINCT alert types on the same entity -> an incident. Later alerts update that incident
(no duplicates). process(alert) returns ("created"|"updated", incident, escalated) or None.
escalated = new incident, a new alert type, or a higher severity (this is what triggers the agent)."""
import uuid
from collections import deque

from app import config

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

pending: deque = deque()                 # alerts not (yet) part of any incident, oldest first
incidents: dict[str, dict] = {}          # incident id -> incident
entity_index: dict[str, str] = {}        # "user:alice" -> incident id


def entity_keys(alert: dict) -> set:
    """Entities an alert touches, limited to the fields chosen in CORRELATION_KEYS."""
    return {f"{k}:{alert[k]}" for k in config.CORRELATION_KEYS if alert.get(k)}


def _find_open_incident(keys: set, now: float):
    """An incident that shares an entity with this alert and was active inside the window."""
    best = None
    for k in keys:
        inc = incidents.get(entity_index.get(k, ""))
        if inc and inc["status"] != "closed" and now - inc["updated_ts"] <= config.CORRELATION_WINDOW_S:  # closed = analyst said false positive
            if best is None or inc["updated_ts"] > best["updated_ts"]:
                best = inc
    return best


def _add_alert(inc: dict, alert: dict) -> None:
    alert["incident_id"] = inc["id"]
    inc["alert_ids"].append(alert["id"])
    if alert["type"] not in inc["alert_types"]:
        inc["alert_types"].append(alert["type"])
    inc["timeline"].append({
        "ts": alert["ts"], "alert_id": alert["id"], "type": alert["type"],
        "mitre_tactic": alert["mitre_tactic"],
        "mitre_technique_id": alert.get("mitre_technique_id"),
        "technique_id": alert.get("mitre_technique_id"),
        "mitre_technique": alert.get("mitre_technique"),
        "severity": alert["severity"],
        "entity": alert["entity"], "evidence_event_ids": alert["evidence_event_ids"],
        "detail": alert["detail"],
    })
    inc["timeline"].sort(key=lambda t: t["ts"])  # keep the timeline ordered
    if SEV_ORDER[alert["severity"]] > SEV_ORDER[inc["severity"]]:
        inc["severity"] = alert["severity"]
    inc["updated_ts"] = max(inc["updated_ts"], alert["ts"])
    for k in entity_keys(alert):
        if k not in inc["entities"]:
            inc["entities"].append(k)
        entity_index[k] = inc["id"]


def process(alert: dict):
    now = alert["ts"]
    while pending and now - pending[0]["ts"] > config.CORRELATION_WINDOW_S:  # roll the window
        pending.popleft()
    keys = entity_keys(alert)

    # 1) An open incident already covers one of these entities -> update it.
    inc = _find_open_incident(keys, now)
    if inc:
        old_sev, old_types = SEV_ORDER[inc["severity"]], len(inc["alert_types"])
        _add_alert(inc, alert)
        escalated = SEV_ORDER[inc["severity"]] > old_sev or len(inc["alert_types"]) > old_types
        return "updated", inc, escalated

    # 2) Earlier unattached alerts on the same entity? If that makes 2+ distinct types -> new incident.
    related = [a for a in pending if a["incident_id"] is None and keys & entity_keys(a)]
    if len({a["type"] for a in related} | {alert["type"]}) >= 2:
        inc = {"id": "INC-" + uuid.uuid4().hex[:6].upper(), "created_ts": min(a["ts"] for a in related),
               "updated_ts": now, "status": "open", "severity": "low",
               "entities": [], "alert_types": [], "alert_ids": [], "timeline": [],
               "investigation": None, "risk": None, "feedback": None}
        incidents[inc["id"]] = inc
        for a in related + [alert]:
            _add_alert(inc, a)
        return "created", inc, True

    # 3) Not enough yet: remember it and wait for more.
    pending.append(alert)
    return None


def load(saved: list[dict]) -> None:
    """Restore incidents from SQLite at startup so correlation can keep updating them (oldest first,
    so the newest incident wins an entity)."""
    for inc in sorted(saved, key=lambda i: i["updated_ts"]):
        incidents[inc["id"]] = inc
        for k in inc["entities"]:
            entity_index[k] = inc["id"]
