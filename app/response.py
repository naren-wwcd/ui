"""Response layer: playbooks, approval gate, RPA queue and audit log.
 - Low-risk / safe actions run automatically, ONLY when the agent says true_positive.
 - High-impact actions (disable_user, isolate_host) always wait as 'pending_approval' for a human.
 - Playbooks change simulated state in SQLite (dedicated tables and system_state); every step is written to audit_log."""
import asyncio
import time
import uuid

from app import bus, config, db, rpa_interface

_lock = asyncio.Lock()   # makes approve/reject atomic (no double execution)


# ---------------- playbooks (each returns a result string) ----------------
async def block_ip(a: dict) -> str:
    await db.add_blocked_ip(a["target"], a["id"], a.get("reason", ""))
    await db.set_state("blocked_ip", a["target"], a["id"], a.get("reason", ""))
    return f"IP {a['target']} added to the blocklist"


async def disable_user(a: dict) -> str:
    await db.add_disabled_user(a["target"], a["id"], a.get("reason", ""))
    await db.set_state("disabled_user", a["target"], a["id"], a.get("reason", ""))
    return f"user {a['target']} disabled"


async def isolate_host(a: dict) -> str:
    await db.add_isolated_host(a["target"], a["id"], a.get("reason", ""))
    await db.set_state("isolated_host", a["target"], a["id"], a.get("reason", ""))
    return f"host {a['target']} isolated from the network"


async def revoke_sessions(a: dict) -> str:
    await db.add_revoked_session(a["target"], a["id"], a.get("reason", ""))
    await db.set_state("sessions_revoked", a["target"], a["id"], a.get("reason", ""))
    return f"all sessions for {a['target']} revoked"


async def open_ticket(a: dict) -> str:
    ticket = "TCK-" + uuid.uuid4().hex[:6].upper()
    await db.add_ticket(ticket, a["target"], a.get("reason", ""), a["id"])
    await db.set_state("ticket", ticket, a["id"], f"{a['target']}: {a.get('reason', '')}")
    return f"ticket {ticket} opened for incident {a['target']}"


async def send_notification(a: dict) -> str:
    nid = "NOTIF-" + uuid.uuid4().hex[:6].upper()
    await db.add_notification(nid, a["target"], a.get("reason", ""), a["id"])
    await db.set_state("notification", nid, a["id"], f"{a['target']}: {a.get('reason', '')}")
    return f"notification {nid} sent to {a['target']}"


async def generate_report(a: dict) -> str:
    rid = "REP-" + uuid.uuid4().hex[:6].upper()
    await db.set_state("report", rid, a["id"], f"{a['target']}: {a.get('reason', '')}")
    return f"report {rid} generated for incident {a['target']}"


PLAYBOOKS = {
    "block_ip": block_ip,
    "disable_user": disable_user,
    "isolate_host": isolate_host,
    "revoke_sessions": revoke_sessions,
    "open_ticket": open_ticket,
    "send_notification": send_notification,
    "generate_report": generate_report,
}


async def _withdraw_stale(inc: dict, wanted: set) -> None:
    """A newer investigation sees more alerts. Pending proposals it no longer recommends are withdrawn."""
    for old in await db.list_actions("pending_approval"):
        if old["incident_id"] != inc["id"] or (old["type"], old["target"]) in wanted:
            continue
        async with _lock:                              # same lock as approve/reject: a human decision wins any race
            cur = await db.get_action(old["id"])
            if not cur or cur["status"] != "pending_approval":
                continue
            msg = "replaced by a newer investigation"
            await db.update_action(old["id"], status="rejected", decided_ts=time.time(), decided_by="superseded", result=msg)
            await db.add_audit("response", "action_superseded", inc["id"], old["id"], f"{old['type']} {old['target']}: {msg}")
            cur.update(status="rejected", decided_by="superseded", result=msg)
            bus.broadcast("action", cur)
            print(f"[ACTION] {old['id']} {old['type']} {old['target']} -> WITHDRAWN (newer investigation)")


async def propose_actions(inc: dict, investigation: dict) -> list[dict]:
    """Turn the agent's recommendations into actions: validate, de-duplicate, auto-run or queue for approval."""
    verdict = investigation["verdict"]
    if verdict == "false_positive":
        await db.add_audit("response", "no_actions", inc["id"], None, "agent verdict is false_positive")
        return []
    observed = await db.incident_observed(inc["id"])
    in_scope = {
        "block_ip": observed["ips"],
        "disable_user": observed["users"],
        "revoke_sessions": observed["users"],
        "isolate_host": observed["hosts"],
        "send_notification": observed["users"] + observed["hosts"] + [inc["id"]],
        "generate_report": [inc["id"]],
    }
    created, wanted = [], set()                        # wanted = (type, target) pairs the latest investigation recommends
    for rec in investigation["recommended_actions"]:
        type_, target = str(rec.get("action", "")).strip(), str(rec.get("target", "")).strip()
        reason = str(rec.get("reason", ""))[:300]
        if type_ not in PLAYBOOKS:
            await db.add_audit("response", "action_dropped", inc["id"], None, f"unknown action '{type_}'")
            continue
        if type_ == "isolate_host" and config.is_cloud_host(target):
            await db.add_audit("response", "action_dropped", inc["id"], None,
                                f"isolate_host '{target}' dropped: a cloud resource (S3/IAM/CloudTrail/STS) cannot be "
                                "network-isolated; disable_user / revoke_sessions are the right actions here")
            continue
        if type_ in ("open_ticket", "generate_report"):
            target = inc["id"]
        elif type_ == "send_notification":
            target = target or inc["id"]
        elif target not in in_scope[type_]:
            await db.add_audit("response", "action_dropped", inc["id"], None,
                                f"{type_} target '{target}' is not part of this incident")
            continue
        wanted.add((type_, target))
        if await db.action_exists(inc["id"], type_, target):   # agent re-runs must not duplicate actions
            continue
        auto = type_ in ("open_ticket", "send_notification", "generate_report") or (verdict == "true_positive" and type_ in config.AUTO_ACTIONS)
        mode = "auto" if auto else "approval"
        mode_label = "AUTO_EXECUTE" if auto else "REQUIRES_APPROVAL"
        initial_status = "queued" if auto else "pending_approval"
        a = {
            "id": "ACT-" + uuid.uuid4().hex[:6].upper(),
            "incident_id": inc["id"],
            "type": type_,
            "target": target,
            "reason": reason,
            "status": initial_status,
            "mode": mode,
            "mode_label": mode_label,
            "created_ts": time.time(),
            "decided_ts": None,
            "decided_by": None,
            "result": None,
            "executor": None,
            "claim_time": None,
            "finish_time": None,
            "verification_status": None,
            "verification_detail": None,
            "recommended_next_step": None,
            "claim_id": None,
        }
        await db.insert_action(a)
        await db.add_audit("agent", "action_proposed", inc["id"], a["id"], f"{type_} {target} ({mode_label}): {reason}")
        created.append(a)
        bus.broadcast("action", a)
        if auto:
            await rpa_interface.queue_action(a)
        else:
            print(f"[ACTION] {a['id']} {type_} {target} -> PENDING APPROVAL  (POST /actions/{a['id']}/approve)")
    await _withdraw_stale(inc, wanted)
    await db.add_audit("response", "response_decision", inc["id"], None,
                       f"evaluated actions for verdict={verdict}: proposed {len(created)}")
    return created


async def approve(action_id: str, actor: str = "human") -> dict:
    async with _lock:
        a = await db.get_action(action_id)
        if not a:
            raise LookupError(action_id)
        if a["status"] != "pending_approval":
            raise ValueError(f"action is already {a['status']}")
        now = time.time()
        await db.update_action(a["id"], status="approved", decided_ts=now, decided_by=actor)
        await db.add_audit(actor, "action_approved", a["incident_id"], a["id"], f"{a['type']} {a['target']}")
        a.update(status="approved", decided_ts=now, decided_by=actor)
        bus.broadcast("action", a)
        print(f"[ACTION] {a['id']} {a['type']} {a['target']} -> APPROVED by {actor}")
        await rpa_interface.queue_action(a)
        return await db.get_action(action_id)


async def reject(action_id: str, actor: str = "human") -> dict:
    async with _lock:
        a = await db.get_action(action_id)
        if not a:
            raise LookupError(action_id)
        if a["status"] != "pending_approval":
            raise ValueError(f"action is already {a['status']}")
        await db.update_action(a["id"], status="rejected", decided_ts=time.time(), decided_by=actor)
        await db.add_audit(actor, "action_rejected", a["incident_id"], a["id"], f"{a['type']} {a['target']}")
        a.update(status="rejected", decided_by=actor)
        bus.broadcast("action", a)
        print(f"[ACTION] {a['id']} {a['type']} {a['target']} -> REJECTED by {actor}")
        return await db.get_action(action_id)


async def retry(action_id: str, actor: str = "human") -> dict:
    """Re-queue an action after failure or verification failure (audited)."""
    async with _lock:
        a = await db.get_action(action_id)
        if not a:
            raise LookupError(action_id)
        await db.update_action(
            a["id"],
            status="queued",
            executor=None,
            claim_id=None,
            claim_time=None,
            finish_time=None,
            result=None,
            verification_status=None,
            verification_detail=None,
            recommended_next_step=None,
        )
        await db.add_audit(actor, "action_retried", a.get("incident_id"), a["id"],
                           f"retry requested for {a['type']} {a['target']}")
        a.update(
            status="queued",
            executor=None,
            claim_id=None,
            claim_time=None,
            finish_time=None,
            result=None,
            verification_status=None,
            verification_detail=None,
            recommended_next_step=None,
        )
        bus.broadcast("action", a)
        print(f"[ACTION] {a['id']} {a['type']} {a['target']} -> RETRY (queued)")
        await rpa_interface.queue_action(a)
        return await db.get_action(action_id)
