"""RPA Interface: Action queue management, bot claims, timeouts and fallback execution."""
import asyncio
import logging
import time
import uuid

from app import bus, config, db, verification

logger = logging.getLogger(__name__)

_lock = asyncio.Lock()
_timers: dict[str, asyncio.Task] = {}
_last_bot_claim_time: float = 0.0


def is_bot_online() -> bool:
    """True if a bot claimed an action in the last 60 seconds."""
    return (time.time() - _last_bot_claim_time) < 60.0


async def queue_action(a: dict) -> dict:
    """Transition an action to 'queued' and route based on RPA_MODE."""
    action_id = a["id"]
    status = "queued"
    a.update(status=status)
    await db.update_action(action_id, status=status)
    await db.add_audit("response", "action_queued", a.get("incident_id"), action_id,
                       f"{a['type']} {a['target']}")
    bus.broadcast("action", a)
    print(f"[ACTION] {action_id} {a['type']} {a['target']} -> QUEUED (mode={config.RPA_MODE})")

    mode = config.RPA_MODE.lower()
    if mode == "builtin":
        asyncio.create_task(run_builtin_executor(action_id, fallback=False))
    elif mode == "uipath":
        # Waits in queue for an external bot to claim
        pass
    else:  # "auto"
        # Wait RPA_CLAIM_TIMEOUT_S for bot claim; fallback to builtin if unclaimed
        task = asyncio.create_task(_auto_fallback_timer(action_id, config.RPA_CLAIM_TIMEOUT_S))
        _timers[action_id] = task

    return a


async def _auto_fallback_timer(action_id: str, timeout_s: float) -> None:
    try:
        await asyncio.sleep(timeout_s)
        async with _lock:
            a = await db.get_action(action_id)
            if not a or a["status"] != "queued":
                return
            print(f"[RPA] Action {action_id} unclaimed after {timeout_s}s -> triggering builtin fallback")
            await _run_builtin_locked(a, fallback=True)
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.exception("Error in auto fallback timer for %s: %s", action_id, exc)
    finally:
        _timers.pop(action_id, None)


async def run_builtin_executor(action_id: str, fallback: bool = False) -> dict | None:
    async with _lock:
        a = await db.get_action(action_id)
        if not a or a["status"] != "queued":
            return a
        return await _run_builtin_locked(a, fallback=fallback)


async def _run_builtin_locked(a: dict, fallback: bool) -> dict:
    action_id = a["id"]
    timer = _timers.pop(action_id, None)
    if timer and not timer.done() and asyncio.current_task() != timer:
        timer.cancel()

    # Transition: executing
    claim_time = time.time()
    executor = "builtin"
    executing_status = "executing"
    a.update(status=executing_status, executor=executor, claim_time=claim_time)
    await db.update_action(action_id, status=executing_status, executor=executor, claim_time=claim_time)
    await db.add_audit("builtin", "action_claimed", a.get("incident_id"), action_id,
                       f"claimed by builtin{' (fallback)' if fallback else ''}")
    await db.add_audit("builtin", "action_executing", a.get("incident_id"), action_id,
                       f"executing by builtin{' fallback' if fallback else ''}")
    bus.broadcast("action", a)

    # Execute playbook
    from app.response import PLAYBOOKS
    playbook = PLAYBOOKS.get(a["type"])
    finish_time = time.time()
    if playbook:
        try:
            result = await playbook(a)
            status = "executed"
        except Exception as exc:
            result = f"failed: {exc!r}"
            status = "failed"
    else:
        result = f"unknown playbook for type '{a['type']}'"
        status = "failed"

    finish_time = time.time()
    a.update(status=status, finish_time=finish_time, result=result)
    await db.update_action(action_id, status=status, finish_time=finish_time, result=result)

    if fallback:
        audit_detail = "executed by builtin fallback (no bot claimed)"
        if result:
            audit_detail += f": {result}"
    else:
        audit_detail = f"{a['type']} {a['target']}: {result}"
    await db.add_audit("builtin", f"action_{status}", a.get("incident_id"), action_id, audit_detail)
    bus.broadcast("action", a)
    print(f"[ACTION] {action_id} {a['type']} {a['target']} -> {status.upper()} by builtin{' (fallback)' if fallback else ''}")

    # Run independent verification
    return await verification.verify_action(a)


async def claim_next() -> dict | None:
    """Atomically claim the oldest queued action."""
    async with _lock:
        a = await db.get_oldest_queued_action()
        if not a:
            return None
        return await _claim_action_locked(a)


async def claim_action(action_id: str) -> dict:
    """Atomically claim a specific action by ID."""
    async with _lock:
        a = await db.get_action(action_id)
        if not a:
            raise LookupError(f"no such action {action_id}")
        if a["status"] != "queued":
            raise ValueError(f"action is already {a['status']}")
        return await _claim_action_locked(a)


async def _claim_action_locked(a: dict) -> dict:
    action_id = a["id"]
    timer = _timers.pop(action_id, None)
    if timer and not timer.done():
        timer.cancel()

    claim_id = "CLM-" + uuid.uuid4().hex[:8].upper()
    claim_time = time.time()
    global _last_bot_claim_time
    _last_bot_claim_time = claim_time
    executor = "uipath"
    status = "executing"

    a.update(claim_id=claim_id, claim_time=claim_time, executor=executor, status=status)
    await db.update_action(
        action_id,
        claim_id=claim_id,
        claim_time=claim_time,
        executor=executor,
        status=status,
    )
    await db.add_audit("uipath", "action_claimed", a.get("incident_id"), action_id,
                       f"claimed by bot: claim_id={claim_id}")
    bus.broadcast("action", a)
    print(f"[RPA] {action_id} claimed by uipath (claim_id={claim_id})")

    return {
        "id": a["id"],
        "type": a["type"],
        "target": a["target"],
        "incident_id": a.get("incident_id"),
        "params": {"target": a["target"], "reason": a.get("reason", "")},
        "claim_id": claim_id,
    }


async def submit_result(action_id: str, claim_id: str, status: str, detail: str) -> dict:
    """Record execution result from bot and run verification."""
    async with _lock:
        a = await db.get_action(action_id)
        if not a:
            raise LookupError(f"no such action {action_id}")
        if a["status"] != "executing" or a.get("claim_id") != claim_id:
            raise ValueError("stale or invalid claim")

        finish_time = time.time()
        exec_status = "executed" if status == "done" else "failed"
        a.update(status=exec_status, finish_time=finish_time, result=detail)
        await db.update_action(action_id, status=exec_status, finish_time=finish_time, result=detail)
        await db.add_audit("uipath", f"action_{exec_status}", a.get("incident_id"), action_id, detail)
        bus.broadcast("action", a)
        print(f"[RPA] {action_id} reported result: {status} ({detail})")

        # Independently verify the action
        return await verification.verify_action(a)
