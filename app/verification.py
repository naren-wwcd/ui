"""Verification engine: independently verifies simulated state after action execution."""
import logging
from app import bus, db

logger = logging.getLogger(__name__)


async def verify_action(a: dict) -> dict:
    """Check simulated state tables independently by querying SQLite.

    Does NOT trust the executor's return value.
    Updates action status to 'verified' or 'verification_failed' (or keeps 'executed' if skipped).
    Stores verification_status ('verified' | 'failed' | 'skipped') and verification_detail.
    On failure, adds recommended_next_step ('retry / manual').
    Audits and broadcasts the result.
    """
    action_type = a.get("type", "")
    target = a.get("target", "")
    action_id = a.get("id", "")

    # If execution itself had failed
    if a.get("status") == "failed":
        v_status = "failed"
        detail = f"execution failed: {a.get('result', '')}"
        status = "failed"
        next_step = "retry"
    elif action_type == "block_ip":
        if await db.is_ip_blocked(target):
            v_status = "verified"
            detail = f"IP {target} confirmed in blocked_ips table"
            status = "verified"
            next_step = None
        else:
            v_status = "failed"
            detail = f"IP {target} not found in blocked_ips table"
            status = "verification_failed"
            next_step = "retry / manual"
    elif action_type == "revoke_sessions":
        if await db.is_session_revoked(target):
            v_status = "verified"
            detail = f"session for {target} confirmed in revoked_sessions table"
            status = "verified"
            next_step = None
        else:
            v_status = "failed"
            detail = f"session for {target} not found in revoked_sessions table"
            status = "verification_failed"
            next_step = "retry / manual"
    elif action_type == "open_ticket":
        if await db.is_ticket_open(target, action_id):
            v_status = "verified"
            detail = f"ticket confirmed in tickets table for {target}"
            status = "verified"
            next_step = None
        else:
            v_status = "failed"
            detail = f"ticket not found in tickets table for {target}"
            status = "verification_failed"
            next_step = "retry / manual"
    elif action_type == "disable_user":
        if await db.is_user_disabled(target):
            v_status = "verified"
            detail = f"user {target} confirmed in disabled_users table"
            status = "verified"
            next_step = None
        else:
            v_status = "failed"
            detail = f"user {target} not found in disabled_users table"
            status = "verification_failed"
            next_step = "retry / manual"
    elif action_type == "isolate_host":
        if await db.is_host_isolated(target):
            v_status = "verified"
            detail = f"host {target} confirmed in isolated_hosts table"
            status = "verified"
            next_step = None
        else:
            v_status = "failed"
            detail = f"host {target} not found in isolated_hosts table"
            status = "verification_failed"
            next_step = "retry / manual"
    elif action_type == "send_notification":
        if await db.is_notification_sent(target, action_id):
            v_status = "verified"
            detail = f"notification confirmed in notifications table for {target}"
            status = "verified"
            next_step = None
        else:
            v_status = "failed"
            detail = f"notification not found in notifications table for {target}"
            status = "verification_failed"
            next_step = "retry / manual"
    elif action_type == "generate_report":
        v_status = "skipped"
        detail = "generate_report produces transient output; verification skipped"
        status = "executed"
        next_step = None
    else:
        v_status = "skipped"
        detail = f"no verification rule for action type '{action_type}'"
        status = a.get("status", "executed")
        next_step = None

    a.update(
        status=status,
        verification_status=v_status,
        verification_detail=detail,
        recommended_next_step=next_step,
    )
    await db.update_action(
        action_id,
        status=status,
        verification_status=v_status,
        verification_detail=detail,
        recommended_next_step=next_step,
    )
    audit_event = f"action_{v_status}" if v_status != "failed" else "action_verification_failed"
    audit_detail = f"{action_type} {target}: {detail}"
    if next_step:
        audit_detail += f" (recommended: {next_step})"
    await db.add_audit("verification", audit_event, a.get("incident_id"), action_id, audit_detail)
    bus.broadcast("action", a)
    print(f"[VERIFY] {action_id} {action_type} {target} -> {v_status.upper()}: {detail}")
    return a
