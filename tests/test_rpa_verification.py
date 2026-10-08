"""Tests for Part R1 & Part R2:
- Itemized risk score breakdown & LLM influence
- Simulated environment tables & independent verification engine
- Intentional state-breaking test expecting verification_failed
- RPA Queue API: claim, result, token rejection (401), double-claim / stale claim (409)
- Auto fallback after timeout with audit note
- Simulated Admin Console endpoints & element IDs
"""
import asyncio
import os
import sys
import tempfile
import time

tmp = tempfile.mkdtemp()
db_file = os.path.join(tmp, "test_rpa.db")
os.environ.update(
    DB_PATH=db_file,
    RPA_MODE="auto",
    RPA_CLAIM_TIMEOUT_S="0.2",
    RPA_TOKEN="secret-test-token",
    COLLECTOR_ENABLED="false",
    PRINT_EVENTS="false",
)

sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from app import config, db, response, risk, rpa_interface, verification
from app.main import app


def test_itemized_risk():
    inc = {
        "severity": "high",
        "timeline": [{"mitre_tactic": "Privilege Escalation (TA0004)"}],
    }
    investigation = {
        "verdict": "true_positive",
        "confidence": 0.9,
    }
    res = risk.score(inc, investigation, ["web-01"])
    assert "breakdown" in res, "breakdown list must be present in risk score"
    assert "llm_influence" in res, "llm_influence note must be present in risk score"
    breakdown = res["breakdown"]
    assert len(breakdown) == 4
    total_pts = sum(b["points"] for b in breakdown)
    assert total_pts == res["score"], f"breakdown sum {total_pts} must equal score {res['score']}"
    assert "points come from agent confidence" in res["llm_influence"]
    print("ok itemized risk breakdown")


def test_state_break_verification_failed():
    async def run():
        await db.init_db()
        # 1. Create a simulated action
        act = {
            "id": "ACT-TEST-FAIL",
            "incident_id": "INC-TEST",
            "type": "block_ip",
            "target": "198.51.100.1",
            "reason": "bad ip",
            "status": "executing",
            "mode": "auto",
            "mode_label": "AUTO_EXECUTE",
            "created_ts": time.time(),
            "decided_ts": None,
            "decided_by": None,
            "result": None,
            "executor": "builtin",
            "claim_time": time.time(),
            "finish_time": time.time(),
            "verification_status": None,
            "verification_detail": None,
            "recommended_next_step": None,
            "claim_id": None,
        }
        await db.insert_action(act)

        # 2. Simulate playbook writing row, but state breaks on purpose (delete the row)
        await db.add_blocked_ip("198.51.100.1", act["id"], "blocked")
        # Intentionally break the state before verification runs
        await db.remove_blocked_ip("198.51.100.1")

        # 3. Run verification engine independently
        verified = await verification.verify_action(act)
        assert verified["status"] == "verification_failed", f"expected verification_failed, got {verified['status']}"
        assert verified["verification_status"] == "failed"
        assert "not found in blocked_ips" in verified["verification_detail"]
        assert verified["recommended_next_step"] is not None
        print("ok intentional state break -> verification_failed")

    asyncio.run(run())


def test_rpa_api_and_console():
    with TestClient(app) as client:
        # 1. Check Console GET /console contains expected element IDs and banner
        r = client.get("/console")
        assert r.status_code == 200
        html = r.text
        assert "SIMULATED ADMIN CONSOLE - no real systems are changed" in html
        assert 'id="ip"' in html and 'id="block"' in html
        assert 'id="user"' in html and 'id="revoke"' in html
        assert 'id="title"' in html and 'id="create"' in html
        assert 'id="message"' in html and 'id="notify"' in html
        assert 'id="disable-user"' in html
        assert 'id="isolate-host"' in html
        print("ok console html and selectors")

        # 2. Token rejection (401)
        r = client.get("/rpa/queue/next")
        assert r.status_code == 401
        r = client.get("/rpa/queue/next", headers={"X-RPA-Token": "wrong-token"})
        assert r.status_code == 401
        print("ok token rejection 401")

        # 3. Console POST adds row to simulated state
        r = client.post("/console/block-ip", json={"ip": "203.0.113.99"})
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

        # 4. Queue claim and result flow
        # Insert a queued action in uipath mode
        async def insert_queued():
            act = {
                "id": "ACT-RPA-1",
                "incident_id": "INC-RPA",
                "type": "block_ip",
                "target": "203.0.113.99",
                "reason": "testing rpa",
                "status": "queued",
                "mode": "auto",
                "mode_label": "AUTO_EXECUTE",
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
            await db.insert_action(act)
        asyncio.run(insert_queued())

        # Bot claims action
        headers = {"X-RPA-Token": "secret-test-token"}
        r = client.get("/rpa/queue/next", headers=headers)
        assert r.status_code == 200
        claimed = r.json()
        assert claimed["id"] == "ACT-RPA-1"
        assert claimed["claim_id"].startswith("CLM-")
        claim_id = claimed["claim_id"]

        # Double claim test: trying to claim already claimed action returns 409
        r = client.post("/rpa/actions/ACT-RPA-1/claim", headers=headers)
        assert r.status_code == 409
        print("ok double claim rejection 409")

        # Bot submits result
        r = client.post(
            "/rpa/actions/ACT-RPA-1/result",
            headers=headers,
            json={"claim_id": claim_id, "status": "done", "detail": "IP blocked by bot"},
        )
        assert r.status_code == 200
        res = r.json()
        assert res["status"] == "verified"
        assert res["executor"] == "uipath"
        assert res["verification_status"] == "verified"
        print("ok bot claim/result flow and verification")

        # Stale claim submission: second submit with same claim_id returns 409
        r = client.post(
            "/rpa/actions/ACT-RPA-1/result",
            headers=headers,
            json={"claim_id": claim_id, "status": "done", "detail": "duplicate"},
        )
        assert r.status_code == 409
        print("ok stale claim rejection 409")

        # 5. Auto fallback timeout test
        async def test_fallback():
            act = {
                "id": "ACT-RPA-FALLBACK",
                "incident_id": "INC-FB",
                "type": "block_ip",
                "target": "198.51.100.77",
                "reason": "test fallback",
                "status": "pending_approval",
                "mode": "auto",
                "mode_label": "AUTO_EXECUTE",
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
            await db.insert_action(act)
            await rpa_interface.queue_action(act)
            # Wait for timeout (configured to 0.2s)
            await asyncio.sleep(0.4)
            updated = await db.get_action(act["id"])
            assert updated["executor"] == "builtin"
            assert updated["status"] == "verified"
            # Verify audit log includes fallback note
            audits = await db.list_audit(limit=10)
            fb_audits = [a for a in audits if "executed by builtin fallback (no bot claimed)" in a["detail"]]
            assert len(fb_audits) > 0, "audit log must record fallback execution"
            print("ok auto fallback after timeout with audit note")

        asyncio.run(test_fallback())


if __name__ == "__main__":
    test_itemized_risk()
    test_state_break_verification_failed()
    test_rpa_api_and_console()
    print("ALL RPA & VERIFICATION TESTS PASSED")
