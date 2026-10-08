"""Tests for the tamper-evident hash-chained audit log.
Verifies chain computation, old row handling, and tamper detection.

NOTE: This system is tamper-evident, not immutable.
Any modification to historical audit entries breaks the cryptographic hash chain.
"""
import os
import sqlite3
import sys
import tempfile
import time

tmp_db = os.path.join(tempfile.mkdtemp(), "test_audit.db")
os.environ.update(
    DB_PATH=tmp_db,
    COLLECTOR_ENABLED="false",
    PRINT_EVENTS="false",
    ANTHROPIC_API_KEY="",
    LLM_API_KEY="",
)
sys.path.insert(0, os.getcwd())

from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as client:
    # 1. Verification with empty/initial state (tamper-evident)
    res = client.get("/audit/verify").json()
    assert res["valid"] is True
    print("ok initial chain verify:", res)

    # 2. Add an old row without hashes directly via sqlite to test "old rows without hashes start the chain"
    con = sqlite3.connect(tmp_db)
    con.execute(
        "INSERT INTO audit_log (ts, actor, event, action, incident_id, action_id, detail, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
        (time.time() - 100, "legacy", "system_init", "system_init", None, None, "legacy unhashed event"),
    )
    con.commit()
    con.close()

    res = client.get("/audit/verify").json()
    assert res["valid"] is True
    print("ok unhashed legacy row starts chain cleanly:", res)

    # 3. Create chained audit entries through application actions
    client.post("/console/block-ip", json={"ip": "198.51.100.22"})
    client.post("/console/revoke-session", json={"user": "bob"})
    client.post("/console/create-ticket", json={"title": "Test Incident Ticket"})

    # Check that audit log has entries with hashes
    audit_rows = client.get("/audit?limit=10").json()
    assert len(audit_rows) >= 3
    for r in audit_rows[:3]:
        assert r.get("hash"), f"Row {r['id']} missing hash"

    # 4. Verify that the tamper-evident chain recomputes valid=True
    res = client.get("/audit/verify").json()
    assert res["valid"] is True
    assert res["entries"] >= 3
    assert res["first_broken_id"] is None
    print(f"ok tamper-evident chain verified with {res['entries']} entries")

    # 5. Tamper with a row directly in SQLite
    target_row = audit_rows[1]  # tamper with the second newest row
    tampered_id = target_row["id"]
    con = sqlite3.connect(tmp_db)
    con.execute("UPDATE audit_log SET detail = ? WHERE id = ?", ("Tampered unauthorized modification", tampered_id))
    con.commit()
    con.close()

    # 6. Verify that tampering is detected: valid=false and first_broken_id matches
    res_tampered = client.get("/audit/verify").json()
    assert res_tampered["valid"] is False, "Tampered row must invalidate chain"
    assert res_tampered["first_broken_id"] == tampered_id, f"Expected broken id {tampered_id}, got {res_tampered['first_broken_id']}"
    print(f"ok tamper detected correctly: valid=False, first_broken_id={res_tampered['first_broken_id']}")

print("ALL TAMPER-EVIDENT AUDIT CHAIN TESTS PASSED")
