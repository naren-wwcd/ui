"""Cloud path test, no API key and no network (the agent uses its cached fallback).
Run from the project root:   python tests/test_cloudtrail.py [simulate|ingest]"""
import json, os, sys, tempfile, time
MODE = sys.argv[1] if len(sys.argv) > 1 else "simulate"
os.environ.update(DB_PATH=os.path.join(tempfile.mkdtemp(), "t.db"), COLLECTOR_ENABLED="false", ATTACK_DELAY_SCALE="0.1",
                  AGENT_DEBOUNCE_S="1", PRINT_EVENTS="false", ANTHROPIC_API_KEY="", LLM_API_KEY="")
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from app.main import app
from app.producers import cloudtrail_adapter as ca

# ---- adapter unit checks ----
recs = ca.load_sample(); events, stats = ca.to_events(recs)
assert stats["unsupported"] >= 3 and stats["invalid"] == 0 and len(events) == len({e["id"] for e in events}), stats
by = {}
for e in events: by.setdefault(e["action"], []).append(e)
assert {"login_success", "login_failed", "iam_create_access_key", "iam_attach_admin_policy", "iam_attach_policy",
        "cloudtrail_stop_logging", "s3_get_object"} <= set(by), set(by)
assert by["iam_attach_policy"][0]["host"] == "iam:dave"                       # ReadOnlyAccess is NOT privilege escalation
assert max(e["bytes"] for e in by["s3_get_object"]) > 900_000_000 and by["cloudtrail_stop_logging"][0]["host"] == "cloudtrail:company-trail"
assert [e["country"] for e in by["iam_create_access_key"]] == ["RU"]
assert ca.map_record({"eventName": "ListBuckets", "eventTime": "2026-10-07T09:30:00Z"}) is None
put = ca.map_record({"eventName": "PutUserPolicy", "eventTime": "2026-10-07T09:30:00Z", "eventSource": "iam.amazonaws.com",
                     "userIdentity": {"userName": "x"}, "sourceIPAddress": "1.2.3.4", "awsRegion": "eu-west-2", "requestParameters": {"userName": "x"}})
assert put["action"] == "iam_put_user_policy" and put["country"] == "GB"      # unknown IP -> country of the region
print("ok adapter:", stats)

WANT = {"new_country_login", "impossible_travel", "privilege_escalation", "defense_evasion", "large_data_transfer"}
with TestClient(app) as c:
    if MODE == "simulate":
        r = c.post("/simulate/cloud-attack"); assert r.status_code == 200, r.text; print("started:", r.json())
    else:
        assert c.post("/ingest/cloudtrail", content="not json").status_code == 400
        assert c.post("/ingest/cloudtrail", json={"x": 1}).status_code == 400
        r = c.post("/ingest/cloudtrail?rebase=true", json=recs); assert r.status_code == 200, r.text; print("ingested:", r.json())
        assert r.json()["ingested"] == len(events)
        time.sleep(2)                                                                          # let the first batch be stored
        again = c.post("/ingest/cloudtrail?rebase=true", json={"Records": recs}).json()      # CloudTrail file shape + duplicate send
        assert again["ingested"] == 0 and again["duplicates_skipped"] == len(events), again
    t0 = time.time(); inc = None
    while time.time() - t0 < 30:
        incs = c.get("/incidents").json()
        if incs and incs[0]["investigation"] and WANT <= set(incs[0]["alert_types"]) and incs[0]["investigation"]["alerts_considered"] >= 5:
            inc = incs[0]; break
        time.sleep(0.5)
    assert inc, [(i["id"], i["alert_types"], bool(i["investigation"])) for i in c.get("/incidents").json()]
    alerts = c.get("/alerts?limit=50").json()
    cloud = [a for a in alerts if a["user"] == "eve" or a["host"] and a["host"].split(":")[0] in ("s3", "iam", "cloudtrail", "sts")]
    assert {a["type"] for a in cloud} == WANT, {a["type"] for a in cloud}      # exactly these 5, and nothing from the noise
    assert len(c.get("/incidents").json()) == 1, "the cloud attack must be ONE incident"
    ev = {a["type"]: a for a in alerts}
    assert ev["defense_evasion"]["severity"] == "high" and ev["defense_evasion"]["mitre_tactic"].startswith("Defense Evasion")
    inv = inc["investigation"]; acts = c.get("/actions").json()
    pend = {(a["type"], a["target"]) for a in acts if a["status"] == "pending_approval"}
    print("INCIDENT", inc["id"], inc["severity"], "risk", inc["risk"]["score"], inc["alert_types"])
    print("TIMELINE", [(t["mitre_tactic"].split(" (")[0], t["type"]) for t in inc["timeline"]])
    print("INVESTIGATION", inv["source"], inv["verdict"], "| fallback_reason:", inv.get("fallback_reason"))
    print("PENDING", sorted(pend)); print("AUTO", sorted((a["type"], a["target"]) for a in acts if a["mode"] == "auto"))
    # A2: cloud resources cannot be isolated, so no isolate_host proposal may exist (pending or otherwise)
    assert ("disable_user", "eve") in pend, pend
    assert not [a for a in acts if a["type"] == "isolate_host"], [a for a in acts if a["type"] == "isolate_host"]
    dropped = [r for r in c.get("/audit?limit=200").json() if r["event"] == "action_dropped" and "isolate_host" in r["detail"]]
    assert dropped and "cannot be network-isolated" in dropped[0]["detail"], dropped
print("PASS cloud", MODE)
