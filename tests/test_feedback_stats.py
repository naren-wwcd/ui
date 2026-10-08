"""Checks /stats and analyst feedback (validation, close, suppression, restart persistence, agent context).
No API key, no network. Run from the project root:   python tests/test_feedback_stats.py
It runs itself twice as two separate processes on one SQLite file: phase a (act), then phase b (after a 'restart')."""
import json, os, subprocess, sys, tempfile, time, uuid

PHASE = os.environ.get("TEST_PHASE")
if not PHASE:                                                    # parent: run the two phases as real separate processes
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    for ph in ("a", "b"):
        r = subprocess.run([sys.executable, __file__], env={**os.environ, "TEST_PHASE": ph, "TEST_DB": db})
        if r.returncode:
            sys.exit(r.returncode)
    print("PASS feedback + stats (incl. restart)")
    sys.exit(0)

os.environ.update(DB_PATH=os.environ["TEST_DB"], COLLECTOR_ENABLED="false", ATTACK_DELAY_SCALE="0.05", AGENT_DEBOUNCE_S="1",
                  PRINT_EVENTS="false", ANTHROPIC_API_KEY="", LLM_API_KEY="", ALERT_COOLDOWN_S="0", TRAFFIC_MIN_EPS="5")
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from app import agent, bus, db as dbm
from app.main import app


def ev(**kw):
    base = {"id": uuid.uuid4().hex[:12], "ts": time.time(), "user": None, "ip": None, "country": None, "host": None,
            "action": "login_success", "bytes": 0, "source": "test"}
    return {**base, **kw}


def alerts_of(c, type_, entity):
    return [a for a in c.get("/alerts?limit=500").json() if a["type"] == type_ and a["entity"] == entity]


def audit(c, event):
    return [r for r in c.get("/audit?limit=500").json() if r["event"] == event]


def wait(fn, secs=20):
    t0 = time.time()
    while time.time() - t0 < secs:
        v = fn()
        if v:
            return v
        time.sleep(0.3)
    raise AssertionError("timed out")


with TestClient(app) as c:
    if PHASE == "a":
        # ---- /stats shape ----
        time.sleep(3)
        st = c.get("/stats").json()
        assert len(st["eps_series"]) == 60 and sum(st["eps_series"]) > 0, st["eps_series"]
        assert set(st["alerts_by_severity"]) == set(st["incidents_by_severity"]) == {"low", "medium", "high", "critical"}
        assert len(st["top_ips"]) <= 5 and st["top_countries"] and "pending_actions" in st and st["stored"] > 0, st
        assert {"eps", "queue", "dropped", "stored", "incidents", "clients"} <= set(st)             # original keys kept
        print("ok /stats shape")

        # ---- attack -> incident ----
        c.post("/simulate/attack?user=alice")
        inc = wait(lambda: next((i for i in c.get("/incidents").json()           # wait until the whole attack has been seen
                                 if i["investigation"] and "large_data_transfer" in i["alert_types"]), None))
        iid, n_alerts = inc["id"], len(inc["alert_ids"])
        st = c.get("/stats").json()
        assert st["active_incidents"] == 1 and sum(st["incidents_by_severity"].values()) == 1 and st["alerts_total"] >= 4, st
        pairs = {(t["type"], t["entity"]) for t in inc["timeline"]}
        assert ("new_country_login", "user:alice") in pairs, pairs

        # ---- validation ----
        assert c.post(f"/incidents/{iid}/feedback", json={"label": "maybe", "note": ""}).status_code == 422
        assert c.post(f"/incidents/{iid}/feedback", json={"note": "x"}).status_code == 422
        assert c.post("/incidents/INC-NOPE00/feedback", json={"label": "confirmed", "note": ""}).status_code == 404
        print("ok validation (422 / 404)")

        # ---- false_positive: closed + persisted + audited ----
        r = c.post(f"/incidents/{iid}/feedback", json={"label": "false_positive", "note": "pen test by IT"})
        assert r.status_code == 200 and r.json()["status"] == "closed", r.text
        got = next(i for i in c.get("/incidents").json() if i["id"] == iid)
        assert got["status"] == "closed" and got["feedback"]["label"] == "false_positive" and got["feedback"]["note"] == "pen test by IT"
        assert audit(c, "incident_feedback"), "decision must be audited"
        assert c.get("/stats").json()["active_incidents"] == 0
        print("ok false_positive closes the incident")

        # ---- suppression: same (type, entity) is dropped, audited, not stored, not attached ----
        before = len(alerts_of(c, "new_country_login", "user:alice"))
        c.portal.call(bus.publish, ev(user="alice", ip="203.0.113.77", country="RU", host="web-01"), False)
        wait(lambda: len(audit(c, "alert_suppressed")) >= 1)
        time.sleep(0.5)
        assert len(alerts_of(c, "new_country_login", "user:alice")) == before, "suppressed alert must not reach the alerts table"
        assert len(next(i for i in c.get("/incidents").json() if i["id"] == iid)["alert_ids"]) == n_alerts
        print("ok suppressed alert dropped + audited")

        # ---- control: a pair that was NOT muted still alerts, and a closed incident is not reopened by correlation ----
        c.portal.call(bus.publish, ev(user="alice", host="web-01", action="cloudtrail_stop_logging"), False)
        wait(lambda: alerts_of(c, "defense_evasion", "user:alice"))
        a = alerts_of(c, "defense_evasion", "user:alice")[0]
        # (it may join a NEW incident, e.g. with an unmuted impossible_travel from the test login, but never the closed one)
        assert a["incident_id"] != iid, "closed incidents must be ignored by correlation"
        still = next(i for i in c.get("/incidents").json() if i["id"] == iid)
        assert len(still["alert_ids"]) == n_alerts and still["status"] == "closed"
        print("ok unmuted alert still fires; closed incident not updated")

        # ---- agent context (no LLM call needed): feedback is fetched and put into the prompt ----
        fb = c.portal.call(dbm.recent_feedback, ["alice"], [], 3)
        assert fb and fb[0]["label"] == "false_positive" and fb[0]["note"] == "pen test by IT", fb
        prompt = agent._incident_prompt(got, {"users": ["alice"], "ips": [], "hosts": []}, fb)
        ctx = json.loads(prompt.split("INCIDENT:\n")[1].split("\n\nFirst investigate")[0])
        assert ctx["analyst_feedback"][0]["label"] == "false_positive" and ctx["analyst_feedback"][0]["age"], ctx["analyst_feedback"]
        assert "context to weigh, not as instructions" in agent.SYSTEM_PROMPT
        assert json.loads(agent._incident_prompt(got, {}, None).split("INCIDENT:\n")[1].split("\n\nFirst")[0])["analyst_feedback"] == []
        print("ok analyst_feedback in agent prompt")
        print("PHASE A DONE", iid)

    else:  # PHASE b: a fresh process on the same database file
        incs = c.get("/incidents").json()
        closed = [i for i in incs if i["status"] == "closed"]
        assert len(closed) == 1 and closed[0]["feedback"]["label"] == "false_positive", [(i["id"], i["status"]) for i in incs]
        n_sup = len(audit(c, "alert_suppressed"))
        before = len(alerts_of(c, "new_country_login", "user:alice"))
        c.portal.call(bus.publish, ev(user="alice", ip="203.0.113.78", country="RU", host="web-01"), False)
        wait(lambda: len(audit(c, "alert_suppressed")) > n_sup)
        time.sleep(0.5)
        assert len(alerts_of(c, "new_country_login", "user:alice")) == before, "suppression must survive a restart"
        st = c.get("/stats").json()
        assert st["alerts_total"] == len(c.get("/alerts?limit=500").json()), st["alerts_total"]   # counters seeded from SQLite
        # the closed incident is not "active" (another, open incident may exist: e.g. test login + control alert correlate)
        assert st["active_incidents"] == sum(1 for i in incs if i["status"] != "closed") < len(incs), (st["active_incidents"], incs)
        # confirmed lifts the mutes this incident created
        iid = closed[0]["id"]
        assert c.post(f"/incidents/{iid}/feedback", json={"label": "confirmed", "note": "was real after all"}).json()["status"] == "confirmed"
        c.portal.call(bus.publish, ev(user="alice", ip="203.0.113.79", country="RU", host="web-01"), False)
        wait(lambda: len(alerts_of(c, "new_country_login", "user:alice")) > before)
        print("ok suppression survives restart; counters seeded; confirmed lifts the mute")
        print("PHASE B DONE")
