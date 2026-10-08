"""Offline check of the REAL Claude code path using a scripted fake Anthropic client (no API key, no network).
Run from the project root:   python tests/test_claude_path.py
Scenarios: good (tools + valid JSON), invented_id (retry then ok), always_bad_id (ids stripped), api_error (fallback)."""
import json, os, re, sys, tempfile, time
from types import SimpleNamespace as NS

SCENARIO = sys.argv[1] if len(sys.argv) > 1 else "good"
tmp = tempfile.mkdtemp()
os.environ.update(ANTHROPIC_API_KEY="sk-fake", DB_PATH=os.path.join(tmp, "t.db"), COLLECTOR_ENABLED="false",
                  ATTACK_DELAY_SCALE="0.05", AGENT_DEBOUNCE_S="1", PRINT_EVENTS="false", AGENT_TIMEOUT_S="20")
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from app import agent
from app.main import app

calls = {"n": 0}


def text(t): return NS(type="text", text=t)
def tool(i, name, inp): return NS(type="tool_use", id=f"tu_{i}", name=name, input=inp)


class FakeMessages:
    async def create(self, **kw):
        calls["n"] += 1
        msgs = kw["messages"]
        if SCENARIO == "api_error":
            raise RuntimeError("simulated 529 overloaded")
        prompt = msgs[0]["content"]
        inc = json.loads(prompt.split("INCIDENT:\n")[1].split("\n\nFirst investigate")[0])
        ev = [i for t in inc["alert_timeline"] for i in t["evidence_event_ids"]]
        obs = inc["observed"]
        n_tool_results = sum(1 for m in msgs if m["role"] == "user" and isinstance(m["content"], list))
        last = msgs[-1]["content"]
        if n_tool_results == 0:
            return NS(stop_reason="tool_use", content=[
                tool(1, "check_ip_reputation", {"ip": obs["ips"][0]}),
                tool(2, "get_asset_info", {"host": obs["hosts"][0]}),
                tool(3, "get_user_history", {"user": obs["users"][0]}),
                tool(4, "get_related_events", {"entity": f"user:{obs['users'][0]}", "minutes": 30})])
        bad = SCENARIO == "always_bad_id" or (SCENARIO == "invented_id" and isinstance(last, list))
        ids = ev[:2] + (["deadbeef0000"] if bad else [])
        final = {"verdict": "true_positive", "confidence": 0.93, "summary": "Credential compromise.",
                 "attack_timeline": [{"time": "12:00:00", "tactic": "Credential Access (TA0006)", "description": "x", "event_ids": ids}],
                 "key_evidence": [{"event_id": i, "why": "w"} for i in ids],
                 "recommended_actions": [
                     {"action": "block_ip", "target": obs["ips"][0], "reason": "malicious ip"},
                     {"action": "disable_user", "target": obs["users"][0], "reason": "compromised"},
                     {"action": "isolate_host", "target": obs["hosts"][0], "reason": "priv esc"},
                     {"action": "open_ticket", "target": inc["incident_id"], "reason": "track"}]}
        return NS(stop_reason="end_turn", content=[text(json.dumps(final))])


agent._get_client = lambda: NS(messages=FakeMessages())

with TestClient(app) as c:
    r = c.post("/simulate/attack?user=alice"); assert r.status_code == 200, r.text
    t0 = time.time(); inc = None
    while time.time() - t0 < 25:
        incs = c.get("/incidents").json()
        if incs and incs[0].get("investigation") and "tool_calls" in incs[0]["investigation"]:
            inc = incs[0]
            if inc["investigation"]["alerts_considered"] >= 4: break
        time.sleep(0.5)
    assert inc, "no investigated incident"
    inv = inc["investigation"]
    print("RESULT", {k: inv.get(k) for k in ("source", "tool_calls", "validation", "verdict", "confidence", "fallback_reason", "alerts_considered")})
    print("RISK", inc["risk"]["score"], inc["risk"]["level"], inc["risk"]["justification"])
    acts = c.get("/actions").json()
    print("ACTIONS", [(a["type"], a["target"], a["status"], a["mode"]) for a in acts])
    print("FAKE API CALLS", calls["n"])
