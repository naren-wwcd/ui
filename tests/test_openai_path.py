"""Tests the OpenAI-compatible provider path (Gemini/Groq/...) with the REAL openai SDK against a local fake server.
Run from the project root:   python tests/test_openai_path.py [good|invented_id|http_error]"""
import json, os, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCENARIO = sys.argv[1] if len(sys.argv) > 1 else "good"
seen = {"requests": 0, "bad_shape": []}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        seen["requests"] += 1
        if SCENARIO == "http_error":
            self.send_response(429); self.end_headers(); self.wfile.write(b'{"error":{"message":"quota"}}'); return
        msgs = body["messages"]
        assert msgs[0]["role"] == "system"
        for m in msgs:                                    # every message must be a plain, API-valid shape
            if m["role"] == "tool" and not m.get("tool_call_id"): seen["bad_shape"].append(m)
            if m["role"] == "assistant" and "tool_calls" in m and not all(t.get("id") and t["function"]["name"] for t in m["tool_calls"]):
                seen["bad_shape"].append(m)
        assert body["tools"][0]["type"] == "function" and "parameters" in body["tools"][0]["function"]
        inc = json.loads(msgs[1]["content"].split("INCIDENT:\n")[1].split("\n\nFirst investigate")[0])
        ev = [i for t in inc["alert_timeline"] for i in t["evidence_event_ids"]]; obs = inc["observed"]
        has_tool_result = any(m["role"] == "tool" for m in msgs)
        retried = any(m["role"] == "user" and "problems" in str(m["content"]) for m in msgs)
        if not has_tool_result:
            msg = {"role": "assistant", "content": None, "tool_calls": [
                {"id": f"call_{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}}
                for i, (n, a) in enumerate([("check_ip_reputation", {"ip": obs["ips"][0]}), ("get_asset_info", {"host": obs["hosts"][0]}),
                                            ("get_user_history", {"user": obs["users"][0]}),
                                            ("get_related_events", {"entity": "user:" + obs["users"][0], "minutes": 30})])]}
        else:
            ids = ev[:2] + (["deadbeef0000"] if SCENARIO == "invented_id" and not retried else [])
            final = {"verdict": "true_positive", "confidence": 0.9, "summary": "Credential compromise.",
                     "attack_timeline": [{"time": "12:00:00", "tactic": "Credential Access (TA0006)", "description": "x", "event_ids": ids}],
                     "key_evidence": [{"event_id": i, "why": "w"} for i in ids],
                     "recommended_actions": [{"action": "block_ip", "target": obs["ips"][0], "reason": "bad ip"},
                                             {"action": "disable_user", "target": obs["users"][0], "reason": "compromised"},
                                             {"action": "open_ticket", "target": inc["incident_id"], "reason": "track"}]}
            msg = {"role": "assistant", "content": "```json\n" + json.dumps(final) + "\n```"}   # fences on purpose
        out = {"id": "x", "object": "chat.completion", "created": 0, "model": body["model"],
               "choices": [{"index": 0, "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop", "message": msg}]}
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = tempfile.mkdtemp()
os.environ.update(ANTHROPIC_API_KEY="", LLM_API_KEY="fake", LLM_BASE_URL=f"http://127.0.0.1:{srv.server_port}/v1/",
                  LLM_MODEL="gemini-2.5-flash", LLM_NAME="gemini", DB_PATH=os.path.join(tmp, "t.db"),
                  COLLECTOR_ENABLED="false", ATTACK_DELAY_SCALE="0.05", AGENT_DEBOUNCE_S="1", PRINT_EVENTS="false", AGENT_TIMEOUT_S="20")
os.environ.pop("ANTHROPIC_API_KEY")
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as c:
    assert c.post("/simulate/attack?user=alice").status_code == 200
    t0 = time.time(); inc = None
    while time.time() - t0 < 25:
        incs = c.get("/incidents").json()
        if incs and incs[0].get("investigation") and incs[0]["investigation"]["alerts_considered"] >= 4:
            inc = incs[0]; break
        time.sleep(0.5)
    assert inc, "no fully investigated incident"
    inv = inc["investigation"]
    print("RESULT", {k: inv.get(k) for k in ("source", "model", "tool_calls", "validation", "verdict", "fallback_reason")})
    print("ACTIONS", [(a["type"], a["target"], a["status"], a["mode"]) for a in c.get("/actions").json()])
    print("HTTP REQUESTS", seen["requests"], "BAD MESSAGE SHAPES", seen["bad_shape"])
