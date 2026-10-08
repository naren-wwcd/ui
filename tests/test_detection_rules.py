"""Pure detection tests (no server, no LLM). Run from the project root:   python tests/test_detection_rules.py
Checks every new rule on its scenario, the Step 1 bug fixes, and that 20,000 normal events give 0 alerts."""
import os, sys, time, uuid
os.environ["COLLECTOR_ENABLED"] = "false"
sys.path.insert(0, os.getcwd())
from app import config, detection
from app.producers import traffic_gen

T0 = time.time()
def ev(action, user=None, ip=None, country=None, host="web-01", nbytes=0, dt=0.0, source="test"):
    return {"id": uuid.uuid4().hex[:12], "ts": T0 + dt, "user": user, "ip": ip, "country": country,
            "host": host, "action": action, "bytes": nbytes, "source": source}
def types(events): return [a["type"] for e in events for a in detection.detect(e)]

# --- bug 1: entity is never "user:None" ---
a = detection.detect(ev("sudo", user=None, host="db-09"))[0]
assert a["entity"] == "host:db-09", a["entity"]

# --- impossible travel ---
assert types([ev("login_success", "alice", "73.12.4.21", "US", dt=0)]) == []
t = types([ev("login_success", "alice", "1.2.3.4", "JP", dt=600)])
assert "impossible_travel" in t, t
assert "impossible_travel" not in types([ev("login_success", "alice", "73.12.4.21", "US", dt=700)]), "same pair must alert once"
assert "impossible_travel" not in types([ev("login_success", "bob", "98.45.101.7", "US", dt=0),
                                         ev("login_success", "bob", "9.9.9.9", "FR", dt=4000)]), "gap > 60 min"
print("ok impossible travel")

# --- password spraying ---
ip = "185.1.1.1"
fails = [ev("login_failed", u, ip, "RU", dt=i) for i, u in enumerate(["alice", "bob", "carol", "dave"])]
assert "password_spraying" not in types(fails), "4 users must not trigger"
out = detection.detect(ev("login_failed", "eve", ip, "RU", dt=5))
assert [a["type"] for a in out] == ["password_spraying"], [a["type"] for a in out]   # brute force must NOT also fire (5 failures)
assert out[0]["user"] is None and out[0]["entity"] == f"ip:{ip}" and len(out[0]["evidence_event_ids"]) == 5
ip2 = "185.2.2.2"
assert "password_spraying" not in types([ev("login_failed", "alice", ip2, "RU", dt=i) for i in range(5)]), "one user repeatedly = not spraying"
print("ok password spraying")

# --- off-hours (disabled by default) ---
night = time.mktime((2026, 10, 7, 3, 0, 0, 0, 0, -1)); day = time.mktime((2026, 10, 7, 11, 0, 0, 0, 0, -1))  # a Wednesday
def at(ts, user): e = ev("login_success", user, "73.12.4.21", "US"); e["ts"] = ts; return e
assert not config.OFF_HOURS_ENABLED and "off_hours_login" not in types([at(night, "alice")]), "must be off by default"
config.OFF_HOURS_ENABLED = True
assert "off_hours_login" in types([at(night + 1, "bob")]) and "off_hours_login" not in types([at(day, "carol")])
assert [a for a in detection.detect(at(night + 5000, "dave")) if a["type"] == "off_hours_login"][0]["severity"] == "low"
config.OFF_HOURS_ENABLED = False
print("ok off-hours")

# --- cryptominer ---
h = "web-77"
assert types([ev("cpu_spike:97pct", host=h, dt=0)]) == [], "spike alone"
out = detection.detect(ev("process_start:xmrig", user="www", host=h, dt=30))
assert [a["type"] for a in out] == ["cryptominer"] and len(out[0]["evidence_event_ids"]) == 2 and out[0]["entity"] == f"host:{h}"
assert types([ev("process_start:xmrig", host="web-78", dt=0), ev("cpu_spike:99pct", host="web-78", dt=200)]) == [], "> 2 min apart"
assert types([ev("cpu_spike:99pct", host="web-79", dt=0), ev("process_start:bash", host="web-79", dt=5)]) == [], "ignored process"
assert "cryptominer" in types([ev("process_start:kworkerds", host="web-80", dt=0), ev("cpu_spike:99pct", host="web-80", dt=20)]), "process first, then spike"
print("ok cryptominer")

# --- bug 2: baseline learns only from normal events ---
u = "heidi"; before = list(detection.baseline_bytes[u])
detection.detect(ev("login_failed", u, "73.1.1.1", "US", nbytes=9000))                  # failed login
detection.detect(ev("file_access", u, "185.9.9.9", "RU", host="file-01", nbytes=400000))  # event from an unusual country
assert detection.baseline_bytes[u] == before, "baseline must not change"
detection.detect(ev("file_access", u, "24.18.200.5", "US", host="file-01", nbytes=1000, dt=10_000))   # normal, long after any alert
assert detection.baseline_bytes[u][0] == before[0] + 1
print("ok baseline")

# --- normal traffic: 20,000 events (~17 simulated minutes) must raise 0 alerts ---
detection.last_login.clear(); detection._last_alert.clear()
alerts = []
for i in range(20000):
    e = traffic_gen.make_normal_event(); e["ts"] = T0 + 50_000 + i * 0.05
    alerts += detection.detect(e)
assert not alerts, [(a["type"], a["entity"]) for a in alerts[:5]]
print("ok 20,000 normal events -> 0 alerts")
