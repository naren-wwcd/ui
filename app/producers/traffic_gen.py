"""Live traffic generator: continuous random normal activity at 5-20 events/sec."""
import asyncio
import random
import time
import uuid

from app import config
from app.bus import publish

# Each user has a home country, a few usual IPs, and a usual host.
# (Later, detection builds its "baseline" from this behaviour.)
USERS = {
    "alice":   {"country": "US", "ips": ["73.12.4.21", "73.12.4.22"],     "host": "web-01"},
    "bob":     {"country": "US", "ips": ["98.45.101.7"],                   "host": "db-01"},
    "carol":   {"country": "GB", "ips": ["81.2.69.142", "81.2.69.150"],    "host": "web-02"},
    "dave":    {"country": "DE", "ips": ["85.214.132.9"],                  "host": "app-01"},
    "eve":     {"country": "IN", "ips": ["49.204.18.33", "49.204.18.40"],  "host": "app-02"},
    "frank":   {"country": "CA", "ips": ["142.112.55.3"],                  "host": "web-01"},
    "grace":   {"country": "AU", "ips": ["203.0.113.77"],                  "host": "db-01"},
    "heidi":   {"country": "US", "ips": ["24.18.200.5"],                   "host": "file-01"},
}

# (action, relative weight, typical bytes range)
ACTIONS = [
    ("login_success", 25, (200, 800)),
    ("file_access",   35, (1_000, 500_000)),
    ("api_call",      35, (300, 20_000)),
    ("login_failed", 0.2, (200, 400)),  # rare normal noise (typo'd passwords)
]


def make_normal_event() -> dict:
    user = random.choice(list(USERS))
    profile = USERS[user]
    action, _, (lo, hi) = random.choices(ACTIONS, weights=[a[1] for a in ACTIONS])[0]
    return {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "user": user,
        "ip": random.choice(profile["ips"]),
        "country": profile["country"],
        "host": profile["host"],
        "action": action,
        "bytes": random.randint(lo, hi),
        "source": "traffic_gen",
    }


async def run() -> None:
    """Emit events forever; the target rate drifts between min and max EPS."""
    rate = random.uniform(config.TRAFFIC_MIN_EPS, config.TRAFFIC_MAX_EPS)
    next_rate_change = time.monotonic() + 5
    while True:
        await publish(make_normal_event())
        # Exponential gaps give natural, bursty-looking arrivals at ~rate/sec
        await asyncio.sleep(random.expovariate(rate))
        if time.monotonic() > next_rate_change:
            rate = random.uniform(config.TRAFFIC_MIN_EPS, config.TRAFFIC_MAX_EPS)
            next_rate_change = time.monotonic() + 5
