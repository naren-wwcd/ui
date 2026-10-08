"""Attack injector: plays a 4-stage attack into the live queue, in real time, with delays.
Normal traffic keeps flowing the whole time. Triggered by POST /simulate/attack (or app/cli.py)."""
import asyncio
import random
import time
import uuid

from app import config
from app.bus import publish
from app.producers.traffic_gen import USERS

ATTACKERS = [("185.220.101.45", "RU"), ("45.155.205.233", "NL"),
             ("103.75.190.12", "CN"), ("196.251.88.21", "NG")]


def plan_attack(user: str | None = None) -> dict:
    """Pick the victim and attacker up front so the HTTP endpoint can return them immediately."""
    victim = user or random.choice(list(USERS))
    ip, country = random.choice(ATTACKERS)
    return {"attack_id": uuid.uuid4().hex[:8], "victim": victim, "host": USERS[victim]["host"],
            "attacker_ip": ip, "attacker_country": country}


def _event(plan: dict, action: str, nbytes: int, host: str | None = None) -> dict:
    return {"id": uuid.uuid4().hex[:12], "ts": time.time(), "user": plan["victim"],
            "ip": plan["attacker_ip"], "country": plan["attacker_country"],
            "host": host or plan["host"], "action": action, "bytes": nbytes, "source": "attack_injector"}


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds * config.ATTACK_DELAY_SCALE)


async def run_attack(plan: dict) -> None:
    # droppable=False: attack events must never be shed by backpressure, or the demo breaks.
    print(f">>> ATTACK {plan['attack_id']} started: {plan['attacker_ip']} ({plan['attacker_country']}) "
          f"-> user {plan['victim']}")

    print(">>> stage 1/4: brute-force failed logins")
    for _ in range(8):
        await publish(_event(plan, "login_failed", random.randint(200, 400)), droppable=False)
        await _sleep(random.uniform(0.3, 1.0))

    await _sleep(3)
    print(">>> stage 2/4: successful login from a new country")
    await publish(_event(plan, "login_success", random.randint(300, 700)), droppable=False)

    await _sleep(4)
    print(">>> stage 3/4: privilege escalation")
    await publish(_event(plan, "admin_group_add", 0), droppable=False)

    await _sleep(5)
    print(">>> stage 4/4: large data download")
    await publish(_event(plan, "file_download", random.randint(600_000_000, 900_000_000), host="file-01"),
                  droppable=False)
    print(f">>> ATTACK {plan['attack_id']} finished")


# ---------------- scenario 2: password spraying (separate from the 4-stage attack above) ----------------
SPRAY_TARGETS = 5   # users that fail; must equal config.SPRAY_MIN_USERS to trip the rule without also tripping brute force


def plan_spray() -> dict:
    """One attacker IP, one password, many users: 5 fail, a 6th account falls."""
    ip, country = random.choice(ATTACKERS)
    users = random.sample(list(USERS), SPRAY_TARGETS + 1)
    return {"attack_id": uuid.uuid4().hex[:8], "attacker_ip": ip, "attacker_country": country,
            "sprayed_users": users[:SPRAY_TARGETS], "compromised_user": users[SPRAY_TARGETS]}


def _spray_event(plan: dict, user: str, action: str) -> dict:
    return {"id": uuid.uuid4().hex[:12], "ts": time.time(), "user": user, "ip": plan["attacker_ip"],
            "country": plan["attacker_country"], "host": USERS[user]["host"], "action": action,
            "bytes": random.randint(200, 400), "source": "attack_injector"}


async def run_spray(plan: dict) -> None:
    print(f">>> SPRAY {plan['attack_id']} started from {plan['attacker_ip']} ({plan['attacker_country']})")
    print(f">>> one failed login each against {plan['sprayed_users']}")
    for user in plan["sprayed_users"]:                    # ONE attempt per user: spraying, not brute force
        await publish(_spray_event(plan, user, "login_failed"), droppable=False)
        await _sleep(random.uniform(0.3, 1.0))
    await _sleep(3)
    print(f">>> {plan['compromised_user']} used the sprayed password: successful login from {plan['attacker_country']}")
    await publish(_spray_event(plan, plan["compromised_user"], "login_success"), droppable=False)
    print(f">>> SPRAY {plan['attack_id']} finished")
