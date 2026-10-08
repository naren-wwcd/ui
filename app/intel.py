"""Tiny loaders for the mock threat-intel and asset inventory files (shared by agent and risk)."""
import json
from functools import lru_cache

from app import config


@lru_cache(maxsize=None)
def _load(name: str) -> dict:
    try:
        return json.loads((config.DATA_DIR / name).read_text())
    except Exception:
        return {}


def get_ip_reputation(ip: str) -> dict:
    entry = _load("threat_intel.json").get(ip)
    return {"ip": ip, **entry} if entry else {"ip": ip, "reputation": "unknown", "note": "not in the threat-intel feed"}


def get_asset(host: str) -> dict:
    assets = _load("assets.json")
    entry = assets.get(host) or assets.get(str(host).split(":", 1)[0])   # "iam:bob" -> the generic "iam" record
    return {"host": host, **entry} if entry else {"host": host, "criticality": "unknown", "note": "not in the asset inventory"}
