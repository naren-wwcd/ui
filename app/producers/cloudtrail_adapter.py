"""AWS CloudTrail adapter: maps CloudTrail JSON records to the one event schema
{id, ts, user, ip, country, host, action, bytes, source}, so the EXISTING detection rules work on cloud logs.

  CloudTrail event                          -> action (what the rules see)
  ConsoleLogin  (Success / Failure)         -> login_success / login_failed
  GetCallerIdentity (first call of a key)   -> login_success   (an access key being used = an authenticated session)
  CreateAccessKey                           -> iam_create_access_key     (privilege escalation)
  AttachUserPolicy (AdministratorAccess..)  -> iam_attach_admin_policy   (privilege escalation)
  AttachUserPolicy (any other policy)       -> iam_attach_policy         (harmless, no alert)
  PutUserPolicy                             -> iam_put_user_policy       (privilege escalation)
  StopLogging                               -> cloudtrail_stop_logging   (defense evasion, own rule)
  GetObject (bytes = bytesTransferredOut)   -> s3_get_object             (large-transfer rule)
Anything else (ListBuckets, DescribeInstances, ...) is skipped and counted. host = the cloud resource or service,
e.g. s3:company-data, iam:eve, cloudtrail:company-trail, aws-console."""
import asyncio
import ipaddress
import json
import time
import uuid
from datetime import datetime

from app import config
from app.bus import publish
from app.producers.attack_injector import ATTACKERS
from app.producers.traffic_gen import USERS

SAMPLE_FILE = config.DATA_DIR / "sample_cloudtrail.json"
ADMIN_POLICIES = {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess"}   # attaching these = privilege escalation

# --- country lookup: exact source IP first (small table), else the AWS region the call was made in ---
IP_COUNTRY = {ip: p["country"] for p in USERS.values() for ip in p["ips"]}    # the users' usual IPs
IP_COUNTRY.update({ip: c for ip, c in ATTACKERS})                              # the known attacker IPs
IP_COUNTRY.update({"91.240.118.172": "RU"})                                    # attacker IP used by the sample cloud attack
REGION_COUNTRY = {
    "us-east-1": "US", "us-east-2": "US", "us-west-1": "US", "us-west-2": "US", "ca-central-1": "CA",
    "eu-west-1": "IE", "eu-west-2": "GB", "eu-west-3": "FR", "eu-central-1": "DE", "eu-north-1": "SE",
    "ap-south-1": "IN", "ap-southeast-1": "SG", "ap-southeast-2": "AU", "ap-northeast-1": "JP",
    "ap-northeast-2": "KR", "sa-east-1": "BR", "me-south-1": "BH", "af-south-1": "ZA",
}


def _user(ident: dict) -> str | None:
    """Who did it: IAM user name, 'root', or role/session for assumed roles."""
    name = ident.get("userName")
    if not name and ident.get("type") == "Root":
        name = "root"
    if not name and ":assumed-role/" in str(ident.get("arn", "")):
        name = str(ident["arn"]).split(":assumed-role/", 1)[1]          # RoleName/session
    name = name or ident.get("invokedBy") or ident.get("principalId")
    if not name or str(name).upper().startswith("HIDDEN_DUE_TO"):         # CloudTrail hides names of failed logins
        return None
    return str(name)


def _ip(rec: dict) -> str | None:
    """Only real IPs count ('AWS Internal' / 'cloudtrail.amazonaws.com' are not an attacker address)."""
    try:
        return str(ipaddress.ip_address(rec.get("sourceIPAddress")))
    except ValueError:
        return None


def _ts(rec: dict) -> float:
    return datetime.fromisoformat(rec["eventTime"].replace("Z", "+00:00")).timestamp()


def map_record(rec: dict) -> dict | None:
    """One CloudTrail record -> one event, or None if this event type is not supported."""
    name = rec.get("eventName")
    src = str(rec.get("eventSource", "")).split(".")[0]                   # s3, iam, signin, cloudtrail, sts
    params = rec.get("requestParameters") or {}
    extra = rec.get("additionalEventData") or {}
    resp = rec.get("responseElements") or {}
    ident = rec.get("userIdentity") or {}
    actor = _user(ident)
    host, nbytes, action = src or "aws", 0, None

    if name == "ConsoleLogin":
        result = str(resp.get("ConsoleLogin") or extra.get("ConsoleLogin") or "").lower()
        action = {"success": "login_success", "failure": "login_failed"}.get(result)
        host = "aws-console"
    elif rec.get("errorCode"):
        return None                                                        # the call was denied: nothing happened
    elif name == "GetCallerIdentity":
        action, host = "login_success", "sts"
    elif name == "CreateAccessKey":
        action, host = "iam_create_access_key", f"iam:{params.get('userName') or actor}"
    elif name == "AttachUserPolicy":
        policy = str(params.get("policyArn", "")).rsplit("/", 1)[-1]
        action = "iam_attach_admin_policy" if policy in ADMIN_POLICIES else "iam_attach_policy"
        host = f"iam:{params.get('userName') or actor}"
    elif name == "PutUserPolicy":
        action, host = "iam_put_user_policy", f"iam:{params.get('userName') or actor}"
    elif name == "StopLogging":
        action, host = "cloudtrail_stop_logging", f"cloudtrail:{str(params.get('name', 'unknown')).rsplit('/', 1)[-1]}"
    elif name == "GetObject":
        action, host = "s3_get_object", f"s3:{params.get('bucketName', 'unknown')}"
        nbytes = int(extra.get("bytesTransferredOut") or 0)
    if action is None:
        return None

    ip = _ip(rec)
    eid = str(rec.get("eventID", "")).replace("-", "")[:12] or uuid.uuid4().hex[:12]
    return {"id": eid, "ts": _ts(rec), "user": actor, "ip": ip,
            "country": IP_COUNTRY.get(ip) or REGION_COUNTRY.get(rec.get("awsRegion")),
            "host": host, "action": action, "bytes": nbytes, "source": "cloudtrail"}


def to_events(records: list, rebase: bool = False) -> tuple[list[dict], dict]:
    """Map many records (sorted by eventTime). rebase=True shifts all timestamps so the last record is 'now'
    (use it for old sample files, so the agent's 'last N minutes' tools can see the events)."""
    events, stats = [], {"received": len(records), "mapped": 0, "unsupported": 0, "invalid": 0}
    for rec in records:
        try:
            e = map_record(rec)
        except Exception:                                                  # one malformed record must not stop the batch
            stats["invalid"] += 1
            continue
        if e is None:
            stats["unsupported"] += 1
        else:
            events.append(e)
    events.sort(key=lambda e: e["ts"])
    if rebase and events:
        shift = time.time() - events[-1]["ts"]
        for e in events:
            e["ts"] += shift
    stats["mapped"] = len(events)
    return events, stats


def load_sample() -> list[dict]:
    return json.loads(SAMPLE_FILE.read_text())


def sample_meta(records: list) -> dict:
    """Victim and attacker of the sample attack = whoever makes the first GetCallerIdentity call."""
    first = next(r for r in records if r.get("eventName") == "GetCallerIdentity")
    ip = first["sourceIPAddress"]
    return {"victim": first["userIdentity"]["userName"], "attacker_ip": ip,
            "attacker_country": IP_COUNTRY.get(ip) or REGION_COUNTRY.get(first.get("awsRegion"))}


async def replay(events: list[dict]) -> None:
    """Feed events into the live queue with the SAME gaps as in the file (x ATTACK_DELAY_SCALE), stamped 'now'.
    Fresh ids each time, so the demo can be run again and again. droppable=False: never shed by backpressure."""
    events = sorted(events, key=lambda e: e["ts"])
    if not events:
        return
    t0, start = events[0]["ts"], time.monotonic()
    print(f">>> CLOUD ATTACK replay started ({len(events)} events)")
    for e in events:
        wait = (e["ts"] - t0) * config.ATTACK_DELAY_SCALE - (time.monotonic() - start)
        if wait > 0:
            await asyncio.sleep(wait)
        await publish({**e, "id": uuid.uuid4().hex[:12], "ts": time.time()}, droppable=False)
    print(">>> CLOUD ATTACK replay finished")
