"""All settings live here. Values come from .env (or the environment)."""
import os
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
DB_PATH = os.getenv("DB_PATH", "security.db")
QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", "1000"))
TRAFFIC_MIN_EPS = float(os.getenv("TRAFFIC_MIN_EPS", "5"))
TRAFFIC_MAX_EPS = float(os.getenv("TRAFFIC_MAX_EPS", "20"))
PRINT_EVENTS = os.getenv("PRINT_EVENTS", "true").lower() == "true"

# --- Step 2: detection rules ---
FAILED_LOGIN_THRESHOLD = int(os.getenv("FAILED_LOGIN_THRESHOLD", "5"))      # alert when count is MORE than this
FAILED_LOGIN_WINDOW_S = int(os.getenv("FAILED_LOGIN_WINDOW_S", "120"))
TRANSFER_MULTIPLIER = float(os.getenv("TRANSFER_MULTIPLIER", "10"))         # x the user's average bytes
TRANSFER_MIN_BYTES = int(os.getenv("TRANSFER_MIN_BYTES", "10000000"))       # ...and at least this big
DEFAULT_BASELINE_BYTES = int(os.getenv("DEFAULT_BASELINE_BYTES", "50000"))  # used until enough samples
BASELINE_MIN_SAMPLES = int(os.getenv("BASELINE_MIN_SAMPLES", "20"))
ALERT_COOLDOWN_S = int(os.getenv("ALERT_COOLDOWN_S", "60"))                 # no repeat alert of a type per entity

# --- Extra detection rules ---
IMPOSSIBLE_TRAVEL_WINDOW_S = int(os.getenv("IMPOSSIBLE_TRAVEL_WINDOW_S", "3600"))  # two logins from different countries within this
SPRAY_MIN_USERS = int(os.getenv("SPRAY_MIN_USERS", "5"))                           # failed logins from one IP vs this many distinct users...
SPRAY_WINDOW_S = int(os.getenv("SPRAY_WINDOW_S", "120"))                           # ...inside this window
# Off-hours login is DISABLED by default: demo timestamps use the real clock, so it would fire at random.
OFF_HOURS_ENABLED = os.getenv("OFF_HOURS_ENABLED", "false").lower() == "true"
BUSINESS_HOURS_START = int(os.getenv("BUSINESS_HOURS_START", "9"))                 # server local time, inclusive
BUSINESS_HOURS_END = int(os.getenv("BUSINESS_HOURS_END", "18"))                    # exclusive
BUSINESS_DAYS = {int(d) for d in os.getenv("BUSINESS_DAYS", "0,1,2,3,4").split(",") if d.strip()}  # Mon=0 ... Sun=6
CRYPTOMINER_WINDOW_S = int(os.getenv("CRYPTOMINER_WINDOW_S", "120"))               # CPU spike + new process on one host within this
# New processes that never count as a miner (common short-lived tools), so a build or a shell doesn't alert.
CRYPTOMINER_IGNORE_PROCESSES = {p.strip().lower() for p in os.getenv(
    "CRYPTOMINER_IGNORE_PROCESSES",
    "sh,bash,zsh,dash,python,python3,node,git,ls,cat,grep,sleep,ps,top,cc,gcc,g++,cc1,cc1plus,ld,make,cargo,rustc,"
    "npm,pip,uvicorn,chrome,firefox,code,java,mdworker,mds,cat,awk,sed,curl,wget").split(",") if p.strip()}

# --- Step 2: attack injector ---
ATTACK_DELAY_SCALE = float(os.getenv("ATTACK_DELAY_SCALE", "1.0"))

# --- Step 3: correlation ---
CORRELATION_WINDOW_S = int(os.getenv("CORRELATION_WINDOW_S", "600"))
# Which alert fields count as "the same entity". Add "host" to also join on shared hosts.
CORRELATION_KEYS = [k.strip() for k in os.getenv("CORRELATION_KEYS", "user,ip").split(",") if k.strip()]

# --- Step 4: investigation agent ---
from pathlib import Path  # noqa: E402
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
AGENT_DEBOUNCE_S = int(os.getenv("AGENT_DEBOUNCE_S", "30"))   # max one agent run per incident per this many seconds
AGENT_TIMEOUT_S = int(os.getenv("AGENT_TIMEOUT_S", "90"))     # whole investigation; on timeout -> fallback
AGENT_MAX_TURNS = int(os.getenv("AGENT_MAX_TURNS", "8"))      # tool-use round trips per conversation
AGENT_MAX_TOKENS = int(os.getenv("AGENT_MAX_TOKENS", "4096"))

# --- Optional: any OpenAI-compatible provider (Gemini, Groq, OpenRouter, Ollama). Used only if ANTHROPIC_API_KEY is empty. ---
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash")
LLM_NAME = os.getenv("LLM_NAME", "gemini")                       # label shown on the dashboard
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "8192"))        # higher: some models count "thinking" tokens too

# --- Step 5: response ---
AUTO_ACTIONS = {a.strip() for a in os.getenv("AUTO_ACTIONS", "open_ticket,block_ip,revoke_sessions,send_notification,generate_report").split(",") if a.strip()}

# --- RPA interface ---
RPA_MODE = os.getenv("RPA_MODE", "auto").lower()  # builtin | uipath | auto
RPA_CLAIM_TIMEOUT_S = float(os.getenv("RPA_CLAIM_TIMEOUT_S", "10"))
RPA_TOKEN = os.getenv("RPA_TOKEN", "rpa-secret-token")

# --- Step 6: system collector ---
COLLECTOR_ENABLED = os.getenv("COLLECTOR_ENABLED", "true").lower() == "true"
COLLECTOR_INTERVAL_S = float(os.getenv("COLLECTOR_INTERVAL_S", "1"))
LOG_FILE = os.getenv("LOG_FILE", "logs/app.log")                 # tailed in real time
CPU_SPIKE_PCT = float(os.getenv("CPU_SPIKE_PCT", "90"))
NET_SPIKE_BYTES_PER_S = float(os.getenv("NET_SPIKE_BYTES_PER_S", "20000000"))
COLLECTOR_MAX_EVENTS_PER_POLL = int(os.getenv("COLLECTOR_MAX_EVENTS_PER_POLL", "20"))  # flood guard

# --- Step 2: cloud ingestion ---
INGEST_MAX_RECORDS = int(os.getenv("INGEST_MAX_RECORDS", "5000"))   # max CloudTrail records per POST /ingest/cloudtrail

# --- Analyst feedback ---
FEEDBACK_SUPPRESS_S = int(os.getenv("FEEDBACK_SUPPRESS_S", "86400"))   # a false_positive mutes its (alert type, entity) pairs this long
STATS_MAX_KEYS = int(os.getenv("STATS_MAX_KEYS", "5000"))             # cap on distinct IPs / countries tracked for /stats (log text is attacker-controlled)

# Cloud "hosts" are API resources (S3 bucket, IAM user, CloudTrail trail, STS), not machines: they cannot be network-isolated.
CLOUD_HOST_PREFIXES = ("s3:", "iam:", "cloudtrail:")


def is_cloud_host(target) -> bool:
    """True if a host/target names a cloud resource (s3:..., iam:..., cloudtrail:..., or sts)."""
    t = str(target or "").strip().lower()
    return t.startswith(CLOUD_HOST_PREFIXES) or t == "sts"
