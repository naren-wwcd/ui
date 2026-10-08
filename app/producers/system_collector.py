"""System collector: REAL events from the local machine, ~1 second after they happen.
  - psutil: new processes, new outbound network connections, CPU spikes, network-throughput spikes
  - tails a real log file (LOG_FILE): JSON lines, or classic auth.log lines (Failed/Accepted password, sudo)
Psutil calls can be slow, so polling runs in a worker thread and never blocks the event loop."""
import asyncio
import ipaddress
import json
import os
import re
import socket
import time
import uuid

import psutil

from app import config
from app.bus import publish

HOST = socket.gethostname()


def _event(action, user=None, ip=None, country=None, host=None, nbytes=0) -> dict:
    return {"id": uuid.uuid4().hex[:12], "ts": time.time(), "user": user, "ip": ip, "country": country,
            "host": host or HOST, "action": action, "bytes": nbytes, "source": "system_collector"}


# ---------------- log line parsing ----------------
_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
_ACCEPTED = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
_SUDO = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=")


def parse_log_line(line: str) -> dict | None:
    """One log line -> one event, or None if it isn't something we understand."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):  # JSON line: {"user": "...", "ip": "...", "action": "...", "country": "...", "bytes": 0}
        try:
            d = json.loads(line)
            if not isinstance(d, dict) or "action" not in d:
                return None
            return _event(str(d["action"]), d.get("user"), d.get("ip"), d.get("country"), d.get("host"),
                          int(d.get("bytes") or 0))
        except (ValueError, TypeError):
            return None
    if m := _FAILED.search(line):
        return _event("login_failed", m.group(1), m.group(2))
    if m := _ACCEPTED.search(line):
        return _event("login_success", m.group(1), m.group(2))
    if m := _SUDO.search(line):
        return _event("sudo", m.group(1))
    return None


# ---------------- polling ----------------
class _State:
    def __init__(self):
        self.procs = None        # set of (pid, create_time) seen last poll (None = first poll, just learn)
        self.conns = None        # set of (pid, remote_ip, remote_port)
        self.net_prev = None     # total bytes at last poll
        self.net_t = None
        self.cpu_hot = False
        self.net_hot = False
        self.log_pos = None      # byte offset we have read up to
        psutil.cpu_percent(interval=None)  # first call is meaningless; prime it


def _skip_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_link_local or a.is_unspecified
    except ValueError:
        return True


def _poll_system(st: _State) -> list[dict]:
    events = []

    # CPU spike: one event when it crosses the threshold (not one per second while it stays high)
    cpu = psutil.cpu_percent(interval=None)
    hot = cpu >= config.CPU_SPIKE_PCT
    if hot and not st.cpu_hot:
        events.append(_event(f"cpu_spike:{cpu:.0f}pct"))
    st.cpu_hot = hot

    # Network throughput spike (bytes per second, all interfaces)
    io, now = psutil.net_io_counters(), time.monotonic()
    total = io.bytes_sent + io.bytes_recv
    if st.net_prev is not None:
        rate = (total - st.net_prev) / max(now - st.net_t, 1e-3)
        hot = rate >= config.NET_SPIKE_BYTES_PER_S
        if hot and not st.net_hot:
            events.append(_event("net_spike", nbytes=int(rate)))
        st.net_hot = hot
    st.net_prev, st.net_t = total, now

    # New processes
    cur = {}
    for p in psutil.process_iter(["pid", "name", "username", "create_time"]):
        i = p.info
        cur[(i["pid"], i["create_time"])] = i
    if st.procs is not None:
        for key, i in cur.items():
            if key not in st.procs:
                events.append(_event(f"process_start:{i['name']}", user=i["username"]))
    st.procs = set(cur)

    # New outbound connections
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):   # e.g. macOS without root
        conns = []
    seen = {(c.pid, c.raddr.ip, c.raddr.port) for c in conns
            if c.status == psutil.CONN_ESTABLISHED and c.raddr and not _skip_ip(c.raddr.ip)}
    if st.conns is not None:
        for pid, rip, rport in seen - st.conns:
            user = None
            try:
                user = psutil.Process(pid).username() if pid else None
            except psutil.Error:
                pass
            events.append(_event(f"net_connect:{rport}", user=user, ip=rip))
    st.conns = seen

    return events[:config.COLLECTOR_MAX_EVENTS_PER_POLL]   # flood guard


def _tail(st: _State) -> list[dict]:
    """Return events for lines appended to LOG_FILE since the last poll (starts at end of file)."""
    path = config.LOG_FILE
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if st.log_pos is None:
        st.log_pos = size                      # only new lines, not history
        return []
    if size < st.log_pos:
        st.log_pos = 0                         # file was truncated or rotated
    if size == st.log_pos:
        return []
    with open(path, "rb") as f:
        f.seek(st.log_pos)
        data = f.read()
    end = data.rfind(b"\n")
    if end == -1:
        return []                              # incomplete line, wait for the rest
    st.log_pos += end + 1
    return [e for e in map(parse_log_line, data[:end].decode("utf-8", "replace").splitlines()) if e]


async def run() -> None:
    if not config.COLLECTOR_ENABLED:
        return
    os.makedirs(os.path.dirname(config.LOG_FILE) or ".", exist_ok=True)
    open(config.LOG_FILE, "a").close()         # make sure the file exists so it can be tailed
    st = _State()
    print(f"[collector] watching this machine ({HOST}) and tailing {config.LOG_FILE}")
    while True:
        try:
            system_events = await asyncio.to_thread(_poll_system, st)
            log_events = await asyncio.to_thread(_tail, st)
        except Exception as exc:               # a collector hiccup must never take the app down
            print(f"[collector error] {exc!r}")
            system_events, log_events = [], []
        for e in system_events:
            await publish(e)                   # droppable under backpressure
        for e in log_events:
            await publish(e, droppable=False)  # real log lines are never shed
        await asyncio.sleep(config.COLLECTOR_INTERVAL_S)
