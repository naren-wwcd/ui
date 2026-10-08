# AI Security Operations Agent

A real-time SOC agent. It watches a live event stream, detects suspicious activity, correlates alerts into
MITRE ATT&CK-mapped incidents, has Claude investigate each incident with tools, scores the risk, and
proposes or runs responses (with a human approval gate for anything high-impact).

```
 producers                      pipeline (all async, one process)                       outputs
 ---------                      ---------------------------------                       -------
 traffic generator ─┐
 system collector  ─┼─> bounded queue ─> detection rules ─> correlation ─> incidents ─> dashboard (WebSocket)
   (psutil + log tail)│    (backpressure)   (streaming,        (entity +      (SQLite)    approve / reject
 attack injector   ─┘                      no ML)             time window)       │
                                                                                  v
                                            Claude investigation agent (tool-use loop, background)
                                                                                  │
                                       deterministic risk score 0-100  <──────────┤
                                                                                  v
                                       response layer: auto-run (low risk) / human approval (high impact) + audit log
```

## Run it (one command)

Python 3.10+.

```bash
pip install -r requirements.txt && python -m uvicorn app.main:app --port 8000
```

Open http://127.0.0.1:8000 — the dashboard. With no API key it runs in **fallback mode** (a cached sample
investigation), so the demo never breaks.

### Turn on the real Claude investigation

```bash
cp .env.example .env          # Windows: copy .env.example .env
# edit .env and set  ANTHROPIC_API_KEY=sk-ant-...
python -m uvicorn app.main:app --port 8000
```

### Free option: Google Gemini instead of Claude

Get a free key at https://aistudio.google.com (Get API key), then in `.env` leave `ANTHROPIC_API_KEY` empty and set:

```
LLM_API_KEY=your-gemini-key
LLM_MODEL=gemini-2.5-flash
AGENT_DEBOUNCE_S=60
```

The same investigation loop runs through Gemini's OpenAI-compatible endpoint (the defaults in `.env.example` already point
there). Any OpenAI-compatible provider works by changing `LLM_BASE_URL`, `LLM_MODEL` and `LLM_NAME` (Groq, OpenRouter, Ollama).
Free tiers have a low requests-per-minute cap, so `AGENT_DEBOUNCE_S=60` keeps the two investigations of one attack apart; if
`fallback_reason` shows a 429 error, raise it. If `ANTHROPIC_API_KEY` is set, Claude is used instead.

### Trigger an attack

In a second terminal (or `curl -X POST "http://127.0.0.1:8000/simulate/attack?user=alice"`):

```bash
python -m app.cli attack --user alice
```

A 4-stage attack plays out live over ~20 s while normal traffic keeps flowing:
brute force -> login from a new country -> privilege escalation -> 800 MB download.

### Confirm the real Claude path worked

Server log, per investigation:

```
[AGENT]   tool check_ip_reputation({"ip": "185.220.101.45"})
...
[AGENT] INC-XXXXXX verdict=TRUE_POSITIVE confidence=0.95 source=claude (14.2s, 5 tool calls)
```

Or query the API (works on any OS):

```bash
python -c "import json,urllib.request as u;[print(i['id'],{k:i['investigation'].get(k) for k in ('source','model','tool_calls','validation','fallback_reason','duration_s')}) for i in json.load(u.urlopen('http://127.0.0.1:8000/incidents')) if i.get('investigation')]"
```

Healthy result: `source=claude` (or `gemini`), `tool_calls` greater than 0, `validation` is `ok` (or `retried`).
If `source=fallback`, the `fallback_reason` field tells you why (bad key, wrong model name, timeout, bad JSON).

### Real data from this machine (optional)

The collector watches the host with psutil (new processes, outbound connections, CPU/network spikes) and tails
`logs/app.log` (JSON lines or sshd/sudo-style lines). Append lines to see real events flow through detection:

```bash
for i in 1 2 3 4 5 6 7 8; do echo "sshd[1]: Failed password for invalid user admin from 185.220.101.45 port 22 ssh2" >> logs/app.log; done
echo "sudo:   admin : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash" >> logs/app.log
```

## What each stage does

| Stage | Where | Notes |
|---|---|---|
| Ingest | `app/bus.py`, `app/main.py` | One bounded `asyncio.Queue`. Normal events are shed and counted when full; attack and log events are never dropped. Alerts are handled inline, so they cannot be dropped. |
| Detect | `app/detection.py` | Brute force (sliding window), login from a new country (per-user baseline), privilege escalation, large transfer (x10 the user's own average). Plain rules, no ML. |
| Correlate | `app/correlation.py` | 2+ distinct alert types on the same user/IP inside a 10-minute window become one incident; later alerts update it. Each alert carries a MITRE ATT&CK tactic. |
| Investigate | `app/agent.py` | Claude tool-use loop with 4 tools over SQLite and mock intel/asset files. Output is validated: JSON schema, and every cited event ID must exist (one retry, then invented IDs are stripped). Runs in the background, debounced per incident, with a 90 s timeout and a cached fallback. |
| Score | `app/risk.py` | Plain code, not the LLM: 30 x severity + 25 x agent confidence + 20 x asset criticality + 25 x attack stage, with a plain-English justification. |
| Respond | `app/response.py` | `block_ip` / `revoke_sessions` auto-run only when the verdict is `true_positive`. `disable_user` / `isolate_host` always wait for a human. `open_ticket` is created for any verdict except `false_positive` (which takes no action). Targets must be entities that belong to the incident. Every step is written to the audit log. |
| Show | `dashboard/index.html` | Single file, live over `/ws`: feed, alerts, incidents, investigation, risk, approve/reject buttons. |

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /` | Dashboard |
| `GET /health` | Throughput, queue depth, drops, running investigations |
| `POST /simulate/attack?user=alice` | Start the multi-stage attack |
| `GET /incidents`, `GET /alerts` | Current incidents / recent alerts |
| `GET /stats` | Events/sec (last 60 s), alert and incident counts, top 5 IPs / countries, pending actions |
| `POST /incidents/{id}/feedback` | Analyst decision `{"label": "false_positive"\|"confirmed", "note": "..."}`; false_positive closes the incident and mutes its alert type + entity pairs for `FEEDBACK_SUPPRESS_S` |
| `GET /actions?status=pending_approval` | Approval queue |
| `POST /actions/{id}/approve`, `.../reject` | Human decision |
| `GET /audit` | Audit log |
| `WS /ws` | Live updates |

## Configuration

All settings are environment variables (see `.env.example`). The useful ones:

| Variable | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | empty | Empty means fallback mode |
| `ANTHROPIC_MODEL` | `claude-sonnet-5-5` | Model used for investigations |
| `AGENT_DEBOUNCE_S` | 30 | Max one investigation per incident per N seconds (lower it for a snappier demo) |
| `AGENT_TIMEOUT_S` | 90 | Whole investigation; on timeout the fallback is used |
| `AGENT_MAX_TOKENS` | 4096 | Per model response |
| `ATTACK_DELAY_SCALE` | 1.0 | 0.2 plays the attack 5x faster |
| `AUTO_ACTIONS` | `open_ticket,block_ip,revoke_sessions` | Actions allowed to run without approval |
| `COLLECTOR_ENABLED` | true | Real-machine collector on/off |
| `DB_PATH` | `security.db` | Delete this file for a clean start |

## Check the Claude code path without a key

```bash
python tests/test_claude_path.py good          # also: invented_id | always_bad_id | api_error
```

Runs the real agent loop against a scripted fake Anthropic client (tool calls, citation validation, retry,
fallback). `python tests/test_openai_path.py good` does the same for the Gemini/OpenAI-compatible path, using the real
`openai` SDK against a local fake server. They prove the plumbing; they do not replace one run with a real key.

## Honest scope

- Response actions change **simulated** state in SQLite (blocklist, disabled users, isolated hosts, tickets). They do not touch real firewalls or identity providers.
- Threat intel and the asset inventory are mock JSON files in `data/`; the traffic generator and attacker are synthetic.
- Detection thresholds are fixed rules tuned for the demo, not learned.
- Single process; the production path would put a real broker (Kafka/NATS) and a real SIEM/EDR behind the same event schema.
