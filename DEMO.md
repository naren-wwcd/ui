# Demo script (3:00) and judge Q&A

## Before you go on (2 minutes, not part of the 3:00)

1. `.env` has your key: `ANTHROPIC_API_KEY` for Claude, or `LLM_API_KEY` for free Gemini (with `AGENT_DEBOUNCE_S=60` on Gemini; on Claude `15` is fine). Keep `ATTACK_DELAY_SCALE=1.0`.
2. Delete the old database so the dashboard starts clean: remove `security.db` (and `security.db-wal` / `-shm` if present).
3. Start the server: `python -m uvicorn app.main:app --port 8000`
4. Open http://127.0.0.1:8000 full screen. Put a second terminal next to it, already in the project folder, with this typed but not run:
   `python -m app.cli attack --user alice`
5. Do one dry run of the whole thing with the real key. Confirm the card says `claude` or `gemini`, tool calls above 0. Then restart with a fresh DB.
6. If the dry run showed `fallback`, check `fallback_reason` (see README). Do not demo it as "Claude" in that case.

## Script

| Time | Do | Say |
|---|---|---|
| 0:00 | Dashboard on screen, feed scrolling | "Security teams drown in alerts. Our agent watches a live event stream and does what a tier-1 analyst does: detect, correlate, investigate, score the risk, and respond. It is running right now on a live stream, about 15 events a second, plus real events from this laptop." |
| 0:20 | Point at throughput numbers and the feed | "Normal traffic, eight users, no alerts. Detection is streaming rules, no ML, so every alert is explainable. The queue is bounded with backpressure, so a flood cannot take the pipeline down." |
| 0:35 | Switch to terminal, press Enter on the attack command | "Now I'll inject a real multi-stage attack: someone guesses a password, gets in from a new country, escalates privileges, then pulls a large download. Normal traffic keeps flowing around it." |
| 0:45 | Watch alerts appear one by one | "Brute force. A login from a country this user has never used. Privilege escalation. Each alert is tagged with a MITRE ATT&CK tactic. Individually these are noise. Correlation joins them on the same user and IP." |
| 1:05 | Incident card appears, risk score climbs | "That is one incident, not four alerts. The risk score is plain code, not the LLM: severity, how sure the agent is, how critical the asset is, and how far the attack has progressed. It shows its working in plain English." |
| 1:20 | Show "investigating" indicator, then the investigation card | "Now the AI agent investigates, in the background so ingestion never waits. It calls tools: IP reputation, the asset inventory, the user's 24-hour history, related events. Here: the model name on the card, N tool calls. Verdict true positive, with a timeline." |
| 1:50 | Point at the evidence list | "Every event it cites is checked against the database. If it invents an ID, we retry once and then strip it. The model cannot cite evidence that does not exist." |
| 2:05 | Point at the actions panel | "Low-risk actions ran on their own because the verdict was true positive: the attacker IP is blocked, sessions revoked, a ticket opened. Disabling the account and isolating the host are high impact, so they wait for a human." |
| 2:20 | Click Approve on `disable_user` | "I approve. That is executed and written to the audit log with who decided and when. The agent also cannot act on anything outside the incident: targets must be entities the incident actually involved." |
| 2:35 | Final risk score (high 90s, critical) after the exfil alert lands | "As the huge download landed, the incident escalated, the agent re-investigated with the full picture, and the score went critical." |
| 2:45 | Back to the whole dashboard | "Detect, correlate, investigate, assess, respond, with a human in the loop where it matters and an audit trail for every step. If the Claude API ever fails, a cached investigation keeps the pipeline working, and the dashboard labels it as fallback. Thank you." |

Timing notes: the first investigation starts about 8 s after the attack begins; the follow-up with all four alerts
arrives roughly `AGENT_DEBOUNCE_S` + investigation time later. Keep talking through the 1:20 to 1:50 window. If the
final score is late, say "it is re-investigating with the new evidence" and move on; it will update on screen.

## Optional 20-second beat: real data

If you have time to spare, show `logs/app.log` being tailed: run the two commands in the README ("Real data from this
machine"). The failed-login lines and a `sudo` line become real events, an alert, and an incident.

## If something goes wrong

- API slow, rate-limited or down: the card says `fallback` and shows the reason. Say so: "the live model call failed, so the cached investigation took over, which is exactly the resilience path." Do not hide it.
- Dashboard blank: refresh the page; it rebuilds from a snapshot over the WebSocket.
- Attack did nothing: `curl -X POST "http://127.0.0.1:8000/simulate/attack?user=alice"`
- Unclean state from earlier runs: stop the server, delete `security.db*`, start again.

## Likely judge questions

**What makes this an agent and not a script with an LLM call?**
Claude chooses which tools to call and in what order, reads the results, and decides when it has enough evidence. Its output is then validated, and what it recommends is checked against policy before anything runs.

**Why rules for detection instead of ML?**
Explainability and no training data. Every alert says exactly why it fired, which is what a SOC needs for trust. The pipeline is ML-ready: a model can emit alerts in the same schema and the rest is unchanged.

**What stops the LLM from hallucinating?**
Four things: it must gather evidence with tools; its JSON is schema-checked; every cited event ID is verified against the database (retry once, then strip); and recommended action targets must belong to the incident. The risk score is deterministic code, not LLM output.

**What about prompt injection through logs or usernames?**
The system prompt marks event data as untrusted. More importantly, the design limits the damage: the agent can only call read-only tools, targets are checked against the incident, and high-impact actions need a human. We have not run a formal red-team on this, so we do not claim it is immune.

**Why is a human needed for some actions?**
Disabling a user or isolating a host can take down a legitimate employee or a production server. Blocking an IP or revoking sessions is cheap to reverse, so those auto-run, and only on a true-positive verdict.

**What happens if the Claude API is down or slow?**
90 s timeout, then a cached fallback investigation built from the incident's own alerts, so every citation is real. The card is labeled `fallback` with the reason, so nobody mistakes it for a live analysis.

**Are the response actions real?**
No. They change simulated state in SQLite and are fully audited. The playbook interface is where a real firewall, IdP, or EDR API call would go. We would rather say that than overclaim.

**Is the threat intel real?**
Mock feed in `data/threat_intel.json`, behind a single function (`check_ip_reputation`). Swapping in AbuseIPDB, VirusTotal, or a commercial feed changes that function and nothing else.

**How does it scale?**
This is a single-process demo: a bounded asyncio queue with backpressure (normal events are shed and counted; alerts are never dropped), SQLite in WAL mode, and investigations run in the background and are debounced per incident. For production: Kafka or NATS in front, Postgres, and a worker pool for investigations.

**How do you control LLM cost and latency?**
One investigation per incident per debounce window, extra triggers are coalesced into one follow-up, there is a turn cap and a timeout, and Claude only sees incidents (two or more correlated alert types), not raw events.

**How is the risk score computed, and why not let the LLM do it?**
30 x severity + 25 x the agent's confidence + 20 x asset criticality + 25 x attack stage reached. It is reproducible, auditable, and gives the same answer for the same input. The LLM supplies only the verdict and confidence.

**Which MITRE techniques do you cover?**
Tactics, not full techniques: Credential Access (TA0006), Initial Access (TA0001), Privilege Escalation (TA0004), Exfiltration (TA0010). Mapping to specific technique IDs is a natural extension.

**How do you handle false positives?**
Three layers: a cooldown per alert type and entity, correlation requires two distinct alert types, and the agent can return `false_positive`, in which case no actions are proposed at all.

**Can it handle cloud environments?**
The pipeline consumes one normalized event schema (`id, ts, user, ip, country, host, action, bytes, source`). A CloudTrail, VPC flow log, or Azure activity log adapter just maps into that schema, the same way our log tailer does.

**What would you build next?**
Real connectors for ingestion and response, technique-level ATT&CK mapping, per-user learned baselines, and an analyst feedback loop where approve/reject decisions tune the agent.

**What does the audit log record?**
Every investigation, every proposed action, who approved or rejected it and when, and every action the policy dropped and why.
