# UiPath RPA Integration Contract

This document specifies the interface contract between the AI Security Operations Agent and external RPA automation bots (e.g., UiPath).

---

## 1. Architecture & Execution Modes

The agent response subsystem supports three RPA operational modes configured via the `RPA_MODE` environment variable:

- `builtin`: All response actions are executed directly by the built-in simulated executor.
- `uipath`: Actions wait indefinitely in the queue for an external UiPath bot to claim and execute them.
- `auto` (Default): Actions wait up to `RPA_CLAIM_TIMEOUT_S` (default: 10 seconds) for an external bot to claim them. If unclaimed within the timeout window, the built-in executor runs fallback execution and logs `"executed by builtin fallback (no bot claimed)"`.

---

## 2. Authentication

All RPA queue endpoints require the shared secret token passed via the HTTP request header:

```http
X-RPA-Token: <RPA_TOKEN>
```

- Configured via environment variable `RPA_TOKEN` (default: `rpa-secret-token`).
- Requests with a missing or invalid token are rejected with **HTTP 401 Unauthorized**.

---

## 3. RPA Queue Endpoints

### 3.1 Claim Next Action
**Endpoint:** `GET /rpa/queue/next`  
**Header:** `X-RPA-Token: <token>`

Atomically claims the oldest queued action.

**Responses:**
- **HTTP 200 OK**: An action was claimed.
  ```json
  {
    "id": "ACT-A1B2C3",
    "type": "block_ip",
    "target": "185.220.101.45",
    "incident_id": "INC-8BEF98",
    "params": {
      "target": "185.220.101.45",
      "reason": "malicious IP associated with brute force"
    },
    "claim_id": "CLM-4F2A81B0"
  }
  ```
- **HTTP 204 No Content**: The action queue is currently empty.
- **HTTP 401 Unauthorized**: Invalid or missing `X-RPA-Token`.

### 3.2 Submit Execution Result
**Endpoint:** `POST /rpa/actions/{id}/result`  
**Header:** `X-RPA-Token: <token>`  
**Body:**
```json
{
  "claim_id": "CLM-4F2A81B0",
  "status": "done",
  "detail": "IP 185.220.101.45 added to enterprise firewall blocklist"
}
```

- Allowed values for `status`: `"done"` | `"failed"`
- **HTTP 200 OK**: Result recorded and independent verification completed.
- **HTTP 401 Unauthorized**: Invalid or missing `X-RPA-Token`.
- **HTTP 404 Not Found**: Action ID does not exist.
- **HTTP 409 Conflict**: Stale claim, duplicate submission, or mismatched `claim_id`.

---

## 4. Simulated Admin Console (`GET /console`)

UiPath bots utilizing UI automation (click/type activities) can automate actions against the Simulated Admin Console at `http://<host>:<port>/console`.

> **Notice:** The console is labeled:  
> `SIMULATED ADMIN CONSOLE - no real systems are changed`

### UI Element Selectors

| Action | Form ID | Target Input Selector | Submit Button Selector |
| :--- | :--- | :--- | :--- |
| **Block IP** | `#form-block` | `input#ip` | `button#block` |
| **Revoke Session** | `#form-revoke` | `input#user` | `button#revoke` |
| **Create Ticket** | `#form-ticket` | `input#title` | `button#create` |
| **Send Notification** | `#form-notify` | `input#message` | `button#notify` |
| **Disable User** | `#form-disable` | `input#disable-user-input` | `button#disable-user` |
| **Isolate Host** | `#form-isolate` | `input#isolate-host-input` | `button#isolate-host` |

### Confirmation Banner
- Element selector: `#confirmation`
- Shows visible text indicating success or error upon submission.

### Direct Console API Endpoints
Bots may optionally invoke the console endpoints directly via HTTP POST:
- `POST /console/block-ip` with `{"ip": "185.220.101.45"}`
- `POST /console/revoke-session` with `{"user": "alice"}`
- `POST /console/create-ticket` with `{"title": "INC-8BEF98"}`
- `POST /console/send-notification` with `{"message": "alert notification"}`
- `POST /console/disable-user` with `{"user": "alice"}`
- `POST /console/isolate-host` with `{"host": "web-01"}`

---

## 5. Action Lifecycle & Verification Contract

### 5.1 Lifecycle States
```
pending_approval ──(analyst approve)──> approved ──> queued ──(claim)──> executing ──(result)──> executed ──> verified | verification_failed
```
*(Safe actions such as `block_ip`, `revoke_sessions`, `open_ticket`, `send_notification`, `generate_report` skip approval and enter `queued` immediately).*

- `pending_approval`: Waiting for human analyst approval.
- `approved`: Analyst approved the action.
- `queued`: Waiting to be claimed by a bot or builtin executor.
- `executing`: Claimed by bot (`executor: "uipath"`) or builtin runner.
- `executed`: Action reported completed.
- `verified`: Verification engine confirmed state in database.
- `verification_failed`: Target state was not found in database. `recommended_next_step` set to `"retry / manual"`.

### 5.2 Verification Engine
After an action is reported `"done"`, the agent's verification engine independently inspects the database:
- `block_ip`: Verifies `target` is present in `blocked_ips` table.
- `revoke_sessions`: Verifies `target` is present in `revoked_sessions` table.
- `open_ticket`: Verifies ticket exists in `tickets` table.
- `disable_user`: Verifies `target` is present in `disabled_users` table.
- `isolate_host`: Verifies `target` is present in `isolated_hosts` table.
- `send_notification`: Verifies entry in `notifications` table.
- `generate_report`: Transient report output (`verification_status: "skipped"`).

If the bot reports `"done"` but did not update the simulated state, verification status is marked `failed` and action status is `verification_failed`.

---

## 6. Example Workflow Run

### Step 1: UiPath Bot Polls Queue
```bash
curl -X GET http://localhost:8000/rpa/queue/next \
  -H "X-RPA-Token: rpa-secret-token"
```

Response:
```json
{
  "id": "ACT-84A12F",
  "type": "block_ip",
  "target": "185.220.101.45",
  "incident_id": "INC-8BEF98",
  "params": {"target": "185.220.101.45", "reason": "Brute force attack source"},
  "claim_id": "CLM-91B24E"
}
```

### Step 2: Bot Automates the Action
The UiPath bot navigates to `http://localhost:8000/console`, inputs `"185.220.101.45"` into `input#ip`, and clicks `button#block`.

*(Or executes `POST http://localhost:8000/console/block-ip`)*.

### Step 3: Bot Reports Execution Result
```bash
curl -X POST http://localhost:8000/rpa/actions/ACT-84A12F/result \
  -H "X-RPA-Token: rpa-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "claim_id": "CLM-91B24E",
    "status": "done",
    "detail": "IP blocked successfully on perimeter firewall"
  }'
```

Response:
```json
{
  "id": "ACT-84A12F",
  "type": "block_ip",
  "target": "185.220.101.45",
  "status": "verified",
  "executor": "uipath",
  "verification_status": "verified",
  "verification_detail": "IP 185.220.101.45 confirmed in blocked_ips table"
}
```
