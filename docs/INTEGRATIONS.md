# SentinelWP - Enterprise Integrations & REST API Specification

## 1. Ticketing Abstraction

SentinelWP decouples finding lifecycle events from external ticket management systems through a vendor-neutral integration layer.

### Core Data Models:
- `Integration`: Tenant-scoped connector configuration (`jira`, `servicenow`, `webhook`).
- `TicketReference`: Bidirectional link between a finding and an external ticket (`external_ticket_id`, `external_url`, `status`, `last_sync_at`).

### Supported Adapters:
1. **Jira Software / Jira Service Management (`JiraIntegration`)**:
   - Creates tickets with project key, summary, priority mapping (`P1` -> Highest, `P2` -> High, etc.).
   - Updates ticket comments and status.
   - Synchronizes external ticket status.
2. **ServiceNow Incident / SecOps SIR (`ServiceNowIntegration`)**:
   - Maps exposures to `incident` or `sn_si_incident` tables.
   - Generates direct deep links to the ServiceNow instance navigator.
   - Resolves incidents upon finding verification.

### Credential Safety:
- Plaintext API tokens, service passwords, and bearer tokens are **NEVER** stored directly in the database.
- Configurations store an environment or vault key reference (`secret_reference`).
- Adapters resolve credentials from the runtime execution environment (`os.environ`).
- Credentials are scrubbed from logs and API payloads.

---

## 2. Signed Webhook Delivery & Retries

### HMAC-SHA256 Payload Signing:
All outgoing webhook notifications include an HTTP header:
```http
X-Sentinel-Signature: sha256=<hex_digest>
```
The signature is computed over the raw canonical JSON payload:
```python
signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()
```
Receivers can verify authenticity and integrity using constant-time comparison (`hmac.compare_digest`).

### Delivery & Retry Policy:
- Webhooks execute asynchronously via Celery (`deliver_webhook_task`).
- Each delivery attempt records status (`delivered`, `failed`), HTTP response code, and error trace.
- Exponential backoff retry with jitter up to 5 attempts.
- Payloads carry a unique `payload_hash` to support idempotency and deduplication on the receiver.

---

## 3. Scoped REST API v1

SentinelWP exposes a versioned, secure REST API under `/api/v1/`.

### Authentication:
- API keys follow the format: `swp_live_<48_hex_chars>`.
- The plaintext token is returned **ONCE** upon creation and never stored.
- The platform stores a cryptographic SHA-256 hash (`key_hash`) and an identifying prefix (`key_prefix`, first 12 characters).
- Authentication header:
  ```http
  Authorization: Bearer swp_live_...
  ```
  or
  ```http
  X-API-Key: swp_live_...
  ```

### Scope Enforcement:
Endpoints enforce role and scope least privilege:
- `findings:read`: Read findings, observations, history.
- `findings:write`: Transition finding statuses, add comments.
- `remediation:read`: Read remediation tasks and actions.
- `remediation:write`: Create or update remediation tasks.
- `risk-acceptances:read`: View risk acceptances.
- `risk-acceptances:write`: Submit risk acceptance requests.
- `admin`: Approve/reject/revoke risk acceptances, manage SLA policies and API keys.

### Endpoints Overview:
| Method | Route | Description | Required Scope |
|:---|:---|:---|:---|
| `GET` | `/api/v1/assets` | List tenant assets | `assets:read` |
| `GET` | `/api/v1/findings` | List findings with filters | `findings:read` |
| `GET` | `/api/v1/findings/<id>` | Get finding detail | `findings:read` |
| `POST` | `/api/v1/findings/<id>/status` | Transition status (optimistic lock) | `findings:write` |
| `GET` | `/api/v1/remediations` | List remediation workflows | `remediation:read` |
| `POST` | `/api/v1/remediations` | Create remediation | `remediation:write` |
| `GET` | `/api/v1/risk-acceptances` | List risk acceptances | `risk-acceptances:read` |
| `POST` | `/api/v1/risk-acceptances` | Request risk acceptance | `risk-acceptances:write` |
| `POST` | `/api/v1/risk-acceptances/<id>/approve` | Approve risk acceptance | `admin` |
| `POST` | `/api/v1/risk-acceptances/<id>/revoke` | Revoke risk acceptance | `admin` |
| `GET` | `/api/v1/slas` | List SLA policies | `admin` / `slas:read` |

---

## 4. Multi-Tenant Isolation & IDOR Protection

SentinelWP enforces strict logical multi-tenant isolation at both API and repository layers:
1. Every query strictly filters by `tenant_id`:
   ```sql
   SELECT * FROM findings WHERE id = :id AND tenant_id = :tenant_id;
   ```
2. Cross-tenant access attempts return `HTTP 404 Not Found` rather than `403 Forbidden` to prevent resource enumeration and information disclosure.
3. Every entity (Findings, Observations, History, Remediations, Risk Acceptances, Integrations, Ticket References, API Keys) is bounded by tenant context.
