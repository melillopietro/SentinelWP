# SentinelWP - Remediation Governance & SLA Engine Specification

## 1. Remediation Workflow

Remediation in SentinelWP links exposure findings to concrete operational tasks and measurable outcomes.

### Remediation Statuses:
- `OPEN`: Task created, pending triage or assignment.
- `PLANNED`: Scheduled into upcoming sprint or patch maintenance window.
- `IN_PROGRESS`: Engineering effort underway.
- `BLOCKED`: Blocked by external dependencies, vendor upstream, or pending risk acceptance.
- `DONE`: Implementation finished, awaiting verification.
- `CANCELLED`: Withdrawn (e.g. decommissioned asset or deemed false positive).

### Remediation Actions:
Remediations can be broken into granular steps (`RemediationAction`):
- Action types: `patch`, `configuration`, `waf_rule`, `code_fix`, `decommission`.
- Each action carries an owner, due date, status, and completion timestamp.

---

## 2. Multi-Factor SLA Policy Engine

SLA policies define time-to-remediate obligations based on business and threat context.

### Multi-Factor Specificity Matching:
When calculating SLA deadlines, SentinelWP matches findings against tenant-configured policies using a specificity hierarchy:
1. Exact match on `(severity, asset_criticality, priority_band, kev, internet_exposed)`
2. Partial matches prioritized by weighted specificity score:
   - Severity: +10 pts
   - Asset Criticality: +8 pts
   - Priority Band: +6 pts
   - CISA KEV: +4 pts
   - Internet Exposed: +2 pts
3. Fallback to default priority band SLAs:
   - **P1** (Critical / KEV / Active Threat): **1 day** (Warning window: 12 hours)
   - **P2** (High / Internet Critical): **7 days** (Warning window: 2 days)
   - **P3** (Medium / Internal): **30 days** (Warning window: 7 days)
   - **P4** (Low / Informational): **90 days** (Warning window: 14 days)

### SLA Status Lifecycle:
- `NOT_APPLICABLE`: Finding has no applicable SLA or policy.
- `ON_TRACK`: Finding is within remediation window and outside warning threshold.
- `WARNING`: Finding has entered the warning window before SLA breach.
- `BREACHED`: Current time has exceeded `sla_due_at`.
- `PAUSED`: Countdown paused due to approved `RISK_ACCEPTED` status.
- `COMPLIED`: Remediation achieved and verified prior to breach.

### Periodic SLA Evaluator Celery Task:
- Task: `core.tasks.remediation_tasks.evaluate_sla_breaches`
- Scheduled periodically (e.g. hourly or via Celery beat).
- Scans active findings, evaluates breach conditions, and updates `sla_status`.
- **Deduplication**: Avoids duplicate alerts or repetitive history writes if finding is already marked `BREACHED`.

---

## 3. Risk Acceptance Governance (Two-Person Rule)

To prevent conflicts of interest and maintain strict compliance with enterprise security frameworks:
- **Analyst Role**: Authorized to submit a Risk Acceptance Request with required business justification, compensating controls, and expiration date (`valid_until`).
- **Admin Role**: Required to formally review and Approve or Reject the request.
- **Strict Anti-Self-Approval**: An analyst or admin cannot approve their own request (`requested_by != approved_by`). Any attempt is rejected with `HTTP 400 Bad Request`.
- **SLA Countdown Pausing**: Upon approval, the finding transitions to `RISK_ACCEPTED` and `sla_status` becomes `PAUSED` (`sla_paused_at` recorded).
- **Revocation**: Admins can revoke an active risk acceptance at any time, returning the finding to `REOPENED` and resuming the SLA timer.

### Periodic Expiration Celery Task:
- Task: `core.tasks.remediation_tasks.expire_risk_acceptances`
- Runs daily to check for risk acceptances where `valid_until < now()`.
- Automatically transitions expired acceptances to `EXPIRED`.
- Automatically transitions corresponding findings to `REOPENED`.
- Clears `sla_paused_at` and triggers SLA recalculation.

---

## 4. Contextual Vulnerability Prioritization

SentinelWP distinguishes between raw vulnerability metrics and contextual risk:
- **CVSS Score (0-10.0)**: Intrinsic technical severity of the vulnerability.
- **Site Security Score (0-100)**: Overall posture score of the WordPress target asset.
- **Priority Score (0-100.0)**: Contextual risk rating determining operational priority:
  ```
  Priority Score = Base Severity Points
                 + (CVSS * 2.0)
                 + (EPSS * 20.0)
                 + (25.0 if CISA KEV else 0)
                 + (15.0 if Critical Asset else 10.0 if High else 0)
                 + (10.0 if Internet Facing else 0)
                 + (10.0 if Ransomware Relevant else 0)
  ```
  Clamped strictly to `[0.0, 100.0]`.

### Priority Bands:
- **P1 (Score >= 80.0)**: Emergency remediation required (24h SLA).
- **P2 (Score >= 60.0)**: High priority remediation (7d SLA).
- **P3 (Score >= 35.0)**: Standard priority remediation (30d SLA).
- **P4 (Score < 35.0)**: Low priority backlog (90d SLA).

---

## 5. False Positive Management

False positives require explicit governance to prevent silent dismissal of real exposures:
- Transition to `FALSE_POSITIVE` requires a mandatory reason and comment.
- Actor ID and timestamp are permanently recorded in `FindingHistory`.
- If an issue was marked false positive erroneously, it can be transitioned back to `OPEN` or `REOPENED`.
