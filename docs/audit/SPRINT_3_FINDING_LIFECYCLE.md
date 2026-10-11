# Sprint 3 — Finding Lifecycle

## Overview

Sprint 3 documents and clarifies the existing finding lifecycle machinery,
adds `get_finding_lifecycle()` for complete timeline queries, and provides
the `ScanDifferential` engine for comparing consecutive scans.

---

## Finding States

States are defined in `core/lifecycle.py::FindingStatus`:

| State | Who sets it | Description |
|-------|-------------|-------------|
| `OPEN` | Scanner | Initial state for all new findings |
| `ACKNOWLEDGED` | Analyst | Finding reviewed, work not started |
| `IN_PROGRESS` | Analyst | Active remediation in progress |
| `REMEDIATED` | Analyst | Fix applied, awaiting verification |
| `VERIFICATION_PENDING` | Analyst | Awaiting scanner confirmation |
| `VERIFIED` | Scanner | Not seen in a subsequent completed scan |
| `RISK_ACCEPTED` | Analyst | Risk formally accepted |
| `FALSE_POSITIVE` | Analyst | Confirmed false positive |
| `CLOSED` | Analyst | Manually closed |
| `REOPENED` | Scanner | Reappeared after VERIFIED/CLOSED/REMEDIATED |

---

## Scanner-Observed vs Workflow-Managed Separation

| Layer | Records | Mutation |
|-------|---------|----------|
| Scanner-observed | `FindingObservation` | Only by `process_scan_findings()` |
| Workflow-managed | `FindingHistory`, `FindingComment` | Only by `transition_finding_status()` |

These are returned separately by `get_finding_lifecycle()`:
```python
lifecycle = get_finding_lifecycle(finding_id, tenant_id=tenant_id)
# lifecycle["observations"] → scanner evidence events
# lifecycle["history"]      → analyst workflow transitions
# lifecycle["comments"]     → analyst commentary
# lifecycle["remediation"]  → remediation record (if any)
```

---

## First/Last Seen

`first_seen_at` is set in `process_scan_findings()` at finding creation and
**never overwritten** — even if the finding is reopened.

`last_seen_at` is updated every time the scanner observes the finding in a
new completed scan.

---

## Differential Change States

`core/differential.py::ScanDifferential` computes between two scans:

| State | Condition |
|-------|-----------|
| `NEW` | Fingerprint in new scan only |
| `PERSISTING` | Fingerprint in both scans, still open |
| `RESOLVED` | Fingerprint in baseline, absent in new **completed** scan |
| `REOPENED` | Was VERIFIED/CLOSED in baseline, present and open in new scan |
| `UNKNOWN` | Cannot determine (new scan not completed) |

**Critical safety invariant** (Acceptance criterion 5):
> RESOLVED change state is **never** produced when the new scan's status
> is not `COMPLETED`. A failed scan with zero findings cannot trigger
> false resolution events.

```python
if not new_scan_completed:
    diff.is_complete = False
    # All "absent in new scan" findings become UNKNOWN, not RESOLVED
```

---

## Finding History

Every status transition is recorded in `finding_history`:
- `action`: `finding_created`, `finding_reopened`, `finding_verified`,
  `finding_status_transition`, `finding_acknowledged`, etc.
- `old_status`, `new_status`: before/after state
- `actor_user_id`: `"system:scanner"` for automated events, user ID for manual

**Acceptance criterion 4** (Finding changes can be tracked between scans)
is satisfied by `FindingHistory` + `FindingObservation` + `ScanDifferential`.
