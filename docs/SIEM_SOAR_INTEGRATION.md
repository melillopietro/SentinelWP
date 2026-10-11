# SIEM & SOAR Integration Architecture

## Overview
SentinelWP integrates with enterprise Security Information and Event Management (SIEM) systems (Splunk, Elastic, QRadar, ArcSight) and Security Orchestration, Automation, and Response (SOAR) platforms (Cortex XSOAR, Splunk SOAR, Tines) using an asynchronous Outbox Pattern.

## Outbox Pattern & Reliability Guarantees
Direct synchronous HTTP calls during scan processing introduce latency and vulnerability to external downstream outages. SentinelWP decouples event dispatch via the `integration_outbox` table:
1. **Idempotent Staging**: Events (e.g. `critical_finding`, `kev_detected`) are staged transactionally with the finding lifecycle.
2. **Deterministic Payload Hashing**: SHA-256 hash deduplication ensures no duplicate event is dispatched.
3. **Secret Redaction**: Payloads are cleansed before insertion into the outbox.
4. **Retry Loop with Exponential Backoff**: Background workers process pending outbox events, tracking delivery attempts and capturing error diagnostics.

## Event Formats
- **Common Event Format (CEF)**:
  `CEF:0|SentinelWP|CorePlatform|2.0.0|<event_type>|<title>|<severity>|cs1Label=Asset cs1=<hostname> cs2Label=Priority cs2=<band>`
- **Standardized JSON Event**:
  Structured JSON over HTTPS with HMAC-SHA256 request signatures for webhooks.

## SOAR Remediations & Actions
The SOAR interface allows external playbooks to execute non-destructive governance tasks:
- `assign_owner`: Reassign finding or asset ownership based on CMDB queries.
- `trigger_verification_scan`: Trigger passive scan validation following patch deployment.
- `escalate_ticket`: Dispatch Jira / ServiceNow incident tickets upon SLA warning thresholds.
