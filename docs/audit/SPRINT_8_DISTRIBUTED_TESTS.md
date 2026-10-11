# SentinelWP — Sprint 8 Distributed Infrastructure & Reliability Testing
## Celery Worker Processing, Redis Distributed Locks, Outbox Crash Recovery & Real Infrastructure Analysis

**Sprint:** Sprint 8 — End-to-End Pilot Validation & Release Candidate Certification  
**Target Branch:** `test/sentinelwp-sprint8-pilot-validation`  
**Test Suite Coverage:** `tests/test_phase3_postgres_celery_ha.py`, `tests/test_sprint5_resilience.py`, `tests/test_sprint7_qa_hardening.py`, `tests/test_sprint8_pilot_validation.py`  

---

### 1. Distributed Infrastructure Architecture & Topologies

SentinelWP provides horizontal scalability and resilience through decoupled distributed components:

```
[ Web Service (Stateless Flask/Gunicorn) ]
                     │
         Enqueues Scan & Intel Jobs
                     │
                     ▼
           [ Redis 7.0 Broker ]
         ┌───────────┴───────────┐
         ▼                       ▼
 [ Celery Worker: scan ]   [ Celery Worker: intel/maint ]
 (Concurrency: 4-8 slots)  (Concurrency: 2 slots)
         │                       │
         └───────────┬───────────┘
                     ▼
       [ PostgreSQL 16 / SQLite WAL ]
       [ Integration Outbox Table   ]
```

---

### 2. Distributed Locking & Fail-Closed Semantics

#### 2.1 Mutual Exclusion via Redis Distributed Lock
- **Lock Identifier:** `sentinelwp:vuln_intel_sync`
- **Mechanism:** Redis `SET key value NX PX 900000` with unique UUID ownership token.
- **Safe Release:** Atomic Lua script verifies ownership token matches before deleting key, preventing accidental lock deletion by expired lease holders:
  ```lua
  if redis.call("get", KEYS[1]) == ARGV[1] then
      return redis.call("del", KEYS[1])
  else
      return 0
  end
  ```
- **Live Infrastructure Verification:** Verified against live local Redis on `localhost:6379`.

#### 2.2 Fail-Closed Guarantee
- When `REQUIRE_DISTRIBUTED_LOCK=true`:
  - If Redis is unreachable, the system raises a `RuntimeError` rather than silently degrading to local in-process threading.
  - Guarantees zero uncoordinated concurrent synchronization loops in multi-node clusters.

---

### 3. Outbox Pattern Crash Recovery & Worker Fault Tolerance

#### 3.1 Worker Crash Scenario (S4-GAP-001)
If a worker crashes while processing an integration event in `PROCESSING` state:
- **Detection:** `recover_stale_outbox_events_task` runs periodically via Celery Beat, querying events exceeding `stale_threshold_seconds` (default 600s).
- **Lease Claiming:** Atomically claims the event with an incremented attempt counter.
- **Idempotency Check:** Verifies whether the associated `ScanJob` or `ScanResult` was already written before worker death. If completed, marks event `DELIVERED` without duplicate execution.
- **Bounded Retries:** Transitions to `DEAD_LETTER` after 3 failed attempts, preventing infinite execution loops.

#### 3.2 Scheduled Run Reconciliation (S4-GAP-003)
- If a scheduler claims a scheduled run but crashes before dispatching the Celery task, `reconcile_orphaned_scheduled_runs_task` flags the run as failed and logs an audit trail event, allowing subsequent scheduled runs to trigger cleanly.

---

### 4. Real vs. Mocked Infrastructure Test Breakdown

| Test Area | Execution Environment | Real Infrastructure Components | Mocked / Simulated Components | Technical Justification |
|---|:---:|---|---|---|
| **Redis Distributed Locking** | **Live** | Local Redis 7.0 daemon (`localhost:6379`), socket connections, Lua scripts | None | Tests actual network socket semantics and mutual exclusion. |
| **Outbox Crash Recovery** | **Live** | Real SQLite `integration_outbox` table, transaction commits, queries | Worker termination simulated by setting status `PROCESSING` | Validates SQL schema compatibility and state transitions without killing processes. |
| **PostgreSQL Schema Migration** | **Hybrid** | SQLAlchemy 2.x engine, metadata reflection, table DDL | Target network socket in unit tests | Verifies dual-compatibility without requiring dedicated external Postgres database. |
| **Celery Tasks Execution** | **In-Memory** | Celery task signatures, serialization, database persistence | Celery worker subprocess IPC (executed eagerly/directly) | Guarantees deterministic assertion checking without IPC flakiness. |

---

### 5. High Availability (HA) Pilot Readiness Verdict

> [!NOTE] High Availability Status  
> In-cluster fail-closed distributed locking, atomic lease reclamation, and idempotent outbox recovery are verified. True multi-node high availability requires multi-node Redis Sentinel / cluster deployments in enterprise production environments.
