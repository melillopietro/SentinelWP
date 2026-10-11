# Architectural Migration Plan: SQLite to PostgreSQL & Alembic

**Author:** Principal Security Architect & Lead Python Engineer  
**System:** SentinelWP Enterprise Posture Management  
**Iteration:** Phase 2 (Enterprise Multi-Tenancy & Asset Authorization)  
**Status:** Approved Architecture Plan  

---

## 1. Executive Summary & Rationale

SentinelWP has completed Phase 1 (Enterprise P0 Hardening & Multi-Target Scheduler) and Phase 2 (Workspace/Tenant Isolation, Asset Inventory 360, Scan Authorization Guardrails, and Immutable Audit Logging). While SQLite 3 with Write-Ahead Logging (WAL) and foreign keys enabled provides a robust, zero-dependency development and single-node runtime, scaling to true enterprise tier requires migrating to **PostgreSQL (v15+)** managed with **Alembic**.

### Key Drivers for Migration:
1. **Concurrency & Throughput:** SQLite serializes write transactions with a database-level lock. Under heavy concurrent scanning, asynchronous finding ingestion, and concurrent multi-tenant reporting, write contention occurs. PostgreSQL offers fine-grained Multi-Version Concurrency Control (MVCC) with row-level locking.
2. **Native JSONB Performance:** Vulnerability intelligence CVE mappings, raw scanner outputs, and immutable audit metadata benefit from indexed PostgreSQL `JSONB` with GIN indexing (`@>`, `jsonb_path_ops`).
3. **Database-Level Tenant Enforcement via Row-Level Security (RLS):** While application-level enforcement (`core/authorization.py`) currently prevents cross-tenant access, PostgreSQL RLS provides Defense-in-Depth, ensuring queries executed with `app.current_tenant_id` cannot access foreign tenant records even in case of an application logic bug or raw query injection.
4. **Data Integrity & Precise Types:** Transition from SQLite dynamic typing to native PostgreSQL `UUID`, `TIMESTAMPTZ`, `ENUM`, `BOOLEAN`, and strict relational constraints with cascading foreign keys.

---

## 2. Target PostgreSQL Schema Specification

```
                                  +-------------------+
                                  |      tenants      |
                                  +-------------------+
                                    |        |      |
           +------------------------+        |      +-----------------------+
           |                                 |                              |
           v                                 v                              v
     +-----------+                     +------------+                +--------------+
     |   users   |                     |   assets   |                | audit_events |
     +-----------+                     +------------+                +--------------+
                                         |        |
                         +---------------+        +---------------+
                         |                                        |
                         v                                        v
                 +---------------+                       +---------------------+
                 |     scans     |<----------------------| scan_authorizations |
                 +---------------+                       +---------------------+
                         |
                         v
                 +---------------+
                 |   findings    |
                 +---------------+
```

### 2.1 Table Schemas & Data Types

#### 1. `tenants`
```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);
CREATE INDEX idx_tenants_slug ON tenants(slug);
```

#### 2. `users`
```sql
CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');
CREATE TYPE user_status AS ENUM ('active', 'disabled', 'pending');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(150) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL DEFAULT '',
    role user_role NOT NULL DEFAULT 'viewer',
    status user_status NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_users_tenant_username UNIQUE (tenant_id, username)
);
CREATE INDEX idx_users_tenant ON users(tenant_id);
```

#### 3. `assets`
```sql
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    canonical_url TEXT NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    business_owner VARCHAR(255) NOT NULL DEFAULT '',
    technical_owner VARCHAR(255) NOT NULL DEFAULT '',
    environment VARCHAR(50) NOT NULL DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development', 'internal')),
    internet_exposure VARCHAR(50) NOT NULL DEFAULT 'external' CHECK (internet_exposure IN ('external', 'internal', 'restricted')),
    criticality VARCHAR(50) NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    data_classification VARCHAR(50) NOT NULL DEFAULT 'confidential' CHECK (data_classification IN ('public', 'internal', 'confidential', 'restricted')),
    authorization_status VARCHAR(50) NOT NULL DEFAULT 'unauthorized' CHECK (authorization_status IN ('authorized', 'unauthorized', 'pending', 'expired')),
    authorization_review_date TIMESTAMPTZ,
    tags TEXT NOT NULL DEFAULT '',
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    CONSTRAINT uq_assets_tenant_canonical UNIQUE (tenant_id, canonical_url)
);
CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_assets_hostname ON assets(tenant_id, hostname);
CREATE INDEX idx_assets_criticality ON assets(tenant_id, criticality);
CREATE INDEX idx_assets_auth_status ON assets(tenant_id, authorization_status);
```

#### 4. `scan_authorizations`
```sql
CREATE TABLE scan_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    allowed_profiles VARCHAR(255) NOT NULL DEFAULT 'safe_active,passive',
    request_budget INTEGER NOT NULL DEFAULT 1000 CHECK (request_budget > 0),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMPTZ NOT NULL,
    approved_by VARCHAR(150) NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    CONSTRAINT chk_auth_valid_window CHECK (valid_until > valid_from)
);
CREATE INDEX idx_scan_auth_asset ON scan_authorizations(asset_id);
CREATE INDEX idx_scan_auth_tenant ON scan_authorizations(tenant_id);
CREATE INDEX idx_scan_auth_window ON scan_authorizations(asset_id, status, valid_from, valid_until);
```

#### 5. `scans`
```sql
CREATE TYPE scan_status_enum AS ENUM ('pending', 'running', 'completed', 'failed');

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    status scan_status_enum NOT NULL DEFAULT 'pending',
    scan_mode VARCHAR(50) NOT NULL DEFAULT 'passive',
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    score DOUBLE PRECISION,
    grade VARCHAR(5),
    notes TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    initiated_by VARCHAR(150) NOT NULL DEFAULT '',
    wp_version VARCHAR(50),
    is_wordpress BOOLEAN,
    whois_info TEXT
);
CREATE INDEX idx_scans_tenant ON scans(tenant_id);
CREATE INDEX idx_scans_asset ON scans(asset_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_started ON scans(tenant_id, started_at DESC);
```

#### 6. `findings`
```sql
CREATE TYPE severity_enum AS ENUM ('critical', 'high', 'medium', 'low', 'info');

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category VARCHAR(100) NOT NULL DEFAULT '',
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity severity_enum NOT NULL DEFAULT 'info',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    remediation TEXT NOT NULL DEFAULT '',
    reference TEXT NOT NULL DEFAULT '',
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_findings_tenant ON findings(tenant_id);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_asset ON findings(asset_id);
CREATE INDEX idx_findings_severity ON findings(tenant_id, severity);
CREATE INDEX idx_findings_raw_gin ON findings USING GIN (raw_data jsonb_path_ops);
```

#### 7. `scheduled_scans`
```sql
CREATE TABLE scheduled_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    scan_mode VARCHAR(50) NOT NULL DEFAULT 'passive',
    interval_hours INTEGER NOT NULL DEFAULT 24 CHECK (interval_hours IN (12, 24, 168)),
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(150) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_sched_tenant ON scheduled_scans(tenant_id);
CREATE INDEX idx_sched_next_run ON scheduled_scans(enabled, next_run_at) WHERE enabled = TRUE;
```

#### 8. `audit_events`
```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_user_id VARCHAR(100) NOT NULL DEFAULT '',
    actor_username VARCHAR(150) NOT NULL DEFAULT '',
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL DEFAULT '',
    resource_id VARCHAR(100) NOT NULL DEFAULT '',
    result VARCHAR(50) NOT NULL DEFAULT 'success' CHECK (result IN ('success', 'denied', 'failure')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Append-only rule: block UPDATE and DELETE on audit_events
CREATE RULE audit_no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_events DO INSTEAD NOTHING;

CREATE INDEX idx_audit_tenant_time ON audit_events(tenant_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_events(tenant_id, action);
CREATE INDEX idx_audit_result ON audit_events(tenant_id, result);
CREATE INDEX idx_audit_metadata_gin ON audit_events USING GIN (metadata jsonb_path_ops);
```

#### 9. `vulnerabilities` & Intelligence Tables
```sql
CREATE TABLE vulnerabilities (
    id VARCHAR(100) PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    cvss_score DOUBLE PRECISION,
    severity severity_enum NOT NULL DEFAULT 'medium',
    software_type VARCHAR(50) NOT NULL DEFAULT 'plugin',
    plugin_slug VARCHAR(200),
    affected_versions TEXT NOT NULL DEFAULT '',
    patched_version VARCHAR(100),
    published_date TIMESTAMPTZ,
    last_modified TIMESTAMPTZ,
    source VARCHAR(50) NOT NULL DEFAULT 'wordfence',
    kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vuln_plugin ON vulnerabilities(plugin_slug);
CREATE INDEX idx_vuln_kev ON vulnerabilities(kev_listed) WHERE kev_listed = TRUE;

CREATE TABLE feed_sync_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    records_synced INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE app_settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

---

## 3. Defense-in-Depth: PostgreSQL Row-Level Security (RLS)

To eliminate any chance of application-level IDOR bypass, PostgreSQL Row-Level Security will be activated on all tenant-partitioned tables (`users`, `assets`, `scan_authorizations`, `scans`, `findings`, `scheduled_scans`, `audit_events`).

### 3.1 Enabling RLS and Policy Definition
```sql
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Dynamic Tenant Context Policy
CREATE POLICY tenant_isolation_assets ON assets
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_scans ON scans
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_findings ON findings
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_schedules ON scheduled_scans
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_authorizations ON scan_authorizations
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_audit ON audit_events
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_users ON users
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
```

### 3.2 SQLAlchemy / Psycopg3 Session Integration
When acquiring a connection from the pool before executing queries in a request context:
```python
def set_tenant_context(connection, tenant_id: str):
    with connection.cursor() as cursor:
        cursor.execute("SET LOCAL app.current_tenant_id = %s;", (tenant_id,))
```
This guarantees that queries physically cannot return rows belonging to another tenant.

---

## 4. Alembic Migration Strategy

### 4.1 Setup & Configuration
1. Initialize Alembic:
   ```bash
   alembic init alembic
   ```
2. Configure `alembic.ini` and `env.py` to target `DATABASE_URL` (e.g. `postgresql+psycopg://user:pass@host:5432/sentinelwp`).
3. Set naming conventions for constraints in `env.py` to prevent unnamed foreign key collisions:
   ```python
   naming_convention = {
       "ix": "ix_%(column_0_label)s",
       "uq": "uq_%(table_name)s_%(column_0_name)s",
       "ck": "ck_%(table_name)s_%(constraint_name)s",
       "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
       "pk": "pk_%(table_name)s"
   }
   ```

### 4.2 Revision Roadmap
- **`0001_baseline_enterprise_schema.py`**:
  - Creates ENUMs, `tenants`, `users`, `assets`, `scan_authorizations`, `scans`, `findings`, `scheduled_scans`, `audit_events`, `vulnerabilities`, `feed_sync_runs`, `app_settings`.
  - Sets up all Primary, Foreign Key constraints, Unique constraints, and Indexes.
  - Seeds the default workspace `default-tenant`.
- **`0002_enable_rls_policies.py`**:
  - Applies Row-Level Security policies and app-level session hooks.
  - Adds audit append-only rules.

---

## 5. Offline & Online Data Migration Procedure

### 5.1 Dual-Phase Migration Approach

```
Phase A: Schema Setup & Validation
         Deploy PostgreSQL + run alembic upgrade head
         ↓
Phase B: Data Export & Normalization (ETL)
         Extract from data/wsa.db
         Transform string timestamps to ISO8601 UTC
         Map string IDs to UUID format
         ↓
Phase C: Bulk Ingestion (COPY / Batch Insert)
         Load tenants -> users -> assets -> authorizations -> scans -> findings -> schedules -> audit
         ↓
Phase D: Verification & Parity Checks
         Record counts match 100%
         Hash verification of findings
         ↓
Phase E: Cutover
         Update DATABASE_URL environment variable to PostgreSQL
         Restart app service
```

### 5.2 SQLite Export & Transformation Script (`scripts/migrate_sqlite_to_pg.py`)
A migration script transforms legacy SQLite rows:
- Replaces any empty `tenant_id` with `default-tenant`'s UUID.
- Validates that every `scan` with a valid `canonical_url` maps to an existing `assets` record.
- Encodes dict fields into valid JSON strings for `JSONB` bulk COPY.
- Executes `COPY ... FROM STDIN WITH (FORMAT csv)` for rapid sub-second ingestion.

---

## 6. Rollback Plan & Parity Checklist

### 6.1 Rollback Plan
- **Condition:** Any data disparity, connection pool exhaustion, or transaction latency exceeding SLA during cutover.
- **Rollback Steps:**
  1. Set application environment `WSA_DATABASE_BACKEND=sqlite`.
  2. Point `DATABASE_PATH` back to validated `data/wsa.db`.
  3. Restart application service.
  4. Post-mortem review of PostgreSQL logs and metrics.

### 6.2 Verification Checklist
- [ ] Record count parity: `COUNT(*)` matches across all tables between SQLite and PostgreSQL.
- [ ] Tenant integrity: 0 orphan rows without valid `tenant_id`.
- [ ] Asset canonicalization: 0 duplicate `(tenant_id, canonical_url)` assets.
- [ ] Audit log integrity: 0 modified or deleted audit entries.
- [ ] Scan authorization guardrail: Safe Active scans block without active authorization window.
- [ ] Cross-tenant IDOR: Cross-tenant accesses return HTTP 404.
- [ ] Performance benchmark: 100 concurrent read queries complete in < 50ms p95.
