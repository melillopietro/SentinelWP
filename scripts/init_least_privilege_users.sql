-- =============================================================================
-- SentinelWP Enterprise Database User Hardening & Least Privilege Script
-- =============================================================================
-- Establishes role-based database segregation enforcing the Principle of Least Privilege (PoLP):
-- 1. sentinelwp_migration: DDL Administrator for Alembic schema migrations.
-- 2. sentinelwp_app: Application runtime role (DML only, no DDL/DROP/ALTER rights).
-- 3. sentinelwp_readonly: Reporting / BI / Audit inspection role (SELECT only).
-- =============================================================================

-- Ensure database exists
\connect sentinelwp

-- 1. Create Roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinelwp_migration') THEN
        CREATE ROLE sentinelwp_migration WITH LOGIN PASSWORD 'MIGRATE_PASSWORD_CHANGE_ME_IN_PROD';
    END IF;

    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinelwp_app') THEN
        CREATE ROLE sentinelwp_app WITH LOGIN PASSWORD 'APP_PASSWORD_CHANGE_ME_IN_PROD';
    END IF;

    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinelwp_readonly') THEN
        CREATE ROLE sentinelwp_readonly WITH LOGIN PASSWORD 'READONLY_PASSWORD_CHANGE_ME_IN_PROD';
    END IF;
END $$;

-- 2. Schema Permissions
GRANT USAGE, CREATE ON SCHEMA public TO sentinelwp_migration;
GRANT USAGE ON SCHEMA public TO sentinelwp_app;
GRANT USAGE ON SCHEMA public TO sentinelwp_readonly;

-- 3. Table Permissions for Migration Role (Full DDL + DML)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sentinelwp_migration;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sentinelwp_migration;

-- 4. Table Permissions for Application Runtime Role (DML Only: SELECT, INSERT, UPDATE, DELETE)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinelwp_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinelwp_app;

-- Revoke dangerous DDL permissions from application runtime
REVOKE TRUNCATE, TRIGGER ON ALL TABLES IN SCHEMA public FROM sentinelwp_app;

-- 5. Table Permissions for Read-Only Role (SELECT Only)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO sentinelwp_readonly;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER ON ALL TABLES IN SCHEMA public FROM sentinelwp_readonly;

-- 6. Configure Default Privileges for Future Tables & Sequences
ALTER DEFAULT PRIVILEGES FOR ROLE sentinelwp_migration IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinelwp_app;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelwp_migration IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sentinelwp_app;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelwp_migration IN SCHEMA public
    GRANT SELECT ON TABLES TO sentinelwp_readonly;

-- 7. Verification Query
SELECT rolname, rolcanlogin, rolsuper FROM pg_roles WHERE rolname LIKE 'sentinelwp%';
