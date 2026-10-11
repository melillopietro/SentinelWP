"""
Seed isolated test fixtures for Sprint 9 Browser & E2E Validation.
Creates Admin, Analyst, and Viewer accounts, test assets, and sample findings.
"""
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import repository, auth
from core.models import Tenant, User, Asset, Finding, Severity, ScanResult, ScanStatus, ScanAuthorization

def seed_pilot_fixtures(db_path="/tmp/sentinelwp_pilot_test.db"):
    os.environ["WSA_DB_PATH"] = db_path
    repository.DATABASE_PATH = db_path
    repository.init_db()

    tenant_id = "pilot-enterprise-tenant"
    if not repository.get_tenant(tenant_id):
        repository.create_tenant(Tenant(id=tenant_id, name="Pilot Corp Global", slug="pilot-corp"))

    # Seed Admin
    admin_pw = os.getenv("PILOT_ADMIN_PASSWORD", "PilotAdminPass2026!")
    if not repository.get_user_by_username("pilot_admin", tenant_id=tenant_id):
        u_admin = auth.create_user(username="pilot_admin", password=admin_pw, email="admin@pilot.local", role="admin")
        u_admin.tenant_id = tenant_id
        u_admin.status = "active"
        repository.save_user(u_admin)

    # Seed Analyst
    analyst_pw = os.getenv("PILOT_ANALYST_PASSWORD", "PilotAnalystPass2026!")
    if not repository.get_user_by_username("pilot_analyst", tenant_id=tenant_id):
        u_analyst = auth.create_user(username="pilot_analyst", password=analyst_pw, email="analyst@pilot.local", role="analyst")
        u_analyst.tenant_id = tenant_id
        u_analyst.status = "active"
        repository.save_user(u_analyst)

    # Seed Viewer
    viewer_pw = os.getenv("PILOT_VIEWER_PASSWORD", "PilotViewerPass2026!")
    if not repository.get_user_by_username("pilot_viewer", tenant_id=tenant_id):
        u_viewer = auth.create_user(username="pilot_viewer", password=viewer_pw, email="viewer@pilot.local", role="viewer")
        u_viewer.tenant_id = tenant_id
        u_viewer.status = "active"
        repository.save_user(u_viewer)

    # Seed Asset
    asset_id = "asset-pilot-001"
    asset = repository.get_asset(asset_id, tenant_id=tenant_id)
    if not asset:
        asset = Asset(
            id=asset_id,
            tenant_id=tenant_id,
            canonical_url="http://127.0.0.1:8099",
            hostname="127.0.0.1:8099",
            display_name="WordPress Pilot Lab Target",
            environment="staging",
            criticality="high",
            status="active",
            monitoring_enabled=True,
            wp_version="6.4.3",
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        repository.save_asset(asset)

    # Grant active ScanAuthorization
    auth_rec = ScanAuthorization(
        id=f"auth-{uuid.uuid4().hex[:8]}",
        tenant_id=tenant_id,
        asset_id=asset_id,
        status="active",
        approved_by="pilot_admin",
        notes="Authorized for Sprint 9 Pilot Testing",
        valid_until="2030-01-01T00:00:00Z"
    )
    repository.save_scan_authorization(auth_rec)

    print("Pilot fixtures successfully seeded into:", db_path)

if __name__ == "__main__":
    seed_pilot_fixtures()
