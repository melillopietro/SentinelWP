"""Technology inventory catalog and per-asset canonical versioning."""
import pytest

from core import repository
from core.models import Asset, Finding, Severity, TechnologyObservation, Tenant
from core.technology_inventory import (
    collect_detected_themes,
    sync_asset_technology_inventory,
)


@pytest.fixture(autouse=True)
def _db():
    repository.init_db(force=True)
    tid = "tech-inv-tenant"
    repository.save_tenant(Tenant(id=tid, name="Tech", slug="tech-inv"))
    asset = Asset(
        tenant_id=tid,
        canonical_url="https://wp.example.com",
        hostname="wp.example.com",
        display_name="WP Test",
    )
    repository.save_asset(asset)
    yield tid, asset.id


def test_collect_detected_themes_merges_confidence(_db):
    findings = [
        Finding(
            category="information_disclosure",
            title="Theme Identified: twentytwentyfour",
            severity=Severity.INFO,
            raw_data={"theme": "twentytwentyfour", "version": None, "version_confidence": "low"},
        ),
        Finding(
            category="information_disclosure",
            title="Default Theme Present: twentytwentyfour",
            severity=Severity.LOW,
            raw_data={
                "theme": "twentytwentyfour",
                "slug": "twentytwentyfour",
                "version": "1.2",
                "version_confidence": "high",
            },
        ),
    ]
    themes = collect_detected_themes(findings)
    assert len(themes) == 1
    assert themes[0]["slug"] == "twentytwentyfour"
    assert themes[0]["version"] == "1.2"


def test_sync_inventory_canonical_per_asset(_db):
    tid, asset_id = _db
    findings = [
        Finding(category="plugins", title="Plugin Detected: woocommerce", severity=Severity.INFO, raw_data={"slug": "woocommerce", "version": "8.0.0", "version_confidence": "high"}),
        Finding(category="plugins", title="Plugin Detected: woocommerce", severity=Severity.INFO, raw_data={"slug": "woocommerce", "version": "8.1.0", "version_confidence": "low"}),
        Finding(category="information_disclosure", title="Theme Identified: storefront", severity=Severity.INFO, raw_data={"theme": "storefront", "version": "4.0", "version_confidence": "high"}),
    ]
    sync_asset_technology_inventory(
        tid,
        asset_id,
        findings,
        is_wordpress=True,
        wp_version="6.8.2",
        wp_version_source="meta_generator",
        wp_version_confidence="high",
    )
    obs = repository.list_technology_observations(tid, asset_id=asset_id)
    by_name = {o.name: o for o in obs}
    assert by_name["WordPress"].version == "6.8.2"
    assert by_name["woocommerce"].version == "8.0.0"
    assert by_name["storefront"].version == "4.0"

    sync_asset_technology_inventory(
        tid,
        asset_id,
        [
            Finding(category="plugins", title="Plugin Detected: woocommerce", severity=Severity.INFO, raw_data={"slug": "woocommerce", "version": "9.0.0", "version_confidence": "high"}),
        ],
        is_wordpress=True,
        wp_version="6.8.2",
    )
    obs2 = repository.list_technology_observations(tid, asset_id=asset_id)
    woo_rows = [o for o in obs2 if o.name == "woocommerce"]
    assert len(woo_rows) == 1
    assert woo_rows[0].version == "9.0.0"

    catalog = repository.aggregate_technology_catalog(tid)
    woo_plugin = [c for c in catalog if c.name == "woocommerce" and c.technology_type == "WORDPRESS_PLUGIN"]
    assert len(woo_plugin) == 1
    assert woo_plugin[0].version == "9.0.0"
    assets_v9 = repository.list_assets_by_technology(
        tid, technology_type="WORDPRESS_PLUGIN", name="woocommerce", version="9.0.0"
    )
    assert len(assets_v9) == 1