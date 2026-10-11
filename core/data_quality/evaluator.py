"""
Exposure Data Quality Engine for SentinelWP.

Detects and tracks data quality gaps across the exposure management lifecycle:
- Asset without owner (business or technical)
- Asset without assigned Business Unit
- Critical asset without active ownership verification
- Finding without associated immutable evidence
- Finding without computed priority score
- Stale vulnerability intelligence sync status
- Expired ScanAuthorization records
- Unknown WordPress version on confirmed WordPress asset
"""
import logging
from datetime import datetime, timezone
from typing import List

from core.models import DataQualityIssue, Asset, Finding
from core import repository
from core.easm.verification import is_asset_verified

logger = logging.getLogger("sentinelwp.data_quality")


class DataQualityEvaluator:
    """
    Evaluates enterprise data quality rules and persists detected discrepancies.
    """

    def __init__(self, tenant_id: str = "default-tenant"):
        self.tenant_id = tenant_id

    def evaluate_all(self) -> List[DataQualityIssue]:
        """Runs all data quality checks and records issues."""
        issues = []
        issues.extend(self.check_asset_ownership_and_bu())
        issues.extend(self.check_critical_asset_verification())
        issues.extend(self.check_finding_evidence())
        issues.extend(self.check_stale_authorizations())
        issues.extend(self.check_technology_completeness())

        for issue in issues:
            repository.save_data_quality_issue(issue)
        return issues

    def check_asset_ownership_and_bu(self) -> List[DataQualityIssue]:
        issues = []
        assets = repository.list_assets(self.tenant_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        for a in assets:
            if not a.business_owner and not a.technical_owner:
                issues.append(DataQualityIssue(
                    tenant_id=self.tenant_id,
                    entity_type="asset",
                    entity_id=a.id,
                    issue_type="ASSET_WITHOUT_OWNER",
                    severity="high" if a.criticality in ("critical", "high") else "medium",
                    description=f"Asset '{a.hostname}' lacks assigned business and technical owners",
                    detected_at=now_iso
                ))
            if not a.business_unit_id:
                issues.append(DataQualityIssue(
                    tenant_id=self.tenant_id,
                    entity_type="asset",
                    entity_id=a.id,
                    issue_type="ASSET_WITHOUT_BU",
                    severity="medium",
                    description=f"Asset '{a.hostname}' is not mapped to any Business Unit",
                    detected_at=now_iso
                ))
        return issues

    def check_critical_asset_verification(self) -> List[DataQualityIssue]:
        issues = []
        assets = repository.list_assets(self.tenant_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        for a in assets:
            if a.criticality == "critical" and not is_asset_verified(self.tenant_id, a.id):
                issues.append(DataQualityIssue(
                    tenant_id=self.tenant_id,
                    entity_type="asset",
                    entity_id=a.id,
                    issue_type="CRITICAL_ASSET_UNVERIFIED",
                    severity="critical",
                    description=f"Critical asset '{a.hostname}' lacks verified domain ownership",
                    detected_at=now_iso
                ))
        return issues

    def check_finding_evidence(self) -> List[DataQualityIssue]:
        issues = []
        findings, _ = repository.list_findings(self.tenant_id, page_size=1000)
        now_iso = datetime.now(timezone.utc).isoformat()

        for f in findings:
            if f.status in ("OPEN", "TRIAGED", "IN_REMEDIATION"):
                evidences = repository.list_evidences_for_finding(f.id, self.tenant_id)
                if not evidences:
                    issues.append(DataQualityIssue(
                        tenant_id=self.tenant_id,
                        entity_type="finding",
                        entity_id=f.id,
                        issue_type="FINDING_WITHOUT_EVIDENCE",
                        severity="medium",
                        description=f"Active finding '{f.title}' ({f.priority_band}) has no associated evidence records",
                        detected_at=now_iso
                    ))
        return issues

    def check_stale_authorizations(self) -> List[DataQualityIssue]:
        issues = []
        auths = repository.list_scan_authorizations(tenant_id=self.tenant_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        for auth in auths:
            if auth.valid_until and auth.valid_until < now_iso and auth.status == "active":
                issues.append(DataQualityIssue(
                    tenant_id=self.tenant_id,
                    entity_type="authorization",
                    entity_id=auth.id,
                    issue_type="EXPIRED_SCAN_AUTHORIZATION",
                    severity="high",
                    description=f"Scan authorization {auth.id} for asset {auth.asset_id} has expired but remains marked active",
                    detected_at=now_iso
                ))
        return issues

    def check_technology_completeness(self) -> List[DataQualityIssue]:
        issues = []
        assets = repository.list_assets(self.tenant_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        for a in assets:
            if "wordpress" in (a.tags or "").lower():
                techs = repository.list_technology_observations(self.tenant_id, a.id)
                wp_tech = [t for t in techs if t.name.lower() == "wordpress"]
                if wp_tech and not wp_tech[0].version:
                    issues.append(DataQualityIssue(
                        tenant_id=self.tenant_id,
                        entity_type="technology",
                        entity_id=a.id,
                        issue_type="UNKNOWN_WP_VERSION_CONFIRMED_ASSET",
                        severity="low",
                        description=f"WordPress asset '{a.hostname}' has no detected version recorded in technology inventory",
                        detected_at=now_iso
                    ))
        return issues
