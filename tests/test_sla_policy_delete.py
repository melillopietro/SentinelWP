"""Regression: SLA policy deletion (repository + Postgres RemediationRepository)."""
import os
import sys
import uuid
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import repository
from core.models import SLAPolicy, Tenant
from config import is_postgres_configured


class TestSLAPolicyDelete(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository.init_db()

    def setUp(self):
        self.tenant_id = f"sla-del-{uuid.uuid4().hex[:8]}"
        repository.create_tenant(
            Tenant(id=self.tenant_id, name="SLA Delete Test", slug=f"sla-{uuid.uuid4().hex[:6]}")
        )

    def test_delete_sla_policy_sqlite_repository(self):
        policy = SLAPolicy(
            tenant_id=self.tenant_id,
            name="Critical 7-day",
            severity="critical",
            due_days=7,
        )
        repository.create_sla_policy(policy)
        self.assertIsNotNone(repository.get_sla_policy(policy.id, self.tenant_id))
        self.assertTrue(repository.delete_sla_policy(policy.id, self.tenant_id))
        self.assertIsNone(repository.get_sla_policy(policy.id, self.tenant_id))
        self.assertFalse(repository.delete_sla_policy(policy.id, self.tenant_id))

    def test_delete_sla_policy_tenant_scoped(self):
        other_tenant = f"sla-other-{uuid.uuid4().hex[:8]}"
        repository.create_tenant(
            Tenant(id=other_tenant, name="Other", slug=f"oth-{uuid.uuid4().hex[:6]}")
        )
        policy = SLAPolicy(tenant_id=self.tenant_id, name="Scoped", severity="high")
        repository.create_sla_policy(policy)
        self.assertFalse(repository.delete_sla_policy(policy.id, other_tenant))
        self.assertIsNotNone(repository.get_sla_policy(policy.id, self.tenant_id))

    @unittest.skipUnless(is_postgres_configured(), "PostgreSQL not configured")
    def test_delete_sla_policy_remediation_repository(self):
        from core.db.session import get_session_factory
        from core.db.repositories.remediation_repo import RemediationRepository

        policy = SLAPolicy(
            tenant_id=self.tenant_id,
            name="PG delete",
            severity="medium",
            due_days=14,
        )
        factory = get_session_factory()
        with factory() as session:
            repo = RemediationRepository(session)
            repo.create_sla_policy(policy)
            session.commit()
        with factory() as session:
            repo = RemediationRepository(session)
            self.assertTrue(repo.delete_sla_policy(policy.id, tenant_id=self.tenant_id))
            session.commit()
            self.assertIsNone(repo.get_sla_policy(policy.id, tenant_id=self.tenant_id))


if __name__ == "__main__":
    unittest.main()
