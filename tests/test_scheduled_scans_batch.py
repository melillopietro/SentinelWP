import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock
from app import app
from core import repository
from core.models import ScheduledScan


class TestScheduledScansBatch(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        # Clean any test schedules in repository
        for s in repository.list_scheduled_scans():
            repository.delete_scheduled_scan(s.id)

    def _login(self, client, role="analyst"):
        with client.session_transaction() as sess:
            sess["user_id"] = "test-user-id"
            sess["username"] = "testanalyst"
            sess["role"] = role

    # 1. 3 URL valide -> 3 ScheduledScan create
    def test_three_valid_urls_creates_three_schedules(self):
        self._login(self.client)
        payload = {
            "targets": "https://site1.example.org\nhttps://site2.example.org\nhttps://site3.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
            "auto_authorize": "1",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 3)
        urls = {s.target_url for s in schedules}
        self.assertEqual(urls, {"https://site1.example.org", "https://site2.example.org", "https://site3.example.org"})

    # 2. URL senza schema -> normalizzata a https://
    def test_missing_scheme_normalized_to_https(self):
        self._login(self.client)
        payload = {
            "targets": "site-no-scheme.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
            "auto_authorize": "1",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 1)
        self.assertEqual(schedules[0].target_url, "https://site-no-scheme.example.org")

    # 3. URL duplicate nell'input -> una sola schedule
    def test_duplicate_input_urls_creates_single_schedule(self):
        self._login(self.client)
        payload = {
            "targets": "https://dup.example.org\nhttps://dup.example.org/\ndup.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
            "auto_authorize": "1",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 1)
        self.assertEqual(schedules[0].target_url, "https://dup.example.org")

    # 4. Schedule già esistente -> non duplicata
    def test_existing_schedule_not_duplicated(self):
        self._login(self.client)
        existing = ScheduledScan(
            target_url="https://existing.example.org",
            scan_mode="safe-active",
            interval_hours=24,
            created_by="test",
        )
        repository.save_scheduled_scan(existing)

        payload = {
            "targets": "https://existing.example.org\nhttps://brand-new.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
            "auto_authorize": "1",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Skipped 1 duplicate schedule(s)", resp.data)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 2)
        urls = {s.target_url for s in schedules}
        self.assertEqual(urls, {"https://existing.example.org", "https://brand-new.example.org"})

    def test_safe_active_without_authorization_rejected(self):
        """SWP-08: Safe Active schedule creation without auto_authorize or pre-existing auth is rejected."""
        self._login(self.client)
        payload = {
            "targets": "https://unauthorized-target.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Authorization required for Safe Active/Full profiles", resp.data)
        schedules = [s for s in repository.list_scheduled_scans() if s.target_url == "https://unauthorized-target.example.org"]
        self.assertEqual(len(schedules), 0)

    # 5. localhost -> batch rifiutato (Fail-Closed)
    def test_localhost_target_rejects_entire_batch(self):
        self._login(self.client)
        payload = {
            "targets": "https://valid1.example.org\nhttp://localhost\nhttps://valid2.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Schedule not created. Invalid target(s)", resp.data)
        self.assertIn(b"localhost", resp.data)
        # Ensure 0 schedules were created (fail-closed)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 0)

    # 6. 192.168.1.1 -> batch rifiutato (Fail-Closed)
    def test_private_ip_target_rejects_entire_batch(self):
        self._login(self.client)
        payload = {
            "targets": "https://valid1.example.org\nhttp://192.168.1.1\nhttps://valid2.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "24",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Schedule not created. Invalid target(s)", resp.data)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 0)

    # 7. 169.254.169.254 -> batch rifiutato (Fail-Closed)
    def test_cloud_metadata_ip_rejects_entire_batch(self):
        self._login(self.client)
        payload = {
            "targets": "https://valid.example.org\nhttp://169.254.169.254/latest/meta-data",
            "scan_mode": "safe-active",
            "interval_hours": "24",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Schedule not created. Invalid target(s)", resp.data)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 0)

    # 8. Input vuoto -> errore
    def test_empty_targets_returns_error(self):
        self._login(self.client)
        payload = {
            "targets": "   \n\n  ",
            "scan_mode": "safe-active",
            "interval_hours": "24",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Target URL is required", resp.data)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 0)

    # 9. Oltre WSA_MAX_SCHEDULE_TARGETS -> errore
    @patch("app.WSA_MAX_SCHEDULE_TARGETS", 5)
    def test_exceeding_max_targets_rejects_batch(self):
        self._login(self.client)
        six_targets = "\n".join(f"https://target{i}.example.org" for i in range(6))
        payload = {
            "targets": six_targets,
            "scan_mode": "safe-active",
            "interval_hours": "24",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Batch exceeds maximum limit", resp.data)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 0)

    # 10. Interval non valido -> errore
    def test_invalid_interval_rejected(self):
        self._login(self.client)
        payload = {
            "targets": "https://valid.example.org",
            "scan_mode": "safe-active",
            "interval_hours": "99",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid frequency interval", resp.data)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 0)

    # 11. Scan mode non valido -> errore
    def test_invalid_scan_mode_rejected(self):
        self._login(self.client)
        payload = {
            "targets": "https://valid.example.org",
            "scan_mode": "destructive-exploit-mode",
            "interval_hours": "24",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid scan mode", resp.data)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 0)

    # 12. target_url legacy singolo -> ancora supportato
    def test_legacy_single_target_url_supported(self):
        self._login(self.client)
        payload = {
            "target_url": "https://legacy-single.example.org",
            "scan_mode": "passive",
            "interval_hours": "12",
        }
        resp = self.client.post("/schedule/create", data=payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        schedules = repository.list_scheduled_scans()
        self.assertEqual(len(schedules), 1)
        self.assertEqual(schedules[0].target_url, "https://legacy-single.example.org")
        self.assertEqual(schedules[0].scan_mode, "passive")
        self.assertEqual(schedules[0].interval_hours, 12)


if __name__ == "__main__":
    unittest.main()
