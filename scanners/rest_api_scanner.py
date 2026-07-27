"""
WordPress REST API Scanner Module
Checks exposure, reachability, route discovery, and sensitive endpoints via /wp-json/
"""
from typing import Optional, Dict, Any, List
from scanners.base import BaseScanner
from core.models import Severity


class RESTAPIScanner(BaseScanner):
    """
    Scanner for WordPress REST API endpoints.
    Audits /wp-json/, /wp-json/wp/v2/, /wp-json/wp/v2/users,
    /wp-json/wp/v2/posts, and /wp-json/wp/v2/pages.
    """

    def scan(self) -> list:
        self._check_root_endpoint()
        self._check_wp_v2_endpoint()
        self._check_users_endpoint()
        self._check_posts_endpoint()
        self._check_pages_endpoint()
        return self.findings

    def _check_root_endpoint(self):
        """1. Check GET /wp-json/ - verify reachability and detect WordPress namespace"""
        url = f"{self.target_url}/wp-json/"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        if not isinstance(data, dict):
            return

        namespaces = data.get("namespaces", [])
        if not isinstance(namespaces, list):
            namespaces = []

        is_wp = any(
            isinstance(ns, str) and (ns == "wp/v2" or ns.startswith("wp/"))
            for ns in namespaces
        ) or "routes" in data or "name" in data

        if is_wp:
            detected_namespaces = [ns for ns in namespaces if isinstance(ns, str)]
            self._add_finding(
                category="rest_api",
                title="WordPress REST API Root Accessible",
                description="The WordPress REST API root endpoint (/wp-json/) is publicly accessible.",
                severity=Severity.INFO,
                confidence=1.0,
                remediation="Ensure sensitive endpoints are protected if public access to API root is not required.",
                raw_data={
                    "url": url,
                    "status_code": resp.status_code,
                    "endpoint_reachable": True,
                    "namespaces": detected_namespaces,
                },
            )

    def _check_wp_v2_endpoint(self):
        """2. Check GET /wp-json/wp/v2/ - endpoint discovery, list available routes"""
        url = f"{self.target_url}/wp-json/wp/v2/"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        if not isinstance(data, dict):
            return

        routes_dict = data.get("routes", {})
        routes_list = []
        if isinstance(routes_dict, dict):
            routes_list = sorted(list(routes_dict.keys()))

        self._add_finding(
            category="rest_api",
            title="WordPress REST API Route Discovery (wp/v2)",
            description=f"Discovered wp/v2 REST API namespace with {len(routes_list)} available routes.",
            severity=Severity.INFO,
            confidence=0.95,
            remediation="Review available REST API routes and disable unused or internal endpoints.",
            raw_data={
                "url": url,
                "status_code": resp.status_code,
                "endpoint_reachable": True,
                "route_count": len(routes_list),
                "routes": routes_list,
            },
        )

    def _check_users_endpoint(self):
        """
        3. Check GET /wp-json/wp/v2/users - count records and exposed fields.
        DO NOT save emails, tokens, or personal data.
        Only save: endpoint reachable, record count, exposed field names, whether auth is required.
        """
        url = f"{self.target_url}/wp-json/wp/v2/users"
        resp = self._get(url)
        if not resp:
            return

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                data = None

            if isinstance(data, list):
                record_count = len(data)
                exposed_fields_set = set()
                for item in data:
                    if isinstance(item, dict):
                        exposed_fields_set.update(item.keys())
                exposed_fields = sorted(list(exposed_fields_set))

                self._add_finding(
                    category="rest_api",
                    title="WordPress REST API Users Endpoint Accessible",
                    description="Informational — Public user identifiers or display names exposed via REST API",
                    severity=Severity.INFO,
                    confidence=1.0,
                    remediation="Restrict access to /wp-json/wp/v2/users if user enumeration should be disabled.",
                    raw_data={
                        "url": url,
                        "endpoint_reachable": True,
                        "record_count": record_count,
                        "exposed_fields": exposed_fields,
                        "exposed_field_names": exposed_fields,
                        "auth_required": False,
                    },
                )
        elif resp.status_code in (401, 403):
            # Auth required - no public user data exposed
            pass

    def _check_posts_endpoint(self):
        """4. Check GET /wp-json/wp/v2/posts - verify public access without auth"""
        url = f"{self.target_url}/wp-json/wp/v2/posts"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        if isinstance(data, list):
            self._add_finding(
                category="rest_api",
                title="WordPress REST API Posts Endpoint Accessible",
                description="The /wp-json/wp/v2/posts endpoint is publicly accessible without authentication.",
                severity=Severity.LOW,
                confidence=0.9,
                remediation="Restrict access to REST API posts endpoint if post content should not be accessible via API.",
                raw_data={
                    "url": url,
                    "status_code": resp.status_code,
                    "endpoint_reachable": True,
                    "record_count": len(data),
                    "auth_required": False,
                },
            )

    def _check_pages_endpoint(self):
        """5. Check GET /wp-json/wp/v2/pages - verify public access without auth"""
        url = f"{self.target_url}/wp-json/wp/v2/pages"
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        if isinstance(data, list):
            self._add_finding(
                category="rest_api",
                title="WordPress REST API Pages Endpoint Accessible",
                description="The /wp-json/wp/v2/pages endpoint is publicly accessible without authentication.",
                severity=Severity.LOW,
                confidence=0.9,
                remediation="Restrict access to REST API pages endpoint if page content should not be accessible via API.",
                raw_data={
                    "url": url,
                    "status_code": resp.status_code,
                    "endpoint_reachable": True,
                    "record_count": len(data),
                    "auth_required": False,
                },
            )
