# SentinelWP — Sprint 9 Remaining Technical Gaps & Post-Pilot Roadmap

## 1. Overview

While SentinelWP is certified **GO** for a controlled enterprise pilot, this document catalogs non-blocking observations and future enhancements planned for Sprint 10 / General Availability (GA).

---

## 2. Tracked Technical Items

| ID | Category | Description | Severity / Priority | Planned Resolution |
|----|----------|-------------|---------------------|--------------------|
| **GAP-S9-01** | UI / CSP | Content Security Policy currently blocks remote Google Fonts (`fonts.googleapis.com`). Fonts fallback gracefully to system fonts. | Low / P3 | Bundle Inter font assets locally in `static/fonts/` or update CSP `style-src` / `font-src` directives. |
| **GAP-S9-02** | Security | urlllib3 TLS InsecureRequestWarnings emitted during unverified HTTPS requests to test endpoints or DNS lookups. | Low / P3 | Maintain central TLS warning filter or configure dedicated trust store for internal enterprise certificates. |
| **GAP-S9-03** | Operations | Celery Beat periodic task scheduling defaults to in-memory schedule in local development. | Medium / P2 | Deploy `django-celery-beat` or Redis-backed schedule store for multi-replica Celery Beat redundancy in GA. |
| **GAP-S9-04** | Performance | In-memory report rendering for scans with >10,000 findings could increase worker RAM footprint. | Low / P3 | Stream large Excel/SARIF exports in chunks for enterprise multi-thousand asset batch scans. |

---

## 3. Production Readiness Criteria for GA (General Availability)

1. Zero CSP console violations when rendering with bundled fonts.
2. Production load testing with 50+ concurrent active scans against a distributed worker pool.
3. Multi-cluster PostgreSQL read-replica configuration for global analytics queries.
