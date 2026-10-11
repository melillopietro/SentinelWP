# SentinelWP — Sprint 9 WordPress Laboratory Validation Report

## 1. Laboratory Environment Profile

The WordPress validation target was hosted in container `sentinelwp-pilot-wordpress` connected to MariaDB 10.5:
- **Target URL**: `http://127.0.0.1:8099/`
- **Core Version**: WordPress 6.4.3
- **Active Theme**: Twenty Twenty-Four
- **Lab Status**: Fresh initialized installation with synthetic admin posts and default configuration.

---

## 2. Scan Execution & Detection Accuracy

### 2.1 Scan Parameters
- **Profile**: `safe-active`
- **Initiated By**: `pilot_admin`
- **Tenant ID**: `pilot-enterprise-tenant`
- **Asset ID**: `asset-pilot-001`
- **Scan Authorization Guardrail**: Verified active and valid through 2030.

### 2.2 Execution Metrics
- **Duration**: 6.28 seconds
- **CMS Identification**: `is_wordpress = True` (Confidence: `high`, 1.0)
- **Detected Core Version**: `6.4.3` (Source: generator tag / core probes, 100% exact match)
- **Findings Count**: 48 findings
- **Calculated Posture Score**: 85.3 (Security Grade: **F**, due to plaintext HTTP deployment and default WordPress surface)

---

## 3. Findings Breakdown

| Category | Finding Title | Severity | Confidence | Remediation Recommendation |
|----------|---------------|----------|------------|----------------------------|
| `encryption` | Site Not Using HTTPS | **CRITICAL** | 1.0 | Enforce TLS/HTTPS across all endpoints. |
| `enumeration` | REST API WAF/Rewrite Bypass for User Enumeration | **HIGH** | 0.9 | Restrict unauthenticated REST endpoint `?rest_route=/wp/v2/users`. |
| `enumeration` | Author Archive User Enumeration | **HIGH** | 0.9 | Disable author archive enumeration queries (`/?author=1`). |
| `headers` | Missing Security Header: Strict-Transport-Security | **HIGH** | 1.0 | Configure `Strict-Transport-Security` header. |
| `authentication` | XML-RPC system.multicall Available | **HIGH** | 0.9 | Disable XML-RPC or restrict via reverse proxy. |
| `information` | WordPress Version Disclosed in Meta Generator | **LOW** | 1.0 | Suppress generator meta tag in theme header. |

---

## 4. Differential Scan Stability & Reproducibility

A second baseline comparison scan was executed against `http://127.0.0.1:8099` by `pilot_analyst`:
- **Finding Count**: Exactly 48 findings (100% match).
- **Finding State Transitions**: No phantom findings, zero false closures.
- **Differential Result**: `0 NEW`, `48 PERSISTING`, `0 RESOLVED`.
- **Verdict**: Detection engine demonstrates deterministic stability and reproducibility.
