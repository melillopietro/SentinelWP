# SentinelWP Enterprise - Release & Quality Assurance Process

## 1. Release Philosophy

Every SentinelWP release must adhere to strict quality and security standards. Because SentinelWP performs critical security posture monitoring, stability, zero regressions, and cryptographic verification are non-negotiable.

---

## 2. Release Gates & Mandatory Checklists

Before any commit or tag can be merged into `main` or promoted to production, the following release gates **must pass**:

### Gate 1: WordPress Version Detection Regression Guard
```bash
pytest tests/test_wordpress_version_regression.py -q
```
- **Requirement**: **28/28 PASS** (0 failures, 0 errors).
- **Protected Capabilities**:
  - Passive, Safe Active, and Full scan profile parity.
  - Multi-source version detection (generator, scripts, style, readme, RSS, login, asset query params).
  - Unknown fallback guarantee (never emit an invented version for non-WP targets).
  - Confidence scoring (`high`, `medium`, `low`, `unknown`).

### Gate 2: Full Repository Test Suite
```bash
pytest tests/ -q
```
- **Requirement**: **100% passing tests**.

### Gate 3: Database Migration Verification
```bash
alembic check
alembic heads
```
- **Requirement**: Schema is clean, and there is exactly one single head revision.

### Gate 4: Security SAST & Dependency Auditing
```bash
bandit -r core/ scanners/ -ll
python scripts/generate_sbom.py sbom.json
```
- **Requirement**: No high or critical SAST vulnerabilities; valid CycloneDX 1.5 SBOM generated.

---

## 3. Branching & Tagging Conventions

- **Production Branch**: `main` (protected; requires PR approval + passing CI).
- **Release Branches**: `release/vX.Y.Z`.
- **Hotfix Branches**: `fix/<issue-name>`.
- **Feature Branches**: `feat/<feature-name>`.

### Version Tagging:
Releases use Semantic Versioning (`vMAJOR.MINOR.PATCH`):
- Major: Incompatible API or database architecture changes.
- Minor: Backwards-compatible features, new scanners, posture improvements.
- Patch: Bug fixes, vulnerability updates, performance enhancements.

---

## 4. Container Image Signing & Artifact Verification

All production Docker container images are signed using Cosign:

```bash
# Build image
docker build -t ghcr.io/melillopietro/sentinelwp:v5.0.0 .

# Sign container image
cosign sign --key k8s://sentinelwp-secrets/cosign-key ghcr.io/melillopietro/sentinelwp:v5.0.0
```
