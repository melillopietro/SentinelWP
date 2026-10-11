# CI security gates (blocking)

Used by `.github/workflows/security_ci.yml` on PRs to `main`.

| Gate | Tool | Policy |
|------|------|--------|
| SAST | **Bandit** JSON + script | Scan uses `--exit-zero` to emit full JSON; **fail** only if any **issue severity HIGH** (Medium/Low are non-blocking). |
| Dependencies | **pip-audit** | **Fail** on `requirements-prod.txt` with `--strict` (Python **3.12**, production pin set). |
| Secrets | **Gitleaks** | **Fail** on detected secrets (no `continue-on-error`); full `fetch-depth: 0` for PR diff scan; allowlist in `.gitleaks.toml` for test fixtures only. |
| Lint | **Flake8** | **Fail** on `E9,F63,F7,F82` in `core/` and `scanners/`. |

**Justified non-blockers:** Bandit Medium/Low severities are informational until remediated in a dedicated hardening pass; HIGH is merge-blocking.

**PostgreSQL:** Disposable `postgres:15-alpine` service runs Alembic head, then Sprint 10 integration tests via `SENTINELWP_SPRINT10_PG_URL`.
