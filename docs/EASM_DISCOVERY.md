# EASM Discovery Architecture & Scope Governance

## Overview
The External Attack Surface Management (EASM) bounded discovery engine allows security teams to identify, inventory, and govern internet-exposed WordPress assets while maintaining strict governance boundaries.

## Core Concepts

### Discovery Scopes
A discovery scope defines legal, organizational, and technical boundaries for candidate identification:
- `root_domain`: Root domain (e.g. `example.com`).
- `allowed_suffixes`: Allowed suffixes (e.g. `['.example.com', 'example.com']`).
- `excluded_patterns`: Regex patterns for subdomains or paths that must NEVER be discovered or scanned (e.g. `[r"dev\.", r"staging\.", r"internal\."]`).
- `max_depth`: Maximum depth of subdomain discovery relative to the root (e.g. `2` allows `a.b.example.com` but excludes `a.b.c.example.com`).

### Candidate Lifecycle
1. **Candidate Ingestion**: Candidates are identified via DNS, certificates, or existing scan observations and placed in `discovered_assets` with status `NEW`.
2. **Review & Triage**: Security teams inspect candidates, review discovery confidence (`HIGH`, `MEDIUM`, `LOW`), and inspect raw evidence.
3. **Promotion**: Validated candidates are promoted into full `Asset` records (`DiscoveredAssetStatus.PROMOTED`) and linked to an Asset ID.
4. **Dismissal**: False positives or out-of-scope targets are transitioned to `DISMISSED` with an audit trail.

### Safe Boundary Guardrails
- **Strict Suffix Matching**: Subdomain discovery strictly verifies suffix boundaries to prevent discovery leakage to third-party CDNs or vendor domains.
- **Negative Pattern Exclusion**: Blacklisted substrings/regexes are evaluated before any network connection is attempted.
- **Max Depth Clamping**: Mitigates DNS wildcard loops and excessively deep multi-tier routing.
- **Zero Offensive Actions**: Discovery performs only passive resolution and inventory indexing; it never attempts exploitation, brute forcing, or unauthorized probing.
