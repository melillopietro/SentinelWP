# Policy Engine & Versioning Governance

## Overview
The SentinelWP Policy Engine enforces immutable, audit-compliant configuration management for scanning profiles, exposure rules, and vulnerability acceptance criteria.

## Versioning & Immutability Rules
1. **Never Overwrite ACTIVE Versions**: Active policy versions are completely frozen. Any modifications generate a new `DRAFT` version with an incremented version number.
2. **Deterministic Checksum**: Every policy definition is serialized into canonical JSON (sorted keys) and hashed using SHA-256 (`checksum`).
3. **Activation Lifecycle**:
   - `DRAFT`: Editable version under development.
   - `ACTIVE`: Enforced version. Activating a draft automatically transitions the prior active version to `RETIRED`.
   - `RETIRED`: Archived version preserved for historical audit trails.
4. **Independent Approval**: When two-person approval is enabled (`POLICY_APPROVAL_REQUIRED`), activation requires an independent approver different from the author (`approved_by != created_by`).
5. **Field-Level Diffing**: `diff_versions(v1_id, v2_id)` computes precise structural additions, removals, and modifications between versions.
