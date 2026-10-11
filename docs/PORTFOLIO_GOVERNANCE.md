# Portfolio & Business Unit Governance

## Overview
SentinelWP enables enterprise organizations to map digital assets and vulnerability exposure to organizational hierarchies, business units, and service boundaries.

## Hierarchical Domain Model
- **BusinessUnit**: Organizational division (e.g. `Finance IT`, `E-Commerce Operations`).
  - Fields: `code`, `name`, `parent_id` (supporting multi-level hierarchies), `owner_user_id`, `criticality`.
- **BusinessService**: Critical business application or workflow supported by one or more assets (e.g. `Customer Checkout Portal`).
- **Asset Mapping**: Assets are assigned to a `business_unit_id` and linked to `BusinessService` entities via many-to-many associations.

## Aggregated Portfolio Metrics
The `get_portfolio_metrics(tenant_id, bu_id=None)` engine delivers multi-dimensional posture data:
- **Coverage Metrics**: % of assets with designated Business Owners, Technical Owners, and Business Unit mappings.
- **Verification Coverage**: % of assets with verified domain ownership via DNS TXT or HTTP token challenge.
- **Risk Exposure**: Active P1/P2 findings, KEV occurrences, and SLA breaches sliced by Business Unit.
- **Multi-Tenant Isolation**: All queries enforce strict tenant boundary partitioning to eliminate cross-tenant data leakage.
