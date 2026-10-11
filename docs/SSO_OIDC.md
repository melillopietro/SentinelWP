# SentinelWP Enterprise - Single Sign-On (SSO / OIDC) Integration Guide

## 1. Overview

SentinelWP Enterprise provides standard OpenID Connect (OIDC) 1.0 Single Sign-On.
Supported Identity Providers (IdP):
- Okta
- Microsoft Entra ID (Azure AD)
- Keycloak / Red Hat SSO
- Google Workspace
- Auth0 / CyberArk / Ping Identity

---

## 2. Authentication Flow

SentinelWP implements the OIDC Authorization Code Flow with cryptographic `state` and `nonce` parameters stored in secure HTTP-only session cookies to guard against CSRF, replay, and token injection attacks.

```
+------------+          +---------------+          +--------------------+
|  End User  |          |  SentinelWP   |          |  Identity Provider |
|  (Browser) |          |  (Relying P.) |          |     (IdP / OIDC)   |
+-----+------+          +-------+-------+          +---------+----------+
      |                         |                            |
      | 1. Click "Enterprise SSO"|                           |
      +------------------------>|                            |
      |                         | 2. Generate state & nonce  |
      |                         |    Store in session        |
      | 3. Redirect to IdP Auth |                            |
      |<------------------------+                            |
      |                                                      |
      | 4. Authenticate & Approve Claims                     |
      +----------------------------------------------------->|
      |                                                      |
      | 5. Redirect back with authorization code & state     |
      |<-----------------------------------------------------+
      |                                                      |
      | 6. GET /auth/oidc/callback?code=...&state=...        |
      +------------------------>|                            |
                                | 7. Validate state          |
                                |    POST /token (exchange)  |
                                +--------------------------->|
                                |                            |
                                | 8. Return tokens (ID+Access|
                                |<---------------------------+
                                |                            |
                                | 9. Validate ID token & nonce
                                |    Extract claims & roles  |
                                |    Map tenant ID           |
                                |    Issue session           |
      | 10. Redirect to /dashboard                           |
      |<------------------------+                            |
```

---

## 3. Configuration Reference

Set the following environment variables or configure them via the Secrets Provider:

| Parameter | Type | Required | Description | Default |
|---|---|---|---|---|
| `OIDC_ENABLED` | bool | Yes | Enables SSO / OIDC authentication buttons and endpoints. | `False` |
| `OIDC_ISSUER_URL` | str | Yes | Canonical base URL of the Identity Provider. | `""` |
| `OIDC_CLIENT_ID` | str | Yes | Client ID registered in the IdP for SentinelWP. | `""` |
| `OIDC_CLIENT_SECRET` | str | Yes | Confidential client secret. | `""` |
| `OIDC_REDIRECT_URI` | str | Yes | Callback URL (e.g., `https://sentinelwp.corp.com/auth/oidc/callback`). | `""` |
| `OIDC_SCOPES` | str | No | Space-delimited scopes requested from IdP. | `openid profile email groups` |
| `OIDC_ROLES_CLAIM` | str | No | Claim attribute holding user roles/groups in the JWT. | `groups` |
| `OIDC_TENANT_CLAIM` | str | No | Claim attribute holding tenant/org assignment. | `tenant_id` |
| `OIDC_DEFAULT_ROLE` | str | No | Role assigned if no matching group is found (`viewer`, `analyst`, `admin`). | `viewer` |

---

## 4. Role Mapping Hierarchy

SentinelWP maps groups from the IdP token claims to application roles according to the highest-privilege hierarchy:

```
admin > analyst > viewer
```

### Default Group Name Matchers:
- **Admin**: `sentinelwp_admins`, `admins`, `secops-lead`, `global-admin`
- **Analyst**: `sentinelwp_analysts`, `analysts`, `security-engineers`, `soc-analyst`
- **Viewer**: `sentinelwp_viewers`, `viewers`, `auditors`, `engineering-read`

If a user belongs to both `sentinelwp_analysts` and `sentinelwp_admins`, SentinelWP assigns the `admin` role.

---

## 5. Multi-Tenant Claim Routing

In multi-tenant deployments, SentinelWP automatically maps incoming SSO users to their respective tenant workspace:

1. SentinelWP inspects the claim specified by `OIDC_TENANT_CLAIM` (default `tenant_id` or `organization`).
2. If the claim matches an existing tenant ID or tenant slug in the database, the user is authenticated directly into that workspace.
3. If no tenant claim is provided, the user defaults to `default-tenant`.
4. Tenant boundaries are enforced strictly via database tenant isolation.

---

## 6. Audit & Security Operations

All SSO operations generate immutable audit events:
- `user_logged_in_oidc`: Successful login, recording IdP sub, username, assigned role, tenant, and client IP.
- `oidc_login_failed`: Authentication failure, recording the error reason (state mismatch, token expiration, IdP network error).
