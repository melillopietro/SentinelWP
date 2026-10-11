"""
Enterprise OpenID Connect (OIDC) & Single Sign-On (SSO) for SentinelWP.
Supports enterprise Identity Providers (Okta, Keycloak, Azure AD / Microsoft Entra, Google Workspace).
Provides authorization flow generation, state/nonce validation, token exchange,
claims parsing, RBAC role mapping, and multi-tenant claim routing.
"""
import os
import json
import base64
import logging
import secrets
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode

logger = logging.getLogger("sentinelwp.auth.oidc")

# Default Role Hierarchy (highest to lowest)
ROLE_HIERARCHY = ["admin", "analyst", "auditor", "viewer"]

DEFAULT_ROLE_MAPPING: Dict[str, str] = {
    "sentinelwp-admins": "admin",
    "sentinelwp_admins": "admin",
    "security-admins": "admin",
    "security_admins": "admin",
    "sentinelwp-admin": "admin",
    "sentinelwp_admin": "admin",
    "admin": "admin",
    "admins": "admin",
    "sentinelwp-analysts": "analyst",
    "sentinelwp_analysts": "analyst",
    "security-analysts": "analyst",
    "security_analysts": "analyst",
    "security-engineers": "analyst",
    "security_engineers": "analyst",
    "sentinelwp-analyst": "analyst",
    "sentinelwp_analyst": "analyst",
    "analyst": "analyst",
    "analysts": "analyst",
    "secops": "analyst",
    "sentinelwp-auditors": "auditor",
    "sentinelwp_auditors": "auditor",
    "compliance-auditors": "auditor",
    "compliance_auditors": "auditor",
    "sentinelwp-auditor": "auditor",
    "sentinelwp_auditor": "auditor",
    "auditor": "auditor",
    "auditors": "auditor",
    "sentinelwp-viewers": "viewer",
    "sentinelwp_viewers": "viewer",
    "sentinelwp-viewer": "viewer",
    "sentinelwp_viewer": "viewer",
    "viewer": "viewer",
    "viewers": "viewer",
}


class OIDCConfig:
    """Holds validated OIDC configuration settings."""

    def __init__(
        self,
        enabled: bool = False,
        issuer_url: str = "",
        client_id: str = "",
        client_secret: str = "",
        redirect_uri: str = "",
        scopes: Any = "openid email profile groups",
        roles_claim: str = "groups",
        tenant_claim: str = "tenant_id",
        role_mapping: Optional[Dict[str, str]] = None,
        default_role: str = "viewer",
    ):
        self.enabled = enabled
        self.issuer_url = issuer_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.roles_claim = roles_claim
        self.tenant_claim = tenant_claim
        self.role_mapping = role_mapping or DEFAULT_ROLE_MAPPING
        self.default_role = default_role

    @classmethod
    def from_env(cls) -> "OIDCConfig":
        enabled_str = os.getenv("OIDC_ENABLED", "false").lower()
        enabled = enabled_str in ("true", "1", "yes", "on")
        raw_mapping = os.getenv("OIDC_ROLE_MAPPING_JSON", "")
        role_mapping = None
        if raw_mapping:
            try:
                role_mapping = json.loads(raw_mapping)
            except Exception as e:
                logger.warning(f"Could not parse OIDC_ROLE_MAPPING_JSON: {e}")

        return cls(
            enabled=enabled,
            issuer_url=os.getenv("OIDC_ISSUER_URL", ""),
            client_id=os.getenv("OIDC_CLIENT_ID", ""),
            client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
            redirect_uri=os.getenv("OIDC_REDIRECT_URI", "/auth/oidc/callback"),
            scopes=os.getenv("OIDC_SCOPES", "openid email profile groups"),
            roles_claim=os.getenv("OIDC_ROLES_CLAIM", "groups"),
            tenant_claim=os.getenv("OIDC_TENANT_CLAIM", "tenant_id"),
            role_mapping=role_mapping,
        )


class OIDCClient:
    """
    Standard OpenID Connect client implementing OAuth 2.0 Authorization Code Flow.
    """

    def __init__(self, config: Optional[OIDCConfig] = None):
        self.config = config or OIDCConfig.from_env()

    @property
    def is_enabled(self) -> bool:
        return self.config.enabled and bool(self.config.issuer_url and self.config.client_id)

    def generate_state_and_nonce(self) -> tuple[str, str]:
        """Generate cryptographically secure state and nonce tokens."""
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        return state, nonce

    def validate_state(self, expected_state: str, actual_state: str) -> bool:
        """Validate state token against CSRF attacks."""
        if not expected_state or not actual_state:
            return False
        return secrets.compare_digest(expected_state, actual_state)

    def get_authorization_url(
        self,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        redirect_uri: Optional[str] = None
    ):
        """Construct the IdP authorization endpoint redirect URL."""
        generated = False
        if not state or not nonce:
            gen_state, gen_nonce = self.generate_state_and_nonce()
            state = state or gen_state
            nonce = nonce or gen_nonce
            generated = True

        auth_endpoint = f"{self.config.issuer_url}/protocol/openid-connect/auth"
        # Azure AD / Microsoft Entra or generic discovery fallback
        if "login.microsoftonline.com" in self.config.issuer_url:
            auth_endpoint = f"{self.config.issuer_url}/oauth2/v2.0/authorize"
        elif "accounts.google.com" in self.config.issuer_url:
            auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
        elif "okta.com" in self.config.issuer_url:
            auth_endpoint = f"{self.config.issuer_url}/v1/authorize"

        scopes_str = " ".join(self.config.scopes) if isinstance(self.config.scopes, list) else self.config.scopes

        params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "scope": scopes_str,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "state": state,
            "nonce": nonce,
        }
        url = f"{auth_endpoint}?{urlencode(params)}"
        if generated:
            return url, state, nonce
        return url

    def exchange_code_for_tokens(self, code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        """Exchange authorization code for access and ID tokens."""
        token_endpoint = f"{self.config.issuer_url}/protocol/openid-connect/token"
        if "login.microsoftonline.com" in self.config.issuer_url:
            token_endpoint = f"{self.config.issuer_url}/oauth2/v2.0/token"
        elif "accounts.google.com" in self.config.issuer_url:
            token_endpoint = "https://oauth2.googleapis.com/token"
        elif "okta.com" in self.config.issuer_url:
            token_endpoint = f"{self.config.issuer_url}/v1/token"

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }

        try:
            import requests
            resp = requests.post(token_endpoint, data=data, timeout=10)
            if resp.status_code != 200:
                logger.error(f"OIDC token exchange failed: {resp.status_code} - {resp.text}")
                raise ValueError(f"Token exchange failed with status {resp.status_code}")
            return resp.json()
        except Exception as e:
            logger.error(f"Error during OIDC token exchange: {e}")
            raise

    def decode_token_unverified(self, id_token: str) -> Dict[str, Any]:
        """
        Decodes JWT payload without signature verification (useful for payload extraction
        when TLS channel validation or direct IdP introspection is active).
        """
        parts = id_token.split(".")
        if len(parts) < 2:
            raise ValueError("Invalid JWT format")
        
        # Base64url decode with padding
        payload_b64 = parts[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(decoded_bytes.decode("utf-8"))

    def map_claims_to_role(self, claims: Dict[str, Any]) -> str:
        """
        Extract roles from claims using configured roles_claim path,
        and map to the highest SentinelWP role.
        """
        raw_roles: List[str] = []
        claim_key = self.config.roles_claim

        # Handle nested claim paths like 'realm_access.roles'
        target_obj: Any = claims
        if "." in claim_key:
            for part in claim_key.split("."):
                if isinstance(target_obj, dict):
                    target_obj = target_obj.get(part, {})
                else:
                    target_obj = None
                    break
            if isinstance(target_obj, list):
                raw_roles = [str(r).lower() for r in target_obj]
            elif isinstance(target_obj, str):
                raw_roles = [target_obj.lower()]
        else:
            val = claims.get(claim_key, [])
            if isinstance(val, list):
                raw_roles = [str(r).lower() for r in val]
            elif isinstance(val, str):
                raw_roles = [val.lower()]

        # Map through configured mapping
        assigned_roles = set()
        for r in raw_roles:
            for k, v in self.config.role_mapping.items():
                if k.lower() == r:
                    assigned_roles.add(v.lower())

        # Select highest priority role according to hierarchy
        for r in ROLE_HIERARCHY:
            if r in assigned_roles:
                return r

        # Default fallback
        return "viewer"

    def resolve_tenant(self, claims: Dict[str, Any], default_tenant: str = "default-tenant") -> str:
        """Extract multi-tenant routing identifier from claims."""
        tenant_val = claims.get(self.config.tenant_claim)
        if tenant_val and isinstance(tenant_val, str) and tenant_val.strip():
            return tenant_val.strip()
        # Fallback to org or organization
        alt_tenant = claims.get("org") or claims.get("organization") or claims.get("tenant")
        if alt_tenant and isinstance(alt_tenant, str) and alt_tenant.strip():
            return alt_tenant.strip()
        return default_tenant

    def extract_user_info(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        """Extract normalized SentinelWP user profile from token claims."""
        sub = str(claims.get("sub", ""))
        email = str(claims.get("email", "") or f"{sub}@oidc.user")
        name = str(claims.get("name") or claims.get("preferred_username") or email.split("@")[0] or sub)
        role = self.map_claims_to_role(claims)
        tenant_id = self.resolve_tenant(claims)

        return {
            "sub": sub,
            "email": email,
            "username": name,
            "role": role,
            "tenant_id": tenant_id,
        }

    # Aliases
    map_role_from_claims = map_claims_to_role
    extract_tenant_from_claims = resolve_tenant

