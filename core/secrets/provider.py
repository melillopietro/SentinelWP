"""
Enterprise Secrets Provider Abstraction for SentinelWP.
Provides pluggable access to environment variables, Docker/Kubernetes secrets,
and HashiCorp Vault with graceful fallbacks and strict secret protection.
"""
import os
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List

logger = logging.getLogger("sentinelwp.secrets")


class BaseSecretProvider(ABC):
    """Abstract Base Class for secret providers."""

    @abstractmethod
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieve a secret by key."""
        pass

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Convenience alias for get_secret."""
        return self.get_secret(key, default)


class EnvSecretProvider(BaseSecretProvider):
    """Fetches secrets from operating system environment variables."""

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return os.environ.get(key, default)


class FileSecretProvider(BaseSecretProvider):
    """
    Fetches secrets mounted from container filesystems (e.g., Docker Swarm,
    Kubernetes Secrets mounted at /run/secrets/ or custom paths).
    """

    def __init__(self, secrets_dir: str = "/run/secrets", base_path: Optional[str] = None):
        self.secrets_dir = base_path or secrets_dir

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        candidates = [
            os.path.join(self.secrets_dir, key),
            os.path.join(self.secrets_dir, key.lower())
        ]
        for secret_file in candidates:
            if os.path.isfile(secret_file):
                try:
                    with open(secret_file, "r", encoding="utf-8") as f:
                        return f.read().strip()
                except Exception as e:
                    logger.warning(f"Failed to read secret file {secret_file}: {e}")
        return default


class VaultSecretProvider(BaseSecretProvider):
    """
    HashiCorp Vault KV v2 Secret Provider.
    Communicates via Vault HTTP API using VAULT_ADDR and VAULT_TOKEN.
    """

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        mount_point: str = "secret",
        path_prefix: str = "sentinelwp",
    ):
        self.vault_addr = (vault_addr or os.getenv("VAULT_ADDR", "")).rstrip("/")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN", "")
        self.mount_point = mount_point
        self.path_prefix = path_prefix
        self._cache: Dict[str, str] = {}

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        if not self.vault_addr or not self.vault_token:
            return default

        if key in self._cache:
            return self._cache[key]

        try:
            import requests
            url = f"{self.vault_addr}/v1/{self.mount_point}/data/{self.path_prefix}/{key}"
            headers = {"X-Vault-Token": self.vault_token}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("data", {})
                val = data.get("value") or data.get(key)
                if val is not None:
                    self._cache[key] = str(val)
                    return str(val)
        except Exception as e:
            logger.warning(f"Error connecting to HashiCorp Vault at {self.vault_addr}: {e}")

        return default


class CompositeSecretProvider(BaseSecretProvider):
    """
    Orchestrates multiple providers in priority sequence:
    1. Vault (if configured)
    2. File / Container Mount (e.g. /run/secrets)
    3. Environment Variables
    """

    def __init__(self, providers: Optional[List[BaseSecretProvider]] = None):
        if providers is not None:
            self.providers = providers
        else:
            self.providers = [
                VaultSecretProvider(),
                FileSecretProvider(),
                EnvSecretProvider(),
            ]

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        for provider in self.providers:
            val = provider.get_secret(key)
            if val is not None and val != "":
                return val
        return default


_default_provider: Optional[BaseSecretProvider] = None


def get_secret_provider() -> BaseSecretProvider:
    """Return the global singleton secret provider."""
    global _default_provider
    if _default_provider is None:
        _default_provider = CompositeSecretProvider()
    return _default_provider


def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieve secret using the active secret provider chain."""
    return get_secret_provider().get_secret(key, default)
