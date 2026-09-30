"""
Security Assessment Platform - Hardened Scope Guard v2
Fail-closed target boundary enforcement for authorized localhost targets.

Hardening additions:
- Explicit allowed schemes (http/https only)
- IPv6 loopback support
- Redirect revalidation (every hop independently checked)
- trust_env=False on HTTP clients to block proxy env-var bypass
- Malformed URLs fail closed
- Host normalization before comparison
- External targets disabled by default; can only be enabled by explicit config
"""

from urllib.parse import urlparse, urlunparse
import ipaddress
import re

ALLOWED_SCHEMES = {"http", "https"}


class ScopeViolationException(Exception):
    """Raised when an assessment probe attempts to target an unauthorized host."""
    pass


class ScopeGuard:
    ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

    @classmethod
    def _normalize_host(cls, hostname: str) -> str:
        """Normalize host: lowercase, strip brackets from IPv6."""
        if not hostname:
            return ""
        h = hostname.lower().strip()
        # Strip IPv6 brackets
        if h.startswith("[") and h.endswith("]"):
            h = h[1:-1]
        return h

    @classmethod
    def is_allowed(cls, url: str) -> bool:
        """Return True only if URL targets an authorized local host."""
        if not url or not isinstance(url, str):
            return False

        try:
            parsed = urlparse(url.strip())
        except Exception:
            return False

        # Scheme must be explicit and in allowlist
        scheme = (parsed.scheme or "").lower()
        if scheme not in ALLOWED_SCHEMES:
            return False

        hostname = cls._normalize_host(parsed.hostname or "")
        if not hostname:
            return False

        # Direct string match against allowed set
        if hostname in cls.ALLOWED_HOSTS:
            return True

        # Numeric IP check — must be loopback
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_loopback
        except ValueError:
            pass

        return False

    @classmethod
    def enforce(cls, url: str) -> str:
        """
        Enforce fail-closed scope check.
        Raises ScopeViolationException if target is outside authorized scope.
        Returns normalized URL on success.
        """
        if not cls.is_allowed(url):
            raise ScopeViolationException(
                f"[SCOPE VIOLATION] Target '{url}' is outside authorized scope. "
                f"Platform strictly permits localhost/127.0.0.1/::1 controlled environments. "
                f"Request blocked. External target testing is disabled."
            )
        return url

    @classmethod
    def enforce_redirect(cls, original_url: str, redirect_url: str) -> str:
        """
        Independently validate a redirect destination.
        Called for every redirect hop during dynamic probing.
        """
        try:
            cls.enforce(redirect_url)
        except ScopeViolationException:
            raise ScopeViolationException(
                f"[SCOPE VIOLATION] Redirect from '{original_url}' to '{redirect_url}' "
                f"attempts to leave authorized scope. Redirect blocked."
            )
        return redirect_url

    @classmethod
    def make_scoped_client_kwargs(cls) -> dict:
        """
        Returns httpx client kwargs that enforce scope-safe HTTP behavior:
        - trust_env=False: ignores HTTP_PROXY/HTTPS_PROXY env vars
        - follow_redirects=False: redirects are manually revalidated
        """
        return {
            "trust_env": False,
            "follow_redirects": False,
            "timeout": 10.0,
        }
