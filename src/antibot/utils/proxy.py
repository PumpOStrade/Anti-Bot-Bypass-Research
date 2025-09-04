"""Proxy management with rotation and failure tracking."""

import logging
import random
from pathlib import Path

logger = logging.getLogger(__name__)


class ProxyManager:
    """Manages a pool of proxies with round-robin rotation and failure tracking.

    Supports http://, https://, socks5:// with optional auth.
    Format: protocol://user:pass@host:port
    """

    def __init__(self, proxy_url: str | None = None, proxy_file: str | None = None):
        self.proxies: list[str] = []
        self.failed: set[str] = set()
        self._index = 0

        if proxy_url:
            self.proxies.append(proxy_url)
        if proxy_file:
            self._load_file(proxy_file)

        if self.proxies:
            logger.info(f"[Proxy] Loaded {len(self.proxies)} proxies")

    def _load_file(self, filepath: str):
        """Load proxies from a file (one per line)."""
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"[Proxy] File not found: {filepath}")
            return

        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Auto-add protocol if missing
                if "://" not in line:
                    line = f"http://{line}"
                self.proxies.append(line)

    @property
    def has_proxies(self) -> bool:
        return len(self.proxies) > 0

    @property
    def available(self) -> list[str]:
        """Return proxies that haven't been marked as failed."""
        return [p for p in self.proxies if p not in self.failed]

    def get_next(self) -> str | None:
        """Get next proxy via round-robin rotation."""
        avail = self.available
        if not avail:
            return None

        proxy = avail[self._index % len(avail)]
        self._index += 1
        return proxy

    def get_random(self) -> str | None:
        """Get a random available proxy."""
        avail = self.available
        if not avail:
            return None
        return random.choice(avail)

    def mark_failed(self, proxy: str):
        """Mark a proxy as failed (will be skipped in rotation)."""
        self.failed.add(proxy)
        logger.warning(f"[Proxy] Marked as failed: {proxy}")

    def reset_failures(self):
        """Reset all failure marks."""
        self.failed.clear()

    def get_playwright_proxy(self, proxy_url: str | None = None) -> dict | None:
        """Format proxy for Playwright's browser context.

        Returns dict like {"server": "socks5://host:port", "username": "...", "password": "..."}
        """
        url = proxy_url or self.get_next()
        if not url:
            return None

        result = {"server": url}

        # Extract auth if present: protocol://user:pass@host:port
        if "@" in url:
            proto_and_auth, host_port = url.rsplit("@", 1)
            proto, auth = proto_and_auth.split("://", 1)
            if ":" in auth:
                user, password = auth.split(":", 1)
                result["server"] = f"{proto}://{host_port}"
                result["username"] = user
                result["password"] = password

        return result

    def get_curl_proxy(self, proxy_url: str | None = None) -> str | None:
        """Get proxy URL formatted for curl_cffi."""
        return proxy_url or self.get_next()


# --- Residential Proxy Providers ---

class ResidentialProxyProvider:
    """Base class for residential proxy API integration."""

    def get_proxy(self, country: str = "US", session_id: str | None = None) -> str:
        raise NotImplementedError


class BrightDataProvider(ResidentialProxyProvider):
    """Bright Data (formerly Luminati) residential proxy integration."""

    def __init__(self, username: str, password: str, zone: str = "residential"):
        self.username = username
        self.password = password
        self.zone = zone

    def get_proxy(self, country: str = "US", session_id: str | None = None) -> str:
        user = f"{self.username}-zone-{self.zone}-country-{country.lower()}"
        if session_id:
            user += f"-session-{session_id}"
        return f"http://{user}:{self.password}@brd.superproxy.io:22225"


class OxylabsProvider(ResidentialProxyProvider):
    """Oxylabs residential proxy integration."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def get_proxy(self, country: str = "US", session_id: str | None = None) -> str:
        user = f"customer-{self.username}-cc-{country.lower()}"
        if session_id:
            user += f"-sessid-{session_id}"
        return f"http://{user}:{self.password}@pr.oxylabs.io:7777"


class SmartProxyProvider(ResidentialProxyProvider):
    """SmartProxy residential proxy integration."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def get_proxy(self, country: str = "US", session_id: str | None = None) -> str:
        user = f"{self.username}"
        if session_id:
            user += f"-session-{session_id}"
        return f"http://{user}:{self.password}@gate.smartproxy.com:7000"


class GenericResidentialProvider(ResidentialProxyProvider):
    """Generic residential proxy with URL template.

    Template vars: {country}, {session_id}
    Example: http://user-{country}:pass@proxy.example.com:8080
    """

    def __init__(self, url_template: str):
        self.template = url_template

    def get_proxy(self, country: str = "US", session_id: str | None = None) -> str:
        return self.template.format(
            country=country.lower(),
            session_id=session_id or random.randint(100000, 999999),
        )


PROVIDERS = {
    "brightdata": BrightDataProvider,
    "oxylabs": OxylabsProvider,
    "smartproxy": SmartProxyProvider,
    "generic": GenericResidentialProvider,
}
