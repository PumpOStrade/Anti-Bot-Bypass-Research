"""Live TLS fingerprint testing — capture your actual JA3/JA4 hash and compare."""

import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TLSResult:
    client_type: str  # "curl_cffi", "playwright", "requests"
    ja3_hash: str | None = None
    ja3_full: str | None = None
    ja4: str | None = None
    user_agent: str | None = None
    ip: str | None = None
    http_version: str | None = None
    tls_version: str | None = None
    raw_response: dict | None = None


@dataclass
class TLSComparison:
    client_type: str
    ja3_matches_chrome: bool
    ja3_hash: str | None
    chrome_ja3: str | None
    http_version_match: bool
    risk_level: str  # "low", "medium", "high", "critical"
    details: list[str]


# Known TLS echo services
TLS_ECHO_URLS = [
    "https://tls.peet.ws/api/all",
    "https://tls.browserleaks.com/json",
]


class TLSLiveTester:
    """Test your actual TLS fingerprint against echo services."""

    async def test_curl_cffi(self, impersonate: str = "chrome131", proxy: str | None = None) -> TLSResult:
        """Test TLS fingerprint of curl_cffi client."""
        from antibot.utils.http import create_client

        result = TLSResult(client_type=f"curl_cffi ({impersonate})")

        for echo_url in TLS_ECHO_URLS:
            try:
                async with create_client(impersonate=impersonate, proxy=proxy) as client:
                    response = await client.get(echo_url)
                    data = response.json()

                    # Parse response based on service format
                    if "tls" in data:
                        # tls.peet.ws format
                        tls_data = data.get("tls", {})
                        result.ja3_hash = tls_data.get("ja3_hash")
                        result.ja3_full = tls_data.get("ja3")
                        result.ja4 = tls_data.get("ja4")
                        result.tls_version = tls_data.get("version")
                    elif "ja3_hash" in data:
                        result.ja3_hash = data.get("ja3_hash")
                        result.ja3_full = data.get("ja3_text")

                    result.ip = data.get("ip")
                    result.user_agent = data.get("user_agent")
                    result.http_version = data.get("http_version", str(data.get("http2", "")))
                    result.raw_response = data
                    break

            except Exception as e:
                logger.debug(f"[TLS] Echo service {echo_url} failed: {e}")
                continue

        return result

    async def test_playwright(self, proxy: str | None = None) -> TLSResult:
        """Test TLS fingerprint of Playwright browser."""
        from antibot.solver.browser import PlaywrightSolver

        result = TLSResult(client_type="playwright")
        pw_solver = PlaywrightSolver()
        pw = None
        browser = None

        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser(proxy=proxy)

            for echo_url in TLS_ECHO_URLS:
                try:
                    response = await page.goto(echo_url, timeout=15000)
                    if response and response.ok:
                        text = await page.inner_text("body")
                        data = json.loads(text)

                        if "tls" in data:
                            tls_data = data.get("tls", {})
                            result.ja3_hash = tls_data.get("ja3_hash")
                            result.ja3_full = tls_data.get("ja3")
                            result.ja4 = tls_data.get("ja4")
                            result.tls_version = tls_data.get("version")
                        elif "ja3_hash" in data:
                            result.ja3_hash = data.get("ja3_hash")

                        result.ip = data.get("ip")
                        result.user_agent = data.get("user_agent")
                        result.http_version = data.get("http_version")
                        result.raw_response = data
                        break
                except Exception as e:
                    logger.debug(f"[TLS] Playwright echo {echo_url} failed: {e}")
                    continue
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

        return result

    def compare_to_chrome(self, result: TLSResult) -> TLSComparison:
        """Compare a TLS result against known Chrome fingerprints."""
        from antibot.fingerprint.tls import KNOWN_JA3_HASHES

        chrome_hashes = {v.get("ja3") for k, v in KNOWN_JA3_HASHES.items() if "chrome" in k}
        details = []
        risk = "low"

        ja3_match = result.ja3_hash in chrome_hashes if result.ja3_hash else False

        if ja3_match:
            details.append("JA3 matches known Chrome fingerprint")
        elif result.ja3_hash:
            # Check if it matches a known bot
            bot_hashes = {v.get("ja3") for k, v in KNOWN_JA3_HASHES.items() if "python" in k}
            if result.ja3_hash in bot_hashes:
                risk = "critical"
                details.append("JA3 matches known Python/bot fingerprint!")
            else:
                risk = "medium"
                details.append(f"JA3 ({result.ja3_hash}) doesn't match any known Chrome hash")
        else:
            risk = "high"
            details.append("Could not determine JA3 hash")

        http2_match = "2" in str(result.http_version) if result.http_version else False
        if http2_match:
            details.append("HTTP/2 supported (good)")
        else:
            details.append("HTTP/2 NOT detected (suspicious)")
            if risk == "low":
                risk = "medium"

        return TLSComparison(
            client_type=result.client_type,
            ja3_matches_chrome=ja3_match,
            ja3_hash=result.ja3_hash,
            chrome_ja3=next(iter(chrome_hashes), None),
            http_version_match=http2_match,
            risk_level=risk,
            details=details,
        )
