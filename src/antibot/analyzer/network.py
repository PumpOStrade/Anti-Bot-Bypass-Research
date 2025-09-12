"""Network traffic analyzer — capture and diff real browser vs bot client traffic."""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CapturedRequest:
    url: str
    method: str
    headers: dict
    body: str | None
    timestamp: float
    resource_type: str = ""


@dataclass
class CapturedResponse:
    url: str
    status: int
    headers: dict
    body_size: int
    timestamp: float


@dataclass
class TrafficCapture:
    source: str  # "browser" or "bot"
    url: str
    requests: list[CapturedRequest] = field(default_factory=list)
    responses: list[CapturedResponse] = field(default_factory=list)
    cookies_timeline: list[dict] = field(default_factory=list)
    total_duration_ms: int = 0


@dataclass
class RequestDiff:
    url: str
    difference: str  # "missing_in_bot", "missing_in_browser", "header_diff", "timing_diff"
    details: str = ""


@dataclass
class TrafficDiff:
    missing_in_bot: list[str] = field(default_factory=list)
    missing_in_browser: list[str] = field(default_factory=list)
    header_diffs: list[RequestDiff] = field(default_factory=list)
    timing_diffs: list[RequestDiff] = field(default_factory=list)
    cookie_diffs: list[dict] = field(default_factory=list)
    total_browser_requests: int = 0
    total_bot_requests: int = 0

    def report(self) -> str:
        """Generate human-readable diff report."""
        lines = [
            "=" * 60,
            "NETWORK TRAFFIC DIFF REPORT",
            "=" * 60,
            f"\nTotal requests — Browser: {self.total_browser_requests}, Bot: {self.total_bot_requests}",
        ]

        if self.missing_in_bot:
            lines.append(f"\n--- Requests made by BROWSER but NOT by BOT ({len(self.missing_in_bot)}) ---")
            for url in self.missing_in_bot[:20]:
                lines.append(f"  [MISSING] {url}")

        if self.missing_in_browser:
            lines.append(f"\n--- Requests made by BOT but NOT by BROWSER ({len(self.missing_in_browser)}) ---")
            for url in self.missing_in_browser[:20]:
                lines.append(f"  [EXTRA] {url}")

        if self.header_diffs:
            lines.append(f"\n--- Header differences ({len(self.header_diffs)}) ---")
            for diff in self.header_diffs[:10]:
                lines.append(f"  [{diff.url[:60]}]")
                lines.append(f"    {diff.details}")

        if self.cookie_diffs:
            lines.append(f"\n--- Cookie differences ({len(self.cookie_diffs)}) ---")
            for diff in self.cookie_diffs[:10]:
                lines.append(f"  {diff.get('name', '?')}: {diff.get('difference', '?')}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)


class NetworkAnalyzer:
    """Compare network traffic between a real browser and a bot client."""

    async def capture_real_browser(self, url: str, proxy: str | None = None) -> TrafficCapture:
        """Capture all network traffic from a real Playwright browser."""
        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw, browser, context, page = await pw_solver.launch_stealth_browser(proxy=proxy)

        capture = TrafficCapture(source="browser", url=url)
        start_time = time.time()

        async def on_request(request):
            capture.requests.append(CapturedRequest(
                url=request.url,
                method=request.method,
                headers=dict(request.headers),
                body=request.post_data,
                timestamp=time.time() - start_time,
                resource_type=request.resource_type,
            ))

        async def on_response(response):
            capture.responses.append(CapturedResponse(
                url=response.url,
                status=response.status,
                headers=dict(response.headers),
                body_size=len(await response.body()) if response.ok else 0,
                timestamp=time.time() - start_time,
            ))

        page.on("request", on_request)
        page.on("response", on_response)

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(5.0)  # Wait for async requests

            # Capture cookies at this point
            cookies = await pw_solver.get_all_cookies(page)
            capture.cookies_timeline.append({
                "time": time.time() - start_time,
                "cookies": cookies,
            })
        finally:
            capture.total_duration_ms = int((time.time() - start_time) * 1000)
            await browser.close()
            await pw.stop()

        return capture

    async def capture_bot_client(self, url: str, proxy: str | None = None) -> TrafficCapture:
        """Capture traffic from a curl_cffi bot client."""
        from antibot.utils.http import create_client

        capture = TrafficCapture(source="bot", url=url)
        start_time = time.time()

        async with create_client(proxy=proxy) as client:
            response = await client.get(url, allow_redirects=True)

            capture.requests.append(CapturedRequest(
                url=url,
                method="GET",
                headers=dict(response.request.headers) if hasattr(response, "request") else {},
                body=None,
                timestamp=time.time() - start_time,
            ))

            capture.responses.append(CapturedResponse(
                url=url,
                status=response.status_code,
                headers=dict(response.headers),
                body_size=len(response.content),
                timestamp=time.time() - start_time,
            ))

            cookies = {}
            for name in response.cookies:
                cookies[name] = str(response.cookies[name])
            capture.cookies_timeline.append({
                "time": time.time() - start_time,
                "cookies": cookies,
            })

        capture.total_duration_ms = int((time.time() - start_time) * 1000)
        return capture

    def diff(self, browser: TrafficCapture, bot: TrafficCapture) -> TrafficDiff:
        """Compare browser and bot traffic captures."""
        result = TrafficDiff(
            total_browser_requests=len(browser.requests),
            total_bot_requests=len(bot.requests),
        )

        browser_urls = {self._normalize_url(r.url) for r in browser.requests}
        bot_urls = {self._normalize_url(r.url) for r in bot.requests}

        result.missing_in_bot = sorted(browser_urls - bot_urls)
        result.missing_in_browser = sorted(bot_urls - browser_urls)

        # Compare headers for common requests
        common_urls = browser_urls & bot_urls
        for url in common_urls:
            browser_req = next((r for r in browser.requests if self._normalize_url(r.url) == url), None)
            bot_req = next((r for r in bot.requests if self._normalize_url(r.url) == url), None)
            if browser_req and bot_req:
                header_diffs = self._diff_headers(browser_req.headers, bot_req.headers)
                if header_diffs:
                    result.header_diffs.append(RequestDiff(
                        url=url,
                        difference="header_diff",
                        details="; ".join(header_diffs[:5]),
                    ))

        # Compare cookies
        if browser.cookies_timeline and bot.cookies_timeline:
            browser_cookies = browser.cookies_timeline[-1].get("cookies", {})
            bot_cookies = bot.cookies_timeline[-1].get("cookies", {})

            for name in set(list(browser_cookies.keys()) + list(bot_cookies.keys())):
                if name in browser_cookies and name not in bot_cookies:
                    result.cookie_diffs.append({"name": name, "difference": "missing in bot"})
                elif name not in browser_cookies and name in bot_cookies:
                    result.cookie_diffs.append({"name": name, "difference": "missing in browser"})

        return result

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for comparison (strip query params with timestamps)."""
        # Keep path, strip random query params
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    @staticmethod
    def _diff_headers(h1: dict, h2: dict) -> list[str]:
        """Compare two header dicts."""
        diffs = []
        all_keys = set(k.lower() for k in h1) | set(k.lower() for k in h2)
        skip = {"date", "age", "x-request-id", "cf-ray"}  # Dynamic headers

        for key in sorted(all_keys - skip):
            v1 = next((v for k, v in h1.items() if k.lower() == key), None)
            v2 = next((v for k, v in h2.items() if k.lower() == key), None)
            if v1 and not v2:
                diffs.append(f"'{key}' only in browser")
            elif v2 and not v1:
                diffs.append(f"'{key}' only in bot")
            elif v1 != v2:
                diffs.append(f"'{key}' differs")

        return diffs
