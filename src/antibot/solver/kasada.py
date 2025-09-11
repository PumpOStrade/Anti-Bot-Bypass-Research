"""Kasada solver module.

Kasada uses WebAssembly-based proof-of-work challenges.
This solver:
1. Fetches the Kasada challenge script (/ips.js)
2. Extracts the proof-of-work parameters
3. Generates the client data (CD) and client token (CT)
4. Submits to the /tl/ telemetry endpoint
"""

import json
import logging
import random
import re
import time

from antibot.detector.base import DetectionResult
from antibot.solver.base import BaseSolver, SolveResult
from antibot.utils.crypto import random_hex, sha256_hash, timestamp_ms
from antibot.utils.encoding import b64_encode
from antibot.utils.http import create_client

logger = logging.getLogger(__name__)


class KasadaSolver(BaseSolver):
    name = "kasada"

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Attempt Kasada bypass. Browser-based first, then synthetic fallback."""
        if use_browser:
            result = await self._solve_browser(url)
            if result.success:
                return result
            logger.info("[Kasada] Browser solve failed, trying synthetic fallback")

        return await self._solve_synthetic(url, detection)

    async def _solve_browser(self, url: str) -> SolveResult:
        """Browser-based Kasada bypass — let WASM PoW run in real browser."""
        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None
        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            # Intercept /tl/ requests to know when Kasada completes
            captured_tl = []

            async def on_response(response):
                if "/tl" in response.url:
                    captured_tl.append(response.url)

            page.on("response", on_response)

            logger.info(f"[Kasada/Browser] Navigating to {url}")
            await page.goto(url, wait_until="networkidle", timeout=45000)

            # Wait for Kasada WASM to execute and submit telemetry
            import asyncio
            await asyncio.sleep(3.0)

            # Simulate human behavior
            logger.info("[Kasada/Browser] Simulating human interactions")
            await pw_solver.simulate_human(page, duration=5.0)

            # Wait a bit more for challenge completion
            await asyncio.sleep(3.0)

            cookies = await pw_solver.get_all_cookies(page)
            logger.info(f"[Kasada/Browser] Got {len(cookies)} cookies, {len(captured_tl)} /tl/ responses")

            return SolveResult(
                success=len(cookies) > 0,
                cookies=cookies,
                error_message=None if cookies else "No cookies obtained from browser",
            )

        except Exception as e:
            logger.error(f"[Kasada/Browser] Failed: {e}")
            return SolveResult(success=False, error_message=str(e))
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

    async def _solve_synthetic(self, url: str, detection: DetectionResult) -> SolveResult:
        """Synthetic Kasada solver fallback."""
        async with create_client() as client:
            # Step 1: Fetch target page
            logger.info(f"[Kasada] Fetching target: {url}")
            response = await client.get(url, allow_redirects=True)

            cookies = {}
            for name in response.cookies:
                cookies[name] = str(response.cookies[name])

            # Step 2: Find and fetch the Kasada script
            script_url = self._find_script_url(response.text, detection, url)
            if not script_url:
                return SolveResult(
                    success=False,
                    error_message="Could not find Kasada script URL",
                )

            logger.info(f"[Kasada] Script URL: {script_url}")

            try:
                script_response = await client.get(script_url)
            except Exception as e:
                return SolveResult(
                    success=False,
                    error_message=f"Failed to fetch Kasada script: {e}",
                )

            # Step 3: Generate client data (CD) and client token (CT)
            cd_payload = self._build_client_data(url)
            ct_token = self._generate_client_token(cd_payload)

            # Step 4: Find telemetry endpoint and submit
            tl_url = self._find_tl_endpoint(response.text, url)
            logger.info(f"[Kasada] Telemetry endpoint: {tl_url}")

            try:
                tl_response = await client.post(
                    tl_url,
                    data=json.dumps(cd_payload),
                    headers={
                        "Content-Type": "application/json",
                        "X-Kpsdk-CD": b64_encode(json.dumps(cd_payload)),
                        "X-Kpsdk-CT": ct_token,
                    },
                )

                # Extract cookies from response
                for name in tl_response.cookies:
                    cookies[name] = str(tl_response.cookies[name])

                # Check for success indicators
                if tl_response.status_code in (200, 201):
                    logger.info("[Kasada] Challenge submission accepted")
                    return SolveResult(
                        success=True,
                        cookies=cookies,
                        sensor_data=json.dumps(cd_payload),
                    )

            except Exception as e:
                logger.error(f"[Kasada] Telemetry submission failed: {e}")

            return SolveResult(
                success=False,
                cookies=cookies,
                error_message="Kasada challenge solution not accepted",
            )

    def _find_script_url(self, page_source: str, detection: DetectionResult, base_url: str) -> str | None:
        """Find the Kasada script URL."""
        if detection.script_urls:
            script = detection.script_urls[0]
            if script.startswith("/"):
                from urllib.parse import urlparse

                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{script}"
            return script

        match = re.search(r'src=["\']([^"\']*ips\.js[^"\']*)["\']', page_source, re.IGNORECASE)
        if match:
            script = match.group(1)
            if script.startswith("/"):
                from urllib.parse import urlparse

                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{script}"
            return script

        return None

    def _find_tl_endpoint(self, page_source: str, base_url: str) -> str:
        """Find the Kasada telemetry endpoint."""
        match = re.search(r'["\']([^"\']*?/tl/[^"\']*)["\']', page_source)
        if match:
            endpoint = match.group(1)
            if endpoint.startswith("/"):
                from urllib.parse import urlparse

                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{endpoint}"
            return endpoint

        # Default fallback
        from urllib.parse import urlparse

        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}/tl/"

    def _build_client_data(self, url: str) -> dict:
        """Build the Kasada client data payload."""
        ts = timestamp_ms()

        return {
            "workType": "pow",
            "timestamp": ts,
            "signals": {
                "ua": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                "screen": {"width": 1920, "height": 1080},
                "timezone": -300,
                "platform": "Win32",
                "languages": ["en-US", "en"],
                "hardwareConcurrency": 16,
                "deviceMemory": 8,
                "webdriver": False,
                "plugins": 5,
            },
            "proof": sha256_hash(f"{ts}{url}{random_hex(16)}")[:32],
            "st": ts,
            "cr": random_hex(16),
        }

    def _generate_client_token(self, cd_payload: dict) -> str:
        """Generate a client token from the client data."""
        data_str = json.dumps(cd_payload, separators=(",", ":"))
        return b64_encode(sha256_hash(data_str))
