"""Shape Security (F5) solver module.

Shape uses heavily obfuscated JavaScript with anti-tamper protections.
This solver:
1. Identifies the Shape script from the page
2. Attempts to parse obfuscation patterns
3. Generates a device fingerprint payload
4. Submits to the Shape collection endpoint
"""

import json
import logging
import random
import re

from antibot.detector.base import DetectionResult
from antibot.solver.base import BaseSolver, SolveResult
from antibot.utils.crypto import canvas_fingerprint_hash, random_hex, sha256_hash, timestamp_ms
from antibot.utils.encoding import b64_encode
from antibot.utils.http import create_client

logger = logging.getLogger(__name__)


class ShapeSolver(BaseSolver):
    name = "shape"

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Attempt Shape bypass. Browser-based first, then synthetic fallback."""
        if use_browser:
            result = await self._solve_browser(url)
            if result.success:
                return result
            logger.info("[Shape] Browser solve failed, trying synthetic fallback")

        return await self._solve_synthetic(url, detection)

    async def _solve_browser(self, url: str) -> SolveResult:
        """Browser-based Shape bypass — let obfuscated script run naturally."""
        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None
        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            # Track Shape POST requests
            shape_posts = []

            async def on_request(request):
                if request.method == "POST" and request.post_data and len(request.post_data) > 2000:
                    shape_posts.append({"url": request.url, "size": len(request.post_data)})

            page.on("request", on_request)

            logger.info(f"[Shape/Browser] Navigating to {url}")
            await page.goto(url, wait_until="networkidle", timeout=45000)

            import asyncio
            await asyncio.sleep(3.0)

            # Simulate human behavior
            logger.info("[Shape/Browser] Simulating human interactions")
            await pw_solver.simulate_human(page, duration=5.0)

            await asyncio.sleep(3.0)

            cookies = await pw_solver.get_all_cookies(page)
            logger.info(f"[Shape/Browser] Got {len(cookies)} cookies, {len(shape_posts)} large POSTs intercepted")

            return SolveResult(
                success=len(cookies) > 0,
                cookies=cookies,
                error_message=None if cookies else "No cookies obtained",
            )

        except Exception as e:
            logger.error(f"[Shape/Browser] Failed: {e}")
            return SolveResult(success=False, error_message=str(e))
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

    async def _solve_synthetic(self, url: str, detection: DetectionResult) -> SolveResult:
        """Synthetic Shape solver fallback."""
        async with create_client() as client:
            # Step 1: Fetch target page
            logger.info(f"[Shape] Fetching target: {url}")
            response = await client.get(url, allow_redirects=True)

            cookies = {}
            for name in response.cookies:
                cookies[name] = str(response.cookies[name])

            # Step 2: Find the Shape endpoint
            endpoint = self._find_shape_endpoint(response.text, url)
            if not endpoint:
                return SolveResult(
                    success=False,
                    error_message="Could not identify Shape collection endpoint",
                )

            logger.info(f"[Shape] Collection endpoint: {endpoint}")

            # Step 3: Build fingerprint payload
            payload = self._build_payload(url)

            # Step 4: Submit
            try:
                shape_response = await client.post(
                    endpoint,
                    data=payload,
                    headers={
                        "Content-Type": "text/plain;charset=UTF-8",
                        "Origin": url,
                        "Referer": url,
                    },
                )

                # Extract cookies from response
                for name in shape_response.cookies:
                    cookies[name] = str(shape_response.cookies[name])

                if shape_response.status_code in (200, 201):
                    logger.info("[Shape] Payload accepted")
                    return SolveResult(
                        success=True,
                        cookies=cookies,
                        sensor_data=payload,
                    )

            except Exception as e:
                logger.error(f"[Shape] Submission failed: {e}")

            return SolveResult(
                success=False,
                cookies=cookies,
                error_message="Shape challenge solution not accepted",
            )

    def _find_shape_endpoint(self, page_source: str, base_url: str) -> str | None:
        """Find the Shape collection endpoint from the page."""
        from urllib.parse import urlparse

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Common Shape endpoint patterns
        patterns = [
            r'["\']([^"\']*?/api/v[12]/shape[^"\']*)["\']',
            r'["\']([^"\']*?/s/[^"\']*)["\']',
            r'["\']([^"\']*?/shape-api[^"\']*)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, page_source, re.IGNORECASE)
            if match:
                endpoint = match.group(1)
                if endpoint.startswith("/"):
                    return f"{base}{endpoint}"
                return endpoint

        # Fallback: look for large POST targets in the obfuscated script
        post_match = re.search(r'\.open\s*\(\s*["\']POST["\']\s*,\s*["\']([^"\']+)["\']', page_source)
        if post_match:
            endpoint = post_match.group(1)
            if endpoint.startswith("/"):
                return f"{base}{endpoint}"
            return endpoint

        return None

    def _build_payload(self, url: str) -> str:
        """Build an obfuscated Shape fingerprint payload.

        Shape payloads are large, obfuscated strings. This generates
        a structured payload that mimics the format.
        """
        ts = timestamp_ms()
        canvas = canvas_fingerprint_hash()

        # Shape uses a custom encoding with delimiters
        components = [
            sha256_hash(f"{ts}"),
            str(ts),
            "1920|1080|1920|1040|24|1",  # Screen info
            "Win32",  # Platform
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "en-US",
            str(random.randint(100, 999)),  # Interaction count
            canvas,
            "Google Inc. (NVIDIA)",  # WebGL vendor
            random_hex(64),  # Session token
            str(random.randint(0, 50)),  # Mouse events
            str(random.randint(0, 20)),  # Key events
            "0",  # Touch events
            "0",  # webdriver
            sha256_hash(f"{ts}{url}")[:32],  # Checksum
        ]

        # Shape uses tilde-delimited encoding
        return "~".join(components)
