"""PerimeterX (HUMAN Security) cookie solver.

Generates valid _px3/_px2 cookies by:
1. Extracting the PX App ID from the page
2. Fetching the PX client-side script
3. Generating a device fingerprint payload
4. Submitting to the PX collector endpoint
5. Extracting the resulting cookies
"""

import json
import logging
import random
import time

from antibot.detector.base import DetectionResult
from antibot.solver.base import BaseSolver, SolveResult
from antibot.utils.crypto import canvas_fingerprint_hash, random_hex, sha256_hash, timestamp_ms
from antibot.utils.http import create_client

logger = logging.getLogger(__name__)


class PerimeterXSolver(BaseSolver):
    name = "perimeterx"

    # PX collector endpoints
    COLLECTOR_PATHS = [
        "/api/v2/collector",
        "/assets/js/bundle",
    ]

    PX_COOKIE_NAMES = ["_px3", "_pxvid", "_px2", "_pxde", "_pxhd", "_px"]

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Attempt PX bypass. Browser-based first, then synthetic fallback."""
        if use_browser:
            result = await self._solve_browser(url)
            if result.success:
                return result
            logger.info("[PX] Browser solve failed, trying synthetic fallback")

        return await self._solve_synthetic(url, detection)

    async def _solve_browser(self, url: str) -> SolveResult:
        """Browser-based PerimeterX bypass."""
        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None
        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            logger.info(f"[PX/Browser] Navigating to {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            import asyncio
            await asyncio.sleep(2.0)

            # Simulate human behavior to pass behavioral checks
            logger.info("[PX/Browser] Simulating human interactions")
            await pw_solver.simulate_human(page, duration=6.0)

            # Check for PX cookies
            cookies = await pw_solver.get_all_cookies(page)
            px_found = {k: v for k, v in cookies.items() if k.startswith("_px")}

            if px_found:
                logger.info(f"[PX/Browser] PX cookies obtained: {list(px_found.keys())}")
                return SolveResult(success=True, cookies=cookies)

            # Try waiting longer
            await asyncio.sleep(3.0)
            cookies = await pw_solver.get_all_cookies(page)
            px_found = {k: v for k, v in cookies.items() if k.startswith("_px")}

            return SolveResult(
                success=len(px_found) > 0,
                cookies=cookies,
                error_message=None if px_found else "No PX cookies obtained",
            )

        except Exception as e:
            logger.error(f"[PX/Browser] Failed: {e}")
            return SolveResult(success=False, error_message=str(e))
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

    async def _solve_synthetic(self, url: str, detection: DetectionResult) -> SolveResult:
        """Synthetic PX solver fallback."""
        async with create_client() as client:
            # Step 1: Fetch target page
            logger.info(f"[PX] Fetching target: {url}")
            response = await client.get(url, allow_redirects=True)

            cookies = {}
            for name in response.cookies:
                cookies[name] = str(response.cookies[name])

            # Step 2: Extract PX App ID
            import re

            app_id_match = re.search(r'["\']?(PX[A-Za-z0-9]{4,12})["\']?', response.text)
            app_id = app_id_match.group(1) if app_id_match else None

            if not app_id:
                return SolveResult(
                    success=False,
                    error_message="Could not extract PX App ID from page",
                )

            logger.info(f"[PX] Found App ID: {app_id}")

            # Step 3: Build device fingerprint payload
            payload = self._build_payload(app_id, url)

            # Step 4: Submit to collector
            from urllib.parse import urlparse

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for collector_path in self.COLLECTOR_PATHS:
                try:
                    collector_url = f"{base_url}{collector_path}"
                    logger.info(f"[PX] Submitting to collector: {collector_url}")

                    collector_response = await client.post(
                        collector_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )

                    # Extract cookies from response
                    for name in collector_response.cookies:
                        cookies[name] = str(collector_response.cookies[name])

                    if any(c.startswith("_px") for c in cookies):
                        logger.info("[PX] PX cookies obtained")
                        return SolveResult(
                            success=True,
                            cookies=cookies,
                            sensor_data=json.dumps(payload),
                        )
                except Exception as e:
                    logger.debug(f"[PX] Collector {collector_path} failed: {e}")
                    continue

            return SolveResult(
                success=False,
                cookies=cookies,
                error_message="Failed to obtain valid PX cookies from any collector endpoint",
            )

    def _build_payload(self, app_id: str, url: str) -> dict:
        """Build the PX collector payload with device fingerprint."""
        ts = timestamp_ms()

        return {
            "appId": app_id,
            "tag": "v8.10.1",
            "uuid": random_hex(32),
            "ft": ts,
            "seq": 0,
            "en": "NTA",
            "pc": sha256_hash(f"{ts}{app_id}")[:16],
            "pxhd": random_hex(64),
            "rsc": 1,
            "ci": {
                "s": 1920,
                "sh": 1080,
                "cd": 24,
                "pr": 1,
                "tz": -300,
                "ss": True,
                "ls": True,
                "idb": True,
                "odb": True,
            },
            "d": {
                "PX1199": canvas_fingerprint_hash(),
                "PX1200": random.randint(100, 999),
                "PX1069": random.randint(0, 50),
                "PX1070": random.randint(0, 20),
                "PX1071": 0,
            },
            "cs": sha256_hash(f"{ts}{app_id}{url}")[:16],
        }
