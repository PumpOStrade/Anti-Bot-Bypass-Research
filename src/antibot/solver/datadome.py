"""DataDome cookie solver.

Generates valid DataDome cookies by:
1. Extracting the DataDome JS key from the page
2. Building a device check payload
3. POSTing to the DataDome API endpoint
4. Extracting the refreshed datadome cookie
"""

import json
import logging
import random
import re

from antibot.detector.base import DetectionResult
from antibot.solver.base import BaseSolver, SolveResult
from antibot.utils.crypto import canvas_fingerprint_hash, random_hex, sha256_hash, timestamp_ms
from antibot.utils.http import create_client

logger = logging.getLogger(__name__)


class DataDomeSolver(BaseSolver):
    name = "datadome"

    DD_API_URL = "https://api-js.datadome.co/js/"

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Attempt DataDome bypass. Browser-based first, then synthetic fallback."""
        if use_browser:
            result = await self._solve_browser(url)
            if result.success:
                return result
            logger.info("[DataDome] Browser solve failed, trying synthetic fallback")

        return await self._solve_synthetic(url, detection)

    async def _solve_browser(self, url: str) -> SolveResult:
        """Browser-based DataDome bypass."""
        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None
        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            # Track DataDome API calls
            dd_api_called = []

            async def on_response(response):
                if "datadome" in response.url.lower():
                    dd_api_called.append(response.url)

            page.on("response", on_response)

            logger.info(f"[DataDome/Browser] Navigating to {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            import asyncio
            await asyncio.sleep(2.0)

            # Simulate human behavior to generate real behavioral data
            logger.info("[DataDome/Browser] Simulating human interactions")
            await pw_solver.simulate_human(page, duration=5.0)

            # Wait for DataDome to process
            await asyncio.sleep(2.0)

            cookies = await pw_solver.get_all_cookies(page)
            has_dd = "datadome" in cookies
            logger.info(f"[DataDome/Browser] Got {len(cookies)} cookies, datadome={'yes' if has_dd else 'no'}, {len(dd_api_called)} API calls")

            return SolveResult(
                success=has_dd,
                cookies=cookies,
                error_message=None if has_dd else "No datadome cookie obtained",
            )

        except Exception as e:
            logger.error(f"[DataDome/Browser] Failed: {e}")
            return SolveResult(success=False, error_message=str(e))
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

    async def _solve_synthetic(self, url: str, detection: DetectionResult) -> SolveResult:
        """Synthetic DataDome solver fallback."""
        async with create_client() as client:
            # Step 1: Fetch target page
            logger.info(f"[DataDome] Fetching target: {url}")
            response = await client.get(url, allow_redirects=True)

            cookies = {}
            for name in response.cookies:
                cookies[name] = str(response.cookies[name])

            # Step 2: Extract DataDome JS key
            dd_key = self._extract_dd_key(response.text)
            if not dd_key:
                return SolveResult(
                    success=False,
                    error_message="Could not extract DataDome JS key from page",
                )

            logger.info(f"[DataDome] Found DD key: {dd_key}")

            # Step 3: Build device check payload
            payload = self._build_payload(dd_key, url, cookies.get("datadome", ""))

            # Step 4: POST to DataDome API
            logger.info("[DataDome] Submitting device check to DataDome API")

            try:
                api_response = await client.post(
                    self.DD_API_URL,
                    data=payload,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": url,
                        "Referer": url,
                    },
                )

                # Extract datadome cookie from response
                for name in api_response.cookies:
                    cookies[name] = str(api_response.cookies[name])

                # Also check Set-Cookie in response body (DataDome sometimes returns it in JSON)
                try:
                    body = api_response.json()
                    if "cookie" in body:
                        # Parse the Set-Cookie value
                        cookie_val = body["cookie"].split("datadome=")[1].split(";")[0]
                        cookies["datadome"] = cookie_val
                except Exception:
                    pass

                if "datadome" in cookies and len(cookies["datadome"]) > 20:
                    logger.info("[DataDome] Valid datadome cookie obtained")
                    return SolveResult(
                        success=True,
                        cookies=cookies,
                        sensor_data=json.dumps(payload),
                    )

            except Exception as e:
                logger.error(f"[DataDome] API request failed: {e}")

            return SolveResult(
                success=False,
                cookies=cookies,
                error_message="Failed to obtain valid DataDome cookie",
            )

    def _extract_dd_key(self, page_source: str) -> str | None:
        """Extract the DataDome JS key from page source."""
        # Try ddjskey variable
        match = re.search(r'ddjskey\s*[=:]\s*["\']([A-Za-z0-9]+)["\']', page_source)
        if match:
            return match.group(1)

        # Try ddoptions object
        match = re.search(r'ddoptions\s*=\s*\{[^}]*key\s*:\s*["\']([A-Za-z0-9]+)["\']', page_source)
        if match:
            return match.group(1)

        # Try DataDome.init call
        match = re.search(r'DataDome\.init\s*\(\s*["\']([A-Za-z0-9]+)["\']', page_source)
        if match:
            return match.group(1)

        return None

    def _build_payload(self, dd_key: str, url: str, existing_cookie: str) -> dict:
        """Build the DataDome device check payload."""
        ts = timestamp_ms()

        return {
            "jsData": json.dumps({
                "ttst": ts - random.randint(1000, 5000),
                "ifov": False,
                "tagpu": 14.2,
                "glvd": "Google Inc. (NVIDIA)",
                "glrd": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "hc": 16,
                "br_oh": 1040,
                "br_ow": 1920,
                "ua": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                "wbd": False,
                "dp0": True,
                "tagco": True,
                "stession": True,
                "lstession": True,
                "idb": True,
                "odb": True,
                "cpt": 0,
                "slg": "en-US",
                "pf": "Win32",
                "wl": 0,
                "rvTZ": -300,
                "cW": 1920,
                "cH": 937,
                "sW": 1920,
                "sH": 1080,
                "wW": 1920,
                "wH": 937,
                "oW": 1920,
                "oH": 1040,
                "aW": 1920,
                "aH": 1040,
                "dpr": 1,
                "ce": True,
                "ama": False,
                "jset": ts,
                "cfpp": canvas_fingerprint_hash(),
                "stcfp": sha256_hash(f"{ts}{dd_key}")[:16],
                "dcok": ".example.com",
                "tbce": 0,
                "tbd": 0,
                "tse": 0,
                "tbe": 0,
                "dnse": 0,
                "dnsce": 0,
                "re": 0,
                "epar": 0,
                "uf": 0,
                "mmf": 0,
                "hmm": random.randint(10, 50),
                "hms": random.randint(100, 500),
                "ccs": random.randint(5, 20),
                "ccsr": random.randint(5, 20),
            }),
            "events": "[]",
            "eventCounters": json.dumps({"mouseMove": random.randint(20, 80)}),
            "jsType": "ch",
            "cid": existing_cookie or "",
            "ddk": dd_key,
            "Referer": url,
            "request": url,
            "responsePage": "origin",
            "ddv": "4.15.0",
        }
