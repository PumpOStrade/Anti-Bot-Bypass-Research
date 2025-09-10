"""Akamai Bot Manager _abck cookie solver.

Implements the full sensor_data generation and cookie challenge flow:
1. Fetch target page → get initial _abck cookie (invalid, ~-1~)
2. Find and fetch the Akamai sensor script
3. Parse script for dynamic config (POST target, version, puzzle params)
4. Build sensor_data payload with device/timing/interaction data
5. POST sensor_data → get updated _abck cookie
6. Validate cookie (check for ~0~ marker)
7. Repeat if needed (some sites require 2-3 iterations)
"""

import logging
import random
import re
import time

from antibot.detector.base import DetectionResult
from antibot.solver.base import BaseSolver, SolveResult
from antibot.utils.crypto import canvas_fingerprint_hash, md5_hash, random_hex, timestamp_ms, webgl_fingerprint_hash
from antibot.utils.encoding import pipe_join, url_encode
from antibot.utils.http import create_client

logger = logging.getLogger(__name__)

# Default device parameters that mimic a real Chrome browser
DEFAULT_DEVICE = {
    "screen_width": 1920,
    "screen_height": 1080,
    "screen_avail_width": 1920,
    "screen_avail_height": 1040,
    "color_depth": 24,
    "pixel_ratio": 1,
    "timezone_offset": -300,
    "session_storage": True,
    "local_storage": True,
    "indexed_db": True,
    "open_database": True,
    "cpu_class": None,
    "platform": "Win32",
    "do_not_track": None,
    "plugins_hash": "f3a01f94e9b30ecc49cb2e885c8a6a4a",
    "canvas_hash": None,  # Generated dynamically
    "webgl_vendor": "Google Inc. (NVIDIA)",
    "webgl_renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "language": "en-US",
    "languages": "en-US,en",
    "hardware_concurrency": 16,
    "device_memory": 8,
    "max_touch_points": 0,
}


class AkamaiSolver(BaseSolver):
    name = "akamai"

    # Max iterations for cookie validation
    MAX_ITERATIONS = 3

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Attempt Akamai bypass. Tries browser-based first, falls back to synthetic."""
        if use_browser:
            result = await self._solve_browser(url, detection)
            if result.success:
                return result
            logger.info("[Akamai] Browser solve didn't get valid cookie, trying synthetic fallback")

        return await self._solve_synthetic(url, detection)

    async def _solve_browser(self, url: str, detection: DetectionResult) -> SolveResult:
        """Browser-based Akamai bypass using Playwright."""
        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None
        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            logger.info(f"[Akamai/Browser] Navigating to {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Wait for Akamai script to load and set initial _abck
            import asyncio
            await asyncio.sleep(2.0)

            # Simulate human behavior to trigger sensor collection
            logger.info("[Akamai/Browser] Simulating human interactions")
            await pw_solver.simulate_human(page, duration=5.0)

            # Wait for _abck cookie to become valid
            logger.info("[Akamai/Browser] Waiting for valid _abck cookie")
            for attempt in range(3):
                cookies = await pw_solver.get_all_cookies(page)
                abck = cookies.get("_abck", "")
                if self._is_valid_cookie(abck):
                    logger.info(f"[Akamai/Browser] Valid _abck obtained (attempt {attempt + 1})")
                    return SolveResult(success=True, cookies=cookies)

                # More interactions
                await pw_solver.simulate_human(page, duration=3.0)
                await asyncio.sleep(1.0)

            # Return what we have even if not validated
            cookies = await pw_solver.get_all_cookies(page)
            has_abck = "_abck" in cookies
            return SolveResult(
                success=has_abck,
                cookies=cookies,
                error_message=None if has_abck else "No _abck cookie obtained",
            )

        except Exception as e:
            logger.error(f"[Akamai/Browser] Failed: {e}")
            return SolveResult(success=False, error_message=str(e))
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

    async def _solve_synthetic(self, url: str, detection: DetectionResult) -> SolveResult:
        """Synthetic sensor_data generation fallback."""
        async with create_client() as client:
            # Step 1: Fetch target page to get initial cookies
            logger.info(f"[Akamai] Fetching target page: {url}")
            response = await client.get(url, allow_redirects=True)

            cookies = {}
            for name in response.cookies:
                cookies[name] = str(response.cookies[name])

            initial_abck = cookies.get("_abck", "")
            if not initial_abck:
                return SolveResult(
                    success=False,
                    error_message="No _abck cookie received from target",
                )

            logger.info(f"[Akamai] Initial _abck: {initial_abck[:60]}...")

            # Step 2: Find the sensor script URL
            script_url = self._find_script_url(response.text, detection)
            if not script_url:
                return SolveResult(
                    success=False,
                    error_message="Could not find Akamai sensor script URL",
                )

            # Make script URL absolute
            if script_url.startswith("/"):
                from urllib.parse import urlparse

                parsed = urlparse(url)
                script_url = f"{parsed.scheme}://{parsed.netloc}{script_url}"

            logger.info(f"[Akamai] Sensor script: {script_url}")

            # Step 3: Fetch and parse the sensor script
            script_response = await client.get(script_url)
            script_content = script_response.text

            config = self._parse_script_config(script_content, url)
            logger.info(f"[Akamai] Parsed config — version: {config.get('version', 'unknown')}")

            # Step 4-6: Generate sensor_data and POST (iterate if needed)
            last_sensor = None
            for iteration in range(self.MAX_ITERATIONS):
                sensor_data = self._build_sensor_data(config, iteration)
                last_sensor = sensor_data

                # POST sensor_data
                post_url = config.get("post_url", url)
                post_body = f"sensor_data={url_encode(sensor_data)}"

                logger.info(f"[Akamai] Posting sensor_data (iteration {iteration + 1}, {len(sensor_data)} bytes)")

                sensor_response = await client.post(
                    post_url,
                    data=post_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                # Extract updated _abck
                for name in sensor_response.cookies:
                    cookies[name] = str(sensor_response.cookies[name])

                new_abck = cookies.get("_abck", "")

                # Validate
                if self._is_valid_cookie(new_abck):
                    logger.info(f"[Akamai] Valid _abck obtained on iteration {iteration + 1}")
                    return SolveResult(
                        success=True,
                        cookies=cookies,
                        sensor_data=sensor_data,
                    )

                logger.info(f"[Akamai] Cookie not yet valid after iteration {iteration + 1}")
                # Small delay between iterations
                await self._random_delay()

            return SolveResult(
                success=False,
                cookies=cookies,
                sensor_data=last_sensor,
                error_message=f"Cookie not valid after {self.MAX_ITERATIONS} iterations",
            )

    def _find_script_url(self, page_source: str, detection: DetectionResult) -> str | None:
        """Find the Akamai sensor script URL from the page."""
        # First check detection results
        if detection.script_urls:
            return detection.script_urls[0]

        # Try to find hex-path pattern
        match = re.search(
            r'src=["\'](/[a-f0-9]{20,}/[a-f0-9]{6,}(?:/[a-f0-9]*)*(?:\.js)?)["\']',
            page_source,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)

        # Try alternative patterns
        match = re.search(r'src=["\']([^"\']*/_bm/[^"\']*\.js)["\']', page_source, re.IGNORECASE)
        if match:
            return match.group(1)

        return None

    def _parse_script_config(self, script_content: str, target_url: str) -> dict:
        """Parse the Akamai sensor script to extract dynamic configuration."""
        config = {
            "post_url": target_url,
            "version": "unknown",
            "dynamic_key": "",
        }

        # Extract version
        ver_match = re.search(r'ak\.v="([^"]+)"', script_content)
        if ver_match:
            config["version"] = ver_match.group(1)

        # Extract the POST target URL
        # The sensor script usually contains the target path
        post_match = re.search(r'"(/[^"]*)"[^}]*sensor_data', script_content)
        if post_match:
            from urllib.parse import urlparse

            parsed = urlparse(target_url)
            config["post_url"] = f"{parsed.scheme}://{parsed.netloc}{post_match.group(1)}"

        # Extract dynamic keys/seeds from the script
        key_match = re.search(r'bmak\.\w+="([a-f0-9]{32,})"', script_content)
        if key_match:
            config["dynamic_key"] = key_match.group(1)

        return config

    def _build_sensor_data(self, config: dict, iteration: int) -> str:
        """Build the sensor_data payload.

        The sensor_data is a pipe-delimited string containing device info,
        timing data, interaction summaries, and fingerprint hashes.
        """
        device = DEFAULT_DEVICE.copy()

        # Generate dynamic values
        start_ts = timestamp_ms() - random.randint(2000, 5000)
        now_ts = timestamp_ms()

        # Canvas fingerprint
        canvas_hash = canvas_fingerprint_hash()
        webgl_hash = webgl_fingerprint_hash(device["webgl_vendor"], device["webgl_renderer"])

        # Simulate realistic timing
        dom_complete = random.randint(800, 2500)
        dom_interactive = dom_complete - random.randint(100, 500)
        load_event = dom_complete + random.randint(50, 300)

        # Simulate interaction data
        mouse_moves = random.randint(20, 80) if iteration > 0 else random.randint(5, 20)
        mouse_clicks = random.randint(1, 5) if iteration > 0 else 0
        key_presses = random.randint(0, 10) if iteration > 0 else 0
        touch_events = 0  # Desktop = no touch

        # Build the sensor fields
        # Note: The exact field order and encoding varies by Akamai script version.
        # This represents a common structure.
        fields = [
            # Device identification
            "7a74G7m23Vrp0o5c9173161.75",  # Version identifier
            "-1",  # d1 (reserved)
            "-1",  # d2 (reserved)

            # Screen info
            str(device["screen_width"]),
            str(device["screen_height"]),
            str(device["screen_avail_width"]),
            str(device["screen_avail_height"]),
            str(device["color_depth"]),
            str(device["pixel_ratio"]),

            # Navigator info
            device["user_agent"],
            device["language"],
            device["languages"],
            str(device["hardware_concurrency"]),
            str(device["device_memory"]),
            str(device["max_touch_points"]),

            # Feature detection
            "1" if device["session_storage"] else "0",
            "1" if device["local_storage"] else "0",
            "1" if device["indexed_db"] else "0",
            "1" if device["open_database"] else "0",

            # Platform
            device["platform"],
            str(device["do_not_track"] or ""),
            str(device["timezone_offset"]),

            # Plugins hash
            device["plugins_hash"],

            # Canvas and WebGL
            canvas_hash,
            webgl_hash,
            device["webgl_vendor"],
            device["webgl_renderer"],

            # Timing
            str(start_ts),
            str(now_ts),
            str(dom_interactive),
            str(dom_complete),
            str(load_event),

            # Interaction data
            str(mouse_moves),
            str(mouse_clicks),
            str(key_presses),
            str(touch_events),

            # Automation detection (all must be clean)
            "0",  # webdriver = false
            "0",  # phantom = false
            "0",  # nightmare = false
            "0",  # selenium = false
            "0",  # domAutomation = false

            # Dynamic fields
            config.get("version", ""),
            config.get("dynamic_key", random_hex(32)),

            # Checksum / hash of above fields
            md5_hash(f"{start_ts}{device['user_agent']}{canvas_hash}"),

            # Iteration marker
            str(iteration),
        ]

        return pipe_join(fields)

    def _is_valid_cookie(self, cookie_value: str) -> bool:
        """Check if the _abck cookie indicates a valid/passed state.

        Valid cookies contain ~0~ as the second tilde-separated segment.
        Invalid cookies contain ~-1~ or ~1~ or higher.
        """
        if not cookie_value:
            return False

        parts = cookie_value.split("~")
        if len(parts) >= 3:
            try:
                return parts[1] == "0"
            except (IndexError, ValueError):
                pass
        return False

    async def _random_delay(self):
        """Add a random delay between iterations to appear human-like."""
        import asyncio

        delay = random.uniform(1.0, 3.0)
        await asyncio.sleep(delay)
