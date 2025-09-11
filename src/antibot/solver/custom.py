"""Custom / in-house anti-bot solver.

Uses Playwright browser-based solving since custom protections
can't be bypassed with synthetic payloads — we need to execute
the site's own JavaScript in a real browser.
"""

import logging

from antibot.detector.base import DetectionResult
from antibot.solver.base import BaseSolver, SolveResult
from antibot.solver.browser import PlaywrightSolver

logger = logging.getLogger(__name__)


class CustomSolver(BaseSolver):
    name = "custom"

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Solve custom anti-bot by navigating with a real browser."""
        if not use_browser:
            return SolveResult(
                success=False,
                error_message="Custom protections require browser mode (--no-browser not supported)",
            )

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None
        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            import asyncio

            logger.info(f"[Custom/Browser] Navigating to {url}")
            # Use domcontentloaded — SPAs like X never reach networkidle
            # because they stream data continuously
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Wait for JS to bootstrap the SPA
            await asyncio.sleep(3.0)

            # Simulate human behavior to trigger any behavioral checks
            logger.info("[Custom/Browser] Simulating human interactions")
            await pw_solver.simulate_human(page, duration=6.0)

            # Wait for async API calls and cookie-setting to complete
            await asyncio.sleep(3.0)

            # Get all cookies
            cookies = await pw_solver.get_all_cookies(page)

            # Get the final page URL (may have redirected)
            final_url = page.url
            logger.info(f"[Custom/Browser] Final URL: {final_url}, got {len(cookies)} cookies")

            return SolveResult(
                success=len(cookies) > 0,
                cookies=cookies,
                error_message=None if cookies else "No cookies obtained",
            )

        except Exception as e:
            logger.error(f"[Custom/Browser] Failed: {e}")
            return SolveResult(success=False, error_message=str(e))
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()
