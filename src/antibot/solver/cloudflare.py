"""Cloudflare solver module.

Uses Playwright to pass Cloudflare challenges:
1. Navigate with real browser
2. Wait for challenge JS to execute
3. Handle Turnstile auto-solve (non-interactive mode)
4. Wait for cf_clearance cookie
5. Extract all cookies
"""

import asyncio
import logging

from antibot.detector.base import DetectionResult
from antibot.solver.base import BaseSolver, SolveResult
from antibot.solver.browser import PlaywrightSolver

logger = logging.getLogger(__name__)


class CloudflareSolver(BaseSolver):
    name = "cloudflare"

    TARGET_COOKIES = ["cf_clearance", "__cf_bm"]

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Solve Cloudflare challenge via browser."""
        if not use_browser:
            return SolveResult(
                success=False,
                error_message="Cloudflare challenges require browser mode",
            )

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None
        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            logger.info(f"[Cloudflare/Browser] Navigating to {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Wait for Cloudflare challenge JS to run
            await asyncio.sleep(3.0)

            # Check if we landed on a challenge page
            title = await page.title()
            is_challenge = any(t in title.lower() for t in [
                "just a moment", "attention required", "verify", "checking",
            ])

            if is_challenge:
                logger.info("[Cloudflare/Browser] Challenge page detected, waiting for auto-solve")

                # Simulate human — move mouse to center of page
                # Turnstile non-interactive mode auto-solves but needs mouse activity
                await pw_solver.simulate_human(page, duration=3.0)

                # Wait for challenge to complete and redirect
                for attempt in range(6):
                    await asyncio.sleep(3.0)

                    # Check if we've been redirected past the challenge
                    new_title = await page.title()
                    if new_title != title:
                        logger.info(f"[Cloudflare/Browser] Challenge passed, new title: {new_title[:50]}")
                        break

                    # Check for cf_clearance cookie
                    cookies = await pw_solver.get_all_cookies(page)
                    if "cf_clearance" in cookies:
                        logger.info("[Cloudflare/Browser] cf_clearance cookie obtained")
                        break

                    # Try clicking the Turnstile checkbox if visible
                    try:
                        turnstile = page.frame_locator("iframe[src*='challenges.cloudflare.com']")
                        checkbox = turnstile.locator("input[type='checkbox'], .cb-lb")
                        if await checkbox.count() > 0:
                            await checkbox.first.click()
                            logger.info("[Cloudflare/Browser] Clicked Turnstile checkbox")
                            await asyncio.sleep(3.0)
                    except Exception:
                        pass

                    # More human simulation
                    await pw_solver.simulate_human(page, duration=2.0)
            else:
                # No challenge page — just collect cookies
                logger.info("[Cloudflare/Browser] No challenge page, collecting cookies")
                await pw_solver.simulate_human(page, duration=3.0)
                await asyncio.sleep(2.0)

            # Final cookie collection
            cookies = await pw_solver.get_all_cookies(page)
            cf_cookies = {k: v for k, v in cookies.items() if "cf" in k.lower() or k.startswith("__cf")}

            logger.info(f"[Cloudflare/Browser] Got {len(cookies)} total cookies, {len(cf_cookies)} CF cookies")

            return SolveResult(
                success=len(cookies) > 0,
                cookies=cookies,
                error_message=None if cookies else "No cookies obtained",
            )

        except Exception as e:
            logger.error(f"[Cloudflare/Browser] Failed: {e}")
            return SolveResult(success=False, error_message=str(e))
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()
