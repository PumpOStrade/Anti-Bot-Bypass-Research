"""Shared Playwright-based solver with stealth and human simulation.

Provides a base class that launches a stealth browser, simulates human
interactions, and extracts cookies after anti-bot scripts complete.
"""

import asyncio
import logging
import math
import random
import time

from playwright.async_api import BrowserContext, Page, async_playwright

from antibot.solver.base import SolveResult

logger = logging.getLogger(__name__)

# JavaScript to inject before page load to hide automation signals
STEALTH_SCRIPT = """
// Hide navigator.webdriver
Object.defineProperty(navigator, 'webdriver', { get: () => false });

// Inject window.chrome
if (!window.chrome) {
    window.chrome = {
        runtime: {
            onMessage: { addListener: function() {}, removeListener: function() {} },
            sendMessage: function() {},
            connect: function() { return { onMessage: { addListener: function() {} } }; }
        },
        loadTimes: function() { return {}; },
        csi: function() { return {}; },
    };
}

// Fix plugins array (headless Chrome has empty plugins)
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const plugins = [
            { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1 },
            { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: '', length: 1 },
            { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: '', length: 1 },
            { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: '', length: 1 },
            { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: '', length: 1 },
        ];
        plugins.refresh = function() {};
        plugins.namedItem = function(name) { return this.find(p => p.name === name) || null; };
        plugins.item = function(i) { return this[i] || null; };
        return plugins;
    }
});

// Fix permissions query
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => {
    if (parameters.name === 'notifications') {
        return Promise.resolve({ state: Notification.permission });
    }
    return originalQuery(parameters);
};

// Fix languages
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

// Hide automation-related properties
delete window.__nightmare;
delete window._phantom;
delete window.callPhantom;
delete window.domAutomation;
delete window.domAutomationController;

// Hide CDP (Chrome DevTools Protocol) artifacts
try {
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
} catch(e) {}

// Canvas fingerprint randomization — add subtle noise per session
const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    if (ctx && this.width > 0 && this.height > 0) {
        try {
            const imageData = ctx.getImageData(0, 0, Math.min(this.width, 16), Math.min(this.height, 16));
            for (let i = 0; i < imageData.data.length; i += 4) {
                if (Math.random() > 0.99) imageData.data[i] ^= 1;
            }
            ctx.putImageData(imageData, 0, 0);
        } catch(e) {}
    }
    return _origToDataURL.apply(this, arguments);
};

// WebGL vendor/renderer spoofing
const _getParam = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return 'Google Inc. (NVIDIA)';
    if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
    return _getParam.apply(this, arguments);
};
try {
    const _getParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return 'Google Inc. (NVIDIA)';
        if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        return _getParam2.apply(this, arguments);
    };
} catch(e) {}

// Navigator property hardening
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 16 });
Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0 });

// Notification permission consistency
try {
    Object.defineProperty(Notification, 'permission', { get: () => 'default' });
} catch(e) {}
"""


class PlaywrightSolver:
    """Base class for Playwright-based anti-bot solving.

    Provides stealth browser launching, human simulation, cookie
    extraction, and request interception.
    """

    async def launch_stealth_browser(self, proxy: str | None = None) -> tuple:
        """Launch a stealth Playwright browser with anti-detection measures.

        Args:
            proxy: Optional proxy URL (e.g. 'socks5://host:port').

        Returns (playwright_instance, browser, context, page).
        Caller is responsible for closing.
        """
        pw = await async_playwright().start()

        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-infobars",
                "--disable-features=IsolateOrigins,site-per-process",
                "--flag-switches-begin",
                "--flag-switches-end",
                "--window-size=1920,1080",
                "--start-maximized",
            ],
        )

        # Randomize viewport slightly to avoid fingerprint consistency
        vw = 1920 + random.randint(-20, 20)
        vh = 1080 + random.randint(-10, 10)

        # Randomize timezone
        timezones = ["America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"]

        # Build context kwargs
        context_kwargs = {
            "viewport": {"width": vw, "height": vh},
            "screen": {"width": 1920, "height": 1080},
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "locale": "en-US",
            "timezone_id": random.choice(timezones),
            "color_scheme": "light",
            "java_script_enabled": True,
            "has_touch": False,
            "is_mobile": False,
            "device_scale_factor": 1,
        }

        # Add proxy if provided
        if proxy:
            from antibot.utils.proxy import ProxyManager
            pm = ProxyManager(proxy_url=proxy)
            proxy_config = pm.get_playwright_proxy(proxy)
            if proxy_config:
                context_kwargs["proxy"] = proxy_config

        context = await browser.new_context(**context_kwargs)

        # Inject stealth script before every page navigation
        await context.add_init_script(STEALTH_SCRIPT)

        page = await context.new_page()
        return pw, browser, context, page

    async def simulate_human(self, page: Page, duration: float = 5.0):
        """Simulate realistic human behavior on a page.

        Generates Bezier-curve mouse movements, random scrolls,
        and natural pauses.
        """
        start = time.time()
        viewport = page.viewport_size or {"width": 1920, "height": 1080}
        w, h = viewport["width"], viewport["height"]

        # Initial mouse movement to a random spot
        x, y = random.randint(200, w - 200), random.randint(200, h - 200)
        await self._bezier_mouse_move(page, x, y)
        await asyncio.sleep(random.uniform(0.3, 0.8))

        while time.time() - start < duration:
            action = random.choices(
                ["mouse_move", "scroll", "pause"],
                weights=[50, 30, 20],
                k=1,
            )[0]

            if action == "mouse_move":
                # Move to a new random position with Bezier curve
                new_x = max(50, min(w - 50, x + random.randint(-300, 300)))
                new_y = max(50, min(h - 50, y + random.randint(-200, 200)))
                await self._bezier_mouse_move(page, new_x, new_y)
                x, y = new_x, new_y
                await asyncio.sleep(random.uniform(0.1, 0.4))

            elif action == "scroll":
                # Random scroll
                delta = random.choice([-300, -200, -100, 100, 200, 300])
                await page.mouse.wheel(0, delta)
                await asyncio.sleep(random.uniform(0.3, 0.8))

            elif action == "pause":
                # Natural reading pause
                await asyncio.sleep(random.uniform(0.5, 1.5))

    async def _bezier_mouse_move(self, page: Page, target_x: int, target_y: int, steps: int = 20):
        """Move mouse along a Bezier curve to target position."""
        # Get current position (approximate from viewport center if unknown)
        viewport = page.viewport_size or {"width": 1920, "height": 1080}
        start_x = random.randint(100, viewport["width"] - 100)
        start_y = random.randint(100, viewport["height"] - 100)

        # Generate control points for cubic Bezier
        cp1_x = start_x + random.randint(-100, 100)
        cp1_y = start_y + random.randint(-100, 100)
        cp2_x = target_x + random.randint(-100, 100)
        cp2_y = target_y + random.randint(-100, 100)

        for i in range(steps):
            t = i / steps
            # Cubic Bezier formula
            x = int(
                (1 - t) ** 3 * start_x
                + 3 * (1 - t) ** 2 * t * cp1_x
                + 3 * (1 - t) * t ** 2 * cp2_x
                + t ** 3 * target_x
            )
            y = int(
                (1 - t) ** 3 * start_y
                + 3 * (1 - t) ** 2 * t * cp1_y
                + 3 * (1 - t) * t ** 2 * cp2_y
                + t ** 3 * target_y
            )
            await page.mouse.move(x, y)
            await asyncio.sleep(random.uniform(0.005, 0.02))

        await page.mouse.move(target_x, target_y)

    async def wait_for_cookies(
        self,
        page: Page,
        cookie_names: list[str],
        timeout: float = 30.0,
        poll_interval: float = 0.5,
    ) -> dict[str, str]:
        """Wait for specific cookies to appear on the page.

        Returns a dict of cookie_name -> cookie_value for all found cookies.
        """
        start = time.time()
        while time.time() - start < timeout:
            cookies = await page.context.cookies()
            found = {}
            for cookie in cookies:
                if cookie["name"] in cookie_names:
                    found[cookie["name"]] = cookie["value"]

            if found:
                return found

            await asyncio.sleep(poll_interval)

        return {}

    async def get_all_cookies(self, page: Page) -> dict[str, str]:
        """Get all cookies from the current page context."""
        cookies = await page.context.cookies()
        return {c["name"]: c["value"] for c in cookies}

    async def intercept_requests(
        self,
        page: Page,
        url_pattern: str,
        timeout: float = 30.0,
    ) -> list[dict]:
        """Intercept outgoing requests matching a URL pattern.

        Returns list of captured requests with url, method, headers, body.
        """
        captured = []

        async def on_request(request):
            if url_pattern.lower() in request.url.lower():
                captured.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data,
                })

        page.on("request", on_request)

        # Wait for captures or timeout
        start = time.time()
        while time.time() - start < timeout and not captured:
            await asyncio.sleep(0.5)

        return captured

    async def solve_with_browser(
        self,
        url: str,
        target_cookies: list[str],
        wait_time: float = 8.0,
        interaction_time: float = 5.0,
    ) -> SolveResult:
        """Generic browser-based solving flow.

        1. Launch stealth browser
        2. Navigate to URL
        3. Simulate human interactions
        4. Wait for target cookies
        5. Return all cookies

        Provider-specific solvers can override this or call it directly.
        """
        pw = None
        browser = None
        try:
            pw, browser, context, page = await self.launch_stealth_browser()

            logger.info(f"[Browser] Navigating to {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Wait for page scripts to load
            await asyncio.sleep(random.uniform(1.0, 2.0))

            # Simulate human behavior
            logger.info(f"[Browser] Simulating human interactions ({interaction_time}s)")
            await self.simulate_human(page, duration=interaction_time)

            # Wait for target cookies to appear
            logger.info(f"[Browser] Waiting for cookies: {target_cookies}")
            target_found = await self.wait_for_cookies(page, target_cookies, timeout=wait_time)

            # Get all cookies regardless
            all_cookies = await self.get_all_cookies(page)

            if target_found:
                logger.info(f"[Browser] Target cookies obtained: {list(target_found.keys())}")
                return SolveResult(
                    success=True,
                    cookies=all_cookies,
                )

            # Even without target cookies, return what we have
            logger.info(f"[Browser] Got {len(all_cookies)} cookies (target not found)")
            return SolveResult(
                success=len(all_cookies) > 0,
                cookies=all_cookies,
                error_message=f"Target cookies {target_cookies} not found after {wait_time}s" if not all_cookies else None,
            )

        except Exception as e:
            logger.error(f"[Browser] Solve failed: {e}")
            return SolveResult(success=False, error_message=str(e))

        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()
