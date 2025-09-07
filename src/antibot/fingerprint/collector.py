"""Browser fingerprint collection using Playwright."""

import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# JavaScript to collect comprehensive browser fingerprint
FINGERPRINT_SCRIPT = """
() => {
    const fp = {};

    // Navigator properties
    fp.userAgent = navigator.userAgent;
    fp.platform = navigator.platform;
    fp.language = navigator.language;
    fp.languages = Array.from(navigator.languages || []);
    fp.hardwareConcurrency = navigator.hardwareConcurrency || null;
    fp.deviceMemory = navigator.deviceMemory || null;
    fp.maxTouchPoints = navigator.maxTouchPoints || 0;
    fp.doNotTrack = navigator.doNotTrack;
    fp.webdriver = navigator.webdriver;
    fp.cookieEnabled = navigator.cookieEnabled;
    fp.pdfViewerEnabled = navigator.pdfViewerEnabled;

    // Plugins
    fp.plugins = [];
    if (navigator.plugins) {
        for (let i = 0; i < navigator.plugins.length; i++) {
            fp.plugins.push(navigator.plugins[i].name);
        }
    }

    // Screen
    fp.screenWidth = screen.width;
    fp.screenHeight = screen.height;
    fp.screenAvailWidth = screen.availWidth;
    fp.screenAvailHeight = screen.availHeight;
    fp.colorDepth = screen.colorDepth;
    fp.pixelDepth = screen.pixelDepth;

    // Timezone
    fp.timezoneOffset = new Date().getTimezoneOffset();
    try {
        fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch(e) {
        fp.timezone = null;
    }

    // Canvas fingerprint
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 300;
        canvas.height = 150;
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('AntiBotLab fp', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('AntiBotLab fp', 4, 17);
        fp.canvasHash = canvas.toDataURL().length.toString();
    } catch(e) {
        fp.canvasHash = null;
    }

    // WebGL fingerprint
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                fp.webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                fp.webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            }
            fp.webglVersion = gl.getParameter(gl.VERSION);
            fp.webglShadingLanguageVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
            // Hash of supported extensions
            const extensions = gl.getSupportedExtensions() || [];
            fp.webglExtensions = extensions.length;
            fp.webglHash = extensions.join(',').length.toString();
        }
    } catch(e) {
        fp.webglVendor = null;
        fp.webglRenderer = null;
    }

    // Automation detection flags
    fp.automationIndicators = {
        'navigator.webdriver': !!navigator.webdriver,
        'window._phantom': !!window._phantom,
        'window.callPhantom': !!window.callPhantom,
        'window.__nightmare': !!window.__nightmare,
        'window.domAutomation': !!window.domAutomation,
        'window.domAutomationController': !!window.domAutomationController,
        'navigator.plugins.length > 0': navigator.plugins.length > 0,
        'navigator.languages.length > 0': (navigator.languages || []).length > 0,
    };

    // Check for Chrome-specific properties
    fp.chrome = !!window.chrome;
    fp.chromeRuntime = !!(window.chrome && window.chrome.runtime);

    // Performance timing (useful for timing-based detection)
    if (performance && performance.timing) {
        const t = performance.timing;
        fp.performanceTiming = {
            connectEnd: t.connectEnd,
            domComplete: t.domComplete,
            domContentLoadedEventEnd: t.domContentLoadedEventEnd,
            domInteractive: t.domInteractive,
            loadEventEnd: t.loadEventEnd,
            navigationStart: t.navigationStart,
        };
    }

    return fp;
}
"""


class FingerprintCollector:
    """Collect browser fingerprints using Playwright."""

    async def collect_real_fingerprint(self, browser_type: str = "chromium") -> "Fingerprint":
        """Launch a real browser and collect its fingerprint.

        Args:
            browser_type: Browser to use ('chromium', 'firefox', 'webkit').

        Returns:
            A saved Fingerprint ORM object.
        """
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser_launcher = getattr(p, browser_type)
            browser = await browser_launcher.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Navigate to a blank page to collect fingerprint
            await page.goto("about:blank")
            fp_data = await page.evaluate(FINGERPRINT_SCRIPT)

            await browser.close()

        # Save to database
        return await self._save_fingerprint(fp_data, source=f"real_{browser_type}")

    async def collect_bot_fingerprint(self) -> "Fingerprint":
        """Collect the fingerprint as a bot HTTP client would appear.

        This creates a baseline of what anti-bot systems see from
        a standard Python HTTP client (no browser APIs available).
        """
        import platform

        from antibot.config import settings

        fp_data = {
            "userAgent": settings.default_user_agent,
            "platform": platform.system(),
            "screenWidth": None,
            "screenHeight": None,
            "colorDepth": None,
            "timezone": None,
            "timezoneOffset": None,
            "languages": None,
            "hardwareConcurrency": None,
            "deviceMemory": None,
            "plugins": None,
            "canvasHash": None,
            "webglVendor": None,
            "webglRenderer": None,
            "webglHash": None,
            "webdriver": None,
            "automationIndicators": {},
        }

        return await self._save_fingerprint(fp_data, source="bot_http_client")

    async def _save_fingerprint(self, fp_data: dict, source: str) -> "Fingerprint":
        """Persist a collected fingerprint to the database."""
        from antibot.database import async_session
        from antibot.models import Fingerprint

        fp = Fingerprint(
            source=source,
            collected_at=datetime.utcnow(),
            user_agent=fp_data.get("userAgent"),
            screen_width=fp_data.get("screenWidth"),
            screen_height=fp_data.get("screenHeight"),
            timezone=fp_data.get("timezone"),
            languages=json.dumps(fp_data.get("languages")) if fp_data.get("languages") else None,
            plugins_hash=str(len(fp_data.get("plugins", []) or [])),
            canvas_hash=fp_data.get("canvasHash"),
            webgl_hash=fp_data.get("webglHash"),
            webgl_vendor=fp_data.get("webglVendor"),
            webgl_renderer=fp_data.get("webglRenderer"),
            platform=fp_data.get("platform"),
            hardware_concurrency=fp_data.get("hardwareConcurrency"),
            device_memory=fp_data.get("deviceMemory"),
            raw_data=json.dumps(fp_data),
        )

        async with async_session() as session:
            session.add(fp)
            await session.commit()
            await session.refresh(fp)

        return fp
