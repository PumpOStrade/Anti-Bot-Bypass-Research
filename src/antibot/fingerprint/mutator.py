"""Fingerprint mutation engine — systematically test which browser properties trigger detection."""

import asyncio
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MutationTest:
    field: str
    mutation: str
    js_inject: str
    original_value: str | None = None
    blocked: bool | None = None


@dataclass
class MutationReport:
    url: str
    baseline_blocked: bool
    total_tests: int = 0
    critical_fields: list[str] = field(default_factory=list)
    moderate_fields: list[str] = field(default_factory=list)
    ignored_fields: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    detection_threshold: int = 0

    def summary(self) -> str:
        lines = [
            f"Mutation Report for {self.url}",
            f"Baseline blocked: {self.baseline_blocked}",
            f"Tests run: {self.total_tests}",
            f"\nCRITICAL fields (changing = instant block): {', '.join(self.critical_fields) or 'none'}",
            f"MODERATE fields (changing = higher risk):    {', '.join(self.moderate_fields) or 'none'}",
            f"IGNORED fields (no effect when changed):     {', '.join(self.ignored_fields) or 'none'}",
        ]
        return "\n".join(lines)


# Mutation definitions
MUTATIONS = [
    MutationTest(
        field="webdriver",
        mutation="set to true",
        js_inject="Object.defineProperty(navigator, 'webdriver', { get: () => true });",
    ),
    MutationTest(
        field="user_agent",
        mutation="set to python-requests",
        js_inject='Object.defineProperty(navigator, "userAgent", { get: () => "python-requests/2.31.0" });',
    ),
    MutationTest(
        field="plugins",
        mutation="empty array",
        js_inject="""Object.defineProperty(navigator, 'plugins', {
            get: () => { const p = []; p.refresh = function(){}; return p; }
        });""",
    ),
    MutationTest(
        field="languages",
        mutation="empty array",
        js_inject='Object.defineProperty(navigator, "languages", { get: () => [] });',
    ),
    MutationTest(
        field="canvas",
        mutation="randomize all pixels",
        js_inject="""
            const _cTD = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {
                const ctx = this.getContext('2d');
                if (ctx) {
                    const id = ctx.getImageData(0,0,this.width,this.height);
                    for(let i=0;i<id.data.length;i+=4) id.data[i] ^= 0xFF;
                    ctx.putImageData(id,0,0);
                }
                return _cTD.apply(this, arguments);
            };
        """,
    ),
    MutationTest(
        field="webgl_vendor",
        mutation="set to Mesa/llvmpipe",
        js_inject="""
            const _gp = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(p) {
                if (p === 37445) return 'Mesa';
                if (p === 37446) return 'llvmpipe (LLVM 15.0.0, 256 bits)';
                return _gp.apply(this, arguments);
            };
        """,
    ),
    MutationTest(
        field="screen_size",
        mutation="set to 0x0",
        js_inject="""
            Object.defineProperty(screen, 'width', { get: () => 0 });
            Object.defineProperty(screen, 'height', { get: () => 0 });
        """,
    ),
    MutationTest(
        field="timezone",
        mutation="set to UTC+14",
        js_inject="Date.prototype.getTimezoneOffset = function() { return -840; };",
    ),
    MutationTest(
        field="hardware_concurrency",
        mutation="set to 1",
        js_inject='Object.defineProperty(navigator, "hardwareConcurrency", { get: () => 1 });',
    ),
    MutationTest(
        field="device_memory",
        mutation="set to 0.25",
        js_inject='Object.defineProperty(navigator, "deviceMemory", { get: () => 0.25 });',
    ),
    MutationTest(
        field="platform",
        mutation="set to Linux",
        js_inject='Object.defineProperty(navigator, "platform", { get: () => "Linux x86_64" });',
    ),
    MutationTest(
        field="chrome_object",
        mutation="remove window.chrome",
        js_inject="delete window.chrome;",
    ),
]


class FingerprintMutator:
    """Systematically test which browser properties trigger anti-bot detection."""

    async def test_all_fields(self, url: str, proxy: str | None = None) -> MutationReport:
        """Run all mutation tests against a URL."""
        report = MutationReport(url=url, baseline_blocked=False)

        # Step 1: Baseline test (no mutations)
        logger.info(f"[Mutator] Running baseline test on {url}")
        baseline_blocked = await self._test_with_script(url, "", proxy)
        report.baseline_blocked = baseline_blocked

        if baseline_blocked:
            logger.warning("[Mutator] Baseline is already blocked! Results may not be meaningful.")

        # Step 2: Test each mutation
        for mutation in MUTATIONS:
            logger.info(f"[Mutator] Testing: {mutation.field} ({mutation.mutation})")
            blocked = await self._test_with_script(url, mutation.js_inject, proxy)

            result = {
                "field": mutation.field,
                "mutation": mutation.mutation,
                "blocked": blocked,
                "baseline_blocked": baseline_blocked,
            }
            report.results.append(result)
            report.total_tests += 1

            if blocked and not baseline_blocked:
                # This mutation caused blocking
                report.critical_fields.append(mutation.field)
            elif not blocked and baseline_blocked:
                # Interesting — this mutation actually helped
                report.moderate_fields.append(f"{mutation.field} (helped!)")
            elif not blocked:
                report.ignored_fields.append(mutation.field)

        return report

    async def _test_with_script(self, url: str, inject_script: str, proxy: str | None = None) -> bool:
        """Navigate to URL with injected script and check if blocked."""
        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw = None
        browser = None

        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser(proxy=proxy)

            if inject_script:
                await context.add_init_script(inject_script)

            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            await asyncio.sleep(3.0)

            # Check for block indicators
            title = (await page.title()).lower()
            content = (await page.content()).lower()

            blocked_indicators = [
                "blocked", "denied", "forbidden", "captcha",
                "verify you are human", "just a moment",
                "access denied", "bot detected",
            ]

            status_code = 200
            # Check if we got a 403/429
            blocked = any(ind in title or ind in content for ind in blocked_indicators)

            return blocked

        except Exception as e:
            logger.debug(f"[Mutator] Test failed: {e}")
            return True  # Assume blocked if error
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()
