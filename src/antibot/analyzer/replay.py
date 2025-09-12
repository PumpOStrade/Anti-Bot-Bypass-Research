"""Challenge recording and replay — record a full challenge flow and replay with modifications."""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class RecordedRequest:
    index: int
    url: str
    method: str
    headers: dict
    body: str | None
    timestamp: float
    resource_type: str = ""


@dataclass
class RecordedResponse:
    url: str
    status: int
    headers: dict
    timestamp: float


@dataclass
class ChallengeRecording:
    id: int | None = None
    url: str = ""
    domain: str = ""
    provider: str = ""
    recorded_at: str = ""
    requests: list[RecordedRequest] = field(default_factory=list)
    responses: list[RecordedResponse] = field(default_factory=list)
    cookies_before: dict = field(default_factory=dict)
    cookies_after: dict = field(default_factory=dict)
    console_logs: list[str] = field(default_factory=list)
    total_duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url, "domain": self.domain, "provider": self.provider,
            "recorded_at": self.recorded_at,
            "requests": [{"index": r.index, "url": r.url, "method": r.method, "headers": r.headers, "body": r.body, "timestamp": r.timestamp} for r in self.requests],
            "responses": [{"url": r.url, "status": r.status, "headers": r.headers, "timestamp": r.timestamp} for r in self.responses],
            "cookies_before": self.cookies_before, "cookies_after": self.cookies_after,
            "console_logs": self.console_logs, "total_duration_ms": self.total_duration_ms,
        }


@dataclass
class ReplayResult:
    success: bool
    status_code: int = 0
    cookies_obtained: dict = field(default_factory=dict)
    modifications_applied: dict = field(default_factory=dict)
    error: str | None = None


class ChallengeRecorder:
    """Record a complete challenge flow in a real browser."""

    async def record(self, url: str, proxy: str | None = None) -> ChallengeRecording:
        """Launch browser, navigate to URL, record all network activity."""
        from urllib.parse import urlparse

        from antibot.solver.browser import PlaywrightSolver

        pw_solver = PlaywrightSolver()
        pw, browser, context, page = await pw_solver.launch_stealth_browser(proxy=proxy)

        recording = ChallengeRecording(
            url=url,
            domain=urlparse(url).netloc,
            recorded_at=datetime.utcnow().isoformat(),
        )

        start_time = time.time()
        req_index = 0

        async def on_request(request):
            nonlocal req_index
            recording.requests.append(RecordedRequest(
                index=req_index,
                url=request.url,
                method=request.method,
                headers=dict(request.headers),
                body=request.post_data,
                timestamp=time.time() - start_time,
                resource_type=request.resource_type,
            ))
            req_index += 1

        async def on_response(response):
            recording.responses.append(RecordedResponse(
                url=response.url,
                status=response.status,
                headers=dict(response.headers),
                timestamp=time.time() - start_time,
            ))

        def on_console(msg):
            recording.console_logs.append(f"[{msg.type}] {msg.text}")

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("console", on_console)

        try:
            # Get cookies before
            recording.cookies_before = await pw_solver.get_all_cookies(page)

            logger.info(f"[Recorder] Navigating to {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Wait for challenge to complete
            await asyncio.sleep(3.0)
            await pw_solver.simulate_human(page, duration=5.0)
            await asyncio.sleep(3.0)

            # Get cookies after
            recording.cookies_after = await pw_solver.get_all_cookies(page)
            recording.total_duration_ms = int((time.time() - start_time) * 1000)

            logger.info(f"[Recorder] Captured {len(recording.requests)} requests, {len(recording.responses)} responses")

        finally:
            await browser.close()
            await pw.stop()

        # Detect provider
        from antibot.detector.engine import DetectionEngine
        from antibot.utils.http import fetch_page
        try:
            response, page_source = await fetch_page(url, proxy=proxy)
            engine = DetectionEngine()
            for detector in engine.detectors.values():
                result = await detector.detect(url, response, page_source)
                if result:
                    recording.provider = result.provider
                    break
        except Exception:
            pass

        # Save to DB
        await self._save_recording(recording)

        return recording

    async def _save_recording(self, recording: ChallengeRecording):
        """Persist recording to database."""
        from antibot.database import async_session
        from antibot.models import Recording

        rec = Recording(
            url=recording.url,
            domain=recording.domain,
            provider=recording.provider,
            recorded_at=datetime.utcnow(),
            request_count=len(recording.requests),
            data=json.dumps(recording.to_dict()),
            status="completed",
        )

        async with async_session() as session:
            session.add(rec)
            await session.commit()
            await session.refresh(rec)
            recording.id = rec.id


class ChallengeReplayer:
    """Replay recorded challenges with modifications to test field validation."""

    async def test_field(self, recording_id: int, field_name: str, new_value: str) -> ReplayResult:
        """Modify one field in the recording and replay to test if it's validated."""
        from sqlalchemy import select

        from antibot.database import async_session
        from antibot.models import Recording

        async with async_session() as session:
            rec = (await session.execute(select(Recording).where(Recording.id == recording_id))).scalar_one_or_none()
            if not rec:
                return ReplayResult(success=False, error=f"Recording {recording_id} not found")

        data = json.loads(rec.data)

        # Navigate with the modification applied
        from antibot.solver.browser import PlaywrightSolver
        pw_solver = PlaywrightSolver()
        pw = None
        browser = None

        try:
            pw, browser, context, page = await pw_solver.launch_stealth_browser()

            # Inject modification script
            mod_script = self._build_modification_script(field_name, new_value)
            await context.add_init_script(mod_script)

            await page.goto(data["url"], wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(3.0)
            await pw_solver.simulate_human(page, duration=3.0)
            await asyncio.sleep(3.0)

            cookies = await pw_solver.get_all_cookies(page)
            status = 200  # If we got here, page loaded

            # Check if we got blocked
            title = await page.title()
            blocked = any(t in title.lower() for t in ["blocked", "denied", "verify", "captcha", "just a moment"])

            return ReplayResult(
                success=not blocked,
                status_code=status,
                cookies_obtained=cookies,
                modifications_applied={field_name: new_value},
            )

        except Exception as e:
            return ReplayResult(success=False, error=str(e), modifications_applied={field_name: new_value})
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

    def _build_modification_script(self, field_name: str, value: str) -> str:
        """Generate JS to modify a specific browser property."""
        modifications = {
            "webdriver": f"Object.defineProperty(navigator, 'webdriver', {{ get: () => {value} }});",
            "user_agent": f'Object.defineProperty(navigator, "userAgent", {{ get: () => "{value}" }});',
            "platform": f'Object.defineProperty(navigator, "platform", {{ get: () => "{value}" }});',
            "plugins": f'Object.defineProperty(navigator, "plugins", {{ get: () => [] }});' if value == "empty" else "",
            "languages": f'Object.defineProperty(navigator, "languages", {{ get: () => [] }});' if value == "empty" else "",
            "canvas": """
                const _orig = HTMLCanvasElement.prototype.toDataURL;
                HTMLCanvasElement.prototype.toDataURL = function() {
                    const ctx = this.getContext('2d');
                    if (ctx) ctx.fillRect(0, 0, 1, 1);
                    return _orig.apply(this, arguments);
                };
            """,
            "webgl_vendor": f"""
                const _gp = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(p) {{
                    if (p === 37445) return "{value}";
                    return _gp.apply(this, arguments);
                }};
            """,
            "screen_width": f'Object.defineProperty(screen, "width", {{ get: () => {value} }});',
            "screen_height": f'Object.defineProperty(screen, "height", {{ get: () => {value} }});',
            "timezone": f'Date.prototype.getTimezoneOffset = function() {{ return {value}; }};',
            "hardware_concurrency": f'Object.defineProperty(navigator, "hardwareConcurrency", {{ get: () => {value} }});',
        }

        return modifications.get(field_name, f"// Unknown field: {field_name}")
