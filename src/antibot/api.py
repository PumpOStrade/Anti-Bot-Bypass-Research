"""REST API server for programmatic access to AntiBotLab."""

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from antibot.config import settings
from antibot.database import init_db


# --- Request/Response models ---

class ScanRequest(BaseModel):
    url: str
    detectors: list[str] | None = None
    bypass: bool = False
    proxy: str | None = None


class BypassRequest(BaseModel):
    url: str
    provider: str | None = None
    proxy: str | None = None


class ScanResponse(BaseModel):
    detections: list[dict]
    bypass_results: list[dict] | None = None
    cookies: dict[str, str] | None = None


# --- Auth ---

async def verify_api_key(x_api_key: str | None = Header(None)):
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


# --- App ---

def create_api() -> FastAPI:
    app = FastAPI(
        title="AntiBotLab API",
        description="Programmatic access to anti-bot detection, bypass, and session management",
        version="0.1.0",
    )

    @app.on_event("startup")
    async def startup():
        await init_db()

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.post("/api/v1/scan", dependencies=[Depends(verify_api_key)])
    async def scan(req: ScanRequest):
        from antibot.detector.engine import DetectionEngine

        engine = DetectionEngine()
        results = await engine.scan(req.url, detectors=req.detectors, proxy=req.proxy)

        detections = [
            {
                "provider": r.provider,
                "confidence": r.confidence,
                "evidence": [{"description": e.description, "value": e.value} for e in r.evidence],
                "cookies_found": r.cookies_found,
            }
            for r in results
        ]

        bypass_results = None
        all_cookies = None

        if req.bypass and results:
            from antibot.solver.engine import SolverEngine

            solver = SolverEngine()
            bypass_results = []
            for detection in results:
                solve_result = await solver.solve(req.url, detection, use_browser=True)
                bypass_results.append({
                    "provider": detection.provider,
                    "success": solve_result.success,
                    "duration_ms": solve_result.duration_ms,
                    "error": solve_result.error_message,
                })
                if solve_result.success and solve_result.cookies:
                    all_cookies = solve_result.cookies

                    # Auto-save session
                    from urllib.parse import urlparse

                    from antibot.session import SessionManager
                    sm = SessionManager()
                    domain = urlparse(req.url).netloc
                    await sm.save(domain, solve_result.cookies, detection.provider, req.proxy)

        response = {"detections": detections}
        if bypass_results is not None:
            response["bypass_results"] = bypass_results
        if all_cookies:
            response["cookies"] = all_cookies

            from antibot.utils.export import to_curl, to_python_requests
            response["export"] = {
                "curl": to_curl(req.url, all_cookies),
                "python": to_python_requests(req.url, all_cookies),
            }

        return response

    @app.post("/api/v1/bypass", dependencies=[Depends(verify_api_key)])
    async def bypass(req: BypassRequest):
        from antibot.detector.engine import DetectionEngine
        from antibot.solver.engine import SolverEngine

        engine = DetectionEngine()
        results = await engine.scan(req.url, proxy=req.proxy)

        if req.provider:
            results = [r for r in results if req.provider in r.provider]

        if not results:
            return {"success": False, "error": "No matching protection detected"}

        solver = SolverEngine()
        for detection in results:
            solve_result = await solver.solve(req.url, detection, use_browser=True)
            if solve_result.success and solve_result.cookies:
                from urllib.parse import urlparse

                from antibot.session import SessionManager
                sm = SessionManager()
                domain = urlparse(req.url).netloc
                await sm.save(domain, solve_result.cookies, detection.provider, req.proxy)

                from antibot.utils.export import to_curl, to_python_requests
                return {
                    "success": True,
                    "provider": detection.provider,
                    "duration_ms": solve_result.duration_ms,
                    "cookies": solve_result.cookies,
                    "export": {
                        "curl": to_curl(req.url, solve_result.cookies),
                        "python": to_python_requests(req.url, solve_result.cookies),
                    },
                }

        return {"success": False, "error": "Bypass failed for all detected protections"}

    @app.get("/api/v1/sessions", dependencies=[Depends(verify_api_key)])
    async def list_sessions():
        from antibot.session import SessionManager
        sm = SessionManager()
        return {"sessions": await sm.list_sessions()}

    @app.get("/api/v1/sessions/{domain}", dependencies=[Depends(verify_api_key)])
    async def get_session(domain: str):
        from antibot.session import SessionManager
        sm = SessionManager()
        cookies = await sm.load(domain)
        if not cookies:
            raise HTTPException(status_code=404, detail=f"No active session for {domain}")

        from antibot.utils.export import to_curl, to_python_requests
        url = f"https://{domain}/"
        return {
            "domain": domain,
            "cookies": cookies,
            "export": {
                "curl": to_curl(url, cookies),
                "python": to_python_requests(url, cookies),
            },
        }

    @app.post("/api/v1/sessions/{domain}/refresh", dependencies=[Depends(verify_api_key)])
    async def refresh_session(domain: str, proxy: str | None = None):
        from antibot.session import SessionManager
        sm = SessionManager()
        cookies = await sm.refresh(domain, proxy=proxy)
        if not cookies:
            raise HTTPException(status_code=500, detail=f"Failed to refresh session for {domain}")
        return {"domain": domain, "cookies": cookies, "status": "refreshed"}

    @app.delete("/api/v1/sessions/{domain}", dependencies=[Depends(verify_api_key)])
    async def delete_session(domain: str):
        from antibot.session import SessionManager
        sm = SessionManager()
        deleted = await sm.delete(domain)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"No sessions found for {domain}")
        return {"domain": domain, "status": "deleted"}

    @app.post("/api/v1/fingerprint/collect", dependencies=[Depends(verify_api_key)])
    async def collect_fingerprint(browser: str = "chromium"):
        from antibot.fingerprint.collector import FingerprintCollector
        collector = FingerprintCollector()
        fp = await collector.collect_real_fingerprint(browser_type=browser)
        return {"id": fp.id, "source": fp.source, "user_agent": fp.user_agent}

    @app.post("/api/v1/fingerprint/compare", dependencies=[Depends(verify_api_key)])
    async def compare_fingerprints(bot_id: int, real_id: int):
        from antibot.fingerprint.comparator import FingerprintComparator
        comparator = FingerprintComparator()
        report = await comparator.compare_by_ids(bot_id, real_id)
        return {
            "risk_score": report.risk_score,
            "mismatches": [
                {"field": m.field, "bot_value": m.bot_value, "real_value": m.real_value, "severity": m.severity}
                for m in report.mismatches
            ],
        }

    return app
