"""Dashboard API and page routes."""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from antibot.dashboard.app import templates
from antibot.database import get_session
from antibot.models import ComparisonResult, Detection, Fingerprint, Scan, SolveAttempt
from antibot.schemas import ScanRequest

router = APIRouter()


# --- Page Routes ---


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request, session: AsyncSession = Depends(get_session)):
    """Main dashboard page with stats, charts, and recent scans."""
    # Total scans
    total_scans = (await session.execute(select(func.count(Scan.id)))).scalar() or 0

    # Unique domains
    sites_tracked = (await session.execute(select(func.count(func.distinct(Scan.domain))))).scalar() or 0

    # Protection distribution
    detection_counts = (
        await session.execute(
            select(Detection.provider, func.count(Detection.id))
            .group_by(Detection.provider)
        )
    ).all()
    protection_distribution = {row[0]: row[1] for row in detection_counts}
    active_protections = len(protection_distribution)

    # Bypass success rate
    total_attempts = (await session.execute(select(func.count(SolveAttempt.id)))).scalar() or 0
    successful_attempts = (
        await session.execute(select(func.count(SolveAttempt.id)).where(SolveAttempt.success == True))
    ).scalar() or 0
    bypass_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0.0

    # Recent scans
    recent_scans_result = await session.execute(
        select(Scan)
        .options(selectinload(Scan.detections))
        .order_by(Scan.started_at.desc())
        .limit(20)
    )
    recent_scans = recent_scans_result.scalars().all()

    # Per-provider bypass rates for chart
    provider_rates = {}
    for provider, _ in detection_counts:
        p_total = (
            await session.execute(
                select(func.count(SolveAttempt.id))
                .join(Detection)
                .where(Detection.provider == provider)
            )
        ).scalar() or 0
        p_success = (
            await session.execute(
                select(func.count(SolveAttempt.id))
                .join(Detection)
                .where(Detection.provider == provider, SolveAttempt.success == True)
            )
        ).scalar() or 0
        provider_rates[provider] = (p_success / p_total * 100) if p_total > 0 else 0.0

    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_scans": total_scans,
        "sites_tracked": sites_tracked,
        "bypass_rate": bypass_rate,
        "active_protections": active_protections,
        "protection_distribution": json.dumps(protection_distribution),
        "provider_rates": json.dumps(provider_rates),
        "recent_scans": recent_scans,
    })


@router.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """New scan form page."""
    return templates.TemplateResponse("scan.html", {"request": request})


@router.get("/results/{scan_id}", response_class=HTMLResponse)
async def results_page(request: Request, scan_id: int, session: AsyncSession = Depends(get_session)):
    """Scan results detail page."""
    scan = (
        await session.execute(
            select(Scan)
            .options(
                selectinload(Scan.detections).selectinload(Detection.solve_attempts)
            )
            .where(Scan.id == scan_id)
        )
    ).scalar_one_or_none()

    if not scan:
        return HTMLResponse("<h1>Scan not found</h1>", status_code=404)

    return templates.TemplateResponse("results.html", {
        "request": request,
        "scan": scan,
    })


@router.get("/fingerprints", response_class=HTMLResponse)
async def fingerprints_page(request: Request, session: AsyncSession = Depends(get_session)):
    """Fingerprint collection and comparison page."""
    fingerprints = (
        await session.execute(select(Fingerprint).order_by(Fingerprint.collected_at.desc()))
    ).scalars().all()

    comparisons = (
        await session.execute(
            select(ComparisonResult)
            .options(
                selectinload(ComparisonResult.bot_fp),
                selectinload(ComparisonResult.real_fp),
            )
            .order_by(ComparisonResult.compared_at.desc())
            .limit(10)
        )
    ).scalars().all()

    return templates.TemplateResponse("fingerprint.html", {
        "request": request,
        "fingerprints": fingerprints,
        "comparisons": comparisons,
    })


# --- API Routes ---


@router.post("/api/scan")
async def api_scan(scan_request: ScanRequest, session: AsyncSession = Depends(get_session)):
    """Execute a scan via the API."""
    from antibot.detector.engine import DetectionEngine

    engine = DetectionEngine()
    results = await engine.scan(
        str(scan_request.url),
        detectors=scan_request.detectors,
    )

    # If bypass requested, attempt it
    solve_results = []
    if scan_request.attempt_bypass and results:
        from antibot.solver.engine import SolverEngine

        solver = SolverEngine()
        for detection in results:
            solve_result = await solver.solve(str(scan_request.url), detection)
            solve_results.append({
                "provider": detection.provider,
                "success": solve_result.success,
                "duration_ms": solve_result.duration_ms,
                "cookies": solve_result.cookies,
                "error": solve_result.error_message,
            })

    # Get the most recent scan from DB
    latest_scan = (
        await session.execute(
            select(Scan).order_by(Scan.id.desc()).limit(1)
        )
    ).scalar_one_or_none()

    return {
        "scan_id": latest_scan.id if latest_scan else None,
        "url": str(scan_request.url),
        "detections": [
            {
                "provider": r.provider,
                "confidence": r.confidence,
                "evidence": [{"description": e.description, "value": e.value} for e in r.evidence],
                "script_urls": r.script_urls,
                "cookies_found": r.cookies_found,
            }
            for r in results
        ],
        "solve_results": solve_results,
    }


@router.post("/api/fingerprint/collect")
async def api_collect_fingerprint(browser: str = "chromium"):
    """Collect a real browser fingerprint."""
    from antibot.fingerprint.collector import FingerprintCollector

    collector = FingerprintCollector()
    fp = await collector.collect_real_fingerprint(browser_type=browser)
    return {
        "id": fp.id,
        "source": fp.source,
        "user_agent": fp.user_agent,
        "platform": fp.platform,
        "screen": f"{fp.screen_width}x{fp.screen_height}",
    }


@router.post("/api/fingerprint/collect-bot")
async def api_collect_bot_fingerprint():
    """Collect a bot baseline fingerprint."""
    from antibot.fingerprint.collector import FingerprintCollector

    collector = FingerprintCollector()
    fp = await collector.collect_bot_fingerprint()
    return {
        "id": fp.id,
        "source": fp.source,
        "user_agent": fp.user_agent,
    }


@router.post("/api/fingerprint/compare")
async def api_compare_fingerprints(bot_id: int, real_id: int):
    """Compare two fingerprints."""
    from antibot.fingerprint.comparator import FingerprintComparator

    comparator = FingerprintComparator()
    report = await comparator.compare_by_ids(bot_id, real_id)
    return {
        "risk_score": report.risk_score,
        "total_fields": report.total_fields_compared,
        "matching_fields": report.matching_fields,
        "mismatches": [
            {
                "field": m.field,
                "bot_value": m.bot_value,
                "real_value": m.real_value,
                "severity": m.severity,
                "description": m.description,
            }
            for m in report.mismatches
        ],
    }


@router.get("/api/stats")
async def api_stats(session: AsyncSession = Depends(get_session)):
    """Get dashboard statistics."""
    total_scans = (await session.execute(select(func.count(Scan.id)))).scalar() or 0
    sites_tracked = (await session.execute(select(func.count(func.distinct(Scan.domain))))).scalar() or 0
    total_attempts = (await session.execute(select(func.count(SolveAttempt.id)))).scalar() or 0
    successful = (
        await session.execute(select(func.count(SolveAttempt.id)).where(SolveAttempt.success == True))
    ).scalar() or 0

    return {
        "total_scans": total_scans,
        "sites_tracked": sites_tracked,
        "bypass_rate": (successful / total_attempts * 100) if total_attempts > 0 else 0,
        "total_attempts": total_attempts,
        "successful_attempts": successful,
    }
