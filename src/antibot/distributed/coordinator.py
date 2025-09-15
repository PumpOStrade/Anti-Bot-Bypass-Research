"""Batch scan coordinator — queue and run multiple URL scans concurrently."""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ScanOptions:
    bypass: bool = False
    use_browser: bool = True
    detectors: list[str] | None = None
    proxy: str | None = None
    proxy_file: str | None = None


@dataclass
class ScanResult:
    url: str
    status: str  # "completed", "failed", "skipped"
    detections: list[dict] = field(default_factory=list)
    bypass_results: list[dict] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0


@dataclass
class BatchJob:
    id: str
    urls: list[str]
    options: ScanOptions
    status: str = "pending"  # "pending", "running", "completed"
    created_at: str = ""
    results: list[ScanResult] = field(default_factory=list)
    completed: int = 0
    failed: int = 0
    total: int = 0


class ScanCoordinator:
    """Coordinate batch scanning with configurable concurrency."""

    def __init__(self):
        self.jobs: dict[str, BatchJob] = {}

    async def submit_batch(
        self,
        urls: list[str],
        options: ScanOptions | None = None,
        concurrency: int = 5,
    ) -> BatchJob:
        """Submit a batch of URLs for scanning."""
        opts = options or ScanOptions()
        job = BatchJob(
            id=str(uuid.uuid4())[:8],
            urls=urls,
            options=opts,
            status="running",
            created_at=datetime.utcnow().isoformat(),
            total=len(urls),
        )
        self.jobs[job.id] = job

        # Setup proxy rotation if proxy file provided
        proxy_manager = None
        if opts.proxy_file:
            from antibot.utils.proxy import ProxyManager
            proxy_manager = ProxyManager(proxy_file=opts.proxy_file)

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(concurrency)

        async def scan_url(url: str) -> ScanResult:
            async with semaphore:
                proxy = opts.proxy
                if proxy_manager:
                    proxy = proxy_manager.get_next()

                return await self._scan_single(url, opts, proxy)

        # Run all scans concurrently (limited by semaphore)
        logger.info(f"[Batch {job.id}] Starting {len(urls)} scans (concurrency: {concurrency})")
        tasks = [scan_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                scan_result = ScanResult(url=urls[i], status="failed", error=str(result))
                job.failed += 1
            else:
                scan_result = result
                if scan_result.status == "completed":
                    job.completed += 1
                else:
                    job.failed += 1
            job.results.append(scan_result)

        job.status = "completed"
        logger.info(f"[Batch {job.id}] Done: {job.completed}/{job.total} succeeded, {job.failed} failed")

        # Fire webhook if configured
        try:
            from antibot.alerts.webhook import WebhookManager
            wm = WebhookManager()
            await wm.fire("batch.completed", {
                "batch_id": job.id,
                "total": job.total,
                "completed": job.completed,
                "failed": job.failed,
            })
        except Exception:
            pass

        return job

    async def _scan_single(self, url: str, options: ScanOptions, proxy: str | None) -> ScanResult:
        """Scan a single URL."""
        from antibot.database import init_db
        from antibot.detector.engine import DetectionEngine

        await init_db()

        start = time.time()
        try:
            engine = DetectionEngine()
            detections = await engine.scan(url, detectors=options.detectors, proxy=proxy)

            result = ScanResult(
                url=url,
                status="completed",
                detections=[
                    {"provider": d.provider, "confidence": d.confidence}
                    for d in detections
                ],
            )

            if options.bypass and detections:
                from antibot.solver.engine import SolverEngine

                solver = SolverEngine()
                for detection in detections:
                    solve_result = await solver.solve(url, detection, use_browser=options.use_browser)
                    result.bypass_results.append({
                        "provider": detection.provider,
                        "success": solve_result.success,
                        "duration_ms": solve_result.duration_ms,
                    })
                    if solve_result.success and solve_result.cookies:
                        result.cookies = solve_result.cookies
                        break

            result.duration_ms = int((time.time() - start) * 1000)
            return result

        except Exception as e:
            return ScanResult(
                url=url, status="failed", error=str(e),
                duration_ms=int((time.time() - start) * 1000),
            )

    def get_status(self, batch_id: str) -> BatchJob | None:
        return self.jobs.get(batch_id)

    def save_results(self, batch_id: str, output_path: str):
        """Save batch results to JSON file."""
        job = self.jobs.get(batch_id)
        if not job:
            return

        data = {
            "batch_id": job.id,
            "status": job.status,
            "total": job.total,
            "completed": job.completed,
            "failed": job.failed,
            "results": [
                {
                    "url": r.url, "status": r.status,
                    "detections": r.detections,
                    "bypass_results": r.bypass_results,
                    "cookie_count": len(r.cookies),
                    "error": r.error,
                    "duration_ms": r.duration_ms,
                }
                for r in job.results
            ],
        }

        Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info(f"[Batch {batch_id}] Results saved to {output_path}")
