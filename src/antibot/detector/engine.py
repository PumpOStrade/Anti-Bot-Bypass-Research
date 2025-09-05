"""Detection engine — orchestrates all detector modules."""

import asyncio
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

from antibot.detector.akamai import AkamaiDetector
from antibot.detector.base import DetectionResult
from antibot.detector.cloudflare import CloudflareDetector
from antibot.detector.custom import CustomDetector
from antibot.detector.datadome import DataDomeDetector
from antibot.detector.kasada import KasadaDetector
from antibot.detector.perimeterx import PerimeterXDetector
from antibot.detector.shape import ShapeDetector
from antibot.utils.http import fetch_page

logger = logging.getLogger(__name__)

ALL_DETECTORS = {
    "akamai": AkamaiDetector,
    "perimeterx": PerimeterXDetector,
    "datadome": DataDomeDetector,
    "kasada": KasadaDetector,
    "shape": ShapeDetector,
    "cloudflare": CloudflareDetector,
    "custom": CustomDetector,
}


class DetectionEngine:
    """Runs all (or selected) detectors against a target URL."""

    def __init__(self):
        self.detectors = {name: cls() for name, cls in ALL_DETECTORS.items()}

    async def scan(
        self,
        url: str,
        detectors: list[str] | None = None,
        save: bool = True,
        proxy: str | None = None,
    ) -> list[DetectionResult]:
        """Scan a URL for anti-bot protection.

        Args:
            url: Target URL to scan.
            detectors: List of detector names to run (None = all).
            save: Whether to persist results to the database.
            proxy: Optional proxy URL.
        """
        # Fetch the page
        try:
            response, page_source = await fetch_page(url, proxy=proxy)
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            raise

        # Select detectors
        active = self.detectors
        if detectors:
            active = {k: v for k, v in self.detectors.items() if k in detectors}

        # Run all detectors concurrently
        tasks = [
            detector.detect(url, response, page_source)
            for detector in active.values()
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful detections
        results: list[DetectionResult] = []
        for name, result in zip(active.keys(), raw_results):
            if isinstance(result, Exception):
                logger.warning(f"Detector {name} failed: {result}")
                continue
            if result is not None:
                results.append(result)

        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)

        # Persist to DB
        if save:
            await self._save_results(url, response, results)

        return results

    async def _save_results(self, url: str, response: object, results: list[DetectionResult]):
        """Save scan and detection results to the database."""
        from antibot.database import async_session
        from antibot.models import Detection, Scan

        domain = urlparse(url).netloc

        # Extract headers and cookies from response
        headers_dict = dict(getattr(response, "headers", {}))
        cookies_dict = {}
        if hasattr(response, "cookies"):
            for name in response.cookies:
                cookies_dict[name] = str(response.cookies[name])

        scan = Scan(
            url=url,
            domain=domain,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            status="completed",
            raw_headers=json.dumps(headers_dict),
            raw_cookies=json.dumps(cookies_dict),
        )

        async with async_session() as session:
            session.add(scan)
            await session.flush()

            for result in results:
                detection = Detection(
                    scan_id=scan.id,
                    provider=result.provider,
                    confidence=result.confidence,
                    evidence=json.dumps([{"description": e.description, "value": e.value} for e in result.evidence]),
                    script_urls=json.dumps(result.script_urls),
                    cookies_found=json.dumps(result.cookies_found),
                )
                session.add(detection)

            await session.commit()
