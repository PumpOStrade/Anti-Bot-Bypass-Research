"""Solver engine — orchestrates bypass attempts."""

import json
import logging
import time
from datetime import datetime

from antibot.detector.base import DetectionResult
from antibot.solver.akamai import AkamaiSolver
from antibot.solver.base import BaseSolver, SolveResult
from antibot.solver.cloudflare import CloudflareSolver
from antibot.solver.custom import CustomSolver
from antibot.solver.datadome import DataDomeSolver
from antibot.solver.kasada import KasadaSolver
from antibot.solver.perimeterx import PerimeterXSolver
from antibot.solver.shape import ShapeSolver

logger = logging.getLogger(__name__)

SOLVERS: dict[str, type[BaseSolver]] = {
    "akamai": AkamaiSolver,
    "perimeterx": PerimeterXSolver,
    "datadome": DataDomeSolver,
    "kasada": KasadaSolver,
    "shape": ShapeSolver,
    "cloudflare": CloudflareSolver,
    "custom": CustomSolver,
}


class SolverEngine:
    """Orchestrates bypass attempts for detected protections."""

    def __init__(self):
        self.solvers = {name: cls() for name, cls in SOLVERS.items()}

    async def solve(self, url: str, detection: DetectionResult, use_browser: bool = True) -> SolveResult:
        """Attempt to bypass the detected protection.

        Args:
            url: The target URL.
            detection: Detection result identifying the protection.
            use_browser: If True, try Playwright-based solving first.

        Returns:
            SolveResult with success status and generated cookies.
        """
        # Match solver by provider name (handle "custom (X)" -> "custom")
        provider_key = detection.provider.split(" (")[0] if " (" in detection.provider else detection.provider
        solver = self.solvers.get(provider_key)
        if not solver:
            return SolveResult(
                success=False,
                error_message=f"No solver available for provider: {detection.provider}",
            )

        start_time = time.time()
        try:
            result = await solver.solve(url, detection, use_browser=use_browser)
            result.duration_ms = int((time.time() - start_time) * 1000)
        except Exception as e:
            logger.error(f"Solver {detection.provider} failed: {e}")
            result = SolveResult(
                success=False,
                duration_ms=int((time.time() - start_time) * 1000),
                error_message=str(e),
            )

        # Persist the attempt
        await self._save_attempt(detection, result)

        return result

    async def _save_attempt(self, detection: DetectionResult, result: SolveResult):
        """Save solve attempt to the database."""
        from antibot.database import async_session
        from antibot.models import SolveAttempt

        # Find the detection ID from the DB
        # The detection might not be saved yet if running from CLI without save
        try:
            cookie_name = next(iter(result.cookies), None) if result.cookies else None
            cookie_value = result.cookies.get(cookie_name) if cookie_name else None

            attempt = SolveAttempt(
                detection_id=getattr(detection, "db_id", 1),
                attempted_at=datetime.utcnow(),
                success=result.success,
                duration_ms=result.duration_ms,
                cookie_name=cookie_name,
                cookie_value=cookie_value,
                sensor_data=result.sensor_data,
                error_message=result.error_message,
            )

            async with async_session() as session:
                session.add(attempt)
                await session.commit()
        except Exception as e:
            logger.warning(f"Failed to save solve attempt: {e}")
