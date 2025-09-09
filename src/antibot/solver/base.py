"""Abstract base solver and result types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from antibot.detector.base import DetectionResult


@dataclass
class SolveResult:
    success: bool
    cookies: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0
    sensor_data: str | None = None
    error_message: str | None = None


class BaseSolver(ABC):
    """Abstract base class for anti-bot bypass solver modules."""

    name: str = "unknown"

    @abstractmethod
    async def solve(self, url: str, detection: DetectionResult) -> SolveResult:
        """Attempt to solve/bypass the detected anti-bot protection.

        Args:
            url: The target URL.
            detection: The detection result identifying the protection.

        Returns:
            SolveResult with success status and generated cookies.
        """
        ...
