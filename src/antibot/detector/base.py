"""Abstract base detector and result types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Evidence:
    description: str
    value: str | None = None


@dataclass
class DetectionResult:
    provider: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    script_urls: list[str] = field(default_factory=list)
    cookies_found: list[str] = field(default_factory=list)


class BaseDetector(ABC):
    """Abstract base class for anti-bot detection modules."""

    name: str = "unknown"

    @abstractmethod
    async def detect(
        self,
        url: str,
        response: object,
        page_source: str,
    ) -> DetectionResult | None:
        """Analyze a response to detect this provider's protection.

        Returns a DetectionResult if the provider is detected, None otherwise.
        """
        ...
