"""Pydantic request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, HttpUrl


# --- Scan ---
class ScanRequest(BaseModel):
    url: HttpUrl
    detectors: list[str] | None = None  # None = all
    attempt_bypass: bool = False


class EvidenceItem(BaseModel):
    description: str
    value: str | None = None


class DetectionResponse(BaseModel):
    provider: str
    confidence: float
    evidence: list[EvidenceItem]
    script_urls: list[str]
    cookies_found: list[str]

    model_config = {"from_attributes": True}


class SolveAttemptResponse(BaseModel):
    id: int
    success: bool
    duration_ms: int
    cookie_name: str | None
    cookie_value: str | None
    error_message: str | None
    attempted_at: datetime

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: int
    url: str
    domain: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    detections: list[DetectionResponse]

    model_config = {"from_attributes": True}


# --- Fingerprint ---
class FingerprintResponse(BaseModel):
    id: int
    source: str
    collected_at: datetime
    user_agent: str | None
    ja3_hash: str | None
    platform: str | None
    screen_width: int | None
    screen_height: int | None
    timezone: str | None
    canvas_hash: str | None
    webgl_vendor: str | None
    webgl_renderer: str | None
    hardware_concurrency: int | None
    device_memory: float | None

    model_config = {"from_attributes": True}


class MismatchItem(BaseModel):
    field: str
    bot_value: str | None
    real_value: str | None
    severity: str  # "low", "medium", "high", "critical"


class ComparisonResponse(BaseModel):
    id: int
    risk_score: float
    mismatches: list[MismatchItem]
    compared_at: datetime

    model_config = {"from_attributes": True}


# --- Dashboard Stats ---
class DashboardStats(BaseModel):
    total_scans: int
    sites_tracked: int
    overall_bypass_rate: float
    active_protections: int
    protection_distribution: dict[str, int]
    recent_scans: list[ScanResponse]
