"""SQLAlchemy ORM models."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from antibot.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    raw_headers: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    raw_cookies: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    detections: Mapped[list["Detection"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    script_urls: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    cookies_found: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array

    scan: Mapped["Scan"] = relationship(back_populates="detections")
    solve_attempts: Mapped[list["SolveAttempt"]] = relationship(back_populates="detection", cascade="all, delete-orphan")


class SolveAttempt(Base):
    __tablename__ = "solve_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    detection_id: Mapped[int] = mapped_column(Integer, ForeignKey("detections.id"), nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    cookie_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cookie_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    sensor_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    detection: Mapped["Detection"] = relationship(back_populates="solve_attempts")


class Fingerprint(Base):
    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ja3_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ja4_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    screen_width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    screen_height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(100), nullable=True)
    languages: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    plugins_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    canvas_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    webgl_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    webgl_vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    webgl_renderer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(50), nullable=True)
    hardware_concurrency: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_memory: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)  # Full JSON blob

    bot_comparisons: Mapped[list["ComparisonResult"]] = relationship(
        back_populates="bot_fp", foreign_keys="ComparisonResult.bot_fp_id"
    )
    real_comparisons: Mapped[list["ComparisonResult"]] = relationship(
        back_populates="real_fp", foreign_keys="ComparisonResult.real_fp_id"
    )


class ComparisonResult(Base):
    __tablename__ = "comparison_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    bot_fp_id: Mapped[int] = mapped_column(Integer, ForeignKey("fingerprints.id"), nullable=False)
    real_fp_id: Mapped[int] = mapped_column(Integer, ForeignKey("fingerprints.id"), nullable=False)
    compared_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    mismatches: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array

    bot_fp: Mapped["Fingerprint"] = relationship(back_populates="bot_comparisons", foreign_keys=[bot_fp_id])
    real_fp: Mapped["Fingerprint"] = relationship(back_populates="real_comparisons", foreign_keys=[real_fp_id])


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    cookies: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    proxy_used: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")


class Recording(Base):
    __tablename__ = "recordings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[str] = mapped_column(Text, nullable=False)  # Full JSON recording
    status: Mapped[str] = mapped_column(String(20), default="completed")


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    events: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
