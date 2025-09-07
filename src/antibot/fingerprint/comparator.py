"""Fingerprint comparison engine.

Compares a bot fingerprint against a real browser fingerprint,
identifies mismatches, and scores the detection risk.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Mismatch:
    field: str
    bot_value: str | None
    real_value: str | None
    severity: str  # "low", "medium", "high", "critical"
    description: str = ""


@dataclass
class ComparisonReport:
    risk_score: float  # 0.0 (identical) to 1.0 (obvious bot)
    mismatches: list[Mismatch] = field(default_factory=list)
    total_fields_compared: int = 0
    matching_fields: int = 0


# Field definitions with severity weights
COMPARISON_FIELDS = [
    # (field_name, raw_data_key, severity, weight, description)
    ("user_agent", "userAgent", "high", 0.15, "User-Agent string mismatch"),
    ("platform", "platform", "high", 0.10, "Navigator platform mismatch"),
    ("screen_width", "screenWidth", "medium", 0.05, "Screen width mismatch"),
    ("screen_height", "screenHeight", "medium", 0.05, "Screen height mismatch"),
    ("timezone", "timezone", "medium", 0.05, "Timezone mismatch"),
    ("languages", "languages", "medium", 0.05, "Browser languages mismatch"),
    ("hardware_concurrency", "hardwareConcurrency", "low", 0.03, "CPU core count mismatch"),
    ("device_memory", "deviceMemory", "low", 0.03, "Device memory mismatch"),
    ("canvas_hash", "canvasHash", "high", 0.12, "Canvas fingerprint mismatch"),
    ("webgl_vendor", "webglVendor", "high", 0.10, "WebGL vendor mismatch"),
    ("webgl_renderer", "webglRenderer", "high", 0.10, "WebGL renderer mismatch"),
    ("webgl_hash", "webglHash", "medium", 0.07, "WebGL extensions hash mismatch"),
    ("plugins_hash", "plugins", "medium", 0.05, "Plugin list mismatch"),
]

# Critical checks that heavily indicate bot behavior
CRITICAL_CHECKS = [
    ("webdriver_flag", "navigator.webdriver", "critical", 0.20, "navigator.webdriver is true (automation detected)"),
    ("no_plugins", "navigator.plugins.length > 0", "high", 0.10, "No browser plugins (headless indicator)"),
    ("no_languages", "navigator.languages.length > 0", "high", 0.08, "No browser languages set"),
    ("missing_screen", None, "high", 0.10, "Screen properties missing entirely"),
    ("missing_webgl", None, "critical", 0.15, "WebGL properties missing entirely"),
]


class FingerprintComparator:
    """Compare bot fingerprints against real browser baselines."""

    async def compare_by_ids(self, bot_fp_id: int, real_fp_id: int) -> ComparisonReport:
        """Compare two fingerprints by their database IDs."""
        from antibot.database import async_session
        from antibot.models import ComparisonResult, Fingerprint

        async with async_session() as session:
            from sqlalchemy import select

            bot_fp = (await session.execute(select(Fingerprint).where(Fingerprint.id == bot_fp_id))).scalar_one()
            real_fp = (await session.execute(select(Fingerprint).where(Fingerprint.id == real_fp_id))).scalar_one()

            bot_data = json.loads(bot_fp.raw_data) if bot_fp.raw_data else {}
            real_data = json.loads(real_fp.raw_data) if real_fp.raw_data else {}

            report = self.compare(bot_data, real_data)

            # Save comparison result
            result = ComparisonResult(
                bot_fp_id=bot_fp_id,
                real_fp_id=real_fp_id,
                compared_at=datetime.utcnow(),
                risk_score=report.risk_score,
                mismatches=json.dumps([
                    {
                        "field": m.field,
                        "bot_value": m.bot_value,
                        "real_value": m.real_value,
                        "severity": m.severity,
                    }
                    for m in report.mismatches
                ]),
            )
            session.add(result)
            await session.commit()

        return report

    def compare(self, bot_data: dict, real_data: dict) -> ComparisonReport:
        """Compare two fingerprint data dicts field by field."""
        mismatches: list[Mismatch] = []
        total_weight = 0.0
        mismatch_weight = 0.0
        total_fields = 0
        matching = 0

        # Standard field comparisons
        for field_name, data_key, severity, weight, description in COMPARISON_FIELDS:
            bot_val = bot_data.get(data_key)
            real_val = real_data.get(data_key)
            total_weight += weight
            total_fields += 1

            # Normalize for comparison
            bot_str = self._normalize(bot_val)
            real_str = self._normalize(real_val)

            if bot_str != real_str:
                mismatch_weight += weight
                mismatches.append(Mismatch(
                    field=field_name,
                    bot_value=bot_str,
                    real_value=real_str,
                    severity=severity,
                    description=description,
                ))
            else:
                matching += 1

        # Critical automation checks
        bot_indicators = bot_data.get("automationIndicators", {})
        real_indicators = real_data.get("automationIndicators", {})

        for check_name, indicator_key, severity, weight, description in CRITICAL_CHECKS:
            total_weight += weight

            if indicator_key:
                bot_val = bot_indicators.get(indicator_key)
                real_val = real_indicators.get(indicator_key)
                total_fields += 1

                if check_name == "webdriver_flag" and bot_val is True:
                    mismatch_weight += weight
                    mismatches.append(Mismatch(
                        field=check_name,
                        bot_value=str(bot_val),
                        real_value=str(real_val),
                        severity=severity,
                        description=description,
                    ))
                elif check_name == "no_plugins" and bot_val is False:
                    mismatch_weight += weight
                    mismatches.append(Mismatch(
                        field=check_name,
                        bot_value="no plugins",
                        real_value="has plugins",
                        severity=severity,
                        description=description,
                    ))
                elif check_name == "no_languages" and bot_val is False:
                    mismatch_weight += weight
                    mismatches.append(Mismatch(
                        field=check_name,
                        bot_value="no languages",
                        real_value="has languages",
                        severity=severity,
                        description=description,
                    ))
                else:
                    matching += 1
            else:
                # Check for missing critical fields
                total_fields += 1
                if check_name == "missing_screen":
                    if bot_data.get("screenWidth") is None and real_data.get("screenWidth") is not None:
                        mismatch_weight += weight
                        mismatches.append(Mismatch(
                            field=check_name,
                            bot_value="missing",
                            real_value="present",
                            severity=severity,
                            description=description,
                        ))
                    else:
                        matching += 1
                elif check_name == "missing_webgl":
                    if bot_data.get("webglVendor") is None and real_data.get("webglVendor") is not None:
                        mismatch_weight += weight
                        mismatches.append(Mismatch(
                            field=check_name,
                            bot_value="missing",
                            real_value="present",
                            severity=severity,
                            description=description,
                        ))
                    else:
                        matching += 1

        # Calculate risk score
        risk_score = min(mismatch_weight / total_weight, 1.0) if total_weight > 0 else 0.0

        return ComparisonReport(
            risk_score=risk_score,
            mismatches=mismatches,
            total_fields_compared=total_fields,
            matching_fields=matching,
        )

    @staticmethod
    def _normalize(value) -> str:
        """Normalize a value for comparison."""
        if value is None:
            return "null"
        if isinstance(value, list):
            return json.dumps(sorted(str(v) for v in value))
        if isinstance(value, bool):
            return str(value).lower()
        return str(value)
