"""Tests for the fingerprint comparator."""

import pytest

from antibot.fingerprint.comparator import FingerprintComparator


@pytest.fixture
def comparator():
    return FingerprintComparator()


def test_identical_fingerprints(comparator):
    """Identical fingerprints should have risk_score near 0."""
    fp = {
        "userAgent": "Mozilla/5.0 Chrome/131.0",
        "platform": "Win32",
        "screenWidth": 1920,
        "screenHeight": 1080,
        "timezone": "America/New_York",
        "languages": ["en-US"],
        "hardwareConcurrency": 16,
        "deviceMemory": 8,
        "canvasHash": "abc123",
        "webglVendor": "Google Inc.",
        "webglRenderer": "ANGLE (NVIDIA)",
        "webglHash": "hash123",
        "plugins": ["PDF Viewer"],
        "automationIndicators": {
            "navigator.webdriver": False,
            "navigator.plugins.length > 0": True,
            "navigator.languages.length > 0": True,
        },
    }

    report = comparator.compare(fp, fp)
    assert report.risk_score == 0.0
    assert len(report.mismatches) == 0


def test_bot_vs_real_fingerprint(comparator):
    """Bot fingerprint should have high risk score vs real browser."""
    bot_fp = {
        "userAgent": "python-requests/2.31.0",
        "platform": None,
        "screenWidth": None,
        "screenHeight": None,
        "timezone": None,
        "languages": None,
        "hardwareConcurrency": None,
        "deviceMemory": None,
        "canvasHash": None,
        "webglVendor": None,
        "webglRenderer": None,
        "webglHash": None,
        "plugins": None,
        "automationIndicators": {},
    }

    real_fp = {
        "userAgent": "Mozilla/5.0 Chrome/131.0",
        "platform": "Win32",
        "screenWidth": 1920,
        "screenHeight": 1080,
        "timezone": "America/New_York",
        "languages": ["en-US"],
        "hardwareConcurrency": 16,
        "deviceMemory": 8,
        "canvasHash": "abc123",
        "webglVendor": "Google Inc.",
        "webglRenderer": "ANGLE (NVIDIA)",
        "webglHash": "hash123",
        "plugins": ["PDF Viewer"],
        "automationIndicators": {
            "navigator.webdriver": False,
            "navigator.plugins.length > 0": True,
            "navigator.languages.length > 0": True,
        },
    }

    report = comparator.compare(bot_fp, real_fp)
    assert report.risk_score > 0.5
    assert len(report.mismatches) > 5


def test_webdriver_flag_critical(comparator):
    """navigator.webdriver = true should be a critical mismatch."""
    bot_fp = {
        "automationIndicators": {"navigator.webdriver": True},
    }
    real_fp = {
        "automationIndicators": {"navigator.webdriver": False},
    }

    report = comparator.compare(bot_fp, real_fp)
    critical = [m for m in report.mismatches if m.severity == "critical"]
    assert len(critical) > 0


def test_minor_differences_low_risk(comparator):
    """Small differences should produce low risk score."""
    fp1 = {
        "userAgent": "Mozilla/5.0 Chrome/131.0",
        "platform": "Win32",
        "screenWidth": 1920,
        "screenHeight": 1080,
        "timezone": "America/New_York",
        "hardwareConcurrency": 16,
        "canvasHash": "abc123",
        "webglVendor": "Google Inc.",
        "webglRenderer": "ANGLE (NVIDIA)",
    }

    fp2 = fp1.copy()
    fp2["hardwareConcurrency"] = 8  # Minor diff

    report = comparator.compare(fp1, fp2)
    assert report.risk_score < 0.3
