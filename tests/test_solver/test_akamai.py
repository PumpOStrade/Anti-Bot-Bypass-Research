"""Tests for the Akamai solver."""

import pytest

from antibot.solver.akamai import AkamaiSolver


@pytest.fixture
def solver():
    return AkamaiSolver()


def test_is_valid_cookie_valid(solver):
    """Valid _abck cookies contain ~0~."""
    assert solver._is_valid_cookie("abc123~0~xyz~valid") is True
    assert solver._is_valid_cookie("longvalue~0~moredata~0~end") is True


def test_is_valid_cookie_invalid(solver):
    """Invalid _abck cookies contain ~-1~ or other values."""
    assert solver._is_valid_cookie("abc123~-1~xyz~invalid") is False
    assert solver._is_valid_cookie("abc123~1~xyz") is False
    assert solver._is_valid_cookie("abc123~2~xyz") is False
    assert solver._is_valid_cookie("") is False
    assert solver._is_valid_cookie("no_tildes_here") is False


def test_build_sensor_data(solver):
    """Sensor data should be pipe-delimited with expected fields."""
    config = {"version": "2.0", "dynamic_key": "abc123", "post_url": "https://example.com"}
    sensor_data = solver._build_sensor_data(config, iteration=0)

    assert "|" in sensor_data
    fields = sensor_data.split("|")
    assert len(fields) > 20  # Should have many fields

    # Should contain user agent
    assert "Mozilla" in sensor_data
    # Should contain platform
    assert "Win32" in sensor_data
    # Automation flags should be clean (all 0)
    assert "Chrome" in sensor_data


def test_find_script_url_from_detection(solver):
    """Should use script URLs from detection result."""
    from antibot.detector.base import DetectionResult

    detection = DetectionResult(
        provider="akamai",
        confidence=0.9,
        script_urls=["/abcdef0123456789abcdef01/script.js"],
    )

    url = solver._find_script_url("<html></html>", detection)
    assert url == "/abcdef0123456789abcdef01/script.js"


def test_find_script_url_from_page(solver):
    """Should find script URL from page source when not in detection."""
    from antibot.detector.base import DetectionResult

    detection = DetectionResult(provider="akamai", confidence=0.9)

    page = '<html><script src="/abcdef0123456789abcdef01/abcdef0123.js"></script></html>'
    url = solver._find_script_url(page, detection)
    assert url is not None
    assert "abcdef" in url
