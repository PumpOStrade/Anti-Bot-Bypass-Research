"""Tests for the Cloudflare detector."""

from unittest.mock import MagicMock

import pytest

from antibot.detector.cloudflare import CloudflareDetector


@pytest.fixture
def detector():
    return CloudflareDetector()


def make_response(cookies=None, headers=None, status_code=200):
    resp = MagicMock()
    resp.cookies = cookies or {}
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


@pytest.mark.asyncio
async def test_detects_cf_server_and_ray(detector):
    """Should detect Cloudflare by server header and cf-ray."""
    response = make_response(
        headers={"server": "cloudflare", "cf-ray": "abc123-IAD"},
        cookies={"__cf_bm": "abc123"},
    )
    result = await detector.detect("https://example.com", response, "<html></html>")

    assert result is not None
    assert result.provider == "cloudflare"
    assert result.confidence >= 0.5
    assert "__cf_bm" in result.cookies_found


@pytest.mark.asyncio
async def test_detects_challenge_page(detector):
    """Should detect Cloudflare challenge page."""
    response = make_response(
        status_code=403,
        headers={"server": "cloudflare", "cf-ray": "xyz"},
    )
    page = '''<html><head><title>Just a moment...</title></head>
    <body>
    <div id="cf-browser-verification">Checking if the site connection is secure</div>
    <script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>
    </body></html>'''

    result = await detector.detect("https://example.com", response, page)
    assert result is not None
    assert result.confidence >= 0.7


@pytest.mark.asyncio
async def test_detects_turnstile(detector):
    """Should detect Cloudflare Turnstile CAPTCHA."""
    response = make_response(
        headers={"server": "cloudflare", "cf-ray": "abc"},
    )
    page = '''<html><body>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
    <div class="cf-turnstile"></div>
    </body></html>'''

    result = await detector.detect("https://example.com", response, page)
    assert result is not None
    assert any("Turnstile" in e.description for e in result.evidence)


@pytest.mark.asyncio
async def test_detects_cf_clearance(detector):
    """Should detect cf_clearance cookie (passed challenge)."""
    response = make_response(
        cookies={"cf_clearance": "long_clearance_value_here"},
        headers={"server": "cloudflare", "cf-ray": "abc"},
    )
    result = await detector.detect("https://example.com", response, "<html></html>")
    assert result is not None
    assert "cf_clearance" in result.cookies_found


@pytest.mark.asyncio
async def test_detects_cf_mitigated(detector):
    """Should detect active Cloudflare challenge via cf-mitigated header."""
    response = make_response(
        headers={"server": "cloudflare", "cf-ray": "abc", "cf-mitigated": "challenge"},
    )
    result = await detector.detect("https://example.com", response, "<html></html>")
    assert result is not None
    assert any("Active" in e.description for e in result.evidence)


@pytest.mark.asyncio
async def test_no_detection_clean_page(detector):
    """Should not detect Cloudflare on a clean page."""
    response = make_response(headers={"server": "nginx"})
    result = await detector.detect("https://example.com", response, "<html>Normal</html>")
    assert result is None
