"""Tests for the Akamai detector."""

from unittest.mock import MagicMock

import pytest

from antibot.detector.akamai import AkamaiDetector


@pytest.fixture
def detector():
    return AkamaiDetector()


def make_response(cookies=None, headers=None, status_code=200):
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.cookies = cookies or {}
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


@pytest.mark.asyncio
async def test_detects_abck_cookie(detector):
    """Should detect Akamai when _abck cookie is present."""
    response = make_response(cookies={"_abck": "abc123~-1~xyz~-1~", "bm_sz": "abc123"})
    page_source = "<html><body>Hello</body></html>"

    result = await detector.detect("https://example.com", response, page_source)

    assert result is not None
    assert result.provider == "akamai"
    assert result.confidence >= 0.5
    assert "_abck" in result.cookies_found
    assert "bm_sz" in result.cookies_found


@pytest.mark.asyncio
async def test_detects_hex_path_script(detector):
    """Should detect Akamai sensor script with hex path."""
    response = make_response()
    page_source = '''
    <html>
    <script src="/abcdef0123456789abcdef01/abcdef0123.js"></script>
    <body>Hello</body>
    </html>
    '''

    # Hex path alone is not enough (score < 0.4 threshold)
    # Add a cookie to boost score
    response.cookies = {"_abck": "test~-1~val~-1~"}
    result = await detector.detect("https://example.com", response, page_source)

    assert result is not None
    assert result.provider == "akamai"
    assert len(result.script_urls) > 0


@pytest.mark.asyncio
async def test_detects_bmak_in_source(detector):
    """Should detect Akamai signature strings in page source."""
    response = make_response(cookies={"_abck": "val~-1~xxx~-1~", "bm_sz": "val"})
    page_source = "<html><script>var bmak = {}; bmak.sensor_data = '';</script></html>"

    result = await detector.detect("https://example.com", response, page_source)

    assert result is not None
    assert result.confidence >= 0.6


@pytest.mark.asyncio
async def test_no_detection_for_clean_page(detector):
    """Should not detect Akamai on a clean page."""
    response = make_response()
    page_source = "<html><body>Just a normal page</body></html>"

    result = await detector.detect("https://example.com", response, page_source)
    assert result is None


@pytest.mark.asyncio
async def test_cloudflare_negative_signal(detector):
    """Cloudflare indicators should reduce Akamai confidence."""
    response = make_response(cookies={"_abck": "test~-1~val"})
    page_source = "<html><script>var _cf_chl_opt = {};</script></html>"

    result = await detector.detect("https://example.com", response, page_source)
    # Score should be reduced by Cloudflare negative signal
    if result:
        assert result.confidence < 0.5


@pytest.mark.asyncio
async def test_valid_abck_cookie_detected(detector):
    """Should note when _abck cookie is in valid state."""
    response = make_response(cookies={"_abck": "abc123~0~xyz~valid", "bm_sz": "data"})
    page_source = "<html></html>"

    result = await detector.detect("https://example.com", response, page_source)
    assert result is not None

    evidence_descs = [e.description for e in result.evidence]
    assert any("VALID" in d for d in evidence_descs)
