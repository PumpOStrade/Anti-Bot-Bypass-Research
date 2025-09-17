"""Tests for the PerimeterX detector."""

from unittest.mock import MagicMock

import pytest

from antibot.detector.perimeterx import PerimeterXDetector


@pytest.fixture
def detector():
    return PerimeterXDetector()


def make_response(cookies=None, headers=None, status_code=200):
    resp = MagicMock()
    resp.cookies = cookies or {}
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


@pytest.mark.asyncio
async def test_detects_px_cookies(detector):
    response = make_response(cookies={"_px3": "abc", "_pxvid": "xyz"})
    result = await detector.detect("https://example.com", response, "<html></html>")

    assert result is not None
    assert result.provider == "perimeterx"
    assert "_px3" in result.cookies_found


@pytest.mark.asyncio
async def test_detects_px_app_id(detector):
    response = make_response(cookies={"_px3": "abc"})
    page = '<html><script>window._pxAppId = "PXa1b2c3d4";</script></html>'
    result = await detector.detect("https://example.com", response, page)

    assert result is not None
    assert result.confidence >= 0.5


@pytest.mark.asyncio
async def test_detects_block_page(detector):
    response = make_response(status_code=403)
    page = '<html><div id="px-captcha">Please verify you are human</div></html>'
    result = await detector.detect("https://example.com", response, page)

    assert result is not None


@pytest.mark.asyncio
async def test_no_detection_clean_page(detector):
    response = make_response()
    result = await detector.detect("https://example.com", response, "<html>Clean</html>")
    assert result is None
