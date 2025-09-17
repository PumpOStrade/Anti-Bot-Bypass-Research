"""Tests for the DataDome detector."""

from unittest.mock import MagicMock

import pytest

from antibot.detector.datadome import DataDomeDetector


@pytest.fixture
def detector():
    return DataDomeDetector()


def make_response(cookies=None, headers=None, status_code=200):
    resp = MagicMock()
    resp.cookies = cookies or {}
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


@pytest.mark.asyncio
async def test_detects_datadome_cookie(detector):
    response = make_response(cookies={"datadome": "abc123xyz456"})
    result = await detector.detect("https://example.com", response, "<html></html>")

    assert result is not None
    assert result.provider == "datadome"
    assert "datadome" in result.cookies_found


@pytest.mark.asyncio
async def test_detects_datadome_headers(detector):
    response = make_response(headers={"X-DataDome-CID": "abc123"})
    result = await detector.detect("https://example.com", response, "<html></html>")

    assert result is not None
    assert result.provider == "datadome"
    assert result.confidence >= 0.3


@pytest.mark.asyncio
async def test_detects_datadome_script(detector):
    response = make_response(cookies={"datadome": "val"})
    page = '<html><script src="https://js.datadome.co/tags.js"></script></html>'
    result = await detector.detect("https://example.com", response, page)

    assert result is not None
    assert len(result.script_urls) > 0


@pytest.mark.asyncio
async def test_no_detection_clean_page(detector):
    response = make_response()
    result = await detector.detect("https://example.com", response, "<html>Clean</html>")
    assert result is None
