"""Tests for the custom/in-house detector."""

from unittest.mock import MagicMock

import pytest

from antibot.detector.custom import CustomDetector


@pytest.fixture
def detector():
    return CustomDetector()


def make_response(cookies=None, headers=None, status_code=200):
    resp = MagicMock()
    resp.cookies = cookies or {}
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


@pytest.mark.asyncio
async def test_detects_twitter(detector):
    """Should detect X/Twitter by ct0 cookie and twimg scripts."""
    response = make_response(
        cookies={"ct0": "abc123", "gt": "guest_token_value"},
        headers={"x-transaction-id": "abc", "x-connection-hash": "def"},
    )
    page = '<html><script src="https://abs.twimg.com/responsive-web/client-web/main.js"></script><div id="react-root"></div></html>'

    result = await detector.detect("https://x.com/", response, page)
    assert result is not None
    assert "X (Twitter)" in result.provider
    assert result.confidence >= 0.3
    assert "ct0" in result.cookies_found


@pytest.mark.asyncio
async def test_detects_instagram(detector):
    """Should detect Instagram by csrftoken and script domains."""
    response = make_response(
        cookies={"csrftoken": "abc", "ig_did": "xyz", "mid": "123"},
        headers={"x-ig-app-id": "936619743392459"},
    )
    page = '<html><script src="https://static.cdninstagram.com/bundle.js"></script></html>'

    result = await detector.detect("https://www.instagram.com/", response, page)
    assert result is not None
    assert "Instagram" in result.provider


@pytest.mark.asyncio
async def test_detects_rate_limiting(detector):
    """Should detect rate limiting headers."""
    response = make_response(
        headers={
            "x-rate-limit-limit": "100",
            "x-rate-limit-remaining": "95",
            "x-rate-limit-reset": "1234567890",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        },
    )
    page = '<html><div id="root"></div><noscript>You need to enable JavaScript to run this app.</noscript></html>'

    result = await detector.detect("https://api.example.com", response, page)
    assert result is not None
    assert result.provider.startswith("custom")


@pytest.mark.asyncio
async def test_detects_spa_shell(detector):
    """Should detect SPA shell pages with JS fingerprinting."""
    response = make_response(
        cookies={"csrf_token": "abc123"},
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        },
    )
    page = '''<html><head>
    <script>var fingerprint = getBrowserFingerprint(); var deviceId = computeDeviceId();</script>
    </head><body><div id="root"></div>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <script src="/static/js/main.chunk.js"></script>
    </body></html>'''

    result = await detector.detect("https://app.example.com", response, page)
    assert result is not None
    assert any("fingerprint" in e.description.lower() or "SPA" in e.description for e in result.evidence)


@pytest.mark.asyncio
async def test_detects_auth_gated(detector):
    """Should detect auth-gated responses."""
    response = make_response(
        status_code=403,
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        },
    )
    page = '<html><body>Forbidden</body></html>'

    result = await detector.detect("https://api.example.com", response, page)
    assert result is not None
    assert any("Auth-gated" in e.description for e in result.evidence)


@pytest.mark.asyncio
async def test_no_detection_simple_site(detector):
    """Should not detect custom protection on a simple static site."""
    response = make_response()
    page = '''<html><head><title>My Blog</title></head>
    <body><h1>Welcome to my blog</h1><p>This is a normal static website with plenty of text content
    that fills up the page and makes it clearly not a SPA shell or JS-gated app.</p></body></html>'''

    result = await detector.detect("https://blog.example.com", response, page)
    assert result is None
