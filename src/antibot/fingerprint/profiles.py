"""Known browser fingerprint profiles for comparison baselines."""

# These profiles represent typical real browser fingerprints.
# Used as baselines for comparing bot fingerprints against real ones.

CHROME_131_WIN11 = {
    "source": "chrome_131_win11",
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "platform": "Win32",
    "screen_width": 1920,
    "screen_height": 1080,
    "color_depth": 24,
    "timezone": "America/New_York",
    "timezone_offset": -300,
    "languages": ["en-US", "en"],
    "hardware_concurrency": 16,
    "device_memory": 8,
    "max_touch_points": 0,
    "webgl_vendor": "Google Inc. (NVIDIA)",
    "webgl_renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "plugins": [
        "PDF Viewer",
        "Chrome PDF Viewer",
        "Chromium PDF Viewer",
        "Microsoft Edge PDF Viewer",
        "WebKit built-in PDF",
    ],
    "do_not_track": None,
    "webdriver": False,
    "automation_indicators": {
        "navigator.webdriver": False,
        "window._phantom": False,
        "window.callPhantom": False,
        "window.__nightmare": False,
        "document.__selenium_unwrapped": False,
        "navigator.plugins.length > 0": True,
        "navigator.languages.length > 0": True,
    },
}

CHROME_131_MACOS = {
    "source": "chrome_131_macos",
    "user_agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "platform": "MacIntel",
    "screen_width": 2560,
    "screen_height": 1440,
    "color_depth": 30,
    "timezone": "America/Los_Angeles",
    "timezone_offset": -480,
    "languages": ["en-US", "en"],
    "hardware_concurrency": 12,
    "device_memory": 8,
    "max_touch_points": 0,
    "webgl_vendor": "Google Inc. (Apple)",
    "webgl_renderer": "ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Pro, Unspecified Version)",
    "plugins": [
        "PDF Viewer",
        "Chrome PDF Viewer",
        "Chromium PDF Viewer",
        "Microsoft Edge PDF Viewer",
        "WebKit built-in PDF",
    ],
    "do_not_track": None,
    "webdriver": False,
}

FIREFOX_132_WIN11 = {
    "source": "firefox_132_win11",
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
        "Gecko/20100101 Firefox/132.0"
    ),
    "platform": "Win32",
    "screen_width": 1920,
    "screen_height": 1080,
    "color_depth": 24,
    "timezone": "America/New_York",
    "timezone_offset": -300,
    "languages": ["en-US", "en"],
    "hardware_concurrency": 16,
    "device_memory": None,  # Firefox doesn't expose this
    "max_touch_points": 0,
    "webgl_vendor": "Mozilla",
    "webgl_renderer": "Mozilla",  # Firefox obscures WebGL info by default
    "plugins": [],  # Firefox returns empty in newer versions
    "do_not_track": "1",
    "webdriver": False,
}

SAFARI_17_MACOS = {
    "source": "safari_17_macos",
    "user_agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.6 Safari/605.1.15"
    ),
    "platform": "MacIntel",
    "screen_width": 2560,
    "screen_height": 1440,
    "color_depth": 30,
    "timezone": "America/Los_Angeles",
    "timezone_offset": -480,
    "languages": ["en-US"],
    "hardware_concurrency": 12,
    "device_memory": None,  # Safari doesn't expose this
    "max_touch_points": 0,
    "webgl_vendor": "Apple Inc.",
    "webgl_renderer": "Apple GPU",
    "plugins": [
        "WebKit built-in PDF",
    ],
    "do_not_track": None,
    "webdriver": False,
}

# Bot fingerprint: what a naive Python HTTP client looks like
PYTHON_BOT_BASELINE = {
    "source": "python_bot",
    "user_agent": "python-requests/2.31.0",
    "platform": None,
    "screen_width": None,
    "screen_height": None,
    "color_depth": None,
    "timezone": None,
    "timezone_offset": None,
    "languages": None,
    "hardware_concurrency": None,
    "device_memory": None,
    "max_touch_points": None,
    "webgl_vendor": None,
    "webgl_renderer": None,
    "plugins": None,
    "do_not_track": None,
    "webdriver": None,
    "automation_indicators": {
        "navigator.webdriver": None,
        "navigator.plugins.length > 0": None,
        "navigator.languages.length > 0": None,
    },
}

# Lookup by name
PROFILES = {
    "chrome_131_win11": CHROME_131_WIN11,
    "chrome_131_macos": CHROME_131_MACOS,
    "firefox_132_win11": FIREFOX_132_WIN11,
    "safari_17_macos": SAFARI_17_MACOS,
    "python_bot": PYTHON_BOT_BASELINE,
}
