"""TLS fingerprint analysis (JA3/JA4).

TLS fingerprinting is one of the most effective anti-bot techniques.
Python's ssl module produces a JA3 hash that doesn't match any real browser,
making it trivially detectable. This module helps analyze and compare
TLS fingerprints.
"""

import hashlib
import logging

logger = logging.getLogger(__name__)

# Known JA3 hashes for common browsers (these change per version)
KNOWN_JA3_HASHES = {
    "chrome_131": {
        "ja3": "773906b0efdefa24a7f2b8eb6985bf37",
        "ja3_full": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    },
    "chrome_124": {
        "ja3": "cd08e31494f9531f560d64c695473da9",
    },
    "firefox_132": {
        "ja3": "b32309a26951912be7dba376398abc3b",
    },
    "safari_17": {
        "ja3": "773906b0efdefa24a7f2b8eb6985bf37",
    },
    "python_requests": {
        "ja3": "3e9b20610098b6c0f88e1b72a1ab92a1",
        "description": "Default Python requests/urllib3 — instantly flagged as bot",
    },
    "python_httpx": {
        "ja3": "b20b9e62c02a3020e23c0989b506ad8b",
        "description": "Python httpx default — also flagged",
    },
    "curl_cffi_chrome": {
        "ja3": "773906b0efdefa24a7f2b8eb6985bf37",
        "description": "curl_cffi impersonating Chrome — matches real Chrome",
    },
}

# Known JA4 fingerprints
KNOWN_JA4_HASHES = {
    "chrome_131": "t13d1516h2_8daaf6152771_e5627efa2ab1",
    "firefox_132": "t13d1715h2_5b57614c22b0_cfb1c0855e84",
}

# HTTP/2 SETTINGS frame order (another fingerprinting vector)
# Browsers send SETTINGS parameters in a specific order
H2_SETTINGS_ORDER = {
    "chrome": [
        "HEADER_TABLE_SIZE",
        "ENABLE_PUSH",
        "MAX_CONCURRENT_STREAMS",
        "INITIAL_WINDOW_SIZE",
        "MAX_FRAME_SIZE",
        "MAX_HEADER_LIST_SIZE",
    ],
    "firefox": [
        "HEADER_TABLE_SIZE",
        "INITIAL_WINDOW_SIZE",
        "MAX_FRAME_SIZE",
    ],
    "safari": [
        "HEADER_TABLE_SIZE",
        "ENABLE_PUSH",
        "INITIAL_WINDOW_SIZE",
        "MAX_CONCURRENT_STREAMS",
        "MAX_FRAME_SIZE",
        "MAX_HEADER_LIST_SIZE",
    ],
}


def compute_ja3(
    tls_version: int,
    ciphers: list[int],
    extensions: list[int],
    elliptic_curves: list[int],
    ec_point_formats: list[int],
) -> str:
    """Compute JA3 hash from TLS Client Hello parameters.

    JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    All values are decimal, comma-separated within groups, dash-separated between groups.
    """
    parts = [
        str(tls_version),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in extensions),
        "-".join(str(ec) for ec in elliptic_curves),
        "-".join(str(f) for f in ec_point_formats),
    ]
    ja3_string = ",".join(parts)
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_hash


def compute_ja4(
    protocol: str,
    tls_version: str,
    num_ciphers: int,
    num_extensions: int,
    alpn_first: str,
    ciphers_hash: str,
    extensions_hash: str,
) -> str:
    """Compute JA4 fingerprint.

    JA4 format: [protocol][version][SNI][num_ciphers][num_extensions][alpn]_[cipher_hash]_[extension_hash]
    """
    ja4_a = f"{protocol}{tls_version}{'d' if True else 'i'}{num_ciphers:02d}{num_extensions:02d}{alpn_first}"
    return f"{ja4_a}_{ciphers_hash}_{extensions_hash}"


def check_tls_fingerprint(ja3_hash: str) -> dict:
    """Check a JA3 hash against known browser fingerprints.

    Returns a dict with match info and risk assessment.
    """
    result = {
        "ja3_hash": ja3_hash,
        "matches": [],
        "is_bot_like": True,
        "risk_level": "high",
    }

    for browser, data in KNOWN_JA3_HASHES.items():
        if data.get("ja3") == ja3_hash:
            result["matches"].append(browser)

    if result["matches"]:
        # Check if it matches a known bot fingerprint
        bot_matches = [m for m in result["matches"] if "python" in m.lower() or "bot" in m.lower()]
        browser_matches = [m for m in result["matches"] if m not in bot_matches]

        if browser_matches:
            result["is_bot_like"] = False
            result["risk_level"] = "low"
        elif bot_matches:
            result["is_bot_like"] = True
            result["risk_level"] = "critical"
    else:
        # Unknown JA3 — suspicious but not conclusive
        result["risk_level"] = "medium"

    return result


def get_recommended_impersonation(target_browser: str = "chrome") -> dict:
    """Get recommended TLS impersonation settings for a target browser."""
    recommendations = {
        "chrome": {
            "curl_cffi_target": "chrome131",
            "ja3_target": KNOWN_JA3_HASHES.get("chrome_131", {}).get("ja3"),
            "h2_settings_order": H2_SETTINGS_ORDER["chrome"],
            "notes": "Use curl_cffi with impersonate='chrome131' for best results",
        },
        "firefox": {
            "curl_cffi_target": "firefox132",
            "ja3_target": KNOWN_JA3_HASHES.get("firefox_132", {}).get("ja3"),
            "h2_settings_order": H2_SETTINGS_ORDER["firefox"],
            "notes": "Firefox has distinct JA3 and H2 settings — don't mix with Chrome UA",
        },
        "safari": {
            "curl_cffi_target": "safari17_5",
            "ja3_target": KNOWN_JA3_HASHES.get("safari_17", {}).get("ja3"),
            "h2_settings_order": H2_SETTINGS_ORDER["safari"],
            "notes": "Safari has unique H2 settings order",
        },
    }
    return recommendations.get(target_browser, recommendations["chrome"])
