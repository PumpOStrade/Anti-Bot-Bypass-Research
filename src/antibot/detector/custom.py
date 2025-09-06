"""Custom / in-house anti-bot detection module.

Detects sites that build their own anti-bot protections instead of using
third-party vendors. Catches patterns like:
- Rate limiting headers
- Auth-gated SPA shell pages
- CSRF / security tokens
- Custom fingerprinting JavaScript
- Known platform signatures (X/Twitter, Instagram, LinkedIn, etc.)
"""

import re

from antibot.detector.base import BaseDetector, DetectionResult, Evidence


# Known platform-specific signatures
PLATFORM_SIGNATURES = {
    "x_twitter": {
        "name": "X (Twitter)",
        "cookies": ["ct0", "gt", "auth_token", "_twitter_sess", "twid", "kdt"],
        "script_domains": ["abs.twimg.com", "api.x.com", "api.twitter.com"],
        "page_strings": ["twitter", "twimg.com", "__INITIAL_STATE__"],
        "headers": ["x-transaction-id", "x-connection-hash", "x-guest-token"],
    },
    "instagram": {
        "name": "Instagram",
        "cookies": ["csrftoken", "ig_did", "ig_nrcb", "mid", "sessionid", "ds_user_id"],
        "script_domains": ["instagram.com/static", "cdninstagram.com"],
        "page_strings": ["instagram", "_sharedData", "graphql"],
        "headers": ["x-ig-app-id", "x-instagram-ajax"],
    },
    "linkedin": {
        "name": "LinkedIn",
        "cookies": ["JSESSIONID", "li_at", "liap", "li_sugr", "bcookie", "bscookie"],
        "script_domains": ["static.licdn.com", "platform.linkedin.com"],
        "page_strings": ["linkedin", "voyager"],
        "headers": ["x-li-track", "x-restli-protocol-version"],
    },
    "facebook": {
        "name": "Facebook / Meta",
        "cookies": ["c_user", "xs", "fr", "datr", "sb"],
        "script_domains": ["static.xx.fbcdn.net", "connect.facebook.net"],
        "page_strings": ["facebook.com", "__comet_req"],
        "headers": ["x-fb-debug", "x-fb-trip-id"],
    },
    "tiktok": {
        "name": "TikTok",
        "cookies": ["tt_webid", "ttwid", "msToken", "tt_chain_token", "s_v_web_id"],
        "script_domains": ["lf16-tiktok-web.ttwstatic.com", "sf16-website-login.neutral.ttwstatic.com"],
        "page_strings": ["tiktok", "sigi.state", "webapp.video-detail"],
        "headers": ["x-tt-params"],
    },
}

# Generic rate-limit header patterns
RATE_LIMIT_HEADERS = [
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
]

# CSRF / security token cookie names
CSRF_COOKIES = ["ct0", "csrf_token", "_csrf", "csrftoken", "XSRF-TOKEN", "xsrf_token", "_xsrf"]

# Security headers that indicate hardened API
SECURITY_HEADERS = [
    "content-security-policy",
    "x-content-type-options",
    "strict-transport-security",
    "x-frame-options",
    "x-xss-protection",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
]

# SPA framework indicators
SPA_ROOT_PATTERNS = [
    re.compile(r'<div\s+id=["\'](?:root|app|__next|__nuxt|main-content)["\']>\s*</div>', re.IGNORECASE),
    re.compile(r'<div\s+id=["\']react-root["\']', re.IGNORECASE),
]

# JS fingerprinting indicators in page source
FINGERPRINT_JS_PATTERNS = [
    re.compile(r'\bfingerprint\b', re.IGNORECASE),
    re.compile(r'\bdeviceId\b'),
    re.compile(r'\bclientId\b'),
    re.compile(r'\bbrowserId\b'),
    re.compile(r'navigator\s*\.\s*(?:webdriver|plugins|languages|hardwareConcurrency)'),
    re.compile(r'canvas\s*\.\s*toDataURL'),
    re.compile(r'getContext\s*\(\s*["\']webgl'),
    re.compile(r'AudioContext'),
]


class CustomDetector(BaseDetector):
    name = "custom"

    async def detect(self, url: str, response: object, page_source: str) -> DetectionResult | None:
        score = 0.0
        evidence: list[Evidence] = []
        script_urls: list[str] = []
        cookies_found: list[str] = []
        platform_name = None

        # --- Extract response data ---
        response_cookies = {}
        if hasattr(response, "cookies"):
            for name in response.cookies:
                response_cookies[name] = str(response.cookies[name])

        response_headers = {}
        if hasattr(response, "headers"):
            response_headers = {k.lower(): v for k, v in response.headers.items()}

        source_lower = page_source.lower()

        # === 1. Known Platform Detection ===
        for platform_key, sigs in PLATFORM_SIGNATURES.items():
            platform_score = 0.0

            # Check cookies
            matched_cookies = [c for c in sigs["cookies"] if c in response_cookies]
            if matched_cookies:
                platform_score += 0.15 * min(len(matched_cookies), 3)

            # Check script domains in page source
            matched_scripts = [d for d in sigs["script_domains"] if d in source_lower]
            if matched_scripts:
                platform_score += 0.15

            # Check page strings
            matched_strings = [s for s in sigs["page_strings"] if s.lower() in source_lower]
            if matched_strings:
                platform_score += 0.1

            # Check headers
            matched_headers = [h for h in sigs["headers"] if h in response_headers]
            if matched_headers:
                platform_score += 0.1

            if platform_score >= 0.2:
                score += platform_score
                platform_name = sigs["name"]
                cookies_found.extend(matched_cookies)
                evidence.append(Evidence(
                    description=f"Known platform detected: {sigs['name']}",
                    value=f"cookies: {matched_cookies}, scripts: {matched_scripts[:2]}",
                ))
                break  # Only match one platform

        # === 2. Rate Limiting Headers ===
        rate_limit_found = [h for h in RATE_LIMIT_HEADERS if h in response_headers]
        if rate_limit_found:
            score += 0.1 * min(len(rate_limit_found), 3)
            evidence.append(Evidence(
                description=f"Rate limiting headers detected ({len(rate_limit_found)})",
                value=", ".join(rate_limit_found[:5]),
            ))

        # === 3. CSRF / Security Token Cookies ===
        csrf_found = [c for c in CSRF_COOKIES if c in response_cookies]
        if csrf_found:
            score += 0.1
            cookies_found.extend(csrf_found)
            evidence.append(Evidence(
                description="CSRF/security token cookies detected",
                value=", ".join(csrf_found),
            ))

        # === 4. SPA Shell Page Detection ===
        # Check for minimal HTML with JS-only rendering
        body_match = re.search(r'<body[^>]*>([\s\S]*)</body>', page_source, re.IGNORECASE)
        if body_match:
            body_content = body_match.group(1).strip()
            # Remove script tags to see if there's actual content
            text_only = re.sub(r'<script[\s\S]*?</script>', '', body_content, flags=re.IGNORECASE)
            text_only = re.sub(r'<[^>]+>', '', text_only).strip()

            if len(text_only) < 200 and len(page_source) > 1000:
                score += 0.1
                evidence.append(Evidence(
                    description="SPA shell page detected (minimal text content, JS-heavy)",
                    value=f"Text content: {len(text_only)} chars, total page: {len(page_source)} chars",
                ))

        for pattern in SPA_ROOT_PATTERNS:
            if pattern.search(page_source):
                score += 0.05
                evidence.append(Evidence(description="SPA root element detected (React/Next/Vue/Nuxt)"))
                break

        # Noscript with JS-required message
        noscript_match = re.search(r'<noscript[^>]*>([\s\S]*?)</noscript>', page_source, re.IGNORECASE)
        if noscript_match:
            noscript_text = noscript_match.group(1).lower()
            if any(kw in noscript_text for kw in ["javascript", "enable", "browser", "support"]):
                score += 0.05
                evidence.append(Evidence(description="<noscript> requires JavaScript (JS-gated content)"))

        # === 5. Security Headers ===
        sec_headers_found = [h for h in SECURITY_HEADERS if h in response_headers]
        if len(sec_headers_found) >= 3:
            score += 0.1
            evidence.append(Evidence(
                description=f"Hardened security headers ({len(sec_headers_found)}/{len(SECURITY_HEADERS)})",
                value=", ".join(sec_headers_found[:5]),
            ))

        # === 6. JS Fingerprinting in Page Source ===
        fp_patterns_found = []
        for pattern in FINGERPRINT_JS_PATTERNS:
            if pattern.search(page_source):
                fp_patterns_found.append(pattern.pattern[:30])

        if len(fp_patterns_found) >= 2:
            score += 0.1
            evidence.append(Evidence(
                description=f"Client-side fingerprinting JS detected ({len(fp_patterns_found)} patterns)",
                value=", ".join(fp_patterns_found[:4]),
            ))

        # === 7. Auth-Gated Redirect Detection ===
        status_code = getattr(response, "status_code", 200)
        if status_code in (401, 403):
            score += 0.1
            evidence.append(Evidence(
                description=f"Auth-gated response (HTTP {status_code})",
            ))
        elif status_code in (301, 302, 303, 307, 308):
            location = response_headers.get("location", "")
            if any(kw in location.lower() for kw in ["login", "auth", "signin", "sso", "oauth"]):
                score += 0.1
                evidence.append(Evidence(
                    description="Redirect to login/auth page detected",
                    value=location[:100],
                ))

        # === Build result ===
        if score >= 0.2:
            provider_label = f"custom ({platform_name})" if platform_name else "custom"
            return DetectionResult(
                provider=provider_label,
                confidence=min(max(score, 0.0), 1.0),
                evidence=evidence,
                script_urls=script_urls,
                cookies_found=list(set(cookies_found)),
            )
        return None
