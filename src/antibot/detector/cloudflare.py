"""Cloudflare detection module.

Detects Cloudflare protection by looking for:
- __cf_bm, cf_clearance, _cfuvid cookies
- server: cloudflare, cf-ray headers
- /cdn-cgi/challenge-platform/ scripts
- _cf_chl_opt config object
- Turnstile CAPTCHA references
- Challenge page patterns ("Just a moment...", "Verify you are human")
"""

import re

from antibot.detector.base import BaseDetector, DetectionResult, Evidence


class CloudflareDetector(BaseDetector):
    name = "cloudflare"

    # Cloudflare cookies
    CF_COOKIES = {
        "__cf_bm": ("Bot Management cookie", 0.2),
        "cf_clearance": ("Challenge clearance cookie (passed challenge)", 0.3),
        "__cflb": ("Load balancer cookie", 0.1),
        "_cfuvid": ("Unique visitor ID", 0.1),
        "cf_chl_seq_*": None,  # handled via prefix match
    }

    # Cloudflare response headers
    CF_HEADERS = {
        "cf-ray": 0.25,
        "cf-cache-status": 0.1,
        "cf-mitigated": 0.3,
        "cf-chl-bypass": 0.2,
    }

    # Challenge page indicators
    CHALLENGE_TITLES = [
        "just a moment",
        "attention required",
        "verify you are human",
        "checking if the site connection is secure",
        "please wait",
        "one more step",
    ]

    # Script/page source patterns
    SOURCE_PATTERNS = [
        (re.compile(r'/cdn-cgi/challenge-platform/', re.IGNORECASE), 0.25, "Cloudflare challenge platform script"),
        (re.compile(r'_cf_chl_opt', re.IGNORECASE), 0.2, "Cloudflare challenge config (_cf_chl_opt)"),
        (re.compile(r'cf-browser-verification', re.IGNORECASE), 0.15, "Cloudflare browser verification element"),
        (re.compile(r'challenges\.cloudflare\.com/turnstile', re.IGNORECASE), 0.2, "Cloudflare Turnstile CAPTCHA"),
        (re.compile(r'cdn-cgi/scripts/', re.IGNORECASE), 0.1, "Cloudflare CDN-CGI scripts"),
        (re.compile(r'cloudflare[\-_]static', re.IGNORECASE), 0.1, "Cloudflare static resources"),
        (re.compile(r'cpo\.src\s*=\s*["\']\/cdn-cgi', re.IGNORECASE), 0.15, "Cloudflare challenge script loader"),
    ]

    async def detect(self, url: str, response: object, page_source: str) -> DetectionResult | None:
        score = 0.0
        evidence: list[Evidence] = []
        script_urls: list[str] = []
        cookies_found: list[str] = []

        # --- Cookie analysis ---
        response_cookies = {}
        if hasattr(response, "cookies"):
            for name in response.cookies:
                response_cookies[name] = str(response.cookies[name])

        for cookie_name, info in self.CF_COOKIES.items():
            if info is None:
                continue
            desc, weight = info
            if cookie_name in response_cookies:
                score += weight
                cookies_found.append(cookie_name)
                evidence.append(Evidence(
                    description=f"Cloudflare cookie '{cookie_name}' — {desc}",
                    value=response_cookies[cookie_name][:60] + "..." if len(response_cookies[cookie_name]) > 60 else response_cookies[cookie_name],
                ))

        # Check cf_chl_seq prefix cookies
        for name in response_cookies:
            if name.startswith("cf_chl_"):
                score += 0.1
                cookies_found.append(name)
                evidence.append(Evidence(description=f"Cloudflare challenge cookie '{name}'"))
                break

        # --- Response header analysis ---
        response_headers = {}
        if hasattr(response, "headers"):
            response_headers = {k.lower(): v for k, v in response.headers.items()}

        # Server header
        server = response_headers.get("server", "").lower()
        if "cloudflare" in server:
            score += 0.3
            evidence.append(Evidence(
                description="Server header is 'cloudflare'",
                value=response_headers.get("server", ""),
            ))

        # Other CF headers
        for header, weight in self.CF_HEADERS.items():
            if header in response_headers:
                score += weight
                val = response_headers[header]
                evidence.append(Evidence(
                    description=f"Cloudflare header '{header}'",
                    value=val[:100],
                ))

                # cf-mitigated: challenge means active blocking
                if header == "cf-mitigated" and "challenge" in val.lower():
                    score += 0.15
                    evidence.append(Evidence(description="Active Cloudflare challenge (cf-mitigated: challenge)"))

        # --- Page source analysis ---
        source_lower = page_source.lower()

        for pattern, weight, desc in self.SOURCE_PATTERNS:
            if pattern.search(page_source):
                score += weight
                evidence.append(Evidence(description=desc))

                # Extract script URLs
                if "challenge-platform" in desc.lower() or "cdn-cgi" in desc.lower():
                    script_match = re.search(
                        r'src=["\']([^"\']*cdn-cgi[^"\']*)["\']',
                        page_source,
                        re.IGNORECASE,
                    )
                    if script_match:
                        script_urls.append(script_match.group(1))

        # Challenge page title detection
        title_match = re.search(r'<title[^>]*>(.*?)</title>', page_source, re.IGNORECASE | re.DOTALL)
        if title_match:
            title_text = title_match.group(1).strip().lower()
            for challenge_title in self.CHALLENGE_TITLES:
                if challenge_title in title_text:
                    score += 0.2
                    evidence.append(Evidence(
                        description=f"Cloudflare challenge page title detected",
                        value=title_match.group(1).strip()[:80],
                    ))
                    break

        # HTTP 403 with Cloudflare indicators = strong signal
        status_code = getattr(response, "status_code", 200)
        if status_code == 403 and "cloudflare" in server:
            score += 0.15
            evidence.append(Evidence(description="HTTP 403 from Cloudflare server (likely challenge page)"))

        # Meta refresh to /cdn-cgi/
        if re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*/cdn-cgi/', page_source, re.IGNORECASE):
            score += 0.2
            evidence.append(Evidence(description="Meta refresh redirect to /cdn-cgi/ challenge"))

        # --- Negative signals ---
        # If we see other vendors strongly, reduce CF score
        for neg_indicator in ["_abck", "datadome", "_px3", "kpsdk"]:
            if neg_indicator in str(response_cookies):
                score -= 0.1

        if score >= 0.3:
            return DetectionResult(
                provider=self.name,
                confidence=min(max(score, 0.0), 1.0),
                evidence=evidence,
                script_urls=script_urls,
                cookies_found=cookies_found,
            )
        return None
