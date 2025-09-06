"""PerimeterX (HUMAN Security) detection module.

Detects PerimeterX by looking for:
- _px3, _pxvid, _px2, _pxde, _pxhd cookies
- PX app ID patterns in page source
- PerimeterX script URLs and captcha references
- Block page indicators
"""

import re

from antibot.detector.base import BaseDetector, DetectionResult, Evidence


class PerimeterXDetector(BaseDetector):
    name = "perimeterx"

    PX_COOKIES = {"_px3", "_pxvid", "_px2", "_pxde", "_pxhd", "_px", "_pxff"}

    # PX App ID pattern: PX followed by alphanumeric chars
    APP_ID_PATTERN = re.compile(r'["\']?(PX[A-Za-z0-9]{4,12})["\']?')

    # Script URL patterns
    SCRIPT_PATTERNS = [
        re.compile(r'src=["\']([^"\']*client\.perimeterx\.net[^"\']*)["\']', re.IGNORECASE),
        re.compile(r'src=["\']([^"\']*px-cdn\.net[^"\']*)["\']', re.IGNORECASE),
        re.compile(r'src=["\']([^"\']*px/client/main\.min\.js[^"\']*)["\']', re.IGNORECASE),
        re.compile(r'src=["\']([^"\']+/init\.js)["\']', re.IGNORECASE),
    ]

    # Block page indicators
    BLOCK_INDICATORS = [
        "px-captcha",
        "px-block",
        "perimeterx",
        "captcha.perimeterx.net",
        "captcha.px-cdn.net",
        "_pxAppId",
        "human security",
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

        found_px_cookies = self.PX_COOKIES & set(response_cookies.keys())
        if found_px_cookies:
            score += 0.15 * len(found_px_cookies)
            cookies_found.extend(found_px_cookies)
            evidence.append(Evidence(
                description=f"PerimeterX cookies detected: {', '.join(sorted(found_px_cookies))}",
            ))

        # --- PX App ID in page source ---
        app_id_match = self.APP_ID_PATTERN.search(page_source)
        if app_id_match:
            app_id = app_id_match.group(1)
            # Validate it looks like a real PX app ID (not just any PX-prefixed string)
            if len(app_id) >= 6:
                score += 0.35
                evidence.append(Evidence(
                    description="PerimeterX App ID found in page source",
                    value=app_id,
                ))

        # --- Script URL detection ---
        for pattern in self.SCRIPT_PATTERNS:
            match = pattern.search(page_source)
            if match:
                script_url = match.group(1)
                score += 0.2
                script_urls.append(script_url)
                evidence.append(Evidence(
                    description="PerimeterX script URL detected",
                    value=script_url,
                ))
                break

        # --- Block page / captcha indicators ---
        source_lower = page_source.lower()
        for indicator in self.BLOCK_INDICATORS:
            if indicator.lower() in source_lower:
                score += 0.1
                evidence.append(Evidence(
                    description=f"PerimeterX indicator found: '{indicator}'",
                ))

        # --- Response header analysis ---
        if hasattr(response, "headers"):
            headers = {k.lower(): v for k, v in response.headers.items()}
            for header_name, header_val in headers.items():
                if header_name.startswith("x-px"):
                    score += 0.2
                    evidence.append(Evidence(
                        description=f"PerimeterX header detected",
                        value=f"{header_name}: {header_val[:100]}",
                    ))
                    break

        # --- HTTP 403 with PX content = strong signal ---
        status_code = getattr(response, "status_code", 200)
        if status_code == 403 and any(ind.lower() in source_lower for ind in ["px-captcha", "_pxAppId"]):
            score += 0.2
            evidence.append(Evidence(description="HTTP 403 with PerimeterX block page"))

        if score >= 0.3:
            return DetectionResult(
                provider=self.name,
                confidence=min(max(score, 0.0), 1.0),
                evidence=evidence,
                script_urls=script_urls,
                cookies_found=cookies_found,
            )
        return None
