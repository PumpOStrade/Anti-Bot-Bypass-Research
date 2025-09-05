"""Akamai Bot Manager detection module.

Detects Akamai protection by looking for:
- _abck and bm_sz cookies
- Hex-path sensor scripts
- bmak/sensor_data references in page source
- Akamai-specific response headers
"""

import re

from antibot.detector.base import BaseDetector, DetectionResult, Evidence


class AkamaiDetector(BaseDetector):
    name = "akamai"

    # Cookie names set by Akamai Bot Manager
    PRIMARY_COOKIES = {"_abck", "bm_sz"}
    SECONDARY_COOKIES = {"ak_bmsc", "bm_sv", "bm_mi"}

    # Regex for the Akamai sensor script URL pattern (hex-path)
    SCRIPT_PATTERN = re.compile(
        r'["\'](/[a-f0-9]{20,}/[a-f0-9]{6,}(?:/[a-f0-9]*)*(?:\.js)?)["\']',
        re.IGNORECASE,
    )

    # Alternative Akamai script path patterns
    ALT_SCRIPT_PATTERNS = [
        re.compile(r'src=["\']([^"\']*/_bm/[^"\']*\.js)["\']', re.IGNORECASE),
        re.compile(r'src=["\']([^"\']*akam/[^"\']*\.js)["\']', re.IGNORECASE),
    ]

    # Strings found in Akamai's sensor script
    SCRIPT_SIGNATURES = [
        "bmak",
        "sensor_data",
        "ak.v=",
        "bm.pers",
        "mn_abck",
        "ab.storage",
    ]

    # Response headers
    AKAMAI_HEADERS = [
        "x-akamai-session-info",
        "x-akamai-transformed",
        "x-akamai-request-id",
        "server",
    ]
    AKAMAI_SERVER_VALUES = ["akamaighost", "akamainetStorage"]

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

        for cookie in self.PRIMARY_COOKIES:
            if cookie in response_cookies:
                score += 0.3
                cookies_found.append(cookie)
                evidence.append(Evidence(
                    description=f"Primary Akamai cookie '{cookie}' present",
                    value=response_cookies[cookie][:80] + "..." if len(response_cookies[cookie]) > 80 else response_cookies[cookie],
                ))

                # Check _abck cookie format (valid vs. invalid)
                if cookie == "_abck":
                    val = response_cookies[cookie]
                    if "~0~" in val:
                        evidence.append(Evidence(description="_abck cookie appears VALID (contains ~0~)"))
                    elif "~-1~" in val:
                        evidence.append(Evidence(description="_abck cookie is in initial/invalid state (~-1~)"))

        for cookie in self.SECONDARY_COOKIES:
            if cookie in response_cookies:
                score += 0.1
                cookies_found.append(cookie)
                evidence.append(Evidence(description=f"Secondary Akamai cookie '{cookie}' present"))

        # --- Script URL detection ---
        for match in self.SCRIPT_PATTERN.finditer(page_source):
            script_url = match.group(1)
            # Filter out false positives (must look like a hex path, not a normal path)
            if re.match(r'^/[a-f0-9]{20,}/', script_url):
                score += 0.2
                script_urls.append(script_url)
                evidence.append(Evidence(
                    description="Akamai sensor script detected (hex-path pattern)",
                    value=script_url,
                ))
                break  # One is enough

        for pattern in self.ALT_SCRIPT_PATTERNS:
            match = pattern.search(page_source)
            if match:
                score += 0.15
                script_urls.append(match.group(1))
                evidence.append(Evidence(
                    description="Akamai script detected (alternate path pattern)",
                    value=match.group(1),
                ))

        # --- Page source signature analysis ---
        source_lower = page_source.lower()
        for sig in self.SCRIPT_SIGNATURES:
            if sig.lower() in source_lower:
                score += 0.05
                evidence.append(Evidence(description=f"Akamai signature string '{sig}' in page source"))

        # --- Response header analysis ---
        response_headers = {}
        if hasattr(response, "headers"):
            response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header in self.AKAMAI_HEADERS:
            if header in response_headers:
                if header == "server":
                    server_val = response_headers[header].lower()
                    if any(s in server_val for s in self.AKAMAI_SERVER_VALUES):
                        score += 0.1
                        evidence.append(Evidence(
                            description=f"Server header indicates Akamai",
                            value=response_headers[header],
                        ))
                else:
                    score += 0.1
                    evidence.append(Evidence(
                        description=f"Akamai header '{header}' present",
                        value=response_headers[header][:100],
                    ))

        # --- Negative signals (not Akamai) ---
        if "_cf_chl_opt" in page_source or "cf-browser-verification" in source_lower:
            score -= 0.3
            evidence.append(Evidence(description="Cloudflare signals detected (negative for Akamai)"))

        if score >= 0.4:
            return DetectionResult(
                provider=self.name,
                confidence=min(max(score, 0.0), 1.0),
                evidence=evidence,
                script_urls=script_urls,
                cookies_found=cookies_found,
            )
        return None
