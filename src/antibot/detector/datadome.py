"""DataDome detection module.

Detects DataDome by looking for:
- datadome cookie
- X-DataDome-CID and related headers (very distinctive)
- js.datadome.co script references
- captcha-delivery.com references
- ddjskey/ddoptions JavaScript config variables
"""

import re

from antibot.detector.base import BaseDetector, DetectionResult, Evidence


class DataDomeDetector(BaseDetector):
    name = "datadome"

    # DataDome script URLs
    SCRIPT_PATTERNS = [
        re.compile(r'src=["\']([^"\']*js\.datadome\.co[^"\']*)["\']', re.IGNORECASE),
        re.compile(r'src=["\']([^"\']*datadome[^"\']*tags\.js[^"\']*)["\']', re.IGNORECASE),
    ]

    # DataDome response headers (case-insensitive matching)
    DD_HEADER_PREFIXES = ["x-datadome", "x-dd-"]

    # JavaScript config variables
    JS_CONFIG_VARS = ["ddjskey", "ddoptions", "DataDome"]

    # Captcha/challenge URLs
    CHALLENGE_URLS = [
        "captcha-delivery.com",
        "geo.captcha-delivery.com",
        "interstitial.captcha-delivery.com",
        "api-js.datadome.co",
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

        if "datadome" in response_cookies:
            score += 0.4
            cookies_found.append("datadome")
            cookie_val = response_cookies["datadome"]
            evidence.append(Evidence(
                description="DataDome cookie present",
                value=cookie_val[:60] + "..." if len(cookie_val) > 60 else cookie_val,
            ))

        # --- Response headers (most distinctive signal) ---
        if hasattr(response, "headers"):
            headers = {k.lower(): v for k, v in response.headers.items()}

            for header_name, header_val in headers.items():
                for prefix in self.DD_HEADER_PREFIXES:
                    if header_name.startswith(prefix):
                        score += 0.35
                        evidence.append(Evidence(
                            description=f"DataDome header detected: {header_name}",
                            value=header_val[:100],
                        ))
                        break

            if headers.get("server", "").lower() == "datadome":
                score += 0.3
                evidence.append(Evidence(description="Server header is 'DataDome'"))

        # --- Script URL detection ---
        for pattern in self.SCRIPT_PATTERNS:
            match = pattern.search(page_source)
            if match:
                script_url = match.group(1)
                score += 0.2
                script_urls.append(script_url)
                evidence.append(Evidence(
                    description="DataDome script URL detected",
                    value=script_url,
                ))
                break

        # --- JavaScript config variables ---
        for var in self.JS_CONFIG_VARS:
            if var in page_source:
                score += 0.05
                evidence.append(Evidence(description=f"DataDome JS variable '{var}' found"))

        # --- Challenge/captcha URL references ---
        source_lower = page_source.lower()
        for challenge_url in self.CHALLENGE_URLS:
            if challenge_url in source_lower:
                score += 0.15
                evidence.append(Evidence(
                    description=f"DataDome challenge URL reference: {challenge_url}",
                ))
                break

        # --- POST to api-js.datadome.co pattern ---
        if "api-js.datadome.co/js/" in page_source:
            score += 0.1
            evidence.append(Evidence(description="DataDome API endpoint reference found"))

        if score >= 0.3:
            return DetectionResult(
                provider=self.name,
                confidence=min(max(score, 0.0), 1.0),
                evidence=evidence,
                script_urls=script_urls,
                cookies_found=cookies_found,
            )
        return None
