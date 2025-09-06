"""Kasada detection module.

Detects Kasada by looking for:
- X-Kpsdk-* headers (CD, CT, V)
- /ips.js script with UUID-based paths
- WASM module loading patterns
- /tl/ telemetry endpoint references
- JWT-like cookie values (eyJ...)
"""

import re

from antibot.detector.base import BaseDetector, DetectionResult, Evidence


class KasadaDetector(BaseDetector):
    name = "kasada"

    # Kasada header patterns
    KPSDK_HEADER_PREFIX = "x-kpsdk"

    # Script URL patterns
    SCRIPT_PATTERNS = [
        re.compile(r'src=["\']([^"\']*ips\.js[^"\']*)["\']', re.IGNORECASE),
        re.compile(
            r'src=["\']([^"\']*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[^"\']*\.js)["\']',
            re.IGNORECASE,
        ),
        re.compile(r'src=["\']([^"\']*k\.tl/[^"\']*)["\']', re.IGNORECASE),
    ]

    # Telemetry endpoint
    TL_PATTERN = re.compile(r'["\']([^"\']*?/tl/[^"\']*)["\']')

    # Kasada-specific strings in source
    SOURCE_SIGNATURES = ["kpsdk", "KP_", "kasada"]

    async def detect(self, url: str, response: object, page_source: str) -> DetectionResult | None:
        score = 0.0
        evidence: list[Evidence] = []
        script_urls: list[str] = []
        cookies_found: list[str] = []

        # --- Response header analysis ---
        if hasattr(response, "headers"):
            headers = {k.lower(): v for k, v in response.headers.items()}
            for header_name, header_val in headers.items():
                if header_name.startswith(self.KPSDK_HEADER_PREFIX):
                    score += 0.4
                    evidence.append(Evidence(
                        description=f"Kasada header detected: {header_name}",
                        value=header_val[:100],
                    ))

        # --- Cookie analysis (JWT-like tokens) ---
        if hasattr(response, "cookies"):
            for name in response.cookies:
                val = str(response.cookies[name])
                if val.startswith("eyJ") and len(val) > 50:
                    score += 0.15
                    cookies_found.append(name)
                    evidence.append(Evidence(
                        description=f"JWT-like cookie '{name}' (possible Kasada token)",
                        value=val[:60] + "...",
                    ))

        # --- Script URL detection ---
        for pattern in self.SCRIPT_PATTERNS:
            match = pattern.search(page_source)
            if match:
                script_url = match.group(1)
                score += 0.25
                script_urls.append(script_url)
                evidence.append(Evidence(
                    description="Kasada script URL detected",
                    value=script_url,
                ))
                break

        # --- Telemetry endpoint ---
        tl_match = self.TL_PATTERN.search(page_source)
        if tl_match:
            score += 0.15
            evidence.append(Evidence(
                description="Kasada telemetry endpoint (/tl/) detected",
                value=tl_match.group(1),
            ))

        # --- WASM loading associated with Kasada ---
        if ".wasm" in page_source:
            # WASM alone is not enough, must be near Kasada indicators
            source_lower = page_source.lower()
            if any(sig.lower() in source_lower for sig in self.SOURCE_SIGNATURES):
                score += 0.15
                evidence.append(Evidence(description="WASM module load associated with Kasada signatures"))

        # --- Source signature strings ---
        source_lower = page_source.lower()
        for sig in self.SOURCE_SIGNATURES:
            if sig.lower() in source_lower:
                score += 0.05
                evidence.append(Evidence(description=f"Kasada signature string '{sig}' in source"))

        # --- HTTP 429 challenge page ---
        status_code = getattr(response, "status_code", 200)
        if status_code == 429 and any(sig.lower() in source_lower for sig in self.SOURCE_SIGNATURES):
            score += 0.2
            evidence.append(Evidence(description="HTTP 429 with Kasada challenge indicators"))

        if score >= 0.3:
            return DetectionResult(
                provider=self.name,
                confidence=min(max(score, 0.0), 1.0),
                evidence=evidence,
                script_urls=script_urls,
                cookies_found=cookies_found,
            )
        return None
