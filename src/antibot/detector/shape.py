"""Shape Security (F5 Distributed Cloud Bot Defense) detection module.

Detects Shape by looking for:
- Extremely large obfuscated inline/external scripts (200KB+)
- Massive string arrays with rotation functions (Shape's obfuscation hallmark)
- F5/Shape response headers
- Very long encoded cookie values (500+ chars)
- Self-defending code patterns
"""

import re

from antibot.detector.base import BaseDetector, DetectionResult, Evidence


class ShapeDetector(BaseDetector):
    name = "shape"

    # Header patterns
    SHAPE_HEADERS = ["x-f5-", "x-shape-"]

    # Script characteristics
    MIN_OBFUSCATED_SCRIPT_SIZE = 50000  # 50KB+ inline script
    STRING_ARRAY_PATTERN = re.compile(r'var\s+\w+\s*=\s*\[(?:"[^"]*",?\s*){50,}\]')

    # Shape-specific patterns in scripts
    SHAPE_PATTERNS = [
        re.compile(r'window\.s_bfp\b'),
        re.compile(r'window\.s_\w{2,6}\b'),
        re.compile(r'\bFunction\s*\(\s*["\']return\s+this["\']\s*\)'),  # indirect eval
    ]

    # Long cookie value threshold
    LONG_COOKIE_THRESHOLD = 500
    LONG_COOKIE_PATTERN = re.compile(r'^[A-Za-z0-9+/=|~_-]+$')

    async def detect(self, url: str, response: object, page_source: str) -> DetectionResult | None:
        score = 0.0
        evidence: list[Evidence] = []
        script_urls: list[str] = []
        cookies_found: list[str] = []

        # --- Response header analysis ---
        if hasattr(response, "headers"):
            headers = {k.lower(): v for k, v in response.headers.items()}
            for header_name, header_val in headers.items():
                for prefix in self.SHAPE_HEADERS:
                    if header_name.startswith(prefix):
                        score += 0.3
                        evidence.append(Evidence(
                            description=f"Shape/F5 header detected: {header_name}",
                            value=header_val[:100],
                        ))
                        break

        # --- Large obfuscated script detection ---
        # Find all script blocks (both inline and track external src)
        inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', page_source, re.IGNORECASE)
        for script_content in inline_scripts:
            script_len = len(script_content.strip())
            if script_len < self.MIN_OBFUSCATED_SCRIPT_SIZE:
                continue

            # Check for string array pattern (Shape hallmark)
            if self.STRING_ARRAY_PATTERN.search(script_content):
                score += 0.35
                evidence.append(Evidence(
                    description=f"Large obfuscated script ({script_len // 1024}KB) with string array rotation (Shape pattern)",
                ))

                # Check for additional Shape patterns within this script
                for pattern in self.SHAPE_PATTERNS:
                    if pattern.search(script_content):
                        score += 0.05
                        evidence.append(Evidence(
                            description=f"Shape code pattern: {pattern.pattern[:60]}",
                        ))
                break
            elif script_len > 100000:
                # Very large script without clear string array — weaker signal
                score += 0.1
                evidence.append(Evidence(
                    description=f"Very large inline script ({script_len // 1024}KB) — possible Shape",
                ))

        # --- Large external scripts that might be Shape ---
        external_scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
            page_source,
            re.IGNORECASE,
        )
        for src in external_scripts:
            # Shape scripts are typically first-party with opaque paths
            if re.search(r'/s/|/shape/|/[a-f0-9]{16,}\.js', src, re.IGNORECASE):
                score += 0.15
                script_urls.append(src)
                evidence.append(Evidence(
                    description="Possible Shape external script (opaque path pattern)",
                    value=src,
                ))

        # --- Long encoded cookie values ---
        if hasattr(response, "cookies"):
            for name in response.cookies:
                val = str(response.cookies[name])
                if len(val) > self.LONG_COOKIE_THRESHOLD and self.LONG_COOKIE_PATTERN.match(val):
                    score += 0.15
                    cookies_found.append(name)
                    evidence.append(Evidence(
                        description=f"Long encoded cookie '{name}' ({len(val)} chars) — Shape fingerprint pattern",
                        value=val[:80] + "...",
                    ))

        # --- Anti-tamper / self-defending code ---
        anti_tamper_patterns = [
            r'setInterval\s*\(\s*function\s*\(\)\s*\{[^}]*debugger',
            r'constructor\s*\(\s*"return this"\s*\)',
        ]
        for pattern in anti_tamper_patterns:
            if re.search(pattern, page_source):
                score += 0.05
                evidence.append(Evidence(description="Anti-tamper/self-defending code detected"))

        # --- HTTP 400/403 with minimal body (Shape block) ---
        status_code = getattr(response, "status_code", 200)
        if status_code in (400, 403) and len(page_source.strip()) < 500:
            score += 0.1
            evidence.append(Evidence(description=f"HTTP {status_code} with minimal response body"))

        if score >= 0.3:
            return DetectionResult(
                provider=self.name,
                confidence=min(max(score, 0.0), 1.0),
                evidence=evidence,
                script_urls=script_urls,
                cookies_found=cookies_found,
            )
        return None
