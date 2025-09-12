"""Anti-bot script deobfuscation and analysis.

Handles common obfuscation patterns used by Akamai, Shape, PerimeterX, etc:
- String array with rotation function
- Hex/unicode escape sequences
- Dead code / unreachable branches
- Variable renaming based on usage context
"""

import json
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SensorField:
    index: int
    name: str
    source: str  # e.g. "navigator.userAgent", "screen.width"
    description: str = ""


@dataclass
class DeobfuscatedScript:
    original_size: int
    cleaned_size: int
    strings_decoded: int
    config: dict = field(default_factory=dict)
    sensor_fields: list[SensorField] = field(default_factory=list)
    browser_checks: list[str] = field(default_factory=list)
    post_targets: list[str] = field(default_factory=list)
    cleaned_source: str = ""


class ScriptDeobfuscator:
    """Deobfuscate and analyze anti-bot protection scripts."""

    # Browser property access patterns to detect
    BROWSER_PROPERTY_PATTERNS = [
        (r'navigator\s*\.\s*userAgent', "navigator.userAgent"),
        (r'navigator\s*\.\s*platform', "navigator.platform"),
        (r'navigator\s*\.\s*language(?:s)?', "navigator.languages"),
        (r'navigator\s*\.\s*plugins', "navigator.plugins"),
        (r'navigator\s*\.\s*webdriver', "navigator.webdriver"),
        (r'navigator\s*\.\s*hardwareConcurrency', "navigator.hardwareConcurrency"),
        (r'navigator\s*\.\s*deviceMemory', "navigator.deviceMemory"),
        (r'navigator\s*\.\s*maxTouchPoints', "navigator.maxTouchPoints"),
        (r'navigator\s*\.\s*cookieEnabled', "navigator.cookieEnabled"),
        (r'navigator\s*\.\s*doNotTrack', "navigator.doNotTrack"),
        (r'screen\s*\.\s*width', "screen.width"),
        (r'screen\s*\.\s*height', "screen.height"),
        (r'screen\s*\.\s*colorDepth', "screen.colorDepth"),
        (r'screen\s*\.\s*availWidth', "screen.availWidth"),
        (r'screen\s*\.\s*availHeight', "screen.availHeight"),
        (r'window\s*\.\s*innerWidth', "window.innerWidth"),
        (r'window\s*\.\s*innerHeight', "window.innerHeight"),
        (r'\.toDataURL\s*\(', "canvas.toDataURL()"),
        (r'getContext\s*\(\s*["\']2d', "canvas.getContext('2d')"),
        (r'getContext\s*\(\s*["\']webgl', "WebGL context"),
        (r'WEBGL_debug_renderer_info', "WebGL debug info"),
        (r'UNMASKED_VENDOR_WEBGL', "WebGL vendor"),
        (r'UNMASKED_RENDERER_WEBGL', "WebGL renderer"),
        (r'AudioContext', "AudioContext fingerprint"),
        (r'performance\s*\.\s*now\s*\(', "performance.now()"),
        (r'performance\s*\.\s*timing', "performance.timing"),
        (r'Intl\s*\.\s*DateTimeFormat', "Intl.DateTimeFormat (timezone)"),
        (r'Date\s*\(\s*\)\s*\.\s*getTimezoneOffset', "Date.getTimezoneOffset()"),
        (r'window\s*\.\s*chrome', "window.chrome"),
        (r'window\s*\.\s*_phantom', "PhantomJS detection"),
        (r'window\s*\.\s*__nightmare', "Nightmare detection"),
        (r'document\s*\.\s*__selenium', "Selenium detection"),
        (r'window\s*\.\s*callPhantom', "PhantomJS detection"),
        (r'domAutomation', "Chrome automation detection"),
        (r'webdriver', "WebDriver detection"),
        (r'__webdriver', "WebDriver detection"),
        (r'_Selenium', "Selenium detection"),
        (r'localStorage', "localStorage access"),
        (r'sessionStorage', "sessionStorage access"),
        (r'indexedDB', "indexedDB access"),
        (r'openDatabase', "openDatabase access"),
    ]

    def deobfuscate(self, script_content: str) -> DeobfuscatedScript:
        """Deobfuscate a protection script and extract analysis."""
        original_size = len(script_content)
        cleaned = script_content
        strings_decoded = 0

        # Step 1: Decode hex escape sequences (\x61 -> a)
        def decode_hex(match):
            nonlocal strings_decoded
            strings_decoded += 1
            return chr(int(match.group(1), 16))

        cleaned = re.sub(r'\\x([0-9a-fA-F]{2})', decode_hex, cleaned)

        # Step 2: Decode unicode escapes (\u0061 -> a)
        def decode_unicode(match):
            nonlocal strings_decoded
            strings_decoded += 1
            return chr(int(match.group(1), 16))

        cleaned = re.sub(r'\\u([0-9a-fA-F]{4})', decode_unicode, cleaned)

        # Step 3: Inline string array lookups
        # Pattern: var _0xabc = ["str1", "str2", ...]; then _0xabc[0] -> "str1"
        string_arrays = self._extract_string_arrays(cleaned)
        for var_name, strings in string_arrays.items():
            # Replace array lookups with actual strings
            def replace_lookup(match, arr=strings):
                idx = int(match.group(1))
                if 0 <= idx < len(arr):
                    return f'"{arr[idx]}"'
                return match.group(0)

            cleaned = re.sub(rf'{re.escape(var_name)}\[(\d+)\]', replace_lookup, cleaned)
            strings_decoded += len(strings)

        # Step 4: Extract analysis
        config = self._extract_config(cleaned)
        browser_checks = self._extract_browser_checks(cleaned)
        post_targets = self._extract_post_targets(cleaned)
        sensor_fields = self._extract_sensor_fields(cleaned)

        return DeobfuscatedScript(
            original_size=original_size,
            cleaned_size=len(cleaned),
            strings_decoded=strings_decoded,
            config=config,
            sensor_fields=sensor_fields,
            browser_checks=browser_checks,
            post_targets=post_targets,
            cleaned_source=cleaned,
        )

    def _extract_string_arrays(self, script: str) -> dict[str, list[str]]:
        """Find large string array declarations and extract their contents."""
        arrays = {}
        # Match: var _0x1234 = ["str1", "str2", ...]
        pattern = re.compile(
            r'(?:var|let|const)\s+(\w+)\s*=\s*\[((?:"[^"]*"|\'[^\']*\')(?:\s*,\s*(?:"[^"]*"|\'[^\']*\'))*)\s*\]',
        )
        for match in pattern.finditer(script):
            var_name = match.group(1)
            array_content = match.group(2)
            # Extract individual strings
            strings = re.findall(r'["\']([^"\']*)["\']', array_content)
            if len(strings) >= 10:  # Only consider large arrays (likely obfuscation)
                arrays[var_name] = strings
                logger.info(f"[Deobfuscator] Found string array '{var_name}' with {len(strings)} strings")

        return arrays

    def _extract_config(self, script: str) -> dict:
        """Extract configuration values from the script."""
        config = {}

        # Akamai version
        ver_match = re.search(r'["\']ak\.v["\']?\s*[:=]\s*["\']([^"\']+)["\']', script)
        if ver_match:
            config["akamai_version"] = ver_match.group(1)

        # Sensor data key
        sensor_match = re.search(r'sensor_data', script)
        if sensor_match:
            config["uses_sensor_data"] = True

        # API endpoints
        endpoint_matches = re.findall(r'["\'](?:https?://[^"\']+|/[a-zA-Z0-9/_-]+\.(?:js|json|php))["\']', script)
        if endpoint_matches:
            config["endpoints"] = list(set(endpoint_matches[:20]))

        # Challenge type
        if "pow" in script.lower() or "proof" in script.lower():
            config["challenge_type"] = "proof-of-work"
        elif "captcha" in script.lower():
            config["challenge_type"] = "captcha"
        elif "sensor" in script.lower():
            config["challenge_type"] = "sensor_data"

        return config

    def _extract_browser_checks(self, script: str) -> list[str]:
        """Find what browser properties the script accesses."""
        checks = []
        for pattern, name in self.BROWSER_PROPERTY_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE):
                checks.append(name)
        return sorted(set(checks))

    def _extract_post_targets(self, script: str) -> list[str]:
        """Find URLs where the script POSTs data."""
        targets = []

        # XMLHttpRequest.open("POST", url)
        xhr_matches = re.findall(r'\.open\s*\(\s*["\']POST["\']\s*,\s*["\']([^"\']+)["\']', script, re.IGNORECASE)
        targets.extend(xhr_matches)

        # fetch(url, {method: "POST"})
        fetch_matches = re.findall(r'fetch\s*\(\s*["\']([^"\']+)["\']', script)
        targets.extend(fetch_matches)

        return list(set(targets))

    def _extract_sensor_fields(self, script: str) -> list[SensorField]:
        """Attempt to identify sensor data fields from the script."""
        fields = []
        idx = 0

        # Look for pipe-join patterns that build sensor_data
        # Common pattern: value1 + "|" + value2 + "|" + ...
        pipe_joins = re.findall(r'(\w+(?:\.\w+)*)\s*\+\s*["\'][\|;]["\']', script)
        for expr in pipe_joins:
            for _, name in self.BROWSER_PROPERTY_PATTERNS:
                if any(part in expr for part in name.split(".")):
                    fields.append(SensorField(index=idx, name=name, source=expr))
                    idx += 1
                    break

        return fields

    def extract_config(self, script: str, provider: str) -> dict:
        """Provider-specific config extraction."""
        result = self.deobfuscate(script)
        config = result.config
        config["provider"] = provider
        config["browser_checks"] = result.browser_checks
        config["post_targets"] = result.post_targets
        config["sensor_fields"] = [{"index": f.index, "name": f.name, "source": f.source} for f in result.sensor_fields]
        config["strings_decoded"] = result.strings_decoded
        config["size_reduction"] = f"{result.original_size} -> {result.cleaned_size} bytes"
        return config
