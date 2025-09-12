"""Parse anti-bot scripts to extract sensor fields, POST targets, and validation logic."""

import re
from dataclasses import dataclass, field


@dataclass
class ValidationCheck:
    property_name: str
    check_type: str  # "exists", "equals", "not_equals", "typeof"
    expected_value: str | None = None
    description: str = ""


def parse_sensor_fields(script: str) -> list[dict]:
    """Identify sensor_data fields and their source browser properties."""
    fields = []

    # Look for assignments that build the sensor payload
    # Pattern: arr.push(navigator.userAgent) or arr[i] = screen.width
    push_patterns = re.findall(
        r'\.push\s*\(\s*([\w.]+(?:\s*\.\s*\w+)*)\s*\)',
        script,
    )
    for i, expr in enumerate(push_patterns):
        if "." in expr and any(prop in expr for prop in ["navigator", "screen", "window", "document", "performance"]):
            fields.append({"index": i, "source": expr.strip()})

    return fields


def parse_post_target(script: str) -> str | None:
    """Extract the URL where sensor data gets POSTed."""
    # XMLHttpRequest
    match = re.search(r'\.open\s*\(\s*["\']POST["\']\s*,\s*["\']([^"\']+)["\']', script, re.IGNORECASE)
    if match:
        return match.group(1)

    # fetch
    match = re.search(r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*method\s*:\s*["\']POST["\']', script, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def parse_validation_logic(script: str) -> list[ValidationCheck]:
    """Extract what properties the script validates (automation detection)."""
    checks = []

    # navigator.webdriver checks
    if re.search(r'navigator\s*\.\s*webdriver', script):
        checks.append(ValidationCheck(
            property_name="navigator.webdriver",
            check_type="equals",
            expected_value="false",
            description="Checks if browser is automated via WebDriver",
        ))

    # Phantom/Nightmare/Selenium detection
    automation_checks = {
        r'window\s*\.\s*_phantom': ("window._phantom", "PhantomJS detection"),
        r'window\s*\.\s*__nightmare': ("window.__nightmare", "Nightmare.js detection"),
        r'document\s*\.\s*__selenium': ("document.__selenium", "Selenium detection"),
        r'window\s*\.\s*callPhantom': ("window.callPhantom", "PhantomJS v2 detection"),
        r'domAutomation': ("window.domAutomation", "Chrome DevTools Protocol detection"),
        r'cdc_\w+': ("window.cdc_*", "ChromeDriver detection (CDP leak)"),
    }

    for pattern, (prop, desc) in automation_checks.items():
        if re.search(pattern, script, re.IGNORECASE):
            checks.append(ValidationCheck(
                property_name=prop,
                check_type="not_exists",
                description=desc,
            ))

    # Plugin count check
    if re.search(r'navigator\s*\.\s*plugins\s*\.\s*length', script):
        checks.append(ValidationCheck(
            property_name="navigator.plugins.length",
            check_type="greater_than",
            expected_value="0",
            description="Checks that browser has plugins (headless usually has 0)",
        ))

    # Languages check
    if re.search(r'navigator\s*\.\s*languages\s*\.\s*length', script):
        checks.append(ValidationCheck(
            property_name="navigator.languages.length",
            check_type="greater_than",
            expected_value="0",
            description="Checks that browser has language preferences set",
        ))

    return checks
