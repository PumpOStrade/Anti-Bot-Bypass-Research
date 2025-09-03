# AntiBotLab — Anti-Bot Bypass Research Tool

**IMPORTANT: This tool is intended for authorized security research, penetration testing, and educational purposes only. Do not use this tool against systems without explicit written permission from the system owner. Unauthorized access to computer systems is illegal.**

## Overview

AntiBotLab detects, analyzes, and fingerprints anti-bot protection systems. It helps security researchers understand how anti-bot systems work and evaluate their effectiveness.

### Features

- **Detection Engine** — Identifies which anti-bot protection a site uses:
  - Akamai Bot Manager
  - PerimeterX (HUMAN Security)
  - DataDome
  - Kasada
  - Shape Security (F5)

- **Solver Modules** — Generates valid sensor data and challenge responses:
  - Full Akamai `_abck` cookie generation flow
  - DataDome, PerimeterX, Kasada, and Shape solvers

- **Fingerprint Comparison** — Compares bot vs real browser fingerprints:
  - TLS fingerprint analysis (JA3/JA4)
  - Canvas, WebGL, navigator property comparison
  - Automation indicator detection
  - Risk scoring with severity levels

- **Dashboard** — Web-based UI showing:
  - Protection distribution across scanned sites
  - Bypass success rates by provider
  - Scan history with detailed results
  - Side-by-side fingerprint comparison

## Installation

```bash
# Clone the repo
cd antibot

# Install in development mode
pip install -e ".[dev]"

# Install Playwright browsers (for fingerprint collection)
playwright install chromium
```

## Usage

### CLI

```bash
# Scan a URL for anti-bot protection
python -m antibot scan https://example.com

# Scan and attempt bypass
python -m antibot scan https://example.com --bypass

# Scan with specific detectors only
python -m antibot scan https://example.com --detectors akamai datadome

# Start the dashboard
python -m antibot serve
python -m antibot serve --port 9000

# Collect a real browser fingerprint
python -m antibot fingerprint --collect

# Compare two fingerprints
python -m antibot fingerprint --compare 1 2
```

### Dashboard

Start the web dashboard:

```bash
python -m antibot serve
```

Open http://127.0.0.1:8000 in your browser.

## Project Structure

```
src/antibot/
├── detector/     # Anti-bot detection modules (one per provider)
├── solver/       # Bypass/solver modules (sensor data generation)
├── fingerprint/  # Browser fingerprint collection and comparison
├── dashboard/    # FastAPI web dashboard
└── utils/        # HTTP client, crypto, encoding helpers
```

## Legal Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse of this tool. Users are solely responsible for ensuring they have proper authorization before testing any system.

By using this tool, you agree to:
1. Only test systems you own or have written permission to test
2. Comply with all applicable laws and regulations
3. Use the tool responsibly and ethically
