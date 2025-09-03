"""CLI entry point: python -m antibot"""

import argparse
import asyncio
import json
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="antibot",
        description="Anti-Bot Bypass Research Tool — detect, analyze, and fingerprint anti-bot systems",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a URL for anti-bot protection")
    scan_parser.add_argument("url", help="Target URL to scan")
    scan_parser.add_argument("--bypass", action="store_true", help="Attempt to bypass detected protection")
    scan_parser.add_argument("--browser", action="store_true", default=True, help="Use Playwright browser for bypass (default: on)")
    scan_parser.add_argument("--no-browser", action="store_true", help="Disable browser-based bypass, use synthetic only")
    scan_parser.add_argument("--proxy", help="Proxy URL (e.g. socks5://127.0.0.1:1080)")
    scan_parser.add_argument("--proxy-file", help="File with proxy list (one per line)")
    scan_parser.add_argument(
        "--export",
        choices=["curl", "python", "json", "all"],
        help="Export bypass cookies (curl command, Python code, JSON file, or all)",
    )
    scan_parser.add_argument(
        "--detectors",
        nargs="+",
        choices=["akamai", "perimeterx", "datadome", "kasada", "shape", "cloudflare", "custom"],
        help="Specific detectors to run (default: all)",
    )

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start the dashboard web server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    serve_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    # api command
    api_parser = subparsers.add_parser("api", help="Start the REST API server")
    api_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    api_parser.add_argument("--port", type=int, default=8001, help="Port to bind to")
    api_parser.add_argument("--key", help="API key for authentication")
    api_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    # session command
    session_parser = subparsers.add_parser("session", help="Manage bypass sessions")
    session_sub = session_parser.add_subparsers(dest="session_command")

    session_sub.add_parser("list", help="List all sessions")

    session_get = session_sub.add_parser("get", help="Get cookies for a domain")
    session_get.add_argument("domain", help="Domain to get session for")
    session_get.add_argument("--export", choices=["curl", "python", "json"], help="Export format")

    session_refresh = session_sub.add_parser("refresh", help="Re-bypass and refresh a session")
    session_refresh.add_argument("domain", help="Domain to refresh")
    session_refresh.add_argument("--proxy", help="Proxy URL for refresh")

    session_delete = session_sub.add_parser("delete", help="Delete sessions for a domain")
    session_delete.add_argument("domain", help="Domain to delete sessions for")

    # fingerprint command
    fp_parser = subparsers.add_parser("fingerprint", help="Collect or compare browser fingerprints")
    fp_parser.add_argument("--collect", action="store_true", help="Collect a real browser fingerprint")
    fp_parser.add_argument("--compare", nargs=2, type=int, metavar=("BOT_ID", "REAL_ID"), help="Compare two fingerprints by ID")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Deobfuscate and analyze anti-bot scripts")
    analyze_parser.add_argument("url", help="URL to fetch and analyze protection scripts")
    analyze_parser.add_argument("--provider", help="Expected provider (akamai, kasada, etc.)")

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Compare browser vs bot network traffic")
    diff_parser.add_argument("url", help="URL to diff")
    diff_parser.add_argument("--proxy", help="Proxy URL")

    # tls command
    tls_parser = subparsers.add_parser("tls", help="Test TLS fingerprint")
    tls_parser.add_argument("--test", action="store_true", help="Test your TLS fingerprint live")
    tls_parser.add_argument("--proxy", help="Proxy URL")

    # replay command
    replay_parser = subparsers.add_parser("replay", help="Record and replay challenge flows")
    replay_sub = replay_parser.add_subparsers(dest="replay_command")
    replay_record = replay_sub.add_parser("record", help="Record a challenge flow")
    replay_record.add_argument("url", help="URL to record")
    replay_test = replay_sub.add_parser("test", help="Test a field modification")
    replay_test.add_argument("recording_id", type=int, help="Recording ID")
    replay_test.add_argument("--field", required=True, help="Field to modify")
    replay_test.add_argument("--value", required=True, help="New value for the field")

    # mutate command
    mutate_parser = subparsers.add_parser("mutate", help="Test which fingerprint fields trigger detection")
    mutate_parser.add_argument("url", help="URL to test against")
    mutate_parser.add_argument("--proxy", help="Proxy URL")

    # profile command
    profile_parser = subparsers.add_parser("profile", help="Manage browser profiles")
    profile_sub = profile_parser.add_subparsers(dest="profile_command")
    profile_sub.add_parser("list", help="List all profiles")
    profile_create = profile_sub.add_parser("create", help="Create a new profile")
    profile_create.add_argument("name", help="Profile name")
    profile_delete = profile_sub.add_parser("delete", help="Delete a profile")
    profile_delete.add_argument("name", help="Profile name")

    # batch command
    batch_parser = subparsers.add_parser("batch", help="Batch scan multiple URLs")
    batch_parser.add_argument("urls_file", help="File with one URL per line")
    batch_parser.add_argument("--bypass", action="store_true", help="Attempt bypass")
    batch_parser.add_argument("--concurrency", type=int, default=5, help="Max concurrent scans")
    batch_parser.add_argument("--output", help="Output JSON file for results")
    batch_parser.add_argument("--proxy-file", help="Proxy list file")

    # webhook command
    webhook_parser = subparsers.add_parser("webhook", help="Manage webhook alerts")
    webhook_sub = webhook_parser.add_subparsers(dest="webhook_command")
    webhook_sub.add_parser("list", help="List webhooks")
    webhook_add = webhook_sub.add_parser("add", help="Add a webhook")
    webhook_add.add_argument("url", help="Webhook URL")
    webhook_add.add_argument("--events", nargs="+", required=True, help="Events to subscribe to")
    webhook_del = webhook_sub.add_parser("delete", help="Delete a webhook")
    webhook_del.add_argument("id", type=int, help="Webhook ID")

    # monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Watch a domain for protection changes")
    monitor_parser.add_argument("domain", help="Domain to monitor")
    monitor_parser.add_argument("--interval", type=int, default=60, help="Check interval in minutes")
    monitor_parser.add_argument("--proxy", help="Proxy URL")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        asyncio.run(run_scan(args))
    elif args.command == "serve":
        run_serve(args)
    elif args.command == "api":
        run_api(args)
    elif args.command == "session":
        asyncio.run(run_session(args))
    elif args.command == "fingerprint":
        asyncio.run(run_fingerprint(args))
    elif args.command == "analyze":
        asyncio.run(run_analyze(args))
    elif args.command == "diff":
        asyncio.run(run_diff(args))
    elif args.command == "tls":
        asyncio.run(run_tls(args))
    elif args.command == "replay":
        asyncio.run(run_replay(args))
    elif args.command == "mutate":
        asyncio.run(run_mutate(args))
    elif args.command == "profile":
        run_profile(args)
    elif args.command == "batch":
        asyncio.run(run_batch(args))
    elif args.command == "webhook":
        asyncio.run(run_webhook(args))
    elif args.command == "monitor":
        asyncio.run(run_monitor(args))


async def run_scan(args):
    """Execute a detection scan."""
    from antibot.database import init_db
    from antibot.detector.engine import DetectionEngine

    await init_db()

    # Setup proxy
    proxy = args.proxy
    if args.proxy_file:
        from antibot.utils.proxy import ProxyManager
        pm = ProxyManager(proxy_file=args.proxy_file)
        proxy = pm.get_next()
        if proxy:
            print(f"[*] Using proxy: {proxy}")

    engine = DetectionEngine()

    print(f"\n[*] Scanning: {args.url}")
    print("-" * 60)

    results = await engine.scan(args.url, detectors=args.detectors, proxy=proxy)

    if not results:
        print("[!] No anti-bot protection detected.")
        return

    for result in results:
        filled = int(result.confidence * 20)
        confidence_bar = "#" * filled + "-" * (20 - filled)
        print(f"\n[+] {result.provider.upper()}")
        print(f"    Confidence: [{confidence_bar}] {result.confidence:.0%}")
        for ev in result.evidence:
            print(f"    - {ev.description}")
            if ev.value:
                print(f"      > {ev.value}")
        if result.script_urls:
            print(f"    Scripts: {', '.join(result.script_urls[:3])}")
        if result.cookies_found:
            print(f"    Cookies: {', '.join(result.cookies_found)}")

    if args.bypass:
        use_browser = not args.no_browser
        print("\n" + "-" * 60)
        print(f"[*] Attempting bypass ({'browser' if use_browser else 'synthetic'} mode)...")
        from antibot.solver.engine import SolverEngine

        solver = SolverEngine()
        for result in results:
            solve_result = await solver.solve(args.url, result, use_browser=use_browser)
            if solve_result.success:
                print(f"[+] {result.provider.upper()} bypass SUCCESS ({solve_result.duration_ms}ms)")
                for name, value in solve_result.cookies.items():
                    display_val = value[:80] + "..." if len(value) > 80 else value
                    print(f"    {name} = {display_val}")

                # Auto-save session
                from urllib.parse import urlparse

                from antibot.session import SessionManager
                sm = SessionManager()
                domain = urlparse(args.url).netloc
                await sm.save(domain, solve_result.cookies, result.provider, proxy)
                print(f"    [*] Session saved for {domain}")

                # Export cookies if requested
                if args.export and solve_result.cookies:
                    from antibot.utils.export import export_cookies

                    print("\n" + "-" * 60)
                    exported = export_cookies(args.url, solve_result.cookies, args.export)
                    print(exported)
            else:
                print(f"[-] {result.provider.upper()} bypass FAILED: {solve_result.error_message}")

    print()


def run_serve(args):
    """Start the dashboard server."""
    import uvicorn

    print(f"\n[*] Starting AntiBotLab dashboard at http://{args.host}:{args.port}")
    uvicorn.run(
        "antibot.dashboard.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def run_api(args):
    """Start the API server."""
    import uvicorn

    from antibot.config import settings

    if args.key:
        settings.api_key = args.key

    print(f"\n[*] Starting AntiBotLab API at http://{args.host}:{args.port}")
    if settings.api_key:
        print(f"    API key required: X-API-Key header")
    else:
        print(f"    No API key set (open access)")
    uvicorn.run(
        "antibot.api:create_api",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


async def run_session(args):
    """Manage bypass sessions."""
    from antibot.database import init_db

    await init_db()

    from antibot.session import SessionManager

    sm = SessionManager()

    if args.session_command == "list":
        sessions = await sm.list_sessions()
        if not sessions:
            print("[!] No sessions found.")
            return

        print(f"\n{'ID':>4}  {'Domain':<30}  {'Provider':<15}  {'Status':<10}  {'Cookies':>7}  {'Expires':<20}")
        print("-" * 100)
        for s in sessions:
            status_color = s["status"]
            print(f"{s['id']:>4}  {s['domain']:<30}  {s['provider'] or '-':<15}  {status_color:<10}  {s['cookie_count']:>7}  {s['expires_at']:<20}")

    elif args.session_command == "get":
        cookies = await sm.load(args.domain)
        if not cookies:
            print(f"[!] No active session for {args.domain}")
            return

        if args.export:
            from antibot.utils.export import export_cookies

            url = f"https://{args.domain}/"
            exported = export_cookies(url, cookies, args.export)
            print(exported)
        else:
            print(f"\n[+] Session for {args.domain} ({len(cookies)} cookies)")
            for name, value in cookies.items():
                display_val = value[:80] + "..." if len(value) > 80 else value
                print(f"    {name} = {display_val}")

    elif args.session_command == "refresh":
        print(f"[*] Refreshing session for {args.domain}...")
        proxy = getattr(args, "proxy", None)
        cookies = await sm.refresh(args.domain, proxy=proxy)
        if cookies:
            print(f"[+] Session refreshed ({len(cookies)} cookies)")
        else:
            print(f"[-] Failed to refresh session for {args.domain}")

    elif args.session_command == "delete":
        deleted = await sm.delete(args.domain)
        if deleted:
            print(f"[+] Sessions deleted for {args.domain}")
        else:
            print(f"[!] No sessions found for {args.domain}")

    else:
        print("[!] Specify: list, get, refresh, or delete")


async def run_fingerprint(args):
    """Collect or compare fingerprints."""
    from antibot.database import init_db

    await init_db()

    if args.collect:
        from antibot.fingerprint.collector import FingerprintCollector

        collector = FingerprintCollector()
        print("[*] Collecting real browser fingerprint via Playwright...")
        fp = await collector.collect_real_fingerprint()
        print(f"[+] Fingerprint collected (ID: {fp.id})")
        print(f"    User-Agent: {fp.user_agent}")
        print(f"    Platform: {fp.platform}")
        print(f"    Screen: {fp.screen_width}x{fp.screen_height}")
        print(f"    Canvas hash: {fp.canvas_hash}")
        print(f"    WebGL: {fp.webgl_vendor} / {fp.webgl_renderer}")
    elif args.compare:
        from antibot.fingerprint.comparator import FingerprintComparator

        comparator = FingerprintComparator()
        report = await comparator.compare_by_ids(args.compare[0], args.compare[1])
        filled = int(report.risk_score * 20)
        risk_bar = "#" * filled + "-" * (20 - filled)
        print(f"\n[*] Fingerprint Comparison")
        print(f"    Risk Score: [{risk_bar}] {report.risk_score:.0%}")
        print(f"    Mismatches: {len(report.mismatches)}")
        for m in report.mismatches:
            print(f"    [{m.severity.upper():8s}] {m.field}: {m.bot_value} vs {m.real_value}")
    else:
        print("[!] Specify --collect or --compare")


async def run_analyze(args):
    """Deobfuscate and analyze anti-bot scripts."""
    from antibot.analyzer.deobfuscator import ScriptDeobfuscator
    from antibot.utils.http import fetch_page

    print(f"[*] Fetching {args.url}...")
    _, page_source = await fetch_page(args.url)

    # Find and fetch protection scripts
    import re
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', page_source)

    deob = ScriptDeobfuscator()
    provider = args.provider or "unknown"

    # Also analyze inline scripts
    inline_scripts = re.findall(r'<script[^>]*>([\s\S]{500,}?)</script>', page_source)
    for i, script in enumerate(inline_scripts[:3]):
        print(f"\n[*] Analyzing inline script #{i+1} ({len(script)} bytes)...")
        result = deob.deobfuscate(script)
        _print_analysis(result, provider)

    # Fetch and analyze external scripts (first 3)
    for script_url in scripts[:3]:
        if any(skip in script_url for skip in ["google", "facebook", "analytics", "gtag", "gtm"]):
            continue
        try:
            if script_url.startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(args.url)
                script_url = f"{parsed.scheme}://{parsed.netloc}{script_url}"
            print(f"\n[*] Fetching script: {script_url[:80]}...")
            _, script_content = await fetch_page(script_url)
            result = deob.deobfuscate(script_content)
            if result.browser_checks:  # Only show if it's doing fingerprinting
                _print_analysis(result, provider)
        except Exception as e:
            print(f"    [!] Failed: {e}")


def _print_analysis(result, provider):
    """Print deobfuscation analysis results."""
    print(f"    Size: {result.original_size} -> {result.cleaned_size} bytes ({result.strings_decoded} strings decoded)")
    if result.config:
        print(f"    Config: {json.dumps(result.config, indent=2)[:500]}" if hasattr(result.config, '__len__') else "")
        import json
        for k, v in result.config.items():
            if isinstance(v, list):
                print(f"    {k}: {len(v)} items")
            else:
                val = str(v)[:80]
                print(f"    {k}: {val}")
    if result.browser_checks:
        print(f"    Browser checks ({len(result.browser_checks)}):")
        for check in result.browser_checks:
            print(f"      - {check}")
    if result.post_targets:
        print(f"    POST targets:")
        for target in result.post_targets:
            print(f"      > {target}")


async def run_diff(args):
    """Compare browser vs bot network traffic."""
    from antibot.analyzer.network import NetworkAnalyzer

    analyzer = NetworkAnalyzer()
    proxy = getattr(args, "proxy", None)

    print(f"[*] Capturing real browser traffic for {args.url}...")
    browser_capture = await analyzer.capture_real_browser(args.url, proxy=proxy)
    print(f"    {len(browser_capture.requests)} requests captured")

    print(f"[*] Capturing bot client traffic for {args.url}...")
    bot_capture = await analyzer.capture_bot_client(args.url, proxy=proxy)
    print(f"    {len(bot_capture.requests)} requests captured")

    diff = analyzer.diff(browser_capture, bot_capture)
    print(diff.report())


async def run_tls(args):
    """Test TLS fingerprint."""
    from antibot.fingerprint.tls_live import TLSLiveTester

    tester = TLSLiveTester()
    proxy = getattr(args, "proxy", None)

    print("[*] Testing curl_cffi TLS fingerprint...")
    curl_result = await tester.test_curl_cffi(proxy=proxy)
    curl_comp = tester.compare_to_chrome(curl_result)

    print(f"\n  curl_cffi (chrome131 impersonation):")
    print(f"    JA3:  {curl_result.ja3_hash or 'unknown'}")
    print(f"    JA4:  {curl_result.ja4 or 'unknown'}")
    print(f"    HTTP: {curl_result.http_version or 'unknown'}")
    print(f"    Risk: {curl_comp.risk_level.upper()}")
    for d in curl_comp.details:
        print(f"    - {d}")

    print("\n[*] Testing Playwright TLS fingerprint...")
    pw_result = await tester.test_playwright(proxy=proxy)
    pw_comp = tester.compare_to_chrome(pw_result)

    print(f"\n  Playwright (Chromium):")
    print(f"    JA3:  {pw_result.ja3_hash or 'unknown'}")
    print(f"    JA4:  {pw_result.ja4 or 'unknown'}")
    print(f"    HTTP: {pw_result.http_version or 'unknown'}")
    print(f"    Risk: {pw_comp.risk_level.upper()}")
    for d in pw_comp.details:
        print(f"    - {d}")


async def run_replay(args):
    """Record or replay challenge flows."""
    from antibot.database import init_db
    await init_db()

    if args.replay_command == "record":
        from antibot.analyzer.replay import ChallengeRecorder
        recorder = ChallengeRecorder()
        print(f"[*] Recording challenge flow for {args.url}...")
        recording = await recorder.record(args.url)
        print(f"[+] Recording #{recording.id}: {len(recording.requests)} requests, {recording.total_duration_ms}ms")
        print(f"    Provider: {recording.provider or 'unknown'}")
        print(f"    Cookies before: {len(recording.cookies_before)}, after: {len(recording.cookies_after)}")

    elif args.replay_command == "test":
        from antibot.analyzer.replay import ChallengeReplayer
        replayer = ChallengeReplayer()
        print(f"[*] Testing field '{args.field}' = '{args.value}' on recording #{args.recording_id}...")
        result = replayer.test_field(args.recording_id, args.field, args.value)
        if result.success:
            print(f"[+] NOT blocked — field '{args.field}' is not validated")
        else:
            print(f"[-] BLOCKED — field '{args.field}' is checked! ({result.error or 'blocked'})")

    else:
        print("[!] Specify: record or test")


async def run_mutate(args):
    """Run fingerprint mutation tests."""
    from antibot.fingerprint.mutator import FingerprintMutator

    mutator = FingerprintMutator()
    proxy = getattr(args, "proxy", None)

    print(f"[*] Running fingerprint mutation tests on {args.url}...")
    print(f"    This will launch ~12 browser instances. May take a few minutes.\n")

    report = await mutator.test_all_fields(args.url, proxy=proxy)
    print(report.summary())

    print(f"\nDetailed results:")
    for r in report.results:
        status = "BLOCKED" if r["blocked"] else "OK"
        print(f"  [{status:7s}] {r['field']:<25s} ({r['mutation']})")


def run_profile(args):
    """Manage browser profiles."""
    from antibot.profiles.manager import ProfileManager

    pm = ProfileManager()

    if args.profile_command == "create":
        profile = pm.create(args.name)
        print(f"[+] Profile '{profile.name}' created")
        print(f"    Screen: {profile.screen_width}x{profile.screen_height}")
        print(f"    GPU: {profile.webgl_renderer[:60]}")
        print(f"    TZ: {profile.timezone}")
        print(f"    Cores: {profile.hardware_concurrency}, RAM: {profile.device_memory}GB")
        print(f"    Canvas seed: {profile.canvas_seed}")

    elif args.profile_command == "list":
        profiles = pm.list()
        if not profiles:
            print("[!] No profiles found.")
            return
        print(f"\n{'Name':<20}  {'Screen':<12}  {'GPU':<40}  {'TZ':<20}")
        print("-" * 95)
        for p in profiles:
            print(f"{p.name:<20}  {p.screen_width}x{p.screen_height:<5}  {p.webgl_renderer[:38]:<40}  {p.timezone:<20}")

    elif args.profile_command == "delete":
        if pm.delete(args.name):
            print(f"[+] Profile '{args.name}' deleted")
        else:
            print(f"[!] Profile '{args.name}' not found")

    else:
        print("[!] Specify: create, list, or delete")


async def run_batch(args):
    """Batch scan multiple URLs."""
    from pathlib import Path

    from antibot.database import init_db
    from antibot.distributed.coordinator import ScanCoordinator, ScanOptions

    await init_db()

    urls_path = Path(args.urls_file)
    if not urls_path.exists():
        print(f"[!] File not found: {args.urls_file}")
        return

    urls = [line.strip() for line in urls_path.read_text().splitlines() if line.strip() and not line.startswith("#")]
    print(f"[*] Batch scanning {len(urls)} URLs (concurrency: {args.concurrency})")

    coordinator = ScanCoordinator()
    options = ScanOptions(
        bypass=args.bypass,
        proxy_file=args.proxy_file,
    )

    job = await coordinator.submit_batch(urls, options, concurrency=args.concurrency)

    print(f"\n[+] Batch {job.id} completed: {job.completed}/{job.total} succeeded, {job.failed} failed")

    for result in job.results:
        providers = ", ".join(d["provider"] for d in result.detections) or "none"
        bypass_status = ""
        if result.bypass_results:
            bypass_ok = any(b["success"] for b in result.bypass_results)
            bypass_status = " [BYPASS OK]" if bypass_ok else " [BYPASS FAIL]"
        status_icon = "+" if result.status == "completed" else "-"
        print(f"  [{status_icon}] {result.url:<50} {providers}{bypass_status}")

    if args.output:
        coordinator.save_results(job.id, args.output)
        print(f"\n[*] Results saved to {args.output}")


async def run_webhook(args):
    """Manage webhooks."""
    from antibot.database import init_db
    await init_db()

    from antibot.alerts.webhook import WebhookManager
    wm = WebhookManager()

    if args.webhook_command == "add":
        webhook_id = await wm.register(args.url, args.events)
        print(f"[+] Webhook #{webhook_id} registered: {args.url}")
        print(f"    Events: {', '.join(args.events)}")

    elif args.webhook_command == "list":
        webhooks = await wm.list_webhooks()
        if not webhooks:
            print("[!] No webhooks registered.")
            return
        print(f"\n{'ID':>4}  {'URL':<50}  {'Events':<40}  {'Active'}")
        print("-" * 100)
        for w in webhooks:
            events_str = ", ".join(w["events"])
            print(f"{w['id']:>4}  {w['url'][:48]:<50}  {events_str[:38]:<40}  {w['active']}")

    elif args.webhook_command == "delete":
        if await wm.delete(args.id):
            print(f"[+] Webhook #{args.id} deleted")
        else:
            print(f"[!] Webhook #{args.id} not found")

    else:
        print("[!] Specify: add, list, or delete")


async def run_monitor(args):
    """Watch a domain for protection changes."""
    from antibot.alerts.monitor import ProtectionMonitor

    monitor = ProtectionMonitor()
    print(f"[*] Monitoring {args.domain} every {args.interval} minutes (Ctrl+C to stop)")
    proxy = getattr(args, "proxy", None)

    try:
        await monitor.watch(args.domain, interval_minutes=args.interval, proxy=proxy)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")


if __name__ == "__main__":
    main()
