"""Protection monitor — watch sites for protection changes and session expiry."""

import asyncio
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ProtectionMonitor:
    """Periodically re-scan domains and alert on changes."""

    def __init__(self):
        self._watching: dict[str, dict] = {}  # domain -> last detection state

    async def watch(self, domain: str, interval_minutes: int = 60, proxy: str | None = None):
        """Continuously monitor a domain for protection changes.

        Runs until cancelled. Fires webhooks on changes.
        """
        url = f"https://{domain}/"
        logger.info(f"[Monitor] Watching {domain} every {interval_minutes}m")

        from antibot.database import init_db
        await init_db()

        while True:
            try:
                await self._check_domain(url, domain, proxy)
            except Exception as e:
                logger.error(f"[Monitor] Error checking {domain}: {e}")

            await asyncio.sleep(interval_minutes * 60)

    async def _check_domain(self, url: str, domain: str, proxy: str | None):
        """Run a single check on a domain."""
        from antibot.detector.engine import DetectionEngine

        engine = DetectionEngine()
        results = await engine.scan(url, proxy=proxy, save=False)

        current_state = {
            r.provider: round(r.confidence, 2) for r in results
        }

        previous_state = self._watching.get(domain)

        if previous_state is not None and current_state != previous_state:
            # Protection changed!
            logger.warning(f"[Monitor] Protection changed for {domain}: {previous_state} -> {current_state}")

            from antibot.alerts.webhook import WebhookManager
            wm = WebhookManager()
            await wm.fire("protection.changed", {
                "domain": domain,
                "previous": previous_state,
                "current": current_state,
                "timestamp": datetime.utcnow().isoformat(),
            })

        self._watching[domain] = current_state

        # Also check session expiry
        from antibot.session import SessionManager
        sm = SessionManager()
        if await sm.is_expired(domain):
            from antibot.alerts.webhook import WebhookManager
            wm = WebhookManager()
            await wm.fire("session.expired", {
                "domain": domain,
                "timestamp": datetime.utcnow().isoformat(),
            })
