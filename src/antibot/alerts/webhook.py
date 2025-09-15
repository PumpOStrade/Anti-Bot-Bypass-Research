"""Webhook notification system — fire events to registered URLs."""

import asyncio
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

VALID_EVENTS = [
    "bypass.success",
    "bypass.failed",
    "session.expired",
    "protection.changed",
    "batch.completed",
]


class WebhookManager:
    """Register and fire webhook notifications."""

    async def register(self, url: str, events: list[str]) -> int:
        """Register a webhook URL for specific events."""
        from antibot.database import async_session
        from antibot.models import Webhook

        # Validate events
        for event in events:
            if event not in VALID_EVENTS:
                raise ValueError(f"Invalid event: {event}. Valid: {VALID_EVENTS}")

        webhook = Webhook(
            url=url,
            events=json.dumps(events),
            created_at=datetime.utcnow(),
            active=True,
        )

        async with async_session() as session:
            session.add(webhook)
            await session.commit()
            await session.refresh(webhook)
            logger.info(f"[Webhook] Registered #{webhook.id}: {url} for {events}")
            return webhook.id

    async def fire(self, event: str, data: dict):
        """Send POST to all registered webhooks for this event."""
        from sqlalchemy import select

        from antibot.database import async_session
        from antibot.models import Webhook

        async with async_session() as session:
            result = await session.execute(
                select(Webhook).where(Webhook.active == True)
            )
            webhooks = result.scalars().all()

        payload = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data,
        }

        for webhook in webhooks:
            events = json.loads(webhook.events)
            if event not in events:
                continue

            # Fire with retry
            asyncio.create_task(self._send_with_retry(webhook.url, payload))

    async def _send_with_retry(self, url: str, payload: dict, max_retries: int = 3):
        """Send webhook with exponential backoff retry."""
        from antibot.utils.http import create_client

        for attempt in range(max_retries):
            try:
                async with create_client() as client:
                    response = await client.post(
                        url,
                        data=json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                    )
                    if response.status_code < 400:
                        logger.info(f"[Webhook] Sent to {url}: {payload['event']}")
                        return
                    logger.warning(f"[Webhook] {url} returned {response.status_code}")
            except Exception as e:
                logger.warning(f"[Webhook] Attempt {attempt + 1} failed for {url}: {e}")

            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff

        logger.error(f"[Webhook] Failed to deliver to {url} after {max_retries} attempts")

    async def list_webhooks(self) -> list[dict]:
        """List all registered webhooks."""
        from sqlalchemy import select

        from antibot.database import async_session
        from antibot.models import Webhook

        async with async_session() as session:
            result = await session.execute(select(Webhook).order_by(Webhook.created_at.desc()))
            webhooks = result.scalars().all()

            return [
                {
                    "id": w.id,
                    "url": w.url,
                    "events": json.loads(w.events),
                    "active": w.active,
                    "created_at": w.created_at.strftime("%Y-%m-%d %H:%M:%S") if w.created_at else "",
                }
                for w in webhooks
            ]

    async def delete(self, webhook_id: int) -> bool:
        """Delete a webhook."""
        from sqlalchemy import delete

        from antibot.database import async_session
        from antibot.models import Webhook

        async with async_session() as session:
            result = await session.execute(delete(Webhook).where(Webhook.id == webhook_id))
            await session.commit()
            return result.rowcount > 0
