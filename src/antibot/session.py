"""Session manager — save, load, refresh, and export bypass sessions."""

import json
import logging
from datetime import datetime, timedelta

from antibot.config import settings

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages bypass sessions with persistence and expiry."""

    async def save(
        self,
        domain: str,
        cookies: dict[str, str],
        provider: str | None = None,
        proxy_used: str | None = None,
        ttl_minutes: int | None = None,
    ) -> int:
        """Save a bypass session."""
        from antibot.database import async_session
        from antibot.models import Session

        ttl = ttl_minutes or settings.session_ttl_minutes
        now = datetime.utcnow()

        session_obj = Session(
            domain=domain,
            cookies=json.dumps(cookies),
            provider=provider,
            user_agent=settings.default_user_agent,
            proxy_used=proxy_used,
            created_at=now,
            expires_at=now + timedelta(minutes=ttl),
            status="active",
        )

        async with async_session() as db:
            db.add(session_obj)
            await db.commit()
            await db.refresh(session_obj)
            logger.info(f"[Session] Saved session for {domain} (ID: {session_obj.id}, TTL: {ttl}m)")
            return session_obj.id

    async def load(self, domain: str) -> dict | None:
        """Load the latest active session for a domain. Returns cookies dict or None."""
        from sqlalchemy import select

        from antibot.database import async_session
        from antibot.models import Session

        async with async_session() as db:
            result = await db.execute(
                select(Session)
                .where(Session.domain == domain, Session.status == "active")
                .order_by(Session.created_at.desc())
                .limit(1)
            )
            session_obj = result.scalar_one_or_none()

            if not session_obj:
                return None

            # Check expiry
            if session_obj.expires_at and session_obj.expires_at < datetime.utcnow():
                session_obj.status = "expired"
                await db.commit()
                return None

            return json.loads(session_obj.cookies)

    async def is_expired(self, domain: str) -> bool:
        """Check if the session for a domain is expired."""
        cookies = await self.load(domain)
        return cookies is None

    async def list_sessions(self) -> list[dict]:
        """List all sessions with their status."""
        from sqlalchemy import select

        from antibot.database import async_session
        from antibot.models import Session

        async with async_session() as db:
            result = await db.execute(select(Session).order_by(Session.created_at.desc()))
            sessions = result.scalars().all()

            now = datetime.utcnow()
            items = []
            for s in sessions:
                # Auto-update expired status
                if s.status == "active" and s.expires_at and s.expires_at < now:
                    s.status = "expired"

                items.append({
                    "id": s.id,
                    "domain": s.domain,
                    "provider": s.provider,
                    "status": s.status,
                    "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else "",
                    "expires_at": s.expires_at.strftime("%Y-%m-%d %H:%M:%S") if s.expires_at else "",
                    "cookie_count": len(json.loads(s.cookies)) if s.cookies else 0,
                    "proxy": s.proxy_used or "",
                })
            await db.commit()
            return items

    async def delete(self, domain: str) -> bool:
        """Delete all sessions for a domain."""
        from sqlalchemy import delete

        from antibot.database import async_session
        from antibot.models import Session

        async with async_session() as db:
            result = await db.execute(delete(Session).where(Session.domain == domain))
            await db.commit()
            return result.rowcount > 0

    async def refresh(self, domain: str, proxy: str | None = None) -> dict | None:
        """Re-run bypass for an expired session. Returns new cookies or None."""
        from antibot.database import init_db
        from antibot.detector.engine import DetectionEngine
        from antibot.solver.engine import SolverEngine

        await init_db()

        # Run detection
        url = f"https://{domain}/"
        engine = DetectionEngine()
        results = await engine.scan(url, proxy=proxy)

        if not results:
            logger.warning(f"[Session] No protection detected on {domain}, can't refresh")
            return None

        # Try bypass
        solver = SolverEngine()
        for detection in results:
            solve_result = await solver.solve(url, detection, use_browser=True)
            if solve_result.success and solve_result.cookies:
                # Save new session
                await self.save(
                    domain=domain,
                    cookies=solve_result.cookies,
                    provider=detection.provider,
                    proxy_used=proxy,
                )
                return solve_result.cookies

        return None
