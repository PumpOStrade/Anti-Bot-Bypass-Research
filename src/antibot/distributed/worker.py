"""Scan worker — picks up jobs and executes them."""

import logging

logger = logging.getLogger(__name__)


# The coordinator handles worker logic internally via asyncio tasks.
# This module exists as an extension point for future remote worker support.

class ScanWorker:
    """Worker that processes scan jobs.

    Currently runs in-process via the coordinator's asyncio pool.
    Can be extended for remote worker support (Redis queue, etc.).
    """

    def __init__(self, worker_id: str = "local"):
        self.worker_id = worker_id
        self.jobs_completed = 0
        self.jobs_failed = 0

    async def process(self, url: str, options: dict) -> dict:
        """Process a single scan job."""
        from antibot.distributed.coordinator import ScanCoordinator, ScanOptions

        coord = ScanCoordinator()
        opts = ScanOptions(**options)
        result = await coord._scan_single(url, opts, options.get("proxy"))

        if result.status == "completed":
            self.jobs_completed += 1
        else:
            self.jobs_failed += 1

        return {
            "url": result.url,
            "status": result.status,
            "detections": result.detections,
            "error": result.error,
        }
