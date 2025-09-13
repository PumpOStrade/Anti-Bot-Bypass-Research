"""FastAPI application factory for the AntiBotLab dashboard."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from antibot.database import init_db

DASHBOARD_DIR = Path(__file__).parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def create_app() -> FastAPI:
    app = FastAPI(
        title="AntiBotLab",
        description="Anti-Bot Bypass Research Tool Dashboard",
        version="0.1.0",
    )

    # Mount static files
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Register routes
    from antibot.dashboard.routes import router
    app.include_router(router)

    @app.on_event("startup")
    async def startup():
        await init_db()

    return app
