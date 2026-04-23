"""CIDAS daemon entry point."""
from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .router import router
from .utils.logger import get_logger

log = get_logger(__name__)

app = FastAPI(
    title="CIDAS Daemon",
    description="Pre-install npm package security screening",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["vscode-webview://*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.on_event("startup")
async def _startup() -> None:
    log.info("CIDAS daemon starting on %s:%s", settings.daemon_host, settings.daemon_port)
    await init_db()
    log.info("SQLite cache initialised at %s", settings.sqlite_db_path)


@app.on_event("shutdown")
async def _shutdown() -> None:
    log.info("CIDAS daemon shutting down")


def start() -> None:
    uvicorn.run(
        "daemon.main:app",
        host=settings.daemon_host,
        port=settings.daemon_port,
        log_level=settings.daemon_log_level,
        reload=False,
    )


if __name__ == "__main__":
    start()
