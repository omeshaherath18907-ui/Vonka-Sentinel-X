from datetime import datetime, timezone

from fastapi import FastAPI

APP_NAME = "VONKA SENTINEL-X"
APP_VERSION = "0.1.0"

api = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Local defensive network monitoring foundation.",
    docs_url=None,
    redoc_url=None,
)


@api.get("/")
def root():
    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "message": "Local backend is running.",
    }


@api.get("/health")
def health():
    return {
        "status": "healthy",
        "application": APP_NAME,
        "version": APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
