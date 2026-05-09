"""AegisTwin main FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.api.router import api_router

app = FastAPI(
    title="AegisTwin",
    description=(
        "Dual-agent cybersecurity platform: Offensive Red-Team AI + Defensive Hunter AI "
        "sharing a Company Digital Twin and Attack Path Graph."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount versioned API router
app.include_router(api_router, prefix="/api/v1")


@app.get("/health", tags=["health"])
async def health_check() -> JSONResponse:
    """Liveness probe."""
    return JSONResponse({"status": "ok", "service": "AegisTwin"})
