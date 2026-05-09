"""Central API router — mounts all sub-routers."""

from fastapi import APIRouter, Depends

from app.api.endpoints import (
    auth,
    tenants,
    assets,
    engagements,
    missions,
    telemetry,
    clusters,
    attack_paths,
    findings,
    deception,
    detections,
    remediation,
    audit,
    reports,
)
from app.core.deps import get_current_user

api_router = APIRouter()

# ─── Public routes (no auth required) ────────────────────────────────────────
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])

# ─── Authenticated routes (JWT required for every endpoint) ──────────────────
# All routes below require a valid Bearer JWT.  The tenant_id for data scoping
# is ALWAYS sourced from the JWT payload — never from query parameters.
_auth = Depends(get_current_user)

api_router.include_router(tenants.router,     prefix="/tenants",     tags=["Tenants"],            dependencies=[_auth])
api_router.include_router(assets.router,      prefix="/assets",      tags=["Assets"],             dependencies=[_auth])
api_router.include_router(engagements.router, prefix="/engagements", tags=["Engagements"],        dependencies=[_auth])
api_router.include_router(missions.router,    prefix="/missions",    tags=["Offensive Missions"], dependencies=[_auth])
api_router.include_router(telemetry.router,   prefix="/telemetry",   tags=["Telemetry"],          dependencies=[_auth])
api_router.include_router(clusters.router,    prefix="/clusters",    tags=["Actor Clusters"],     dependencies=[_auth])
api_router.include_router(attack_paths.router,prefix="/attack-paths",tags=["Attack Paths"],      dependencies=[_auth])
api_router.include_router(findings.router,    prefix="/findings",    tags=["Findings"],           dependencies=[_auth])
api_router.include_router(deception.router,   prefix="/deception",   tags=["Deception"],          dependencies=[_auth])
api_router.include_router(detections.router,  prefix="/detections",  tags=["Detection Drafts"],  dependencies=[_auth])
api_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation"],        dependencies=[_auth])
api_router.include_router(audit.router,       prefix="/audit",       tags=["Audit"],              dependencies=[_auth])
api_router.include_router(reports.router,     prefix="/reports",     tags=["Reports"],            dependencies=[_auth])
