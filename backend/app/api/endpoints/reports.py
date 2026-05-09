"""Dashboard reports endpoint — aggregated stats for the UI."""
from typing import Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.db.session import get_db
from app.db.models import (
    Finding, OffensiveMission, ActorCluster, TelemetryEvent,
    DeceptionEvent, DetectionDraft, RemediationTicket, Asset
)

router = APIRouter()

@router.get("/dashboard")
async def dashboard_summary(tenant_id: str = Query(...),
                            db: AsyncSession = Depends(get_db)) -> Any:
    """Aggregated dashboard statistics."""

    async def count(model, *filters):
        r = await db.execute(select(func.count()).select_from(model).where(*filters))
        return r.scalar()

    findings_total = await count(Finding, Finding.tenant_id == tenant_id)
    findings_open = await count(Finding, Finding.tenant_id == tenant_id,
                                Finding.status == "open")
    critical = await count(Finding, Finding.tenant_id == tenant_id,
                           Finding.risk_level == "critical")
    high = await count(Finding, Finding.tenant_id == tenant_id,
                       Finding.risk_level == "high")
    missions = await count(OffensiveMission, OffensiveMission.tenant_id == tenant_id)
    clusters = await count(ActorCluster, ActorCluster.tenant_id == tenant_id)
    telemetry = await count(TelemetryEvent, TelemetryEvent.tenant_id == tenant_id)
    deception_events = await count(DeceptionEvent, DeceptionEvent.tenant_id == tenant_id)
    drafts = await count(DetectionDraft, DetectionDraft.tenant_id == tenant_id)
    tickets = await count(RemediationTicket, RemediationTicket.tenant_id == tenant_id)
    assets = await count(Asset, Asset.tenant_id == tenant_id)

    return {
        "tenant_id": tenant_id,
        "findings": {"total": findings_total, "open": findings_open,
                     "critical": critical, "high": high},
        "offensive_missions": missions,
        "actor_clusters": clusters,
        "telemetry_events": telemetry,
        "deception_events": deception_events,
        "detection_drafts": drafts,
        "remediation_tickets": tickets,
        "assets": assets,
        "risk_posture": "critical" if critical > 0 else ("high" if high > 0 else "medium"),
    }
