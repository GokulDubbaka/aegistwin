"""
Telemetry Ingestion API
========================
POST /telemetry/ingest       — Ingest one event
POST /telemetry/ingest/bulk  — Ingest multiple events
GET  /telemetry/             — List events
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.db.models import TelemetryEvent, ActorCluster
from app.schemas.schemas import TelemetryEventCreate, TelemetryEventOut, ActorClusterOut
from app.agents.defensive.agent import (
    TelemetryIngestionAgent,
    ActorClusterBuilder,
    ForensicTimelineBuilder,
    IncidentResponseRecommender,
    DefensiveReportGenerator,
)
from app.detections.agent import DetectionEngineeringAgent

router = APIRouter()


@router.post("/ingest", response_model=TelemetryEventOut, status_code=201)
async def ingest_event(
    payload: TelemetryEventCreate,
    tenant_id: str = Query(..., description="Tenant ID"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Ingest a single telemetry event and run behavioral analysis."""
    ingestion = TelemetryIngestionAgent(tenant_id)
    normalized = ingestion.normalize(payload.model_dump())

    event = TelemetryEvent(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        source=normalized["source"],
        event_timestamp=datetime.fromisoformat(str(normalized["event_timestamp"])),
        actor_ip=normalized.get("actor_ip"),
        actor_asn=normalized.get("actor_asn"),
        actor_user_agent=normalized.get("actor_user_agent"),
        actor_ja3=normalized.get("actor_ja3"),
        actor_ja4=normalized.get("actor_ja4"),
        actor_account=normalized.get("actor_account"),
        target_asset_id=normalized.get("target_asset_id"),
        target_resource=normalized.get("target_resource"),
        target_endpoint=normalized.get("target_endpoint"),
        action=normalized.get("action"),
        raw_event=normalized.get("raw_event"),
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


@router.post("/ingest/bulk")
async def ingest_bulk(
    events: List[TelemetryEventCreate],
    tenant_id: str = Query(..., description="Tenant ID"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Bulk ingest telemetry events and run full defensive analysis pipeline.
    Returns an actor cluster if suspicious behavior is detected.
    """
    _MAX_BULK = 500
    if len(events) > _MAX_BULK:
        raise HTTPException(
            status_code=413,
            detail=f"Bulk ingest limit is {_MAX_BULK} events per request. Got {len(events)}.",
        )
    ingestion = TelemetryIngestionAgent(tenant_id)
    normalized_events = [ingestion.normalize(e.model_dump()) for e in events]

    # Persist all events
    db_events = []
    for n in normalized_events:
        event = TelemetryEvent(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            source=n["source"],
            event_timestamp=datetime.fromisoformat(str(n["event_timestamp"])),
            actor_ip=n.get("actor_ip"),
            actor_asn=n.get("actor_asn"),
            actor_user_agent=n.get("actor_user_agent"),
            actor_ja3=n.get("actor_ja3"),
            actor_ja4=n.get("actor_ja4"),
            actor_account=n.get("actor_account"),
            target_asset_id=n.get("target_asset_id"),
            target_resource=n.get("target_resource"),
            target_endpoint=n.get("target_endpoint"),
            action=n.get("action"),
            raw_event=n.get("raw_event"),
        )
        db.add(event)
        db_events.append(event)

    # Run defensive analysis
    cluster_builder = ActorClusterBuilder(tenant_id)
    cluster_data = cluster_builder.build_cluster(normalized_events)

    cluster = None
    if cluster_data.get("confidence", 0) > 0.3:
        # Persist the cluster
        cluster = ActorCluster(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            cluster_label=cluster_data["cluster_id"],
            confidence=cluster_data["confidence"],
            likely_automation=cluster_data["likely_automation"],
            likely_ai_assisted=cluster_data["likely_ai_assisted"],
            evidence=cluster_data["evidence"],
            recommended_actions=cluster_data["recommended_actions"],
            fingerprint=cluster_data["fingerprint"],
            event_count=len(normalized_events),
        )
        db.add(cluster)

    await db.commit()

    # Build forensic timeline and IR recommendations
    timeline = ForensicTimelineBuilder().build(normalized_events)
    ir = IncidentResponseRecommender().recommend(cluster_data)
    report = DefensiveReportGenerator().generate(cluster_data, timeline, ir)

    # Generate detection drafts if suspicious
    detection_drafts = []
    if cluster and cluster_data.get("confidence", 0) > 0.5:
        det_agent = DetectionEngineeringAgent()
        detection_drafts = det_agent.from_cluster(cluster_data, tenant_id)

    return {
        "events_ingested": len(db_events),
        "cluster": cluster_data,
        "cluster_id": cluster.id if cluster else None,
        "forensic_timeline": timeline[:10],
        "ir_recommendations": ir,
        "defensive_report": report,
        "detection_drafts_generated": len(detection_drafts),
    }


@router.get("/", response_model=List[TelemetryEventOut])
async def list_events(
    tenant_id: str = Query(...),
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(
        select(TelemetryEvent)
        .where(TelemetryEvent.tenant_id == tenant_id)
        .limit(limit)
    )
    return result.scalars().all()
