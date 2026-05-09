"""
Offensive Missions API
=======================
POST /missions/           — Create mission
POST /missions/{id}/run   — Run mission (returns full attack path report)
GET  /missions/           — List missions
GET  /missions/{id}       — Get mission + report
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.db.models import OffensiveMission, Engagement, Asset, Finding
from app.schemas.schemas import MissionCreate, MissionOut
from app.agents.offensive.agent import OffensiveMissionPlanner
from app.risk.engine import RiskFactors, risk_engine
from app.remediation.agent import remediation_agent
from app.detections.agent import DetectionEngineeringAgent
from app.core.policy import PolicyEngine, ActionType

router = APIRouter()
policy_engine = PolicyEngine()
detection_agent = DetectionEngineeringAgent()


@router.post("/", response_model=MissionOut, status_code=201)
async def create_mission(
    payload: MissionCreate,
    tenant_id: str = Query(..., description="Tenant ID"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a new offensive mission (does not run yet)."""
    mission = OffensiveMission(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        engagement_id=payload.engagement_id,
        name=payload.name,
        objective=payload.objective,
        status="planned",
    )
    db.add(mission)
    await db.commit()
    await db.refresh(mission)
    return mission


@router.post("/{mission_id}/run")
async def run_mission(
    mission_id: str,
    tenant_id: str = Query(..., description="Tenant ID"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Run the offensive mission through the full AI agent loop.
    Returns structured attack path report with risk scores and remediation plan.
    """
    # Load mission
    result = await db.execute(
        select(OffensiveMission).where(OffensiveMission.id == mission_id)
    )
    mission = result.scalar_one_or_none()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")

    if mission.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Load engagement to get allowed targets
    eng_result = await db.execute(
        select(Engagement).where(Engagement.id == mission.engagement_id)
    )
    engagement = eng_result.scalar_one_or_none()
    allowed_targets = engagement.allowed_targets if engagement else None

    # Load assets for this tenant
    assets_result = await db.execute(
        select(Asset).where(Asset.tenant_id == tenant_id)
    )
    assets = assets_result.scalars().all()
    assets_data = [
        {
            "name": a.name,
            "asset_type": a.asset_type,
            "hostname": a.hostname,
            "url": a.url,
            "criticality": a.criticality,
            "data_sensitivity": a.data_sensitivity,
        }
        for a in assets
    ]

    # Run the offensive agent
    planner = OffensiveMissionPlanner(tenant_id, mission.engagement_id)
    report = planner.run_mission(
        objective=mission.objective or "Identify highest-risk attack path",
        assets=assets_data,
        allowed_targets=allowed_targets,
    )

    # Update mission with report
    mission.status = "completed"
    mission.report = report
    mission.risk_score = report.get("risk_score")
    mission.risk_level = report.get("risk_level")
    db.add(mission)

    # Auto-create findings from report
    findings_created = []
    attack_nodes = report.get("attack_path", {}).get("nodes", [])
    for node in attack_nodes[:3]:
        if node.get("node_type") == "Weakness":
            finding = Finding(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                mission_id=mission_id,
                title=node.get("label", "Security Weakness"),
                description=node.get("description"),
                risk_level=report.get("risk_level", "high"),
                risk_score=report.get("risk_score"),
                recommended_fix=report.get("recommended_fix"),
                retest_plan=report.get("retest_plan"),
                source="offensive",
            )
            db.add(finding)
            findings_created.append(finding)

    await db.commit()

    return {
        "mission_id": mission_id,
        "status": "completed",
        "report": report,
        "findings_created": len(findings_created),
    }


@router.get("/", response_model=List[MissionOut])
async def list_missions(
    tenant_id: str = Query(..., description="Tenant ID"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(
        select(OffensiveMission).where(OffensiveMission.tenant_id == tenant_id)
    )
    return result.scalars().all()


@router.get("/{mission_id}", response_model=MissionOut)
async def get_mission(
    mission_id: str,
    tenant_id: str = Query(..., description="Tenant ID"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(
        select(OffensiveMission).where(OffensiveMission.id == mission_id)
    )
    mission = result.scalar_one_or_none()
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    if mission.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return mission


@router.post("/policy-check")
async def check_policy(
    action_type: str,
    target: Optional[str] = None,
    tenant_id: str = Query(..., description="Tenant ID"),
) -> Any:
    """
    Explicit policy check endpoint — useful for testing safety boundaries.
    Tries to evaluate an action against the policy engine.
    """
    try:
        action = ActionType(action_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown action type '{action_type}'",
        )

    decision = policy_engine.evaluate(
        action_type=action,
        tenant_id=tenant_id,
        engagement_id="policy-check",
        target=target,
    )

    return {
        "action_type": action_type,
        "target": target,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "blocked_by": decision.blocked_by,
    }
