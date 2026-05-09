"""Attack paths endpoint."""
from typing import Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import AttackPathNode, AttackPathEdge

router = APIRouter()

@router.get("/")
async def list_attack_paths(tenant_id: str = Query(...),
                            mission_id: str = Query(None),
                            db: AsyncSession = Depends(get_db)) -> Any:
    query = select(AttackPathNode).where(AttackPathNode.tenant_id == tenant_id)
    if mission_id:
        query = query.where(AttackPathNode.mission_id == mission_id)
    result = await db.execute(query)
    nodes = result.scalars().all()
    return {
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "nodes": [
            {"id": n.id, "node_type": n.node_type, "label": n.label,
             "description": n.description, "risk_score": n.risk_score}
            for n in nodes
        ],
    }
