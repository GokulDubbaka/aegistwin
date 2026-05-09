"""Actor clusters, findings, deception, detections, remediation, attack paths, audit, reports endpoints."""

# ── clusters.py ──────────────────────────────────────────────────────────────
from typing import Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import ActorCluster
from app.schemas.schemas import ActorClusterOut

router = APIRouter()

@router.get("/", response_model=List[ActorClusterOut])
async def list_clusters(tenant_id: str = Query(...), db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(ActorCluster).where(ActorCluster.tenant_id == tenant_id))
    return result.scalars().all()

@router.get("/{cluster_id}", response_model=ActorClusterOut)
async def get_cluster(cluster_id: str, tenant_id: str = Query(...),
                      db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(ActorCluster).where(ActorCluster.id == cluster_id))
    c = result.scalar_one_or_none()
    if not c or c.tenant_id != tenant_id:
        from fastapi import HTTPException
        raise HTTPException(404, "Cluster not found")
    return c
