"""Engagements API endpoints."""
import uuid
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import Engagement
from app.schemas.schemas import EngagementCreate, EngagementOut

router = APIRouter()

@router.post("/", response_model=EngagementOut, status_code=201)
async def create_engagement(payload: EngagementCreate,
                            tenant_id: str = Query(...),
                            db: AsyncSession = Depends(get_db)) -> Any:
    eng = Engagement(id=str(uuid.uuid4()), tenant_id=tenant_id, **payload.model_dump())
    db.add(eng)
    await db.commit()
    await db.refresh(eng)
    return eng

@router.get("/", response_model=List[EngagementOut])
async def list_engagements(tenant_id: str = Query(...), db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Engagement).where(Engagement.tenant_id == tenant_id))
    return result.scalars().all()

@router.get("/{eng_id}", response_model=EngagementOut)
async def get_engagement(eng_id: str, tenant_id: str = Query(...),
                         db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Engagement).where(Engagement.id == eng_id))
    e = result.scalar_one_or_none()
    if not e or e.tenant_id != tenant_id:
        raise HTTPException(404, "Engagement not found")
    return e
