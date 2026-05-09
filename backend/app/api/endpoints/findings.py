"""Findings endpoint."""
import uuid
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import Finding
from app.schemas.schemas import FindingCreate, FindingOut

router = APIRouter()

@router.post("/", response_model=FindingOut, status_code=201)
async def create_finding(payload: FindingCreate, tenant_id: str = Query(...),
                         db: AsyncSession = Depends(get_db)) -> Any:
    f = Finding(id=str(uuid.uuid4()), tenant_id=tenant_id, **payload.model_dump())
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return f

@router.get("/", response_model=List[FindingOut])
async def list_findings(tenant_id: str = Query(...), db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Finding).where(Finding.tenant_id == tenant_id))
    return result.scalars().all()

@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, tenant_id: str = Query(...),
                      db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    f = result.scalar_one_or_none()
    if not f or f.tenant_id != tenant_id:
        raise HTTPException(404, "Finding not found")
    return f
