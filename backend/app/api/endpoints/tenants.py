"""Tenants API endpoints."""
import uuid
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import Tenant
from app.schemas.schemas import TenantCreate, TenantOut

router = APIRouter()

@router.post("/", response_model=TenantOut, status_code=201)
async def create_tenant(payload: TenantCreate, db: AsyncSession = Depends(get_db)) -> Any:
    tenant = Tenant(id=str(uuid.uuid4()), name=payload.name, slug=payload.slug,
                    metadata_json=payload.metadata_json)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return tenant

@router.get("/", response_model=List[TenantOut])
async def list_tenants(db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Tenant))
    return result.scalars().all()

@router.get("/{tenant_id}", response_model=TenantOut)
async def get_tenant(tenant_id: str, db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Tenant not found")
    return t
