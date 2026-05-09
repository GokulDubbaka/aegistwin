"""Assets API endpoints."""
import uuid
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import Asset
from app.schemas.schemas import AssetCreate, AssetOut

router = APIRouter()

@router.post("/", response_model=AssetOut, status_code=201)
async def create_asset(payload: AssetCreate,
                       tenant_id: str = Query(...),
                       db: AsyncSession = Depends(get_db)) -> Any:
    asset = Asset(id=str(uuid.uuid4()), tenant_id=tenant_id, **payload.model_dump())
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset

@router.get("/", response_model=List[AssetOut])
async def list_assets(tenant_id: str = Query(...), db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Asset).where(Asset.tenant_id == tenant_id))
    return result.scalars().all()

@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: str, tenant_id: str = Query(...),
                    db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    a = result.scalar_one_or_none()
    if not a or a.tenant_id != tenant_id:
        raise HTTPException(404, "Asset not found")
    return a

@router.patch("/{asset_id}", response_model=AssetOut)
async def update_asset(asset_id: str, payload: AssetCreate,
                       tenant_id: str = Query(...),
                       db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    a = result.scalar_one_or_none()
    if not a or a.tenant_id != tenant_id:
        raise HTTPException(404, "Asset not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(a, k, v)
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a
