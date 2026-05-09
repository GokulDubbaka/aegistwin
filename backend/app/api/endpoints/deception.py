"""Deception fabric endpoint."""
import uuid
from typing import Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import DeceptionItem, DeceptionEvent
from app.schemas.schemas import DeceptionItemCreate, DeceptionItemOut, DeceptionEventOut
from app.deception.fabric import deception_fabric

router = APIRouter()

@router.post("/items", response_model=DeceptionItemOut, status_code=201)
async def create_deception_item(payload: DeceptionItemCreate,
                                tenant_id: str = Query(...),
                                db: AsyncSession = Depends(get_db)) -> Any:
    if payload.item_type == "honey_token":
        data = deception_fabric.create_honey_token(tenant_id, payload.label,
                                                   metadata=payload.metadata_json)
    elif payload.item_type == "honey_credential":
        data = deception_fabric.create_honey_credential(tenant_id, payload.label,
                                                        metadata=payload.metadata_json)
    elif payload.item_type == "canary_doc":
        data = deception_fabric.create_canary_document(tenant_id, payload.label,
                                                       metadata=payload.metadata_json)
    else:
        data = deception_fabric.create_decoy_asset(tenant_id, payload.label,
                                                   metadata=payload.metadata_json)
    item = DeceptionItem(**{k: v for k, v in data.items() if k != "triggered_at"})
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item

@router.get("/items", response_model=List[DeceptionItemOut])
async def list_deception_items(tenant_id: str = Query(...),
                               db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(DeceptionItem).where(DeceptionItem.tenant_id == tenant_id))
    return result.scalars().all()

@router.get("/events", response_model=List[DeceptionEventOut])
async def list_deception_events(tenant_id: str = Query(...),
                                db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(DeceptionEvent).where(DeceptionEvent.tenant_id == tenant_id))
    return result.scalars().all()

@router.post("/events/{item_id}/trigger", status_code=201)
async def trigger_deception_event(item_id: str, tenant_id: str = Query(...),
                                  source_ip: str = Query(None),
                                  db: AsyncSession = Depends(get_db)) -> Any:
    """Simulate a deception item being triggered."""
    # SECURITY: verify the deception item belongs to the requesting tenant
    item_result = await db.execute(
        select(DeceptionItem).where(DeceptionItem.id == item_id)
    )
    item = item_result.scalar_one_or_none()
    if not item:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Deception item not found")
    if item.tenant_id != tenant_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Access denied")

    event_data = deception_fabric.create_deception_event(
        tenant_id=tenant_id,
        deception_item_id=item_id,
        triggered_by_ip=source_ip,
    )
    event = DeceptionEvent(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        deception_item_id=item_id,
        triggered_by_ip=source_ip,
        raw_event=event_data,
    )
    db.add(event)
    await db.commit()
    return event_data
