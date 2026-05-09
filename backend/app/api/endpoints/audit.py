"""Audit log endpoint."""
from typing import Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import AuditEvent
from app.schemas.schemas import AuditEventOut

router = APIRouter()

@router.get("/", response_model=List[AuditEventOut])
async def list_audit_events(tenant_id: str = Query(...),
                            limit: int = Query(default=100, le=1000),
                            db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(
        select(AuditEvent).where(AuditEvent.tenant_id == tenant_id).limit(limit)
    )
    return result.scalars().all()
