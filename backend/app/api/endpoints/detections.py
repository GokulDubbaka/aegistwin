"""Detection drafts endpoint."""
import uuid
from typing import Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import DetectionDraft
from app.schemas.schemas import DetectionDraftOut

router = APIRouter()

@router.get("/", response_model=List[DetectionDraftOut])
async def list_detection_drafts(tenant_id: str = Query(...),
                                db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(DetectionDraft).where(DetectionDraft.tenant_id == tenant_id))
    return result.scalars().all()

@router.post("/", status_code=201)
async def create_detection_draft(title: str, rule_type: str, content: str,
                                 tenant_id: str = Query(...),
                                 db: AsyncSession = Depends(get_db)) -> Any:
    draft = DetectionDraft(id=str(uuid.uuid4()), tenant_id=tenant_id,
                           title=title, rule_type=rule_type, content=content)
    db.add(draft)
    await db.commit()
    await db.refresh(draft)
    return draft
