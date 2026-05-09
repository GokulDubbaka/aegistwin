"""Remediation tickets endpoint."""
import uuid
from typing import Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import RemediationTicket, Finding
from app.schemas.schemas import RemediationTicketOut
from app.remediation.agent import remediation_agent

router = APIRouter()

@router.post("/from-finding/{finding_id}", status_code=201)
async def create_tickets_from_finding(finding_id: str, tenant_id: str = Query(...),
                                      db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        from fastapi import HTTPException
        raise HTTPException(404, "Finding not found")

    finding_dict = {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "risk_level": finding.risk_level,
        "risk_score": finding.risk_score,
        "evidence": finding.evidence,
        "recommended_fix": finding.recommended_fix,
        "retest_plan": finding.retest_plan,
        "cve_ids": finding.cve_ids,
    }
    tickets_data = remediation_agent.from_finding(finding_dict, tenant_id)

    created = []
    for t in tickets_data:
        ticket = RemediationTicket(
            id=t["id"],
            tenant_id=tenant_id,
            finding_id=finding_id,
            title=t["title"],
            description=t["description"],
            priority=t["priority"],
            suggested_owner=t["suggested_owner"],
            ticket_type=t["ticket_type"],
            ticket_payload=t["ticket_payload"],
            retest_plan=t["retest_plan"],
        )
        db.add(ticket)
        created.append(t)
    await db.commit()
    return {"tickets_created": len(created), "tickets": created}

@router.get("/", response_model=List[RemediationTicketOut])
async def list_tickets(tenant_id: str = Query(...), db: AsyncSession = Depends(get_db)) -> Any:
    result = await db.execute(
        select(RemediationTicket).where(RemediationTicket.tenant_id == tenant_id)
    )
    return result.scalars().all()
