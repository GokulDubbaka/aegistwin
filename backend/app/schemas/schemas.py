"""Pydantic schemas for all API request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, EmailStr
import uuid


def new_id() -> str:
    return str(uuid.uuid4())


# ─── Tenant ───────────────────────────────────────────────────────────────────

class TenantCreate(BaseModel):
    name: str
    slug: str
    metadata_json: Optional[Dict[str, Any]] = None


class TenantOut(BaseModel):
    id: str
    name: str
    slug: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Asset ────────────────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    description: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    url: Optional[str] = None
    criticality: int = Field(default=5, ge=1, le=10)
    data_sensitivity: int = Field(default=5, ge=1, le=10)
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    is_in_scope: bool = True


class AssetOut(AssetCreate):
    id: str
    tenant_id: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Engagement ───────────────────────────────────────────────────────────────

class EngagementCreate(BaseModel):
    name: str
    description: Optional[str] = None
    engagement_type: str = "red_team"
    allowed_targets: Optional[List[str]] = None
    rules_of_engagement: Optional[Dict[str, Any]] = None
    approved_by: Optional[str] = None


class EngagementOut(EngagementCreate):
    id: str
    tenant_id: str
    status: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Offensive Mission ────────────────────────────────────────────────────────

class MissionCreate(BaseModel):
    name: str
    objective: Optional[str] = None
    engagement_id: str


class MissionOut(BaseModel):
    id: str
    tenant_id: str
    engagement_id: str
    name: str
    objective: Optional[str]
    status: str
    report: Optional[Dict[str, Any]]
    risk_score: Optional[float]
    risk_level: Optional[str]
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Telemetry Event ─────────────────────────────────────────────────────────

class TelemetryEventCreate(BaseModel):
    source: str = Field(
        description="Source: waf|edr|idp|cloud|dns|github|email|firewall|custom"
    )
    timestamp: datetime
    actor: Dict[str, Any] = Field(
        description="Actor context: ip, asn, user_agent, ja3, ja4, account"
    )
    target: Dict[str, Any] = Field(
        description="Target context: asset_id, resource, endpoint"
    )
    action: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class TelemetryEventOut(BaseModel):
    id: str
    tenant_id: str
    source: str
    event_timestamp: datetime
    actor_ip: Optional[str]
    actor_asn: Optional[str]
    action: Optional[str]
    is_suspicious: bool
    cluster_id: Optional[str]
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Actor Cluster ────────────────────────────────────────────────────────────

class ActorClusterOut(BaseModel):
    id: str
    tenant_id: str
    cluster_label: str
    confidence: float
    likely_automation: str
    likely_ai_assisted: str
    evidence: Optional[List[Any]]
    recommended_actions: Optional[List[str]]
    fingerprint: Optional[Dict[str, Any]]
    event_count: int
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Finding ─────────────────────────────────────────────────────────────────

class FindingCreate(BaseModel):
    title: str
    description: Optional[str] = None
    risk_level: str = "medium"
    asset_id: Optional[str] = None
    evidence: Optional[List[Any]] = None
    recommended_fix: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cvss_score: Optional[float] = None
    retest_plan: Optional[str] = None
    source: str = "offensive"


class FindingOut(FindingCreate):
    id: str
    tenant_id: str
    mission_id: Optional[str]
    risk_score: Optional[float]
    status: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Deception ────────────────────────────────────────────────────────────────

class DeceptionItemCreate(BaseModel):
    item_type: str  # honey_credential|honey_token|canary_doc|decoy_asset
    label: str
    metadata_json: Optional[Dict[str, Any]] = None


class DeceptionItemOut(BaseModel):
    id: str
    tenant_id: str
    item_type: str
    label: str
    fake_value: str
    internal_marker: str
    is_active: bool
    triggered_count: int
    created_at: datetime
    model_config = {"from_attributes": True}


class DeceptionEventOut(BaseModel):
    id: str
    tenant_id: str
    deception_item_id: str
    triggered_by_ip: Optional[str]
    triggered_by_account: Optional[str]
    raw_event: Optional[Dict[str, Any]]
    cluster_id: Optional[str]
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Detection Draft ─────────────────────────────────────────────────────────

class DetectionDraftOut(BaseModel):
    id: str
    tenant_id: str
    title: str
    rule_type: str
    content: str
    description: Optional[str]
    status: str
    finding_id: Optional[str]
    cluster_id: Optional[str]
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Remediation Ticket ───────────────────────────────────────────────────────

class RemediationTicketOut(BaseModel):
    id: str
    tenant_id: str
    finding_id: Optional[str]
    title: str
    description: Optional[str]
    priority: str
    suggested_owner: Optional[str]
    ticket_type: str
    ticket_payload: Optional[Dict[str, Any]]
    retest_plan: Optional[str]
    status: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Attack Path ─────────────────────────────────────────────────────────────

class AttackPathNodeOut(BaseModel):
    id: str
    node_type: str
    label: str
    description: Optional[str]
    properties: Optional[Dict[str, Any]]
    risk_score: Optional[float]
    detection_coverage: Optional[bool]
    model_config = {"from_attributes": True}


class AttackPathOut(BaseModel):
    mission_id: str
    nodes: List[AttackPathNodeOut]
    edges: List[Dict[str, Any]]
    risk_score: float
    explained: str


# ─── Audit ────────────────────────────────────────────────────────────────────

class AuditEventOut(BaseModel):
    id: str
    tenant_id: str
    actor_id: Optional[str]
    actor_type: str
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    decision: Optional[str]
    reason: Optional[str]
    created_at: datetime
    model_config = {"from_attributes": True}
