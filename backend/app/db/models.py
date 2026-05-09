"""SQLAlchemy ORM models — Tenant, User, Asset, Engagement, Policy, Audit."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Enum,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


# ─── Enums ────────────────────────────────────────────────────────────────────

class AssetType(str, PyEnum):
    WEB_APP = "web_app"
    API = "api"
    REPOSITORY = "repository"
    CLOUD_ACCOUNT = "cloud_account"
    IDENTITY_PROVIDER = "identity_provider"
    DATABASE = "database"
    NETWORK_DEVICE = "network_device"
    CONTAINER = "container"
    OTHER = "other"


class RiskLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EngagementStatus(str, PyEnum):
    PLANNED = "planned"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class FindingStatus(str, PyEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


# ─── Base mixin ───────────────────────────────────────────────────────────────

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# ─── Tenant ───────────────────────────────────────────────────────────────────

class Tenant(TimestampMixin, Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    users: Mapped[List["User"]] = relationship("User", back_populates="tenant")
    assets: Mapped[List["Asset"]] = relationship("Asset", back_populates="tenant")
    engagements: Mapped[List["Engagement"]] = relationship(
        "Engagement", back_populates="tenant"
    )
    audit_events: Mapped[List["AuditEvent"]] = relationship(
        "AuditEvent", back_populates="tenant"
    )


# ─── User ─────────────────────────────────────────────────────────────────────

class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")  # admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")


# ─── Asset ────────────────────────────────────────────────────────────────────

class Asset(TimestampMixin, Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    criticality: Mapped[int] = mapped_column(Integer, default=5)  # 1-10
    data_sensitivity: Mapped[int] = mapped_column(Integer, default=5)  # 1-10
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_in_scope: Mapped[bool] = mapped_column(Boolean, default=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="assets")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="asset")


# ─── Engagement ───────────────────────────────────────────────────────────────

class Engagement(TimestampMixin, Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="planned")
    engagement_type: Mapped[str] = mapped_column(
        String(50), default="red_team"
    )  # red_team|blue_team|purple_team
    allowed_targets: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    rules_of_engagement: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="engagements")
    missions: Mapped[List["OffensiveMission"]] = relationship(
        "OffensiveMission", back_populates="engagement"
    )


# ─── Offensive Mission ────────────────────────────────────────────────────────

class OffensiveMission(TimestampMixin, Base):
    __tablename__ = "offensive_missions"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("engagements.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="planned")
    report: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Full attack path report
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    engagement: Mapped["Engagement"] = relationship(
        "Engagement", back_populates="missions"
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="mission"
    )


# ─── Finding ─────────────────────────────────────────────────────────────────

class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    mission_id: Mapped[Optional[str]] = mapped_column(
        String(100), ForeignKey("offensive_missions.id"), nullable=True
    )
    asset_id: Mapped[Optional[str]] = mapped_column(
        String(100), ForeignKey("assets.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open")
    evidence: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    recommended_fix: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cve_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    retest_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="offensive")  # offensive|defensive

    mission: Mapped[Optional["OffensiveMission"]] = relationship(
        "OffensiveMission", back_populates="findings"
    )
    asset: Mapped[Optional["Asset"]] = relationship("Asset", back_populates="findings")


# ─── Attack Path Graph Nodes + Edges ─────────────────────────────────────────

class AttackPathNode(TimestampMixin, Base):
    __tablename__ = "attack_path_nodes"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    mission_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    properties: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detection_coverage: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    outgoing_edges: Mapped[List["AttackPathEdge"]] = relationship(
        "AttackPathEdge",
        foreign_keys="AttackPathEdge.source_node_id",
        back_populates="source_node",
    )


class AttackPathEdge(TimestampMixin, Base):
    __tablename__ = "attack_path_edges"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    source_node_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("attack_path_nodes.id"), nullable=False
    )
    target_node_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("attack_path_nodes.id"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)
    properties: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    source_node: Mapped["AttackPathNode"] = relationship(
        "AttackPathNode",
        foreign_keys=[source_node_id],
        back_populates="outgoing_edges",
    )


# ─── Telemetry Event ─────────────────────────────────────────────────────────

class TelemetryEvent(TimestampMixin, Base):
    __tablename__ = "telemetry_events"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    actor_asn: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    actor_user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actor_ja3: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    actor_ja4: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    actor_account: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_asset_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_resource: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    target_endpoint: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    raw_event: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    cluster_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)


# ─── Actor Cluster ────────────────────────────────────────────────────────────

class ActorCluster(TimestampMixin, Base):
    __tablename__ = "actor_clusters"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    cluster_label: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    likely_automation: Mapped[str] = mapped_column(String(20), default="low")
    likely_ai_assisted: Mapped[str] = mapped_column(String(20), default="low")
    evidence: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    recommended_actions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    fingerprint: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)


# ─── Deception ────────────────────────────────────────────────────────────────

class DeceptionItem(TimestampMixin, Base):
    __tablename__ = "deception_items"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    item_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # honey_credential|honey_token|canary_doc|decoy_asset
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    fake_value: Mapped[str] = mapped_column(Text, nullable=False)
    # Internal marker — always present so the item is distinguishable from real secrets
    internal_marker: Mapped[str] = mapped_column(
        String(100), default="AEGISTWIN_FAKE_DO_NOT_USE"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    triggered_count: Mapped[int] = mapped_column(Integer, default=0)


class DeceptionEvent(TimestampMixin, Base):
    __tablename__ = "deception_events"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    deception_item_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("deception_items.id"), nullable=False
    )
    triggered_by_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    triggered_by_account: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    raw_event: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    cluster_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    deception_item: Mapped["DeceptionItem"] = relationship("DeceptionItem")


# ─── Detection Draft ─────────────────────────────────────────────────────────

class DetectionDraft(TimestampMixin, Base):
    __tablename__ = "detection_drafts"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # sigma|waf|siem_query|edr_hunt|cloud_query
    content: Mapped[str] = mapped_column(Text, nullable=False)  # YAML or query string
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), default="draft"
    )  # draft|reviewed|approved|deployed
    finding_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cluster_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


# ─── Remediation Ticket ───────────────────────────────────────────────────────

class RemediationTicket(TimestampMixin, Base):
    __tablename__ = "remediation_tickets"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    finding_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    priority: Mapped[str] = mapped_column(String(20), default="high")
    suggested_owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ticket_type: Mapped[str] = mapped_column(
        String(20), default="jira"
    )  # jira|github
    ticket_payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    retest_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open")


# ─── Audit Event ─────────────────────────────────────────────────────────────

class AuditEvent(TimestampMixin, Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("tenants.id"), nullable=False
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    actor_type: Mapped[str] = mapped_column(
        String(50), default="agent"
    )  # agent|user|system
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    decision: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )  # allowed|blocked
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="audit_events")
