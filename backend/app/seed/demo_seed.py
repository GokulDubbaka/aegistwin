"""
AegisTwin Demo Seed
====================
Populates the database with a realistic demo tenant, assets,
engagement, and telemetry events so the UI has real data on first boot.

Run via: python -m app.seed.demo_seed
Or automatically by docker-compose on first start.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import select

from app.core.config import settings
from app.db.models import (
    Tenant, User, Asset, Engagement, TelemetryEvent,
    DeceptionItem, AuditEvent, OffensiveMission
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger("DemoSeed")

TENANT_ID   = "demo-tenant-00000000-0000-0000-0000-000000000001"
ENG_ID      = "demo-engage-00000000-0000-0000-0000-000000000001"
MISSION_ID  = "demo-missn--00000000-0000-0000-0000-000000000001"


async def seed(session: AsyncSession) -> None:
    # ── Check if already seeded ──────────────────────────────────────────────
    result = await session.execute(select(Tenant).where(Tenant.id == TENANT_ID))
    if result.scalar_one_or_none():
        logger.info("Demo data already present — skipping seed.")
        return

    logger.info("Seeding demo data...")

    # ── Tenant ────────────────────────────────────────────────────────────────
    tenant = Tenant(
        id=TENANT_ID,
        name="Acme Corp",
        slug="acme-corp",
        is_active=True,
        metadata_json={"industry": "fintech", "size": "mid-market"},
    )
    session.add(tenant)
    await session.flush()

    # ── User (admin) ─────────────────────────────────────────────────────────
    # hashed password = "admin123" via bcrypt (pre-hashed for seed)
    admin = User(
        id=str(uuid.uuid4()),
        tenant_id=TENANT_ID,
        email="admin@acmecorp.demo",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNiGHm9pYG.Z2",
        full_name="Acme Admin",
        role="admin",
        is_active=True,
    )
    session.add(admin)

    # ── Assets ────────────────────────────────────────────────────────────────
    assets = [
        Asset(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            name="Payments API",
            asset_type="api",
            description="Core payment processing REST API — PCI DSS scope",
            hostname="api.payments.acmecorp.internal",
            url="https://api.payments.acmecorp.internal",
            criticality=10,
            data_sensitivity=10,
            owner="payments-team@acmecorp.demo",
            tags=["pci-dss", "critical", "production"],
            is_in_scope=True,
        ),
        Asset(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            name="Customer Portal",
            asset_type="web_app",
            description="React SPA for customer self-service — public facing",
            hostname="portal.acmecorp.demo",
            url="https://portal.acmecorp.demo",
            criticality=8,
            data_sensitivity=7,
            owner="frontend-team@acmecorp.demo",
            tags=["public", "react", "spa"],
            is_in_scope=True,
        ),
        Asset(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            name="Identity Provider",
            asset_type="identity_provider",
            description="Okta-based SSO for all internal and external authentication",
            hostname="sso.acmecorp.internal",
            url="https://sso.acmecorp.internal",
            criticality=10,
            data_sensitivity=10,
            owner="security@acmecorp.demo",
            tags=["sso", "okta", "critical"],
            is_in_scope=True,
        ),
        Asset(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            name="Internal Code Repository",
            asset_type="repository",
            description="GitHub Enterprise — source code for all services",
            hostname="github.acmecorp.internal",
            url="https://github.acmecorp.internal",
            criticality=9,
            data_sensitivity=9,
            owner="platform-team@acmecorp.demo",
            tags=["github", "source-code"],
            is_in_scope=True,
        ),
        Asset(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            name="Production Database Cluster",
            asset_type="database",
            description="PostgreSQL primary+replica cluster — customer PII and transaction data",
            hostname="db-primary.acmecorp.internal",
            criticality=10,
            data_sensitivity=10,
            owner="dba@acmecorp.demo",
            tags=["postgres", "pii", "pci-dss"],
            is_in_scope=True,
        ),
    ]
    for a in assets:
        session.add(a)

    # ── Engagement ────────────────────────────────────────────────────────────
    engagement = Engagement(
        id=ENG_ID,
        tenant_id=TENANT_ID,
        name="Q2 2026 Red Team Assessment",
        description=(
            "Full-scope red team engagement targeting the payments pipeline. "
            "Objective: identify attack paths from perimeter to PCI DSS data."
        ),
        status="active",
        engagement_type="red_team",
        allowed_targets=[
            "api.payments.acmecorp.internal",
            "portal.acmecorp.demo",
            "sso.acmecorp.internal",
        ],
        started_at=datetime.now(timezone.utc) - timedelta(days=7),
        rules_of_engagement={
            "no_destructive_actions": True,
            "no_production_data_exfiltration": True,
            "max_daily_requests": 10000,
            "notify_on_critical_finding": True,
        },
        approved_by="CISO — Acme Corp",
    )
    session.add(engagement)

    # ── Telemetry Events (realistic attack traffic simulation) ────────────────
    now = datetime.now(timezone.utc)
    telemetry = [
        # Credential stuffing from Tor exit node
        TelemetryEvent(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            source="waf",
            event_timestamp=now - timedelta(hours=2, minutes=15),
            actor_ip="185.220.101.47",
            actor_asn="AS201814",
            actor_user_agent="python-requests/2.28.0",
            actor_account="john.smith@acmecorp.demo",
            target_resource="/api/v1/auth/login",
            target_endpoint="POST /api/v1/auth/login",
            action="login_attempt",
            raw_event={
                "status_code": 401,
                "response_time_ms": 142,
                "geo": "NL",
                "threat_category": "credential_stuffing",
            },
            is_suspicious=True,
        ),
        TelemetryEvent(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            source="waf",
            event_timestamp=now - timedelta(hours=2, minutes=14),
            actor_ip="185.220.101.47",
            actor_asn="AS201814",
            actor_user_agent="python-requests/2.28.0",
            actor_account="jane.doe@acmecorp.demo",
            target_resource="/api/v1/auth/login",
            target_endpoint="POST /api/v1/auth/login",
            action="login_attempt",
            raw_event={"status_code": 401, "response_time_ms": 139},
            is_suspicious=True,
        ),
        # IDOR attempt on payment endpoint
        TelemetryEvent(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            source="waf",
            event_timestamp=now - timedelta(hours=1, minutes=30),
            actor_ip="45.155.204.127",
            actor_asn="AS62282",
            actor_user_agent="Mozilla/5.0 (compatible; MSIE 9.0)",
            target_resource="/api/v1/payments/1001",
            target_endpoint="GET /api/v1/payments/{id}",
            action="unauthorized_access",
            raw_event={
                "status_code": 403,
                "sequential_ids_probed": [1000, 1001, 1002, 1003],
                "threat_category": "idor",
            },
            is_suspicious=True,
        ),
        # Honeytoken access
        TelemetryEvent(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            source="custom",
            event_timestamp=now - timedelta(minutes=45),
            actor_ip="94.102.49.190",
            actor_asn="AS206728",
            actor_user_agent="Go-http-client/1.1",
            target_resource="/internal/secrets/FAKE-API-KEY-001",
            action="honeytoken_access",
            raw_event={
                "token_id": "FAKE-API-KEY-001",
                "service": "stripe-like-api",
                "threat_category": "credential_theft",
            },
            is_suspicious=True,
        ),
        # Normal traffic (baseline)
        TelemetryEvent(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            source="waf",
            event_timestamp=now - timedelta(minutes=10),
            actor_ip="182.64.12.201",
            actor_asn="AS45609",
            actor_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
            actor_account="normal.user@acmecorp.demo",
            target_resource="/api/v1/payments/history",
            target_endpoint="GET /api/v1/payments/history",
            action="read",
            raw_event={"status_code": 200, "response_time_ms": 89},
            is_suspicious=False,
        ),
    ]
    for t in telemetry:
        session.add(t)

    # ── Deception Items (Honeytokens) ─────────────────────────────────────────
    deception_items = [
        DeceptionItem(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            item_type="honey_token",
            label="Fake Stripe API Key",
            fake_value="sk_live_AEGISTWIN_FAKE_stripe_key_DO_NOT_USE",
            internal_marker="AEGISTWIN_FAKE_DO_NOT_USE",
            is_active=True,
            metadata_json={"service": "stripe", "deployed_to": "github/config-backup"},
        ),
        DeceptionItem(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            item_type="honey_credential",
            label="Fake Admin Credential",
            fake_value="admin:AEGISTWIN_FAKE_PASSWORD_DO_NOT_USE",
            internal_marker="AEGISTWIN_FAKE_DO_NOT_USE",
            is_active=True,
            metadata_json={"service": "admin-panel", "deployed_to": "passwords.txt-backup"},
        ),
        DeceptionItem(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            item_type="canary_doc",
            label="Q1 Financial Report (Fake)",
            fake_value="AEGISTWIN_CANARY_DOC: Q1-2026-Financials-CONFIDENTIAL.pdf",
            internal_marker="AEGISTWIN_FAKE_DO_NOT_USE",
            is_active=True,
            metadata_json={"mimetype": "application/pdf", "deployed_to": "s3://backups/reports/"},
        ),
    ]
    for d in deception_items:
        session.add(d)

    # ── Audit Events (bootstrap policy decisions) ─────────────────────────────
    audit_events = [
        AuditEvent(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            actor_id="offensive-agent",
            actor_type="agent",
            action="policy_evaluation",
            resource_type="action",
            resource_id="exploit_execution",
            decision="blocked",
            reason="Action type 'exploit_execution' is in the always-blocked safety list",
        ),
        AuditEvent(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            actor_id="offensive-agent",
            actor_type="agent",
            action="policy_evaluation",
            resource_type="action",
            resource_id="subdomain_enum",
            decision="allowed",
            reason="Target is within engagement scope",
        ),
    ]
    for ae in audit_events:
        session.add(ae)

    await session.commit()
    logger.info(
        "Demo seed complete: 1 tenant, 5 assets, 1 engagement, "
        "%d telemetry events, %d deception items",
        len(telemetry),
        len(deception_items),
    )


async def main() -> None:
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as session:
        await seed(session)
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
