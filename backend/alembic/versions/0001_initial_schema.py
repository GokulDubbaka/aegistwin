"""
AegisTwin — Initial Database Migration
=======================================
Auto-generated from SQLAlchemy ORM models.
Creates all tables with proper foreign key constraints and indexes.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── tenants ──────────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("metadata_json", postgresql.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"])

    # ── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), default="analyst", nullable=False),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_index("ix_users_email", "users", ["email"])

    # ── assets ───────────────────────────────────────────────────────────────
    op.create_table(
        "assets",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("asset_type", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("url", sa.String(500), nullable=True),
        sa.Column("criticality", sa.Integer(), default=5, nullable=False),
        sa.Column("data_sensitivity", sa.Integer(), default=5, nullable=False),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("tags", postgresql.JSON(), nullable=True),
        sa.Column("metadata_json", postgresql.JSON(), nullable=True),
        sa.Column("is_in_scope", sa.Boolean(), default=True, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"])

    # ── engagements ───────────────────────────────────────────────────────────
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), default="planned", nullable=False),
        sa.Column("engagement_type", sa.String(50), default="red_team", nullable=False),
        sa.Column("allowed_targets", postgresql.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rules_of_engagement", postgresql.JSON(), nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_engagements_tenant_id", "engagements", ["tenant_id"])

    # ── offensive_missions ───────────────────────────────────────────────────
    op.create_table(
        "offensive_missions",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(100),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("objective", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), default="planned", nullable=False),
        sa.Column("report", postgresql.JSON(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_offensive_missions_tenant_id", "offensive_missions", ["tenant_id"])

    # ── findings ─────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "mission_id",
            sa.String(100),
            sa.ForeignKey("offensive_missions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "asset_id",
            sa.String(100),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("risk_level", sa.String(20), default="medium", nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("status", sa.String(50), default="open", nullable=False),
        sa.Column("evidence", postgresql.JSON(), nullable=True),
        sa.Column("recommended_fix", sa.Text(), nullable=True),
        sa.Column("cve_ids", postgresql.JSON(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("retest_plan", sa.Text(), nullable=True),
        sa.Column("source", sa.String(50), default="offensive", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_findings_tenant_id", "findings", ["tenant_id"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_risk_level", "findings", ["risk_level"])

    # ── attack_path_nodes ────────────────────────────────────────────────────
    op.create_table(
        "attack_path_nodes",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mission_id", sa.String(100), nullable=True),
        sa.Column("node_type", sa.String(50), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("properties", postgresql.JSON(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("detection_coverage", sa.Boolean(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_attack_path_nodes_tenant_id", "attack_path_nodes", ["tenant_id"])

    # ── attack_path_edges ────────────────────────────────────────────────────
    op.create_table(
        "attack_path_edges",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_node_id",
            sa.String(100),
            sa.ForeignKey("attack_path_nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_node_id",
            sa.String(100),
            sa.ForeignKey("attack_path_nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(100), nullable=False),
        sa.Column("properties", postgresql.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # ── telemetry_events ─────────────────────────────────────────────────────
    op.create_table(
        "telemetry_events",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_ip", sa.String(50), nullable=True),
        sa.Column("actor_asn", sa.String(50), nullable=True),
        sa.Column("actor_user_agent", sa.Text(), nullable=True),
        sa.Column("actor_ja3", sa.String(100), nullable=True),
        sa.Column("actor_ja4", sa.String(100), nullable=True),
        sa.Column("actor_account", sa.String(255), nullable=True),
        sa.Column("target_asset_id", sa.String(255), nullable=True),
        sa.Column("target_resource", sa.String(500), nullable=True),
        sa.Column("target_endpoint", sa.String(500), nullable=True),
        sa.Column("action", sa.String(255), nullable=True),
        sa.Column("raw_event", postgresql.JSON(), nullable=True),
        sa.Column("cluster_id", sa.String(100), nullable=True),
        sa.Column("is_suspicious", sa.Boolean(), default=False, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_telemetry_tenant_id", "telemetry_events", ["tenant_id"])
    op.create_index("ix_telemetry_actor_ip", "telemetry_events", ["actor_ip"])
    op.create_index("ix_telemetry_event_timestamp", "telemetry_events", ["event_timestamp"])

    # ── actor_clusters ────────────────────────────────────────────────────────
    op.create_table(
        "actor_clusters",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cluster_label", sa.String(255), nullable=False),
        sa.Column("confidence", sa.Float(), default=0.0, nullable=False),
        sa.Column("likely_automation", sa.String(20), default="low", nullable=False),
        sa.Column("likely_ai_assisted", sa.String(20), default="low", nullable=False),
        sa.Column("evidence", postgresql.JSON(), nullable=True),
        sa.Column("recommended_actions", postgresql.JSON(), nullable=True),
        sa.Column("fingerprint", postgresql.JSON(), nullable=True),
        sa.Column("event_count", sa.Integer(), default=0, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_actor_clusters_tenant_id", "actor_clusters", ["tenant_id"])

    # ── deception_items ───────────────────────────────────────────────────────
    op.create_table(
        "deception_items",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("item_type", sa.String(50), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("fake_value", sa.Text(), nullable=False),
        sa.Column(
            "internal_marker",
            sa.String(100),
            default="AEGISTWIN_FAKE_DO_NOT_USE",
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("metadata_json", postgresql.JSON(), nullable=True),
        sa.Column("triggered_count", sa.Integer(), default=0, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_deception_items_tenant_id", "deception_items", ["tenant_id"])

    # ── deception_events ──────────────────────────────────────────────────────
    op.create_table(
        "deception_events",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "deception_item_id",
            sa.String(100),
            sa.ForeignKey("deception_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("triggered_by_ip", sa.String(50), nullable=True),
        sa.Column("triggered_by_account", sa.String(255), nullable=True),
        sa.Column("raw_event", postgresql.JSON(), nullable=True),
        sa.Column("cluster_id", sa.String(100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # ── detection_drafts ──────────────────────────────────────────────────────
    op.create_table(
        "detection_drafts",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(50), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), default="draft", nullable=False),
        sa.Column("finding_id", sa.String(100), nullable=True),
        sa.Column("cluster_id", sa.String(100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_detection_drafts_tenant_id", "detection_drafts", ["tenant_id"])

    # ── remediation_tickets ───────────────────────────────────────────────────
    op.create_table(
        "remediation_tickets",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("finding_id", sa.String(100), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("priority", sa.String(20), default="high", nullable=False),
        sa.Column("suggested_owner", sa.String(255), nullable=True),
        sa.Column("ticket_type", sa.String(20), default="jira", nullable=False),
        sa.Column("ticket_payload", postgresql.JSON(), nullable=True),
        sa.Column("retest_plan", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), default="open", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_remediation_tickets_tenant_id", "remediation_tickets", ["tenant_id"])

    # ── audit_events ──────────────────────────────────────────────────────────
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(100),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("actor_type", sa.String(50), default="agent", nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("decision", sa.String(20), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("metadata_json", postgresql.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("remediation_tickets")
    op.drop_table("detection_drafts")
    op.drop_table("deception_events")
    op.drop_table("deception_items")
    op.drop_table("actor_clusters")
    op.drop_table("telemetry_events")
    op.drop_table("attack_path_edges")
    op.drop_table("attack_path_nodes")
    op.drop_table("findings")
    op.drop_table("offensive_missions")
    op.drop_table("engagements")
    op.drop_table("assets")
    op.drop_table("users")
    op.drop_table("tenants")
