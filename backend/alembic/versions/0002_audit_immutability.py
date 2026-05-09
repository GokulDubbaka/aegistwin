"""
AegisTwin — Audit Immutability Migration
Adds a PostgreSQL trigger that rejects UPDATE/DELETE on audit_events.

Run: alembic upgrade 0002_audit_immutability
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_audit_immutability"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None

_DENY_SQL = """
CREATE OR REPLACE FUNCTION fn_audit_events_deny_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only. % not permitted.', TG_OP
        USING ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_audit_events_deny_mutation
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION fn_audit_events_deny_mutation();
"""

_DROP_SQL = """
DROP TRIGGER IF EXISTS trg_audit_events_deny_mutation ON audit_events;
DROP FUNCTION IF EXISTS fn_audit_events_deny_mutation();
"""

def upgrade() -> None:
    op.drop_column("audit_events", "updated_at")
    op.execute(sa.text(_DENY_SQL))

def downgrade() -> None:
    op.execute(sa.text(_DROP_SQL))
    op.add_column("audit_events", sa.Column(
        "updated_at", sa.DateTime(timezone=True),
        server_default=sa.text("now()"), nullable=False,
    ))
