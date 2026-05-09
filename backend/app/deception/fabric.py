"""
Deception Fabric
================
Safe deception primitives — honeytoken, honey credential, canary document, decoy asset.

IMPORTANT: No real credentials are ever created here.
All generated values contain clear internal markers so they cannot be confused
with real secrets. All access events feed directly to the Defensive Hunter AI.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


INTERNAL_MARKER = "AEGISTWIN_FAKE_DO_NOT_USE"
FAKE_PREFIX = "FAKE_"


def _tagged(value: str) -> str:
    """Wrap a fake value with clear internal marker."""
    return f"{FAKE_PREFIX}{value}_{INTERNAL_MARKER}"


class DeceptionFabric:
    """
    Generates fake deception items with clear internal markers.
    Real credentials are NEVER created here.
    """

    def create_honey_credential(
        self,
        tenant_id: str,
        label: str,
        username: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a fake credential record.
        The password is clearly marked as fake — it cannot be used for auth.
        """
        fake_user = username or f"fake_user_{secrets.token_hex(4)}"
        fake_pass = _tagged(secrets.token_urlsafe(16))

        return {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "item_type": "honey_credential",
            "label": label,
            "fake_value": f"username={fake_user} password={fake_pass}",
            "internal_marker": INTERNAL_MARKER,
            "is_active": True,
            "metadata_json": {
                "username": fake_user,
                "password_marker": INTERNAL_MARKER,
                "warning": "THIS IS A FAKE CREDENTIAL — DO NOT USE IN PRODUCTION",
                **(metadata or {}),
            },
        }

    def create_honey_token(
        self,
        tenant_id: str,
        label: str,
        token_type: str = "api_key",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a fake API token / JWT / secret.
        Token contains a clear prefix and marker so it's distinguishable.
        """
        fake_token = _tagged(secrets.token_urlsafe(32))

        return {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "item_type": "honey_token",
            "label": label,
            "fake_value": fake_token,
            "internal_marker": INTERNAL_MARKER,
            "is_active": True,
            "metadata_json": {
                "token_type": token_type,
                "warning": "THIS IS A FAKE TOKEN — ACCESSING IT TRIGGERS ALERT",
                **(metadata or {}),
            },
        }

    def create_canary_document(
        self,
        tenant_id: str,
        label: str,
        document_type: str = "pdf",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a canary document record.
        Real file creation not implemented — stores metadata only.
        """
        doc_id = secrets.token_hex(8).upper()
        fake_value = _tagged(f"CANARY_DOC_{doc_id}.{document_type}")

        return {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "item_type": "canary_doc",
            "label": label,
            "fake_value": fake_value,
            "internal_marker": INTERNAL_MARKER,
            "is_active": True,
            "metadata_json": {
                "document_type": document_type,
                "doc_id": doc_id,
                "warning": "CANARY DOCUMENT — ACCESS TRIGGERS SECURITY ALERT",
                **(metadata or {}),
            },
        }

    def create_decoy_asset(
        self,
        tenant_id: str,
        label: str,
        asset_type: str = "server",
        hostname: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a decoy asset record (honeypot metadata).
        Real infrastructure not created here — stores record only.
        """
        fake_hostname = hostname or f"fake-{asset_type}-{secrets.token_hex(4)}.internal"
        fake_value = _tagged(f"DECOY_{asset_type.upper()}_{fake_hostname}")

        return {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "item_type": "decoy_asset",
            "label": label,
            "fake_value": fake_value,
            "internal_marker": INTERNAL_MARKER,
            "is_active": True,
            "metadata_json": {
                "asset_type": asset_type,
                "hostname": fake_hostname,
                "warning": "DECOY ASSET — INTERACTION TRIGGERS SECURITY ALERT",
                **(metadata or {}),
            },
        }

    def create_deception_event(
        self,
        tenant_id: str,
        deception_item_id: str,
        triggered_by_ip: Optional[str] = None,
        triggered_by_account: Optional[str] = None,
        raw_event: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a deception event and return it for feeding to Defensive Hunter.
        This event should also be saved to the database.
        """
        return {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "deception_item_id": deception_item_id,
            "triggered_by_ip": triggered_by_ip,
            "triggered_by_account": triggered_by_account,
            "raw_event": raw_event or {},
            "cluster_id": None,  # Will be assigned by Defensive Hunter
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "severity": "high",  # Honeytoken interaction is always high
            "alert_message": (
                f"⚠️ DECEPTION ITEM TRIGGERED — Item {deception_item_id} "
                f"accessed from IP {triggered_by_ip or 'unknown'}"
            ),
        }


# Singleton
deception_fabric = DeceptionFabric()
