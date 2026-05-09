"""AegisTwin Policy Engine — blocks unsafe offensive actions."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    # ── SAFE actions (always allowed within scope) ─────────────────────────
    ASSET_DISCOVERY = "asset_discovery"
    SUBDOMAIN_ENUM = "subdomain_enum"
    PORT_SCAN = "port_scan"
    WEB_FINGERPRINT = "web_fingerprint"
    DEPENDENCY_SCAN = "dependency_scan"
    SECRET_SCAN = "secret_scan"
    CLOUD_CONFIG_REVIEW = "cloud_config_review"
    TELEMETRY_SEARCH = "telemetry_search"
    HONEYTOKEN_MONITOR = "honeytoken_monitor"
    VULNERABILITY_REASONING = "vulnerability_reasoning"
    ATTACK_PATH_BUILD = "attack_path_build"
    RISK_SCORING = "risk_scoring"
    REPORT_GENERATION = "report_generation"
    DETECTION_DRAFT = "detection_draft"
    REMEDIATION_TICKET = "remediation_ticket"
    NON_DESTRUCTIVE_PROOF = "non_destructive_proof"
    TELEMETRY_INGEST = "telemetry_ingest"
    FINGERPRINT_CORRELATE = "fingerprint_correlate"

    # ── BLOCKED actions (never allowed in production) ──────────────────────
    EXPLOIT_EXECUTION = "exploit_execution"
    CREDENTIAL_USE = "credential_use"
    CREDENTIAL_THEFT = "credential_theft"
    PERSISTENCE = "persistence"
    C2_COMMUNICATION = "c2_communication"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    STEALTH = "stealth"
    LOG_DELETION = "log_deletion"
    DESTRUCTIVE_PAYLOAD = "destructive_payload"
    ANTI_FORENSICS = "anti_forensics"
    HACKING_BACK = "hacking_back"


# Hard-coded block list — these can NEVER be overridden by policy
_ALWAYS_BLOCKED: set[ActionType] = {
    ActionType.EXPLOIT_EXECUTION,
    ActionType.CREDENTIAL_USE,
    ActionType.CREDENTIAL_THEFT,
    ActionType.PERSISTENCE,
    ActionType.C2_COMMUNICATION,
    ActionType.LATERAL_MOVEMENT,
    ActionType.DATA_EXFILTRATION,
    ActionType.STEALTH,
    ActionType.LOG_DELETION,
    ActionType.DESTRUCTIVE_PAYLOAD,
    ActionType.ANTI_FORENSICS,
    ActionType.HACKING_BACK,
}


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    action_type: ActionType
    blocked_by: Optional[str] = None  # "ALWAYS_BLOCKED" | "TENANT_POLICY" | "SCOPE"
    target: Optional[str] = None
    tenant_id: Optional[str] = None
    engagement_id: Optional[str] = None


class PolicyEngine:
    """
    Hard safety boundary enforcer.

    Evaluates every agent action request against:
    1. Global always-blocked list (can never be overridden)
    2. Engagement scope (are the targets in scope?)

    audit_callback: optional callable(PolicyDecision) invoked after every evaluation
    so the API layer can persist a full AuditEvent without coupling the engine to the DB.
    """

    def __init__(self, audit_callback: Optional[Callable[["PolicyDecision"], None]] = None):
        self._audit_callback = audit_callback

    def evaluate(
        self,
        action_type: ActionType,
        tenant_id: str,
        engagement_id: str,
        target: Optional[str] = None,
        allowed_targets: Optional[List[str]] = None,
        context: Optional[dict] = None,
    ) -> PolicyDecision:
        decision = self._evaluate_inner(
            action_type, tenant_id, engagement_id, target, allowed_targets, context
        )
        decision.target = target
        decision.tenant_id = tenant_id
        decision.engagement_id = engagement_id
        if self._audit_callback:
            try:
                self._audit_callback(decision)
            except Exception:  # never let audit failure break the evaluation
                logger.exception("audit_callback raised; decision not persisted")
        return decision

    def _evaluate_inner(
        self,
        action_type: ActionType,
        tenant_id: str,
        engagement_id: str,
        target: Optional[str],
        allowed_targets: Optional[List[str]],
        context: Optional[dict],
    ) -> PolicyDecision:
        # ── 1. Global hard block ───────────────────────────────────────────
        if action_type in _ALWAYS_BLOCKED:
            reason = (
                f"Action '{action_type.value}' is permanently blocked. "
                "AegisTwin does not allow exploit execution, credential abuse, "
                "persistence, C2, lateral movement, data exfiltration, stealth, "
                "log deletion, destructive payloads, or hacking back."
            )
            logger.warning(
                "POLICY_BLOCKED tenant=%s engagement=%s action=%s target=%s",
                tenant_id, engagement_id, action_type.value, target,
            )
            return PolicyDecision(
                allowed=False, reason=reason,
                action_type=action_type, blocked_by="ALWAYS_BLOCKED",
            )

        # ── 2. Scope check (SECURE: target present → allowed_targets MUST be provided)
        #
        # Previous bug: `if target and allowed_targets and ...` silently skipped the
        # check when allowed_targets was None, allowing any target through.
        # Fixed: if a target is specified we REQUIRE an explicit allowed list.
        if target is not None:
            if not allowed_targets:
                reason = (
                    f"Target '{target}' was specified but no allowed_targets list was "
                    f"provided for engagement '{engagement_id}'. "
                    "Cannot verify scope — action blocked by default-deny."
                )
                logger.warning(
                    "POLICY_NO_SCOPE_LIST tenant=%s engagement=%s action=%s target=%s",
                    tenant_id, engagement_id, action_type.value, target,
                )
                return PolicyDecision(
                    allowed=False, reason=reason,
                    action_type=action_type, blocked_by="SCOPE",
                )

            if not _target_in_scope(target, allowed_targets):
                reason = (
                    f"Target '{target}' is not in the approved scope for engagement "
                    f"'{engagement_id}'. Add the target to AllowedTargets before proceeding."
                )
                logger.warning(
                    "POLICY_OUT_OF_SCOPE tenant=%s engagement=%s action=%s target=%s",
                    tenant_id, engagement_id, action_type.value, target,
                )
                return PolicyDecision(
                    allowed=False, reason=reason,
                    action_type=action_type, blocked_by="SCOPE",
                )

        # ── 3. Allowed ────────────────────────────────────────────────────
        logger.info(
            "POLICY_ALLOWED tenant=%s engagement=%s action=%s target=%s",
            tenant_id, engagement_id, action_type.value, target,
        )
        return PolicyDecision(
            allowed=True,
            reason=f"Action '{action_type.value}' is within policy.",
            action_type=action_type,
        )

    def list_blocked_actions(self) -> List[str]:
        """Return names of all permanently blocked action types."""
        return [a.value for a in _ALWAYS_BLOCKED]


def _target_in_scope(target: str, allowed_targets: List[str]) -> bool:
    """
    Check whether *target* is within any of the *allowed_targets*.

    Supports simple wildcard prefix patterns:
      '*.acmefintech.com' matches 'staging.acmefintech.com'

    Does NOT use regex to avoid ReDoS.
    """
    for allowed in allowed_targets:
        if allowed.startswith("*."):
            suffix = allowed[1:]  # e.g. '.acmefintech.com'
            if target == allowed[2:] or target.endswith(suffix):
                return True
        elif target == allowed:
            return True
    return False
