"""
Offensive Red-Team AI Agent
============================
Implements the full offensive reasoning loop:
  Observe → Hypothesize → Validate Safely → Chain → Score → Report → Retest

Safety hard-stops are enforced by the PolicyEngine before any tool execution.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
import os
import json
from typing import Any, Dict, List, Optional

from app.core.policy import ActionType, PolicyDecision, PolicyEngine
from app.risk.engine import RiskEngine, RiskFactors

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None

logger = logging.getLogger(__name__)
policy_engine = PolicyEngine()
risk_engine = RiskEngine()


# ─── Validation Ladder ────────────────────────────────────────────────────────
#
# Level 1: Signal detected
# Level 2: Corroborated by multiple sources
# Level 3: Preconditions verified
# Level 4: Non-destructive proof
# Level 5: Lab/staging reproduction only
# Level 6: Human-approved production validation
# Level 7: Remediated and retested


class OffensiveMissionPlanner:
    """
    Top-level orchestrator for an offensive mission.

    Takes a mission objective and coordinates all sub-agents to produce
    a full attack path report.
    """

    def __init__(self, tenant_id: str, engagement_id: str):
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id
        self.recon = ReconPlanner(tenant_id, engagement_id)
        self.reasoner = VulnerabilityReasoner(tenant_id, engagement_id)
        self.path_builder = AttackPathBuilder(tenant_id, engagement_id)
        self.validator = SafeValidationPlanner(tenant_id, engagement_id)
        self.poc_planner = ProofOfImpactPlanner(tenant_id, engagement_id)
        self.reporter = OffensiveReportGenerator()

    def run_mission(
        self,
        objective: str,
        assets: List[Dict[str, Any]],
        allowed_targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full offensive loop and return a structured report.
        """
        logger.info(
            "MISSION_START tenant=%s engagement=%s objective=%s",
            self.tenant_id,
            self.engagement_id,
            objective,
        )

        # 1. OBSERVE — Recon
        recon_signals = self.recon.gather_signals(assets, allowed_targets)

        # 2. HYPOTHESIZE — Vulnerability reasoning
        hypotheses = self.reasoner.generate_hypotheses(recon_signals, assets)

        # 3. VALIDATE SAFELY — Safe validation plan
        validation_plans = []
        for h in hypotheses:
            plan = self.validator.build_plan(h, allowed_targets)
            validation_plans.append(plan)

        # 4. CHAIN — Build attack path
        best_hypothesis = hypotheses[0] if hypotheses else {}
        attack_path = self.path_builder.build(best_hypothesis, recon_signals, assets)

        # 5. SCORE — Risk scoring
        risk_factors = RiskFactors(
            exposure=best_hypothesis.get("exposure", 0.7),
            exploitability=best_hypothesis.get("exploitability", 0.6),
            asset_criticality=best_hypothesis.get("asset_criticality", 0.8),
            data_sensitivity=best_hypothesis.get("data_sensitivity", 0.8),
            control_gap=best_hypothesis.get("control_gap", 0.7),
            detection_gap=best_hypothesis.get("detection_gap", 0.6),
            confidence=best_hypothesis.get("confidence", 0.7),
        )
        risk = risk_engine.score(risk_factors)

        # 6. PROOF OF IMPACT — What would happen if exploited (lab/staging only)
        poc = self.poc_planner.plan(best_hypothesis, attack_path)

        # 7. REPORT
        report = self.reporter.generate(
            objective=objective,
            hypothesis=best_hypothesis,
            attack_path=attack_path,
            validation_plans=validation_plans,
            risk=risk,
            poc=poc,
            assets=assets,
        )

        logger.info(
            "MISSION_COMPLETE tenant=%s engagement=%s risk=%s",
            self.tenant_id,
            self.engagement_id,
            risk.level,
        )
        return report


class ReconPlanner:
    """
    Gathers attack surface signals without touching production systems.
    Uses only mock adapters in safe mode.
    """

    def __init__(self, tenant_id: str, engagement_id: str):
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id

    def gather_signals(
        self,
        assets: List[Dict[str, Any]],
        allowed_targets: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        signals = []
        for asset in assets:
            target = asset.get("hostname") or asset.get("url") or asset.get("name")
            decision = policy_engine.evaluate(
                action_type=ActionType.ASSET_DISCOVERY,
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                target=target,
                allowed_targets=allowed_targets,
            )
            if not decision.allowed:
                signals.append({
                    "asset": asset.get("name"),
                    "status": "blocked",
                    "reason": decision.reason,
                })
                continue

            # Mock recon signal generation
            signals.extend(self._mock_recon(asset))

        return signals

    def _mock_recon(self, asset: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Deterministic mock signals based on asset type."""
        asset_type = asset.get("asset_type", "")
        name = asset.get("name", "")
        signals = []

        if asset_type in ("web_app", "api"):
            signals.append({
                "asset": name,
                "signal_type": "exposed_endpoint",
                "detail": f"HTTP/HTTPS service detected on {asset.get('url', name)}",
                "confidence": 0.95,
                "source": "web_fingerprint",
            })
            if "staging" in name.lower():
                signals.append({
                    "asset": name,
                    "signal_type": "staging_exposure",
                    "detail": "Staging environment publicly accessible — weak auth controls likely",
                    "confidence": 0.85,
                    "source": "web_fingerprint",
                })

        if asset_type == "repository":
            signals.append({
                "asset": name,
                "signal_type": "secret_candidate",
                "detail": "Potential hardcoded credentials or secrets in commit history",
                "confidence": 0.7,
                "source": "secret_scan",
            })

        if asset_type == "cloud_account":
            signals.append({
                "asset": name,
                "signal_type": "misconfigured_policy",
                "detail": "S3 bucket with public ACL or overpermissive IAM policy detected",
                "confidence": 0.75,
                "source": "cloud_config_review",
            })

        if asset_type == "identity_provider":
            signals.append({
                "asset": name,
                "signal_type": "weak_mfa_policy",
                "detail": "MFA not enforced for all user accounts — conditional MFA gaps",
                "confidence": 0.8,
                "source": "cloud_config_review",
            })

        return signals


class VulnerabilityReasoner:
    """
    Converts recon signals into structured attack hypotheses.
    In production, this would call an LLM with structured prompts.
    Currently uses deterministic mock reasoning.
    """

    def __init__(self, tenant_id: str, engagement_id: str):
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id

    def generate_hypotheses(
        self,
        signals: List[Dict[str, Any]],
        assets: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Generate ranked attack hypotheses from signals.
        """
        decision = policy_engine.evaluate(
            action_type=ActionType.VULNERABILITY_REASONING,
            tenant_id=self.tenant_id,
            engagement_id=self.engagement_id,
        )
        if not decision.allowed:
            return []

        provider = os.getenv("LLM_PROVIDER", "mock").lower()
        if provider == "openai" and AsyncOpenAI:
            # We can't safely await here since generate_hypotheses is synchronous in current design,
            # but we can implement the structure. For now, we degrade gracefully if it's not async.
            # In a real async environment, we'd use await self._llm_reason(signals, assets).
            # To keep things synchronous without rewriting the agent's core loop, we'll use sync OpenAI.
            from openai import OpenAI
            client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            try:
                prompt = f"Analyze these signals: {signals} against assets: {assets}. Generate attack hypotheses as JSON list."
                response = client.chat.completions.create(
                    model="gpt-4o",
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": "You are an expert red-team AI. Return JSON: {'hypotheses': [{'id':'uuid','hypothesis':'string','chained_signals':['string'],'exposure':0.8,'exploitability':0.7,'asset_criticality':0.9,'data_sensitivity':0.9,'control_gap':0.8,'detection_gap':0.8,'confidence':0.9,'target_assets':['string']}]}"},
                        {"role": "user", "content": prompt}
                    ]
                )
                result = json.loads(response.choices[0].message.content)
                return result.get("hypotheses", [])
            except Exception as e:
                logger.error(f"LLM Reasoning failed, falling back to mock: {e}")
        
        # Fallback to mock logic
        hypotheses = []
        signal_types = {s["signal_type"] for s in signals if "signal_type" in s}

        if "staging_exposure" in signal_types and "weak_mfa_policy" in signal_types:
            hypotheses.append({
                "id": str(uuid.uuid4()),
                "hypothesis": (
                    "Attacker accesses staging app unauthenticated or with leaked credentials, "
                    "exploits weak MFA policy to pivot to admin portal, "
                    "then reaches customer data store."
                ),
                "chained_signals": ["staging_exposure", "weak_mfa_policy"],
                "exposure": 0.85,
                "exploitability": 0.7,
                "asset_criticality": 0.9,
                "data_sensitivity": 0.95,
                "control_gap": 0.75,
                "detection_gap": 0.65,
                "confidence": 0.75,
                "target_assets": [
                    a["name"] for a in assets
                    if a.get("asset_type") in ("web_app", "identity_provider", "database")
                ],
            })

        if "misconfigured_policy" in signal_types:
            hypotheses.append({
                "id": str(uuid.uuid4()),
                "hypothesis": (
                    "Overpermissive cloud IAM role can be assumed by attacker with initial foothold, "
                    "granting read access to sensitive S3 buckets or cloud secrets."
                ),
                "chained_signals": ["misconfigured_policy"],
                "exposure": 0.7,
                "exploitability": 0.65,
                "asset_criticality": 0.8,
                "data_sensitivity": 0.85,
                "control_gap": 0.7,
                "detection_gap": 0.7,
                "confidence": 0.65,
                "target_assets": [
                    a["name"] for a in assets if a.get("asset_type") == "cloud_account"
                ],
            })

        if "secret_candidate" in signal_types:
            hypotheses.append({
                "id": str(uuid.uuid4()),
                "hypothesis": (
                    "Hardcoded secrets in repository commit history expose API keys or service account "
                    "credentials usable for unauthorized access."
                ),
                "chained_signals": ["secret_candidate"],
                "exposure": 0.8,
                "exploitability": 0.9,
                "asset_criticality": 0.7,
                "data_sensitivity": 0.75,
                "control_gap": 0.8,
                "detection_gap": 0.8,
                "confidence": 0.6,
                "target_assets": [
                    a["name"] for a in assets if a.get("asset_type") == "repository"
                ],
            })

        # Default hypothesis if no strong signals
        if not hypotheses:
            hypotheses.append({
                "id": str(uuid.uuid4()),
                "hypothesis": "No high-confidence attack path identified from current signals.",
                "chained_signals": list(signal_types),
                "exposure": 0.3,
                "exploitability": 0.3,
                "asset_criticality": 0.5,
                "data_sensitivity": 0.5,
                "control_gap": 0.3,
                "detection_gap": 0.3,
                "confidence": 0.3,
                "target_assets": [],
            })

        return hypotheses


class AttackPathBuilder:
    """
    Constructs a structured attack path graph from a hypothesis.
    Nodes represent attack stages; edges represent attacker movement.
    """

    def __init__(self, tenant_id: str, engagement_id: str):
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id

    def build(
        self,
        hypothesis: Dict[str, Any],
        signals: List[Dict[str, Any]],
        assets: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        decision = policy_engine.evaluate(
            action_type=ActionType.ATTACK_PATH_BUILD,
            tenant_id=self.tenant_id,
            engagement_id=self.engagement_id,
        )
        if not decision.allowed:
            return {"nodes": [], "edges": [], "error": decision.reason}

        nodes = []
        edges = []

        # Build path from chained signals
        chained = hypothesis.get("chained_signals", [])
        prev_id = None

        for i, signal_type in enumerate(chained):
            node_id = f"node_{i}"
            node = self._signal_to_node(signal_type, i)
            node["id"] = node_id
            nodes.append(node)

            if prev_id:
                edges.append({
                    "from": prev_id,
                    "to": node_id,
                    "relationship": "ENABLES",
                })
            prev_id = node_id

        # Add business impact terminal node
        impact_id = f"node_{len(nodes)}"
        nodes.append({
            "id": impact_id,
            "node_type": "BusinessImpact",
            "label": "Customer Data Exposure",
            "description": (
                "Attacker reaches customer financial data store — "
                "regulatory exposure (PCI-DSS, GDPR), reputational damage."
            ),
            "risk_score": hypothesis.get("confidence", 0.7),
            "detection_coverage": False,
        })
        if prev_id:
            edges.append({
                "from": prev_id,
                "to": impact_id,
                "relationship": "LEADS_TO",
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "hypothesis_id": hypothesis.get("id"),
        }

    def _signal_to_node(self, signal_type: str, index: int) -> Dict[str, Any]:
        mapping = {
            "staging_exposure": {
                "node_type": "EntryPoint",
                "label": "Staging App — Public Exposure",
                "description": "Staging environment accessible without VPN or IP restriction",
                "detection_coverage": False,
            },
            "weak_mfa_policy": {
                "node_type": "Weakness",
                "label": "Weak MFA Policy",
                "description": "MFA enforcement gaps allow account takeover via credential stuffing",
                "detection_coverage": True,
            },
            "misconfigured_policy": {
                "node_type": "CloudPermission",
                "label": "Overpermissive IAM Role",
                "description": "Cloud IAM policy grants excessive data read permissions",
                "detection_coverage": False,
            },
            "secret_candidate": {
                "node_type": "Weakness",
                "label": "Exposed Secrets in Repository",
                "description": "API keys or credentials committed to version control history",
                "detection_coverage": False,
            },
            "exposed_endpoint": {
                "node_type": "APIEndpoint",
                "label": "Exposed HTTP Endpoint",
                "description": "Service endpoint visible from public internet",
                "detection_coverage": True,
            },
        }
        return mapping.get(
            signal_type,
            {
                "node_type": "Weakness",
                "label": signal_type.replace("_", " ").title(),
                "description": f"Signal: {signal_type}",
                "detection_coverage": False,
            },
        )


class SafeValidationPlanner:
    """
    Builds a safe validation plan for each hypothesis.
    Maps validation actions to the 7-level safety ladder.
    Explicitly blocks dangerous validation approaches.
    """

    BLOCKED_STEPS = [
        "exploit execution against production",
        "credential use or abuse",
        "persistence installation",
        "C2 beacon delivery",
        "lateral movement automation",
        "data exfiltration",
        "log deletion",
        "destructive payload",
    ]

    def __init__(self, tenant_id: str, engagement_id: str):
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id

    def build_plan(
        self,
        hypothesis: Dict[str, Any],
        allowed_targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        chained = hypothesis.get("chained_signals", [])
        safe_steps = []

        if "staging_exposure" in chained:
            safe_steps.append({
                "level": 1,
                "description": "Confirm staging app is internet-accessible via passive DNS lookup",
                "action": ActionType.SUBDOMAIN_ENUM.value,
                "tool": "subdomain_discovery",
            })
            safe_steps.append({
                "level": 2,
                "description": "Corroborate with web fingerprint scan (header analysis, robots.txt, sitemap)",
                "action": ActionType.WEB_FINGERPRINT.value,
                "tool": "web_fingerprint",
            })
            safe_steps.append({
                "level": 3,
                "description": "Verify login endpoint exists without credential attempt",
                "action": ActionType.WEB_FINGERPRINT.value,
                "tool": "web_fingerprint",
            })

        if "weak_mfa_policy" in chained:
            safe_steps.append({
                "level": 2,
                "description": "Review IdP configuration via cloud config API (read-only)",
                "action": ActionType.CLOUD_CONFIG_REVIEW.value,
                "tool": "cloud_config_review",
            })

        if "secret_candidate" in chained:
            safe_steps.append({
                "level": 1,
                "description": "Scan repository history for entropy-high strings (read-only secret scan)",
                "action": ActionType.SECRET_SCAN.value,
                "tool": "secret_scan",
            })

        safe_steps.append({
            "level": 4,
            "description": (
                "Non-destructive proof: attempt unauthenticated access to staging endpoint, "
                "record response code only — no credential use"
            ),
            "action": ActionType.NON_DESTRUCTIVE_PROOF.value,
            "tool": "web_fingerprint",
        })
        safe_steps.append({
            "level": 5,
            "description": (
                "Lab/staging reproduction: replicate scenario in isolated test environment — "
                "requires explicit approval"
            ),
            "action": ActionType.NON_DESTRUCTIVE_PROOF.value,
            "tool": "mock_lab",
            "requires_approval": True,
        })

        return {
            "hypothesis_id": hypothesis.get("id"),
            "safe_validation_steps": safe_steps,
            "blocked_unsafe_steps": self.BLOCKED_STEPS,
            "validation_ladder_max_reached": max(
                (s["level"] for s in safe_steps), default=0
            ),
        }


class ProofOfImpactPlanner:
    """
    Plans what a proof-of-concept would demonstrate — in lab/staging only.
    Never executes real exploits or causes real impact.
    """

    def __init__(self, tenant_id: str, engagement_id: str):
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id

    def plan(
        self,
        hypothesis: Dict[str, Any],
        attack_path: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "scope": "lab/staging only — never production",
            "requires_human_approval": True,
            "demonstration": (
                "In an isolated clone of the staging environment, demonstrate that "
                "an unauthenticated attacker can reach the admin portal login page "
                "without MFA challenge, confirming the attack path preconditions."
            ),
            "evidence_to_collect": [
                "HTTP response codes showing admin panel reachable",
                "IdP configuration screenshot showing MFA bypass condition",
                "Network trace showing path from entry point to target",
            ],
            "safe_boundaries": [
                "No real user credentials will be used",
                "No data will be read, downloaded, or modified",
                "No persistence will be established",
                "Environment will be destroyed after demonstration",
            ],
        }


class OffensiveReportGenerator:
    """Generates the final structured attack path report."""

    def generate(
        self,
        objective: str,
        hypothesis: Dict[str, Any],
        attack_path: Dict[str, Any],
        validation_plans: List[Dict[str, Any]],
        risk: Any,
        poc: Dict[str, Any],
        assets: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        validation_plan = validation_plans[0] if validation_plans else {}

        return {
            "hypothesis": hypothesis.get("hypothesis", ""),
            "objective": objective,
            "target_assets": hypothesis.get("target_assets", []),
            "required_evidence": [
                "Staging app accessibility confirmation",
                "IdP MFA policy configuration (read-only)",
                "Admin portal login page response",
            ],
            "safe_validation_steps": validation_plan.get("safe_validation_steps", []),
            "blocked_unsafe_steps": validation_plan.get("blocked_unsafe_steps", []),
            "attack_path": {
                "nodes": attack_path.get("nodes", []),
                "edges": attack_path.get("edges", []),
            },
            "risk_score": risk.normalized_score,
            "risk_level": risk.level,
            "confidence": hypothesis.get("confidence", 0.0),
            "business_impact": (
                "Customer financial data exposure, regulatory penalties (PCI-DSS, GDPR), "
                "reputational damage, potential class-action liability."
            ),
            "recommended_fix": (
                "1. Enforce MFA for ALL users including admin accounts — no exceptions. "
                "2. Place staging environment behind VPN or IP allowlist. "
                "3. Rotate any exposed credentials or secrets. "
                "4. Enable cloud audit logging for IAM changes. "
                "5. Implement rate-limiting on login endpoints."
            ),
            "retest_plan": (
                "After remediation: "
                "1. Re-run web fingerprint scan to confirm staging not publicly accessible. "
                "2. Re-check IdP MFA policy via read-only config review. "
                "3. Verify secret scan returns clean results. "
                "4. Re-score risk — expected level: LOW or INFORMATIONAL."
            ),
            "risk_explanation": risk.explanation,
            "risk_factors": risk.factors,
            "proof_of_impact": poc,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
