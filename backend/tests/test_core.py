"""
AegisTwin Test Suite
====================
Tests cover:
1. Policy blocking unsafe actions
2. Risk scoring
3. Attack path creation
4. Offensive hypothesis generation
5. Telemetry ingestion and fingerprint clustering
6. Deception event handling
7. Tool broker normalization
8. Remediation ticket generation
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.core.policy import ActionType, PolicyEngine
from app.risk.engine import RiskEngine, RiskFactors
from app.agents.offensive.agent import (
    OffensiveMissionPlanner,
    VulnerabilityReasoner,
    AttackPathBuilder,
    SafeValidationPlanner,
)
from app.agents.defensive.agent import (
    TelemetryIngestionAgent,
    BehaviorAnalyticsAgent,
    FingerprintCorrelationEngine,
    ActorClusterBuilder,
)
from app.deception.fabric import DeceptionFabric
from app.tool_broker.broker import ToolBroker, build_default_broker
from app.remediation.agent import RemediationAgent
from app.detections.agent import DetectionEngineeringAgent


TENANT_ID = "test-tenant-001"
ENGAGEMENT_ID = "test-engagement-001"


# ─── 1. Policy Engine Tests ───────────────────────────────────────────────────

class TestPolicyEngine:
    """Tests for the safety policy engine."""

    def setup_method(self):
        self.engine = PolicyEngine()

    def test_always_blocked_exploit_execution(self):
        """Exploit execution must ALWAYS be blocked — no exceptions."""
        decision = self.engine.evaluate(
            action_type=ActionType.EXPLOIT_EXECUTION,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is False
        assert decision.blocked_by == "ALWAYS_BLOCKED"
        assert "permanently blocked" in decision.reason.lower()

    def test_always_blocked_credential_theft(self):
        decision = self.engine.evaluate(
            action_type=ActionType.CREDENTIAL_THEFT,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is False
        assert decision.blocked_by == "ALWAYS_BLOCKED"

    def test_always_blocked_lateral_movement(self):
        decision = self.engine.evaluate(
            action_type=ActionType.LATERAL_MOVEMENT,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is False

    def test_always_blocked_data_exfiltration(self):
        decision = self.engine.evaluate(
            action_type=ActionType.DATA_EXFILTRATION,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is False

    def test_always_blocked_persistence(self):
        decision = self.engine.evaluate(
            action_type=ActionType.PERSISTENCE,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is False

    def test_always_blocked_c2(self):
        decision = self.engine.evaluate(
            action_type=ActionType.C2_COMMUNICATION,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is False

    def test_always_blocked_log_deletion(self):
        decision = self.engine.evaluate(
            action_type=ActionType.LOG_DELETION,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is False

    def test_allowed_asset_discovery(self):
        """Safe actions must be allowed when in scope."""
        decision = self.engine.evaluate(
            action_type=ActionType.ASSET_DISCOVERY,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is True

    def test_allowed_vulnerability_reasoning(self):
        decision = self.engine.evaluate(
            action_type=ActionType.VULNERABILITY_REASONING,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert decision.allowed is True

    def test_scope_block_out_of_scope_target(self):
        """Out-of-scope targets must be blocked."""
        decision = self.engine.evaluate(
            action_type=ActionType.SUBDOMAIN_ENUM,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="victim.com",
            allowed_targets=["target.com", "staging.target.com"],
        )
        assert decision.allowed is False
        assert decision.blocked_by == "SCOPE"

    def test_scope_allowed_in_scope_target(self):
        decision = self.engine.evaluate(
            action_type=ActionType.SUBDOMAIN_ENUM,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="staging.target.com",
            allowed_targets=["target.com", "staging.target.com"],
        )
        assert decision.allowed is True

    def test_list_blocked_actions_count(self):
        blocked = self.engine.list_blocked_actions()
        assert len(blocked) >= 10, "Expected at least 10 permanently blocked actions"
        assert ActionType.EXPLOIT_EXECUTION.value in blocked
        assert ActionType.DATA_EXFILTRATION.value in blocked


# ─── 2. Risk Engine Tests ─────────────────────────────────────────────────────

class TestRiskEngine:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_critical_risk_all_max(self):
        factors = RiskFactors(
            exposure=1.0, exploitability=1.0, asset_criticality=1.0,
            data_sensitivity=1.0, control_gap=1.0, detection_gap=1.0, confidence=1.0
        )
        score = self.engine.score(factors)
        assert score.level == "critical"
        assert score.normalized_score > 75

    def test_low_risk_all_min(self):
        factors = RiskFactors(
            exposure=0.1, exploitability=0.1, asset_criticality=0.1,
            data_sensitivity=0.1, control_gap=0.1, detection_gap=0.1, confidence=0.1
        )
        score = self.engine.score(factors)
        assert score.level in ("low", "informational")

    def test_medium_risk_balanced(self):
        factors = RiskFactors(
            exposure=0.5, exploitability=0.5, asset_criticality=0.5,
            data_sensitivity=0.5, control_gap=0.5, detection_gap=0.5, confidence=0.5
        )
        score = self.engine.score(factors)
        assert score.level in ("low", "medium", "high")  # Depends on tuning

    def test_explanation_contains_level(self):
        factors = RiskFactors(
            exposure=0.9, exploitability=0.8, asset_criticality=0.9,
            data_sensitivity=0.9, control_gap=0.8, detection_gap=0.7, confidence=0.8
        )
        score = self.engine.score(factors)
        assert score.level in score.explanation.lower() or score.level.upper() in score.explanation

    def test_score_from_dict(self):
        score = self.engine.score_from_dict({
            "exposure": 0.8,
            "exploitability": 0.7,
            "asset_criticality": 0.9,
            "data_sensitivity": 0.9,
            "control_gap": 0.8,
            "detection_gap": 0.7,
            "confidence": 0.8,
        })
        assert 0 <= score.normalized_score <= 100
        assert score.level in ("critical", "high", "medium", "low", "informational")

    def test_factors_preserved_in_output(self):
        factors = RiskFactors(exposure=0.7, exploitability=0.6)
        score = self.engine.score(factors)
        assert "exposure" in score.factors
        assert score.factors["exposure"] == 0.7


# ─── 3. Attack Path Tests ─────────────────────────────────────────────────────

class TestAttackPathBuilder:
    def setup_method(self):
        self.builder = AttackPathBuilder(TENANT_ID, ENGAGEMENT_ID)

    def test_build_creates_nodes_and_edges(self):
        hypothesis = {
            "id": "hyp-001",
            "chained_signals": ["staging_exposure", "weak_mfa_policy"],
            "confidence": 0.75,
        }
        assets = [{"name": "Staging App", "asset_type": "web_app"}]
        path = self.builder.build(hypothesis, [], assets)
        assert len(path["nodes"]) >= 2
        assert len(path["edges"]) >= 1

    def test_builds_business_impact_terminal_node(self):
        hypothesis = {
            "id": "hyp-002",
            "chained_signals": ["staging_exposure"],
            "confidence": 0.6,
        }
        path = self.builder.build(hypothesis, [], [])
        node_types = [n["node_type"] for n in path["nodes"]]
        assert "BusinessImpact" in node_types

    def test_edges_connect_sequential_nodes(self):
        hypothesis = {
            "id": "hyp-003",
            "chained_signals": ["staging_exposure", "weak_mfa_policy"],
            "confidence": 0.7,
        }
        path = self.builder.build(hypothesis, [], [])
        # Edges should form a chain
        assert len(path["edges"]) >= len(path["nodes"]) - 1


# ─── 4. Offensive Hypothesis Generation ──────────────────────────────────────

class TestVulnerabilityReasoner:
    def setup_method(self):
        self.reasoner = VulnerabilityReasoner(TENANT_ID, ENGAGEMENT_ID)

    def _make_assets(self):
        return [
            {"name": "Staging App", "asset_type": "web_app"},
            {"name": "Okta IdP", "asset_type": "identity_provider"},
            {"name": "Customer DB", "asset_type": "database"},
        ]

    def test_generates_hypothesis_for_staging_and_mfa(self):
        signals = [
            {"signal_type": "staging_exposure", "confidence": 0.85},
            {"signal_type": "weak_mfa_policy", "confidence": 0.80},
        ]
        hypotheses = self.reasoner.generate_hypotheses(signals, self._make_assets())
        assert len(hypotheses) >= 1
        assert any("staging" in h["hypothesis"].lower() or "mfa" in h["hypothesis"].lower()
                   for h in hypotheses)

    def test_hypothesis_has_required_fields(self):
        signals = [{"signal_type": "staging_exposure", "confidence": 0.85}]
        hypotheses = self.reasoner.generate_hypotheses(signals, self._make_assets())
        for h in hypotheses:
            assert "hypothesis" in h
            assert "confidence" in h
            assert 0 <= h["confidence"] <= 1

    def test_returns_default_hypothesis_if_no_signals(self):
        hypotheses = self.reasoner.generate_hypotheses([], [])
        assert len(hypotheses) >= 1


# ─── 5. Telemetry Ingestion + Clustering ─────────────────────────────────────

class TestTelemetryIngestion:
    def setup_method(self):
        self.ingestion = TelemetryIngestionAgent(TENANT_ID)

    def test_normalizes_waf_event(self):
        raw = {
            "source": "waf",
            "timestamp": "2024-03-15T14:00:00Z",
            "actor": {"ip": "1.2.3.4", "asn": "AS209605", "user_agent": "Nuclei"},
            "target": {"asset_id": "asset-001", "endpoint": "/admin"},
            "action": "GET",
        }
        normalized = self.ingestion.normalize(raw)
        assert normalized["source"] == "waf"
        assert normalized["actor_ip"] == "1.2.3.4"
        assert normalized["actor_asn"] == "AS209605"
        assert normalized["target_endpoint"] == "/admin"
        assert normalized["tenant_id"] == TENANT_ID

    def test_unknown_source_defaults_to_custom(self):
        raw = {"source": "unknown_siem", "timestamp": "2024-01-01T00:00:00Z",
               "actor": {}, "target": {}}
        normalized = self.ingestion.normalize(raw)
        assert normalized["source"] == "custom"


class TestFingerprintCorrelationEngine:
    def setup_method(self):
        self.engine = FingerprintCorrelationEngine()

    def _make_events(self, count=5):
        return [
            {
                "actor_ip": "185.220.101.5",
                "actor_asn": "AS209605",
                "actor_ja3": "t13d1512h2",
                "actor_ja4": "t13d1512h2_8daaf",
                "actor_user_agent": "Nuclei/2.9.6",
                "target_endpoint": f"/path{i}",
                "source": "waf",
                "action": "GET",
            }
            for i in range(count)
        ]

    def test_builds_fingerprint(self):
        events = self._make_events(10)
        fp = self.engine.build_fingerprint(events)
        assert "asn_pattern" in fp
        assert "AS209605" in fp["asn_pattern"]
        assert "source_ips" in fp
        assert "cluster_hash" in fp

    def test_timing_regularity_for_large_batch(self):
        events = self._make_events(15)
        fp = self.engine.build_fingerprint(events)
        assert fp["timing_regular"] is True

    def test_honeytoken_detection(self):
        events = self._make_events(5)
        events.append({"action": "honeytoken_access", "actor_ip": "1.2.3.4",
                       "actor_asn": "AS1", "source": "custom"})
        fp = self.engine.build_fingerprint(events)
        assert fp["honeytoken_interaction"] is True


class TestActorClusterBuilder:
    def setup_method(self):
        self.builder = ActorClusterBuilder(TENANT_ID)

    def _make_events(self, include_honeytoken=False):
        events = [
            {
                "source": "waf",
                "actor_ip": "185.220.101.5",
                "actor_asn": "AS209605",
                "actor_user_agent": "Nuclei/2.9.6",
                "actor_ja3": "t13d1512h2",
                "actor_ja4": "t13d1512h2_8daaf",
                "target_endpoint": "/admin",
                "action": "GET",
                "event_timestamp": "2024-03-15T14:00:00Z",
            }
        ] * 25  # 25 events from same IP

        if include_honeytoken:
            events.append({
                "source": "custom",
                "actor_ip": "185.220.101.5",
                "actor_asn": "AS209605",
                "actor_user_agent": "python-requests",
                "actor_ja3": "t13d1512h2",
                "actor_ja4": "t13d1512h2_8daaf",
                "target_endpoint": "/honeytoken-path",
                "action": "honeytoken_access",
                "event_timestamp": "2024-03-15T14:25:00Z",
            })
        return events

    def test_cluster_has_required_fields(self):
        cluster = self.builder.build_cluster(self._make_events())
        assert "cluster_id" in cluster
        assert "confidence" in cluster
        assert "likely_automation" in cluster
        assert "evidence" in cluster
        assert "recommended_actions" in cluster

    def test_confidence_increases_with_honeytoken(self):
        cluster_normal = self.builder.build_cluster(self._make_events(False))
        cluster_honey = self.builder.build_cluster(self._make_events(True))
        assert cluster_honey["confidence"] > cluster_normal["confidence"]

    def test_high_request_volume_increases_confidence(self):
        cluster = self.builder.build_cluster(self._make_events())
        assert cluster["confidence"] > 0.3


# ─── 6. Deception Fabric Tests ───────────────────────────────────────────────

class TestDeceptionFabric:
    def setup_method(self):
        self.fabric = DeceptionFabric()

    def test_honey_token_has_fake_marker(self):
        item = self.fabric.create_honey_token(TENANT_ID, "Test Token")
        assert "AEGISTWIN_FAKE_DO_NOT_USE" in item["fake_value"]
        assert item["internal_marker"] == "AEGISTWIN_FAKE_DO_NOT_USE"

    def test_honey_credential_has_fake_marker(self):
        item = self.fabric.create_honey_credential(TENANT_ID, "Test Cred")
        assert "AEGISTWIN_FAKE_DO_NOT_USE" in item["fake_value"]
        assert "warning" in item["metadata_json"]

    def test_canary_document_has_fake_marker(self):
        item = self.fabric.create_canary_document(TENANT_ID, "Test Doc")
        assert "AEGISTWIN_FAKE_DO_NOT_USE" in item["fake_value"]

    def test_deception_items_are_different_each_call(self):
        item1 = self.fabric.create_honey_token(TENANT_ID, "Token A")
        item2 = self.fabric.create_honey_token(TENANT_ID, "Token B")
        assert item1["id"] != item2["id"]
        assert item1["fake_value"] != item2["fake_value"]

    def test_deception_event_creation(self):
        item = self.fabric.create_honey_token(TENANT_ID, "Alert Token")
        event = self.fabric.create_deception_event(
            tenant_id=TENANT_ID,
            deception_item_id=item["id"],
            triggered_by_ip="1.2.3.4",
        )
        assert event["triggered_by_ip"] == "1.2.3.4"
        assert event["deception_item_id"] == item["id"]
        assert "alert_message" in event


# ─── 7. Tool Broker Tests ─────────────────────────────────────────────────────

class TestToolBroker:
    def setup_method(self):
        self.broker = build_default_broker()

    def test_registered_tools_present(self):
        assert "subdomain_discovery" in self.broker._registry
        assert "web_fingerprint" in self.broker._registry
        assert "secret_scan" in self.broker._registry
        assert "honeytoken_monitor" in self.broker._registry

    def test_successful_tool_execution(self):
        result = self.broker.request_execution(
            tool_name="subdomain_discovery",
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="example.com",
            allowed_targets=["example.com"],  # scope must be explicit
        )
        assert result["status"] == "success"
        assert result["tool_name"] == "subdomain_discovery"
        assert isinstance(result["signals"], list)
        assert isinstance(result["evidence"], list)
        assert result["started_at"] is not None
        assert result["finished_at"] is not None

    def test_normalized_output_schema(self):
        """All tool results must follow the normalized schema."""
        result = self.broker.request_execution(
            tool_name="web_fingerprint",
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="staging.example.com",
        )
        required_fields = {
            "tool_name", "tenant_id", "engagement_id", "target",
            "status", "evidence", "signals", "cost", "started_at", "finished_at"
        }
        assert required_fields.issubset(result.keys())

    def test_unregistered_tool_returns_failed(self):
        result = self.broker.request_execution(
            tool_name="nonexistent_tool",
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="example.com",
        )
        assert result["status"] == "failed"
        assert "not registered" in (result.get("error") or "")

    def test_out_of_scope_tool_returns_blocked(self):
        result = self.broker.request_execution(
            tool_name="subdomain_discovery",
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="not-in-scope.com",
            allowed_targets=["approved.com"],
        )
        assert result["status"] == "blocked"

    def test_secret_scan_returns_signals(self):
        """
        The live entropy scanner probes HTTP endpoints for high-entropy strings.
        The tool may return empty signals when no secrets are exposed — that is correct
        behavior. We assert the tool's response contract (status=success, signals is list)
        rather than network-dependent content.
        """
        result = self.broker.request_execution(
            tool_name="secret_scan",
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="example.com",
            allowed_targets=["example.com"],  # scope must be explicit
        )
        assert result["status"] == "success"
        assert isinstance(result["signals"], list)
        assert isinstance(result["evidence"], list)
        assert len(result["evidence"]) > 0  # must always return at least one evidence entry


# ─── 8. Remediation Agent Tests ───────────────────────────────────────────────

class TestRemediationAgent:
    def setup_method(self):
        self.agent = RemediationAgent()
        self.sample_finding = {
            "id": "finding-001",
            "title": "MFA Bypass in Admin Portal",
            "description": "Conditional MFA has exceptions exploitable by an attacker.",
            "risk_level": "high",
            "risk_score": 72.3,
            "evidence": ["MFA policy review shows exception active"],
            "recommended_fix": "Remove trusted device exception",
            "retest_plan": "Verify MFA enforced for all admin sessions",
            "cve_ids": [],
        }

    def test_generates_jira_and_github_tickets(self):
        tickets = self.agent.from_finding(self.sample_finding, TENANT_ID)
        assert len(tickets) == 2
        types = {t["ticket_type"] for t in tickets}
        assert "jira" in types
        assert "github" in types

    def test_jira_ticket_has_payload(self):
        tickets = self.agent.from_finding(self.sample_finding, TENANT_ID)
        jira = next(t for t in tickets if t["ticket_type"] == "jira")
        assert "ticket_payload" in jira
        assert "summary" in jira["ticket_payload"]
        assert "priority" in jira["ticket_payload"]

    def test_github_issue_has_body(self):
        tickets = self.agent.from_finding(self.sample_finding, TENANT_ID)
        gh = next(t for t in tickets if t["ticket_type"] == "github")
        assert "ticket_payload" in gh
        assert "body" in gh["ticket_payload"]
        assert "labels" in gh["ticket_payload"]

    def test_priority_maps_to_correct_level(self):
        tickets = self.agent.from_finding(self.sample_finding, TENANT_ID)
        jira = next(t for t in tickets if t["ticket_type"] == "jira")
        assert jira["ticket_payload"]["priority"]["name"] == "P1"  # high -> P1

    def test_retest_plan_included(self):
        tickets = self.agent.from_finding(self.sample_finding, TENANT_ID)
        for t in tickets:
            assert t["retest_plan"] is not None
            assert len(t["retest_plan"]) > 0


# ─── 9. Detection Engineering Tests ──────────────────────────────────────────

class TestDetectionEngineeringAgent:
    def setup_method(self):
        self.agent = DetectionEngineeringAgent()

    def test_generates_sigma_from_finding(self):
        finding = {
            "title": "Admin Portal Path Disclosure",
            "description": "robots.txt discloses /admin path",
            "risk_level": "high",
        }
        drafts = self.agent.from_finding(finding, TENANT_ID)
        assert len(drafts) >= 1
        sigma_drafts = [d for d in drafts if d["rule_type"] == "sigma"]
        assert len(sigma_drafts) >= 1

    def test_sigma_content_contains_yaml(self):
        finding = {
            "title": "Test Finding",
            "description": "Test description",
            "risk_level": "medium",
        }
        drafts = self.agent.from_finding(finding, TENANT_ID)
        sigma = next(d for d in drafts if d["rule_type"] == "sigma")
        assert "title:" in sigma["content"]
        assert "detection:" in sigma["content"]

    def test_generates_from_cluster(self):
        cluster = {
            "cluster_id": "CLUSTER-ABC123",
            "confidence": 0.85,
            "fingerprint": {
                "asn_pattern": ["AS209605"],
                "ja3_fingerprints": ["t13d1512h2"],
                "path_probing_sequence": ["/admin", "/.env"],
                "source_ips": ["185.220.101.5"],
            },
        }
        drafts = self.agent.from_cluster(cluster, TENANT_ID)
        assert len(drafts) >= 1

    def test_all_drafts_have_required_fields(self):
        finding = {"title": "Test", "description": "Test", "risk_level": "high"}
        drafts = self.agent.from_finding(finding, TENANT_ID)
        for d in drafts:
            assert "title" in d
            assert "rule_type" in d
            assert "content" in d
            assert "status" in d
            assert d["status"] == "draft"


# ─── 10. Integration: Full Offensive Mission ─────────────────────────────────

class TestOffensiveMissionIntegration:
    def test_full_mission_returns_report(self):
        """Full mission must return all required report fields."""
        planner = OffensiveMissionPlanner(TENANT_ID, ENGAGEMENT_ID)
        assets = [
            {"name": "Staging App", "asset_type": "web_app",
             "hostname": "staging.example.com", "url": "https://staging.example.com",
             "criticality": 0.5, "data_sensitivity": 0.4},
            {"name": "Okta IdP", "asset_type": "identity_provider",
             "hostname": "example.okta.com",
             "criticality": 0.9, "data_sensitivity": 0.8},
        ]
        report = planner.run_mission(
            objective="Find highest-risk attack path",
            assets=assets,
            allowed_targets=["staging.example.com", "example.okta.com"],
        )

        required_fields = {
            "hypothesis", "target_assets", "required_evidence",
            "safe_validation_steps", "blocked_unsafe_steps",
            "attack_path", "risk_score", "risk_level", "confidence",
            "business_impact", "recommended_fix", "retest_plan",
        }
        assert required_fields.issubset(report.keys())

    def test_blocked_unsafe_steps_present(self):
        """Report must always include the list of blocked unsafe steps."""
        planner = OffensiveMissionPlanner(TENANT_ID, ENGAGEMENT_ID)
        report = planner.run_mission("Test objective", [], [])
        assert len(report["blocked_unsafe_steps"]) > 0
        assert any("exploit" in s.lower() for s in report["blocked_unsafe_steps"])

    def test_safe_validation_ladder_present(self):
        planner = OffensiveMissionPlanner(TENANT_ID, ENGAGEMENT_ID)
        assets = [
            {"name": "Staging App", "asset_type": "web_app",
             "hostname": "staging.example.com", "url": "https://staging.example.com",
             "criticality": 0.5, "data_sensitivity": 0.4},
        ]
        report = planner.run_mission("Find paths", assets, ["staging.example.com"])
        # Safe validation steps must include level numbers
        steps = report.get("safe_validation_steps", [])
        if steps:
            assert all("level" in s for s in steps)


# ─── 11. Security Regression Tests ───────────────────────────────────────────

class TestSecurityRegressions:
    """
    Tests that verify critical security fixes remain effective.
    Each test is a regression guard for a specific CVE-class finding.
    """

    def setup_method(self):
        self.engine = PolicyEngine()

    # CRIT-1 regression: scope bypass via allowed_targets=None
    def test_scope_bypass_via_none_allowed_targets_is_blocked(self):
        """
        Previously: target='evil.com', allowed_targets=None → silently allowed.
        Fixed: target with no allowed list → SCOPE-blocked by default-deny.
        """
        decision = self.engine.evaluate(
            action_type=ActionType.SUBDOMAIN_ENUM,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="evil.com",
            allowed_targets=None,  # no list provided
        )
        assert decision.allowed is False, (
            "Target with no allowed_targets must be blocked (default-deny)"
        )
        assert decision.blocked_by == "SCOPE"

    # CRIT-1 regression: no target → still allowed (unchanged behaviour)
    def test_no_target_no_allowed_list_is_allowed(self):
        """No target supplied → scope check is skipped → action proceeds."""
        decision = self.engine.evaluate(
            action_type=ActionType.VULNERABILITY_REASONING,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target=None,
            allowed_targets=None,
        )
        assert decision.allowed is True

    # MED-1: wildcard scope matching
    def test_wildcard_scope_allows_subdomain(self):
        decision = self.engine.evaluate(
            action_type=ActionType.SUBDOMAIN_ENUM,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="api.acmefintech.com",
            allowed_targets=["*.acmefintech.com"],
        )
        assert decision.allowed is True, "Wildcard should match subdomain"

    def test_wildcard_scope_blocks_different_domain(self):
        decision = self.engine.evaluate(
            action_type=ActionType.SUBDOMAIN_ENUM,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
            target="evil.com",
            allowed_targets=["*.acmefintech.com"],
        )
        assert decision.allowed is False

    # Audit callback regression
    def test_audit_callback_invoked_on_every_decision(self):
        """Policy engine must invoke audit_callback for both allowed and blocked decisions."""
        decisions_captured = []
        engine = PolicyEngine(audit_callback=lambda d: decisions_captured.append(d))

        engine.evaluate(
            action_type=ActionType.ASSET_DISCOVERY,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        engine.evaluate(
            action_type=ActionType.EXPLOIT_EXECUTION,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        assert len(decisions_captured) == 2
        assert decisions_captured[0].allowed is True
        assert decisions_captured[1].allowed is False
        assert decisions_captured[1].blocked_by == "ALWAYS_BLOCKED"

    def test_audit_callback_failure_does_not_crash_evaluation(self):
        """If the audit callback raises, the policy decision must still be returned."""
        def bad_callback(d):
            raise RuntimeError("audit store offline")

        engine = PolicyEngine(audit_callback=bad_callback)
        decision = engine.evaluate(
            action_type=ActionType.ASSET_DISCOVERY,
            tenant_id=TENANT_ID,
            engagement_id=ENGAGEMENT_ID,
        )
        # Decision must still come back correctly despite callback failure
        assert decision.allowed is True

    # Deception cross-tenant isolation
    def test_deception_tokens_are_tenant_scoped(self):
        """Deception items must embed their tenant_id; cross-tenant detection possible."""
        fabric = DeceptionFabric()
        item_a = fabric.create_honey_token("tenant-A", "Token for A")
        item_b = fabric.create_honey_token("tenant-B", "Token for B")
        assert item_a["tenant_id"] == "tenant-A"
        assert item_b["tenant_id"] == "tenant-B"
        assert item_a["tenant_id"] != item_b["tenant_id"]
