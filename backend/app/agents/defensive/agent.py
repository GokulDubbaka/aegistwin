"""
Defensive Hunter AI Agent
==========================
Ingests telemetry, detects behavioral anomalies, fingerprints threat actors,
correlates events into actor clusters, and generates response recommendations.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─── Telemetry Ingestion ──────────────────────────────────────────────────────

class TelemetryIngestionAgent:
    """
    Ingests normalized telemetry events from any supported source.
    Supported sources: waf|edr|idp|cloud|dns|github|email|firewall|custom
    """

    SUPPORTED_SOURCES = {
        "waf", "edr", "idp", "cloud", "dns", "github", "email", "firewall", "custom"
    }

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw event to internal schema."""
        source = raw_event.get("source", "custom")
        if source not in self.SUPPORTED_SOURCES:
            source = "custom"

        actor = raw_event.get("actor", {})
        target = raw_event.get("target", {})

        return {
            "tenant_id": self.tenant_id,
            "source": source,
            "event_timestamp": raw_event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "actor_ip": actor.get("ip"),
            "actor_asn": actor.get("asn"),
            "actor_user_agent": actor.get("user_agent"),
            "actor_ja3": actor.get("ja3"),
            "actor_ja4": actor.get("ja4"),
            "actor_account": actor.get("account"),
            "target_asset_id": target.get("asset_id"),
            "target_resource": target.get("resource"),
            "target_endpoint": target.get("endpoint"),
            "action": raw_event.get("action"),
            "raw_event": raw_event.get("raw", {}),
        }


# ─── Behavior Analytics ───────────────────────────────────────────────────────

class BehaviorAnalyticsAgent:
    """
    Analyzes a window of telemetry events to detect suspicious behavior patterns.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def analyze(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze events for behavioral anomalies.
        Returns: { is_suspicious, behavioral_indicators, severity }
        """
        if not events:
            return {"is_suspicious": False, "behavioral_indicators": [], "severity": "none"}

        indicators = []
        is_suspicious = False

        # Check: High request volume from single IP
        ip_counts: Dict[str, int] = {}
        for e in events:
            ip = e.get("actor_ip", "")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        for ip, count in ip_counts.items():
            if count > 20:
                indicators.append({
                    "type": "high_request_volume",
                    "detail": f"IP {ip} sent {count} requests in window",
                    "confidence": min(0.5 + count / 100, 0.99),
                })
                is_suspicious = True

        # Check: User-agent inconsistency (same account, different UAs)
        account_uas: Dict[str, set] = {}
        for e in events:
            acct = e.get("actor_account", "")
            ua = e.get("actor_user_agent", "")
            if acct and ua:
                if acct not in account_uas:
                    account_uas[acct] = set()
                account_uas[acct].add(ua)

        for acct, uas in account_uas.items():
            if len(uas) > 3:
                indicators.append({
                    "type": "user_agent_inconsistency",
                    "detail": f"Account '{acct}' used {len(uas)} different user agents",
                    "confidence": 0.75,
                })
                is_suspicious = True

        # Check: Probing patterns (many 404s, scanning known paths)
        scanning_paths = {"/admin", "/.env", "/config", "/api/v1/users", "/wp-admin"}
        probe_endpoints = [
            e.get("target_endpoint", "") for e in events
            if e.get("target_endpoint") in scanning_paths
        ]
        if len(probe_endpoints) > 3:
            indicators.append({
                "type": "path_probing",
                "detail": f"Probing of {len(probe_endpoints)} sensitive paths detected",
                "confidence": 0.85,
            })
            is_suspicious = True

        # Check: Honeytoken interaction
        for e in events:
            if e.get("action") == "honeytoken_access":
                indicators.append({
                    "type": "honeytoken_triggered",
                    "detail": "Honeytoken was accessed — high confidence attacker activity",
                    "confidence": 0.97,
                })
                is_suspicious = True
                break

        severity = "none"
        if is_suspicious:
            max_confidence = max((i["confidence"] for i in indicators), default=0.0)
            if max_confidence >= 0.9:
                severity = "high"
            elif max_confidence >= 0.7:
                severity = "medium"
            else:
                severity = "low"

        return {
            "is_suspicious": is_suspicious,
            "behavioral_indicators": indicators,
            "severity": severity,
            "event_count": len(events),
        }


# ─── Fingerprint Correlation Engine ──────────────────────────────────────────

class FingerprintCorrelationEngine:
    """
    Builds a multi-dimensional fingerprint for a set of events.
    Fingerprint dimensions:
    - source ASN pattern
    - TLS JA3/JA4
    - HTTP header ordering (from user-agent)
    - request timing
    - path probing sequence
    - login cadence
    - cloud API call sequence
    - user-agent inconsistency
    - honeytoken interaction
    """

    def build_fingerprint(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not events:
            return {}

        asns = list({e.get("actor_asn") for e in events if e.get("actor_asn")})
        ja3s = list({e.get("actor_ja3") for e in events if e.get("actor_ja3")})
        ja4s = list({e.get("actor_ja4") for e in events if e.get("actor_ja4")})
        uas = list({e.get("actor_user_agent") for e in events if e.get("actor_user_agent")})
        ips = list({e.get("actor_ip") for e in events if e.get("actor_ip")})
        accounts = list({e.get("actor_account") for e in events if e.get("actor_account")})
        endpoints = [e.get("target_endpoint") for e in events if e.get("target_endpoint")]
        sources = list({e.get("source") for e in events if e.get("source")})

        # Detect timing cadence (requests per minute estimate)
        timing_regular = self._check_timing_regularity(events)
        honeytoken_hit = any(e.get("action") == "honeytoken_access" for e in events)

        fingerprint = {
            "asn_pattern": asns,
            "ja3_fingerprints": ja3s,
            "ja4_fingerprints": ja4s,
            "user_agents": uas,
            "source_ips": ips,
            "accounts": accounts,
            "path_probing_sequence": endpoints[:20],  # first 20 observed paths
            "telemetry_sources": sources,
            "timing_regular": timing_regular,
            "honeytoken_interaction": honeytoken_hit,
            "event_count": len(events),
        }

        # Generate a stable cluster hash for de-duplication
        fp_str = f"{sorted(asns)}:{sorted(ja3s)}:{sorted(ja4s)}"
        fingerprint["cluster_hash"] = hashlib.sha256(fp_str.encode()).hexdigest()[:16]

        return fingerprint

    def _check_timing_regularity(self, events: List[Dict[str, Any]]) -> bool:
        """Heuristic: if all requests are evenly spaced, likely automation."""
        # TODO: Implement with real timestamp math
        return len(events) > 10  # Mock: >10 events = likely automated


# ─── AI-Assisted Attack Detector ─────────────────────────────────────────────

class AIAssistedAttackDetector:
    """
    Detects patterns consistent with AI-assisted attacks:
    - Unusual request parameter mutations
    - Intelligent path discovery
    - Adaptive behavior after 401/403 responses
    """

    def detect(self, events: List[Dict[str, Any]], fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        signals = []
        likely_ai = "low"

        # Heuristic: many paths tried with intelligent variation
        paths = fingerprint.get("path_probing_sequence", [])
        if len(set(paths)) > 15:
            signals.append("Extensive path discovery — possible AI-generated path list")
            likely_ai = "medium"

        # Heuristic: JA4 fingerprint seen in threat intel (mock)
        ja4s = fingerprint.get("ja4_fingerprints", [])
        if ja4s and any("t13d" in j for j in ja4s):
            signals.append("JA4 fingerprint matches known automated scanning tool profile")
            likely_ai = "medium"

        # Heuristic: honeytoken + continued probing = attacker adapted
        if fingerprint.get("honeytoken_interaction") and len(events) > 50:
            signals.append("Continued probing after honeytoken trigger — adaptive behavior")
            likely_ai = "high"

        return {
            "likely_ai_assisted": likely_ai,
            "signals": signals,
        }


# ─── Threat Intel Correlator ─────────────────────────────────────────────────

class ThreatIntelCorrelator:
    """
    Correlates actor fingerprints against threat intelligence.
    Currently uses mock TI data — replace with real TI API calls.
    """

    # Mock TI database
    KNOWN_BAD_ASNS = {"AS209605", "AS14061", "AS20473"}
    KNOWN_SCANNER_UAS = {"Nuclei", "sqlmap", "nikto", "masscan", "zgrab"}

    def correlate(self, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        matches = []

        asns = fingerprint.get("asn_pattern", [])
        for asn in asns:
            if asn in self.KNOWN_BAD_ASNS:
                matches.append(f"ASN {asn} in threat intel bad-ASN list")

        uas = fingerprint.get("user_agents", [])
        for ua in uas:
            for scanner in self.KNOWN_SCANNER_UAS:
                if scanner.lower() in (ua or "").lower():
                    matches.append(f"User-agent matches known scanner: {scanner}")

        return {
            "ti_matches": matches,
            "ti_confidence_boost": min(len(matches) * 0.1, 0.3),
        }


# ─── Actor Cluster Builder ────────────────────────────────────────────────────

class ActorClusterBuilder:
    """
    Correlates all defensive signals into a named actor cluster.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.behavior = BehaviorAnalyticsAgent(tenant_id)
        self.fingerprinter = FingerprintCorrelationEngine()
        self.ai_detector = AIAssistedAttackDetector()
        self.ti_correlator = ThreatIntelCorrelator()

    def build_cluster(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Full defensive pipeline:
        Ingest events → Analyze behavior → Build fingerprint → Correlate TI → Output cluster
        """
        behavioral = self.behavior.analyze(events)
        fingerprint = self.fingerprinter.build_fingerprint(events)
        ai_signals = self.ai_detector.detect(events, fingerprint)
        ti_data = self.ti_correlator.correlate(fingerprint)

        # Compute cluster confidence
        base_confidence = 0.3
        if behavioral["is_suspicious"]:
            base_confidence += 0.3
        if fingerprint.get("honeytoken_interaction"):
            base_confidence += 0.25
        base_confidence += ti_data["ti_confidence_boost"]
        base_confidence = min(base_confidence, 0.99)

        # Determine automation likelihood
        likely_automation = "low"
        if fingerprint.get("timing_regular") and len(events) > 10:
            likely_automation = "high" if len(events) > 50 else "medium"

        # Recommended actions
        recommended_actions = []
        if fingerprint.get("honeytoken_interaction"):
            recommended_actions.append("IMMEDIATE: Block source IPs — honeytoken triggered")
        if behavioral["severity"] == "high":
            recommended_actions.append("Escalate to incident response team")
        if ti_data["ti_matches"]:
            recommended_actions.append("Correlate with threat intel — known bad actor")
        recommended_actions.append("Generate detection rule draft for observed behavior pattern")
        recommended_actions.append("Review SIEM for historical activity from same fingerprint")

        evidence = behavioral["behavioral_indicators"] + [
            f"TI match: {m}" for m in ti_data["ti_matches"]
        ] + ai_signals["signals"]

        cluster_id = f"CLUSTER-{fingerprint.get('cluster_hash', uuid.uuid4().hex[:8]).upper()}"

        return {
            "cluster_id": cluster_id,
            "tenant_id": self.tenant_id,
            "confidence": round(base_confidence, 2),
            "likely_automation": likely_automation,
            "likely_ai_assisted": ai_signals["likely_ai_assisted"],
            "evidence": evidence,
            "recommended_actions": recommended_actions,
            "fingerprint": fingerprint,
            "event_count": len(events),
            "behavioral_severity": behavioral["severity"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ─── Forensic Timeline Builder ────────────────────────────────────────────────

class ForensicTimelineBuilder:
    """Builds a chronological forensic timeline from events."""

    def build(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sorted_events = sorted(
            events,
            key=lambda e: e.get("event_timestamp", e.get("timestamp", "")),
        )
        timeline = []
        for i, e in enumerate(sorted_events):
            timeline.append({
                "sequence": i + 1,
                "timestamp": e.get("event_timestamp", e.get("timestamp")),
                "source": e.get("source"),
                "actor_ip": e.get("actor_ip"),
                "action": e.get("action"),
                "target": e.get("target_endpoint") or e.get("target_resource"),
                "is_suspicious": e.get("is_suspicious", False),
            })
        return timeline


# ─── Incident Response Recommender ───────────────────────────────────────────

class IncidentResponseRecommender:
    """Generates incident response recommendations from a cluster."""

    def recommend(self, cluster: Dict[str, Any]) -> Dict[str, Any]:
        severity = cluster.get("behavioral_severity", "low")
        confidence = cluster.get("confidence", 0.5)
        honeytoken_hit = cluster.get("fingerprint", {}).get("honeytoken_interaction", False)

        steps = []
        if honeytoken_hit:
            steps.append({
                "priority": "immediate",
                "action": "Block all source IPs from cluster at perimeter firewall",
                "rationale": "Honeytoken access is definitive proof of attacker enumeration",
            })

        if confidence >= 0.7:
            steps.append({
                "priority": "high",
                "action": "Notify SOC and escalate to L2 analyst",
                "rationale": f"Cluster confidence {confidence:.0%} exceeds escalation threshold",
            })

        steps.append({
            "priority": "medium",
            "action": "Enable enhanced logging on all assets in cluster fingerprint scope",
            "rationale": "Capture full context for forensic timeline reconstruction",
        })
        steps.append({
            "priority": "medium",
            "action": "Deploy detection rule draft to SIEM in monitor-only mode",
            "rationale": "Build detection coverage before blocking to avoid false positives",
        })
        steps.append({
            "priority": "low",
            "action": "Submit cluster fingerprint to threat intelligence platform",
            "rationale": "Contribute to collective defense and receive corroborating intel",
        })

        return {
            "cluster_id": cluster.get("cluster_id"),
            "severity": severity,
            "response_steps": steps,
            "escalate_to_ir": confidence >= 0.7 or honeytoken_hit,
        }


# ─── Defensive Report Generator ──────────────────────────────────────────────

class DefensiveReportGenerator:
    """Generates the defensive hunter's structured report."""

    def generate(
        self,
        cluster: Dict[str, Any],
        timeline: List[Dict[str, Any]],
        ir_recommendations: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "cluster_id": cluster.get("cluster_id"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "confidence": cluster.get("confidence"),
            "likely_automation": cluster.get("likely_automation"),
            "likely_ai_assisted": cluster.get("likely_ai_assisted"),
            "evidence": cluster.get("evidence", []),
            "fingerprint_summary": {
                "source_ips": cluster.get("fingerprint", {}).get("source_ips", []),
                "asns": cluster.get("fingerprint", {}).get("asn_pattern", []),
                "honeytoken_triggered": cluster.get("fingerprint", {}).get(
                    "honeytoken_interaction", False
                ),
            },
            "timeline": timeline[:20],  # Limit to 20 events in report
            "recommended_actions": cluster.get("recommended_actions", []),
            "ir_response": ir_recommendations,
        }
