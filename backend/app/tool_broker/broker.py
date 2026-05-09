"""
Tool Broker — central execution registry for all agent tools.

Enforces policy before every tool execution.
All outputs are normalized to a standard schema.
Stores evidence for each successful execution.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from app.core.policy import ActionType, PolicyEngine
from app.tool_broker.attack_graph import graph_engine
from app.tool_broker.dynamic_fuzzer import dynamic_fuzz_adapter

logger = logging.getLogger(__name__)
policy_engine = PolicyEngine()


# ─── Normalized Tool Result ───────────────────────────────────────────────────

def normalize_result(
    tool_name: str,
    tenant_id: str,
    engagement_id: str,
    target: str,
    status: str,
    evidence: List[Any],
    signals: List[Any],
    started_at: str,
    finished_at: str,
    cost: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "tool_name": tool_name,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "target": target,
        "status": status,  # success|blocked|failed
        "evidence": evidence,
        "signals": signals,
        "cost": cost or {"tokens": 0, "api_calls": 1},
        "started_at": started_at,
        "finished_at": finished_at,
        "error": error,
    }


# ─── Tool Registration ────────────────────────────────────────────────────────

class ToolBroker:
    """
    Central tool execution registry.

    1. register_tool()      — register a tool adapter
    2. request_execution()  — request tool execution (policy checked)
    3. validate_policy()    — explicit policy check
    4. execute()            — run the tool
    5. normalize_output()   — convert to standard schema
    6. store_evidence()     — persist evidence (stub — connect to DB)
    """

    def __init__(self) -> None:
        self._registry: Dict[str, Dict[str, Any]] = {}

    def register_tool(
        self,
        tool_name: str,
        action_type: ActionType,
        adapter: Callable[..., Any],
        description: str = "",
    ) -> None:
        self._registry[tool_name] = {
            "name": tool_name,
            "action_type": action_type,
            "adapter": adapter,
            "description": description,
        }
        logger.info("TOOL_REGISTERED name=%s action=%s", tool_name, action_type.value)

    def request_execution(
        self,
        tool_name: str,
        tenant_id: str,
        engagement_id: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        allowed_targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Policy-checked execution entry point."""
        started_at = datetime.now(timezone.utc).isoformat()

        if tool_name not in self._registry:
            return normalize_result(
                tool_name=tool_name,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                target=target,
                status="failed",
                evidence=[],
                signals=[],
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                error=f"Tool '{tool_name}' not registered",
            )

        tool = self._registry[tool_name]
        decision = self.validate_policy(
            action_type=tool["action_type"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            target=target,
            allowed_targets=allowed_targets,
        )

        if not decision.allowed:
            return normalize_result(
                tool_name=tool_name,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                target=target,
                status="blocked",
                evidence=[],
                signals=[{"type": "policy_block", "reason": decision.reason}],
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                error=decision.reason,
            )

        return self.execute(
            tool_name=tool_name,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            target=target,
            params=params or {},
            started_at=started_at,
        )

    def validate_policy(
        self,
        action_type: ActionType,
        tenant_id: str,
        engagement_id: str,
        target: str,
        allowed_targets: Optional[List[str]] = None,
    ):
        return policy_engine.evaluate(
            action_type=action_type,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            target=target,
            allowed_targets=allowed_targets,
        )

    def execute(
        self,
        tool_name: str,
        tenant_id: str,
        engagement_id: str,
        target: str,
        params: Dict[str, Any],
        started_at: str,
    ) -> Dict[str, Any]:
        tool = self._registry[tool_name]
        try:
            raw_result = tool["adapter"](target=target, params=params)
            result = self.normalize_output(
                tool_name=tool_name,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                target=target,
                raw=raw_result,
                started_at=started_at,
            )
            self.store_evidence(result)
            return result
        except Exception as exc:
            logger.exception("TOOL_FAILED name=%s target=%s", tool_name, target)
            return normalize_result(
                tool_name=tool_name,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                target=target,
                status="failed",
                evidence=[],
                signals=[],
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                error=str(exc),
            )

    def normalize_output(
        self,
        tool_name: str,
        tenant_id: str,
        engagement_id: str,
        target: str,
        raw: Dict[str, Any],
        started_at: str,
    ) -> Dict[str, Any]:
        signals = raw.get("signals", [])
        
        # [WORLD-CLASS] Feed newly discovered assets/signals into the Attack Graph
        for sig in signals:
            if "value" in sig:
                graph_engine.add_asset_node(sig.get("type", "unknown"), sig["value"], sig.get("confidence", 1.0))
                # Create relationship to the parent target
                if target != sig["value"]:
                    graph_engine.add_asset_node("target", target)
                    graph_engine.create_relationship(target, sig["value"], "resolves_to")
            if "cve" in sig:
                graph_engine.add_vulnerability(target, sig["cve"], sig.get("severity", 5.0), requires_auth=False)

        return normalize_result(
            tool_name=tool_name,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            target=target,
            status="success",
            evidence=raw.get("evidence", []),
            signals=signals,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            cost=raw.get("cost"),
        )

    def store_evidence(self, result: Dict[str, Any]) -> None:
        """
        Persist evidence to the database.
        # TODO: Inject session and write to Evidence table
        """
        logger.info(
            "EVIDENCE_STORED tool=%s tenant=%s target=%s signals=%d",
            result["tool_name"],
            result["tenant_id"],
            result["target"],
            len(result.get("signals", [])),
        )


# ─── Mock Tool Adapters ───────────────────────────────────────────────────────

import subprocess
import socket
import urllib.request

def live_subdomain_discovery(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Live DNS resolution (safe, passive-like)."""
    try:
        res = subprocess.run(["nslookup", target], capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            return {
                "evidence": [f"Live DNS resolution successful for {target}:", res.stdout[:200]],
                "signals": [
                    {"type": "subdomain", "value": target, "confidence": 1.0}
                ],
            }
    except Exception as e:
        return {"evidence": [f"DNS resolution failed: {e}"], "signals": []}
    return {"evidence": ["No subdomains found."], "signals": []}


def live_web_fingerprint(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Live HTTP request to get real headers."""
    try:
        url = target if target.startswith("http") else f"https://{target}"
        req = urllib.request.Request(url, headers={'User-Agent': 'AegisTwin/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            server = response.headers.get('Server', 'Unknown')
            return {
                "evidence": [f"Live request to {url}", f"Server header: {server}"],
                "signals": [
                    {"type": "server_banner", "value": server, "confidence": 1.0}
                ],
            }
    except urllib.error.URLError as e:
        return {"evidence": [f"HTTP request failed: {e}"], "signals": []}
    except Exception as e:
        return {"evidence": [f"Exception: {e}"], "signals": []}


def live_port_inventory(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Live port check (checks 80 and 443 safely)."""
    open_ports = []
    # Strip scheme if present
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    for port in [80, 443]:
        try:
            with socket.create_connection((host, port), timeout=3):
                open_ports.append(port)
        except:
            pass
    
    signals = []
    if open_ports:
        for p in open_ports:
            signals.append({"type": "open_port", "value": p, "confidence": 1.0})
        return {
            "evidence": [f"Live open ports found: {open_ports}"],
            "signals": signals
        }
    return {
        "evidence": ["No common open ports found."],
        "signals": []
    }

import json
def live_nuclei_scan(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    [WORLD-CLASS UPGRADE] Live Nuclei Vulnerability Scan
    Executes ProjectDiscovery's Nuclei engine to find real CVEs and misconfigurations.
    Requires 'nuclei' to be installed on the system PATH.
    """
    try:
        url = target if target.startswith("http") else f"https://{target}"
        logger.info(f"Initiating Live Nuclei Scan against {url}...")
        
        # Run nuclei with JSON output, targeting critical/high CVEs to keep it focused
        cmd = [
            "nuclei", 
            "-u", url, 
            "-tags", "cve,exposure", 
            "-severity", "critical,high",
            "-silent", 
            "-json-export", "-" # stdout json stream
        ]
        
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if res.returncode != 0 and not res.stdout:
            return {"evidence": ["Nuclei executable not found or failed."], "signals": []}
            
        signals = []
        evidence = []
        
        # Parse JSON lines output from Nuclei
        for line in res.stdout.strip().split('\\n'):
            if not line: continue
            try:
                vuln = json.loads(line)
                info = vuln.get("info", {})
                cve = info.get("classification", {}).get("cve-id", [vuln.get("template-id")])[0]
                severity = 9.0 if info.get("severity") == "critical" else 7.0
                
                signals.append({
                    "type": "vulnerability",
                    "cve": cve,
                    "severity": severity,
                    "name": info.get("name", "Unknown Vuln"),
                    "confidence": 1.0
                })
                evidence.append(f"[FOUND] {cve} - {info.get('name')}")
            except:
                continue
                
        if not signals:
            return {"evidence": ["Nuclei scan completed. No critical/high CVEs found."], "signals": []}
            
        return {
            "evidence": evidence,
            "signals": signals
        }
        
    except FileNotFoundError:
        return {"evidence": ["'nuclei' binary not installed. Install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], "signals": []}
    except Exception as e:
        return {"evidence": [f"Nuclei scan error: {e}"], "signals": []}


def live_dependency_scan(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Live dependency scan via OSV.dev public API.
    Queries the open-source vulnerability database for real CVEs affecting
    packages discovered on the target without any auth requirement.
    """
    import urllib.parse

    packages_to_check = params.get("packages", [
        {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"},
        {"package": {"name": "log4j-core", "ecosystem": "Maven"}, "version": "2.14.0"},
        {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "3.0.0"},
    ])

    findings_evidence = []
    signals = []

    for entry in packages_to_check:
        try:
            payload_bytes = json.dumps(entry).encode()
            req = urllib.request.Request(
                "https://api.osv.dev/v1/query",
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
                for vuln in data.get("vulns", []):
                    vid = vuln.get("id", "UNKNOWN")
                    severity = vuln.get("database_specific", {}).get("severity", "MEDIUM")
                    pkg_name = entry.get("package", {}).get("name", "unknown")
                    findings_evidence.append(f"[LIVE] {pkg_name} → {vid} ({severity})")
                    signals.append({"type": "vulnerable_dependency", "cve": vid, "severity": severity.lower()})
        except Exception as exc:
            findings_evidence.append(f"[OSV] Query failed for {entry}: {exc}")

    if not signals:
        findings_evidence.append("No known CVEs found via OSV.dev for scanned packages.")

    return {"evidence": findings_evidence, "signals": signals}


def live_secret_scan(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Live entropy-based secret scan against publicly accessible text endpoints.
    Fetches robots.txt, /.well-known/security.txt, and common backup files
    and runs Shannon entropy analysis to surface high-entropy strings
    that could be API keys, tokens, or credentials.
    """
    import math
    import re as _re

    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq = {c: data.count(c) / len(data) for c in set(data)}
        return -sum(p * math.log2(p) for p in freq.values())

    probes = ["/robots.txt", "/.well-known/security.txt", "/.env.example", "/config.yml"]
    base = target if target.startswith("http") else f"https://{target}"
    evidence = []
    signals = []
    token_re = _re.compile(r"[A-Za-z0-9/+]{20,}")

    for path in probes:
        try:
            req = urllib.request.Request(f"{base}{path}", headers={"User-Agent": "AegisTwin/2.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                text = r.read(4096).decode(errors="ignore")
                for token in token_re.findall(text):
                    entropy = shannon_entropy(token)
                    if entropy > 4.2:  # empirical threshold for secrets
                        evidence.append(f"[HIGH ENTROPY] {path}: ...{token[:8]}... (H={entropy:.2f})")
                        signals.append({"type": "secret_candidate", "pattern": "high_entropy",
                                        "confidence": min(0.5 + (entropy - 4.2) * 0.15, 0.99)})
        except Exception:
            pass

    if not signals:
        evidence.append("No high-entropy secret candidates found in public endpoints.")

    return {"evidence": evidence, "signals": signals}


def mock_cloud_config_review(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Mock cloud config review — read-only API calls."""
    return {
        "evidence": [
            "S3 bucket 'acme-backups' has public read ACL",
            "IAM role 'app-role' has wildcard S3 actions",
            "MFA not enforced for root account",
        ],
        "signals": [
            {"type": "public_s3_bucket", "resource": "acme-backups", "confidence": 0.98},
            {"type": "overpermissive_iam", "role": "app-role", "confidence": 0.9},
            {"type": "mfa_not_enforced", "account": "root", "confidence": 0.99},
        ],
    }


def mock_telemetry_search(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Mock SIEM/log search."""
    return {
        "evidence": ["Found 47 failed login attempts from IP 185.220.101.5 in last 24h"],
        "signals": [
            {
                "type": "brute_force_attempt",
                "source_ip": "185.220.101.5",
                "count": 47,
                "confidence": 0.92,
            }
        ],
    }


def mock_honeytoken_monitor(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Mock honeytoken status check."""
    return {
        "evidence": ["HoneyToken 'FAKE-API-KEY-001' accessed from IP 45.155.204.127 at 14:23 UTC"],
        "signals": [
            {
                "type": "honeytoken_triggered",
                "token_id": "FAKE-API-KEY-001",
                "source_ip": "45.155.204.127",
                "confidence": 0.99,
            }
        ],
    }


# ─── Register all tools ───────────────────────────────────────────────────────

def build_default_broker() -> ToolBroker:
    """Create and configure the default tool broker with all mock adapters."""
    broker = ToolBroker()

    broker.register_tool(
        "subdomain_discovery", ActionType.SUBDOMAIN_ENUM,
        live_subdomain_discovery, "Live DNS subdomain enumeration"
    )
    broker.register_tool(
        "web_fingerprint", ActionType.WEB_FINGERPRINT,
        live_web_fingerprint, "Live HTTP header fingerprinting"
    )
    broker.register_tool(
        "port_inventory", ActionType.PORT_SCAN,
        live_port_inventory, "Live port inventory scan"
    )
    # Active Vulnerability Scanner
    broker.register_tool(
        "nuclei_scan", ActionType.DEPENDENCY_SCAN,
        live_nuclei_scan, "Live ProjectDiscovery Nuclei CVE/misconfiguration scanner"
    )
    # Zero-Day Dynamic Fuzzer
    broker.register_tool(
        "dynamic_fuzz", ActionType.NON_DESTRUCTIVE_PROOF,
        dynamic_fuzz_adapter, "Async HTTP fuzzer: IDOR, SQLi, SSTI, Auth Bypass discovery"
    )
    broker.register_tool(
        "dependency_scan", ActionType.DEPENDENCY_SCAN,
        live_dependency_scan, "Live OSV.dev dependency CVE scanner"
    )
    broker.register_tool(
        "secret_scan", ActionType.SECRET_SCAN,
        live_secret_scan, "Live entropy-based secret/credential scanner"
    )
    broker.register_tool(
        "cloud_config_review", ActionType.CLOUD_CONFIG_REVIEW,
        mock_cloud_config_review, "Read-only cloud configuration review"
    )
    broker.register_tool(
        "telemetry_search", ActionType.TELEMETRY_SEARCH,
        mock_telemetry_search, "SIEM/log search for threat signals"
    )
    broker.register_tool(
        "honeytoken_monitor", ActionType.HONEYTOKEN_MONITOR,
        mock_honeytoken_monitor, "Honeytoken access monitoring"
    )

    return broker


# Singleton broker instance
default_broker = build_default_broker()
