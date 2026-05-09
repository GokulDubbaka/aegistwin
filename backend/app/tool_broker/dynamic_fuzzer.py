"""
Dynamic HTTP Fuzzer — AegisTwin zero-day discovery engine.

Verify=False is intentionally disabled by default. Security tools targeting
internal or self-signed environments must be able to opt in to TLS bypass.
Pass verify_tls=False only when scanning targets with self-signed certs.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import uuid
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────
MAX_CONCURRENT = 20
BODY_DELTA_THRESHOLD = 150
TIMING_OUTLIER_RATIO = 3.0
REQUEST_TIMEOUT = 8.0

INT_MUTATIONS: List[Any] = [
    lambda v: int(v) + 1,
    lambda v: int(v) - 1,
    lambda v: 0,
    lambda v: -1,
    lambda v: 2**31 - 1,
    lambda v: f"{v}' OR '1'='1",
    lambda v: f"{v} UNION SELECT NULL--",
    lambda v: "../../../etc/passwd",
]

UUID_MUTATIONS: List[Any] = [
    lambda v: str(uuid.uuid4()),
    lambda v: "00000000-0000-0000-0000-000000000000",
    lambda v: v[:-1] + "0",
]

STR_MUTATIONS: List[str] = [
    "../../../etc/passwd",
    "../../../../windows/system32/drivers/etc/hosts",
    "' OR '1'='1",
    '" OR "1"="1',
    "<script>alert(document.domain)</script>",
    "${7*7}",
    "{{7*7}}",
    "#{7*7}",
    "%00",
    "admin",
    "true",
    "null",
    "undefined",
]

AUTH_MUTATIONS: Dict[str, str] = {
    "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
    "X-Forwarded-For": "127.0.0.1",
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
    "X-Custom-IP-Authorization": "127.0.0.1",
}


# ─── Data Models ─────────────────────────────────────────────────────────
@dataclass
class BaselineSnapshot:
    status_code: int
    body_len: int
    body_hash: str
    elapsed_ms: float


@dataclass
class FuzzFinding:
    endpoint: str
    method: str
    param: str
    payload: Any
    baseline_status: int
    finding_status: int
    baseline_len: int
    finding_len: int
    delta_len: int
    elapsed_ms: float
    category: str
    confidence: float
    evidence_snippet: str


@dataclass
class FuzzReport:
    target_url: str
    endpoint: str
    method: str
    findings: List[FuzzFinding] = field(default_factory=list)
    total_payloads_fired: int = 0
    scan_duration_ms: float = 0.0
    tls_verified: bool = True

    def to_broker_signals(self) -> List[Dict[str, Any]]:
        signals = []
        for f in self.findings:
            signals.append({
                "type": "zero_day_candidate",
                "category": f.category,
                "endpoint": f.endpoint,
                "param": f.param,
                "payload": str(f.payload)[:120],
                "status_delta": f"{f.baseline_status} → {f.finding_status}",
                "body_delta_bytes": f.delta_len,
                "confidence": f.confidence,
                "value": f"{f.endpoint}?{f.param}={str(f.payload)[:40]}",
            })
        return signals

    def to_broker_evidence(self) -> List[str]:
        lines = [f"[DynamicFuzz] Target: {self.target_url}{self.endpoint}"]
        lines.append(f"  TLS verified   : {self.tls_verified}")
        lines.append(f"  Payloads fired : {self.total_payloads_fired}")
        lines.append(f"  Scan time      : {self.scan_duration_ms:.0f}ms")
        if not self.findings:
            lines.append("  Result         : No anomalies detected.")
        for f in self.findings:
            lines.append(
                f"  [{f.confidence*100:.0f}% | {f.category}] "
                f"param={f.param!r} payload={str(f.payload)[:60]!r} "
                f"status={f.finding_status} Δbody={f.delta_len:+d}B"
            )
        return lines


# ─── Core Fuzzer ─────────────────────────────────────────────────────────
class DynamicFuzzer:
    """
    Async HTTP fuzzer for business-logic vulnerability discovery.

    TLS verification is enabled by default (verify_tls=True).
    Pass verify_tls=False only when explicitly targeting environments
    with self-signed certificates and only after accepting the risk
    that results may be influenced by a MITM.
    """

    def __init__(
        self,
        base_url: str,
        extra_headers: Optional[Dict[str, str]] = None,
        auth_header: Optional[str] = None,
        verify_tls: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._verify_tls = verify_tls

        if not verify_tls:
            warnings.warn(
                "DynamicFuzzer: TLS verification is disabled (verify_tls=False). "
                "Results may be unreliable if a MITM is present. "
                "Only use this flag against targets with self-signed certificates.",
                stacklevel=2,
            )

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "Accept": "application/json, text/html, */*",
        }
        if extra_headers:
            headers.update(extra_headers)
        if auth_header:
            headers["Authorization"] = auth_header

        self._client = httpx.AsyncClient(
            headers=headers,
            verify=verify_tls,   # secure default; caller opts in to bypass
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
        )
        self._sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def close(self) -> None:
        await self._client.aclose()

    async def _baseline(
        self, endpoint: str, method: str, params: Dict[str, Any],
    ) -> Optional[BaselineSnapshot]:
        url = f"{self.base_url}{endpoint}"
        t0 = time.monotonic()
        try:
            if method.upper() == "GET":
                r = await self._client.get(url, params=params)
            else:
                r = await self._client.request(method.upper(), url, json=params)
            elapsed = (time.monotonic() - t0) * 1000
            body = r.content
            return BaselineSnapshot(
                status_code=r.status_code, body_len=len(body),
                body_hash=hashlib.md5(body).hexdigest(), elapsed_ms=elapsed,
            )
        except Exception as exc:
            logger.warning("Baseline request failed: %s", exc)
            return None

    def _generate_mutations(self, params: Dict[str, Any]) -> List[Tuple[str, Any, str]]:
        mutations: List[Tuple[str, Any, str]] = []
        for key, value in params.items():
            str_val = str(value)
            is_int = isinstance(value, int) or (
                isinstance(value, str) and value.isdigit()
            )
            is_uuid = bool(re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                str_val, re.I,
            ))
            if is_int:
                for fn in INT_MUTATIONS:
                    try:
                        mutations.append((key, fn(str_val), _categorise_int(fn)))
                    except Exception:
                        pass
            elif is_uuid:
                for fn in UUID_MUTATIONS:
                    try:
                        mutations.append((key, fn(str_val), "IDOR"))
                    except Exception:
                        pass
            else:
                for payload in STR_MUTATIONS:
                    mutations.append((key, payload, _categorise_str(payload)))
        return mutations

    async def _fire(
        self, endpoint: str, method: str, base_params: Dict[str, Any],
        param_name: str, payload: Any, category: str, baseline: BaselineSnapshot,
    ) -> Optional[FuzzFinding]:
        url = f"{self.base_url}{endpoint}"
        mutated = {**base_params, param_name: payload}
        async with self._sem:
            t0 = time.monotonic()
            try:
                if method.upper() == "GET":
                    r = await self._client.get(url, params=mutated)
                else:
                    r = await self._client.request(method.upper(), url, json=mutated)
            except Exception:
                return None
            elapsed = (time.monotonic() - t0) * 1000
            body = r.content
            body_len = len(body)
            delta_len = body_len - baseline.body_len
            body_hash = hashlib.md5(body).hexdigest()

        confidence = 0.0
        reasons: List[str] = []
        status_changed = r.status_code != baseline.status_code
        if baseline.status_code in (401, 403) and r.status_code == 200:
            confidence += 0.6
            reasons.append("auth_bypass")
        if r.status_code == 200 and delta_len > 500:
            confidence += 0.3
            reasons.append("large_body_increase")
        if status_changed:
            confidence += 0.2
            reasons.append(f"status_delta:{baseline.status_code}→{r.status_code}")
        body_text = body.decode(errors="ignore").lower()
        for sig in ("sql", "syntax error", "traceback", "exception", "stack trace", "errno", "undefined"):
            if sig in body_text:
                confidence = min(confidence + 0.25, 1.0)
                reasons.append(f"error_leakage:{sig}")
                break
        if elapsed > baseline.elapsed_ms * TIMING_OUTLIER_RATIO and elapsed > 2000:
            confidence = min(confidence + 0.15, 1.0)
            reasons.append("timing_outlier")
            category = "TIMING"
        if confidence < 0.2 and not status_changed:
            return None
        return FuzzFinding(
            endpoint=endpoint, method=method, param=param_name, payload=payload,
            baseline_status=baseline.status_code, finding_status=r.status_code,
            baseline_len=baseline.body_len, finding_len=body_len,
            delta_len=delta_len, elapsed_ms=elapsed, category=category,
            confidence=min(confidence, 1.0),
            evidence_snippet=body[:300].decode(errors="ignore"),
        )

    async def _auth_header_fuzz(
        self, endpoint: str, method: str, params: Dict[str, Any], baseline: BaselineSnapshot,
    ) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        url = f"{self.base_url}{endpoint}"
        for header_name, header_val in AUTH_MUTATIONS.items():
            async with self._sem:
                t0 = time.monotonic()
                try:
                    hdrs = {header_name: header_val}
                    if method.upper() == "GET":
                        r = await self._client.get(url, params=params, headers=hdrs)
                    else:
                        r = await self._client.request(method.upper(), url, json=params, headers=hdrs)
                    elapsed = (time.monotonic() - t0) * 1000
                except Exception:
                    continue
            if r.status_code != baseline.status_code or abs(len(r.content) - baseline.body_len) > BODY_DELTA_THRESHOLD:
                findings.append(FuzzFinding(
                    endpoint=endpoint, method=method, param=header_name, payload=header_val,
                    baseline_status=baseline.status_code, finding_status=r.status_code,
                    baseline_len=baseline.body_len, finding_len=len(r.content),
                    delta_len=len(r.content) - baseline.body_len, elapsed_ms=elapsed,
                    category="AUTH_BYPASS",
                    confidence=0.75 if r.status_code == 200 else 0.4,
                    evidence_snippet=r.content[:300].decode(errors="ignore"),
                ))
        return findings

    async def fuzz(
        self, endpoint: str, method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
    ) -> FuzzReport:
        params = params or {}
        report = FuzzReport(
            target_url=self.base_url, endpoint=endpoint,
            method=method, tls_verified=self._verify_tls,
        )
        scan_start = time.monotonic()
        logger.info("DynamicFuzzer starting: %s %s%s (tls=%s)", method, self.base_url, endpoint, self._verify_tls)
        baseline = await self._baseline(endpoint, method, params)
        if baseline is None:
            logger.warning("Baseline failed — aborting fuzz on %s", endpoint)
            return report
        mutations = self._generate_mutations(params)
        report.total_payloads_fired = len(mutations)
        tasks = [
            self._fire(endpoint, method, params, pname, pval, cat, baseline)
            for pname, pval, cat in mutations
        ]
        tasks.append(self._auth_header_fuzz(endpoint, method, params, baseline))
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in raw_results:
            if isinstance(result, list):
                report.findings.extend(result)
            elif isinstance(result, FuzzFinding):
                report.findings.append(result)
        report.findings.sort(key=lambda f: f.confidence, reverse=True)
        report.scan_duration_ms = (time.monotonic() - scan_start) * 1000
        logger.info(
            "DynamicFuzzer complete: %d payloads, %d findings (%.0fms)",
            report.total_payloads_fired, len(report.findings), report.scan_duration_ms,
        )
        return report


# ─── ToolBroker adapter ─────────────────────────────────────────────────────────
def dynamic_fuzz_adapter(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synchronous wrapper for ToolBroker.execute().
    verify_tls defaults to True. Pass verify_tls=False in params only for
    targets with self-signed certificates.
    """
    endpoint    = params.get("endpoint", "/")
    method      = params.get("method", "GET")
    fuzz_params = params.get("params", {})
    auth_header = params.get("auth_header")
    extra_hdrs  = params.get("extra_headers", {})
    verify_tls  = params.get("verify_tls", True)  # secure default

    async def _run():
        fuzzer = DynamicFuzzer(
            target, extra_headers=extra_hdrs,
            auth_header=auth_header, verify_tls=verify_tls,
        )
        try:
            return await fuzzer.fuzz(endpoint, method, fuzz_params)
        finally:
            await fuzzer.close()

    try:
        report = asyncio.run(_run())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            report = loop.run_until_complete(_run())
        finally:
            loop.close()

    return {
        "evidence": report.to_broker_evidence(),
        "signals":  report.to_broker_signals(),
        "cost":     {"tokens": 0, "api_calls": report.total_payloads_fired},
    }


# ─── Helpers ───────────────────────────────────────────────────────────────────
def _categorise_int(fn) -> str:
    src = fn.__doc__ or ""
    if "IDOR" in src:      return "IDOR"
    if "SQL" in src:       return "SQLI"
    if "traversal" in src: return "PATH_TRAVERSAL"
    return "PARAMETER_TAMPERING"


def _categorise_str(payload: str) -> str:
    lp = payload.lower()
    if "script" in lp:                          return "XSS"
    if "select" in lp or "union" in lp or "or '1'" in lp: return "SQLI"
    if "etc/passwd" in lp or "windows" in lp:  return "PATH_TRAVERSAL"
    if "${" in lp or "{{" in lp or "#{" in lp: return "SSTI"
    return "INJECTION"
