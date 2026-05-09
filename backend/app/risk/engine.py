"""Risk Engine — multi-factor risk scoring with explanation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class RiskFactors:
    """
    All factors are 0.0 – 1.0 unless noted.

    exposure:           How exposed is the asset to potential attackers?
    exploitability:     How easy is it to exploit? (CVSS-like)
    asset_criticality:  Business value of the asset (1-10, normalized internally)
    data_sensitivity:   Sensitivity of data at risk (1-10, normalized internally)
    control_gap:        How weak are existing security controls? (0=strong, 1=none)
    detection_gap:      How likely would this go undetected? (0=detected, 1=blind)
    confidence:         How confident is the finding? (0=speculation, 1=confirmed)
    """
    exposure: float = 0.5
    exploitability: float = 0.5
    asset_criticality: float = 0.5          # will be normalized from 1-10 scale
    data_sensitivity: float = 0.5
    control_gap: float = 0.5
    detection_gap: float = 0.5
    confidence: float = 0.5


@dataclass
class RiskScore:
    raw_score: float        # 0.0 – 1.0
    normalized_score: float # 0 – 100
    level: str              # critical|high|medium|low|informational
    explanation: str
    factors: dict


_LEVEL_THRESHOLDS = [
    (0.75, "critical"),
    (0.55, "high"),
    (0.35, "medium"),
    (0.15, "low"),
    (0.0, "informational"),
]


class RiskEngine:
    """
    Computes a multi-factor risk score.

    Formula:
        raw = exposure * exploitability * asset_criticality
              * data_sensitivity * control_gap * detection_gap * confidence

    The geometric mean normalizes this to be sensitive to all factors.
    """

    def score(self, factors: RiskFactors) -> RiskScore:
        # Normalize 1-10 scales to 0-1
        ac = max(0.0, min(factors.asset_criticality, 1.0))
        ds = max(0.0, min(factors.data_sensitivity, 1.0))

        raw = (
            factors.exposure
            * factors.exploitability
            * ac
            * ds
            * factors.control_gap
            * factors.detection_gap
            * factors.confidence
        )

        # We take 7th root to convert geometric product back to linear scale
        # and multiply by a tuning factor so score is meaningful
        import math
        tuned = math.pow(raw, 1 / 7) * 1.0
        tuned = max(0.0, min(tuned, 1.0))

        level = self._classify(tuned)
        explanation = self._explain(factors, tuned, level)

        return RiskScore(
            raw_score=round(raw, 6),
            normalized_score=round(tuned * 100, 1),
            level=level,
            explanation=explanation,
            factors={
                "exposure": factors.exposure,
                "exploitability": factors.exploitability,
                "asset_criticality": ac,
                "data_sensitivity": ds,
                "control_gap": factors.control_gap,
                "detection_gap": factors.detection_gap,
                "confidence": factors.confidence,
            },
        )

    def score_from_dict(self, d: dict) -> RiskScore:
        """Score from a plain dict — convenient for API usage."""
        return self.score(
            RiskFactors(
                exposure=d.get("exposure", 0.5),
                exploitability=d.get("exploitability", 0.5),
                asset_criticality=d.get("asset_criticality", 0.5),
                data_sensitivity=d.get("data_sensitivity", 0.5),
                control_gap=d.get("control_gap", 0.5),
                detection_gap=d.get("detection_gap", 0.5),
                confidence=d.get("confidence", 0.5),
            )
        )

    def _classify(self, score: float) -> str:
        for threshold, level in _LEVEL_THRESHOLDS:
            if score >= threshold:
                return level
        return "informational"

    def _explain(self, f: RiskFactors, score: float, level: str) -> str:
        drivers = []
        if f.exposure > 0.7:
            drivers.append("high external exposure")
        if f.exploitability > 0.7:
            drivers.append("easily exploitable weakness")
        if f.asset_criticality > 0.7:
            drivers.append("critical business asset")
        if f.data_sensitivity > 0.7:
            drivers.append("sensitive data at risk")
        if f.control_gap > 0.7:
            drivers.append("weak or absent security controls")
        if f.detection_gap > 0.7:
            drivers.append("low detection likelihood")
        if f.confidence > 0.7:
            drivers.append("high confidence finding")

        if not drivers:
            drivers.append("moderate risk across multiple factors")

        return (
            f"Risk level: {level.upper()} (score {score * 100:.1f}/100). "
            f"Key drivers: {', '.join(drivers)}."
        )


# Singleton
risk_engine = RiskEngine()
