"""Aggregator pillar — weighted combination of pillar scores into a final verdict.

The ``aggregate`` method is intentionally a pure function of its inputs so
that it can be unit-tested without mocking any external services.

Weights are read from ``Settings`` at call time so that changing them in
``.env`` takes effect without restarting the daemon (call
``get_settings.cache_clear()`` to invalidate the cache).
"""
from __future__ import annotations

from ..config import Settings
from ..models import PillarScore
from ..utils.logger import get_logger

log = get_logger(__name__)


class Aggregator:
    """Pillar 4: compute the final weighted risk score and human-readable explanation."""

    def aggregate(
        self,
        contextify: PillarScore,
        sentinel: PillarScore,
        shield: PillarScore,
        settings: Settings,
    ) -> tuple[float, str]:
        """Return ``(risk_score, explanation)`` from the three pillar scores.

        risk_score is 0–100 (weighted sum capped at 100).
        explanation is a plain-English summary listing the top signal flags.
        """
        score = (
            settings.context_weight * contextify.score
            + settings.sentinel_weight * sentinel.score
            + settings.shield_weight * shield.score
        )
        score = round(min(score, 100.0), 2)

        explanation = self._build_explanation(score, contextify, sentinel, shield, settings)
        return score, explanation

    @staticmethod
    def get_decision(score: float, settings: Settings) -> str:
        """Map a numeric risk score to a decision string."""
        if score >= settings.block_threshold:
            return "BLOCK"
        if score >= settings.warn_threshold:
            return "WARN"
        return "ALLOW"

    def _build_explanation(
        self,
        score: float,
        contextify: PillarScore,
        sentinel: PillarScore,
        shield: PillarScore,
        settings: Settings,
    ) -> str:
        decision = self.get_decision(score, settings)
        all_flags = contextify.flags + sentinel.flags + shield.flags

        if not all_flags:
            if decision == "ALLOW":
                return f"Package passed all checks (risk score {score:.0f}/100)."
            return f"Package has a moderate risk score ({score:.0f}/100) but no specific flags were raised."

        top_flags = ", ".join(all_flags[:5])
        if decision == "BLOCK":
            return (
                f"Installation blocked (risk score {score:.0f}/100). "
                f"Top signals: {top_flags}."
            )
        if decision == "WARN":
            return (
                f"Proceed with caution (risk score {score:.0f}/100). "
                f"Signals detected: {top_flags}."
            )
        return (
            f"Package passed screening (risk score {score:.0f}/100). "
            f"Minor signals noted: {top_flags}."
        )
