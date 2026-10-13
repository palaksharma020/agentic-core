"""Verdict: combine the source gate and grounding into one label for the answer, deterministically.

    VERIFIED     every delivered claim is grounded in allowed sources and corroboration is met
    SUPPORTED    grounded in allowed sources, but corroboration for this question class is not met
    CONFLICTING  a reviewer (human or model) flagged a conflict; show the sources, don't assert an answer
    REFUSED      no allowed source, or no claim survived grounding

Claims that fail grounding are removed from the answer and listed in the reasons. A model may push the label
down (downgrade_only), never up: the model may propose, never promote trust.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from agentic_core.grounding import KeptClaim, ValidationResult
from agentic_core.sources import SourceCheck


class Verdict(str, Enum):
    VERIFIED = "verified"
    SUPPORTED = "supported"
    CONFLICTING = "conflicting"
    REFUSED = "refused"


_STRENGTH = {Verdict.REFUSED: 0, Verdict.CONFLICTING: 1, Verdict.SUPPORTED: 2, Verdict.VERIFIED: 3}


def downgrade_only(current: Verdict, proposed: Verdict | str) -> Verdict:
    """Apply a proposed label only if it is weaker. Unknown labels change nothing."""
    try:
        p = Verdict(proposed)
    except ValueError:
        return current
    return p if _STRENGTH[p] < _STRENGTH[current] else current


@dataclass
class Decision:
    verdict: Verdict
    claims: list[KeptClaim] = field(default_factory=list)     # what may be shown to the user
    reasons: list[str] = field(default_factory=list)


def decide(grounding: ValidationResult, sources: SourceCheck, *,
           flags: Iterable[Verdict | str] = ()) -> Decision:
    """flags: labels proposed by a reviewer model or rule (e.g. "conflicting"); applied downgrade-only."""
    reasons = [f"source rejected: {r.source_id} ({r.reason.value}: {r.detail})" for r in sources.rejected]
    reasons += [f"claim removed: {d.claim.text[:80]!r} ({d.reason.value})" for d in grounding.dropped]

    if not sources.ok:
        return Decision(Verdict.REFUSED, [], [*reasons, "no source is allowed for this question class"])
    # defence in depth: grounding must have been run against the allowed chunks only
    stray = {e.source_id for k in grounding.kept for e in k.evidence} - set(sources.allowed)
    if stray:
        return Decision(Verdict.REFUSED, [], [*reasons, f"evidence cites sources outside the gate: {sorted(stray)}"])
    if not grounding.kept:
        return Decision(Verdict.REFUSED, [], [*reasons, "no claim is grounded in the allowed sources"])

    origins = {sources.origins[e.source_id] for k in grounding.kept for e in k.evidence}
    verdict = Verdict.VERIFIED
    if len(origins) < sources.origins_needed:
        verdict = Verdict.SUPPORTED
        reasons.append(f"corroboration: {len(origins)} of {sources.origins_needed} independent origins")
    for f in flags:
        new = downgrade_only(verdict, f)
        if new != verdict:
            reasons.append(f"downgraded {verdict.value} -> {new.value} by reviewer flag")
            verdict = new
    return Decision(verdict, list(grounding.kept) if verdict != Verdict.REFUSED else [], reasons)
