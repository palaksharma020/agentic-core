"""Limited authority for model-proposed severities: the model may propose, never promote.

"Tighten-only" (raise, never lower) stops a model hiding risk, but on its own it lets a model inflate risk on a
weak or invented reason. These helpers add the missing limits: a floor set by code, at most `max_step` levels per
proposal, and a `ceiling` above which a human must decide.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class SeverityDecision:
    value: str  # the severity to use now
    applied: bool  # did the proposal change anything?
    needs_human: bool  # was more requested than the model is allowed to grant?
    reason: str


def _rank(scale: Sequence[str]) -> dict[str, int]:
    return {s: i for i, s in enumerate(scale)}


def tighten_severity(
    current: str,
    proposed: str,
    *,
    floor: str | None = None,
    max_step: int = 1,
    ceiling: str = "medium",
    scale: Sequence[str] = SEVERITIES,
) -> SeverityDecision:
    """Apply a model's proposed severity for an existing finding.

    current and floor come from your code and must be on the scale (ValueError otherwise). proposed comes from
    the model and may be anything; unknown values change nothing.
    """
    r = _rank(scale)
    for name, v in (("current", current), ("ceiling", ceiling)) + (
        (("floor", floor),) if floor else ()
    ):
        if v not in r:
            raise ValueError(f"{name} severity {v!r} is not on the scale {tuple(scale)}")
    base = max(r[current], r[floor]) if floor else r[current]
    proposed = str(proposed).strip().lower()
    if proposed not in r:
        return SeverityDecision(
            scale[base], False, False, f"unknown severity {proposed!r}; ignored"
        )
    if r[proposed] <= base:
        return SeverityDecision(
            scale[base], False, False, "tighten-only: cannot lower or keep severity"
        )
    step = min(base + max_step, r[proposed], r[ceiling])
    if step <= base:
        return SeverityDecision(
            scale[base], False, True, f"model may not raise above {ceiling}; needs human review"
        )
    capped = scale[step] != proposed
    return SeverityDecision(
        scale[step],
        True,
        capped,
        f"raised to {scale[step]}" + (f"; {proposed} needs human review" if capped else ""),
    )


def cap_new_severity(
    proposed: str,
    *,
    ceiling: str = "medium",
    default: str = "info",
    scale: Sequence[str] = SEVERITIES,
) -> SeverityDecision:
    """Severity for a finding the model created itself: a lead for review, never above `ceiling`."""
    r = _rank(scale)
    proposed = str(proposed).strip().lower()
    if proposed not in r:
        return SeverityDecision(
            default, False, False, f"unknown severity {proposed!r}; using {default}"
        )
    if r[proposed] > r[ceiling]:
        return SeverityDecision(
            ceiling, True, True, f"new model finding capped at {ceiling}; needs human review"
        )
    return SeverityDecision(proposed, False, False, "within ceiling")
