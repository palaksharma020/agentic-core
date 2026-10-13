"""Grounding: does each claim's evidence quote appear in the context the model was actually shown?

Validate against the prompt, not the corpus. The application (not the model) records which chunks went into
the prompt; a claim survives only if one of its quotes is found, after normalize(), inside one of those chunks.
Cost grows with prompt size, never with corpus size.

What this proves: the quote is faithful to text the model was given.
What it does not prove: that the claim follows from the quote, or that the source is true. Those need
entailment checks or human review, and source controls (see agentic_core.sources).
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentic_core.text import normalize


@dataclass(frozen=True)
class Evidence:
    source_id: str
    quote: str


@dataclass
class Claim:
    text: str
    evidence: list[Evidence] = field(default_factory=list)
    id: str | None = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Claim:
        """Build a Claim from parsed model JSON, tolerating missing or mistyped fields.

        Accepts {"text"|"claim": ..., "id": ..., "evidence": [{"source_id"|"source"|"file": ..., "quote": ...}]}.
        """
        ev = d.get("evidence") or []
        return cls(
            text=str(d.get("text", d.get("claim", ""))),
            evidence=[Evidence(str(e.get("source_id", e.get("source", e.get("file", "")))), str(e.get("quote", "")))
                      for e in (ev if isinstance(ev, list) else []) if isinstance(e, Mapping)],
            id=None if d.get("id") is None else str(d.get("id")),
        )


class DropReason(str, Enum):
    NO_EVIDENCE = "no_evidence"          # no quotes, or every quote shorter than min_quote_chars
    UNKNOWN_SOURCE = "unknown_source"    # cites a source_id that was neither shown nor known
    NOT_SHOWN = "not_shown"              # quote not in the shown context (pass sources= to say why)
    NOT_IN_SOURCE = "not_in_source"      # quote is not in the source at all: invented
    NOT_IN_PROMPT = "not_in_prompt"      # real text in the source, but not in the prompt: recalled or invented


_DETAIL = {
    DropReason.NO_EVIDENCE: "no evidence quote of the minimum length",
    DropReason.UNKNOWN_SOURCE: "cites a source that was not in the prompt",
    DropReason.NOT_SHOWN: "quote not found in the context shown to the model",
    DropReason.NOT_IN_SOURCE: "quote not found in the source (invented)",
    DropReason.NOT_IN_PROMPT: "quote is real text in the source but was not in the prompt (recalled or invented)",
}
# when a claim's quotes fail for different reasons, report the most informative one
_PRIORITY = [DropReason.NOT_IN_PROMPT, DropReason.NOT_IN_SOURCE, DropReason.NOT_SHOWN,
             DropReason.UNKNOWN_SOURCE, DropReason.NO_EVIDENCE]


@dataclass(frozen=True)
class VerifiedEvidence:
    source_id: str
    quote: str
    chunk_index: int       # which shown chunk of source_id contains the quote
    chunk_sha256: str      # hash of that chunk as shown, for the audit record


@dataclass(frozen=True)
class KeptClaim:
    claim: Claim
    evidence: tuple[VerifiedEvidence, ...]
    rejected_evidence: tuple[tuple[Evidence, DropReason], ...] = ()


@dataclass(frozen=True)
class DroppedClaim:
    claim: Claim
    reason: DropReason
    detail: str
    rejected_evidence: tuple[tuple[Evidence, DropReason], ...] = ()


@dataclass
class ValidationResult:
    kept: list[KeptClaim] = field(default_factory=list)
    dropped: list[DroppedClaim] = field(default_factory=list)

    @property
    def all_grounded(self) -> bool:
        return bool(self.kept) and not self.dropped


def _chunks(value: str | Sequence[str]) -> list[str]:
    return [value] if isinstance(value, str) else list(value)


def validate_grounding(
    claims: Iterable[Claim | Mapping[str, Any]],
    shown_context: Mapping[str, str | Sequence[str]],
    *,
    sources: Mapping[str, str] | None = None,
    min_quote_chars: int = 8,
    require_all_evidence: bool = False,
) -> ValidationResult:
    """Keep claims whose evidence quotes appear in the chunks the model was shown.

    shown_context: source_id -> the chunk(s) of that source that were in the prompt. Build it from your
        retrieval log, never from the model's own account of what it read.
    sources: optional full text per source_id. Only used to explain a miss: real text that was not in the
        prompt (NOT_IN_PROMPT) vs text that does not exist (NOT_IN_SOURCE). It never makes a claim pass.
    min_quote_chars: shorter quotes ("the", "yes") match anything and are ignored.
    require_all_evidence: if True, one bad quote drops the claim; by default bad quotes are removed and the
        claim survives on its good ones (each rejection is still recorded).
    """
    shown = {sid: [(normalize(c), c) for c in _chunks(v)] for sid, v in shown_context.items()}
    norm_sources: dict[str, str] = {}
    res = ValidationResult()

    for raw in claims:
        claim = raw if isinstance(raw, Claim) else Claim.from_dict(raw)
        good: list[VerifiedEvidence] = []
        bad: list[tuple[Evidence, DropReason]] = []
        for ev in claim.evidence:
            q = normalize(ev.quote)
            if len(q) < min_quote_chars:
                bad.append((ev, DropReason.NO_EVIDENCE))
                continue
            hit = next((i for i, (nc, _) in enumerate(shown.get(ev.source_id, [])) if q in nc), None)
            if hit is not None:
                chunk = shown[ev.source_id][hit][1]
                good.append(VerifiedEvidence(ev.source_id, ev.quote, hit,
                                             hashlib.sha256(chunk.encode()).hexdigest()))
                continue
            if sources is not None and ev.source_id in sources:
                if ev.source_id not in norm_sources:
                    norm_sources[ev.source_id] = normalize(sources[ev.source_id])
                bad.append((ev, DropReason.NOT_IN_PROMPT if q in norm_sources[ev.source_id]
                            else DropReason.NOT_IN_SOURCE))
            elif ev.source_id in shown:
                bad.append((ev, DropReason.NOT_SHOWN))
            else:
                bad.append((ev, DropReason.UNKNOWN_SOURCE))

        if good and not (require_all_evidence and bad):
            res.kept.append(KeptClaim(claim, tuple(good), tuple(bad)))
        else:
            reason = next((r for r in _PRIORITY if any(b == r for _, b in bad)), DropReason.NO_EVIDENCE)
            res.dropped.append(DroppedClaim(claim, reason, _DETAIL[reason], tuple(bad)))
    return res
