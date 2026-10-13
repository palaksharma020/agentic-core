"""Source gate: decide which retrieved chunks may reach the model, before it is called.

Grounding checks that an answer is faithful to its source; it cannot tell a true source from a poisoned one.
The source gate applies deterministic policy to each retrieved chunk using the record your ingestion pipeline
wrote for it (never anything the chunk or the model says about itself):

- registered:  the chunk has an ingest record
- authority:   its trust tier is allowed for this class of question (1 = system of record)
- integrity:   its SHA-256 still matches the hash taken at ingest
- freshness:   it is younger than the TTL for its tier

Corroboration (how many independent origins must agree) is a policy value the verdict step checks against the
grounded evidence; see agentic_core.verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum


@dataclass(frozen=True)
class SourceRecord:
    """Written by the ingestion pipeline when the chunk is indexed."""
    source_id: str
    tier: int                  # 1 = system of record / signed; higher = less authoritative
    sha256: str                # hash of the chunk text at ingest
    as_of: datetime            # timezone-aware time the content was last known correct
    origin: str = ""           # owning system, for independence when corroborating; defaults to source_id


@dataclass(frozen=True)
class SourcePolicy:
    max_tier: Mapping[str, int]                                      # question class -> least authoritative tier allowed
    default_max_tier: int = 1                                        # unknown question class: system of record only
    ttl: Mapping[int, timedelta] = field(default_factory=dict)       # tier -> max age; missing tier = no limit
    corroborate: Mapping[str, int] = field(default_factory=dict)     # question class -> independent origins needed

    def tier_limit(self, question_class: str) -> int:
        return self.max_tier.get(question_class, self.default_max_tier)

    def origins_needed(self, question_class: str) -> int:
        return self.corroborate.get(question_class, 1)


class SourceRejection(str, Enum):
    UNREGISTERED = "unregistered"
    TIER = "tier"
    HASH_MISMATCH = "hash_mismatch"
    STALE = "stale"


@dataclass(frozen=True)
class RejectedSource:
    source_id: str
    reason: SourceRejection
    detail: str


@dataclass
class SourceCheck:
    question_class: str
    allowed: dict[str, str] = field(default_factory=dict)        # source_id -> chunk text: build the prompt from this
    origins: dict[str, str] = field(default_factory=dict)        # allowed source_id -> origin
    rejected: list[RejectedSource] = field(default_factory=list)
    origins_needed: int = 1

    @property
    def ok(self) -> bool:
        return bool(self.allowed)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_sources(chunks: Mapping[str, str], records: Mapping[str, SourceRecord], policy: SourcePolicy,
                  question_class: str, *, now: datetime | None = None) -> SourceCheck:
    """Split retrieved chunks into allowed and rejected (with reasons). Pure policy: no I/O, no model."""
    now = now or datetime.now(timezone.utc)
    limit = policy.tier_limit(question_class)
    out = SourceCheck(question_class, origins_needed=policy.origins_needed(question_class))
    for sid, text in chunks.items():
        rec = records.get(sid)
        if rec is None:
            out.rejected.append(RejectedSource(sid, SourceRejection.UNREGISTERED, "no ingest record"))
        elif rec.tier > limit:
            out.rejected.append(RejectedSource(sid, SourceRejection.TIER,
                                               f"tier {rec.tier} > max {limit} for {question_class}"))
        elif sha256_text(text) != rec.sha256:
            out.rejected.append(RejectedSource(sid, SourceRejection.HASH_MISMATCH, "content changed since ingest"))
        elif rec.tier in policy.ttl and now - rec.as_of > policy.ttl[rec.tier]:
            out.rejected.append(RejectedSource(sid, SourceRejection.STALE,
                                               f"as_of {rec.as_of:%Y-%m-%d} older than {policy.ttl[rec.tier]}"))
        else:
            out.allowed[sid] = text
            out.origins[sid] = rec.origin or sid
    return out


def render_untrusted(chunks: Mapping[str, str], tag: str = "untrusted_source") -> str:
    """Wrap each chunk in data-marking tags (spotlighting) for the prompt.

    A chunk cannot close the tag early: any '<tag' or '</tag' inside it is defanged. Spotlighting reduces
    indirect prompt injection but does not prevent it; pair it with checks that do not rely on the model obeying.
    """
    def defang(s: str) -> str:
        return s.replace(f"</{tag}", f"&lt;/{tag}").replace(f"<{tag}", f"&lt;{tag}")
    return "\n\n".join(f'<{tag} id="{defang(sid).replace(chr(34), "")}">\n{defang(text)}\n</{tag}>'
                       for sid, text in chunks.items())
