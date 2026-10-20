# SPDX-License-Identifier: Apache-2.0
"""Pluggable advisors: probabilistic classifiers that may tighten a decision, never loosen it.

An InjectionAdvisor scores untrusted text (a user message, a retrieved document, a tool result) for
prompt injection. Its verdict is advice: callers use `flagged` to refuse or to deny actions, and never
to allow something deterministic controls would block. Backends (a DeBERTa classifier, Prompt-Guard, an
LLM) live outside this package so the core stays dependency-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class AdvisorScore:
    score: float  # 0.0 (benign) to 1.0 (injection), as the backend reports it
    flagged: bool  # score >= the backend's threshold
    advisor: str  # backend name, for logs and evals


@runtime_checkable
class InjectionAdvisor(Protocol):
    name: str

    def score(self, text: str) -> AdvisorScore: ...


class NullAdvisor:
    """The default: never flags. Lets callers run the same code path with no advisor installed."""

    name = "none"

    def score(self, text: str) -> AdvisorScore:
        return AdvisorScore(0.0, False, self.name)


def tighten_only(allowed: bool, advice: AdvisorScore) -> bool:
    """Combine a deterministic decision with advice: the result can only be stricter."""
    return allowed and not advice.flagged
