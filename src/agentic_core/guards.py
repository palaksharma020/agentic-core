# SPDX-License-Identifier: Apache-2.0
"""Guardrails: classifiers and redactors around the model, and a content shield for untrusted documents.

Guards give signals; code decides. A guard can only tighten: tighten_all() allows only if every guard allows,
and a guard that can't run (GuardUnavailable) counts as a block. Backends live in adapters (Llama Guard via
Ollama, Microsoft Presidio); this module stays dependency-free.

ContentShield cleans text that came from outside before the model sees it:
    - removes invisible and direction-changing characters (format, control, private-use, unassigned)
    - normalises look-alike characters (Unicode NFKC)
    - caps the size
    - defangs forged conversation lines ("User:", "System:" ...) so a document can't pose as a new turn
    - flags instruction-like phrases (advisory: flags can tighten, e.g. require approval, never allow)
Spotlighting (sources.render_untrusted) marks the result as data. None of this prevents injection on its own;
it lowers the odds, and the deterministic controls (policy, approval) hold either way.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from agentic_core.models import Message


@dataclass(frozen=True)
class GuardVerdict:
    allowed: bool
    source: str
    categories: tuple[str, ...] = ()
    reason: str = ""


class GuardUnavailable(Exception):
    """The guard could not decide (down, timeout, unparseable). Callers treat it as a block."""


@runtime_checkable
class GuardrailPort(Protocol):
    name: str

    def check(self, text: str, *, role: str, context: Sequence[Message] = ()) -> GuardVerdict:
        """Classify `text` said by `role` ("user" or "assistant"); raise GuardUnavailable if it can't."""
        ...


def tighten_all(
    guards: Iterable[GuardrailPort], text: str, *, role: str, context: Sequence[Message] = ()
) -> GuardVerdict:
    """Run every guard; allowed only if all allow. A guard that can't run blocks (fail closed)."""
    for guard in guards:
        try:
            verdict = guard.check(text, role=role, context=context)
        except GuardUnavailable as exc:
            return GuardVerdict(False, guard.name, (), f"guard unavailable: {exc}")
        if not verdict.allowed:
            return verdict
    return GuardVerdict(True, "all")


_HIDDEN = {"Cf", "Cc", "Co", "Cn"}
_ROLE_LINE = re.compile(r"(?im)^(\s*)(user|assistant|system|human|ai|tool)(\s*:)")
_INSTRUCTION_PATTERNS = {
    "addresses the assistant": re.compile(
        r"\b(ai|assistant|chatbot|llm|language model)s?\b.{0,40}\b(must|should|need to|are required)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "overrides instructions": re.compile(
        r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier)\b.{0,20}\binstructions?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "hides from the user": re.compile(
        r"\b(do not|don't|never)\b.{0,20}\b(mention|tell|reveal|inform)\b.{0,30}\b(user|reader)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "asks to send data": re.compile(
        r"\b(send|email|forward|post|upload)\b.{0,60}\b(to|at)\b.{0,10}[\w.+-]+@[\w-]+\.[\w.]+",
        re.IGNORECASE | re.DOTALL,
    ),
    "forged turn": _ROLE_LINE,
}


@dataclass(frozen=True)
class ShieldResult:
    text: str
    removed_chars: int
    truncated: bool
    flags: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return bool(self.flags) or self.removed_chars > 0


@dataclass(frozen=True)
class ContentShield:
    max_chars: int = 8000

    def shield(self, text: str) -> ShieldResult:
        kept = [c for c in text if unicodedata.category(c) not in _HIDDEN or c in "\n\t"]
        removed = len(text) - len(kept)
        clean = unicodedata.normalize("NFKC", "".join(kept))
        flags = tuple(
            sorted(name for name, pat in _INSTRUCTION_PATTERNS.items() if pat.search(clean))
        )
        clean = _ROLE_LINE.sub(r"\1[quoted text] \2\3", clean)  # a document can't open a new turn
        truncated = len(clean) > self.max_chars
        if truncated:
            clean = clean[: self.max_chars] + "\n[truncated: document exceeds the size limit]"
        return ShieldResult(clean, removed, truncated, flags)
