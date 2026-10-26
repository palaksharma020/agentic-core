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
# Removing these is housekeeping (PDF/Windows artefacts, emoji joiners), not a sign of an attack.
_BENIGN_INVISIBLE = {"\u00ad", "\ufeff", "\u200c", "\u200d"}
_LINE_BREAKS = str.maketrans({"\r": "\n", "\u2028": "\n", "\u2029": "\n", "\u0085": "\n"})
# Common look-alike letters (Unicode confusables, UTS #39) folded to Latin for detection only.
_CONFUSABLES = str.maketrans(
    # Cyrillic and Greek look-alikes, written as escapes so the source itself has no homoglyphs.
    "\u0410\u0412\u0415\u0405\u0406\u0408\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0423\u0430"
    "\u0435\u0455\u0456\u0458\u043e\u0440\u0441\u0443\u0445\u0501\u04bb\u051b\u051d\u0391\u0392\u0395"
    "\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7\u03bf\u03b1\u03bd",
    "ABESIJKMHOPCTXYaesijopcyxdhqwABEZHIKMNOPTYXoav",
)
# "model" (a chat-template role) is left out: "Model: XPS 13" style labels are far more common in documents.
_ROLES = r"user|assistant|system|human|ai|tool|developer"
# A role marker: at a line start or after markup/sentence punctuation, the role word, an optional
# "(name)", optional markdown emphasis, then ":" "]" or "|>" (chat-template style).
_ROLE_MARKER = re.compile(
    rf"(?im)(?:^|(?<=[>#*\-\[|<(])|(?<=[.!?;]\s))\s*(?:\*\*|__)?\s*({_ROLES})\b"
    r"\s*(?:\([^)\n]{0,40}\))?\s*(?:\*\*|__)?\s*(?::|\]|\|>)"
)
_ADDRESS = r"[\w.+-]+\s*(?:@|\[at\]|\(at\)|\{at\}|\s+at\s+)\s*[\w-]+\s*(?:\.|\[dot\]|\(dot\)|\s+dot\s+)\s*[\w.]+"
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
        rf"\b(send|email|e-mail|forward|post|upload|mail)\b.{{0,80}}\b(to|at)\b.{{0,15}}{_ADDRESS}",
        re.IGNORECASE | re.DOTALL,
    ),
    "forged turn": _ROLE_MARKER,
}


@dataclass(frozen=True)
class ShieldResult:
    text: str
    removed_chars: int  # every invisible character removed
    truncated: bool
    flags: tuple[str, ...]
    suspicious_chars: int = 0  # bidi, tag and other hidden characters (not PDF/Windows artefacts)

    @property
    def suspicious(self) -> bool:
        return bool(self.flags) or self.suspicious_chars > 0


@dataclass(frozen=True)
class ContentShield:
    max_chars: int = 8000

    def shield(self, text: str) -> ShieldResult:
        text = text.replace("\r\n", "\n").translate(_LINE_BREAKS)
        removed = [c for c in text if unicodedata.category(c) in _HIDDEN and c not in "\n\t"]
        kept = "".join(c for c in text if unicodedata.category(c) not in _HIDDEN or c in "\n\t")
        suspicious_chars = sum(1 for c in removed if c not in _BENIGN_INVISIBLE)
        clean = unicodedata.normalize("NFKC", kept)
        # Detect on a look-alike-folded copy; same length, so match positions line up with `clean`.
        skeleton = clean.translate(_CONFUSABLES)
        flags = {name for name, pat in _INSTRUCTION_PATTERNS.items() if pat.search(skeleton)}
        if skeleton != clean and _ROLE_MARKER.search(skeleton) and not _ROLE_MARKER.search(clean):
            flags.add("look-alike letters in a role marker")
        out, last = [], 0
        for m in _ROLE_MARKER.finditer(skeleton):  # a document can't open a new turn
            out.append(clean[last : m.start(1)] + "[quoted text] ")
            last = m.start(1)
        clean = "".join(out) + clean[last:]
        truncated = len(clean) > self.max_chars
        if truncated:
            clean = clean[: self.max_chars] + "\n[truncated: document exceeds the size limit]"
        return ShieldResult(clean, len(removed), truncated, tuple(sorted(flags)), suspicious_chars)
