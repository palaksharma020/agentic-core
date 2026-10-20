# SPDX-License-Identifier: Apache-2.0
"""Egress scan for model replies: did the model repeat something it must never output?

The primary fix for system-prompt leakage is architectural: keep secrets out of anything the model can
see. This module is the defense in depth that checks every reply on the way out (OWASP LLM07, LLM02):

- canary: a random marker placed in the prompt; seeing it in a reply means the model is reproducing its
  instructions, whatever else it says
- protected values: secrets kept server-side (never in the prompt), matched in disguised forms: case,
  separators, one character per line, leetspeak, reversed, base64, and as an acrostic
- prompt overlap: the share of the prompt's word shingles reproduced in the reply (translation defeats
  this one; the other two do not depend on wording)

Deterministic and dependency-free. A hit should replace the reply and drop any actions in it.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass

_LEET = str.maketrans("013457@$", "OIEASTAS")
_NON_ALNUM = re.compile(r"[^A-Z0-9]")
_B64 = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class ProtectedValue:
    name: str  # what to call it in findings and logs (never log the value)
    value: str


@dataclass(frozen=True)
class LeakFinding:
    rule: str  # "canary" | "protected_value" | "prompt_overlap"
    name: str  # canary, protected value name, or "system_prompt"
    form: str  # how it matched, e.g. "plain_or_obfuscated", "base64", "overlap=0.42"


@dataclass(frozen=True)
class LeakResult:
    leaked: bool
    findings: tuple[LeakFinding, ...]
    prompt_overlap: float


def make_canary(prefix: str = "CANARY") -> str:
    """A fresh random marker, e.g. CANARY-3f9a1c0b7e2d. Generate one per process or per session."""
    return f"{prefix}-{secrets.token_hex(6)}"


def _fold(text: str) -> str:
    """Upper-case, undo common leetspeak, keep only letters and digits."""
    return _NON_ALNUM.sub("", text.upper().translate(_LEET))


def disguised_forms(text: str, value: str) -> list[str]:
    """Which disguises of `value` appear in `text` (empty list: none).

    Values shorter than 4 folded characters are refused (ValueError): they match too much to be useful.
    """
    target = _fold(value)
    if len(target) < 4:
        raise ValueError("protected value too short to match reliably")
    folded = _fold(text)
    found = []
    if target in folded:
        found.append("plain_or_obfuscated")
    if target[::-1] in folded:
        found.append("reversed")
    for token in _B64.findall(text):
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if target in _fold(raw.decode("utf-8", "ignore")):
            found.append("base64")
            break
    initials = "".join(line.strip()[:1] for line in text.splitlines() if line.strip())
    if target in _fold(initials):
        found.append("acrostic")
    return found


def _shingles(text: str, n: int) -> set[tuple[str, ...]]:
    words = _WORD.findall(text.lower())
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


def prompt_overlap(text: str, reference: str, shingle: int = 8) -> float:
    """Share of `reference`'s `shingle`-word sequences that appear verbatim in `text` (0.0 to 1.0)."""
    ref = _shingles(reference, shingle)
    return len(ref & _shingles(text, shingle)) / len(ref) if ref else 0.0


def scan_for_leaks(
    text: str,
    *,
    protected: Iterable[ProtectedValue] = (),
    canaries: Iterable[str] = (),
    reference_prompt: str | None = None,
    overlap_threshold: float = 0.30,
    shingle: int = 8,
) -> LeakResult:
    """Scan one model reply. `leaked` is True if any rule fires."""
    findings: list[LeakFinding] = []
    folded = _fold(text)
    for canary in canaries:
        if _fold(canary) in folded:
            findings.append(LeakFinding("canary", canary, "plain_or_obfuscated"))
    for pv in protected:
        findings += [
            LeakFinding("protected_value", pv.name, f) for f in disguised_forms(text, pv.value)
        ]
    overlap = prompt_overlap(text, reference_prompt, shingle) if reference_prompt else 0.0
    if overlap >= overlap_threshold:
        findings.append(LeakFinding("prompt_overlap", "system_prompt", f"overlap={overlap:.2f}"))
    return LeakResult(bool(findings), tuple(findings), round(overlap, 3))
