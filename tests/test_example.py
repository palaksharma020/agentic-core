# SPDX-License-Identifier: Apache-2.0
"""The example the blog walks through must keep working."""

import importlib.util
from pathlib import Path

from agentic_core import DropReason, SourceRejection, Verdict

_spec = importlib.util.spec_from_file_location(
    "rag_answer", Path(__file__).parents[1] / "examples" / "rag_answer.py"
)
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)


def test_trusted_path_verified_and_recalled_claim_removed():
    d = ex.run_trusted()
    assert d.verdict is Verdict.VERIFIED
    assert [k.claim.text for k in d.claims] == [
        "You have 12.5 days of PTO left. Book leave"
    ]  # link stripped
    assert any(DropReason.NOT_IN_PROMPT.value in r for r in d.reasons)


def test_trusted_path_requery_mismatch_downgrades(monkeypatch):
    monkeypatch.setattr(ex, "hris_requery", lambda g: False)
    d = ex.answer("q", "hr_balance", {"hris:pto/E-1042": ex.HRIS_PTO}, requery=ex.hris_requery)
    assert d.verdict is Verdict.CONFLICTING


def test_grounding_alone_accepts_the_poisoned_page():
    assert len(ex.run_naive().kept) == 1


def test_untrusted_path_refused_with_reasons():
    d = ex.run_untrusted()
    assert d.verdict is Verdict.REFUSED and not d.claims
    joined = " ".join(d.reasons)
    assert SourceRejection.TIER.value in joined and SourceRejection.HASH_MISMATCH.value in joined


def test_unparseable_model_output_fails_closed():
    d = ex.answer(
        "q",
        "hr_balance",
        {"hris:pto/E-1042": ex.HRIS_PTO},
        model=lambda p: "I think about 12 days?",
    )
    assert d.verdict is Verdict.REFUSED
