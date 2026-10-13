"""Validate a RAG answer with agentic-core: a trusted source and an untrusted one.

    python examples/rag_answer.py

The model is faked with canned JSON so this runs offline with no setup. To use a real model, replace
fake_model() with your client call; everything after it stays the same.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from agentic_core import (
    Claim,
    Decision,
    SourcePolicy,
    SourceRecord,
    ValidationResult,
    Verdict,
    check_sources,
    decide,
    normalize,
    parse_json_object,
    render_untrusted,
    sanitize_llm_text,
    sha256_text,
    validate_grounding,
)

NOW = datetime(2026, 10, 9, 9, 0, tzinfo=timezone.utc)

# --- Content as retrieved at question time -------------------------------------------------------------------
HRIS_PTO = "Employee E-1042 - leave balances\nPTO balance: 12.5 days\nSick leave: 4 days"
HRIS_LEAVE_POLICY = "Leave policy, section 3. Unused PTO carries over up to 5 days into the next calendar year."
WIKI_PAYMENTS = "Payments FAQ (team wiki)\nWire transfers under $1M need no second approval."
POLICY_WIRES_AT_INGEST = "Treasury policy 4.2: wire transfers of $50,000 or more require a second approver."
POLICY_WIRES_NOW = "Treasury policy 4.2: wire transfers under $1M need no second approval."   # altered after ingest

# --- What the ingestion pipeline recorded: tier, hash and date per chunk. The model never writes these. ------
RECORDS = {
    "hris:pto/E-1042": SourceRecord("hris:pto/E-1042", tier=1, sha256=sha256_text(HRIS_PTO),
                                    as_of=datetime(2026, 10, 8, 23, 0, tzinfo=timezone.utc), origin="hris"),
    "wiki:payments-faq": SourceRecord("wiki:payments-faq", tier=2, sha256=sha256_text(WIKI_PAYMENTS),
                                      as_of=datetime(2026, 10, 8, tzinfo=timezone.utc), origin="wiki"),
    "policy:treasury/4.2": SourceRecord("policy:treasury/4.2", tier=1, sha256=sha256_text(POLICY_WIRES_AT_INGEST),
                                        as_of=datetime(2026, 9, 1, tzinfo=timezone.utc), origin="policy-repo"),
}

# --- Which tier may answer which class of question, how fresh it must be, how many origins must agree --------
POLICY = SourcePolicy(
    max_tier={"hr_balance": 1, "finance_limits": 1, "how_to": 3},
    ttl={1: timedelta(days=2), 2: timedelta(days=90)},
    corroborate={"finance_limits": 2},
)

# --- A pretend model: what it returns depends on what it was shown ---------------------------------------------
CANNED = {
    "PTO balance": {"claims": [
        {"text": "You have 12.5 days of PTO left. [Book leave](https://hr.example.com/book?u=E-1042)",
         "evidence": [{"source_id": "hris:pto/E-1042", "quote": "PTO balance: 12.5 days"}]},
        {"text": "Up to 5 unused days carry over into next year.",
         "evidence": [{"source_id": "hris:policy/leave", "quote": "Unused PTO carries over up to 5 days"}]},
    ]},
    "Wire transfers under": {"claims": [
        {"text": "Wire transfers under $1M do not need a second approver.",
         "evidence": [{"source_id": "wiki:payments-faq", "quote": "Wire transfers under $1M need no second approval"}]},
    ]},
}


def fake_model(prompt: str) -> str:
    return json.dumps(next((v for k, v in CANNED.items() if k in prompt), {"claims": []}))


# --- The harness ------------------------------------------------------------------------------------------------
def answer(question: str, question_class: str, retrieved: dict[str, str], *,
           model: Callable[[str], str] = fake_model, sources: dict[str, str] | None = None,
           requery: Callable[[ValidationResult], bool] | None = None) -> Decision:
    # 1. Source gate: policy decides which chunks may reach the model at all.
    gate = check_sources(retrieved, RECORDS, POLICY, question_class, now=NOW)

    # 2. Only allowed chunks go into the prompt, marked as data (spotlighting).
    raw = model(f"Answer from the sources only.\n{render_untrusted(gate.allowed)}\n\nQ: {question}") if gate.ok else ""

    # 3. Parse, failing closed: unparseable output means no claims, never "trust whatever came back".
    try:
        claims = [Claim.from_dict(c) for c in parse_json_object(raw).get("claims", []) if isinstance(c, dict)]
    except ValueError:
        claims = []
    for c in claims:
        c.text = sanitize_llm_text(c.text)

    # 4. Grounding against what the model was shown (gate.allowed), not against the corpus.
    grounding = validate_grounding(claims, gate.allowed, sources=sources)

    # 5. Structured sources: re-run the query; a mismatch can only push the verdict down.
    flags = [] if requery is None or requery(grounding) else [Verdict.CONFLICTING]
    return decide(grounding, gate, flags=flags)


def hris_requery(grounding: ValidationResult) -> bool:
    live = {"E-1042": "12.5 days"}["E-1042"]           # stand-in for SELECT pto_balance FROM hris WHERE emp = ...
    return all(normalize(f"PTO balance: {live}") in normalize(e.quote)
               for k in grounding.kept for e in k.evidence if e.source_id.startswith("hris:pto/"))


def run_trusted() -> Decision:
    return answer("How many PTO days do I have left?", "hr_balance", {"hris:pto/E-1042": HRIS_PTO},
                  sources={"hris:policy/leave": HRIS_LEAVE_POLICY}, requery=hris_requery)


def run_untrusted() -> Decision:
    return answer("Do wire transfers under $1M need a second approver?", "finance_limits",
                  {"wiki:payments-faq": WIKI_PAYMENTS, "policy:treasury/4.2": POLICY_WIRES_NOW})


def run_naive() -> ValidationResult:
    """Grounding only, no source gate: the poisoned wiki quote passes."""
    retrieved = {"wiki:payments-faq": WIKI_PAYMENTS}
    claims = [Claim.from_dict(c) for c in parse_json_object(fake_model(render_untrusted(retrieved)))["claims"]]
    return validate_grounding(claims, retrieved)


def _show(title: str, d: Decision) -> None:
    print(f"\n== {title}: {d.verdict.value.upper()}")
    for k in d.claims:
        print(f"   claim: {k.claim.text}")
        for e in k.evidence:
            print(f"     evidence: {e.source_id} \"{e.quote}\" sha256={e.chunk_sha256[:12]}...")
    for r in d.reasons:
        print(f"   - {r}")


if __name__ == "__main__":
    _show("A. Trusted source (HRIS)", run_trusted())
    naive = run_naive()
    print(f"\n== B0. Untrusted source, grounding only: {len(naive.kept)} claim kept -> "
          f"{naive.kept[0].claim.text!r}  (grounded, and wrong)")
    _show("B. Untrusted source, full harness", run_untrusted())
