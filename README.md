# agentic-core

Small, framework-agnostic utilities for building agents whose output you can check.
No LLM calls, no dependencies: plain dataclasses and deterministic checks that sit around a model.

The first utilities form a **validation harness for RAG and tool-using agents**:

| Module | What it does |
|---|---|
| `sources` | **Source gate.** Before the model runs: is each retrieved chunk registered, from an allowed trust tier for this question class, unchanged since ingest (SHA-256) and fresh? Plus `render_untrusted()` for spotlighting. |
| `grounding` | **Faithfulness.** `validate_grounding()` keeps a claim only if its quote appears (normalized) in the chunks the model was *shown*, and says why it dropped the others: invented (`not_in_source`) or real text that was not in the prompt (`not_in_prompt`, recalled or invented). |
| `verdict` | **Decision.** Combines both into `VERIFIED / SUPPORTED / CONFLICTING / REFUSED`. A model may downgrade the label, never upgrade it. |
| `severity` | **Limited authority.** Tighten-only severity with a floor, one level per proposal and a ceiling above which a human decides. |
| `text` | `normalize()`, `sanitize_llm_text()` (strip links, images, URLs, HTML), `parse_json_object()` (raises, so you can fail closed). |

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q && python examples/rag_answer.py
```

## Example

```python
from agentic_core import check_sources, validate_grounding, decide, render_untrusted

gate = check_sources(retrieved, records, policy, "finance_limits")  # 1. which sources may answer
raw = model(prompt_with(render_untrusted(gate.allowed)))  # 2. only allowed chunks reach the model
grounding = validate_grounding(
    claims_from(raw), gate.allowed
)  # 3. quotes must be in what it was shown
decision = decide(grounding, gate)  # 4. VERIFIED / SUPPORTED / CONFLICTING / REFUSED
```

[`examples/rag_answer.py`](examples/rag_answer.py) runs this end to end, offline, for a trusted source (an HRIS
balance) and an untrusted one (a wiki page edited to state a false wire-transfer rule).

## What these checks do not prove

- A grounded quote shows the claim is **faithful** to text the model was given, not that the claim **follows**
  from it. Use entailment checks or human review for high-impact claims.
- The source gate trusts your **ingest records** (tier, hash, date). Protect those records, for example by signing
  them, as carefully as the content.
- Spotlighting reduces indirect prompt injection; it does not prevent it. That is why the other checks do not
  depend on the model obeying instructions.

## Benchmark

```bash
python bench/bench_grounding.py
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
