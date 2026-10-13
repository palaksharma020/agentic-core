"""Time validate_grounding per claim.

    python bench/bench_grounding.py [n_chunks] [n_claims]

Builds a prompt-sized context (default 20 chunks of ~2 KB, about 40 KB) and validates claims against it,
half grounded and half not. Cost depends on the prompt size, not on how large the corpus behind it is.
"""
from __future__ import annotations

import random
import sys
import time

from agentic_core import Claim, Evidence, validate_grounding

WORDS = ["model", "access", "policy", "approval", "transfer", "balance", "limit", "owner", "review", "ticket", "wiki", "record", "signed", "ingest", "retrieval", "chunk", "source", "tier", "fresh", "stale", "hash", "audit", "claim", "quote", "answer"]


def main(n_chunks: int = 20, n_claims: int = 200, repeats: int = 50) -> None:
    rnd = random.Random(42)
    shown = {f"doc{i}": " ".join(rnd.choice(WORDS) for _ in range(300)) for i in range(n_chunks)}
    claims = []
    for j in range(n_claims):
        sid = f"doc{j % n_chunks}"
        words = shown[sid].split()
        start = rnd.randrange(len(words) - 8)
        quote = " ".join(words[start:start + 8]) if j % 2 == 0 else "an invented sentence that is not there"
        claims.append(Claim(f"claim {j}", [Evidence(sid, quote)]))

    validate_grounding(claims, shown)   # warm-up
    t0 = time.perf_counter()
    for _ in range(repeats):
        res = validate_grounding(claims, shown)
    per_call = (time.perf_counter() - t0) / repeats
    size_kb = sum(len(c) for c in shown.values()) / 1024
    print(f"context: {n_chunks} chunks, {size_kb:.0f} KB | claims: {n_claims} ({len(res.kept)} kept)")
    print(f"per validation call: {per_call * 1000:.2f} ms | per claim: {per_call / n_claims * 1000:.4f} ms")


if __name__ == "__main__":
    main(*(int(a) for a in sys.argv[1:3]))
