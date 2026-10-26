# SPDX-License-Identifier: Apache-2.0
"""Retrieve as the user, not as the agent.

The search engine enforces the user's tenant and hidden fields on every request, so results never contain
what the user may not see: no filtering after retrieval. tenant_role_descriptor() builds the permissions for
a short-lived, per-request credential (Elasticsearch role descriptor shape: document-level security as a
query, field-level security as grant/except). Any failure to retrieve raises RetrievalUnavailable; callers
must answer "can't search right now" and never fall back to a broader credential.

MemoryScopedRetriever applies the same rules in memory, for tests. adapters.elastic does it for real.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Protocol, runtime_checkable

from agentic_core.identity import DelegationContext

READ_SCOPE = "docs:read"


class RetrievalUnavailable(Exception):
    """Retrieval could not run safely (store down, licence missing, credential not minted). Fail closed."""


@runtime_checkable
class RetrieverPort(Protocol):
    def search(self, ctx: DelegationContext, query: str, size: int = 5) -> list[dict[str, Any]]: ...

    def read(self, ctx: DelegationContext, doc_id: str) -> dict[str, Any] | None: ...


def tenant_role_descriptor(
    ctx: DelegationContext,
    *,
    index: str,
    tenant_field: str = "tenant",
    hidden_fields: Iterable[str] = (),
) -> dict[str, Any]:
    """Read-only access to one index, limited to the user's tenant, with sensitive fields removed."""
    if READ_SCOPE not in ctx.scopes:
        raise PermissionError(f"{ctx.agent_id} has no {READ_SCOPE!r} scope for {ctx.user}")
    index_priv: dict[str, Any] = {
        "names": [index],
        "privileges": ["read"],
        "query": {"term": {tenant_field: ctx.tenant}},
    }
    hidden = sorted(set(hidden_fields))
    if hidden:
        index_priv["field_security"] = {"grant": ["*"], "except": hidden}
    return {"kb_reader": {"cluster": [], "indices": [index_priv]}}


class MemoryScopedRetriever:
    """Documents as dicts with doc_id and tenant. Same rules as the role descriptor, enforced in memory."""

    def __init__(
        self,
        docs: Sequence[dict[str, Any]],
        *,
        hidden_fields: Iterable[str] = (),
        tenant_field: str = "tenant",
        available: bool = True,
    ) -> None:
        self.docs = list(docs)
        self.hidden = frozenset(hidden_fields)
        self.tenant_field = tenant_field
        self.available = available

    def _visible(self, ctx: DelegationContext) -> list[dict[str, Any]]:
        if not self.available:
            raise RetrievalUnavailable("store unavailable")
        tenant_role_descriptor(ctx, index="memory")  # same scope check as the real credential
        return [
            {k: v for k, v in d.items() if k not in self.hidden}
            for d in self.docs
            if d.get(self.tenant_field) == ctx.tenant
        ]

    def search(self, ctx: DelegationContext, query: str, size: int = 5) -> list[dict[str, Any]]:
        terms = {t for t in query.lower().split() if len(t) > 2}
        scored = [
            (sum(t in " ".join(str(v) for v in d.values()).lower() for t in terms), d)
            for d in self._visible(ctx)
        ]
        return [d for score, d in sorted(scored, key=lambda x: -x[0]) if score > 0][:size]

    def read(self, ctx: DelegationContext, doc_id: str) -> dict[str, Any] | None:
        return next((d for d in self._visible(ctx) if d.get("doc_id") == doc_id), None)
