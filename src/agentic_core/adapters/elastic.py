# SPDX-License-Identifier: Apache-2.0
"""ElasticScopedRetriever: a RetrieverPort that mints a short-lived Elasticsearch API key per request.

For each search or read:
1. The minter client (a service user that may only read the index and manage its own API keys) creates an
   API key whose role descriptor is tenant_role_descriptor(ctx): the user's tenant only (document-level
   security) and without hidden fields (field-level security). Elasticsearch caps the key at the minter's
   own privileges, so the key can never be broader than the minter.
2. The query runs with that key, so Elasticsearch, not this code, removes other tenants' documents.
3. The key is invalidated, as its owner (and expires on its own after `ttl` anyway). A minter with only
   manage_own_api_key must invalidate with owner=true, so the adapter always does.

Duck-typed: pass elasticsearch-py clients (no import here, so agentic-core keeps no dependencies). Any
failure raises RetrievalUnavailable: there is no fallback to the minter's or any broader credential.
Requires a licence with document- and field-level security (Platinum, Enterprise or trial).
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable, Iterable
from typing import Any

from agentic_core.identity import DelegationContext
from agentic_core.retrieval import RetrievalUnavailable, tenant_role_descriptor

log = logging.getLogger(__name__)
_BUGS = (TypeError, AttributeError)  # programming errors surface; everything else fails closed


class ElasticScopedRetriever:
    def __init__(
        self,
        minter: Any,
        client_for_key: Callable[[str], Any],
        *,
        index: str,
        hidden_fields: Iterable[str] = (),
        tenant_field: str = "tenant",
        ttl: str = "5m",
    ) -> None:
        self.minter = minter
        self.client_for_key = client_for_key
        self.index = index
        self.hidden = tuple(hidden_fields)
        self.tenant_field = tenant_field
        self.ttl = ttl

    def _run(self, ctx: DelegationContext, op: Callable[[Any], Any]) -> Any:
        descriptor = tenant_role_descriptor(
            ctx, index=self.index, tenant_field=self.tenant_field, hidden_fields=self.hidden
        )
        try:
            key = self.minter.security.create_api_key(
                name=f"kb-{ctx.tenant}-{ctx.user}-{secrets.token_hex(4)}",
                role_descriptors=descriptor,
                expiration=self.ttl,
                metadata={"user": ctx.user, "tenant": ctx.tenant, "agent": ctx.agent_id},
            )
        except _BUGS:
            raise
        except Exception as exc:
            raise RetrievalUnavailable(
                f"could not mint a scoped key: {type(exc).__name__}"
            ) from exc
        try:
            return op(self.client_for_key(key["encoded"]))
        except _BUGS:
            raise
        except Exception as exc:
            raise RetrievalUnavailable(f"scoped query failed: {type(exc).__name__}") from exc
        finally:
            try:
                self.minter.security.invalidate_api_key(ids=[key["id"]], owner=True)
            except Exception as exc:  # the key still expires after ttl; say so, by id only
                log.warning(
                    "could not invalidate API key %s (%s); it expires after %s",
                    key["id"],
                    type(exc).__name__,
                    self.ttl,
                )

    def search(self, ctx: DelegationContext, query: str, size: int = 5) -> list[dict[str, Any]]:
        def op(es: Any) -> list[dict[str, Any]]:
            res = es.search(
                index=self.index,
                query={"multi_match": {"query": query, "fields": ["title^2", "body"]}},
                size=size,
            )
            # the stored _id wins over any doc_id field inside the document
            return [{**h["_source"], "doc_id": h["_id"]} for h in res["hits"]["hits"]]

        result: list[dict[str, Any]] = self._run(ctx, op)
        return result

    def read(self, ctx: DelegationContext, doc_id: str) -> dict[str, Any] | None:
        def op(es: Any) -> dict[str, Any] | None:
            res = es.options(ignore_status=404).get(index=self.index, id=doc_id)
            return {**res["_source"], "doc_id": doc_id} if res.get("found") else None

        result: dict[str, Any] | None = self._run(ctx, op)
        return result
