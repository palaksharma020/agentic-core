# SPDX-License-Identifier: Apache-2.0
"""ElasticScopedRetriever against fake clients: what it asks Elasticsearch for, and how it fails."""

import pytest

from agentic_core import DelegationContext, RetrievalUnavailable, RetrieverPort
from agentic_core.adapters.elastic import ElasticScopedRetriever

DANA = DelegationContext("dana", "acme", "knowledge-assistant", {"docs:read"})


class FakeSecurity:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.created: list[dict] = []
        self.invalidated: list[str] = []

    def create_api_key(self, **kw):
        if self.fail:
            raise ConnectionError("cluster down")
        self.created.append(kw)
        return {"id": f"key{len(self.created)}", "encoded": f"enc{len(self.created)}"}

    def invalidate_api_key(self, ids, owner=False):
        if not owner:  # like Elasticsearch for a minter that only has manage_own_api_key
            raise PermissionError("security_exception: owner=true required")
        self.invalidated.extend(ids)


class FakeMinter:
    def __init__(self, fail: bool = False) -> None:
        self.security = FakeSecurity(fail)


class FakeScoped:
    def __init__(self, key: str, fail: bool = False) -> None:
        self.key, self.fail = key, fail

    def search(self, **kw):
        if self.fail:
            raise ConnectionError("timeout")
        return {
            "hits": {
                "hits": [{"_id": "a1", "_source": {"tenant": "acme", "title": "t", "body": "b"}}]
            }
        }

    def options(self, **kw):
        return self

    def get(self, index, id):
        return {"found": id == "a1", "_source": {"tenant": "acme", "title": "t"}}


def make(fail_mint=False, fail_query=False):
    minter = FakeMinter(fail_mint)
    used = []

    def client_for_key(encoded):
        used.append(encoded)
        return FakeScoped(encoded, fail_query)

    r = ElasticScopedRetriever(minter, client_for_key, index="kb-docs", hidden_fields=("salary",))
    return r, minter, used


def test_each_request_mints_a_scoped_key_uses_it_and_invalidates_it():
    r, minter, used = make()
    assert isinstance(r, RetrieverPort)
    assert r.search(DANA, "hotel")[0]["doc_id"] == "a1"
    (created,) = minter.security.created
    idx = created["role_descriptors"]["kb_reader"]["indices"][0]
    assert idx["query"] == {"term": {"tenant": "acme"}}
    assert idx["field_security"]["except"] == ["salary"]
    assert created["expiration"] == "5m"
    assert created["metadata"] == {"user": "dana", "tenant": "acme", "agent": "knowledge-assistant"}
    assert used == ["enc1"]
    assert minter.security.invalidated == ["key1"]


def test_read_hidden_by_dls_is_none():
    r, _, _ = make()
    assert r.read(DANA, "g1") is None
    assert r.read(DANA, "a1")["doc_id"] == "a1"


def test_mint_failure_fails_closed():
    r, _, used = make(fail_mint=True)
    with pytest.raises(RetrievalUnavailable):
        r.search(DANA, "hotel")
    assert used == []  # never queried with anything else


def test_query_failure_fails_closed_and_still_invalidates():
    r, minter, _ = make(fail_query=True)
    with pytest.raises(RetrievalUnavailable):
        r.search(DANA, "hotel")
    assert minter.security.invalidated == ["key1"]


def test_no_read_scope_is_refused_before_minting():
    r, minter, _ = make()
    with pytest.raises(PermissionError):
        r.search(DelegationContext("dana", "acme", "knowledge-assistant", set()), "hotel")
    assert minter.security.created == []


def test_document_cannot_spoof_its_id():
    class Spoof(FakeScoped):
        def search(self, **kw):
            return {
                "hits": {"hits": [{"_id": "a1", "_source": {"tenant": "acme", "doc_id": "g1"}}]}
            }

    minter = FakeMinter()
    r = ElasticScopedRetriever(minter, Spoof, index="kb-docs")
    assert r.search(DANA, "x")[0]["doc_id"] == "a1"


def test_failed_invalidation_is_logged_by_id_never_by_secret(caplog):
    class NoInvalidate(FakeSecurity):
        def invalidate_api_key(self, ids, owner=False):
            raise ConnectionError("down")

    minter = FakeMinter()
    minter.security = NoInvalidate()
    r = ElasticScopedRetriever(minter, lambda enc: FakeScoped(enc), index="kb-docs")
    r.search(DANA, "x")
    assert "key1" in caplog.text and "enc1" not in caplog.text
