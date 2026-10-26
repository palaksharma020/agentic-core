# SPDX-License-Identifier: Apache-2.0
import pytest

from agentic_core import (
    DelegationContext,
    MemoryScopedRetriever,
    RetrievalUnavailable,
    RetrieverPort,
    attenuate,
    tenant_role_descriptor,
)

DOCS = [
    {
        "doc_id": "a1",
        "tenant": "acme",
        "title": "Acme travel",
        "body": "hotel cap 220",
        "salary": None,
    },
    {
        "doc_id": "a2",
        "tenant": "acme",
        "title": "Employee Dana",
        "body": "engineer",
        "salary": 182000,
    },
    {
        "doc_id": "g1",
        "tenant": "globex",
        "title": "Globex plan",
        "body": "hotel BLUE HERON",
        "salary": None,
    },
]
DANA = DelegationContext(
    user="dana", tenant="acme", agent_id="knowledge-assistant", scopes={"docs:read"}
)


def test_context_requires_every_field():
    with pytest.raises(ValueError):
        DelegationContext(user="", tenant="acme", agent_id="a", scopes={"docs:read"})
    with pytest.raises(ValueError):
        DelegationContext(user="dana", tenant="", agent_id="a", scopes={"docs:read"})


def test_act_claim_names_user_and_agent():
    assert DANA.act_claim() == {
        "sub": "dana",
        "tenant": "acme",
        "act": {"sub": "knowledge-assistant"},
    }


def test_attenuate_only_narrows():
    narrowed = attenuate(DANA, {"docs:read", "mail:send"})
    assert narrowed.scopes == frozenset({"docs:read"})  # cannot gain mail:send
    assert attenuate(DANA, set()).scopes == frozenset()


def test_role_descriptor_pins_tenant_and_hides_fields():
    rd = tenant_role_descriptor(DANA, index="kb-docs", hidden_fields=("salary",))
    (index_priv,) = rd["kb_reader"]["indices"]
    assert index_priv["names"] == ["kb-docs"]
    assert index_priv["privileges"] == ["read"]
    assert index_priv["query"] == {"term": {"tenant": "acme"}}
    assert index_priv["field_security"] == {"grant": ["*"], "except": ["salary"]}
    assert rd["kb_reader"]["cluster"] == []


def test_role_descriptor_needs_read_scope():
    no_read = DelegationContext(user="dana", tenant="acme", agent_id="a", scopes=set())
    with pytest.raises(PermissionError):
        tenant_role_descriptor(no_read, index="kb-docs")


def test_memory_retriever_enforces_tenant_and_fields():
    r = MemoryScopedRetriever(DOCS, hidden_fields=("salary",))
    assert isinstance(r, RetrieverPort)
    hits = r.search(DANA, "hotel")
    assert [h["doc_id"] for h in hits] == ["a1"]  # globex's hotel doc is invisible
    assert r.read(DANA, "g1") is None  # by id too
    assert "salary" not in r.read(DANA, "a2")


def test_memory_retriever_fails_closed_when_down():
    r = MemoryScopedRetriever(DOCS, available=False)
    with pytest.raises(RetrievalUnavailable):
        r.search(DANA, "hotel")
