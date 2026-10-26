# SPDX-License-Identifier: Apache-2.0
import pytest

from agentic_core import (
    ActionGate,
    AgentManifest,
    AgentStatus,
    ApprovalStatus,
    DelegationContext,
    GateDecision,
    InvalidTransition,
    MemoryApprovalStore,
    MemoryRegistry,
    Reversibility,
    ToolAction,
    ToolGateway,
    check_agent,
    payload_hash,
)

MANIFEST = AgentManifest.from_dict(
    {
        "agent_id": "knowledge-assistant",
        "name": "Enterprise Knowledge Assistant",
        "owner": "platform-team",
        "tools": ["search_docs", "read_doc", "send_email"],
        "scopes": ["docs:read", "mail:send"],
    }
)
DANA = DelegationContext("dana", "acme", "knowledge-assistant", {"docs:read", "mail:send"})
EMAIL = {"to": "x@external-review.example", "subject": "s", "body": "b"}


def active_registry():
    r = MemoryRegistry()
    r.register(MANIFEST, by="admin")
    r.set_status("knowledge-assistant", AgentStatus.ACTIVE, "admin", "go live")
    return r


def test_manifest_refuses_missing_and_unknown_keys():
    with pytest.raises(ValueError):
        AgentManifest.from_dict({"agent_id": "a", "name": "n", "owner": "o", "tools": []})
    with pytest.raises(ValueError):
        AgentManifest.from_dict({**MANIFEST.to_dict(), "run_as": "root"})


def test_new_agent_is_not_active_until_activated():
    r = MemoryRegistry()
    r.register(MANIFEST, by="admin")
    assert not check_agent(r, "knowledge-assistant", "search_docs").ok


def test_revoke_takes_effect_on_the_next_call_and_is_final():
    r = active_registry()
    assert check_agent(r, "knowledge-assistant", "search_docs").ok
    r.set_status("knowledge-assistant", AgentStatus.REVOKED, "admin", "incident")
    check = check_agent(r, "knowledge-assistant", "search_docs")
    assert not check.ok and "revoked" in check.reason
    with pytest.raises(InvalidTransition):
        r.set_status("knowledge-assistant", AgentStatus.ACTIVE, "admin", "oops")
    assert [e["to"] for e in r.events] == ["created", "active", "revoked"]


def test_tool_outside_manifest_is_refused():
    assert not check_agent(active_registry(), "knowledge-assistant", "delete_index").ok


def test_unreachable_registry_means_suspended():
    r = active_registry()
    r.available = False
    check = check_agent(r, "knowledge-assistant", "search_docs")
    assert not check.ok and "unreachable" in check.reason


class AllowAll:
    def decide(self, policy_input):
        self.last = policy_input
        return True, []


def test_gateway_checks_lifecycle_on_every_call():
    r = active_registry()
    gw = ToolGateway({"search_docs": {"type": "object"}}, AllowAll(), registry=r)
    assert gw.check(DANA, "search_docs", {}).allowed
    r.set_status("knowledge-assistant", AgentStatus.SUSPENDED, "admin", "investigate")
    d = gw.check(DANA, "search_docs", {})
    assert (d.allowed, d.stage) == (False, "lifecycle")


def test_policy_sees_approved_only_when_the_server_says_so():
    policy = AllowAll()
    gw = ToolGateway({"send_email": {"type": "object"}}, policy, registry=active_registry())
    gw.check(DANA, "send_email", EMAIL)
    assert policy.last["approved"] is False
    gw.check(DANA, "send_email", EMAIL, approved=True)
    assert policy.last["approved"] is True


GATE = ActionGate(
    {
        "search_docs": ToolAction(Reversibility.REVERSIBLE),
        "send_email": ToolAction(
            Reversibility.IRREVERSIBLE,
            lambda ctx, args: not args["to"].endswith("@" + ctx.tenant + ".example"),
        ),
    }
)


def test_gate_tiers():
    assert GATE.evaluate(DANA, "search_docs", {}) is GateDecision.ALLOW
    assert GATE.evaluate(DANA, "send_email", {"to": "lee@acme.example"}) is GateDecision.ALLOW
    assert GATE.evaluate(DANA, "send_email", EMAIL) is GateDecision.PREVIEW_AND_APPROVE
    assert GATE.evaluate(DANA, "unknown_tool", {}) is GateDecision.PREVIEW_AND_APPROVE


def test_payload_hash_binds_every_field():
    base = payload_hash(DANA, "send_email", EMAIL)
    assert base != payload_hash(DANA, "send_email", {**EMAIL, "body": "b2"})
    assert base != payload_hash(
        DelegationContext("sam", "acme", "knowledge-assistant"), "send_email", EMAIL
    )
    assert base == payload_hash(DANA, "send_email", dict(reversed(list(EMAIL.items()))))


def test_approval_flow_is_single_use_and_exact():
    store = MemoryApprovalStore()
    a = store.create(DANA, "send_email", EMAIL, "preview")
    assert store.redeem(a.approval_id, a.payload_hash).reason == "not_approved"
    with pytest.raises(PermissionError):
        store.decide(a.approval_id, "dana", True)  # no self-approval
    store.decide(a.approval_id, "lee", True)
    assert (
        store.redeem(
            a.approval_id, payload_hash(DANA, "send_email", {**EMAIL, "to": "y@evil.example"})
        ).reason
        == "payload_mismatch"
    )
    assert store.redeem(a.approval_id, a.payload_hash).ok
    assert store.redeem(a.approval_id, a.payload_hash).reason == "already_used"


def test_denied_and_expired_approvals_never_redeem():
    now = [1000.0]
    store = MemoryApprovalStore(ttl_seconds=600, clock=lambda: now[0])
    denied = store.create(DANA, "send_email", EMAIL, "p")
    store.decide(denied.approval_id, "lee", False)
    assert store.get(denied.approval_id).status is ApprovalStatus.DENIED
    assert not store.redeem(denied.approval_id, denied.payload_hash).ok
    late = store.create(DANA, "send_email", EMAIL, "p")
    store.decide(late.approval_id, "lee", True)
    now[0] += 601
    assert store.redeem(late.approval_id, late.payload_hash).reason == "expired"
    assert store.list_pending() == []
