# SPDX-License-Identifier: Apache-2.0
import asyncio
import hashlib
import hmac
import json

import pytest

from agentic_core import (
    AuditLog,
    AuditUnavailable,
    DelegationContext,
    MemoryAuditSink,
    audited_decisions,
    audited_execution,
    verify_chain,
)

DANA = DelegationContext("dana", "acme", "knowledge-assistant", {"mail:send"})
KEY = b"k" * 32


class HmacSigner:  # stand-in for Ed25519 in core tests (no dependency)
    key_id = "test-key"

    def sign(self, data):
        return hmac.new(KEY, data, hashlib.sha256).hexdigest()


def verify(key_id, data, sig):
    return key_id == "test-key" and hmac.compare_digest(
        sig, hmac.new(KEY, data, hashlib.sha256).hexdigest()
    )


def chain(n=3, sink=None):
    sink = sink or MemoryAuditSink()
    log = AuditLog("agent-1", sink, HmacSigner(), clock=lambda: 1000.0)
    for i in range(n):
        intent = log.intent(DANA, "send_email", {"to_domain": "acme.example", "i": i}, durable=True)
        log.outcome(DANA, intent, {"result": "sent"})
    return log, sink


def test_intact_chain_verifies_and_outcomes_reference_intents():
    log, sink = chain()
    assert verify_chain(sink.records, verify, expected_head=(log.seq, log.head)).ok
    assert sink.records[1]["ref"] == sink.records[0]["hash"]
    assert sink.records[0]["actor"] == {
        "sub": "dana",
        "tenant": "acme",
        "act": {"sub": "knowledge-assistant"},
    }


@pytest.mark.parametrize(
    ("tamper", "problem"),
    [
        (lambda r: r[2]["details"].update({"to_domain": "evil.example"}), "edited"),
        (lambda r: r.pop(2), "sequence gap"),
        (lambda r: r.__setitem__(3, {**r[3], "prev_hash": "0" * 64}), "broken link"),
        (lambda r: r.__setitem__(1, {**r[1], "signature": "forged"}), "bad signature"),
        (lambda r: r.__setitem__(1, {**r[1], "key_id": "attacker"}), ""),
    ],
)
def test_tampering_is_detected(tamper, problem):
    _, sink = chain()
    tamper(sink.records)
    check = verify_chain(sink.records, verify)
    assert not check.ok and problem in check.problem


def test_deleting_the_tail_needs_the_published_head():
    log, sink = chain()
    del sink.records[-2:]
    assert verify_chain(sink.records, verify).ok  # undetectable without the head ...
    assert not verify_chain(
        sink.records, verify, expected_head=(log.seq, log.head)
    ).ok  # ... detected with it


def test_head_may_lag_but_must_match():
    _, sink = chain()
    lagging = (2, sink.records[1]["hash"])
    assert verify_chain(sink.records, verify, expected_head=lagging).ok
    wrong = (2, sink.records[2]["hash"])
    check = verify_chain(sink.records, verify, expected_head=wrong)
    assert not check.ok and "different hash" in check.problem


def test_whole_chain_deleted_is_detected_from_its_head():
    check = verify_chain([], verify, expected_head=(3, "abc"))
    assert not check.ok and check.problem == "no records"


def test_sink_outage_buffers_and_flushes_in_order():
    sink = MemoryAuditSink()
    log = AuditLog("agent-1", sink, HmacSigner())
    sink.available = False
    log.write("decision", DANA.act_claim(), "search_docs", {"stage": "allowed"})
    log.write("decision", DANA.act_claim(), "read_doc", {"stage": "allowed"})
    assert sink.records == [] and len(log.buffer) == 2
    sink.available = True
    log.write("decision", DANA.act_claim(), "read_doc", {"stage": "allowed"})
    assert [r["seq"] for r in sink.records] == [1, 2, 3] and verify_chain(sink.records, verify).ok


def test_irreversible_intent_must_be_durable():
    sink = MemoryAuditSink(available=False)
    log = AuditLog("agent-1", sink, HmacSigner())
    with pytest.raises(AuditUnavailable):
        log.intent(DANA, "send_email", {"to_domain": "acme.example"}, durable=True)


def test_full_buffer_refuses_new_records():
    sink = MemoryAuditSink(available=False)
    log = AuditLog("agent-1", sink, HmacSigner(), max_buffer=2)
    log.write("decision", {}, "a", {})
    log.write("decision", {}, "b", {})
    with pytest.raises(AuditUnavailable):
        log.write("decision", {}, "c", {})


def test_ed25519_signatures_round_trip_and_reject_other_keys():
    pytest.importorskip("cryptography")
    from agentic_core.adapters.ed25519 import (
        Ed25519Signer,
        Ed25519Verifier,
        new_seed,
        public_key_b64,
    )

    seed, other = new_seed(), new_seed()
    signer = Ed25519Signer(seed)
    sink = MemoryAuditSink()
    log = AuditLog("agent-1", sink, signer)
    log.write("decision", DANA.act_claim(), "search_docs", {"stage": "allowed"})
    assert verify_chain(sink.records, Ed25519Verifier.from_public(public_key_b64(seed))).ok
    assert not verify_chain(sink.records, Ed25519Verifier.from_public(public_key_b64(other))).ok


@pytest.mark.parametrize(
    "bad",
    [
        {"chain_id": "agent-1"},  # missing fields
        "seq-as-string",
        "not-a-mapping",
    ],
)
def test_malformed_records_fail_the_chain_and_never_raise(bad):
    _, sink = chain()
    records = list(sink.records)
    if bad == "seq-as-string":
        records[0] = {**records[0], "seq": "1"}
    elif bad == "not-a-mapping":
        records.append(["x"])
    else:
        records.append(bad)
    check = verify_chain(records, verify)
    assert not check.ok and "malformed" in check.problem


def test_key_policy_rejects_a_valid_signature_from_the_wrong_key():
    _, sink = chain()
    check = verify_chain(sink.records, verify, key_allowed=lambda r: r.key_id == "approver-key")
    assert not check.ok and "not allowed" in check.problem
    assert verify_chain(sink.records, verify, key_allowed=lambda r: r.key_id == "test-key").ok


def test_a_signer_error_leaves_no_sequence_gap():
    class Flaky(HmacSigner):
        fail = True

        def sign(self, data):
            if self.fail:
                self.fail = False
                raise RuntimeError("hsm busy")
            return super().sign(data)

    sink = MemoryAuditSink()
    log = AuditLog("agent-1", sink, Flaky())
    with pytest.raises(RuntimeError):
        log.write("decision", DANA.act_claim(), "read_doc", {})
    log.write("decision", DANA.act_claim(), "read_doc", {})
    assert [r["seq"] for r in sink.records] == [1] and verify_chain(sink.records, verify).ok


def wrapped(sink):
    log = AuditLog("agent-1", sink, HmacSigner())
    ran = []

    async def tool(name, args):
        ran.append(name)
        return json.dumps({"status": "sent"})

    call = audited_execution(
        tool,
        log,
        DANA,
        facts=lambda t, a: {"tool": t},
        is_irreversible=lambda t: t == "send_email",
    )
    return log, call, ran


def test_execution_wrapper_writes_intent_before_the_tool_and_outcome_after():
    sink = MemoryAuditSink()
    log = AuditLog("agent-1", sink, HmacSigner())
    seen_before = []

    async def tool(name, args):
        seen_before.append([r["kind"] for r in sink.records])
        return "ok"

    call = audited_execution(
        tool, log, DANA, facts=lambda t, a: {"tool": t}, is_irreversible=lambda t: True
    )
    asyncio.run(call("send_email", {}))
    assert seen_before == [["intent"]]
    assert [r["kind"] for r in sink.records] == ["intent", "outcome"]


def test_irreversible_tool_is_refused_and_marked_not_run_when_the_sink_is_down():
    sink = MemoryAuditSink(available=False)
    log, call, ran = wrapped(sink)
    result = asyncio.run(call("send_email", {"to": "x"}))
    assert ran == [] and "audit trail is unavailable" in result
    sink.available = True
    assert log.flush()
    intent, outcome = sink.records
    assert outcome["ref"] == intent["hash"] and outcome["details"]["status"] == "not_run"


def test_reversible_tool_runs_with_records_buffered():
    sink = MemoryAuditSink(available=False)
    log, call, ran = wrapped(sink)
    asyncio.run(call("search_docs", {}))
    assert ran == ["search_docs"] and len(log.buffer) == 2


def test_decision_wrapper_records_what_the_inner_layers_decided():
    sink = MemoryAuditSink()
    log = AuditLog("agent-1", sink, HmacSigner())

    async def denied(name, args):
        return json.dumps({"error": "denied by policy", "stage": "policy"})

    call = audited_decisions(
        denied,
        log,
        DANA,
        facts=lambda t, a: {"tool": t},
        classify=lambda r: {"decision": "denied", "stage": json.loads(r)["stage"]},
        tainted=lambda: True,
    )
    asyncio.run(call("send_email", {}))
    (rec,) = sink.records
    assert rec["kind"] == "decision" and rec["details"] == {
        "tool": "send_email",
        "tainted": True,
        "decision": "denied",
        "stage": "policy",
    }
