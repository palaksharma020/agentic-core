# SPDX-License-Identifier: Apache-2.0
"""Tamper-evident audit trail: who acted, on whose behalf, what was intended and what happened.

Each writer (one process) keeps its own hash chain, so writers never race for the head:
    record.hash = SHA-256(canonical JSON of the record without hash and signature)
    record.prev_hash = hash of the previous record in the same chain ("" for the first)
    record.signature = Ed25519 signature over record.hash, by the writer's key (key_id names it)
verify_chain() recomputes every hash, checks the links, the sequence numbers and every signature: an edited,
deleted, reordered, inserted or forged record breaks it. Deleting the *tail* of a chain is only detectable
against a head kept elsewhere (pass expected_head: the last seq and hash the writer published). The head
may lag the chain (it is published after the record), so records after it are fine; the chain must reach it
and agree with it.

The intent is written before the action. If the sink is down, records wait in a bounded buffer; an
irreversible action needs its intent durably written (not just buffered), otherwise it must not run.
Signing is a port: adapters.ed25519 provides Ed25519 with `cryptography`; the core has no dependencies.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Protocol, runtime_checkable

from agentic_core.identity import DelegationContext


class AuditUnavailable(Exception):
    """The record could not be written durably (and, for buffered writes, the buffer is full).
    `record` is the record left waiting in the buffer, if one was created."""

    def __init__(self, message: str, record: AuditRecord | None = None) -> None:
        super().__init__(message)
        self.record = record


@runtime_checkable
class Signer(Protocol):
    key_id: str

    def sign(self, data: bytes) -> str: ...


@runtime_checkable
class AuditSink(Protocol):
    def append(self, record: Mapping[str, Any]) -> None:
        """Store one record durably; raise on failure."""
        ...


@dataclass(frozen=True)
class AuditRecord:
    chain_id: str
    seq: int
    ts: float
    kind: str  # intent | outcome | decision | lifecycle
    actor: Mapping[str, Any]  # the act claim: user, tenant, agent (or an admin/approver)
    action: str  # tool or lifecycle verb
    details: Mapping[str, Any]  # small, non-secret facts: recipient domain, stage, reasons, result
    ref: str = ""  # for outcomes: the intent's hash
    prev_hash: str = ""
    hash: str = ""
    key_id: str = ""
    signature: str = ""

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("hash", "signature"):
            d.pop(k)
        return d


def canonical(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_hash(record: AuditRecord) -> str:
    return hashlib.sha256(canonical(record.body())).hexdigest()


@dataclass
class AuditLog:
    """One writer's chain. Not thread-safe: one AuditLog per writer thread or process."""

    chain_id: str
    sink: AuditSink
    signer: Signer
    clock: Callable[[], float] = time.time
    max_buffer: int = 100
    seq: int = 0
    head: str = ""
    buffer: list[AuditRecord] = field(default_factory=list)

    def _seal(
        self, kind: str, actor: Mapping[str, Any], action: str, details: Mapping[str, Any], ref: str
    ) -> AuditRecord:
        rec = AuditRecord(
            self.chain_id,
            self.seq + 1,
            self.clock(),
            kind,
            dict(actor),
            action,
            dict(details),
            ref,
            self.head,
            "",
            self.signer.key_id,
        )
        h = record_hash(rec)
        rec = replace(rec, hash=h, signature=self.signer.sign(h.encode()))
        self.seq, self.head = rec.seq, h  # only after signing: a signer error leaves no gap
        return rec

    def flush(self) -> bool:
        """Try to write buffered records in order. True when nothing is left waiting."""
        while self.buffer:
            try:
                self.sink.append(asdict(self.buffer[0]))
            except Exception:
                return False
            self.buffer.pop(0)
        return True

    def write(
        self,
        kind: str,
        actor: Mapping[str, Any],
        action: str,
        details: Mapping[str, Any],
        *,
        ref: str = "",
        durable: bool = False,
    ) -> AuditRecord:
        """Append a record. durable=True means it must reach the sink now (else AuditUnavailable)."""
        if len(self.buffer) >= self.max_buffer and not self.flush():
            raise AuditUnavailable("audit sink down and buffer full")
        rec = self._seal(kind, actor, action, details, ref)
        self.buffer.append(rec)
        if not self.flush() and durable:
            raise AuditUnavailable("audit sink down: the record is buffered, not durable", rec)
        return rec

    def intent(
        self, ctx: DelegationContext, action: str, details: Mapping[str, Any], *, durable: bool
    ) -> AuditRecord:
        return self.write("intent", ctx.act_claim(), action, details, durable=durable)

    def outcome(
        self, ctx: DelegationContext, intent: AuditRecord, details: Mapping[str, Any]
    ) -> AuditRecord:
        return self.write("outcome", ctx.act_claim(), intent.action, details, ref=intent.hash)


@dataclass(frozen=True)
class ChainCheck:
    ok: bool
    checked: int
    problem: str = ""  # first problem found
    at_seq: int | None = None


_TYPES: dict[str, type | tuple[type, ...]] = {
    "chain_id": str,
    "seq": int,
    "ts": (int, float),
    "kind": str,
    "actor": Mapping,
    "action": str,
    "details": Mapping,
    "ref": str,
    "prev_hash": str,
    "hash": str,
    "key_id": str,
    "signature": str,
}


def parse_record(data: Mapping[str, Any]) -> AuditRecord | None:
    """A stored record, or None if it is malformed (missing fields or wrong types)."""
    try:
        fields = {k: data[k] for k in _TYPES}
    except (KeyError, TypeError):
        return None
    for name, kind in _TYPES.items():
        if not isinstance(fields[name], kind) or (name == "seq" and isinstance(fields[name], bool)):
            return None
    return AuditRecord(**fields)


def verify_chain(
    records: Iterable[Mapping[str, Any]],
    verify_signature: Callable[[str, bytes, str], bool],
    *,
    expected_head: tuple[int, str] | None = None,
    key_allowed: Callable[[AuditRecord], bool] | None = None,
) -> ChainCheck:
    """Verify one chain (records of a single chain_id, any order). verify_signature(key_id, data, sig).

    key_allowed(record), when given, says whether that record's key may sign it at all (for example: the key
    belongs to the writer's role and was valid at the record's time). Malformed records fail the chain;
    they never raise."""
    parsed = [parse_record(r) for r in records]
    if any(r is None for r in parsed):
        return ChainCheck(False, 0, "malformed record (missing fields or wrong types)")
    recs: Sequence[AuditRecord] = sorted((r for r in parsed if r is not None), key=lambda r: r.seq)
    if not recs:
        return ChainCheck(expected_head is None, 0, "no records" if expected_head else "")
    prev = ""
    for i, r in enumerate(recs, start=1):
        if r.seq != i:
            return ChainCheck(False, i - 1, f"sequence gap: expected {i}, found {r.seq}", r.seq)
        if r.prev_hash != prev:
            return ChainCheck(False, i - 1, "broken link to the previous record", r.seq)
        if record_hash(r) != r.hash:
            return ChainCheck(
                False, i - 1, "record content does not match its hash (edited)", r.seq
            )
        if key_allowed is not None and not key_allowed(r):
            return ChainCheck(False, i - 1, "signed with a key not allowed for this chain", r.seq)
        if not verify_signature(r.key_id, r.hash.encode(), r.signature):
            return ChainCheck(False, i - 1, "bad signature", r.seq)
        prev = r.hash
    if expected_head is not None:
        head_seq, head_hash = expected_head
        if recs[-1].seq < head_seq:
            return ChainCheck(
                False,
                len(recs),
                "chain ends before the published head (records deleted)",
                recs[-1].seq,
            )
        if recs[head_seq - 1].hash != head_hash:
            return ChainCheck(
                False, len(recs), "record at the published head has a different hash", head_seq
            )
    return ChainCheck(True, len(recs))


ToolCall = Callable[[str, dict[str, Any]], Awaitable[str]]


def audited_execution(
    call_tool: ToolCall,
    log: AuditLog,
    ctx: DelegationContext,
    *,
    facts: Callable[[str, dict[str, Any]], Mapping[str, Any]],
    is_irreversible: Callable[[str], bool],
    failed: Callable[[str], bool] = lambda result: False,
    refusal: str = "not run: the audit trail is unavailable",
) -> ToolCall:
    """Wrap the call that really runs a tool: intent first, outcome after.

    An irreversible tool runs only if its intent reached the sink; otherwise the tool returns `refusal`
    and a "not_run" outcome follows the buffered intent, so the trail never shows an intent that looks
    like it ran. Reversible tools run with their records buffered when the sink is down."""

    async def call(tool: str, args: dict[str, Any]) -> str:
        details = facts(tool, args)
        try:
            intent = log.intent(ctx, tool, details, durable=is_irreversible(tool))
        except AuditUnavailable as exc:
            if exc.record is not None:  # the intent waits in the buffer: record that it never ran
                with contextlib.suppress(AuditUnavailable):
                    log.outcome(
                        ctx, exc.record, {"status": "not_run", "reason": "audit unavailable"}
                    )
            return refusal
        result = await call_tool(tool, args)
        with contextlib.suppress(
            AuditUnavailable
        ):  # the intent is on record; the outcome is buffered
            log.outcome(ctx, intent, {"status": "error" if failed(result) else "ok"})
        return result

    return call


def audited_decisions(
    call_tool: ToolCall,
    log: AuditLog,
    ctx: DelegationContext,
    *,
    facts: Callable[[str, dict[str, Any]], Mapping[str, Any]],
    classify: Callable[[str], Mapping[str, Any]],
    tainted: Callable[[], bool] = lambda: False,
) -> ToolCall:
    """Wrap the outermost tool caller: one decision record per proposed call, whatever was decided.
    classify(result) turns the result the agent got back into facts such as decision, stage, reasons."""

    async def call(tool: str, args: dict[str, Any]) -> str:
        result = await call_tool(tool, args)
        details = {**facts(tool, args), "tainted": tainted(), **classify(result)}
        # Buffered if the sink is down; irreversible execution itself is guarded by audited_execution.
        with contextlib.suppress(AuditUnavailable):
            log.write("decision", ctx.act_claim(), tool, details)
        return result

    return call


@dataclass
class MemoryAuditSink:
    records: list[dict[str, Any]] = field(default_factory=list)
    available: bool = True

    def append(self, record: Mapping[str, Any]) -> None:
        if not self.available:
            raise ConnectionError("audit sink down")
        self.records.append(dict(record))
