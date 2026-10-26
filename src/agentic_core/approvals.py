# SPDX-License-Identifier: Apache-2.0
"""Action gate: some actions can't be undone, so a human approves the exact action first.

Each tool call gets a reversibility tier. An IRREVERSIBLE action that reaches outside the user's tenant (an
email to an outside address) is not run: it becomes a PendingApproval with a dry-run preview. The approval is
bound to the SHA-256 of the exact payload (tool, arguments, user, tenant, agent), is single-use and expires
(10 minutes by default). The caller that executes an approved action must re-check the registry and policy
first (the capstone app does), so an agent revoked after approval still can't act. Show approvers the
arguments themselves, not a stored summary: the hash covers the arguments.

    ActionGate.evaluate(...)          -> ALLOW | PREVIEW_AND_APPROVE
    ApprovalStorePort.create(...)     -> a pending approval, with its preview and payload hash
    ApprovalStorePort.decide(...)     -> an approver approves or denies it (never the requester)
    ApprovalStorePort.redeem(...)     -> burns an approved, unexpired, matching approval exactly once
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from agentic_core.identity import DelegationContext


class Reversibility(str, Enum):
    REVERSIBLE = "reversible"
    COSTLY = "costly"
    IRREVERSIBLE = "irreversible"


class GateDecision(str, Enum):
    ALLOW = "allow"
    PREVIEW_AND_APPROVE = "preview_and_approve"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    USED = "used"


class ApprovalUnavailable(Exception):
    """The approval store can't be reached. The action stays pending; nothing is sent."""


class TooManyPending(ApprovalUnavailable):
    """The user already has the maximum number of approvals waiting (limits approval fatigue)."""


def payload_hash(ctx: DelegationContext, tool: str, args: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON of who, which tool and exactly which arguments."""
    canonical = json.dumps(
        {
            "user": ctx.user,
            "tenant": ctx.tenant,
            "agent": ctx.agent_id,
            "tool": tool,
            "args": dict(args),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class ToolAction:
    reversibility: Reversibility
    is_external: Callable[[DelegationContext, Mapping[str, Any]], bool] = lambda ctx, args: False


@dataclass(frozen=True)
class ActionGate:
    """Tiers per tool. Unknown tools are IRREVERSIBLE and external: the safest assumption."""

    actions: Mapping[str, ToolAction]

    def reversibility(self, tool: str) -> Reversibility:
        """The tool's tier; unknown tools are IRREVERSIBLE."""
        action = self.actions.get(tool)
        return action.reversibility if action else Reversibility.IRREVERSIBLE

    def evaluate(self, ctx: DelegationContext, tool: str, args: Mapping[str, Any]) -> GateDecision:
        action = self.actions.get(tool, ToolAction(Reversibility.IRREVERSIBLE, lambda c, a: True))
        if action.reversibility is Reversibility.IRREVERSIBLE and action.is_external(ctx, args):
            return GateDecision.PREVIEW_AND_APPROVE
        return GateDecision.ALLOW


@dataclass(frozen=True)
class PendingApproval:
    approval_id: str
    payload_hash: str
    tool: str
    args: Mapping[str, Any]
    user: str
    tenant: str
    agent_id: str
    preview: str
    created_at: float
    expires_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None


@dataclass(frozen=True)
class Redemption:
    ok: bool
    reason: str  # ok | unknown | not_approved | expired | already_used | payload_mismatch
    approval: PendingApproval | None = None


@runtime_checkable
class ApprovalStorePort(Protocol):
    def create(
        self, ctx: DelegationContext, tool: str, args: Mapping[str, Any], preview: str
    ) -> PendingApproval: ...

    def get(self, approval_id: str) -> PendingApproval | None: ...

    def list_pending(self, tenant: str) -> list[PendingApproval]: ...

    def decide(self, approval_id: str, approver: str, approve: bool) -> PendingApproval: ...

    def redeem(self, approval_id: str, expected_hash: str) -> Redemption: ...


def check_redemption(a: PendingApproval | None, expected_hash: str, now: float) -> Redemption:
    """Shared rules for every store: approved, unexpired, not used, and exactly the approved payload."""
    if a is None:
        return Redemption(False, "unknown")
    if a.status is ApprovalStatus.USED:
        return Redemption(False, "already_used", a)
    if a.status is not ApprovalStatus.APPROVED:
        return Redemption(False, "not_approved", a)
    if now > a.expires_at:
        return Redemption(False, "expired", a)
    if not secrets.compare_digest(a.payload_hash, expected_hash):
        return Redemption(False, "payload_mismatch", a)
    return Redemption(True, "ok", a)


def check_decision(a: PendingApproval | None, approver: str, now: float) -> PendingApproval:
    if a is None:
        raise KeyError("unknown approval")
    if a.status is not ApprovalStatus.PENDING:
        raise ValueError(f"approval is already {a.status.value}")
    if now > a.expires_at:
        raise ValueError("approval has expired")
    if approver == a.user:
        raise PermissionError("the requester can't approve their own action")
    return a


@dataclass
class MemoryApprovalStore:
    ttl_seconds: float = 600
    clock: Callable[[], float] = time.time
    max_pending_per_user: int = 5
    items: dict[str, PendingApproval] = field(default_factory=dict)

    def create(
        self, ctx: DelegationContext, tool: str, args: Mapping[str, Any], preview: str
    ) -> PendingApproval:
        now = self.clock()
        waiting = [
            a
            for a in self.items.values()
            if a.user == ctx.user and a.status is ApprovalStatus.PENDING and a.expires_at >= now
        ]
        if len(waiting) >= self.max_pending_per_user:
            raise TooManyPending(f"{ctx.user} already has {len(waiting)} approvals waiting")
        a = PendingApproval(
            approval_id=secrets.token_urlsafe(16),
            payload_hash=payload_hash(ctx, tool, args),
            tool=tool,
            args=dict(args),
            user=ctx.user,
            tenant=ctx.tenant,
            agent_id=ctx.agent_id,
            preview=preview,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        self.items[a.approval_id] = a
        return a

    def get(self, approval_id: str) -> PendingApproval | None:
        return self.items.get(approval_id)

    def list_pending(self, tenant: str) -> list[PendingApproval]:
        now = self.clock()
        return [
            a
            for a in self.items.values()
            if a.status is ApprovalStatus.PENDING and a.expires_at >= now and a.tenant == tenant
        ]

    def decide(self, approval_id: str, approver: str, approve: bool) -> PendingApproval:
        a = check_decision(self.items.get(approval_id), approver, self.clock())
        status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        self.items[approval_id] = replace(a, status=status, decided_by=approver)
        return self.items[approval_id]

    def redeem(self, approval_id: str, expected_hash: str) -> Redemption:
        r = check_redemption(self.items.get(approval_id), expected_hash, self.clock())
        if r.ok and r.approval:
            self.items[approval_id] = replace(r.approval, status=ApprovalStatus.USED)
        return r
