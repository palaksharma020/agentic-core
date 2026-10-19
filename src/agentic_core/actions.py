# SPDX-License-Identifier: Apache-2.0
"""Limited authority for model-proposed actions: the model proposes, code decides, the human confirms.

A model's reply may *propose* an action; it never executes one (OWASP LLM06 Excessive Agency):

1. parse_action_proposals() turns `[ACTION:NAME:p1:p2]` lines into proposals (the format is configurable)
2. authorize() checks a proposal against an ActionPolicy for a principal that comes from the server
   session, never from the conversation. Unknown actions and malformed params are denied (fail closed).
   An advisor flag can only tighten: it turns any decision into DENY.
3. GrantIssuer turns NEEDS_CONFIRMATION into a signed, expiring, single-use grant bound to the principal
   and the exact action. Only redeeming it (a human click in the UI) may execute; callers should
   re-authorize at redemption because state can change between proposal and click.

Dependency-free. Validators are app-specific callables: they return a rule id to deny, or None.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

DEFAULT_ACTION_PATTERN = re.compile(r"\[ACTION:(\w+):([^\]\n]+)\]")


@dataclass(frozen=True)
class ActionProposal:
    action: str
    params: tuple[str, ...]
    raw: str = ""  # the matched text, for stripping it from what the user sees


@dataclass(frozen=True)
class Principal:
    id: str  # from the authenticated session, never from the model or the chat history
    attributes: Mapping[str, Any] = field(default_factory=dict)


class AuthzDecision(str, Enum):
    ALLOW = "ALLOW"
    NEEDS_CONFIRMATION = "NEEDS_CONFIRMATION"
    DENY = "DENY"


Validator = Callable[[Mapping[str, str], Principal], "str | None"]


@dataclass(frozen=True)
class ActionRule:
    params: tuple[str, ...]  # parameter names, in order
    validators: Sequence[Validator] = ()
    requires_confirmation: bool = True


@dataclass(frozen=True)
class ActionPolicy:
    rules: Mapping[str, ActionRule]


@dataclass(frozen=True)
class AuthzResult:
    decision: AuthzDecision
    reasons: tuple[str, ...]  # rule ids, safe to log and show
    proposal: ActionProposal
    args: Mapping[str, str] = field(default_factory=dict)


def parse_action_proposals(
    text: str, pattern: re.Pattern[str] = DEFAULT_ACTION_PATTERN
) -> list[ActionProposal]:
    """Every action command in `text`, as proposals. Parsing grants nothing."""
    return [
        ActionProposal(
            m.group(1).upper(), tuple(p.strip() for p in m.group(2).split(":")), m.group(0)
        )
        for m in pattern.finditer(text)
    ]


def strip_action_commands(text: str, pattern: re.Pattern[str] = DEFAULT_ACTION_PATTERN) -> str:
    """The reply with action commands removed, so users see proposals only through the UI."""
    return re.sub(r"\n{3,}", "\n\n", pattern.sub("", text)).strip()


def authorize(
    proposal: ActionProposal,
    principal: Principal,
    policy: ActionPolicy,
    *,
    advisor_flagged: bool = False,
) -> AuthzResult:
    """Decide on one proposal. Returns every failing rule id, not just the first."""
    rule = policy.rules.get(proposal.action)
    if rule is None:
        return AuthzResult(AuthzDecision.DENY, ("unknown_action",), proposal)
    if len(proposal.params) != len(rule.params) or not all(proposal.params):
        return AuthzResult(AuthzDecision.DENY, ("bad_params",), proposal)
    args = dict(zip(rule.params, proposal.params, strict=True))
    reasons = [r for v in rule.validators if (r := v(args, principal))]
    if advisor_flagged:
        reasons.append("advisor_flagged")  # tighten-only: an advisor can deny, never allow
    if reasons:
        return AuthzResult(AuthzDecision.DENY, tuple(reasons), proposal, args)
    decision = (
        AuthzDecision.NEEDS_CONFIRMATION if rule.requires_confirmation else AuthzDecision.ALLOW
    )
    return AuthzResult(decision, (), proposal, args)


@dataclass(frozen=True)
class Grant:
    token: str
    grant_id: str
    expires_at: float


@dataclass(frozen=True)
class GrantCheck:
    valid: bool
    reason: (
        str  # "ok" or a rule id: bad_signature, expired, wrong_principal, already_used, malformed
    )
    proposal: ActionProposal | None = None
    grant_id: str | None = None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class GrantIssuer:
    """HMAC-SHA256 confirmation grants, bound to (principal, action, params), expiring, single-use.

    Used grant ids are kept in memory: one process, lost on restart. Production needs a shared store
    with a TTL (and the key in a KMS/HSM), see the module docs.
    """

    def __init__(
        self, key: bytes, ttl_seconds: float = 300, clock: Callable[[], float] = time.time
    ) -> None:
        if len(key) < 32:
            raise ValueError("grant key must be at least 32 bytes")
        self._key = key
        self._ttl = ttl_seconds
        self._clock = clock
        self._used: set[str] = set()

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()

    def issue(self, principal: Principal, proposal: ActionProposal) -> Grant:
        gid = secrets.token_hex(8)
        exp = self._clock() + self._ttl
        payload = json.dumps(
            {
                "gid": gid,
                "sub": principal.id,
                "act": proposal.action,
                "params": proposal.params,
                "exp": exp,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return Grant(f"{_b64(payload)}.{_b64(self._sign(payload))}", gid, exp)

    def redeem(self, token: str, principal: Principal) -> GrantCheck:
        """Verify and burn a grant. The action comes from the signed payload, never from the caller."""
        try:
            payload_b64, sig_b64 = token.split(".")
            payload = _unb64(payload_b64)
            sig = _unb64(sig_b64)
        except (ValueError, TypeError):
            return GrantCheck(False, "malformed")
        if not hmac.compare_digest(sig, self._sign(payload)):
            return GrantCheck(False, "bad_signature")
        data = json.loads(payload)
        proposal = ActionProposal(data["act"], tuple(data["params"]))
        if data["sub"] != principal.id:
            return GrantCheck(False, "wrong_principal", proposal, data["gid"])
        if self._clock() > data["exp"]:
            return GrantCheck(False, "expired", proposal, data["gid"])
        if data["gid"] in self._used:
            return GrantCheck(False, "already_used", proposal, data["gid"])
        self._used.add(data["gid"])
        return GrantCheck(True, "ok", proposal, data["gid"])
