# SPDX-License-Identifier: Apache-2.0
from decimal import Decimal

import pytest

from agentic_core import (
    ActionPolicy,
    ActionProposal,
    ActionRule,
    AuthzDecision,
    GrantIssuer,
    Principal,
    authorize,
    parse_action_proposals,
    strip_action_commands,
)

ORDERS = {"A1001": ("alice", Decimal(299)), "B2001": ("bob", Decimal(899))}
ALICE = Principal("alice")
BOB = Principal("bob")


def owns_order(args, principal):
    order = ORDERS.get(args["order_id"])
    if order is None:
        return "unknown_order"
    return None if order[0] == principal.id else "not_owner"


def amount_within_price(args, principal):
    order = ORDERS.get(args["order_id"])
    try:
        amount = Decimal(args["amount"].lstrip("$"))
    except ArithmeticError:
        return "bad_amount"
    if amount <= 0:
        return "bad_amount"
    return "amount_exceeds_price" if order and amount > order[1] else None


POLICY = ActionPolicy(
    {"REFUND": ActionRule(("order_id", "amount"), (owns_order, amount_within_price))}
)


def refund(order, amount):
    return ActionProposal("REFUND", (order, amount))


def test_parse_and_strip():
    text = "Sure!\n[ACTION:REFUND:A1001:$299.00]\nAnything else?"
    (p,) = parse_action_proposals(text)
    assert p == ActionProposal("REFUND", ("A1001", "$299.00"), "[ACTION:REFUND:A1001:$299.00]")
    assert strip_action_commands(text) == "Sure!\n\nAnything else?"


def test_own_order_needs_confirmation():
    result = authorize(refund("A1001", "299"), ALICE, POLICY)
    assert result.decision is AuthzDecision.NEEDS_CONFIRMATION
    assert result.args == {"order_id": "A1001", "amount": "299"}


@pytest.mark.parametrize(
    ("proposal", "reasons"),
    [
        (refund("B2001", "899"), ("not_owner",)),  # price matches: only ownership stops it
        (refund("Z9999", "5000"), ("unknown_order",)),
        (refund("A1001", "2999"), ("amount_exceeds_price",)),
        (refund("A1001", "-500"), ("bad_amount",)),
        (refund("A1001", "lots"), ("bad_amount",)),
        (ActionProposal("REFUND", ("A1001",)), ("bad_params",)),
        (ActionProposal("WIRE", ("x", "y")), ("unknown_action",)),
    ],
)
def test_bad_proposals_are_denied_with_every_reason(proposal, reasons):
    result = authorize(proposal, ALICE, POLICY)
    assert result.decision is AuthzDecision.DENY
    assert set(reasons) <= set(result.reasons)


def test_advisor_can_only_tighten():
    result = authorize(refund("A1001", "299"), ALICE, POLICY, advisor_flagged=True)
    assert result.decision is AuthzDecision.DENY and result.reasons == ("advisor_flagged",)


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def issuer():
    clock = Clock()
    issuer = GrantIssuer(b"k" * 32, ttl_seconds=60, clock=clock)
    issuer.clock = clock
    return issuer


def test_grant_round_trip_is_single_use(issuer):
    grant = issuer.issue(ALICE, refund("A1001", "299"))
    first = issuer.redeem(grant.token, ALICE)
    assert first.valid and first.proposal == ActionProposal("REFUND", ("A1001", "299"))
    assert issuer.redeem(grant.token, ALICE).reason == "already_used"


def test_grant_is_bound_to_the_principal(issuer):
    grant = issuer.issue(ALICE, refund("A1001", "299"))
    assert issuer.redeem(grant.token, BOB).reason == "wrong_principal"


def test_grant_expires(issuer):
    grant = issuer.issue(ALICE, refund("A1001", "299"))
    issuer.clock.now += 61
    assert issuer.redeem(grant.token, ALICE).reason == "expired"


def test_tampered_params_break_the_signature(issuer):
    grant = issuer.issue(ALICE, refund("A1001", "29"))
    payload, sig = grant.token.split(".")
    forged = payload.replace(payload[10:14], "AAAA") + "." + sig
    assert issuer.redeem(forged, ALICE).reason in {"bad_signature", "malformed"}
    other = GrantIssuer(b"x" * 32).issue(ALICE, refund("A1001", "299"))
    assert issuer.redeem(other.token, ALICE).reason == "bad_signature"


@pytest.mark.parametrize("token", ["", "abc", "a.b.c", "!!!.???"])
def test_malformed_tokens_fail_closed(issuer, token):
    assert not issuer.redeem(token, ALICE).valid


def test_short_key_is_refused():
    with pytest.raises(ValueError):
        GrantIssuer(b"short")
