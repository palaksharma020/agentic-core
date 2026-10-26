# SPDX-License-Identifier: Apache-2.0
"""PostgresApprovalStore against a fake DB-API connection: the paths a live database rarely shows."""

from datetime import datetime, timedelta, timezone

import pytest

from agentic_core import ApprovalUnavailable, DelegationContext, TooManyPending, payload_hash
from agentic_core.adapters.postgres import PostgresApprovalStore

DANA = DelegationContext("dana", "acme", "knowledge-assistant", {"mail:send"})
EMAIL = {"to": "x@external-review.example", "subject": "s", "body": "b"}
NOW = datetime.now(timezone.utc)
HASH = payload_hash(DANA, "send_email", EMAIL)


def row(status, expires=None):
    expires = expires or NOW + timedelta(minutes=5)
    return (
        "id1",
        HASH,
        "send_email",
        EMAIL,
        "dana",
        "acme",
        "knowledge-assistant",
        "p",
        NOW,
        expires,
        status,
        "lee",
    )


class Cursor:
    def __init__(self, script):
        self.script, self.result = list(script), None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        self.result = step

    def fetchone(self):
        return self.result


class Conn:
    def __init__(self, cursor):
        self.cur = cursor

    def cursor(self):
        return self.cur

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def store(*steps):
    cur = Cursor(steps)
    return PostgresApprovalStore(lambda: Conn(cur))


def test_redeem_success_comes_only_from_the_atomic_update():
    assert store(row("used")).redeem("id1", HASH).ok


def test_reread_showing_approved_never_becomes_success():
    # Review finding H1: the UPDATE matched nothing, but by the re-read an approver had committed.
    r = store(None, row("approved")).redeem("id1", HASH)
    assert not r.ok and r.reason == "not_approved_or_expired"


def test_reread_explains_failures():
    assert store(None, row("used")).redeem("id1", HASH).reason == "already_used"


def test_pending_cap_is_enforced_by_the_insert():
    with pytest.raises(TooManyPending):
        store(None).create(DANA, "send_email", EMAIL, "p")  # INSERT ... WHERE count < cap: no row


def test_database_errors_fail_closed():
    class OperationalError(Exception):
        pass

    with pytest.raises(ApprovalUnavailable):
        store(OperationalError("connection reset")).redeem("id1", HASH)
