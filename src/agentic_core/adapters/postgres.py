# SPDX-License-Identifier: Apache-2.0
"""Postgres adapters for the agent registry and the approval store (psycopg 3 style, duck-typed).

Pass `connect`, a zero-argument callable returning a DB-API connection (for example
`lambda: psycopg.connect(dsn)`). agentic-core imports nothing from psycopg, so it keeps no dependencies.

Concurrency is handled by the database, not by Python:
- status changes lock the agent row (SELECT ... FOR UPDATE) and write an event in the same transaction;
- approval decisions and redemptions are single conditional UPDATE ... RETURNING statements, so two
  concurrent clicks can never both use one approval. Only the UPDATE can report success; a re-read only
  explains a failure.
- creating an approval checks the per-user pending cap in the same INSERT ... SELECT statement.
Use least-privilege roles (see the app's db setup): the agent may create approvals but never update them.
Any database error becomes RegistryUnavailable / ApprovalUnavailable (fail closed); programming errors surface.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from agentic_core.approvals import (
    ApprovalStatus,
    ApprovalUnavailable,
    PendingApproval,
    Redemption,
    TooManyPending,
    check_decision,
    check_redemption,
    payload_hash,
)
from agentic_core.identity import DelegationContext
from agentic_core.lifecycle import (
    AgentManifest,
    AgentRecord,
    AgentStatus,
    InvalidTransition,
    RegistryUnavailable,
    check_transition,
)

# Raised on purpose by the rules (or by bugs): these pass through; any other error is "unavailable".
_BUGS = (TypeError, AttributeError, KeyError, ValueError, PermissionError, InvalidTransition)

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id    text PRIMARY KEY,
    manifest    jsonb NOT NULL,
    status      text NOT NULL CHECK (status IN ('created', 'active', 'suspended', 'revoked')),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_events (
    id          bigserial PRIMARY KEY,
    agent_id    text NOT NULL REFERENCES agents(agent_id),
    from_status text,
    to_status   text NOT NULL,
    by_whom     text NOT NULL,
    reason      text NOT NULL,
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id  text PRIMARY KEY,
    payload_hash text NOT NULL,
    tool         text NOT NULL,
    args         jsonb NOT NULL,
    user_id      text NOT NULL,
    tenant       text NOT NULL,
    agent_id     text NOT NULL,
    preview      text NOT NULL,
    status       text NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'used')),
    decided_by   text,
    executed_at  timestamptz,
    outcome      text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS approvals_pending ON approvals (tenant) WHERE status = 'pending';
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS executed_at timestamptz;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS outcome text;
"""


class _Db:
    def __init__(self, connect: Callable[[], Any], unavailable: type[Exception]) -> None:
        self.connect = connect
        self.unavailable = unavailable

    @contextmanager
    def tx(self) -> Iterator[Any]:
        """One transaction: commit on success, roll back on any error, always close."""
        try:
            conn = self.connect()
        except _BUGS:
            raise
        except Exception as exc:
            raise self.unavailable(f"cannot connect: {type(exc).__name__}") from exc
        try:
            with conn.cursor() as cur:
                yield cur
            conn.commit()
        except _BUGS:
            conn.rollback()
            raise
        except self.unavailable:
            conn.rollback()
            raise
        except Exception as exc:
            conn.rollback()
            raise self.unavailable(f"database error: {type(exc).__name__}") from exc
        finally:
            conn.close()


def create_schema(connect: Callable[[], Any]) -> None:
    with _Db(connect, RegistryUnavailable).tx() as cur:
        cur.execute(SCHEMA)


class PostgresRegistry:
    def __init__(self, connect: Callable[[], Any]) -> None:
        self.db = _Db(connect, RegistryUnavailable)

    def register(self, manifest: AgentManifest, by: str) -> None:
        with self.db.tx() as cur:
            cur.execute(
                "INSERT INTO agents (agent_id, manifest, status) VALUES (%s, %s, 'created')",
                (manifest.agent_id, json.dumps(manifest.to_dict())),
            )
            cur.execute(
                "INSERT INTO agent_events (agent_id, from_status, to_status, by_whom, reason) "
                "VALUES (%s, NULL, 'created', %s, 'registered')",
                (manifest.agent_id, by),
            )

    def get(self, agent_id: str) -> AgentRecord | None:
        with self.db.tx() as cur:
            cur.execute("SELECT manifest, status FROM agents WHERE agent_id = %s", (agent_id,))
            row = cur.fetchone()
        if row is None:
            return None
        manifest = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        return AgentRecord(AgentManifest.from_dict(manifest), AgentStatus(row[1]))

    def set_status(self, agent_id: str, status: AgentStatus, by: str, reason: str) -> None:
        with self.db.tx() as cur:
            cur.execute("SELECT status FROM agents WHERE agent_id = %s FOR UPDATE", (agent_id,))
            row = cur.fetchone()
            if row is None:
                raise KeyError(agent_id)
            current = AgentStatus(row[0])
            check_transition(current, status)
            cur.execute(
                "UPDATE agents SET status = %s, updated_at = now() WHERE agent_id = %s",
                (status.value, agent_id),
            )
            cur.execute(
                "INSERT INTO agent_events (agent_id, from_status, to_status, by_whom, reason) "
                "VALUES (%s, %s, %s, %s, %s)",
                (agent_id, current.value, status.value, by, reason),
            )


_COLUMNS = (
    "approval_id, payload_hash, tool, args, user_id, tenant, agent_id, preview, "
    "created_at, expires_at, status, decided_by"
)


def _row_to_approval(row: tuple[Any, ...]) -> PendingApproval:
    args = row[3] if isinstance(row[3], dict) else json.loads(row[3])
    return PendingApproval(
        approval_id=row[0],
        payload_hash=row[1],
        tool=row[2],
        args=args,
        user=row[4],
        tenant=row[5],
        agent_id=row[6],
        preview=row[7],
        created_at=row[8].timestamp(),
        expires_at=row[9].timestamp(),
        status=ApprovalStatus(row[10]),
        decided_by=row[11],
    )


class PostgresApprovalStore:
    def __init__(
        self, connect: Callable[[], Any], ttl_seconds: float = 600, max_pending_per_user: int = 5
    ) -> None:
        self.db = _Db(connect, ApprovalUnavailable)
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_pending = max_pending_per_user

    def create(
        self, ctx: DelegationContext, tool: str, args: Mapping[str, Any], preview: str
    ) -> PendingApproval:
        now = datetime.now(timezone.utc)
        with self.db.tx() as cur:
            # Insert only while the user is under the cap (approval-fatigue flooding, ASI09).
            cur.execute(
                f"INSERT INTO approvals ({_COLUMNS}) "
                "SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', NULL "
                "WHERE (SELECT count(*) FROM approvals WHERE user_id = %s AND status = 'pending' "
                "AND expires_at > now()) < %s "
                f"RETURNING {_COLUMNS}",
                (
                    secrets.token_urlsafe(16),
                    payload_hash(ctx, tool, args),
                    tool,
                    json.dumps(dict(args)),
                    ctx.user,
                    ctx.tenant,
                    ctx.agent_id,
                    preview,
                    now,
                    now + self.ttl,
                    ctx.user,
                    self.max_pending,
                ),
            )
            row = cur.fetchone()
        if row is None:
            raise TooManyPending(f"{ctx.user} already has {self.max_pending} approvals waiting")
        return _row_to_approval(row)

    def get(self, approval_id: str) -> PendingApproval | None:
        with self.db.tx() as cur:
            cur.execute(f"SELECT {_COLUMNS} FROM approvals WHERE approval_id = %s", (approval_id,))
            row = cur.fetchone()
        return _row_to_approval(row) if row else None

    def list_pending(self, tenant: str) -> list[PendingApproval]:
        with self.db.tx() as cur:
            cur.execute(
                f"SELECT {_COLUMNS} FROM approvals WHERE status = 'pending' AND expires_at > now() "
                "AND tenant = %s ORDER BY created_at",
                (tenant,),
            )
            rows = cur.fetchall()
        return [_row_to_approval(r) for r in rows]

    def decide(self, approval_id: str, approver: str, approve: bool) -> PendingApproval:
        check_decision(self.get(approval_id), approver, datetime.now(timezone.utc).timestamp())
        status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        with self.db.tx() as cur:
            cur.execute(
                "UPDATE approvals SET status = %s, decided_by = %s WHERE approval_id = %s "
                f"AND status = 'pending' AND expires_at > now() AND user_id <> %s RETURNING {_COLUMNS}",
                (status.value, approver, approval_id, approver),
            )
            row = cur.fetchone()
        if row is None:
            raise ValueError("approval is no longer pending")  # lost a race with another decision
        return _row_to_approval(row)

    def record_outcome(self, approval_id: str, outcome: str) -> None:
        """What happened when the approved action ran (sent, or why not). Written once."""
        with self.db.tx() as cur:
            cur.execute(
                "UPDATE approvals SET outcome = %s, executed_at = now() "
                "WHERE approval_id = %s AND status = 'used' AND outcome IS NULL",
                (outcome[:500], approval_id),
            )

    def redeem(self, approval_id: str, expected_hash: str) -> Redemption:
        with self.db.tx() as cur:
            cur.execute(
                "UPDATE approvals SET status = 'used' WHERE approval_id = %s AND status = 'approved' "
                f"AND expires_at > now() AND payload_hash = %s RETURNING {_COLUMNS}",
                (approval_id, expected_hash),
            )
            row = cur.fetchone()
        if row is not None:
            return Redemption(True, "ok", _row_to_approval(row))
        # Not redeemed. The re-read only explains why; it can never turn a failure into success
        # (the row may have changed since the UPDATE, or the app clock may disagree with the database).
        why = check_redemption(
            self.get(approval_id), expected_hash, datetime.now(timezone.utc).timestamp()
        )
        return why if not why.ok else Redemption(False, "not_approved_or_expired", why.approval)
