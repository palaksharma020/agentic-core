# SPDX-License-Identifier: Apache-2.0
"""Delegation context: who the agent is acting for, on every call.

An agent never acts as itself. Each request carries a DelegationContext built by the server from the
authenticated session (never from the conversation): the user, their tenant, the agent, and the scopes the
agent may use for this user. Downstream checks read it: retrieval scopes its credential to it, and the tool
gateway (gateway.ToolGateway) denies any call that arrives without one. The context is only as trustworthy
as the session that built it. The act claim follows the shape of OAuth token exchange (RFC 8693): subject = user, actor = agent.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DelegationContext:
    user: str
    tenant: str
    agent_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    def __init__(self, user: str, tenant: str, agent_id: str, scopes: Iterable[str] = ()) -> None:
        for name, value in (("user", user), ("tenant", tenant), ("agent_id", agent_id)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"delegation context needs a non-empty {name}")
        object.__setattr__(self, "user", user)
        object.__setattr__(self, "tenant", tenant)
        object.__setattr__(self, "agent_id", agent_id)
        object.__setattr__(self, "scopes", frozenset(scopes))

    def act_claim(self) -> dict[str, object]:
        """The subject (user and tenant) with the agent as the actor, for logs and audit records."""
        return {"sub": self.user, "tenant": self.tenant, "act": {"sub": self.agent_id}}


def attenuate(ctx: DelegationContext, scopes: Iterable[str]) -> DelegationContext:
    """Narrow a context to the requested scopes. Scopes it doesn't already hold are dropped, never added."""
    return DelegationContext(ctx.user, ctx.tenant, ctx.agent_id, ctx.scopes & frozenset(scopes))
