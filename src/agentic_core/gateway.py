# SPDX-License-Identifier: Apache-2.0
"""Tool gateway: every tool call the model proposes is checked in code before it runs. Deny by default.

ToolGateway.check(ctx, tool, args) runs, in order:
    1. a delegation context is present           (no context, no call)
    2. the agent is active and the tool is in its manifest   (lifecycle registry, asked every call)
    3. the tool is registered                    (unknown tools are denied)
    4. the tool is pinned                        (optional ToolTrust: in a signed manifest, unchanged)
    5. the arguments match the tool's schema     (a small JSON-Schema subset, see validate_args)
    6. the policy engine allows it               (a PolicyEngine: OPA in production; any error is a deny)
`approved=True` tells the policy a human approved this exact payload (see approvals); only the server sets it,
after redeeming the approval, never the model.
The model never decides any of these. The gateway is the policy enforcement point (PEP); the policy engine
is the decision point (PDP), so policy can change without changing code.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from agentic_core.identity import DelegationContext
from agentic_core.lifecycle import RegistryPort, check_agent


@dataclass(frozen=True)
class GatewayDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()
    stage: str = ""  # context | lifecycle | registry | pinning | schema | policy | allowed


class PolicyUnavailable(Exception):
    """The policy engine could not decide. The gateway treats this as a deny."""


@runtime_checkable
class ToolTrust(Protocol):
    def check(self, tool: str) -> tuple[bool, str]:
        """(trusted, reason). manifests.PinnedTools implements it."""
        ...


@runtime_checkable
class PolicyEngine(Protocol):
    def decide(self, policy_input: Mapping[str, Any]) -> tuple[bool, list[str]]:
        """Return (allowed, reasons). Raise PolicyUnavailable when no decision can be made."""
        ...


_TYPES: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
}


def validate_args(schema: Mapping[str, Any], args: Mapping[str, Any]) -> list[str]:
    """Validate a flat argument object against a JSON-Schema subset: type object, properties with type,
    maxLength, pattern and enum, required, and additionalProperties false. Returns the problems found."""
    problems: list[str] = []
    props: Mapping[str, Any] = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in args:
            problems.append(f"missing required argument {name!r}")
    if schema.get("additionalProperties") is False:
        problems += [f"unexpected argument {n!r}" for n in args if n not in props]
    for name, value in args.items():
        spec = props.get(name)
        if spec is None:
            continue
        expected = _TYPES.get(spec.get("type", ""), object)
        if isinstance(value, bool) and expected is not bool and spec.get("type") != "boolean":
            problems.append(f"{name!r} must be {spec.get('type')}")
            continue
        if not isinstance(value, expected):
            problems.append(f"{name!r} must be {spec.get('type')}")
            continue
        if isinstance(value, str):
            if "maxLength" in spec and len(value) > spec["maxLength"]:
                problems.append(f"{name!r} is longer than {spec['maxLength']} characters")
            if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
                problems.append(f"{name!r} does not match the allowed format")
        if "enum" in spec and value not in spec["enum"]:
            problems.append(f"{name!r} is not an allowed value")
    return problems


@dataclass
class ToolGateway:
    schemas: Mapping[str, Mapping[str, Any]]
    policy: PolicyEngine
    registry: RegistryPort | None = None
    pins: ToolTrust | None = None
    decisions: list[GatewayDecision] = field(default_factory=list)

    def check(
        self,
        ctx: DelegationContext | None,
        tool: str,
        args: Mapping[str, Any],
        *,
        approved: bool = False,
    ) -> GatewayDecision:
        decision = self._check(ctx, tool, args, approved)
        self.decisions.append(decision)
        return decision

    def _check(
        self, ctx: DelegationContext | None, tool: str, args: Mapping[str, Any], approved: bool
    ) -> GatewayDecision:
        if ctx is None:
            return GatewayDecision(False, ("no delegation context",), "context")
        if self.registry is not None:
            agent = check_agent(self.registry, ctx.agent_id, tool)
            if not agent.ok:
                return GatewayDecision(False, (agent.reason,), "lifecycle")
        schema = self.schemas.get(tool)
        if schema is None:
            return GatewayDecision(False, (f"unknown tool {tool!r}",), "registry")
        if self.pins is not None:
            trusted, why = self.pins.check(tool)
            if trusted is not True:
                return GatewayDecision(False, (why or "tool is not trusted",), "pinning")
        if not isinstance(args, Mapping):
            return GatewayDecision(False, ("arguments must be an object",), "schema")
        problems = validate_args(schema, args)
        if problems:
            return GatewayDecision(False, tuple(problems), "schema")
        policy_input = {
            "user": ctx.user,
            "tenant": ctx.tenant,
            "agent": ctx.agent_id,
            "scopes": sorted(ctx.scopes),
            "tool": tool,
            "args": dict(args),
            "approved": approved is True,
        }
        try:
            allowed, reasons = self.policy.decide(policy_input)
        except PolicyUnavailable as exc:
            return GatewayDecision(False, (f"policy engine unavailable: {exc}",), "policy")
        if allowed is not True:  # anything but an explicit True is a deny
            return GatewayDecision(False, tuple(reasons) or ("denied by policy",), "policy")
        return GatewayDecision(True, (), "allowed")
