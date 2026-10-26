# SPDX-License-Identifier: Apache-2.0
"""Agent lifecycle: an agent is a managed identity that can be suspended or revoked at once.

    created -> active <-> suspended
         \\        \\          \\
          `-------`----------`--> revoked   (final)

An AgentManifest declares what an agent may do (tools, scopes, owner). A RegistryPort stores manifests and
status. check_agent() is asked on every tool call, never cached, so a revoke takes effect on the very next
call. If the registry can't be reached the agent is treated as suspended: nothing runs (fail closed).
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class AgentStatus(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


ALLOWED_TRANSITIONS: Mapping[AgentStatus, frozenset[AgentStatus]] = {
    AgentStatus.CREATED: frozenset({AgentStatus.ACTIVE, AgentStatus.REVOKED}),
    AgentStatus.ACTIVE: frozenset({AgentStatus.SUSPENDED, AgentStatus.REVOKED}),
    AgentStatus.SUSPENDED: frozenset({AgentStatus.ACTIVE, AgentStatus.REVOKED}),
    AgentStatus.REVOKED: frozenset(),
}


class RegistryUnavailable(Exception):
    """The registry could not be read or written. Callers treat the agent as suspended."""


class InvalidTransition(Exception):
    """A status change the lifecycle doesn't allow (for example, reactivating a revoked agent)."""


@dataclass(frozen=True)
class AgentManifest:
    agent_id: str
    name: str
    owner: str
    tools: frozenset[str]
    scopes: frozenset[str]
    description: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentManifest:
        """Build from a parsed manifest (YAML or JSON). Unknown keys are refused, missing ones too."""
        required = {"agent_id", "name", "owner", "tools", "scopes"}
        allowed = required | {"description"}
        missing, extra = required - set(data), set(data) - allowed
        if missing or extra:
            raise ValueError(f"manifest: missing {sorted(missing)}, unexpected {sorted(extra)}")
        if not all(
            isinstance(data[k], str) and data[k].strip() for k in ("agent_id", "name", "owner")
        ):
            raise ValueError("manifest: agent_id, name and owner must be non-empty strings")
        return cls(
            agent_id=data["agent_id"],
            name=data["name"],
            owner=data["owner"],
            tools=frozenset(data["tools"]),
            scopes=frozenset(data["scopes"]),
            description=str(data.get("description", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "owner": self.owner,
            "tools": sorted(self.tools),
            "scopes": sorted(self.scopes),
            "description": self.description,
        }


@dataclass(frozen=True)
class AgentRecord:
    manifest: AgentManifest
    status: AgentStatus


@runtime_checkable
class RegistryPort(Protocol):
    def register(self, manifest: AgentManifest, by: str) -> None: ...

    def get(self, agent_id: str) -> AgentRecord | None: ...

    def set_status(self, agent_id: str, status: AgentStatus, by: str, reason: str) -> None: ...


@dataclass(frozen=True)
class AgentCheck:
    ok: bool
    reason: str


def check_agent(registry: RegistryPort, agent_id: str, tool: str) -> AgentCheck:
    """May this agent call this tool right now? Asked on every call; never cached."""
    try:
        record = registry.get(agent_id)
    except RegistryUnavailable:
        return AgentCheck(False, "agent registry unreachable: treated as suspended")
    except ValueError:  # a stored manifest or status that no longer parses
        return AgentCheck(False, f"agent {agent_id!r} has an invalid registry record")
    if record is None:
        return AgentCheck(False, f"agent {agent_id!r} is not registered")
    if record.status is not AgentStatus.ACTIVE:
        return AgentCheck(False, f"agent {agent_id!r} is {record.status.value}")
    if tool not in record.manifest.tools:
        return AgentCheck(False, f"tool {tool!r} is not in agent {agent_id!r}'s manifest")
    return AgentCheck(True, "active")


def check_transition(current: AgentStatus, new: AgentStatus) -> None:
    if new not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransition(f"{current.value} -> {new.value} is not allowed")


@dataclass
class MemoryRegistry:
    """In-memory RegistryPort for tests. `available=False` simulates an unreachable registry."""

    records: dict[str, AgentRecord] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    available: bool = True

    def _up(self) -> None:
        if not self.available:
            raise RegistryUnavailable("registry down")

    def register(self, manifest: AgentManifest, by: str) -> None:
        self._up()
        if manifest.agent_id in self.records:
            raise ValueError(f"agent {manifest.agent_id!r} is already registered")
        self.records[manifest.agent_id] = AgentRecord(manifest, AgentStatus.CREATED)
        self._event(manifest.agent_id, None, AgentStatus.CREATED, by, "registered")

    def get(self, agent_id: str) -> AgentRecord | None:
        self._up()
        return self.records.get(agent_id)

    def set_status(self, agent_id: str, status: AgentStatus, by: str, reason: str) -> None:
        self._up()
        record = self.records.get(agent_id)
        if record is None:
            raise KeyError(agent_id)
        check_transition(record.status, status)
        self.records[agent_id] = AgentRecord(record.manifest, status)
        self._event(agent_id, record.status, status, by, reason)

    def _event(
        self, agent_id: str, old: AgentStatus | None, new: AgentStatus, by: str, reason: str
    ) -> None:
        self.events.append(
            {
                "agent_id": agent_id,
                "from": old.value if old else None,
                "to": new.value,
                "by": by,
                "reason": reason,
                "at": time.time(),
            }
        )


def manifest_scopes_cap(manifest: AgentManifest, requested: Iterable[str]) -> frozenset[str]:
    """The scopes an agent may use for a user: never more than its manifest declares."""
    return manifest.scopes & frozenset(requested)
