# SPDX-License-Identifier: Apache-2.0
"""Model routing: which model may see this data, and what happens when a model is down.

    ModelPort      the protocol every model adapter satisfies (name, max_data_class, complete())
    DataClass      PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED: how sensitive a prompt is
    ModelGateway   sends a conversation to the first route cleared for its data class, falls back to the
                   next route only when a model is unavailable, and fails closed when none can take it
    ScriptedModel  a deterministic stand-in for tests: no network, same answers every run

A route is cleared for a prompt when its max_data_class is at least the prompt's class. A prompt above every
route is never sent anywhere (DataClassNotAllowed). The caller decides the data class from what it put in
the prompt, never from anything the model said.

No network code here: real backends live in agentic_core.adapters (for example adapters.ollama).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Protocol, runtime_checkable

ROLES = frozenset({"system", "user", "assistant"})


class DataClass(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class ModelUnavailable(Exception):
    """The model could not answer (down, timed out, bad response). The gateway may try another route."""


class DataClassNotAllowed(Exception):
    """No route is cleared for this data class, so the prompt was not sent."""


@dataclass(frozen=True)
class Message:
    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role!r}; expected one of {sorted(ROLES)}")


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    prompt_tokens: int = 0
    output_tokens: int = 0
    latency_s: float = 0.0
    skipped: tuple[str, ...] = ()  # routes tried first that were unavailable


@runtime_checkable
class ModelPort(Protocol):
    name: str
    max_data_class: DataClass

    def complete(self, messages: Sequence[Message]) -> Completion:
        """Return the model's reply, or raise ModelUnavailable. Never return a partial or guessed answer."""
        ...


class ModelGateway:
    """Route each conversation by data class, in the order the routes were given."""

    def __init__(self, routes: Iterable[ModelPort]) -> None:
        self.routes = list(routes)
        if not self.routes:
            raise ValueError("a gateway needs at least one route")

    def complete(self, messages: Sequence[Message], data_class: DataClass) -> Completion:
        if not messages:
            raise ValueError("empty conversation")
        cleared = [r for r in self.routes if r.max_data_class >= data_class]
        if not cleared:
            raise DataClassNotAllowed(
                f"no route is cleared for {data_class.name} data; the prompt was not sent"
            )
        skipped: list[str] = []
        for route in cleared:
            try:
                result = route.complete(messages)
            except ModelUnavailable:
                skipped.append(route.name)
                continue
            return replace(result, skipped=tuple(skipped))
        raise ModelUnavailable(f"every cleared route is unavailable: {', '.join(skipped)}")


@dataclass
class ScriptedModel:
    """Answers from a list (in order) or a function of the conversation. An empty or used-up list is a
    model that is down, so tests can exercise the fallback and fail-closed paths."""

    script: Sequence[str] | Callable[[list[Message]], str]
    name: str = "scripted"
    max_data_class: DataClass = DataClass.RESTRICTED
    calls: list[list[Message]] = field(default_factory=list)

    def complete(self, messages: Sequence[Message]) -> Completion:
        conversation = list(messages)
        if callable(self.script):
            self.calls.append(conversation)
            return Completion(self.script(conversation), self.name)
        if len(self.calls) >= len(self.script):
            raise ModelUnavailable(f"{self.name}: script exhausted")
        self.calls.append(conversation)
        return Completion(self.script[len(self.calls) - 1], self.name)
