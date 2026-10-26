# SPDX-License-Identifier: Apache-2.0
"""LlamaGuard: a GuardrailPort for Meta's Llama Guard 3 served by Ollama (standard library only).

Llama Guard classifies a user message (role="user") or an assistant reply in context (role="assistant") as
`safe` or `unsafe` plus hazard categories (S1-S14). It is a content-safety classifier: it does not detect
prompt injection. Anything other than a well-formed verdict raises GuardUnavailable (callers block).
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections.abc import Sequence
from urllib.parse import urlparse

from agentic_core.guards import GuardUnavailable, GuardVerdict
from agentic_core.models import Message

# Llama Guard 3 hazard taxonomy (MLCommons).
CATEGORIES = {
    "S1": "violent crimes",
    "S2": "non-violent crimes",
    "S3": "sex-related crimes",
    "S4": "child sexual exploitation",
    "S5": "defamation",
    "S6": "specialized advice",
    "S7": "privacy",
    "S8": "intellectual property",
    "S9": "indiscriminate weapons",
    "S10": "hate",
    "S11": "suicide and self-harm",
    "S12": "sexual content",
    "S13": "elections",
    "S14": "code interpreter abuse",
}


class LlamaGuard:
    def __init__(
        self,
        model: str = "llama-guard3:1b",
        *,
        base_url: str = "http://127.0.0.1:11434",
        timeout_s: float = 15.0,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"base_url must be an http(s) URL, got {base_url!r}")
        self.model = model
        self.name = f"llama-guard:{model}"
        self.url = f"{base_url.rstrip('/')}/api/chat"
        self.timeout_s = timeout_s
        self.last_latency_s = 0.0

    def check(self, text: str, *, role: str, context: Sequence[Message] = ()) -> GuardVerdict:
        if role not in {"user", "assistant"}:
            raise ValueError("role must be 'user' or 'assistant'")
        convo = [
            {"role": m.role, "content": m.content}
            for m in context
            if m.role in {"user", "assistant"}
        ]
        if role == "assistant" and not any(m["role"] == "user" for m in convo):
            convo.insert(0, {"role": "user", "content": "(request)"})
        convo.append({"role": role, "content": text})
        body = json.dumps(
            {"model": self.model, "stream": False, "messages": convo, "options": {"temperature": 0}}
        ).encode()
        req = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read())
        except Exception as exc:  # network, HTTP protocol, JSON: any failure means "no verdict"
            raise GuardUnavailable(f"{self.name}: {type(exc).__name__}") from exc
        self.last_latency_s = time.perf_counter() - start
        message = data.get("message") if isinstance(data, dict) else None
        reply = message.get("content") if isinstance(message, dict) else None
        if not isinstance(reply, str):
            raise GuardUnavailable(f"{self.name}: no verdict in reply")
        lines = [ln.strip() for ln in reply.strip().splitlines() if ln.strip()]
        if lines and lines[0].lower() == "safe":
            return GuardVerdict(True, self.name)
        if lines and lines[0].lower() == "unsafe":
            codes = tuple(c.strip() for c in lines[1].split(",")) if len(lines) > 1 else ()
            names = tuple(f"{c} {CATEGORIES.get(c, 'unknown')}" for c in codes)
            return GuardVerdict(
                False, self.name, names, "unsafe: " + (", ".join(names) or "unspecified")
            )
        raise GuardUnavailable(f"{self.name}: unparseable verdict")
