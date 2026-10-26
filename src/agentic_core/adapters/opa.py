# SPDX-License-Identifier: Apache-2.0
"""OpaPolicyEngine: a PolicyEngine backed by Open Policy Agent's data API, standard library only.

POSTs {"input": ...} to {base_url}/v1/data/{path} and expects the document at that path to be
{"allow": bool, "deny": [reasons...]}. Anything else (connection refused, timeout, HTTP error, malformed or
undefined result) raises PolicyUnavailable, which the gateway treats as a deny. No decision is cached: a
cached allow could outlive a revocation.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from agentic_core.gateway import PolicyUnavailable


class OpaPolicyEngine:
    def __init__(
        self, path: str, *, base_url: str = "http://127.0.0.1:8181", timeout_s: float = 2.0
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"base_url must be an http(s) URL, got {base_url!r}")
        self.url = f"{base_url.rstrip('/')}/v1/data/{path.strip('/')}"
        self.timeout_s = timeout_s

    def decide(self, policy_input: Mapping[str, Any]) -> tuple[bool, list[str]]:
        body = json.dumps({"input": dict(policy_input)}).encode()
        req = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise PolicyUnavailable(f"{type(exc).__name__}") from exc
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
            raise PolicyUnavailable("policy result is undefined or malformed")
        deny = result.get("deny", [])
        reasons = [str(r) for r in deny] if isinstance(deny, list) else []
        return result["allow"], reasons
