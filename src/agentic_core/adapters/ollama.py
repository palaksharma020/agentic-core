# SPDX-License-Identifier: Apache-2.0
"""OllamaModel: a ModelPort for a local Ollama server, using only the standard library.

The model runs on this machine, so it is cleared for every data class (RESTRICTED) by default; pass a lower
max_data_class if the server is remote. Requests use temperature 0 and a fixed seed so the same prompt gives
the same answer on the same machine. Anything other than a well-formed reply (connection refused, timeout,
HTTP error, malformed JSON, missing text) raises ModelUnavailable: never a partial or guessed answer.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from urllib.parse import urlparse

from agentic_core.models import Completion, DataClass, Message, ModelUnavailable


class OllamaModel:
    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://127.0.0.1:11434",
        timeout_s: float = 60.0,
        max_data_class: DataClass = DataClass.RESTRICTED,
        seed: int = 42,
        max_output_tokens: int | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"base_url must be an http(s) URL, got {base_url!r}")
        self.model = model
        self.name = f"ollama:{model}"
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_data_class = max_data_class
        self.options: dict[str, int | float] = {"temperature": 0, "seed": seed}
        if max_output_tokens is not None:
            self.options["num_predict"] = max_output_tokens

    def complete(self, messages: Sequence[Message]) -> Completion:
        body = json.dumps(
            {
                "model": self.model,
                "stream": False,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "options": self.options,
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/api/chat", data=body, headers={"Content-Type": "application/json"}
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                data = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            # URLError covers HTTP errors and refused connections; ValueError covers malformed JSON.
            raise ModelUnavailable(f"{self.name}: {type(exc).__name__}: {exc}") from exc
        latency = time.perf_counter() - start
        message = data.get("message") if isinstance(data, dict) else None
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str):
            raise ModelUnavailable(f"{self.name}: reply has no message text")
        prompt_tokens, output_tokens = data.get("prompt_eval_count", 0), data.get("eval_count", 0)
        if not isinstance(prompt_tokens, int) or not isinstance(output_tokens, int):
            raise ModelUnavailable(f"{self.name}: reply has malformed token counts")
        return Completion(
            text=text,
            model=self.name,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            latency_s=latency,
        )
