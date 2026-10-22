# SPDX-License-Identifier: Apache-2.0
"""The Ollama adapter against a stub HTTP server on localhost: no Ollama needed, no network."""

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentic_core import DataClass, Message, ModelPort, ModelUnavailable
from agentic_core.adapters.ollama import OllamaModel

ASK = [Message("user", "hi")]


class Stub:
    """What the fake Ollama returns, and what it received."""

    def __init__(self) -> None:
        self.status = 200
        self.body: bytes = json.dumps(
            {
                "model": "llama3.2:3b",
                "message": {"role": "assistant", "content": "hello"},
                "prompt_eval_count": 7,
                "eval_count": 2,
            }
        ).encode()
        self.delay_s = 0.0
        self.requests: list[dict[str, object]] = []


@pytest.fixture
def stub() -> Iterator[tuple[Stub, str]]:
    state = Stub()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers["Content-Length"])
            state.requests.append({"path": self.path, "json": json.loads(self.rfile.read(length))})
            time.sleep(state.delay_s)
            self.send_response(state.status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(state.body)

        def log_message(self, *args: object) -> None:  # keep test output quiet
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_adapter_satisfies_the_port_and_is_local():
    model = OllamaModel("llama3.2:3b")
    assert isinstance(model, ModelPort)
    assert model.max_data_class is DataClass.RESTRICTED  # runs on this machine
    assert model.name == "ollama:llama3.2:3b"


def test_completion_and_deterministic_options(stub):
    state, url = stub
    result = OllamaModel("llama3.2:3b", base_url=url).complete(ASK)
    assert (result.text, result.prompt_tokens, result.output_tokens) == ("hello", 7, 2)
    sent = state.requests[0]
    assert sent["path"] == "/api/chat"
    body = sent["json"]
    assert isinstance(body, dict)
    assert body["stream"] is False
    assert body["options"]["temperature"] == 0 and body["options"]["seed"] == 42
    assert body["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (500, b'{"error": "boom"}'),
        (200, b"not json"),
        (200, b'{"message": {}}'),
        (200, b'{"message": "just a string"}'),
        (200, b'["a", "list"]'),
        (200, b'{"message": {"content": "hi"}, "eval_count": "many"}'),
    ],
)
def test_bad_responses_are_unavailable_not_answers(stub, status, body):
    state, url = stub
    state.status, state.body = status, body
    with pytest.raises(ModelUnavailable):
        OllamaModel("llama3.2:3b", base_url=url).complete(ASK)


def test_timeout_is_unavailable(stub):
    state, url = stub
    state.delay_s = 0.5
    with pytest.raises(ModelUnavailable):
        OllamaModel("llama3.2:3b", base_url=url, timeout_s=0.1).complete(ASK)


def test_nothing_listening_is_unavailable():
    with pytest.raises(ModelUnavailable):
        OllamaModel("llama3.2:3b", base_url="http://127.0.0.1:9", timeout_s=1).complete(ASK)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host", "127.0.0.1:11434"])
def test_only_http_urls_are_accepted(url):
    with pytest.raises(ValueError):
        OllamaModel("llama3.2:3b", base_url=url)


def test_json_output_requests_json_format(stub):
    state, url = stub
    OllamaModel("llama3.2:3b", base_url=url, json_output=True).complete(ASK)
    OllamaModel("llama3.2:3b", base_url=url).complete(ASK)
    with_json, without = (r["json"] for r in state.requests)
    assert isinstance(with_json, dict) and with_json["format"] == "json"
    assert isinstance(without, dict) and "format" not in without
