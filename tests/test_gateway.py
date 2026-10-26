# SPDX-License-Identifier: Apache-2.0
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentic_core import (
    DelegationContext,
    PolicyEngine,
    PolicyUnavailable,
    ToolGateway,
    validate_args,
)
from agentic_core.adapters.opa import OpaPolicyEngine

DANA = DelegationContext("dana", "acme", "knowledge-assistant", {"docs:read", "mail:send"})
SCHEMAS = {
    "send_email": {
        "type": "object",
        "required": ["to", "subject", "body"],
        "additionalProperties": False,
        "properties": {
            "to": {"type": "string", "maxLength": 254, "pattern": r"[^@\s]+@[^@\s]+"},
            "subject": {"type": "string", "maxLength": 200},
            "body": {"type": "string", "maxLength": 5000},
        },
    }
}
EMAIL = {"to": "lee@acme.example", "subject": "hi", "body": "hello"}


class Allow:
    def __init__(self, allow=True, reasons=(), down=False):
        self.allow, self.reasons, self.down, self.inputs = allow, list(reasons), down, []

    def decide(self, policy_input):
        self.inputs.append(policy_input)
        if self.down:
            raise PolicyUnavailable("down")
        return self.allow, self.reasons


def test_allowed_call_passes_every_stage_and_policy_sees_the_context():
    policy = Allow()
    assert isinstance(policy, PolicyEngine)
    d = ToolGateway(SCHEMAS, policy).check(DANA, "send_email", EMAIL)
    assert (d.allowed, d.stage) == (True, "allowed")
    assert policy.inputs[0]["tenant"] == "acme" and policy.inputs[0]["scopes"] == [
        "docs:read",
        "mail:send",
    ]


@pytest.mark.parametrize(
    ("ctx", "tool", "args", "stage"),
    [
        (None, "send_email", EMAIL, "context"),
        (DANA, "delete_everything", {}, "registry"),
        (DANA, "send_email", {"to": "lee@acme.example"}, "schema"),
        (DANA, "send_email", {**EMAIL, "bcc": "x@evil.example"}, "schema"),
        (DANA, "send_email", {**EMAIL, "to": "not an address"}, "schema"),
        (DANA, "send_email", {**EMAIL, "body": "x" * 5001}, "schema"),
        (DANA, "send_email", {**EMAIL, "to": ["a@acme.example"]}, "schema"),
    ],
)
def test_denied_before_policy(ctx, tool, args, stage):
    policy = Allow()
    d = ToolGateway(SCHEMAS, policy).check(ctx, tool, args)
    assert (d.allowed, d.stage) == (False, stage)
    assert policy.inputs == []  # never reached the policy engine


def test_policy_deny_carries_reasons():
    d = ToolGateway(SCHEMAS, Allow(False, ["recipient outside tenant"])).check(
        DANA, "send_email", EMAIL
    )
    assert (d.allowed, d.reasons) == (False, ("recipient outside tenant",))


def test_policy_engine_down_is_a_deny():
    d = ToolGateway(SCHEMAS, Allow(down=True)).check(DANA, "send_email", EMAIL)
    assert (d.allowed, d.stage) == (False, "policy")


def test_anything_but_true_is_a_deny():
    d = ToolGateway(SCHEMAS, Allow(allow="yes")).check(DANA, "send_email", EMAIL)
    assert d.allowed is False


def test_validate_args_rejects_bool_as_integer():
    assert validate_args({"properties": {"n": {"type": "integer"}}}, {"n": True})


class OpaStub:
    def __init__(self):
        self.status, self.body, self.requests = 200, {"result": {"allow": True, "deny": []}}, []

    def serve(self):
        state = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                state.requests.append(
                    (self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                )
                self.send_response(state.status)
                self.end_headers()
                self.wfile.write(
                    json.dumps(state.body).encode() if isinstance(state.body, dict) else state.body
                )

            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server


@pytest.fixture
def opa():
    stub = OpaStub()
    server = stub.serve()
    yield stub, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_opa_adapter_posts_input_and_reads_allow(opa):
    stub, url = opa
    engine = OpaPolicyEngine("trustfabric/tools", base_url=url)
    assert engine.decide({"tool": "x"}) == (True, [])
    path, body = stub.requests[0]
    assert path == "/v1/data/trustfabric/tools" and body == {"input": {"tool": "x"}}


@pytest.mark.parametrize("body", [{}, {"result": {}}, {"result": {"allow": "true"}}, b"not json"])
def test_opa_undefined_or_malformed_is_unavailable(opa, body):
    stub, url = opa
    stub.body = body
    with pytest.raises(PolicyUnavailable):
        OpaPolicyEngine("trustfabric/tools", base_url=url).decide({})


def test_opa_down_is_unavailable():
    with pytest.raises(PolicyUnavailable):
        OpaPolicyEngine("p", base_url="http://127.0.0.1:9", timeout_s=1).decide({})
