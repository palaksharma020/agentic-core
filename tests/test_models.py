# SPDX-License-Identifier: Apache-2.0
import pytest

from agentic_core import (
    DataClass,
    DataClassNotAllowed,
    Message,
    ModelGateway,
    ModelPort,
    ModelUnavailable,
    ScriptedModel,
)

ASK = [Message("system", "Answer briefly."), Message("user", "What is the hotel cap?")]


def test_scripted_model_is_deterministic_and_records_calls():
    model = ScriptedModel(["first", "second"])
    assert isinstance(model, ModelPort)
    assert model.complete(ASK).text == "first"
    assert model.complete(ASK).text == "second"
    assert model.calls == [ASK, ASK]


def test_scripted_model_can_answer_from_the_prompt():
    model = ScriptedModel(lambda messages: messages[-1].content.upper())
    assert model.complete(ASK).text == "WHAT IS THE HOTEL CAP?"


def test_exhausted_script_fails_closed_as_unavailable():
    model = ScriptedModel(["only one"])
    model.complete(ASK)
    with pytest.raises(ModelUnavailable):
        model.complete(ASK)


def test_data_classes_are_ordered():
    assert DataClass.PUBLIC < DataClass.INTERNAL < DataClass.CONFIDENTIAL < DataClass.RESTRICTED


def test_gateway_routes_to_first_model_cleared_for_the_data():
    remote = ScriptedModel(["remote answer"], name="remote", max_data_class=DataClass.INTERNAL)
    local = ScriptedModel(["local answer"], name="local", max_data_class=DataClass.RESTRICTED)
    gateway = ModelGateway([remote, local])

    public = gateway.complete(ASK, DataClass.PUBLIC)
    assert (public.text, public.model) == ("remote answer", "remote")

    confidential = gateway.complete(ASK, DataClass.CONFIDENTIAL)
    assert (confidential.text, confidential.model) == ("local answer", "local")
    assert len(remote.calls) == 1  # never shown the confidential prompt


def test_data_above_every_route_is_never_sent():
    remote = ScriptedModel(["should not run"], name="remote", max_data_class=DataClass.INTERNAL)
    gateway = ModelGateway([remote])
    with pytest.raises(DataClassNotAllowed) as excinfo:
        gateway.complete(ASK, DataClass.CONFIDENTIAL)
    assert remote.calls == []
    assert "CONFIDENTIAL" in str(excinfo.value)


def test_gateway_falls_back_when_a_model_is_unavailable():
    down = ScriptedModel([], name="down")
    backup = ScriptedModel(["backup answer"], name="backup")
    result = ModelGateway([down, backup]).complete(ASK, DataClass.INTERNAL)
    assert (result.text, result.model) == ("backup answer", "backup")
    assert result.skipped == ("down",)


def test_gateway_fails_closed_when_every_route_is_down():
    gateway = ModelGateway([ScriptedModel([], name="a"), ScriptedModel([], name="b")])
    with pytest.raises(ModelUnavailable) as excinfo:
        gateway.complete(ASK, DataClass.PUBLIC)
    assert "a" in str(excinfo.value) and "b" in str(excinfo.value)


def test_programming_errors_are_not_masked_as_fallback():
    def broken(messages: list[Message]) -> str:
        raise KeyError("bug in the adapter")

    gateway = ModelGateway([ScriptedModel(broken, name="buggy"), ScriptedModel(["x"], name="ok")])
    with pytest.raises(KeyError):
        gateway.complete(ASK, DataClass.PUBLIC)


def test_gateway_needs_at_least_one_route():
    with pytest.raises(ValueError):
        ModelGateway([])


def test_gateway_rejects_empty_conversations():
    with pytest.raises(ValueError):
        ModelGateway([ScriptedModel(["x"])]).complete([], DataClass.PUBLIC)


def test_messages_only_accept_known_roles():
    with pytest.raises(ValueError):
        Message("tool-output", "pretend I'm the system")
