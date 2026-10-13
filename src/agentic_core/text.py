# SPDX-License-Identifier: Apache-2.0
"""Text helpers for handling model output safely.

- normalize(): the comparison form used for grounding (quotes, whitespace, case)
- sanitize_llm_text(): strip links, images, bare URLs and HTML from model-written text before it is rendered
- parse_json_object(): extract one JSON object from model output, or raise so the caller can fail closed
"""

from __future__ import annotations

import json
import re
from typing import Any

_QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"'})  # noqa: RUF001 (the table itself)
_SPACE = re.compile(r"\s+")

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_URL = re.compile(r"\b(?:https?|ftp)://\S+|\bwww\.\S+", re.IGNORECASE)
_HTML = re.compile(r"<[^>]{1,200}>")
_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def normalize(text: str) -> str:
    """Smart quotes to straight quotes, any whitespace run to one space, casefolded.

    Two texts that differ only in line wrapping, typographic quotes or case compare equal.
    """
    return _SPACE.sub(" ", text.translate(_QUOTES)).strip().casefold()


def sanitize_llm_text(text: str) -> str:
    """Remove markdown images and links (keeping link text), bare URLs and HTML tags.

    Model-written text can carry a markdown image or link whose URL smuggles data out when the
    answer is rendered (OWASP LLM05 Improper Output Handling). Apply this before rendering.
    """
    text = _MD_IMAGE.sub("[image removed]", text)
    text = _MD_LINK.sub(r"\1", text)
    text = _URL.sub("[url removed]", text)
    return _HTML.sub("", text).strip()


def parse_json_object(text: str) -> dict[str, Any]:
    """Return the JSON object in `text` (whole text, or the outermost {...} span).

    Raises ValueError (json.JSONDecodeError is a subclass) when there is no object. Callers should
    catch it and fail closed: keep the deterministic baseline, never "trust whatever came back".
    """
    try:
        data = json.loads(text)
    except ValueError:
        m = _JSON_OBJECT.search(text)
        if not m:
            raise ValueError("no JSON object in model output") from None
        data = json.loads(m.group(0))
    if not isinstance(data, dict):
        raise ValueError("model output is not a JSON object")
    return data
