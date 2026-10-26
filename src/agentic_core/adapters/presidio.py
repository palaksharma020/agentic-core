# SPDX-License-Identifier: Apache-2.0
"""PresidioRedactor: redact personal data from model output with Microsoft Presidio (duck-typed).

Pass an AnalyzerEngine and an AnonymizerEngine you configured (language model, custom recognizers such as an
organisation's salary or employee-id formats). agentic-core imports nothing from Presidio. Redaction replaces
each finding with <ENTITY_TYPE>. Any analyzer or anonymizer error raises RedactionUnavailable: callers must not
show the unredacted text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


class RedactionUnavailable(Exception):
    """Redaction could not run. Callers withhold the text rather than show it unredacted."""


@dataclass(frozen=True)
class Redaction:
    text: str
    findings: tuple[tuple[str, float], ...]  # (entity type, score); never the matched value


class PresidioRedactor:
    def __init__(
        self,
        analyzer: Any,
        anonymizer: Any,
        *,
        entities: Sequence[str],
        language: str = "en",
        score_threshold: float = 0.5,
    ) -> None:
        self.analyzer = analyzer
        self.anonymizer = anonymizer
        self.entities = list(entities)
        self.language = language
        self.threshold = score_threshold

    def redact(self, text: str) -> Redaction:
        try:
            results = self.analyzer.analyze(
                text=text,
                language=self.language,
                entities=self.entities,
                score_threshold=self.threshold,
            )
            redacted = self.anonymizer.anonymize(text=text, analyzer_results=results).text
        except (TypeError, AttributeError):
            raise
        except Exception as exc:
            raise RedactionUnavailable(f"presidio: {type(exc).__name__}") from exc
        findings = tuple(sorted((r.entity_type, round(float(r.score), 2)) for r in results))
        return Redaction(redacted, findings)
