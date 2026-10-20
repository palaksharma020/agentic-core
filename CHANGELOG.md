# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `CHANGELOG.md`, `CONTRIBUTING.md` (how to add a capability) and a pull request template.
- CI on every pull request and push to `main`: `ruff check`, `ruff format --check`, `mypy src` and `pytest` on Python 3.10 and 3.12.

### Changed
- README reorganized as an index: design rules, capabilities grouped by the question they answer (with the version
  each arrived in), two examples, and limits grouped the same way.

## [0.2.0] - 2026-10-19

### Added
- `leakage`: `scan_for_leaks()` checks model replies for a random canary (`make_canary()`), protected values in
  disguised forms (case, separators, leetspeak, reversed, base64, acrostic) and verbatim prompt overlap. Findings
  name the rule, never the secret.
- `actions`: `parse_action_proposals()`, `authorize()` with app-supplied validators (fails closed on unknown
  actions and malformed parameters), and `GrantIssuer`: HMAC-SHA256 confirmation grants bound to the principal
  and the exact action, expiring and single-use.
- `advisor`: `InjectionAdvisor` protocol, `NullAdvisor` and `tighten_only()` for probabilistic classifiers.

### Fixed
- `sanitize_llm_text()` no longer deletes prose between `<` and `>` (for example "I <3 it, rated 5 > 4!"). Only
  real tags (`<` followed by a letter, `/` or `!`) and HTML comments are removed.

## [0.1.0]

### Added
- `sources`, `grounding`, `verdict`, `severity` and `text`: a validation harness for RAG and tool-using agents.

[Unreleased]: https://github.com/palaksharma020/agentic-core/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/palaksharma020/agentic-core/releases/tag/v0.2.0
