# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `gateway`: `ToolGateway` (context, lifecycle, registry, argument schema via `validate_args`, then a `PolicyEngine`;
  anything but an explicit allow is a deny) and `adapters.opa.OpaPolicyEngine` (no decision cache).
- `lifecycle`: `AgentManifest`, `AgentStatus` (created, active, suspended, revoked; revoked is final), `RegistryPort`,
  `check_agent()` asked on every call (unreachable or corrupt registry means deny), `MemoryRegistry`.
- `approvals`: `Reversibility`, `ActionGate`, exact-payload `payload_hash()`, `ApprovalStorePort` with single-use,
  expiring approvals, no self-approval and a per-user pending cap (`TooManyPending`); `MemoryApprovalStore`.
- `adapters.postgres`: `PostgresRegistry` (row-locked status changes with an event log) and `PostgresApprovalStore`
  (atomic conditional UPDATE for decide and redeem; only the UPDATE can report success; outcome recording).
- `identity`: `DelegationContext` (user, tenant, agent, scopes; built from the server session) with an RFC 8693-style
  `act_claim()`, and `attenuate()`, which only ever narrows scopes.
- `retrieval`: `RetrieverPort`, `tenant_role_descriptor()` (document-level security as a tenant query, field-level
  security as grant/except), `MemoryScopedRetriever` for tests, and `RetrievalUnavailable` (fail closed).
- `adapters.elastic.ElasticScopedRetriever`: mints a short-lived API key per request, limited to the user's tenant
  and visible fields, queries with it and invalidates it as owner. Any failure is `RetrievalUnavailable`; there is
  no fallback to a broader credential. Duck-typed, so agentic-core still has no dependencies.
- `OllamaModel(json_output=True)` asks Ollama to constrain replies to valid JSON, for agents that use a JSON
  tool protocol. It shapes the syntax only; callers still validate the content.
- `models`: `ModelPort` protocol, `DataClass` (`PUBLIC` < `INTERNAL` < `CONFIDENTIAL` < `RESTRICTED`),
  `ModelGateway` (routes by data class, falls back only on `ModelUnavailable`, raises `DataClassNotAllowed`
  without sending when no route is cleared) and `ScriptedModel` for deterministic offline tests.
- `adapters.ollama.OllamaModel`: standard-library adapter for a local Ollama server (temperature 0, fixed seed);
  malformed replies, HTTP errors and timeouts raise `ModelUnavailable`.
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
