# agentic-core

Deterministic checks that sit around a language model, so an agent's inputs, outputs and actions can be verified
in code instead of trusted.

The model can propose; code decides. Every module here follows the same rules:

- **No dependencies; the core makes no LLM calls.** Plain Python dataclasses and functions. The only code that talks
  to a model is an adapter under `agentic_core.adapters`, imported explicitly and standard-library only.
- **Deterministic.** The same input always gets the same decision, so every control is unit-testable.
- **Fail closed.** Unknown, malformed or unparseable input is denied or refused, never let through.
- **Models only tighten.** Where a model or classifier contributes, it can lower a verdict or deny an action. It
  can never raise a verdict or allow something the code refused.
- **Honest about limits.** Each capability lists what it does not prove (see below).

## Install

```bash
pip install "agentic-core @ git+https://github.com/palaksharma020/agentic-core@v0.2.0"
```

Python 3.10 or later. For development: `pip install -e ".[dev]"`.

## Capabilities

### Retrieval and grounding: can this answer be trusted?

| Module | What it decides | Main API | Since |
|---|---|---|---|
| `sources` | Before the model runs: is each retrieved chunk registered, from a trust tier allowed for this question, unchanged since ingest (SHA-256) and fresh? Untrusted text is spotlighted. | `check_sources()`, `render_untrusted()` | 0.1.0 |
| `grounding` | After the model runs: does each claim quote text the model was actually shown? Dropped claims say why: invented, or real text that wasn't in the prompt. | `validate_grounding()` | 0.1.0 |
| `verdict` | Combines the two into `VERIFIED`, `SUPPORTED`, `CONFLICTING` or `REFUSED`. A model may downgrade the label, never upgrade it. | `decide()`, `downgrade_only()` | 0.1.0 |
| `severity` | Limited authority for model-proposed severities: tighten-only, with a floor, one level per step and a ceiling above which a human decides. | `tighten_severity()`, `cap_new_severity()` | 0.1.0 |

### Output safety: what may leave the server?

| Module | What it decides | Main API | Since |
|---|---|---|---|
| `leakage` | Does a reply contain a random canary from the prompt, a protected value in any common disguise (case, separators, leetspeak, reversed, base64, acrostic), or a verbatim dump of the prompt? Findings name the rule, never the secret. | `scan_for_leaks()`, `make_canary()`, `ProtectedValue` | 0.2.0 |
| `text` | Strip HTML tags, markdown images and links, and bare URLs from model text before it is rendered (angle brackets in prose survive). Parse JSON from model output, or raise so the caller fails closed. | `sanitize_llm_text()`, `parse_json_object()`, `normalize()` | 0.1.0 |

### Actions and authority: may this happen?

| Module | What it decides | Main API | Since |
|---|---|---|---|
| `actions` | Is a model-proposed action allowed for this principal? Parsing grants nothing; your validators decide; unknown actions and malformed parameters are denied. Allowed actions get an HMAC-signed grant bound to the principal and the exact action, expiring and single-use, so only a confirmation the user makes can execute them. | `parse_action_proposals()`, `authorize()`, `ActionPolicy`, `GrantIssuer` | 0.2.0 |
| `advisor` | How probabilistic classifiers (prompt-injection detectors, LLM judges) plug in: a protocol plus `tighten_only()`, so advice can deny but never allow. Backends live outside this package. | `InjectionAdvisor`, `tighten_only()`, `NullAdvisor` | 0.2.0 |

## Examples

### Validate a RAG answer

```python
from agentic_core import check_sources, decide, render_untrusted, validate_grounding

# 1. Which retrieved sources may answer this question?
gate = check_sources(retrieved, records, policy, "finance_limits")
# 2. Only allowed chunks reach the model, marked as untrusted.
raw = model(prompt_with(render_untrusted(gate.allowed)))
# 3. Every quote must appear in what the model was shown.
grounding = validate_grounding(claims_from(raw), gate.allowed)
# 4. VERIFIED / SUPPORTED / CONFLICTING / REFUSED
decision = decide(grounding, gate)
```

[`examples/rag_answer.py`](examples/rag_answer.py) runs this end to end, offline: a trusted source (an HR balance)
and an untrusted one (a wiki page edited to state a false wire-transfer rule).

### Guard a chatbot reply and the action it proposes

```python
from agentic_core import (
    ActionPolicy,
    ActionRule,
    AuthzDecision,
    GrantIssuer,
    Principal,
    ProtectedValue,
    authorize,
    make_canary,
    parse_action_proposals,
    sanitize_llm_text,
    scan_for_leaks,
    strip_action_commands,
)

# Put f"Internal reference: {CANARY}" at the end of the system prompt.
CANARY = make_canary()
# Secrets live in server config, never in the prompt.
PROMO = ProtectedValue("promo_code", "PEAK40")


# A validator returns a rule id to deny, or None.
def owns_order(args, principal):
    return None if ORDERS.get(args["order_id"]) == principal.id else "not_owner"


POLICY = ActionPolicy({"REFUND": ActionRule(("order_id", "amount"), (owns_order,))})
grants = GrantIssuer(key=SERVER_KEY)  # 32+ bytes, from your secret store

# The principal comes from your authenticated session, never from the chat.
user = Principal(session.user_id)
leak = scan_for_leaks(reply, protected=[PROMO], canaries=[CANARY], reference_prompt=system_prompt)
if leak.leaked:
    reply = "Sorry, I can't share that."  # and drop any actions in this reply
else:
    # "[ACTION:REFUND:A1001:299]" in the reply becomes a proposal; parsing grants nothing.
    for proposal in parse_action_proposals(reply):
        result = authorize(proposal, user, POLICY)
        if result.decision is AuthzDecision.NEEDS_CONFIRMATION:
            # Execute only after grants.redeem() succeeds in the confirm handler.
            show_confirm_button(grants.issue(user, proposal).token)
        else:
            show_denied(result.reasons)  # e.g. ("not_owner",)
    # Then render it as text (textContent), never as HTML.
    reply = sanitize_llm_text(strip_action_commands(reply))
```

The confirm handler calls `grants.redeem(token, user)`. It returns `valid=False` with a reason
(`wrong_principal`, `expired`, `already_used`, `bad_signature`) unless it is the same user's unused, unexpired grant.
Re-run `authorize()` on `check.proposal` before executing, because state can change between proposal and click.

### Identity and retrieval: whose data may the agent see?

| Module | What it decides | Main API | Since |
|---|---|---|---|
| `identity` | Who the agent acts for. A `DelegationContext` from the server session (never the conversation) travels with every call; scopes can only be narrowed. | `DelegationContext`, `attenuate()` | unreleased |
| `retrieval` | Retrieve as the user: the store itself enforces the user's tenant and hidden fields, so no filtering after retrieval. Failure is `RetrievalUnavailable`, never a broader credential. | `RetrieverPort`, `tenant_role_descriptor()`, `MemoryScopedRetriever` | unreleased |
| `adapters.elastic` | A per-request Elasticsearch API key with document- and field-level security, invalidated after use. | `ElasticScopedRetriever` | unreleased |

### Tools and actions: may the agent do this, now?

| Module | What it decides | Main API | Since |
|---|---|---|---|
| `gateway` | Every tool call the model proposes, in code: delegation context, agent lifecycle, registered tool, argument schema, then a policy engine. Anything but an explicit allow is a deny, including the policy engine being down. | `ToolGateway`, `validate_args()`, `PolicyEngine` | unreleased |
| `adapters.opa` | Open Policy Agent as the policy decision point (data API, standard library only, no decision cache). | `OpaPolicyEngine` | unreleased |
| `lifecycle` | Is this agent active, and is the tool in its manifest? Asked on every call, so a revoke takes effect on the next one. Revoked is final. | `AgentManifest`, `check_agent()`, `RegistryPort` | unreleased |
| `approvals` | Irreversible actions to outside parties wait for a human approval bound to the SHA-256 of the exact payload: single-use, expiring, no self-approval, capped per user. | `ActionGate`, `payload_hash()`, `ApprovalStorePort` | unreleased |
| `adapters.postgres` | Registry and approval store in Postgres; single use enforced by one atomic UPDATE. | `PostgresRegistry`, `PostgresApprovalStore` | unreleased |

### Models: which model may see this data?

| Module | What it decides | Main API | Since |
|---|---|---|---|
| `models` | Which model a conversation may go to. Each route declares the most sensitive data it may receive (`PUBLIC` < `INTERNAL` < `CONFIDENTIAL` < `RESTRICTED`); the gateway uses the first cleared route, falls back only when a model is unavailable, and never sends data above every route. `ScriptedModel` gives deterministic, offline answers for tests. | `ModelGateway`, `ModelPort`, `DataClass`, `ScriptedModel` | unreleased |
| `adapters.ollama` | A `ModelPort` for a local Ollama server, standard library only. Temperature 0 and a fixed seed; any malformed reply, HTTP error or timeout is `ModelUnavailable`, never a partial answer. | `OllamaModel` | unreleased |

## What these checks do not prove

**Retrieval and grounding**
- A grounded quote shows a claim is faithful to text the model was given, not that the claim follows from it.
  Use entailment checks or human review for high-impact claims.
- The source gate trusts your ingest records (tier, hash, date). Protect them, for example by signing them, as
  carefully as the content.
- Spotlighting reduces indirect prompt injection; it does not prevent it. That is why the other checks don't
  depend on the model obeying instructions.

**Output safety**
- The leak scan catches the disguises it knows. The real fix is keeping secrets out of anything the model can see;
  the scan catches mistakes. Prompt overlap misses translations; the canary catches those, unless the model drops
  the canary line, which the overlap check then catches.
- `sanitize_llm_text()` is defense in depth, not an XSS fix. Render model output as text, and add a
  Content-Security-Policy.

**Actions and authority**
- `authorize()` is only as good as the principal you pass. Take it from your authenticated session, never from
  model output, tool arguments the model controls, or chat history.
- Used grant ids are kept in memory: one process, lost on restart. Across processes, use a shared store with a TTL.
- A confirmation is only as strong as the page that shows it: script injected into that page can redeem grants
  too. Fix XSS, and use step-up confirmation (passkey or out-of-band) for high-value actions.
- An advisor's recall on a test set overstates its value against real attacks: successful attacks tend to look
  benign, such as an innocent-looking message that relies on forged conversation history.

**Identity and retrieval**
- A delegation context is only as trustworthy as the session that built it. Authenticate the user first.
- Document- and field-level security needs an Elasticsearch licence that includes it (Platinum, Enterprise or the
  trial). Without one, minting fails and retrieval fails closed: plan for that, don't work around it.
- The minter is a standing credential. Limit it to reading the index and managing its own keys.

**Tools and actions**
- The gateway trusts the context and the registry it is given. Build the context from an authenticated session,
  and give the agent's process a database role that can create approvals but never update them.
- An approval binds the arguments, not their meaning: show approvers the arguments themselves (the capstone
  page escapes hidden characters and flags outside domains), and keep tool schemas strict.
- Whoever executes an approved action must re-check the registry and policy first.

**Models**
- The gateway trusts the data class you pass. Derive it from what your code put in the prompt (the most
  sensitive retrieved document), never from the model or the user.
- A fixed seed and temperature 0 make answers repeatable on the same machine and model version, not across
  hardware or model updates. Security decisions must not depend on the exact wording of an answer.
- Fallback is for availability only. A model that answers badly is not "unavailable"; validate answers with the
  grounding and verdict checks.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy src && pytest -q
python examples/rag_answer.py              # offline example
python bench/bench_grounding.py            # grounding cost per claim
```

Changes are listed in [CHANGELOG.md](CHANGELOG.md). To add a capability, follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
