## What and why

## Checklist ids touched

## How to verify

```bash
ruff check . && ruff format --check . && mypy src && pytest -q
```

## Eval delta

<!-- For security controls: attack success / false positives before → after, number of trials, added latency. Otherwise "n/a". -->

## Failure behaviour added or changed

## If this adds a capability (see CONTRIBUTING.md)

- [ ] Module docstring says what it decides and what it does not
- [ ] Exported in `__init__.py`; tests cover decisions, fail-closed input and a no-over-blocking case
- [ ] README: one row under **Capabilities** (with **Since**), one bullet under **What these checks do not prove**
- [ ] CHANGELOG: entry under `[Unreleased]`
