# Contributing

## Design rules every module follows

1. **No LLM calls and no runtime dependencies.** Backends that need a model or a library (classifiers, judges)
   live outside this package and plug in through a protocol, as `advisor` does.
2. **Deterministic.** Same input, same decision. If a check can't be unit-tested without a model, it doesn't
   belong here.
3. **Fail closed.** Unknown or malformed input is denied, refused or raises. Never "trust whatever came back".
4. **Models only tighten.** Model or classifier input may lower a verdict or deny an action, never the reverse.
5. **Explain decisions.** Return rule ids or reasons that are safe to log and show. Never put secrets, tokens or
   user content in them.

## Adding a capability

A capability is a new module, or a new public function that answers a new question. One pull request per
capability. The pull request template repeats this checklist.

**Code**
- [ ] New module in `src/agentic_core/` with the SPDX header and a module docstring that states what it decides
      and what it does not.
- [ ] Public names exported in `src/agentic_core/__init__.py` (`__all__` kept sorted).
- [ ] Tests in `tests/test_<module>.py`: the decisions it should make, the input it must refuse (fail closed),
      and at least one case showing it does not over-block benign input.
- [ ] `ruff check .`, `ruff format --check .`, `mypy src` and `pytest -q` pass.

**README** (it stays an index; depth goes in docstrings and examples)
- [ ] One row in the right table under **Capabilities**: module, what it decides (one or two sentences), main
      API, and **Since** = the next release version. Add a new group only for a genuinely new question.
- [ ] One bullet in the matching group under **What these checks do not prove**. Every capability has limits;
      write the one a user is most likely to get wrong.
- [ ] A new example under **Examples** only if this opens a new problem area. Otherwise add or extend a file in
      `examples/` and leave the README examples alone.

**Changelog**
- [ ] An entry under `## [Unreleased]` in `CHANGELOG.md` (Added, Changed, Fixed or Removed).

**Measurements** (when the capability is a security control)
- [ ] The pull request body reports the effect against a baseline: attack success rate or false-positive rate
      before and after, with the number of trials, and the added latency.

## Releasing

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new version heading with the date, and update the
   compare links at the bottom.
2. Bump `version` in `pyproject.toml` and `__version__` in `src/agentic_core/__init__.py`.
3. Update the version in the README's install command.
4. Merge, then tag the merge commit on `main`: verify with `git show <tag>:pyproject.toml` that the tagged commit
   carries the new version before pushing the tag. Published tags are never moved.
