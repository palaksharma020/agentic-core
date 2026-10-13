from agentic_core import (
    Claim,
    Evidence,
    SourceCheck,
    Verdict,
    decide,
    downgrade_only,
    validate_grounding,
)


def gate(allowed, origins=None, needed=1):
    return SourceCheck("q", allowed=allowed, origins=origins or {k: k for k in allowed}, origins_needed=needed)


def ground(quotes, shown):
    return validate_grounding([Claim("c", [Evidence(s, q)]) for s, q in quotes], shown)


def test_verified_when_grounded_and_corroborated():
    shown = {"a": "alpha source text", "b": "beta source text"}
    d = decide(ground([("a", "alpha source"), ("b", "beta source")], shown), gate(shown, needed=2))
    assert d.verdict is Verdict.VERIFIED and len(d.claims) == 2


def test_supported_when_corroboration_not_met():
    shown = {"a": "alpha source text", "b": "beta source text"}
    # two sources but the same origin: not independent
    d = decide(ground([("a", "alpha source"), ("b", "beta source")], shown),
               gate(shown, origins={"a": "wiki", "b": "wiki"}, needed=2))
    assert d.verdict is Verdict.SUPPORTED and any("corroboration" in r for r in d.reasons)


def test_refused_when_no_source_allowed_or_nothing_grounded():
    assert decide(ground([], {}), gate({})).verdict is Verdict.REFUSED
    shown = {"a": "alpha source text"}
    d = decide(ground([("a", "not in there at all")], shown), gate(shown))
    assert d.verdict is Verdict.REFUSED and not d.claims and any("claim removed" in r for r in d.reasons)


def test_dropped_claims_removed_from_answer():
    shown = {"a": "alpha source text"}
    d = decide(ground([("a", "alpha source"), ("a", "invented sentence")], shown), gate(shown))
    assert d.verdict is Verdict.VERIFIED and len(d.claims) == 1


def test_evidence_outside_gate_is_refused():
    shown = {"a": "alpha source text", "rejected": "poisoned page text"}
    d = decide(ground([("rejected", "poisoned page")], shown), gate({"a": shown["a"]}))
    assert d.verdict is Verdict.REFUSED and any("outside the gate" in r for r in d.reasons)


def test_flags_can_only_downgrade():
    shown = {"a": "alpha source text"}
    g = ground([("a", "alpha source")], shown)
    assert decide(g, gate(shown), flags=["conflicting"]).verdict is Verdict.CONFLICTING
    weak = decide(g, gate(shown, needed=2), flags=["verified", "nonsense"])
    assert weak.verdict is Verdict.SUPPORTED
    assert downgrade_only(Verdict.REFUSED, Verdict.VERIFIED) is Verdict.REFUSED
