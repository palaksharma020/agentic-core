# SPDX-License-Identifier: Apache-2.0
import hashlib

from agentic_core import Claim, DropReason, Evidence, validate_grounding

DOC = (
    "Model card. This model is deployed in production without any GPUs.\n"
    "Weights are stored as a pickle file (pytorch_model.bin). Known limitation: no jailbreak coverage."
)
SHOWN = {
    "card": "Weights are stored as a pickle file (pytorch_model.bin)."
}  # the excerpt actually in the prompt


def claim(quote, source="card", text="finding"):
    return Claim(text, [Evidence(source, quote)])


def test_grounded_claim_kept_with_chunk_hash():
    res = validate_grounding([claim("stored as a pickle file")], SHOWN)
    assert len(res.kept) == 1 and res.all_grounded
    ev = res.kept[0].evidence[0]
    assert (
        ev.chunk_index == 0
        and ev.chunk_sha256 == hashlib.sha256(SHOWN["card"].encode()).hexdigest()
    )


def test_match_ignores_case_whitespace_and_smart_quotes():
    shown = {"s": "It’s   stored\nas a “pickle” file"}
    assert validate_grounding([claim('it\'s stored as a "PICKLE" file', "s")], shown).kept


def test_fabricated_quote_dropped():
    res = validate_grounding(
        [claim("uses pickle weights and trust_remote_code")], SHOWN, sources={"card": DOC}
    )
    assert not res.kept and res.dropped[0].reason is DropReason.NOT_IN_SOURCE


def test_quote_outside_prompt_excerpt_is_dropped_as_recalled():
    # real text in the document, but not in what the model was shown
    res = validate_grounding(
        [claim("deployed in production without any GPUs")], SHOWN, sources={"card": DOC}
    )
    assert not res.kept and res.dropped[0].reason is DropReason.NOT_IN_PROMPT
    assert "recalled or invented" in res.dropped[0].detail


def test_without_sources_a_miss_is_reported_as_not_shown():
    res = validate_grounding([claim("deployed in production without any GPUs")], SHOWN)
    assert res.dropped[0].reason is DropReason.NOT_SHOWN


def test_unknown_source_dropped():
    res = validate_grounding([claim("stored as a pickle file", source="other")], SHOWN)
    assert res.dropped[0].reason is DropReason.UNKNOWN_SOURCE


def test_short_or_missing_quotes_are_not_evidence():
    res = validate_grounding([claim("pickle"), Claim("no evidence at all")], SHOWN)
    assert not res.kept and {d.reason for d in res.dropped} == {DropReason.NO_EVIDENCE}


def test_bad_quote_removed_but_claim_survives_on_good_one():
    c = Claim(
        "f",
        [
            Evidence("card", "stored as a pickle file"),
            Evidence("card", "an invented sentence here"),
        ],
    )
    res = validate_grounding([c], SHOWN, sources={"card": DOC})
    assert len(res.kept) == 1 and len(res.kept[0].evidence) == 1
    assert res.kept[0].rejected_evidence[0][1] is DropReason.NOT_IN_SOURCE


def test_require_all_evidence_drops_on_any_bad_quote():
    c = Claim(
        "f",
        [Evidence("card", "stored as a pickle file"), Evidence("card", "deployed in production")],
    )
    res = validate_grounding([c], SHOWN, sources={"card": DOC}, require_all_evidence=True)
    assert not res.kept and res.dropped[0].reason is DropReason.NOT_IN_PROMPT


def test_multiple_chunks_per_source_and_dict_claims():
    shown = {"card": ["first excerpt about licences", "second excerpt: no jailbreak coverage"]}
    res = validate_grounding(
        [{"text": "t", "evidence": [{"file": "card", "quote": "no jailbreak coverage"}]}], shown
    )
    assert res.kept[0].evidence[0].chunk_index == 1


def test_from_dict_tolerates_malformed_model_json():
    c = Claim.from_dict({"claim": 3, "evidence": ["junk", {"source": "s"}, None], "id": 7})
    assert c.text == "3" and c.id == "7" and c.evidence == [Evidence("s", "")]
    assert Claim.from_dict({"evidence": "not a list"}).evidence == []


def test_sources_never_make_a_claim_pass():
    res = validate_grounding(
        [claim("deployed in production without any GPUs")], {}, sources={"card": DOC}
    )
    assert not res.kept
