# SPDX-License-Identifier: Apache-2.0
import pytest

from agentic_core import cap_new_severity, tighten_severity


def test_floor_wins_over_lower_current():
    d = tighten_severity("low", "low", floor="medium")
    assert d.value == "medium" and not d.applied


def test_tighten_only_cannot_lower_or_keep():
    d = tighten_severity("medium", "low")
    assert d.value == "medium" and not d.applied and "tighten-only" in d.reason


def test_raise_limited_to_one_level_and_ceiling():
    d = tighten_severity("info", "high")  # info -> low only; high needs a human
    assert d.value == "low" and d.applied and d.needs_human


def test_raise_at_ceiling_needs_human():
    d = tighten_severity("medium", "high")
    assert d.value == "medium" and not d.applied and d.needs_human


def test_allowed_single_step():
    d = tighten_severity("low", "medium")
    assert d.value == "medium" and d.applied and not d.needs_human


def test_unknown_proposal_ignored_and_bad_config_raises():
    assert tighten_severity("low", "catastrophic").value == "low"
    assert tighten_severity("low", " MEDIUM ").value == "medium"
    with pytest.raises(ValueError):
        tighten_severity("severe", "high")


def test_custom_scale_and_limits():
    d = tighten_severity("p3", "p0", scale=("p3", "p2", "p1", "p0"), ceiling="p0", max_step=2)
    assert d.value == "p1" and d.needs_human


def test_new_model_finding_capped_at_medium():
    d = cap_new_severity("high")
    assert d.value == "medium" and d.needs_human
    assert cap_new_severity("low").value == "low"
    assert cap_new_severity("???").value == "info"
