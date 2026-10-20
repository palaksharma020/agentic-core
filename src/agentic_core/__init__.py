# SPDX-License-Identifier: Apache-2.0
"""agentic-core: small, framework-agnostic utilities for building agents you can check.

No LLM calls and no dependencies: plain dataclasses and deterministic checks around a model's output.
"""

from agentic_core.actions import (
    ActionPolicy,
    ActionProposal,
    ActionRule,
    AuthzDecision,
    AuthzResult,
    Grant,
    GrantCheck,
    GrantIssuer,
    Principal,
    authorize,
    parse_action_proposals,
    strip_action_commands,
)
from agentic_core.advisor import AdvisorScore, InjectionAdvisor, NullAdvisor, tighten_only
from agentic_core.grounding import (
    Claim,
    DroppedClaim,
    DropReason,
    Evidence,
    KeptClaim,
    ValidationResult,
    VerifiedEvidence,
    validate_grounding,
)
from agentic_core.leakage import (
    LeakFinding,
    LeakResult,
    ProtectedValue,
    disguised_forms,
    make_canary,
    prompt_overlap,
    scan_for_leaks,
)
from agentic_core.severity import SEVERITIES, SeverityDecision, cap_new_severity, tighten_severity
from agentic_core.sources import (
    RejectedSource,
    SourceCheck,
    SourcePolicy,
    SourceRecord,
    SourceRejection,
    check_sources,
    render_untrusted,
    sha256_text,
)
from agentic_core.text import normalize, parse_json_object, sanitize_llm_text
from agentic_core.verdict import Decision, Verdict, decide, downgrade_only

__version__ = "0.2.0"

__all__ = [
    "SEVERITIES",
    "ActionPolicy",
    "ActionProposal",
    "ActionRule",
    "AdvisorScore",
    "AuthzDecision",
    "AuthzResult",
    "Claim",
    "Decision",
    "DropReason",
    "DroppedClaim",
    "Evidence",
    "Grant",
    "GrantCheck",
    "GrantIssuer",
    "InjectionAdvisor",
    "KeptClaim",
    "LeakFinding",
    "LeakResult",
    "NullAdvisor",
    "Principal",
    "ProtectedValue",
    "RejectedSource",
    "SeverityDecision",
    "SourceCheck",
    "SourcePolicy",
    "SourceRecord",
    "SourceRejection",
    "ValidationResult",
    "Verdict",
    "VerifiedEvidence",
    "authorize",
    "cap_new_severity",
    "check_sources",
    "decide",
    "disguised_forms",
    "downgrade_only",
    "make_canary",
    "normalize",
    "parse_action_proposals",
    "parse_json_object",
    "prompt_overlap",
    "render_untrusted",
    "sanitize_llm_text",
    "scan_for_leaks",
    "sha256_text",
    "strip_action_commands",
    "tighten_only",
    "tighten_severity",
    "validate_grounding",
]
