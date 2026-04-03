"""
Deterministic triage rules.

Rules are evaluated before any RAG or LLM call and offer the highest
confidence verdicts at zero latency cost.

To add a new rule: create a function matching the signature
    (finding: Dict) -> bool
and add a Rule entry to the RULES list.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple


@dataclass
class Rule:
    name: str
    description: str
    check: Callable[[Dict], bool]
    verdict: str = "false-positive"
    confidence: float = 0.9


# ------------------------------------------------------------------
# Rule implementations
# ------------------------------------------------------------------


def _severity_out_of_scope(finding: Dict) -> bool:
    """Skip Info/Informational/Low severities per current policy."""
    severity = (finding.get("severity") or "").lower()
    return severity in ("info", "informational", "low")


def _is_test_file(finding: Dict) -> bool:
    """Finding is inside a test/spec directory – not shipped to production."""
    path = (
        finding.get("file_path")
        or finding.get("sast_source_file_path")
        or ""
    )
    return bool(
        re.search(
            r"[/_\-](test|tests|spec|specs|mock|mocks|fixture|fixtures|example|sample)[/_\-.]",
            path,
            re.IGNORECASE,
        )
    )


def _is_documentation_file(finding: Dict) -> bool:
    """Finding is in a documentation-only file."""
    path = finding.get("file_path") or ""
    return bool(re.search(r"\.(md|rst|txt|adoc|asciidoc)$", path, re.IGNORECASE))


def _is_vendor_backport(finding: Dict) -> bool:
    """Analyst notes explicitly state the vendor has backported the fix."""
    notes = finding.get("notes") or []
    keywords = (
        "патч от вендора",
        "vendor patch",
        "исправление вендора",
        "backported",
        "backport fix",
        "содержащее исправление",
        "содержит исправление",
    )
    for note in notes:
        entry = (note.get("entry") or "").lower()
        if any(kw in entry for kw in keywords):
            return True
    return False


def _is_already_mitigated(finding: Dict) -> bool:
    """Finding is already marked mitigated/closed in DefectDojo."""
    return bool(finding.get("is_mitigated")) and not finding.get("active", True)


# ------------------------------------------------------------------
# Rule registry
# ------------------------------------------------------------------

RULES: List[Rule] = [
    Rule(
        name="severity_out_of_scope",
        description="Severity is Info/Low – out of scope for current analysis cycle",
        check=_severity_out_of_scope,
        confidence=0.95,
    ),
    Rule(
        name="test_file",
        description="Finding is located in a test/spec directory (not in production build)",
        check=_is_test_file,
        confidence=0.88,
    ),
    Rule(
        name="documentation_file",
        description="Finding is in a documentation-only file",
        check=_is_documentation_file,
        confidence=0.90,
    ),
    Rule(
        name="vendor_backport",
        description="Analyst notes confirm the vendor has backported the fix",
        check=_is_vendor_backport,
        confidence=0.87,
    ),
    Rule(
        name="already_mitigated",
        description="Finding is already closed/mitigated in DefectDojo",
        check=_is_already_mitigated,
        confidence=0.95,
    ),
]


def analyze_finding(finding: Dict) -> Tuple[bool, str, float]:
    """Apply all deterministic rules in order.

    Returns:
        (matched, explanation, confidence)
        matched=False means no rule fired.
    """
    for rule in RULES:
        if rule.check(finding):
            explanation = f"[Rule:{rule.name}] {rule.description}"
            return True, explanation, rule.confidence
    return False, "", 0.0
