"""Tests for analysis.rules — deterministic triage rules."""

import pytest
from analysis.rules import analyze_finding, RULES


class TestDeterministicRules:
    def test_low_severity_triggers(self):
        finding = {"severity": "Low", "id": 1}
        matched, explanation, confidence = analyze_finding(finding)
        assert matched
        assert "severity_out_of_scope" in explanation
        assert confidence > 0.9

    def test_info_severity_triggers(self):
        finding = {"severity": "Info", "id": 2}
        matched, _, _ = analyze_finding(finding)
        assert matched

    def test_high_severity_no_match(self):
        finding = {"severity": "High", "id": 3, "title": "SQL Injection"}
        matched, _, _ = analyze_finding(finding)
        assert not matched

    def test_test_file_rule(self):
        finding = {"severity": "High", "file_path": "src/tests/test_utils.py", "id": 4}
        matched, explanation, _ = analyze_finding(finding)
        assert matched
        assert "test_file" in explanation

    def test_production_file_no_match(self):
        finding = {"severity": "High", "file_path": "src/app/main.py", "id": 5}
        matched, _, _ = analyze_finding(finding)
        assert not matched

    def test_documentation_file_rule(self):
        finding = {"severity": "High", "file_path": "docs/README.md", "id": 6}
        matched, explanation, _ = analyze_finding(finding)
        assert matched
        assert "documentation_file" in explanation

    def test_vendor_backport_rule(self):
        finding = {
            "severity": "High",
            "id": 7,
            "notes": [{"entry": "Vendor patch applied, backported to v1.0"}],
        }
        matched, explanation, _ = analyze_finding(finding)
        assert matched
        assert "vendor_backport" in explanation

    def test_already_mitigated_rule(self):
        finding = {
            "severity": "High",
            "id": 8,
            "is_mitigated": True,
            "active": False,
        }
        matched, explanation, _ = analyze_finding(finding)
        assert matched
        assert "already_mitigated" in explanation

    def test_no_rules_match(self):
        finding = {
            "severity": "Critical",
            "id": 9,
            "title": "RCE",
            "file_path": "src/core/handler.py",
        }
        matched, explanation, confidence = analyze_finding(finding)
        assert not matched
        assert explanation == ""
        assert confidence == 0.0
