"""Tests for core.models — KnowledgeEntry and TriageResult."""

import pytest
from core.models import KnowledgeEntry, TriageResult, TriageAction


class TestKnowledgeEntry:
    def test_basic_creation(self):
        entry = KnowledgeEntry(
            id="fp_123_abc",
            document="Test document",
            cve="CVE-2024-1234",
            component_name="openssl",
            component_version="1.1.1",
            rule="semgrep.rule.xss",
            source_finding_id=123,
            product_id=1,
            test_id=42,
            file_path="src/main.py",
            test_name="Semgrep JSON Report",
        )
        assert entry.id == "fp_123_abc"
        assert entry.test_id == 42
        assert entry.file_path == "src/main.py"
        assert entry.test_name == "Semgrep JSON Report"

    def test_to_chroma_metadata_includes_new_fields(self):
        entry = KnowledgeEntry(
            id="fp_1_aaa",
            document="doc",
            test_id=10,
            file_path="app/views.py",
            test_name="Bandit Scan",
        )
        meta = entry.to_chroma_metadata()
        assert "id" not in meta
        assert "document" not in meta
        assert meta["test_id"] == 10
        assert meta["file_path"] == "app/views.py"
        assert meta["test_name"] == "Bandit Scan"

    def test_to_chroma_metadata_excludes_none(self):
        entry = KnowledgeEntry(id="fp_2_bbb", document="doc")
        meta = entry.to_chroma_metadata()
        # None values should be excluded (not scalar)
        assert "cve" not in meta
        assert "test_id" not in meta

    def test_optional_fields_default_none(self):
        entry = KnowledgeEntry(id="x", document="d")
        assert entry.test_id is None
        assert entry.file_path is None
        assert entry.test_name is None


class TestTriageResult:
    def test_basic_result(self):
        result = TriageResult(
            finding_id=1,
            action=TriageAction.DETERMINISTIC_RULE,
            verdict="false-positive",
            confidence=0.95,
            explanation="test",
        )
        assert result.verdict == "false-positive"
        assert result.action == TriageAction.DETERMINISTIC_RULE

    def test_needs_review_fallback(self):
        result = TriageResult(
            finding_id=2,
            action=TriageAction.NEEDS_REVIEW,
            verdict="needs-review",
        )
        assert result.confidence == 0.0
        assert result.similar_finding_ids == []
