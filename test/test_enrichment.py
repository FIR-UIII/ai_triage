"""Tests for knowledge.enrichment — FP reason extraction and enrichment logic."""

import sys
import pytest
from unittest.mock import MagicMock

# Mock chromadb before importing enrichment modules
sys.modules.setdefault("chromadb", MagicMock())
sys.modules.setdefault("chromadb.utils", MagicMock())
sys.modules.setdefault("chromadb.utils.embedding_functions", MagicMock())

from knowledge.enrichment import FPReasonExtractor


class TestFPReasonExtractor:
    def setup_method(self):
        self.extractor = FPReasonExtractor(llm_client=None)

    def test_extract_from_notes(self):
        finding = {
            "notes": [{"entry": "This is a false positive because the component is not used."}],
        }
        reason = self.extractor.extract(finding)
        assert reason is not None
        assert "not used" in reason

    def test_extract_empty_notes(self):
        finding = {"notes": []}
        reason = self.extractor.extract(finding)
        assert reason is None

    def test_extract_no_notes_key(self):
        finding = {}
        reason = self.extractor.extract(finding)
        assert reason is None

    def test_extract_skips_bot_comment(self):
        finding = {
            "notes": [{"entry": "Mitigated by Semgrep JSON Report re-upload"}],
        }
        reason = self.extractor.extract(finding)
        assert reason is None

    def test_extract_truncates_long_notes(self):
        long_text = "A" * 1000
        finding = {"notes": [{"entry": long_text}]}
        reason = self.extractor.extract(finding)
        assert reason is not None
        assert len(reason) <= 500

    def test_extract_multiple_notes(self):
        finding = {
            "notes": [
                {"entry": "First note"},
                {"entry": "Second note"},
            ],
        }
        reason = self.extractor.extract(finding)
        assert "First note" in reason
        assert "Second note" in reason
