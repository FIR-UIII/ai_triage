"""Tests for knowledge.vector_store — VectorStore operations.

Uses mocks to avoid needing a real ChromaDB or embedding model.
"""

import sys
import pytest
from unittest.mock import patch, MagicMock

# Mock chromadb before importing vector_store
sys.modules.setdefault("chromadb", MagicMock())
sys.modules.setdefault("chromadb.utils", MagicMock())
sys.modules.setdefault("chromadb.utils.embedding_functions", MagicMock())

from core.models import KnowledgeEntry


class TestVectorStoreSearchByMeta:
    """Test search_by_meta without a real embedding model."""

    def test_empty_query_returns_empty(self):
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            result = store.search_by_meta(cve=None, component_name=None)
            assert result == []

    def test_search_by_cve_only(self):
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            store.collection.get.return_value = {
                "ids": ["id1"],
                "metadatas": [{"cve": "CVE-2024-1234"}],
                "documents": ["doc1"],
            }
            result = store.search_by_meta(cve="CVE-2024-1234", component_name=None)
            assert len(result) == 1
            assert result[0]["metadata"]["cve"] == "CVE-2024-1234"


class TestVectorStoreSimilarityFilter:
    """Test that similarity threshold filtering works."""

    def test_pack_query_results_calculates_score(self):
        from knowledge.vector_store import VectorStore

        res = {
            "ids": [["id1", "id2"]],
            "metadatas": [[{"rule": "a"}, {"rule": "b"}]],
            "documents": [["doc1", "doc2"]],
            "distances": [[0.3, 0.8]],  # scores: 0.7 and 0.2
        }
        items = VectorStore._pack_query_results(res)
        assert len(items) == 2
        assert items[0]["score"] == pytest.approx(0.7, abs=0.01)
        assert items[1]["score"] == pytest.approx(0.2, abs=0.01)

    def test_similarity_filter_applies_threshold(self):
        """Ensure results below threshold 0.5 are filtered out."""
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            store.collection.query.return_value = {
                "ids": [["id1", "id2"]],
                "metadatas": [[{"rule": "a"}, {"rule": "b"}]],
                "documents": [["doc1", "doc2"]],
                "distances": [[0.3, 0.8]],  # scores: 0.7 and 0.2
            }
            result = store.search_by_similarity("test", threshold=0.5)
            assert len(result) == 1
            assert result[0]["score"] >= 0.5

    def test_find_duplicate_respects_threshold(self):
        """find_duplicate should return None if best match is below threshold."""
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            store.collection.query.return_value = {
                "ids": [["id1"]],
                "metadatas": [[{"rule": "a"}]],
                "documents": [["doc1"]],
                "distances": [[0.5]],  # score 0.5, below default 0.92
            }
            result = store.find_duplicate("test text")
            assert result is None


class TestVectorStoreDeleteMethods:
    """Test delete methods on VectorStore."""

    def test_delete_by_finding_id(self):
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            store.collection.get.return_value = {"ids": ["fp_123_aaa", "fp_123_bbb"]}
            count = store.delete_by_finding_id(123)
            assert count == 2
            store.collection.delete.assert_called_once_with(ids=["fp_123_aaa", "fp_123_bbb"])

    def test_delete_by_finding_id_not_found(self):
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            store.collection.get.return_value = {"ids": []}
            count = store.delete_by_finding_id(999)
            assert count == 0

    def test_delete_by_id(self):
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            ok = store.delete_by_id("fp_1_abc")
            assert ok
            store.collection.delete.assert_called_once_with(ids=["fp_1_abc"])

    def test_delete_by_rule(self):
        from knowledge.vector_store import VectorStore

        with patch.object(VectorStore, "__init__", lambda self, **kw: None):
            store = VectorStore.__new__(VectorStore)
            store.collection = MagicMock()
            store.collection.get.return_value = {"ids": ["id1", "id2", "id3"]}
            count = store.delete_by_rule("semgrep.xss")
            assert count == 3
