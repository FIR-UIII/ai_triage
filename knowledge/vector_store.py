import logging
from typing import Dict, List, Optional

import chromadb

from core.exceptions import RAGError
from core.models import KnowledgeEntry

logger = logging.getLogger(__name__)

# With hnsw:space=cosine, distance ∈ [0, 2].
# score = 1 - distance maps it to [-1, 1] where 1 = identical.
# For typical threshold of 0.75: only confident matches pass.
_DEDUP_THRESHOLD_DEFAULT = 0.92
_SIMILARITY_THRESHOLD_DEFAULT = 0.75


class VectorStore:
    """ChromaDB-backed vector knowledge base for false-positive patterns.

    Uses cosine distance explicitly so score = 1 - distance ∈ [-1, 1].
    """

    def __init__(
        self,
        collection_name: str = "example_collection",
        persist_directory: str = "./rag/chroma_db_metadata",
    ):
        self.client = chromadb.PersistentClient(path=persist_directory)
        # Explicitly request cosine space for consistent score semantics
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            "VectorStore ready: collection='%s', path='%s'",
            collection_name,
            persist_directory,
        )

    # ------------------------------------------------------------------
    # Search methods
    # ------------------------------------------------------------------

    def search_by_meta(
        self,
        cve: Optional[str],
        component_name: Optional[str],
        n_results: int = 5,
    ) -> List[Dict]:
        """Exact metadata filter search by CVE and/or component name."""
        if not cve and not component_name:
            return []

        conditions = []
        if cve:
            conditions.append({"cve": {"$eq": cve}})
        if component_name:
            conditions.append({"component_name": {"$eq": component_name}})

        where = {"$and": conditions} if len(conditions) > 1 else conditions[0]

        try:
            res = self.collection.get(where=where, limit=n_results)
            return self._pack_get_results(res)
        except Exception as e:
            logger.error("Meta search failed: %s", e)
            return []

    def search_by_similarity(
        self,
        text: str,
        n_results: int = 3,
        threshold: float = _SIMILARITY_THRESHOLD_DEFAULT,
    ) -> List[Dict]:
        """Semantic similarity search returning items above the score threshold."""
        if not text:
            return []
        try:
            res = self.collection.query(query_texts=[text], n_results=n_results)
            items = self._pack_query_results(res)
            return [item for item in items if item["score"] >= threshold]
        except Exception as e:
            logger.error("Similarity search failed: %s", e)
            return []

    def search_by_rule(self, rule: str, n_results: int = 3) -> List[str]:
        """Return raw document strings for a given SAST rule (for LLM context)."""
        if not rule:
            return []
        try:
            res = self.collection.get(
                limit=n_results,
                where={"rule": {"$eq": rule}},
            )
            return res.get("documents", [])
        except Exception as e:
            logger.error("Rule search failed: %s", e)
            return []

    def find_duplicate(
        self,
        text: str,
        threshold: float = _DEDUP_THRESHOLD_DEFAULT,
    ) -> Optional[Dict]:
        """Return the most similar entry if it exceeds the dedup threshold."""
        results = self.search_by_similarity(text, n_results=1, threshold=threshold)
        return results[0] if results else None

    # ------------------------------------------------------------------
    # Write methods
    # ------------------------------------------------------------------

    def add_entry(self, entry: KnowledgeEntry) -> bool:
        """Add a new knowledge entry to the collection."""
        try:
            self.collection.add(
                ids=[entry.id],
                documents=[entry.document],
                metadatas=[entry.to_chroma_metadata()],
            )
            logger.info("Added knowledge entry: %s", entry.id)
            return True
        except Exception as e:
            logger.error("Failed to add entry %s: %s", entry.id, e)
            return False

    def entry_exists(self, entry_id: str) -> bool:
        res = self.collection.get(ids=[entry_id])
        return bool(res.get("ids"))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pack_get_results(res: Dict) -> List[Dict]:
        return [
            {"id": id_, "metadata": md, "document": doc}
            for id_, md, doc in zip(
                res.get("ids", []),
                res.get("metadatas", []),
                res.get("documents", []),
            )
        ]

    @staticmethod
    def _pack_query_results(res: Dict) -> List[Dict]:
        if not res.get("ids") or not res["ids"][0]:
            return []
        return [
            {
                "score": round(1 - dist, 4),  # cosine distance -> similarity score
                "metadata": md,
                "document": doc,
            }
            for md, doc, dist in zip(
                res["metadatas"][0],
                res["documents"][0],
                res["distances"][0],
            )
        ]
