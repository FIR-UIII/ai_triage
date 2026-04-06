import logging
import sys
from typing import Dict, List, Optional

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

from core.models import KnowledgeEntry

logger = logging.getLogger(__name__)

# With hnsw:space=cosine, distance ∈ [0, 2].
# score = 1 - distance maps it to [-1, 1] where 1 = identical.
# For typical threshold of 0.75: only confident matches pass.
_DEDUP_THRESHOLD_DEFAULT = 0.92
_SIMILARITY_THRESHOLD_DEFAULT = 0.75

_CANARY = "[CANARY]"


def _canary(msg: str, *args) -> None:
    """Print a canary debug message to stderr for tracing execution flow."""
    formatted = msg % args if args else msg
    print(f"{_CANARY} {formatted}", file=sys.stderr, flush=True)


class VectorStore:
    """ChromaDB-backed vector knowledge base for false-positive patterns.

    Uses cosine distance explicitly so score = 1 - distance ∈ [-1, 1].
    Requires an explicit embedding model name to avoid silent model mismatches.
    """

    def __init__(
        self,
        collection_name: str = "example_collection",
        persist_directory: str = "./rag/chroma_db_metadata",
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        _canary("VectorStore.__init__ START (collection=%s, path=%s, model=%s)",
                collection_name, persist_directory, embedding_model)

        self._embedding_model_name = embedding_model

        _canary("Loading SentenceTransformer embedding model: %s ...", embedding_model)
        self._ef = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
        _canary("Embedding model loaded OK")

        _canary("Opening ChromaDB PersistentClient at: %s", persist_directory)
        self.client = chromadb.PersistentClient(path=persist_directory)
        _canary("ChromaDB client ready")

        # Open collection: try existing first (without embedding_function to
        # avoid metadata conflict if DB was created with a different EF type),
        # then fall back to creating a new one with our explicit EF.
        _canary("Trying to get existing collection '%s' ...", collection_name)
        try:
            self.collection = self.client.get_collection(name=collection_name)
            # Attach our embedding function for client-side embed on query/add
            self.collection._embedding_function = self._ef
            _canary("Opened existing collection '%s', count=%d",
                    collection_name, self.collection.count())
        except Exception:
            _canary("Collection '%s' not found, creating new ...", collection_name)
            self.collection = self.client.create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
                embedding_function=self._ef,
            )
            _canary("Created new collection '%s'", collection_name)

        _canary("Collection ready, count=%d", self.collection.count())

        self._validate_embedding_dimension()

        logger.info(
            "VectorStore ready: collection='%s', path='%s', model='%s'",
            collection_name,
            persist_directory,
            embedding_model,
        )
        _canary("VectorStore.__init__ DONE")

    def _validate_embedding_dimension(self) -> None:
        """Validate that the embedding model dimension matches existing data.

        If the collection has data, generate a test embedding and compare its
        dimension to the stored vectors. A mismatch means the DB was created
        with a different model — raise immediately instead of hanging.
        """
        count = self.collection.count()
        if count == 0:
            _canary("Collection is empty, skipping dimension validation")
            return

        _canary("Validating embedding dimension against %d stored entries ...", count)

        # Get dimension of stored vectors by peeking at first entry
        try:
            peek = self.collection.peek(limit=1)
            if not peek.get("embeddings") or not peek["embeddings"]:
                _canary("No embeddings in peek result, skipping validation")
                return
            stored_dim = len(peek["embeddings"][0])
        except Exception as e:
            _canary("Could not peek at stored embeddings: %s", e)
            return

        # Get dimension of current model
        try:
            test_embedding = self._ef(["dimension test"])
            current_dim = len(test_embedding[0])
        except Exception as e:
            _canary("Could not generate test embedding: %s", e)
            return

        _canary("Dimension check: stored=%d, current_model=%d", stored_dim, current_dim)

        if stored_dim != current_dim:
            msg = (
                f"Embedding dimension mismatch! "
                f"Stored vectors have dimension {stored_dim}, but model "
                f"'{self._embedding_model_name}' produces dimension {current_dim}. "
                f"The ChromaDB was likely created with a different model. "
                f"Either set EMBEDDING_MODEL to the model that created the DB, "
                f"or delete the DB and recreate it."
            )
            _canary("FATAL: %s", msg)
            raise ValueError(msg)

        _canary("Dimension validation OK (%d)", stored_dim)

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
            _canary("search_by_meta: where=%s", where)
            res = self.collection.get(where=where, limit=n_results)
            _canary("search_by_meta: got %d results", len(res.get("ids", [])))
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
            _canary("search_by_similarity: n_results=%d, threshold=%.2f, text=%.60s...",
                    n_results, threshold, text)
            res = self.collection.query(query_texts=[text], n_results=n_results)
            items = self._pack_query_results(res)
            _canary("search_by_similarity: %d raw results, filtering by threshold", len(items))
            filtered = [item for item in items if item["score"] >= threshold]
            _canary("search_by_similarity: %d results above threshold", len(filtered))
            return filtered
        except Exception as e:
            logger.error("Similarity search failed: %s", e)
            return []

    def search_by_rule(self, rule: str, n_results: int = 3) -> List[str]:
        """Return raw document strings for a given SAST rule (for LLM context)."""
        if not rule:
            return []
        try:
            _canary("search_by_rule: rule=%s", rule)
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
        _canary("find_duplicate: threshold=%.2f", threshold)
        results = self.search_by_similarity(text, n_results=1, threshold=threshold)
        return results[0] if results else None

    # ------------------------------------------------------------------
    # Write methods
    # ------------------------------------------------------------------

    def add_entry(self, entry: KnowledgeEntry) -> bool:
        """Add a new knowledge entry to the collection."""
        try:
            _canary("add_entry: id=%s", entry.id)
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
