"""
Модуль vector_store.py содержит реализацию класса VectorStore, который представляет собой векторную базу знаний,
использующую ChromaDB для хранения и поиска шаблонов false-positive. Класс обеспечивает методы для:
- Инициализации и загрузки коллекции ChromaDB с явным указанием модели эмбеддингов для предотвращения несоответствий.
- Валидации размерности эмбеддингов при загрузке коллекции, чтобы гарантировать совместимость с текущей моделью.
- Поиска по метаданным (CVE, имя компонента) с точным совпадением.
- Поиска по семантической схожести с фильтрацией по порогу
- Поиска дубликатов с более строгим порогом для предотвращения добавления похожих шаблонов.
- Добавления новых записей в базу знаний с помощью класса KnowledgeEntry.
- Удаления записей по finding_id, entry_id или правилу для поддержания актуальности базы знаний.
"""

import logging
import os
from typing import Dict, List, Optional

import chromadb
from chromadb.config import Settings
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

from core.models import KnowledgeEntry

# Force offline mode for HuggingFace — use cached/local model only
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

logger = logging.getLogger(__name__)

# With hnsw:space=cosine, distance ∈ [0, 2].
# score = 1 - distance maps it to [-1, 1] where 1 = identical.
# For typical threshold of 0.75: only confident matches pass.
_DEDUP_THRESHOLD_DEFAULT = 0.92
_SIMILARITY_THRESHOLD_DEFAULT = 0.75


class VectorStore:
    """
    Класс для работы с ChromaDB. Инициализирует БД и готовит переменные для дальейшей работы
    """

    def __init__(
        self,
        collection_name: str = "example_collection",
        persist_directory: str = "./rag/chroma_db_metadata",
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        logger.debug("VectorStore.__init__ START (collection=%s, path=%s, model=%s)",
                collection_name, persist_directory, embedding_model)

        self._embedding_model_name = embedding_model

        logger.debug("Loading SentenceTransformer embedding model: %s ...", embedding_model)
        self._ef = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
        logger.debug("Embedding model loaded OK")

        logger.debug("Opening ChromaDB PersistentClient at: %s", persist_directory)
        # Disable ChromaDB anonymized telemetry (PostHog) — avoids network
        # retries/warnings when running offline (host us.i.posthog.com unreachable).
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(anonymized_telemetry=False),
        )
        logger.debug("ChromaDB client ready")

        # Open collection: try existing first (without embedding_function to
        # avoid metadata conflict if DB was created with a different EF type),
        # then fall back to creating a new one with our explicit EF.
        logger.debug("Trying to get existing collection '%s' ...", collection_name)
        try:
            self.collection = self.client.get_collection(name=collection_name)
            # Attach our embedding function for client-side embed on query/add
            self.collection._embedding_function = self._ef
            logger.debug("Opened existing collection '%s', count=%d",
                    collection_name, self.collection.count())
        except Exception:
            logger.debug("Collection '%s' not found, creating new ...", collection_name)
            self.collection = self.client.create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
                embedding_function=self._ef,
            )
            logger.debug("Created new collection '%s'", collection_name)

        logger.debug("Collection ready, count=%d", self.collection.count())

        self._validate_embedding_dimension()

        logger.info(
            "VectorStore ready: collection='%s', path='%s', model='%s'",
            collection_name,
            persist_directory,
            embedding_model,
        )
        logger.debug("VectorStore.__init__ DONE")

    def _validate_embedding_dimension(self) -> None:
        """
        Функция для проверки соответствия размерности эмбеддингов текущей модели и эмбеддингов, 
        уже хранящихся в базе данных.
        Это важно, потому что если база данных была создана с помощью одной модели, а затем
        используется другая модель с другой размерностью эмбеддингов, то поиск по схожести не будет работать корректно.
        Если обнаруживается несоответствие размерности, функция выбрасывает исключение с подробным сообщением, 
        объясняющим проблему и возможные решения (установка правильной модели или пересоздание базы данных).
        """
        count = self.collection.count()
        if count == 0:
            logger.debug("Collection is empty, skipping dimension validation")
            return

        logger.debug("Validating embedding dimension against %d stored entries ...", count)

        # Вот тут как раз и ловим ошибки на несовпадение размерности эмбеддингов, которые могут возникать 
        # при загрузке коллекции, созданной другой моделью.
        try:
            peek = self.collection.peek(limit=1)
            if not peek.get("embeddings") or not peek["embeddings"]:
                logger.debug("No embeddings in peek result, skipping validation")
                return
            stored_dim = len(peek["embeddings"][0])
        except Exception as e:
            logger.debug("Could not peek at stored embeddings: %s", e)
            return

        # Получить значение размерности эмбеддингов текущей модели, сгенерировав тестовый эмбеддинг
        try:
            test_embedding = self._ef(["dimension test"])
            current_dim = len(test_embedding[0])
        except Exception as e:
            logger.debug("Could not generate test embedding: %s", e)
            return

        logger.debug("Dimension check: stored=%d, current_model=%d", stored_dim, current_dim)

        if stored_dim != current_dim:
            msg = (
                f"Embedding dimension mismatch! "
                f"Stored vectors have dimension {stored_dim}, but model "
                f"'{self._embedding_model_name}' produces dimension {current_dim}. "
                f"The ChromaDB was likely created with a different model. "
                f"Either set EMBEDDING_MODEL to the model that created the DB, "
                f"or delete the DB and recreate it."
            )
            logger.debug("FATAL: %s", msg)
            raise ValueError(msg)

        logger.debug("Dimension validation OK (%d)", stored_dim)

    # ------------------------------------------------------------------

    def search_by_meta(
        self,
        cve: Optional[str],
        component_name: Optional[str],
        file_path: Optional[str] = None,
        n_results: int = 5,
    ) -> List[Dict]:
        """
        Точный поиск по метаданным CVE и/или имени компонента. Возвращает список записей, которые точно соответствуют
        заданным метаданным. Если оба параметра указаны, возвращаются записи, которые соответствуют обоим условиям.
        Если ни один из параметров не указан, возвращается пустой список.
        Если CVE не задан, поиск производится по file_path.
        """
        if not cve and not component_name and not file_path:
            return []

        conditions = []
        if cve:
            conditions.append({"cve": {"$eq": cve}})
        if component_name:
            conditions.append({"component_name": {"$eq": component_name}})
        if file_path:
            conditions.append({"file_path": {"$eq": file_path}})

        where = {"$and": conditions} if len(conditions) > 1 else conditions[0]

        try:
            logger.debug("search_by_meta: where=%s", where)
            res = self.collection.get(where=where, limit=n_results)
            logger.debug("search_by_meta: got %d results", len(res.get("ids", [])))
            return self._pack_get_results(res)
        except Exception as e:
            logger.error("Meta search failed: %s", e)
            return []

    def search_by_similarity(
        self,
        text: str,
        n_results: int = 3,
        threshold: float = _SIMILARITY_THRESHOLD_DEFAULT,
        rule: Optional[str] = None,
    ) -> List[Dict]:
        """
        Функция для поиска по семантической схожести. Принимает текст, который нужно сравнить, и возвращает список похожих записей из базы знаний, которые имеют similarity score выше заданного порога.
        Если указано правило, поиск ограничивается записями с этим правилом.
        """
        if not text:
            return []

        where = {"rule": {"$eq": rule}} if rule else None

        try:
            logger.debug("search_by_similarity: n_results=%d, threshold=%.2f, rule=%s, text=%.60s...",
                    n_results, threshold, rule, text)
            res = self.collection.query(
                query_texts=[text],
                n_results=n_results,
                where=where,
            )
            items = self._pack_query_results(res)
            logger.debug("search_by_similarity: %d raw results, filtering by threshold %.2f", len(items), threshold)
            filtered = [item for item in items if item["score"] >= threshold]
            logger.debug("search_by_similarity: %d results above threshold", len(filtered))
            return filtered
        except Exception as e:
            logger.error("Similarity search failed: %s", e)
            return []

    def search_by_rule(self, rule: str, n_results: int = 3) -> List[str]:
        """
        Возвращает список документов, связанных с данным SAST правилом. Это позволяет быстро найти все шаблоны FP
        """
        if not rule:
            return []
        try:
            logger.debug("search_by_rule: rule=%s", rule)
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
        rule: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Поиск дубликата по тексту с заданным порогом схожести. 
        Если указано правило, поиск ограничивается записями с этим правилом.
        """
        logger.debug("find_duplicate: threshold=%.2f, rule=%s", threshold, rule)
        results = self.search_by_similarity(text, n_results=1, threshold=threshold, rule=rule)
        return results[0] if results else None

    # ------------------------------------------------------------------

    def add_entry(self, entry: KnowledgeEntry) -> bool:
        """
        Добавляет новую запись в базу знаний. Принимает объект KnowledgeEntry, который содержит 
        все необходимые данные и метаданные для хранения.
        """
        try:
            logger.debug("add_entry: id=%s", entry.id)
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

    def delete_by_finding_id(self, finding_id: int) -> int:
        """
        Удаляет все записи, связанные с данным finding_id. Это полезно при закрытии/помечании сработки как FP, 
        чтобы очистить связанные шаблоны из базы знаний.
        """
        try:
            res = self.collection.get(
                where={"source_finding_id": {"$eq": finding_id}},
            )
            ids_to_delete = res.get("ids", [])
            if not ids_to_delete:
                logger.info("No entries found for finding_id=%s", finding_id)
                return 0
            self.collection.delete(ids=ids_to_delete)
            logger.info("Deleted %d entries for finding_id=%s", len(ids_to_delete), finding_id)
            return len(ids_to_delete)
        except Exception as e:
            logger.error("Failed to delete entries for finding_id=%s: %s", finding_id, e)
            return 0

    def delete_by_id(self, entry_id: str) -> bool:
        """
        Функция для удаления одной записи по её уникальному идентификатору.
        """
        try:
            self.collection.delete(ids=[entry_id])
            logger.info("Deleted entry: %s", entry_id)
            return True
        except Exception as e:
            logger.error("Failed to delete entry %s: %s", entry_id, e)
            return False

    def delete_by_rule(self, rule: str) -> int:
        """
        Функция для удаления всех записей, связанных с данным SAST правилом. 
        Это полезно при обновлении/удалении правила, чтобы очистить связанные шаблоны FP из базы знаний.
        """
        try:
            res = self.collection.get(where={"rule": {"$eq": rule}})
            ids_to_delete = res.get("ids", [])
            if not ids_to_delete:
                logger.info("No entries found for rule='%s'", rule)
                return 0
            self.collection.delete(ids=ids_to_delete)
            logger.info("Deleted %d entries for rule='%s'", len(ids_to_delete), rule)
            return len(ids_to_delete)
        except Exception as e:
            logger.error("Failed to delete entries for rule='%s': %s", rule, e)
            return 0

    def entry_exists(self, entry_id: str) -> bool:
        res = self.collection.get(ids=[entry_id])
        return bool(res.get("ids"))

    # ------------------------------------------------------------------

    @staticmethod
    def _pack_get_results(res: Dict) -> List[Dict]:
        """
        Функция для упаковки результатов из метода get, который возвращает списки ids, metadatas и documents.
        Преобразует их в список словарей с ключами id, metadata и document.
        Если нет результатов, возвращает пустой список.
        """
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
        """
        Функция для упаковки результатов из метода query, который возвращает расстояния, метаданные и документы.
        Преобразует косинусное расстояние в similarity score и возвращает список словарей 
        с ключами score, metadata и document.
        Если нет результатов, возвращает пустой список.
        """
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
