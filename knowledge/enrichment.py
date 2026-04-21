"""
Модуль enrichment.py содержит реализацию класса KnowledgeEnricher, который отвечает за 
обогащение базы знаний на основе данных о ложных срабатываниях (False Positives) из DefectDojo.

Основные компоненты:
- FPReasonExtractor: Класс для извлечения и нормализации причины ложного срабатывания из заметок к сработке.
- KnowledgeEnricher: Оркестратор всего процесса обогащения. Он извлекает ложные срабатывания для данного теста,
    обрабатывает каждую сработку, извлекая причину FP, проверяя на дубликаты и добавляя уникальные записи в векторное хранилище.
Ключевые функции:
- enrich_from_product(test_id, dry_run): Главная функция для запуска процесса обогащения для всех ложных срабатываний, 
связанных с данным test_id. Возвращает статистику обогащения.
- _process_one(finding, stats, dry_run): Обрабатывает одну сработку: извлекает причину FP, проверяет на дубликаты и добавляет в хранилище.
- _build_document(reason, cve, component, component_version): 
Статический метод для композиции нормализованного текстового документа из его составных частей (причина, CVE, компонент).
"""

import hashlib
import json
import logging
import re
from typing import Dict, List, Optional

from core.models import KnowledgeEntry
from knowledge.vector_store import VectorStore

logger = logging.getLogger(__name__)

# Если нужно будет исключить из обогащения определенные шаблоны комментариев (например, от бота или автозакрытия),
# можно добавить их в этот список. Сейчас он содержит один шаблон, который соответствует комментария
_SKIP_PATTERNS = [
    r"Mitigated by Semgrep JSON Report re-upload",
]

_COMPILED_SKIP_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in _SKIP_PATTERNS
]


class FPReasonExtractor:

    def __init__(self, llm_client=None):
        # llm_client не обязателен, так как LLM extraction временно отключен. 
        # Если llm_client не передан, будет использоваться простая логика извлечения из заметок.
        self.llm = llm_client

    # цель функции распарсить из finding ключ entry в котором содержится описание причины FP
    def extract(self, finding: Dict) -> Optional[str]:
        notes = finding.get("notes") or []
        entries = [n.get("entry", "") for n in notes if n.get("entry")]
        if not entries:
            return None

        combined = "\n---\n".join(entries)

        # Пропустить комментарии бота/автозакрытия — нет аналитического обоснования для извлечения
        if self._is_bot_comment(combined):
            logger.debug("  extract: bot/auto-close comment detected, skipping")
            return None

        # Использовать усеченную заметку в качестве причины
        return combined[:500].strip() or None


    @staticmethod
    def _is_bot_comment(text: str) -> bool:
        """Return True if text matches a known bot/auto-close pattern."""
        for pattern in _COMPILED_SKIP_PATTERNS:
            if pattern.search(text):
                return True
        return False

    # def _extract_with_llm(self, finding: Dict, notes: str) -> Optional[str]:
    #     system_prompt = (
    #         "You are a security analyst assistant. "
    #         "Extract the reason a finding was marked false-positive from analyst notes. "
    #         "Return a single concise sentence (max 200 chars). "
    #         'Return JSON: {"fp_reason": "..."}. '
    #         'If no clear reason: {"fp_reason": null}.'
    #     )
    #     cves = [
    #         v.get("vulnerability_id", "")
    #         for v in finding.get("vulnerability_ids", [])
    #     ]
    #     user_prompt = (
    #         f"Finding: {finding.get('title', 'N/A')}\n"
    #         f"CVE: {', '.join(cves)}\n"
    #         f"Component: {finding.get('component_name', 'N/A')} "
    #         f"{finding.get('component_version', '')}\n"
    #         f"Analyst notes:\n{notes}"
    #     )
    #     try:
    #         raw = self.llm.chat(system_prompt, user_prompt)
    #         data = json.loads(raw)
    #         return data.get("fp_reason")
    #     except Exception as e:
    #         logger.warning("LLM FP reason extraction failed: %s", e)
    #         return None


class KnowledgeEnricher:

    def __init__(
        self,
        dd_client,
        vector_store: VectorStore,
        llm_client=None,
        dedup_threshold: float = 0.92,
    ):
        self.dd = dd_client
        self.store = vector_store
        self.extractor = FPReasonExtractor(llm_client)
        self.dedup_threshold = dedup_threshold

    def enrich_from_product(self, test_id: int, dry_run: bool = False) -> Dict:
        """
        Основная функция для обогащения базы знаний на основе ложных срабатываний из DefectDojo для данного test_id
        """
        stats = {
            "fetched": 0,
            "processed": 0,
            "added": 0,
            "skipped_duplicate": 0,
            "skipped_no_reason": 0,
            "errors": 0,
        }

        logger.debug("enrich_from_product: fetching FPs for product_id=%d ...", test_id)
        fps = self.dd.fetch_false_positives_by_test_id(test_id)
        stats["fetched"] = len(fps)
        logger.debug("enrich_from_product: fetched %d false positives", len(fps))
        logger.info(
            "Enriching from %d false positives (test_id=%d)", len(fps), test_id
        )

        for i, finding in enumerate(fps, 1):
            stats["processed"] += 1
            finding_id = finding.get("id")
            logger.debug("enrich_from_product: processing finding %d/%d (id=%s) ...",
                    i, len(fps), finding_id)
            try:
                self._process_one(finding, stats, dry_run)
            except Exception as e:
                logger.error("Error processing finding %s: %s", finding_id, e)
                logger.debug("enrich_from_product: ERROR on finding %s: %s", finding_id, e)
                stats["errors"] += 1

        logger.debug("enrich_from_product: DONE, stats=%s", stats)
        logger.info("Enrichment complete: %s", stats)
        return stats


    def _process_one(self, finding: Dict, stats: Dict, dry_run: bool) -> None:
        """
        Обрабатывает одно ложное срабатывание, извлекая причину и добавляя запись в базу знаний
        """
        finding_id = finding.get("id")

        reason = self.extractor.extract(finding)
        if not reason:
            logger.debug("Skipping finding %s: no FP reason extracted", finding_id)
            stats["skipped_no_reason"] += 1
            return
        logger.debug("  _process_one(%s): reason=%.60s...", finding_id, reason)

        cves = [
            v.get("vulnerability_id", "")
            for v in finding.get("vulnerability_ids", [])
        ]
        cve = cves[0] if cves else None
        component = finding.get("component_name") or ""
        component_version = finding.get("component_version") or ""
        rule = finding.get("title") or ""

        document = self._build_document(reason, cve, component, component_version)
        doc_hash = hashlib.sha256(document.encode()).hexdigest()[:16]

        # Проверить на дубликаты — если найдено похожее, пропустить добавление
        logger.debug("  _process_one(%s): checking for duplicates (rule=%s) ...", finding_id, rule)
        duplicate = self.store.find_duplicate(
            document, threshold=self.dedup_threshold, rule=rule or None,
        )
        if duplicate:
            logger.debug("  _process_one(%s): duplicate found (score=%.3f), skipping",
                    finding_id, duplicate["score"])
            logger.debug(
                "Skipping finding %s: duplicate found (score=%.3f)",
                finding_id,
                duplicate["score"],
            )
            stats["skipped_duplicate"] += 1
            return

        # Если дубликатов нет, создать запись и добавить в базу знаний использует класс KnowledgeEntry, 
        # который представляет одну запись в базе знаний. 
        entry = KnowledgeEntry(
            id=f"fp_{finding_id}_{doc_hash}",
            document=document,
            cve=cve,
            component_name=component or None,
            component_version=component_version or None,
            rule=rule or None,
            source_finding_id=finding_id,
            product_id=finding.get("product") or finding.get("product_id"),
            test_id=finding.get("test"),
            file_path=finding.get("file_path") or finding.get("sast_source_file_path"),
            test_name=finding.get("test_name"),
            date=(finding.get("mitigated") or "")[:10] or None,
            hash=doc_hash,
        )

        if dry_run:
            logger.debug("  _process_one(%s): [DRY RUN] would add entry", finding_id)
            logger.info("[DRY RUN] Would add entry for finding %s: %s", finding_id, document[:80])
            stats["added"] += 1
        elif self.store.add_entry(entry):
            logger.debug("  _process_one(%s): entry added", finding_id)
            stats["added"] += 1

    @staticmethod
    def _build_document(
        reason: str,
        cve: Optional[str],
        component: str,
        component_version: str,
    ) -> str:
        """
        Функция для создания нормализованного текстового документа из его составных частей (причина, CVE, компонент).
        Документ будет содержать основную причину FP, а также упоминание CVE
        """
        parts = [reason.strip()]
        if cve:
            parts.append(f"CVE: {cve}")
        if component:
            ver = f" {component_version}" if component_version else ""
            parts.append(f"Component: {component}{ver}")
        return ". ".join(parts)
