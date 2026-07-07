"""
Ядро триажного движка, который обрабатывает находки из DefectDojo и принимает решения о том, 
являются ли они ложными срабатываниями или требуют ручной проверки. 
Движок использует несколько этапов проверки, включая детерминированные правила, поиск по метаданным, 
семантический поиск в базе знаний и анализ с помощью LLM. 
Он также поддерживает опциональный этап анализа достижимости для SAST находок. 
Все компоненты (хранилище векторов, LLM клиент, анализ достижимости) внедряются 
через конструктор для гибкости и тестируемости.
"""

import logging
from typing import Dict, List, Optional

from analysis.llm_analyzer import LLMAnalyzer
from analysis.code_context import CodeContextProvider
from analysis.rules import analyze_finding
from analysis.skills import get_skill
from core.models import TriageAction, TriageResult
from knowledge.vector_store import VectorStore
from llm_backend.client import LLMClient

logger = logging.getLogger(__name__)


class TriageEngine:
    """
    Класс TriageEngine обрабатывает находки из DefectDojo и принимает решения о том, являются ли 
    они ложными срабатываниями или требуют ручной проверки.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        llm_client: LLMClient,
        dd_base_url: str = "",
        code_context_provider: Optional[CodeContextProvider] = None,
        checker_llm_client: Optional[LLMClient] = None,
    ):
        self.store = vector_store
        self.llm_analyzer = LLMAnalyzer(llm_client)
        self.checker_llm_analyzer = LLMAnalyzer(checker_llm_client) if checker_llm_client else None
        self.dd_base_url = dd_base_url.rstrip("/")
        self.code_context = code_context_provider

    def triage(self, finding: Dict) -> TriageResult:
        """
        Оркестратор (pipeline) проверок триажа
        """
        finding_id = finding.get("id", 0)
        logger.info(
            "[%s] Triaging: %s", finding_id, str(finding.get("title", ""))[:70]
        )

        # Шаг 1 – Deterministic rules
        result = self._stage_rules(finding)
        if result:
            return result

        # Шаг 2 – Точный поиск metadata match
        cve = self._primary_cve(finding)
        component = finding.get("component_name")
        file_path = finding.get("file_path") if not cve else None
        result = self._stage_meta_match(finding, cve, component, file_path)
        if result:
            return result

        # Шаг 3 – Semantic similarity RAG
        result = self._stage_similarity(finding, cve)
        if result:
            return result

        # Шаг 4 – LLM
        result = self._stage_llm(finding)
        if result:
            # Шаг 4.5 – Verification (optional): только для пограничных вердиктов,
            # чтобы не тратить второй LLM-вызов на уверенные решения
            if self._needs_verification(result):
                result = self._stage_verification(finding, result, cve) or result
            return result

        # Шаг 6 – Fallback при отсутсвии результата
        return TriageResult(
            finding_id=finding_id,
            action=TriageAction.NEEDS_REVIEW,
            verdict="needs-review",
            confidence=0.0,
            explanation="No matching pattern found; manual review required",
            dd_comment="[Auto-triage] No decision. Manual review required.",
        )

    def run_batch(self, findings: List[Dict]) -> List[TriageResult]:
        """
        Функция для обработки партии находок. Итерируется по списку находок, вызывает triage 
        для каждой и собирает результаты.
        Возвращает список TriageResult, который можно использовать для обновления 
        статусов в DefectDojo или для отчетности.
        """
        results: List[TriageResult] = []
        total = len(findings)
        for i, finding in enumerate(findings, 1):
            finding_id = finding.get("id", 0)
            try:
                result = self.triage(finding)
                results.append(result)
            except Exception as e:
                logger.error("Triage error for finding %s: %s", finding_id, e)
                results.append(
                    TriageResult(
                        finding_id=finding_id,
                        action=TriageAction.NEEDS_REVIEW,
                        verdict="needs-review",
                        confidence=0.0,
                        explanation=f"Internal triage error: {e}",
                    )
                )
            logger.debug("Batch progress: %d/%d", i, total)
        return results

    def _stage_rules(self, finding: Dict) -> Optional[TriageResult]:
        """
        Шаг 1. Применение детерминированных правил к сработке.
        """
        matched, explanation, confidence = analyze_finding(finding)
        if not matched:
            return None
        logger.info("[%s] Stage 1 match: %s", finding.get("id"), explanation)
        return TriageResult(
            finding_id=finding["id"],
            action=TriageAction.DETERMINISTIC_RULE,
            verdict="false-positive",
            confidence=confidence,
            explanation=explanation,
            dd_comment=f"[Auto-triage] False positive by rule: {explanation}",
        )

    def _stage_meta_match(
        self,
        finding: Dict,
        cve: Optional[str],
        component: Optional[str],
        file_path: Optional[str] = None,
    ) -> Optional[TriageResult]:
        """
        Шаг 2. Точный поиск по метаданным (CVE + компонент) в базе знаний.
         - Если CVE отсутствует, поиск выполняется по file_path.
         - Если найдено точное совпадение, срабатывает триаж с высоким уровнем доверия.
         - Если совпадений нет, возвращает None для перехода к следующему этапу.
         - Этот этап позволяет быстро отсеивать известные ложные срабатывания на основе их идентификаторов и компонентов.
         - Важно, что для этого этапа требуется, чтобы база знаний была достаточно наполнена и актуальна, иначе он будет часто пропускать возможности для быстрого FP триажа.
         - Поэтому важно регулярно обогащать базу знаний новыми ложными срабатываниями и их метаданными из DefectDojo.
        """
        if not cve and not component and not file_path:
            return None
        matches = self.store.search_by_meta(cve=cve, component_name=component, file_path=file_path)
        if not matches:
            return None
        logger.info(
            "[%s] Stage 2 match: %d meta entries", finding.get("id"), len(matches)
        )
        similar_ids = self._extract_ids(matches)
        return TriageResult(
            finding_id=finding["id"],
            action=TriageAction.RAG_META_MATCH,
            verdict="false-positive",
            confidence=0.87,
            explanation=f"Exact CVE/component match in knowledge base ({len(matches)} entries)",
            similar_finding_ids=similar_ids,
            dd_comment=self._build_similar_comment(matches),
        )

    def _stage_similarity(
        self, finding: Dict, cve: Optional[str]
    ) -> Optional[TriageResult]:
        """
        Шаг 3. Семантический поиск по базе знаний для нахождения похожих записей.
         - Использует векторные эмбеддинги для поиска записей, которые семантически похожи на текущую сработку, 
           даже если у них нет точного совпадения по CVE или компоненту.
         - Если найдено похожее совпадение с достаточным уровнем сходства, срабатывает триаж с умеренным уровнем доверия.
         - Этот этап позволяет отсеивать сработки, которые могут быть ложными срабатываниями, 
           на основе их семантической схожести с известными ложными срабатываниями.
        """
        search_text = cve or finding.get("title", "")
        if not search_text:
            return None
        matches = self.store.search_by_similarity(search_text, n_results=3, threshold=0.5, rule=search_text)
        if not matches:
            return None
        best = matches[0]
        logger.info(
            "[%s] Stage 3 match: score=%.3f", finding.get("id"), best["score"]
        )
        similar_ids = self._extract_ids(matches)
        return TriageResult(
            finding_id=finding["id"],
            action=TriageAction.RAG_SIMILARITY_MATCH,
            verdict="false-positive",
            # Slight confidence penalty vs exact match
            confidence=round(best["score"] * 0.9, 3),
            explanation=f"Semantically similar entry in KB (score={best['score']:.3f})",
            similar_finding_ids=similar_ids,
            dd_comment=self._build_similar_comment(matches, include_score=True),
        )

    def _stage_llm(self, finding: Dict) -> Optional[TriageResult]:
        """
        Шаг 4. Анализ с помощью LLM с RAG-контекстом.
         - Формирует системный промпт, который включает правила и шаблоны для модели, а также RAG-контекст из базы знаний.
         - Вызывает LLM для получения вердикта о том является ли сработка ложным срабатыванием или требует ручной проверки.
        """
        # Build RAG context: file_path first, then rule-specific, then text similarity
        file_path = finding.get("file_path")
        if file_path:
            fp_matches = self.store.search_by_meta(cve=None, component_name=None, file_path=file_path)
            if fp_matches:
                logger.debug("[%s] Stage 4 RAG: %d entries by file_path", finding.get("id"), len(fp_matches))
                rag_context = [m["document"] for m in fp_matches]
            else:
                rag_context = []
        else:
            rag_context = []

        if not rag_context:
            rule_key = finding.get("title", "")
            rag_context = self.store.search_by_rule(rule_key, n_results=3)
            if not rag_context:
                # Fallback: semantic search for context
                cve = self._primary_cve(finding)
                ctx_results = self.store.search_by_similarity(
                    cve or rule_key, n_results=3, threshold=0.5
                )
                rag_context = [r["document"] for r in ctx_results]

        skill = get_skill(finding)
        logger.info("[%s] Stage 4 skill: %s", finding.get("id"), skill.category.value)
        llm_result = self.llm_analyzer.analyze(
            finding,
            rag_context,
            code_context=self._get_code_context(finding),
            skill=skill,
        )
        if not llm_result:
            return None

        verdict = llm_result.get("verdict", "needs-review")
        confidence = float(llm_result.get("confidence", 0.5))
        explanation = llm_result.get("explanation", "")

        logger.info(
            "[%s] Stage 4 LLM: verdict=%s confidence=%.2f",
            finding.get("id"),
            verdict,
            confidence,
        )

        return TriageResult(
            finding_id=finding["id"],
            action=TriageAction.LLM_ANALYSIS,
            verdict=verdict,
            confidence=confidence,
            explanation=explanation,
            dd_comment=(
                f"[LLM Triage] {verdict} "
                f"(confidence={confidence:.2f}): {explanation}"
            ),
        )

    @staticmethod
    def _needs_verification(result: TriageResult) -> bool:
        """
        Определяет, стоит ли тратить второй LLM-вызов на верификацию вердикта.
        Проверяем только пограничные случаи: неуверенный false-positive
        (цена ошибки — пропущенная уязвимость) и likely-true-positive
        (вердикт влияет на приоритизацию у аналитиков).
        """
        if result.verdict == "false-positive" and result.confidence < 0.75:
            return True
        if result.verdict == "likely-true-positive":
            return True
        return False

    def _stage_verification(
        self, finding: Dict, initial_result: TriageResult, cve: Optional[str]
    ) -> Optional[TriageResult]:
        """
        Шаг 5. Проверка результата основного LLM на логические расхождения и уверенность.
         - Опциональный этап, работает только если checker_llm_analyzer инициализирован.
         - Проверяющий LLM анализирует вердикт и объяснение основного LLM.
         - Может менять вердикт, если найдены логические ошибки.
         - Может уточнять уровень уверенности (confidence).
        """
        if not self.checker_llm_analyzer:
            return None

        # Build RAG context for verification
        rule_key = finding.get("title", "")
        rag_context = self.store.search_by_rule(rule_key, n_results=3)
        if not rag_context:
            ctx_results = self.store.search_by_similarity(
                cve or rule_key, n_results=3, threshold=0.5
            )
            rag_context = [r["document"] for r in ctx_results]

        # Convert TriageResult to dict for verification
        initial_dict = {
            "verdict": initial_result.verdict,
            "confidence": initial_result.confidence,
            "explanation": initial_result.explanation,
        }

        verify_result = self.checker_llm_analyzer.verify(
            finding, initial_dict, rag_context
        )
        if not verify_result:
            return None

        # If verification confirms initial result, return None to keep original
        if verify_result.get("verified", True):
            logger.info(
                "[%s] Stage 5 verification: confirmed initial result",
                finding.get("id"),
            )
            return None

        # If verification found issues, update result
        verdict = verify_result.get("verdict", initial_result.verdict)
        confidence = float(verify_result.get("confidence", initial_result.confidence))
        explanation = verify_result.get("explanation", initial_result.explanation)

        logger.info(
            "[%s] Stage 5 verification: verdict changed or confidence updated",
            finding.get("id"),
        )

        return TriageResult(
            finding_id=finding["id"],
            action=TriageAction.LLM_ANALYSIS,
            verdict=verdict,
            confidence=confidence,
            explanation=f"{initial_result.explanation} [Verified: {explanation}]",
            dd_comment=(
                f"[LLM Triage + Verification] {verdict} "
                f"(confidence={confidence:.2f}): {explanation}"
            ),
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _primary_cve(finding: Dict) -> Optional[str]:
        """
        Функция для извлечения основного CVE из сработки, если он есть.
        Нужна для этапов, которые используют CVE для поиска в базе знаний.
        """
        ids = finding.get("vulnerability_ids") or []
        return ids[0].get("vulnerability_id") if ids else None

    def _get_code_context(self, finding: Dict) -> Optional[str]:
        """
        Создает текстовый блок с контекстом исходного кода вокруг уязвимого участка, если доступно.
        Этот контекст может быть включен в RAG для LLM
        """
        if not self.code_context:
            return None
        ctx = self.code_context.get_context(finding)
        if not ctx:
            return None
        header = f"File: {ctx.file_path_resolved}"
        if ctx.is_truncated:
            header += f" (lines {ctx.start_line}-{ctx.end_line} of {ctx.total_lines})"
        return f"{header}\n{ctx.content}"

    @staticmethod
    def _extract_ids(matches: List[Dict]) -> List[int]:
        """
        Возвращает список идентификаторов находок из метаданных совпадений, которые можно использовать 
        для ссылок в комментариях.
        """
        ids = []
        for m in matches:
            fid = m.get("metadata", {}).get("source_finding_id")
            if fid:
                try:
                    ids.append(int(fid))
                except (TypeError, ValueError):
                    pass
        return ids

    def _build_similar_comment(
        self, matches: List[Dict], include_score: bool = False
    ) -> str:
        """
        Возвращает текст комментария, который перечисляет похожие находки из базы знаний, 
        которые были найдены на этапах 2 или 3.
        """
        lines = ["[Auto-triage] Similar false-positive findings:"]
        for m in matches[:3]:
            meta = m.get("metadata", {})
            fp_id = meta.get("source_finding_id") or meta.get("id", "N/A")
            url = (
                f"{self.dd_base_url}/finding/{fp_id}"
                if self.dd_base_url
                else f"Finding #{fp_id}"
            )
            score_tag = f" (score={m['score']:.3f})" if include_score and "score" in m else ""
            doc_preview = m.get("document", "")[:100]
            lines.append(f"  - {url}{score_tag}: {doc_preview}")
        return "\n".join(lines)
