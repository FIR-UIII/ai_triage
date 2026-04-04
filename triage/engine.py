"""
Multi-stage triage engine.

Pipeline stages (in order of precedence):
  1. Deterministic rules  – fast, zero external calls, highest confidence
  2. Exact meta match     – CVE + component exact lookup in vector store
  3. Semantic similarity  – vector similarity search in knowledge base
  4. LLM analysis         – LLM with RAG context injection
  5. Reachability check   – optional SAST reachability analysis
  6. Manual review        – fallback when no decision can be made
"""

import logging
from typing import Dict, List, Optional

from analysis.llm_analyzer import LLMAnalyzer
from analysis.reachability import BaseReachabilityAnalyzer
from analysis.code_context import CodeContextProvider
from analysis.rules import analyze_finding
from core.models import TriageAction, TriageResult
from knowledge.vector_store import VectorStore
from llm_backend.client import LLMClient

logger = logging.getLogger(__name__)


class TriageEngine:
    """Orchestrates the triage pipeline using dependency injection.

    Args:
        vector_store:           VectorStore instance (ChromaDB).
        llm_client:             LLMClient instance (local or API).
        dd_base_url:            DefectDojo base URL for building finding links.
        reachability_analyzer:  Optional SAST reachability tool.
        source_root:            Optional local source root for reachability analysis.
        code_context_provider:  Optional source code reader for LLM enrichment.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        llm_client: LLMClient,
        dd_base_url: str = "",
        reachability_analyzer: Optional[BaseReachabilityAnalyzer] = None,
        source_root: Optional[str] = None,
        code_context_provider: Optional[CodeContextProvider] = None,
    ):
        self.store = vector_store
        self.llm_analyzer = LLMAnalyzer(llm_client)
        self.dd_base_url = dd_base_url.rstrip("/")
        self.reachability = reachability_analyzer
        self.source_root = source_root
        self.code_context = code_context_provider

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def triage(self, finding: Dict) -> TriageResult:
        """Run the full triage pipeline for a single finding."""
        finding_id = finding.get("id", 0)
        logger.info(
            "[%s] Triaging: %s", finding_id, str(finding.get("title", ""))[:70]
        )

        # Stage 1 – Deterministic rules
        result = self._stage_rules(finding)
        if result:
            return result

        # Stage 2 – Exact metadata match
        cve = self._primary_cve(finding)
        component = finding.get("component_name")
        result = self._stage_meta_match(finding, cve, component)
        if result:
            return result

        # Stage 3 – Semantic similarity
        result = self._stage_similarity(finding, cve)
        if result:
            return result

        # Stage 4 – LLM + optional Stage 5 reachability
        result = self._stage_llm(finding)
        if result:
            return result

        # Stage 6 – Fallback
        return TriageResult(
            finding_id=finding_id,
            action=TriageAction.NEEDS_REVIEW,
            verdict="needs-review",
            confidence=0.0,
            explanation="No matching pattern found; manual review required",
            dd_comment="[Auto-triage] No decision. Manual review required.",
        )

    def run_batch(self, findings: List[Dict]) -> List[TriageResult]:
        """Triage a list of findings, collecting errors without raising."""
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

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    def _stage_rules(self, finding: Dict) -> Optional[TriageResult]:
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
    ) -> Optional[TriageResult]:
        if not cve and not component:
            return None
        matches = self.store.search_by_meta(cve=cve, component_name=component)
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
        search_text = cve or finding.get("title", "")
        if not search_text:
            return None
        matches = self.store.search_by_similarity(search_text, n_results=3)
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
        # Build RAG context: try rule-specific first, then text similarity
        rule_key = finding.get("title", "")
        rag_context = self.store.search_by_rule(rule_key, n_results=3)
        if not rag_context:
            # Fallback: semantic search for context
            cve = self._primary_cve(finding)
            ctx_results = self.store.search_by_similarity(
                cve or rule_key, n_results=3, threshold=0.5
            )
            rag_context = [r["document"] for r in ctx_results]

        llm_result = self.llm_analyzer.analyze(finding, rag_context, code_context=self._get_code_context(finding))
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

        # Optional Stage 5 – reachability for SAST findings
        reach_note = ""
        if self.reachability and finding.get("sast_source_file_path"):
            reach = self.reachability.analyze(finding, self.source_root)
            if reach.confidence > 0:
                reach_label = "reachable" if reach.is_reachable else "not reachable"
                reach_note = (
                    f" [Reachability: {reach_label}, conf={reach.confidence:.2f}]"
                )
                logger.info("[%s] Stage 5 reachability: %s", finding.get("id"), reach_label)
                # Unreachable sink → upgrade to FP and lower confidence slightly
                if not reach.is_reachable and reach.confidence >= 0.7:
                    verdict = "false-positive"
                    confidence = round(min(confidence, 0.75), 3)

        return TriageResult(
            finding_id=finding["id"],
            action=TriageAction.LLM_ANALYSIS,
            verdict=verdict,
            confidence=confidence,
            explanation=explanation + reach_note,
            dd_comment=(
                f"[LLM Triage] {verdict} "
                f"(confidence={confidence:.2f}): {explanation}{reach_note}"
            ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _primary_cve(finding: Dict) -> Optional[str]:
        ids = finding.get("vulnerability_ids") or []
        return ids[0].get("vulnerability_id") if ids else None

    def _get_code_context(self, finding: Dict) -> Optional[str]:
        """Build a code context string for the LLM, or None if unavailable."""
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
