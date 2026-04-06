"""
Knowledge base enrichment pipeline.

Flow:
  1. Fetch closed False Positive findings from DefectDojo (by product ID).
  2. Extract the FP reason from analyst notes (pattern-based → LLM fallback).
  3. Check for semantic duplicates in the vector store.
  4. Add new, non-duplicate entries to the knowledge base.
"""

import hashlib
import json
import logging
import re
import sys
from typing import Dict, List, Optional

from core.models import KnowledgeEntry
from knowledge.vector_store import VectorStore

logger = logging.getLogger(__name__)

_DEBUG = "[DEBUG]"


def _DEBUG(msg: str, *args) -> None:
    formatted = msg % args if args else msg
    print(f"{_DEBUG} {formatted}", file=sys.stderr, flush=True)

# ------------------------------------------------------------------
# FP reason extraction
# ------------------------------------------------------------------

# Common Russian / English phrases that signal an FP explanation follows
_FP_PATTERNS = [
    r"(?:ложная тревога|false.positive|fp)[:\s]+(.{20,400})",
    r"(?:причина|reason)[:\s]+(.{20,400})",
    r"(?:патч|исправление|fix|backport)[^.]{0,80}?(?:вендора|vendor)[^.]*\.",
    r"(?:используется версия|version used)[^.]*\.",
    r"(?:сканер не интерпрет|scanner misidentif)[^.]*\.",
]

_COMPILED_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.DOTALL) for p in _FP_PATTERNS
]


class FPReasonExtractor:
    """Extracts and normalises the false-positive reason from finding notes.

    Strategy (cheapest-first):
      1. Regex pattern matching against note text.
      2. LLM call if patterns produce no result and an llm_client is provided.
      3. Truncated raw note as last resort.
    """

    def __init__(self, llm_client=None):
        # llm_client is optional – enrichment can run without LLM
        self.llm = llm_client

    def extract(self, finding: Dict) -> Optional[str]:
        notes = finding.get("notes") or []
        entries = [n.get("entry", "") for n in notes if n.get("entry")]
        if not entries:
            return None

        combined = "\n---\n".join(entries)

        reason = self._extract_by_pattern(combined)
        if reason:
            return reason

        if self.llm:
            reason = self._extract_with_llm(finding, combined)
            if reason:
                return reason

        # Last resort: use a truncated note (at least something goes into RAG)
        return combined[:300].strip() or None

    # ------------------------------------------------------------------

    def _extract_by_pattern(self, text: str) -> Optional[str]:
        for pattern in _COMPILED_PATTERNS:
            m = pattern.search(text)
            if m:
                # Group 1 is preferred (the captured reason), else full match
                return (m.group(1) if m.lastindex else m.group(0)).strip()
        return None

    def _extract_with_llm(self, finding: Dict, notes: str) -> Optional[str]:
        system_prompt = (
            "You are a security analyst assistant. "
            "Extract the reason a finding was marked false-positive from analyst notes. "
            "Return a single concise sentence (max 200 chars). "
            'Return JSON: {"fp_reason": "..."}. '
            'If no clear reason: {"fp_reason": null}.'
        )
        cves = [
            v.get("vulnerability_id", "")
            for v in finding.get("vulnerability_ids", [])
        ]
        user_prompt = (
            f"Finding: {finding.get('title', 'N/A')}\n"
            f"CVE: {', '.join(cves)}\n"
            f"Component: {finding.get('component_name', 'N/A')} "
            f"{finding.get('component_version', '')}\n"
            f"Analyst notes:\n{notes}"
        )
        try:
            raw = self.llm.chat(system_prompt, user_prompt)
            data = json.loads(raw)
            return data.get("fp_reason")
        except Exception as e:
            logger.warning("LLM FP reason extraction failed: %s", e)
            return None


# ------------------------------------------------------------------
# Enrichment orchestrator
# ------------------------------------------------------------------


class KnowledgeEnricher:
    """Orchestrates the enrichment pipeline.

    Args:
        dd_client:    DefectDojoClient instance.
        vector_store: VectorStore instance.
        llm_client:   Optional LLMClient – used for FP reason extraction.
        dedup_threshold: Cosine similarity threshold for duplicate detection.
    """

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
        """Run the full enrichment pipeline for a DefectDojo product.

        Returns a dict with enrichment statistics.
        """
        stats = {
            "fetched": 0,
            "processed": 0,
            "added": 0,
            "skipped_duplicate": 0,
            "skipped_no_reason": 0,
            "errors": 0,
        }

        _DEBUG("enrich_from_product: fetching FPs for product_id=%d ...", test_id)
        fps = self.dd.fetch_false_positives_by_product(test_id)
        stats["fetched"] = len(fps)
        _DEBUG("enrich_from_product: fetched %d false positives", len(fps))
        logger.info(
            "Enriching from %d false positives (test_id=%d)", len(fps), test_id
        )

        for i, finding in enumerate(fps, 1):
            stats["processed"] += 1
            finding_id = finding.get("id")
            _DEBUG("enrich_from_product: processing finding %d/%d (id=%s) ...",
                    i, len(fps), finding_id)
            try:
                self._process_one(finding, stats, dry_run)
            except Exception as e:
                logger.error("Error processing finding %s: %s", finding_id, e)
                _DEBUG("enrich_from_product: ERROR on finding %s: %s", finding_id, e)
                stats["errors"] += 1

        _DEBUG("enrich_from_product: DONE, stats=%s", stats)
        logger.info("Enrichment complete: %s", stats)
        return stats

    # ------------------------------------------------------------------

    def _process_one(self, finding: Dict, stats: Dict, dry_run: bool) -> None:
        finding_id = finding.get("id")

        _DEBUG("  _process_one(%s): extracting FP reason ...", finding_id)
        reason = self.extractor.extract(finding)
        if not reason:
            _DEBUG("  _process_one(%s): no reason found, skipping", finding_id)
            logger.debug("Skipping finding %s: no FP reason extracted", finding_id)
            stats["skipped_no_reason"] += 1
            return
        _DEBUG("  _process_one(%s): reason=%.60s...", finding_id, reason)

        cves = [
            v.get("vulnerability_id", "")
            for v in finding.get("vulnerability_ids", [])
        ]
        cve = cves[0] if cves else None
        component = finding.get("component_name") or ""
        component_version = finding.get("component_version") or ""

        document = self._build_document(reason, cve, component, component_version)
        doc_hash = hashlib.sha256(document.encode()).hexdigest()[:16]

        # Deduplication: check semantic similarity
        _DEBUG("  _process_one(%s): checking for duplicates ...", finding_id)
        duplicate = self.store.find_duplicate(document, threshold=self.dedup_threshold)
        if duplicate:
            _DEBUG("  _process_one(%s): duplicate found (score=%.3f), skipping",
                    finding_id, duplicate["score"])
            logger.debug(
                "Skipping finding %s: duplicate found (score=%.3f)",
                finding_id,
                duplicate["score"],
            )
            stats["skipped_duplicate"] += 1
            return

        entry = KnowledgeEntry(
            id=f"fp_{finding_id}_{doc_hash}",
            document=document,
            cve=cve,
            component_name=component or None,
            component_version=component_version or None,
            source_finding_id=finding_id,
            product_id=finding.get("product") or finding.get("product_id"),
            date=(finding.get("mitigated") or "")[:10] or None,
            hash=doc_hash,
        )

        if dry_run:
            _DEBUG("  _process_one(%s): [DRY RUN] would add entry", finding_id)
            logger.info("[DRY RUN] Would add entry for finding %s: %s", finding_id, document[:80])
            stats["added"] += 1
        elif self.store.add_entry(entry):
            _DEBUG("  _process_one(%s): entry added", finding_id)
            stats["added"] += 1

    @staticmethod
    def _build_document(
        reason: str,
        cve: Optional[str],
        component: str,
        component_version: str,
    ) -> str:
        """Compose a normalised knowledge document from its constituent parts."""
        parts = [reason.strip()]
        if cve:
            parts.append(f"CVE: {cve}")
        if component:
            ver = f" {component_version}" if component_version else ""
            parts.append(f"Component: {component}{ver}")
        return ". ".join(parts)
