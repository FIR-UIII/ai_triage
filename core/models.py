from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TriageAction(str, Enum):
    DETERMINISTIC_RULE = "deterministic_rule"
    RAG_META_MATCH = "rag_meta_match"
    RAG_SIMILARITY_MATCH = "rag_similarity_match"
    LLM_ANALYSIS = "llm_analysis"
    NEEDS_REVIEW = "needs_review"


class VulnerabilityId(BaseModel):
    vulnerability_id: str


class FindingNote(BaseModel):
    id: int
    entry: str
    date: str = ""
    author: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    id: int
    title: str
    severity: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    vulnerability_ids: List[VulnerabilityId] = Field(default_factory=list)
    false_p: bool = False
    active: bool = True
    is_mitigated: bool = False
    cwe: Optional[int] = None
    cvssv3_score: Optional[float] = None
    sast_source_file_path: Optional[str] = None
    sast_source_line: Optional[int] = None
    sast_sink_object: Optional[str] = None
    notes: List[FindingNote] = Field(default_factory=list)
    test: Optional[int] = None
    test_name: Optional[str] = None

    @property
    def primary_cve(self) -> Optional[str]:
        if self.vulnerability_ids:
            return self.vulnerability_ids[0].vulnerability_id
        return None


class TriageResult(BaseModel):
    finding_id: int
    action: TriageAction
    # "false-positive" | "needs-review"
    verdict: str
    confidence: float = 0.0
    explanation: str = ""
    similar_finding_ids: List[int] = Field(default_factory=list)
    # Comment to post back to DefectDojo
    dd_comment: Optional[str] = None
    # Arbitrary extra fields (reachability, matched rule name, etc.)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeEntry(BaseModel):
    """A single entry stored in the vector knowledge base."""

    id: str
    # Human-readable FP explanation used as the embedding document
    document: str
    cve: Optional[str] = None
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    # SAST rule identifier
    rule: Optional[str] = None
    source_finding_id: Optional[int] = None
    product_id: Optional[int] = None
    date: Optional[str] = None
    hash: Optional[str] = None

    def to_chroma_metadata(self) -> Dict[str, Any]:
        """Return only scalar fields suitable for ChromaDB metadata."""
        return {
            k: v
            for k, v in self.model_dump().items()
            if k not in ("id", "document") and isinstance(v, (str, int, float, bool))
        }
