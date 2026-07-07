"""
Классы данных и модели для представления сработок, результатов триажа и знаний о уязвимостях. 
Эти модели используются для обмена данными между различными компонентами системы, такими как анализаторы, 
база знаний и интеграция с DefectDojo.
"""

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
    """
    Класс VulnerabilityId представляет идентификатор уязвимости, связанный с сработкой
    (например, CVE-2021-1234). Используется в классе Finding для хранения списка связанных уязвимостей.
    """
    vulnerability_id: str


class FindingNote(BaseModel):
    """
    Класс FindingNote представляет структуру комментария findingв DefectDojo
    Используется в приложении в файле models.py для нормализации данных сработки и удобного доступа к комментариям
    """
    id: int
    entry: str
    date: str = ""
    author: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    """
    Класс Finding представляет собой сработку безопасности, извлеченную из DefectDojo
    Для номализации данных сработки используется pydantic. Этот класс включает в себя все релевантные поля,
    которые могут понадобиться для анализа, а также некоторые дополнительные поля для удобства доступа к данным
    Используется в приложении в файле models.py для нормализации данных сработки и удобного доступа к полям сработки
    """
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
    """
    Класс TriageResult представляет результат триажа для конкретной сработки
    """
    finding_id: int
    action: TriageAction
    # "false-positive" | "likely-true-positive" | "needs-review"
    verdict: str
    confidence: float = 0.0
    explanation: str = ""
    similar_finding_ids: List[int] = Field(default_factory=list)
    # Comment to post back to DefectDojo
    dd_comment: Optional[str] = None
    # Arbitrary extra fields (reachability, matched rule name, etc.)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeEntry(BaseModel):
    """
    Класс KnowledgeEntry представляет одну запись, хранящуюся в векторной базе знаний
    """

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
    test_id: Optional[int] = None
    file_path: Optional[str] = None
    test_name: Optional[str] = None
    date: Optional[str] = None
    hash: Optional[str] = None

    def to_chroma_metadata(self) -> Dict[str, Any]:
        """Возвращает только скалярные поля, подходящие для метаданных ChromaDB."""
        return {
            k: v
            for k, v in self.model_dump().items()
            if k not in ("id", "document") and isinstance(v, (str, int, float, bool))
        }
