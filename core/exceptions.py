class TriageError(Exception):
    """Base exception for the triage system."""


class DDApiError(TriageError):
    """Raised when DefectDojo API calls fail."""


class RAGError(TriageError):
    """Raised when knowledge base operations fail."""


class LLMError(TriageError):
    """Raised when LLM calls fail."""


class EnrichmentError(TriageError):
    """Raised when knowledge base enrichment fails."""
