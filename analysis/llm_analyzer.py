"""
LLM-based finding analysis with RAG context injection.

Design goals:
  - Minimal token usage: only relevant finding fields are sent.
  - Hallucination reduction: the system prompt instructs the model to rely
    only on the provided context and to express uncertainty explicitly.
  - Structured output: expects JSON with verdict / confidence / explanation.
"""

import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Only forward these fields to the LLM to avoid leaking tokens on irrelevant data
_LLM_FINDING_FIELDS = [
    "id",
    "title",
    "severity",
    "description",
    "file_path",
    "component_name",
    "component_version",
    "vulnerability_ids",
    "cwe",
    "cvssv3_score",
    "sast_source_file_path",
    "sast_source_line",
    "sast_sink_object",
    "test_name",
]

_SYSTEM_PROMPT = """\
You are an expert application security engineer performing automated triage.
Determine if the security finding below is a false-positive or requires manual review.

Known false-positive patterns from the knowledge base (use these as reference):
{rag_context}

Rules:
1. Base your decision ONLY on the provided context and finding data.
2. Do NOT hallucinate CVE details, component versions, or patch information.
3. If the context clearly matches the finding pattern → false-positive.
4. If context is missing or unclear → needs-review with low confidence.
5. Explanation must be factual, concise, max 100 words.

Respond with valid JSON only:
{{
  "verdict": "false-positive" | "needs-review",
  "confidence": <float 0.0-1.0>,
  "explanation": "<string>"
}}"""


class LLMAnalyzer:
    """Wraps an LLMClient and formats the prompts for finding analysis."""

    def __init__(self, llm_client):
        self.llm = llm_client

    def analyze(
        self,
        finding: Dict,
        rag_context: List[str],
    ) -> Optional[Dict]:
        """Analyse a single finding.

        Args:
            finding:     Raw finding dict from DefectDojo.
            rag_context: List of relevant knowledge-base document strings.

        Returns:
            Dict with keys verdict, confidence, explanation – or None on failure.
        """
        normalized = self._normalize_finding(finding)
        context_text = self._format_context(rag_context)
        system_prompt = _SYSTEM_PROMPT.format(rag_context=context_text)
        user_prompt = (
            "Analyse this security finding:\n"
            + json.dumps(normalized, ensure_ascii=False, indent=2)
        )

        try:
            raw = self.llm.chat(system_prompt, user_prompt)
            result = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error("LLM returned non-JSON response: %s | raw=%s", e, raw[:200])
            return None
        except Exception as e:
            logger.error("LLM call failed: %s", e)
            return None

        if "verdict" not in result or "confidence" not in result:
            logger.warning("Unexpected LLM response structure: %s", result)
            return None

        # Clamp confidence to [0, 1]
        result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
        return result

    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_finding(finding: Dict) -> Dict:
        return {
            k: finding[k]
            for k in _LLM_FINDING_FIELDS
            if k in finding and finding[k] is not None
        }

    @staticmethod
    def _format_context(context: List[str]) -> str:
        if not context:
            return "No prior false-positive context available for this finding."
        # Cap at 5 entries to keep the prompt within context limits
        lines = [f"- {entry}" for entry in context[:5]]
        return "\n".join(lines)
