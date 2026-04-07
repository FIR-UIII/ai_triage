"""
Модуль LLMAnalyzer оборачивает LLMClient и формирует системные и пользовательские промпты для анализа сработок. 
Он принимает нормализованную сработку, релевантный контекст из базы знаний и, при наличии, фрагмент исходного кода. 
Затем он вызывает LLM для получения вердикта о том, является ли сработка ложноположительной или требует ручной проверки, 
вместе с объяснением и уровнем уверенности. Ответ от LLM ожидается в виде строго структурированного JSON, 
который затем парсится и возвращается вызывающему коду.
"""

import json
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Список полей сработки, которые мы передаем в LLM для анализа. 
# Это помогает стандартизировать входные данные и избежать передачи избыточной информации.
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

# Системный промпт для LLM, который задает контекст и правила для анализа сработки.
_SYSTEM_PROMPT = """\
You are an expert application security engineer performing automated triage.
Determine if the security finding below is a false-positive or requires manual review.

Known false-positive patterns from the knowledge base (use these as reference):
{rag_context}
{code_context_block}
Rules:
1. Base your decision ONLY on the provided context and finding data.
2. Do NOT hallucinate CVE details, component versions, or patch information.
3. If the context clearly matches the finding pattern → false-positive.
4. If context is missing or unclear → needs-review with low confidence.
5. Explanation must be factual, concise, max 100 words.
6. If source code is provided, use it to verify whether the vulnerability is exploitable in context. Template variables in safe contexts, sanitized inputs, or test fixtures are strong indicators of false positives.

Respond with valid JSON only:
{{
  "verdict": "false-positive" | "needs-review",
  "confidence": <float 0.0-1.0>,
  "explanation": "<string>"
}}"""

# Класс LLMAnalyzer, который использует LLMClient для анализа сработок.
# Он формирует системный и пользовательский промпты, вызывает LLM и обрабатывает ответ.
class LLMAnalyzer:
    """
    Класс LLMAnalyzer оборачивает LLMClient и формирует системные и пользовательские промпты для анализа сработок.
    """

    def __init__(self, llm_client):
        self.llm = llm_client

    def analyze(
        self,
        finding: Dict,
        rag_context: List[str],
        code_context: Optional[str] = None,
    ) -> Optional[Dict]:
        """Analyse a single finding.

        Args:
            finding:      Raw finding dict from DefectDojo.
            rag_context:  List of relevant knowledge-base document strings.
            code_context: Optional source code snippet for the finding location.

        Returns:
            Dict with keys verdict, confidence, explanation – or None on failure.
        """
        normalized = self._normalize_finding(finding)
        context_text = self._format_context(rag_context)
        code_block = self._format_code_context(code_context)
        if code_block is None:
            logger.warning("No code contex found")
        system_prompt = _SYSTEM_PROMPT.format(
            rag_context=context_text,
            code_context_block=code_block,
        )
        user_prompt = (
            "Analyse this security finding:\n"
            + json.dumps(normalized, ensure_ascii=False, indent=2)
        )

        try:
            raw = self.llm.chat(system_prompt, user_prompt)
            result = json.loads(self._strip_markdown_fences(raw))
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
    def _strip_markdown_fences(text: str) -> str:
        """
        Нормализация ответов от LLM, т.к. разные бэкенды могут по-разному обрабатывать форматирование. 
        Удаляем markdown-ограждения, если они есть
        """
        if text is None:
            return ""
        stripped = text.strip()
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", stripped, re.DOTALL)
        if match:
            return match.group(1).strip()
        return stripped

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

    @staticmethod
    def _format_code_context(code_context: Optional[str]) -> str:
        if not code_context:
            return ""
        return (
            "\nSource code at the finding location:\n"
            "```\n" + code_context + "\n```\n"
        )
