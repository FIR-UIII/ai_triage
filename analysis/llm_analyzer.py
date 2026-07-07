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

from analysis.skills import Skill, get_skill

logger = logging.getLogger(__name__)

# Допустимые значения вердикта от LLM
_VALID_VERDICTS = ("false-positive", "likely-true-positive", "needs-review")

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

# Системные промпты анализа перенесены в analysis/skills.py: у каждой категории
# сработки (SAST / SCA / generic) свой специализированный статический промпт.
# Переменные данные (RAG, улики, код, finding) передаются в user-промпте, чтобы
# LLM-сервер мог переиспользовать кэш префикса системного промпта между запросами.

# Системный промпт для проверяющего LLM, который проверяет результат основного LLM.
# Статический — исходный результат и контекст передаются в user-промпте.
_VERIFICATION_SYSTEM_PROMPT = """\
You are an expert security reviewer validating an automated triage decision.
Your role is to verify the correctness and consistency of the initial verdict.

Rules for verification:
1. Check if the verdict is logically consistent with the explanation and finding data.
2. If the explanation contradicts the verdict, flag this as a logical inconsistency.
3. Assess confidence: is the level of confidence (0.0-1.0) justified by the explanation?
4. There are no words in explanation: likely, possibly, presumably, seems, etc.
5. If you find clear logical errors that would reverse the verdict, you MAY change it.
6. Keep explanation concise (max 100 words), focusing on what changed and why.

Respond with valid JSON only:
{
  "verdict": "false-positive" | "likely-true-positive" | "needs-review",
  "confidence": <float 0.0-1.0>,
  "explanation": "<string>",
  "verified": true | false
}

"verified": true means you confirm the initial decision, false means you found issues."""

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
        skill: Optional[Skill] = None,
    ) -> Optional[Dict]:
        """
        Анализ одной сработки.

        Принимает на вход:
            finding:      Сырая сработка из ДД.
            rag_context:  Список с найденными похожими сработками из RAG.
            code_context: Кусок кода, если запуск с --repo флагом и передачей пути до исходников.
            skill:        Скилл (категорийный промпт + сборщик улик); если не передан —
                          определяется автоматически по полям сработки.

        Возвращает:
            Словарь  {verdict, confidence, explanation} или None
        """
        skill = skill or get_skill(finding)
        normalized = self._normalize_finding(finding)
        evidence = skill.collect_evidence(finding, code_context)
        if not code_context:
            logger.warning("No code context found")

        user_prompt = self._build_user_prompt(
            normalized, rag_context, evidence, code_context
        )

        try:
            raw = self.llm.chat(skill.system_prompt, user_prompt)
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
        if result["verdict"] not in _VALID_VERDICTS:
            logger.warning("Unexpected LLM verdict: %s", result["verdict"])
            return None

        # Clamp confidence to [0, 1]
        result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
        return result

    def verify(
        self,
        finding: Dict,
        initial_result: Dict,
        rag_context: List[str],
    ) -> Optional[Dict]:
        """
        Проверка результата основного LLM на логические расхождения и уверенность.

        Принимает на вход:
            finding:         Сырая сработка из ДД.
            initial_result:  Результат от основного LLM.
            rag_context:     Список с похожими сработками из RAG.

        Возвращает:
            Словарь {verdict, confidence, explanation, verified} или None
        """
        normalized = self._normalize_finding(finding)
        context_text = self._format_context(rag_context)
        user_prompt = (
            "Initial Analysis Result:\n"
            + json.dumps(initial_result, ensure_ascii=False, indent=2)
            + "\n\nKnown false-positive patterns from the knowledge base:\n"
            + context_text
            + "\n\nVerify this security finding against the initial triage result above:\n"
            + json.dumps(normalized, ensure_ascii=False, indent=2)
        )

        try:
            raw = self.llm.chat(_VERIFICATION_SYSTEM_PROMPT, user_prompt)
            result = json.loads(self._strip_markdown_fences(raw))
        except json.JSONDecodeError as e:
            logger.error("Verification LLM returned non-JSON response: %s | raw=%s", e, raw[:200])
            return None
        except Exception as e:
            logger.error("Verification LLM call failed: %s", e)
            return None

        if "verdict" not in result or "confidence" not in result:
            logger.warning("Unexpected verification LLM response structure: %s", result)
            return None

        result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
        result.setdefault("verified", True)
        return result

    @classmethod
    def _build_user_prompt(
        cls,
        normalized: Dict,
        rag_context: List[str],
        evidence: List[str],
        code_context: Optional[str],
    ) -> str:
        """
        Собирает user-промпт: RAG-контекст, детерминированные улики, код и finding.
        Все переменные данные находятся здесь, системный промпт скилла остаётся статичным.
        """
        parts = [
            "Known false-positive patterns from the knowledge base:",
            cls._format_context(rag_context),
        ]
        if evidence:
            parts.append("\nDeterministic evidence (collected by static checks):")
            parts.extend(f"- {item}" for item in evidence)
        code_block = cls._format_code_context(code_context)
        if code_block:
            parts.append(code_block)
        parts.append(
            "\nAnalyse this security finding:\n"
            + json.dumps(normalized, ensure_ascii=False, indent=2)
        )
        return "\n".join(parts)

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
