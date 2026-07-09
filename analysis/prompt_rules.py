"""
Модуль для загрузки и применения конфигурируемых правил промптов из prompt_rules.yaml.
Заменяет собой хардкод-правила из analysis/rules.py и добавляет точечную настройку LLM-триажа:
 - scanners: базовые блоки системного промпта по типу сканера (подстрока test_name);
 - rules с verdict: детерминированные правила — принудительный вердикт без вызова LLM
   (первое совпавшее по порядку YAML побеждает);
 - rules с prompt_addition: точечные добавки к системному промпту для конкретных
   сработок (title, vuln_id_from_tool, file_path и т.д.); применяются все совпавшие.
Все условия внутри одного match-блока объединяются по AND.
Если файл отсутствует — движок работает без этих правил; если файл невалиден — ошибка загрузки.
"""

import fnmatch
import logging
import re
from pathlib import Path
from typing import Dict, List, Literal, Optional, Pattern, Tuple, Union

import yaml
from pydantic import BaseModel, Field, PrivateAttr, ValidationError, field_validator, model_validator

logger = logging.getLogger(__name__)


class ScannerPromptBlock(BaseModel):
    """
    Базовый блок промпта для типа сканера. test_name сравнивается как подстрока
    (без учета регистра) с полем test_name сработки из DefectDojo,
    т.к. имена тестов варьируются ("Semgrep JSON Report", "Gitleaks Scan" и т.п.).
    """
    test_name: str
    prompt: str

    def matches(self, finding: Dict) -> bool:
        finding_test_name = (finding.get("test_name") or "").lower()
        return self.test_name.lower() in finding_test_name


class MatchCriteria(BaseModel):
    """
    Условия совпадения правила со сработкой. Все заданные условия объединяются по AND.
    Должно быть задано хотя бы одно условие.
    """
    title: Optional[str] = None
    title_regex: Optional[str] = None
    vuln_id_from_tool: Optional[Union[str, List[str]]] = None
    test_name: Optional[str] = None
    file_path_glob: Optional[str] = None
    file_path_regex: Optional[str] = None
    severity: Optional[List[str]] = None
    cwe: Optional[Union[int, List[int]]] = None
    notes_contains: Optional[List[str]] = None
    is_mitigated: Optional[bool] = None
    active: Optional[bool] = None

    _title_re: Optional[Pattern] = PrivateAttr(default=None)
    _file_path_re: Optional[Pattern] = PrivateAttr(default=None)

    @field_validator("vuln_id_from_tool")
    @classmethod
    def _normalize_vuln_ids(cls, v):
        if isinstance(v, str):
            return [v]
        return v

    @field_validator("cwe")
    @classmethod
    def _normalize_cwe(cls, v):
        if isinstance(v, int):
            return [v]
        return v

    @model_validator(mode="after")
    def _validate_and_compile(self):
        # Хотя бы одно условие должно быть задано
        if not any(
            getattr(self, name) is not None
            for name in self.__class__.model_fields
        ):
            raise ValueError("match block must contain at least one criterion")
        # Компиляция regex на этапе валидации: fail fast на кривом выражении + кэш
        try:
            if self.title_regex is not None:
                self._title_re = re.compile(self.title_regex, re.IGNORECASE)
            if self.file_path_regex is not None:
                self._file_path_re = re.compile(self.file_path_regex, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"invalid regex '{e.pattern}': {e}") from e
        return self

    def matches(self, finding: Dict) -> bool:
        if self.title is not None and finding.get("title") != self.title:
            return False
        if self._title_re is not None and not self._title_re.search(finding.get("title") or ""):
            return False
        if self.vuln_id_from_tool is not None:
            if finding.get("vuln_id_from_tool") not in self.vuln_id_from_tool:
                return False
        if self.test_name is not None:
            if self.test_name.lower() not in (finding.get("test_name") or "").lower():
                return False
        path = finding.get("file_path") or finding.get("sast_source_file_path") or ""
        if self.file_path_glob is not None and not fnmatch.fnmatch(path, self.file_path_glob):
            return False
        if self._file_path_re is not None and not self._file_path_re.search(path):
            return False
        if self.severity is not None:
            allowed = {s.lower() for s in self.severity}
            if (finding.get("severity") or "").lower() not in allowed:
                return False
        if self.cwe is not None and finding.get("cwe") not in self.cwe:
            return False
        if self.notes_contains is not None:
            notes = finding.get("notes") or []
            entries = [(note.get("entry") or "").lower() for note in notes]
            if not any(kw.lower() in entry for entry in entries for kw in self.notes_contains):
                return False
        if self.is_mitigated is not None and bool(finding.get("is_mitigated")) != self.is_mitigated:
            return False
        if self.active is not None and bool(finding.get("active", True)) != self.active:
            return False
        return True


class ForcedVerdict(BaseModel):
    """Принудительный вердикт, выставляемый без вызова LLM."""
    value: Literal["false-positive", "needs-review"]
    confidence: float = Field(0.9, ge=0.0, le=1.0)
    explanation: str = ""


class PromptRule(BaseModel):
    """
    Точечное правило. Содержит РОВНО ОДНО из двух действий:
     - prompt_addition: текст, добавляемый к системному промпту LLM;
     - verdict: принудительный вердикт, минуя LLM.
    """
    name: str
    match: MatchCriteria
    prompt_addition: Optional[str] = None
    verdict: Optional[ForcedVerdict] = None

    @model_validator(mode="after")
    def _validate_action(self):
        if (self.prompt_addition is None) == (self.verdict is None):
            raise ValueError(
                f"rule '{self.name}': exactly one of prompt_addition / verdict must be set"
            )
        return self


class PromptRulesConfig(BaseModel):
    """Корневая модель конфигурации prompt_rules.yaml."""
    version: int = 1
    scanners: List[ScannerPromptBlock] = Field(default_factory=list)
    rules: List[PromptRule] = Field(default_factory=list)

    def scanner_prompt(self, finding: Dict) -> Optional[str]:
        """Возвращает промпт первого scanner-блока, чей test_name совпал со сработкой."""
        for block in self.scanners:
            if block.matches(finding):
                return block.prompt
        return None

    def forced_verdict(self, finding: Dict) -> Optional[Tuple[str, ForcedVerdict]]:
        """Возвращает (имя правила, вердикт) первого совпавшего verdict-правила по порядку YAML."""
        for rule in self.rules:
            if rule.verdict is not None and rule.match.matches(finding):
                return rule.name, rule.verdict
        return None

    def prompt_additions(self, finding: Dict) -> List[Tuple[str, str]]:
        """Возвращает [(имя правила, текст добавки)] для всех совпавших prompt_addition-правил."""
        return [
            (rule.name, rule.prompt_addition)
            for rule in self.rules
            if rule.prompt_addition is not None and rule.match.matches(finding)
        ]


def load_prompt_rules(path: str) -> Optional[PromptRulesConfig]:
    """
    Загружает и валидирует конфигурацию правил промптов.

    Возвращает:
        None, если файл отсутствует (движок работает без правил — как раньше).
        PromptRulesConfig при успешной загрузке (пустой файл → пустой конфиг).

    Бросает:
        ValueError с текстом ошибки yaml/pydantic, если файл есть, но невалиден —
        молча игнорировать конфиг оператора нельзя.
    """
    file_path = Path(path)
    if not file_path.exists():
        logger.warning(
            "Prompt rules file not found: %s — deterministic rules and custom prompts disabled",
            path,
        )
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {path}: {e}") from e

    if data is None:
        data = {}

    try:
        config = PromptRulesConfig.model_validate(data)
    except ValidationError as e:
        raise ValueError(f"Invalid prompt rules config {path}:\n{e}") from e

    logger.info(
        "Loaded prompt rules from %s: %d scanner blocks, %d verdict rules, %d prompt additions",
        path,
        len(config.scanners),
        sum(1 for r in config.rules if r.verdict is not None),
        sum(1 for r in config.rules if r.prompt_addition is not None),
    )
    return config
