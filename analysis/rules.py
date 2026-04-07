"""
Модуль для определения и применения детерминированных правил для автоматической фильтрации 
ложноположительных результатов в DefectDojo.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple


@dataclass
class Rule:
    name: str
    description: str
    check: Callable[[Dict], bool]
    verdict: str = "false-positive"
    confidence: float = 0.9


# Блок правил для автоматической фильтрации сработок.

def _severity_out_of_scope(finding: Dict) -> bool:
    """
    Фильтр по низкой критичности: сработки с severity Info/Low 
    """
    severity = (finding.get("severity") or "").lower()
    return severity in ("info", "informational", "low")


def _is_test_file(finding: Dict) -> bool:
    """Фильтр по тестовым файлам: сработки внутри директорий test/spec не попадают в продакшн."""
    path = (
        finding.get("file_path")
        or finding.get("sast_source_file_path")
        or ""
    )
    return bool(
        re.search(
            r"[/_\-](test|tests|spec|specs|mock|mocks|fixture|fixtures|example|sample)[/_\-.]",
            path,
            re.IGNORECASE,
        )
    )


def _is_documentation_file(finding: Dict) -> bool:
    """Фильтр по документационным файлам: сработки внутри файлов документации не попадают в продакшн."""
    path = finding.get("file_path") or finding.get("sast_source_file_path") or ""
    return bool(re.search(r"\.(md|rst|txt|adoc|asciidoc)$", path, re.IGNORECASE))


def _is_vendor_backport(finding: Dict) -> bool:
    """Фильтр по исправлениям от вендора: аналитические заметки явно указывают, что вендор уже внес исправление."""
    notes = finding.get("notes") or []
    keywords = (
        "патч от вендора",
        "vendor patch",
        "исправление вендора",
        "backported",
        "backport fix",
        "содержащее исправление",
        "содержит исправление",
    )
    for note in notes:
        entry = (note.get("entry") or "").lower()
        if any(kw in entry for kw in keywords):
            return True
    return False


def _is_already_mitigated(finding: Dict) -> bool:
    """Фильтр по уже смягченным/закрытым сработкам: сработки, уже помеченные как mitigated/closed в DefectDojo."""
    return bool(finding.get("is_mitigated")) and not finding.get("active", True)


# ------------------------------------------------------------------
# Регистрация правил и функция анализа сработок. Чтобы добавить новое правило, просто добавь новый объект Rule в список RULES с соответствующей функцией проверки.
# ------------------------------------------------------------------

RULES: List[Rule] = [
    Rule(
        name="severity_out_of_scope",
        description="Фильтр по низкой критичности: сработки с severity Info/Low",
        check=_severity_out_of_scope,
        confidence=0.95,
    ),
    Rule(
        name="test_file",
        description="Фильтр по тестовым файлам: сработки внутри директорий test/spec не попадают в продакшн.",
        check=_is_test_file,
        confidence=0.88,
    ),
    Rule(
        name="documentation_file",
        description="Фильтр по документационным файлам: сработки внутри файлов документации не попадают в продакшн.",
        check=_is_documentation_file,
        confidence=0.90,
    ),
    Rule(
        name="vendor_backport",
        description="Фильтр по исправлениям от вендора: аналитические заметки явно указывают, что вендор уже внес исправление.",
        check=_is_vendor_backport,
        confidence=0.87,
    ),
    Rule(
        name="already_mitigated",
        description="Фильтр по уже смягченным/закрытым сработкам: сработки, уже помеченные как mitigated/closed в DefectDojo.",
        check=_is_already_mitigated,
        confidence=0.95,
    ),
]


def analyze_finding(finding: Dict) -> Tuple[bool, str, float]:
    """
    Применяет все правила к сработке и возвращает первое совпадение.
    Returns:
        Tuple[is_false_positive, explanation, confidence]
    """
    for rule in RULES:
        if rule.check(finding):
            explanation = f"[Rule:{rule.name}] {rule.description}"
            return True, explanation, rule.confidence
    return False, "", 0.0
