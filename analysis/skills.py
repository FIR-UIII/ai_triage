"""
Модуль скиллов для триажа: классифицирует сработку по типу (SCA / SAST / generic) и
подбирает под неё специализированный системный промпт и детерминированные сборщики улик.

Архитектура «роутер + скиллы»: классификация и сбор улик выполняются на Python без LLM,
LLM получает уже специализированный промпт и подготовленные улики одним вызовом.
Чтобы добавить новый скилл — создай Skill с промптом и функцией collect_evidence
и зарегистрируй его в _SKILLS.
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class FindingCategory(str, Enum):
    SCA = "sca"
    SAST = "sast"
    GENERIC = "generic"


def classify_finding(finding: Dict) -> FindingCategory:
    """
    Детерминированная классификация сработки по её полям, без LLM.
     - SCA: есть компонент или CVE — уязвимость в сторонней зависимости.
     - SAST: есть локация в исходном коде (file_path + line), CWE или флаг static_finding.
     - GENERIC: всё остальное.
    """
    if finding.get("component_name") or finding.get("vulnerability_ids"):
        return FindingCategory.SCA

    file_path = finding.get("file_path") or finding.get("sast_source_file_path")
    line = finding.get("line") or finding.get("sast_source_line")
    if (file_path and line) or finding.get("static_finding") or finding.get("cwe"):
        return FindingCategory.SAST

    return FindingCategory.GENERIC


@dataclass(frozen=True)
class Skill:
    """
    Скилл = специализация анализа под категорию сработки:
    статический системный промпт (общая часть кэшируется LLM-сервером как префикс)
    и функция сбора детерминированных улик, результат которой попадает в user-промпт.
    """
    category: FindingCategory
    system_prompt: str
    collect_evidence: Callable[[Dict, Optional[str]], List[str]]


# ---------------------------------------------------------------------------
# Системные промпты
#
# Все промпты статичны (без .format с переменными данными) — это позволяет
# LLM-серверу переиспользовать кэш префикса между запросами.
# Переменные данные (RAG-контекст, улики, код, finding) передаются в user-промпте.
# ---------------------------------------------------------------------------

# Общий блок с форматом ответа: три класса вердикта вместо двух.
_VERDICT_SCHEMA = """\
Respond with valid JSON only:
{
  "verdict": "false-positive" | "likely-true-positive" | "needs-review",
  "confidence": <float 0.0-1.0>,
  "explanation": "<string>"
}

Verdict meaning:
- "false-positive": the finding is not exploitable / not applicable; evidence supports dismissing it.
- "likely-true-positive": evidence indicates a real, reachable vulnerability that should be prioritised.
- "needs-review": evidence is genuinely contradictory or insufficient to decide either way."""

SAST_SYSTEM_PROMPT = """\
You are an expert application security engineer triaging a SAST (static analysis) finding.
Decide whether it is a false-positive, a likely true positive, or genuinely needs manual review.

How to decide:
1. Reason PRIMARILY from the provided source code: trace whether attacker-controlled data can
   reach the flagged sink without sanitization.
2. Knowledge-base patterns and deterministic evidence are supporting signals. The ABSENCE of
   knowledge-base context is NOT a reason to answer needs-review — judge by the code.
3. Do NOT hallucinate code, sanitizers, or framework behaviour not visible in the context.
4. Explanation must be factual, concise, max 100 words.

Common false-positive indicators by vulnerability class:
- Injection (SQLi, command, LDAP): parameterized queries / prepared statements, ORM query builders,
  allow-list validation, constant or config-derived input.
- XSS: template auto-escaping (Jinja2/Django/Handlebars default), explicit escaping or encoding
  (escape(), encodeURIComponent, url_for, |e filter), Content-Security-Policy noted in code,
  value not user-controlled (build-time or server-generated identifiers).
- Path traversal: path normalization + prefix check, allow-list of filenames, no user input in path.
- Crypto / secrets: test fixtures, example or placeholder values, public keys, non-production config.
- Any: dead code, code inside test/mock/fixture directories, commented-out code.

Likely-true-positive indicators:
- User-controlled input (request params, headers, body) reaches the sink with no sanitization visible.
- String concatenation or interpolation directly into SQL/command/HTML with tainted data.
- Disabled escaping (| safe, dangerouslySetInnerHTML, autoescape off) applied to dynamic data.

""" + _VERDICT_SCHEMA

SCA_SYSTEM_PROMPT = """\
You are an expert application security engineer triaging an SCA (dependency / CVE) finding.
Decide whether it is a false-positive, a likely true positive, or genuinely needs manual review.

How to decide:
1. Compare the component version against the vulnerable/fixed version range stated in the
   finding description. If the installed version is at or above the fixed version -> false-positive.
2. Deterministic evidence below may already contain a version comparison or vendor-backport note —
   treat it as high-quality signal.
3. Vendor backports: if analyst notes state the vendor shipped a backported fix for this CVE in the
   installed version -> false-positive.
4. Dev-only / test-only dependencies that never ship to production are strong false-positive signals.
5. Do NOT hallucinate CVE details, affected ranges, or patch versions not present in the provided data.
6. The ABSENCE of knowledge-base context is NOT a reason to answer needs-review — judge by the
   version data provided.
7. Explanation must be factual, concise, max 100 words.

Likely-true-positive indicators:
- Installed version is inside the affected range and no backport/mitigation note exists.
- The vulnerable component is a direct runtime dependency.

""" + _VERDICT_SCHEMA

GENERIC_SYSTEM_PROMPT = """\
You are an expert application security engineer performing automated triage of a security finding.
Decide whether it is a false-positive, a likely true positive, or genuinely needs manual review.

Rules:
1. Base your decision ONLY on the provided context and finding data.
2. Do NOT hallucinate CVE details, component versions, or patch information.
3. If knowledge-base patterns clearly match the finding -> false-positive.
4. If source code is provided, use it to verify whether the vulnerability is exploitable in context.
5. Answer needs-review only when the evidence is genuinely insufficient or contradictory.
6. Explanation must be factual, concise, max 100 words.

""" + _VERDICT_SCHEMA


# ---------------------------------------------------------------------------
# Сборщики улик (детерминированные, без LLM)
# ---------------------------------------------------------------------------

# Названия групп CWE для подсказки модели, какой класс уязвимости анализируется.
_CWE_GROUPS = {
    79: "XSS", 80: "XSS", 83: "XSS",
    89: "SQL injection", 564: "SQL injection",
    77: "Command injection", 78: "Command injection",
    22: "Path traversal", 23: "Path traversal",
    798: "Hardcoded credentials", 259: "Hardcoded credentials", 321: "Hardcoded credentials",
    327: "Weak cryptography", 328: "Weak cryptography", 326: "Weak cryptography",
    502: "Insecure deserialization",
    611: "XXE",
    918: "SSRF",
    352: "CSRF",
}

# Паттерны санитайзеров/безопасных конструкций в коде рядом со сработкой.
_SANITIZER_PATTERNS = [
    (r"\burl_for\s*\(", "url_for()"),
    (r"\bescape\s*\(|\|\s*e\b|\|\s*escape\b", "escape filter/call"),
    (r"encodeURIComponent|encodeURI\b", "URI encoding"),
    (r"htmlspecialchars|htmlentities", "HTML encoding"),
    (r"\bparameteriz|prepared\s*statement|\?\s*,\s*\[|execute\s*\(\s*[\"'][^\"']*%s", "parameterized query"),
    (r"sanitiz", "sanitizer call"),
    (r"DOMPurify", "DOMPurify"),
    (r"secure_filename|os\.path\.normpath|path\.normalize", "path normalization"),
]

# Паттерны опасных конструкций — сигнал в сторону likely-true-positive.
_DANGER_PATTERNS = [
    (r"\|\s*safe\b|autoescape\s+(off|false)|dangerouslySetInnerHTML|innerHTML\s*=", "escaping disabled"),
    (r"request\.(args|form|params|body|GET|POST|query)", "user-controlled input nearby"),
    (r"eval\s*\(|exec\s*\(", "dynamic code execution"),
]

_TEST_PATH_RE = re.compile(
    r"[/_\-](test|tests|spec|specs|mock|mocks|fixture|fixtures|example|sample)[/_\-.]",
    re.IGNORECASE,
)

# Ключевые слова vendor backport — те же, что в analysis/rules.py, но здесь используются
# как улика для LLM, а не как жёсткое правило (правило срабатывает раньше, на Шаге 1).
_BACKPORT_KEYWORDS = (
    "патч от вендора",
    "vendor patch",
    "исправление вендора",
    "backported",
    "backport fix",
    "содержащее исправление",
    "содержит исправление",
)

# Паттерны для извлечения фиксированной версии из описания CVE.
_FIXED_VERSION_RES = [
    re.compile(r"fixed\s+in\s+(?:version\s+)?v?(\d+(?:\.\d+)+)", re.IGNORECASE),
    re.compile(r"upgrade\s+to\s+(?:version\s+)?v?(\d+(?:\.\d+)+)", re.IGNORECASE),
    re.compile(r"(?:versions?\s+)?(?:before|prior\s+to|<)\s*v?(\d+(?:\.\d+)+)", re.IGNORECASE),
    re.compile(r"patched\s+in\s+(?:version\s+)?v?(\d+(?:\.\d+)+)", re.IGNORECASE),
]


def _version_tuple(version: str) -> Optional[tuple]:
    """
    Превращает строку версии в кортеж чисел для сравнения ("1.2.10" > "1.2.9").
    Возвращает None, если версия не парсится — тогда сравнение не проводим.
    """
    match = re.match(r"v?(\d+(?:\.\d+)*)", version.strip())
    if not match:
        return None
    return tuple(int(p) for p in match.group(1).split("."))


def _collect_sast_evidence(finding: Dict, code_context: Optional[str]) -> List[str]:
    """
    Улики для SAST: группа CWE, тестовый путь, санитайзеры и опасные конструкции в код-контексте.
    """
    evidence: List[str] = []

    cwe = finding.get("cwe")
    if cwe:
        group = _CWE_GROUPS.get(int(cwe))
        evidence.append(f"CWE-{cwe}" + (f" ({group})" if group else ""))

    path = finding.get("file_path") or finding.get("sast_source_file_path") or ""
    if path and _TEST_PATH_RE.search(path):
        evidence.append("File path matches test/mock/fixture directory pattern")

    if code_context:
        found_safe = [label for pattern, label in _SANITIZER_PATTERNS if re.search(pattern, code_context)]
        if found_safe:
            evidence.append("Sanitizer-like constructs in code context: " + ", ".join(sorted(set(found_safe))))
        found_danger = [label for pattern, label in _DANGER_PATTERNS if re.search(pattern, code_context)]
        if found_danger:
            evidence.append("Risk indicators in code context: " + ", ".join(sorted(set(found_danger))))
    else:
        evidence.append("Source code context is NOT available for this finding")

    return evidence


def _collect_sca_evidence(finding: Dict, code_context: Optional[str]) -> List[str]:
    """
    Улики для SCA: сравнение установленной версии с фиксированной из описания,
    заметки о vendor backport, компонент и CVE.
    """
    evidence: List[str] = []

    component = finding.get("component_name")
    version = finding.get("component_version")
    if component:
        evidence.append(f"Component: {component}" + (f" {version}" if version else " (version unknown)"))

    cves = [v.get("vulnerability_id", "") for v in (finding.get("vulnerability_ids") or [])]
    cves = [c for c in cves if c]
    if cves:
        evidence.append("Vulnerability IDs: " + ", ".join(cves))

    # Сравнение версий: извлекаем фиксированную версию из описания и сравниваем с установленной
    description = finding.get("description") or ""
    installed = _version_tuple(version) if version else None
    if installed:
        for regex in _FIXED_VERSION_RES:
            match = regex.search(description)
            if match:
                fixed = _version_tuple(match.group(1))
                if fixed:
                    if installed >= fixed:
                        evidence.append(
                            f"Version check: installed {version} >= fixed {match.group(1)} "
                            "(installed version appears to already contain the fix)"
                        )
                    else:
                        evidence.append(
                            f"Version check: installed {version} < fixed {match.group(1)} "
                            "(installed version appears to be affected)"
                        )
                break

    # Vendor backport в заметках аналитиков
    for note in finding.get("notes") or []:
        entry = (note.get("entry") or "").lower()
        if any(kw in entry for kw in _BACKPORT_KEYWORDS):
            evidence.append("Analyst notes mention a vendor backport/fix for this finding")
            break

    return evidence


def _collect_generic_evidence(finding: Dict, code_context: Optional[str]) -> List[str]:
    """Для generic-категории специализированных улик нет."""
    return []


# ---------------------------------------------------------------------------
# Реестр скиллов
# ---------------------------------------------------------------------------

_SKILLS: Dict[FindingCategory, Skill] = {
    FindingCategory.SAST: Skill(
        category=FindingCategory.SAST,
        system_prompt=SAST_SYSTEM_PROMPT,
        collect_evidence=_collect_sast_evidence,
    ),
    FindingCategory.SCA: Skill(
        category=FindingCategory.SCA,
        system_prompt=SCA_SYSTEM_PROMPT,
        collect_evidence=_collect_sca_evidence,
    ),
    FindingCategory.GENERIC: Skill(
        category=FindingCategory.GENERIC,
        system_prompt=GENERIC_SYSTEM_PROMPT,
        collect_evidence=_collect_generic_evidence,
    ),
}


def get_skill(finding: Dict) -> Skill:
    """
    Возвращает скилл для сработки: классифицирует её и отдаёт соответствующий Skill.
    """
    category = classify_finding(finding)
    logger.debug("[%s] classified as %s", finding.get("id"), category.value)
    return _SKILLS[category]
