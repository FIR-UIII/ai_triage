"""
Класс для анализа достижимости (reachability) уязвимостей, используя инструменты статического анализа кода, 
такие как Semgrep и CodeQL.
Реализованы следующие классы:
- ReachabilityResult: структура для хранения результатов анализа достижимости.
- BaseReachabilityAnalyzer: абстрактный базовый класс для всех анализаторов достижимости.
- SemgrepReachabilityAnalyzer: реализация на основе Semgrep для языков с поддержкой dataflow.
- CodeQLReachabilityAnalyzer: реализация на основе CodeQL для языков с поддержкой dataflow.
"""

import json
import logging
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Модель данных для результатов анализа достижимости
@dataclass
class ReachabilityResult:
    is_reachable: bool
    confidence: float  # [0.0, 1.0]; 0 = analysis unavailable
    explanation: str
    source: str  # Tool name / identifier
    flow_paths: List[str] = field(default_factory=list)


class BaseReachabilityAnalyzer(ABC):
    @abstractmethod
    def analyze(
        self, finding: Dict, source_root: Optional[str] = None
    ) -> ReachabilityResult: ...

    @abstractmethod
    def is_available(self) -> bool: ...

    def _unavailable(self, reason: str) -> ReachabilityResult:
        return ReachabilityResult(
            is_reachable=False, confidence=0.0, explanation=reason, source=self.__class__.__name__
        )



# Semgrep

class SemgrepReachabilityAnalyzer(BaseReachabilityAnalyzer):
    """Класс SemgrepReachabilityAnalyzer использует правила dataflow/taint Semgrep для обнаружения достижимых sink'ов.

    Интеграция в пайплайн:
        semgrep --config=auto --dataflow-traces --json <target>

    """

    def __init__(self, semgrep_bin: str = "semgrep", config: str = "auto"):
        self.semgrep_bin = semgrep_bin
        self.config = config

    def is_available(self) -> bool:
        try:
            r = subprocess.run(
                [self.semgrep_bin, "--version"], capture_output=True, timeout=5
            )
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(
        self, finding: Dict, source_root: Optional[str] = None
    ) -> ReachabilityResult:
        target_file = finding.get("sast_source_file_path") or finding.get("file_path")
        if not target_file or not source_root:
            return self._unavailable("No target file or source root provided")

        try:
            result = subprocess.run(
                [
                    self.semgrep_bin,
                    "--config",
                    self.config,
                    "--json",
                    "--dataflow-traces",
                    "--include",
                    target_file,
                    source_root,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(result.stdout) if result.stdout else {}
            sgrep_findings = data.get("results", [])

            sink = finding.get("sast_sink_object") or ""
            matching = [f for f in sgrep_findings if sink and sink in str(f)]

            if matching:
                return ReachabilityResult(
                    is_reachable=True,
                    confidence=0.80,
                    explanation=f"Semgrep found {len(matching)} taint flow(s) to sink '{sink}'",
                    source="semgrep",
                    flow_paths=[str(m.get("path")) for m in matching[:3]],
                )
            return ReachabilityResult(
                is_reachable=False,
                confidence=0.65,
                explanation="Semgrep found no taint flow to the reported sink",
                source="semgrep",
            )
        except subprocess.TimeoutExpired:
            return self._unavailable("Semgrep timed out")
        except Exception as e:
            logger.error("Semgrep analysis error: %s", e)
            return self._unavailable(f"Semgrep error: {e}")


# CodeQL

class CodeQLReachabilityAnalyzer(BaseReachabilityAnalyzer):
    """Класс CodeQLReachabilityAnalyzer использует предсобранную базу данных CodeQL для проверки достижимости данных.

    CI/CD интеграция:
        # Этап сборки (один раз на репозиторий / при изменении исходного кода):
        codeql database create codeql-db --language=python --source-root=.

        # Этап анализа (для каждой сработки):
        Передайте db_path=os.environ["CODEQL_DB_PATH"] в конструктор.

    Поддерживаемые языки: Java, Python, JavaScript, C/C++, C#, Go, Ruby.
    """

    def __init__(self, codeql_bin: str = "codeql", db_path: Optional[str] = None):
        self.codeql_bin = codeql_bin
        self.db_path = db_path

    def is_available(self) -> bool:
        if not self.db_path or not Path(self.db_path).exists():
            return False
        try:
            r = subprocess.run(
                [self.codeql_bin, "version"], capture_output=True, timeout=5
            )
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(
        self, finding: Dict, source_root: Optional[str] = None
    ) -> ReachabilityResult:
        if not self.is_available():
            return self._unavailable("CodeQL database not available")

        sink = finding.get("sast_sink_object")
        if not sink:
            return self._unavailable("No sast_sink_object in finding")

        query = self._build_query(sink)
        with tempfile.NamedTemporaryFile(suffix=".ql", mode="w", delete=False) as f:
            f.write(query)
            query_file = f.name

        try:
            result = subprocess.run(
                [
                    self.codeql_bin,
                    "query",
                    "run",
                    query_file,
                    "--database",
                    self.db_path,
                    "--format=sarifv2.1.0",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            paths: List[str] = []
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                # Extract result locations from SARIF
                for run in data.get("runs", []):
                    for r in run.get("results", []):
                        loc = r.get("locations", [{}])[0]
                        paths.append(str(loc))

            return ReachabilityResult(
                is_reachable=len(paths) > 0,
                confidence=0.90 if paths else 0.75,
                explanation=f"CodeQL: {len(paths)} data-flow path(s) found" if paths else "CodeQL: no paths found",
                source="codeql",
                flow_paths=paths[:3],
            )
        except subprocess.TimeoutExpired:
            return self._unavailable("CodeQL timed out")
        except Exception as e:
            logger.error("CodeQL analysis error: %s", e)
            return self._unavailable(f"CodeQL error: {e}")
        finally:
            Path(query_file).unlink(missing_ok=True)

    @staticmethod
    def _build_query(sink: str) -> str:
        """Генерирует минимальный запрос CodeQL для отслеживания taint для данного sink."""
        return f"""\
/**
 * Auto-generated reachability query for sink: {sink}
 */
import DataFlow
import semmle.code.python.dataflow.TaintTracking

from DataFlow::Node source, DataFlow::Node sinkNode
where TaintTracking::localTaint(source, sinkNode)
  and sinkNode.toString().matches("%{sink}%")
select source, sinkNode, "Data flows to {sink}"
"""

