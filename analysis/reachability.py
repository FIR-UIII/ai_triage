"""
Reachability analysis module.

Provides an abstract interface and concrete implementations for determining
whether a vulnerable code path is actually reachable from an attacker-controlled
source (user input, network, file system, etc.).

Concrete implementations:
  - SemgrepReachabilityAnalyzer  – uses Semgrep dataflow rules
  - CodeQLReachabilityAnalyzer   – uses a pre-built CodeQL database
  - CompositeReachabilityAnalyzer – combines multiple analyzers by confidence vote

Integration into the triage pipeline:
  - Only applicable to SAST findings (those with sast_source_file_path set).
  - Results downgrade confidence when the path is proven unreachable.
  - CI/CD: build the CodeQL DB in the pipeline; pass db_path via env var.

DFD/CFG notes:
  The implementations below use tool-generated CFGs/DFDs.  For a language-agnostic
  lightweight alternative, see the NetworkxCFGAnalyzer stub which consumes a
  pre-computed CFG exported as a JSON node-edge list.
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


# ------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------


@dataclass
class ReachabilityResult:
    is_reachable: bool
    confidence: float  # [0.0, 1.0]; 0 = analysis unavailable
    explanation: str
    source: str  # Tool name / identifier
    flow_paths: List[str] = field(default_factory=list)


# ------------------------------------------------------------------
# Abstract base
# ------------------------------------------------------------------


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


# ------------------------------------------------------------------
# Semgrep implementation
# ------------------------------------------------------------------


class SemgrepReachabilityAnalyzer(BaseReachabilityAnalyzer):
    """Uses Semgrep dataflow/taint rules to detect reachable sinks.

    Pipeline integration:
        semgrep --config=auto --dataflow-traces --json <target>

    Recommended for: web/API backends (Python, Java, JS, Go).
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


# ------------------------------------------------------------------
# CodeQL implementation
# ------------------------------------------------------------------


class CodeQLReachabilityAnalyzer(BaseReachabilityAnalyzer):
    """Uses a pre-built CodeQL database to check data-flow reachability.

    CI/CD integration:
        # Build phase (once per repository / on source change):
        codeql database create codeql-db --language=python --source-root=.

        # Analysis phase (per finding):
        Pass db_path=os.environ["CODEQL_DB_PATH"] to the constructor.

    Supports: Java, Python, JavaScript, C/C++, C#, Go, Ruby.
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
        """Generate a minimal CodeQL taint-tracking query for the given sink."""
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


# ------------------------------------------------------------------
# Composite (ensemble) analyzer
# ------------------------------------------------------------------


class CompositeReachabilityAnalyzer(BaseReachabilityAnalyzer):
    """Runs all available analyzers, combines results by confidence-weighted vote."""

    def __init__(self, analyzers: List[BaseReachabilityAnalyzer]):
        self.analyzers = analyzers

    def is_available(self) -> bool:
        return any(a.is_available() for a in self.analyzers)

    def analyze(
        self, finding: Dict, source_root: Optional[str] = None
    ) -> ReachabilityResult:
        available = [a for a in self.analyzers if a.is_available()]
        if not available:
            return self._unavailable("No reachability analyzers available")

        results = [a.analyze(finding, source_root) for a in available]

        reachable_conf = sum(r.confidence for r in results if r.is_reachable)
        not_reachable_conf = sum(r.confidence for r in results if not r.is_reachable)

        if reachable_conf >= not_reachable_conf:
            best = max((r for r in results if r.is_reachable), key=lambda r: r.confidence)
        else:
            best = max((r for r in results if not r.is_reachable), key=lambda r: r.confidence)

        tools = ", ".join(r.source for r in results)
        return ReachabilityResult(
            is_reachable=best.is_reachable,
            confidence=best.confidence,
            explanation=best.explanation,
            source=f"composite({tools})",
            flow_paths=best.flow_paths,
        )
