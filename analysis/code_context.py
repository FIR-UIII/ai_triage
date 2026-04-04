"""
Source code context provider for SAST finding triage.

Reads source files from a local repository checkout and prepares
code snippets for LLM analysis.  When the file is too large for the
LLM context window, a window centred on the finding line is extracted.
"""

import logging
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class CodeContext:
    file_path_resolved: str
    content: str
    is_truncated: bool
    start_line: int
    end_line: int
    total_lines: int


class CodeContextProvider:
    """Resolves finding file paths against a local repo and reads source code."""

    def __init__(self, repo_root: str, max_chars: int = 24576):
        self.repo_root = Path(repo_root).resolve()
        self.max_chars = max_chars

    def get_context(self, finding: Dict) -> Optional[CodeContext]:
        """Return source code context for a finding, or None if unavailable."""
        file_path = finding.get("file_path") or finding.get("sast_source_file_path")
        if not file_path:
            return None

        resolved = self._resolve_path(file_path)
        if resolved is None:
            logger.warning("Could not resolve file_path '%s' under %s", file_path, self.repo_root)
            return None

        line = finding.get("line") or finding.get("sast_source_line")
        return self._read_and_truncate(resolved, line)

    def _resolve_path(self, file_path: str) -> Optional[Path]:
        """Try progressively shorter suffixes of file_path until one exists under repo_root."""
        posix = PurePosixPath(file_path)
        parts = posix.parts
        start = 1 if parts and parts[0] == "/" else 0

        for i in range(start, len(parts)):
            candidate = self.repo_root / Path(*parts[i:])
            if candidate.is_file():
                return candidate
        return None

    def _read_and_truncate(self, path: Path, line: Optional[int]) -> CodeContext:
        """Read file; return full content or a window centred on *line*."""
        text = path.read_text(encoding="utf-8", errors="replace")
        all_lines = text.splitlines(keepends=True)
        total = len(all_lines)

        if len(text) <= self.max_chars:
            return CodeContext(
                file_path_resolved=str(path),
                content=text,
                is_truncated=False,
                start_line=1,
                end_line=total,
                total_lines=total,
            )

        max_lines = self.max_chars // 80

        if line and 0 < line <= total:
            half = max_lines // 2
            start = max(0, line - 1 - half)
            end = min(total, start + max_lines)
            start = max(0, end - max_lines)
        else:
            start = 0
            end = min(total, max_lines)

        content = "".join(all_lines[start:end])

        # Hard-truncate if lines are unusually long (e.g. minified JS)
        if len(content) > self.max_chars:
            content = content[: self.max_chars]

        return CodeContext(
            file_path_resolved=str(path),
            content=content,
            is_truncated=True,
            start_line=start + 1,
            end_line=start + len(all_lines[start:end]),
            total_lines=total,
        )
