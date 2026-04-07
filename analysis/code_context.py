"""
Сode_context работает для триажа сработок SAST. Цель обогатить контекст LLM для более точного обьяснения сработки
Читает локально файлы исхожного кода репозитория. Если файл слишком большой - обрезает.
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
    """
    Класс для получения контекста исходного кода для сработок SAST. 
    На вход принимает корневой путь репозитория и максимальное количество символов для контекста. 
    Метод get_context принимает словарь с данными finding, извлекает путь к файлу и номер строки, 
    пытается найти файл в репозитории, читает его содержимое и возвращает объект CodeContext 
    с обрезанным контекстом вокруг строки сработки.
    """

    def __init__(self, repo_root: str, max_chars: int = 24576, max_lines: int = 50):
        self.repo_root = Path(repo_root).resolve()
        self.max_chars = max_chars
        self.max_lines = max_lines

    def get_context(self, finding: Dict) -> Optional[CodeContext]:
        """
        Возвращает контекст исходного кода для сработки, или None, если недоступен
        """
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
        """
        Пробует progressively shorter суффиксы file_path, пока не найдется существующий файл в repo_root.
        """
        posix = PurePosixPath(file_path)
        parts = posix.parts
        start = 1 if parts and parts[0] == "/" else 0

        for i in range(start, len(parts)):
            candidate = self.repo_root / Path(*parts[i:])
            if candidate.is_file():
                return candidate
        return None

    def _read_and_truncate(self, path: Path, line: Optional[int]) -> CodeContext:
        """
        Читает файл и возвращает контекст вокруг указанной строки. Если файл слишком большой, обрезает его.
        """
        text = path.read_text(encoding="utf-8", errors="replace")
        all_lines = text.splitlines(keepends=True)
        total = len(all_lines)

        # Если файл помещается и по строкам и по символам — отдаём целиком
        if total <= self.max_lines and len(text) <= self.max_chars:
            return CodeContext(
                file_path_resolved=str(path),
                content=text,
                is_truncated=False,
                start_line=1,
                end_line=total,
                total_lines=total,
            )

        # Ограничение по строкам (основной лимит)
        limit = min(self.max_lines, self.max_chars // 80) if self.max_chars else self.max_lines

        if line and 0 < line <= total:
            half = limit // 2
            start = max(0, line - 1 - half)
            end = min(total, start + limit)
            start = max(0, end - limit)
        else:
            start = 0
            end = min(total, limit)

        content = "".join(all_lines[start:end])

        # Жесткое обрезание, если строки необычно длинные (например, минифицированный JS)
        if self.max_chars and len(content) > self.max_chars:
            content = content[: self.max_chars]

        return CodeContext(
            file_path_resolved=str(path),
            content=content,
            is_truncated=True,
            start_line=start + 1,
            end_line=start + len(all_lines[start:end]),
            total_lines=total,
        )
