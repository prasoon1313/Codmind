"""Recursive, deterministic and non-executing discovery of Python sources."""
from __future__ import annotations

import fnmatch
import io
import os
import tokenize
from pathlib import Path
from typing import Iterator

from codemind.config import DEFAULT_IGNORED_DIRS, Config
from codemind.models import ProjectInfo, ScanIssue
from codemind.parser import parse_source


def _excluded(rel: str, name: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        pat = pattern.rstrip("/")
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat + "/*"):
            return True
    return False


def _ignored_dir(directory: Path, rel: str, name: str, config: Config) -> bool:
    if name in DEFAULT_IGNORED_DIRS or name.endswith(".egg-info"):
        return True
    if (directory / "pyvenv.cfg").exists():  # a virtual environment under any name
        return True
    return _excluded(rel, name, config.exclude)


def iter_python_files(root: Path, config: Config, issues: list[ScanIssue]) -> Iterator[Path]:
    """Yield ``*.py`` files under ``root`` in sorted order, pruning ignored folders."""
    root_resolved = root.resolve()
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept = []
        for name in sorted(dirnames):
            directory = current_path / name
            rel = directory.relative_to(root).as_posix()
            if directory.is_symlink() or _ignored_dir(directory, rel, name, config):
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = current_path / name
            rel = path.relative_to(root).as_posix()
            if _excluded(rel, name, config.exclude):
                continue
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError):
                issues.append(ScanIssue(rel, "unreadable", "cannot resolve path"))
                continue
            if not resolved.is_relative_to(root_resolved):
                issues.append(ScanIssue(rel, "skipped", "symlink points outside the project root"))
                continue
            yield path


def _decode(data: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    return data.decode(encoding)


def scan_project(root: Path, config: Config) -> ProjectInfo:
    """Parse every Python file below ``root``; failures become :class:`ScanIssue`."""
    project = ProjectInfo(root=root, package_prefix=root.resolve().name if (root / "__init__.py").exists() else "")
    limit = config.max_file_size_kb * 1024
    for path in iter_python_files(root, config, project.issues):
        rel = path.relative_to(root).as_posix()
        project.files_found += 1
        try:
            size = path.stat().st_size
            if size > limit:
                project.issues.append(ScanIssue(rel, "too_large", f"{size // 1024} KiB exceeds limit of {config.max_file_size_kb} KiB"))
                continue
            source = _decode(path.read_bytes())
        except OSError as exc:
            project.issues.append(ScanIssue(rel, "unreadable", f"{exc.strerror or exc}"))
            continue
        except (SyntaxError, LookupError, UnicodeDecodeError) as exc:
            project.issues.append(ScanIssue(rel, "unreadable", f"cannot decode source: {exc}"))
            continue
        try:
            project.modules.append(parse_source(source, rel))
        except SyntaxError as exc:
            project.issues.append(ScanIssue(rel, "syntax_error", f"{exc.msg} (line {exc.lineno})", exc.lineno or 1))
        except (ValueError, RecursionError, MemoryError) as exc:
            project.issues.append(ScanIssue(rel, "syntax_error", f"cannot parse: {type(exc).__name__}: {exc}"))
    project.modules.sort(key=lambda m: m.path)
    project.issues.sort(key=lambda i: (i.path, i.kind))
    return project
