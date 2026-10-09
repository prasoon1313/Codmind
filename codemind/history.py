"""SQLite persistence, scan comparison and trend reporting."""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from codemind.analyzer import AnalysisResult
from codemind.models import Confidence, Finding, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    score REAL NOT NULL,
    grade TEXT NOT NULL,
    files INTEGER NOT NULL,
    loc INTEGER NOT NULL,
    functions INTEGER NOT NULL,
    classes INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    mean_complexity REAL NOT NULL,
    max_complexity INTEGER NOT NULL,
    mean_maintainability REAL NOT NULL,
    summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    detail TEXT NOT NULL,
    category TEXT NOT NULL,
    message TEXT NOT NULL,
    suggestion TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS function_metrics (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    qualname TEXT NOT NULL,
    complexity INTEGER NOT NULL,
    loc INTEGER NOT NULL,
    nesting INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id, id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_metrics_scan ON function_metrics(scan_id);
"""


class HistoryError(RuntimeError):
    """Raised for missing scans or unusable databases."""


def default_db_path() -> Path:
    import os

    override = os.environ.get("CODEMIND_DB")
    return Path(override).expanduser() if override else Path.home() / ".codemind" / "history.db"


class HistoryStore:
    """Stores scans of many projects in one SQLite file (parameterised SQL only)."""

    def __init__(self, db_path: Path) -> None:
        self.path = Path(db_path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(self.path))
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.executescript(SCHEMA)
        except (OSError, sqlite3.Error) as exc:
            raise HistoryError(f"cannot open history database {self.path}: {exc}") from None

    def __enter__(self) -> "HistoryStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    # -- writing -----------------------------------------------------------
    def save(self, result: AnalysisResult) -> int:
        """Persist ``result`` and return the new scan id."""
        summary = result.summary()
        payload = {
            "summary": summary,
            "score": result.score.to_dict(),
            "top_files": [s.to_dict() for s in result.top_files(10)],
            "priorities": result.priorities(),
            "config": result.config.to_dict(),
        }
        with self.conn:
            self.conn.execute("INSERT OR IGNORE INTO projects(root) VALUES (?)", (str(result.root),))
            project_id = self.conn.execute("SELECT id FROM projects WHERE root = ?", (str(result.root),)).fetchone()["id"]
            cursor = self.conn.execute(
                "INSERT INTO scans(project_id, created_at, score, grade, files, loc, functions, classes, finding_count,"
                " mean_complexity, max_complexity, mean_maintainability, summary_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (project_id, result.generated_at, summary["score"], summary["grade"], summary["files_analyzed"], summary["loc"],
                 summary["functions"], summary["classes"], summary["findings"], summary["mean_complexity"],
                 summary["max_complexity"], summary["mean_maintainability"], json.dumps(payload, sort_keys=True)),
            )
            scan_id = int(cursor.lastrowid)
            self.conn.executemany(
                "INSERT INTO findings(scan_id, fingerprint, rule_id, severity, confidence, path, line, symbol, detail,"
                " category, message, suggestion) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(scan_id, f.fingerprint, f.rule_id, f.severity.value, f.confidence.value, f.path, f.line, f.symbol,
                  f.detail, f.category, f.message, f.suggestion) for f in result.findings],
            )
            self.conn.executemany(
                "INSERT INTO function_metrics(scan_id, path, qualname, complexity, loc, nesting) VALUES (?,?,?,?,?,?)",
                [(scan_id, m.path, fn.qualname, fn.complexity, fn.loc, fn.max_nesting)
                 for m in result.project.modules for fn in m.functions],
            )
        result.scan_id = scan_id
        return scan_id

    # -- reading -----------------------------------------------------------
    def scan_row(self, scan_id: int) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT s.*, p.root AS root FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            raise HistoryError(f"scan {scan_id} not found in {self.path}")
        return row

    def latest_scan_id(self, root: Path) -> Optional[int]:
        row = self.conn.execute(
            "SELECT MAX(s.id) AS id FROM scans s JOIN projects p ON p.id = s.project_id WHERE p.root = ?",
            (str(root.resolve()),),
        ).fetchone()
        return row["id"] if row and row["id"] is not None else None

    def list_scans(self, root: Path) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT s.* FROM scans s JOIN projects p ON p.id = s.project_id WHERE p.root = ? ORDER BY s.id",
            (str(root.resolve()),),
        ))

    def findings_for(self, scan_id: int) -> list[Finding]:
        rows = self.conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY path, line, rule_id, id", (scan_id,))
        return [Finding(r["rule_id"], Severity(r["severity"]), r["path"], r["line"], r["message"], Confidence(r["confidence"]),
                        r["suggestion"], r["symbol"], r["detail"], r["category"]) for r in rows]

    def function_metrics(self, scan_id: int) -> dict[tuple[str, str], int]:
        metrics: dict[tuple[str, str], int] = {}
        for r in self.conn.execute("SELECT path, qualname, complexity FROM function_metrics WHERE scan_id = ?", (scan_id,)):
            key = (r["path"], r["qualname"])
            metrics[key] = max(metrics.get(key, 0), r["complexity"])
        return metrics

    def stored_report(self, scan_id: int) -> dict[str, Any]:
        row = self.scan_row(scan_id)
        payload = json.loads(row["summary_json"])
        return {"scan_id": scan_id, "root": row["root"], "created_at": row["created_at"], **payload,
                "findings": [f.to_dict() for f in self.findings_for(scan_id)]}

    # -- comparison and trends ----------------------------------------------
    def compare(self, before_id: int, after_id: int) -> dict[str, Any]:
        """Classify findings as new / resolved / persistent and diff complexity."""
        before, after = self.scan_row(before_id), self.scan_row(after_id)
        if before["project_id"] != after["project_id"]:
            raise HistoryError("the two scans belong to different projects")
        old, new = defaultdict(list), defaultdict(list)
        for f in self.findings_for(before_id):
            old[f.fingerprint].append(f)
        for f in self.findings_for(after_id):
            new[f.fingerprint].append(f)
        introduced, resolved, persistent = [], [], []
        for fp in sorted(set(old) | set(new)):
            o, n = old.get(fp, []), new.get(fp, [])
            common = min(len(o), len(n))
            persistent.extend(n[:common])
            introduced.extend(n[common:])
            resolved.extend(o[common:])
        key = lambda f: f.sort_key()  # noqa: E731
        m_old, m_new = self.function_metrics(before_id), self.function_metrics(after_id)
        changes = [{"path": p, "function": q, "before": m_old[(p, q)], "after": m_new[(p, q)], "delta": m_new[(p, q)] - m_old[(p, q)]}
                   for (p, q) in sorted(set(m_old) & set(m_new)) if m_old[(p, q)] != m_new[(p, q)]]
        added = [{"path": p, "function": q, "complexity": m_new[(p, q)]} for (p, q) in sorted(set(m_new) - set(m_old))]
        removed = [{"path": p, "function": q, "complexity": m_old[(p, q)]} for (p, q) in sorted(set(m_old) - set(m_new))]

        def brief(row: sqlite3.Row) -> dict[str, Any]:
            return {k: row[k] for k in ("id", "created_at", "score", "grade", "files", "loc", "functions", "finding_count",
                                        "mean_complexity", "max_complexity", "mean_maintainability")}

        return {
            "root": before["root"],
            "before": brief(before),
            "after": brief(after),
            "delta": {
                "score": round(after["score"] - before["score"], 2),
                "findings": after["finding_count"] - before["finding_count"],
                "loc": after["loc"] - before["loc"],
                "mean_complexity": round(after["mean_complexity"] - before["mean_complexity"], 3),
                "max_complexity": after["max_complexity"] - before["max_complexity"],
                "mean_maintainability": round(after["mean_maintainability"] - before["mean_maintainability"], 2),
            },
            "new_findings": [f.to_dict() for f in sorted(introduced, key=key)],
            "resolved_findings": [f.to_dict() for f in sorted(resolved, key=key)],
            "persistent_findings": [f.to_dict() for f in sorted(persistent, key=key)],
            "complexity_regressions": sorted((c for c in changes if c["delta"] > 0), key=lambda c: (-c["delta"], c["path"], c["function"])),
            "complexity_improvements": sorted((c for c in changes if c["delta"] < 0), key=lambda c: (c["delta"], c["path"], c["function"])),
            "added_functions": sorted(added, key=lambda c: (-c["complexity"], c["path"], c["function"])),
            "removed_functions": removed,
        }

    def trend(self, root: Path) -> list[dict[str, Any]]:
        rows, previous, trend = self.list_scans(root), None, []
        for r in rows:
            trend.append({
                "scan_id": r["id"], "created_at": r["created_at"], "score": r["score"], "grade": r["grade"],
                "findings": r["finding_count"], "loc": r["loc"], "mean_complexity": r["mean_complexity"],
                "max_complexity": r["max_complexity"],
                "score_delta": round(r["score"] - previous["score"], 2) if previous is not None else None,
                "findings_delta": r["finding_count"] - previous["finding_count"] if previous is not None else None,
            })
            previous = r
        return trend
