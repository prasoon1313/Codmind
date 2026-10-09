"""Duplicate-code detection on normalised AST statement sequences (CM304)."""
from __future__ import annotations

import ast
import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from codemind.astutils import FUNCTION_TYPES, child_blocks, node_count, normalize
from codemind.models import Confidence, Finding, ModuleInfo, ProjectInfo, Severity
from codemind.rules.base import Rule, RuleContext, RuleMeta, register

_TRIVIAL = (ast.Pass, ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)


@dataclass
class _Block:
    module: ModuleInfo
    symbol: str
    stmts: list[ast.stmt]


@dataclass(frozen=True)
class _Clone:
    module: ModuleInfo
    symbol: str
    start: int
    end: int
    count: int
    key: str
    others: tuple[tuple[str, int], ...]


def _collect(body: list[ast.stmt], symbol: str, module: ModuleInfo, blocks: list[_Block], funcs: list) -> None:
    blocks.append(_Block(module, symbol, body))
    for stmt in body:
        if isinstance(stmt, (*FUNCTION_TYPES, ast.ClassDef)):
            inner = f"{symbol}.{stmt.name}" if symbol else stmt.name
            if isinstance(stmt, FUNCTION_TYPES):
                funcs.append((module, inner, stmt))
            _collect(stmt.body, inner, module, blocks, funcs)
        else:
            for child in child_blocks(stmt):
                _collect(child, symbol, module, blocks, funcs)


def _digest(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _is_trivial(stmt: ast.stmt) -> bool:
    return isinstance(stmt, _TRIVIAL) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))


@register
class DuplicateCode(Rule):
    meta = RuleMeta(
        "CM304", "duplicate-code-block", "architecture", Severity.LOW, Confidence.MEDIUM,
        "A block of statements (or a whole function) is structurally identical to another one.",
        "Copy-pasted logic must be fixed in several places and the copies drift apart over time.",
        "Extract the shared logic into one function or class and call it from each place.",
        limitations="Clones are matched after abstracting identifiers and literal values (type-2 clones), so blocks that "
        "merely share shape may be reported. Blocks must contain at least 'duplicate_min_statements' statements and "
        "'duplicate_min_nodes' AST nodes. Reports are line-range based, not semantic equivalence proofs.",
    )

    def check_project(self, project: ProjectInfo, ctx: RuleContext) -> Iterable[Finding]:
        t = ctx.config.thresholds
        k, min_nodes = t.duplicate_min_statements, t.duplicate_min_nodes
        blocks: list[_Block] = []
        funcs: list = []
        for module in project.modules:
            _collect(module.tree.body, "", module, blocks, funcs)

        clones = self._window_clones(blocks, k, min_nodes) + self._function_clones(funcs, min_nodes)
        for clone in self._drop_contained(clones):
            shown = ", ".join(f"{p}:{ln}" for p, ln in clone.others[:3])
            extra = f" and {len(clone.others) - 3} more" if len(clone.others) > 3 else ""
            yield self.make(
                clone.module.path, clone.start,
                f"Duplicate block of {clone.count} statement(s) (lines {clone.start}-{clone.end}); similar code at {shown}{extra}.",
                symbol=clone.symbol, detail=clone.key[:12],
                severity=Severity.MEDIUM if clone.count >= 3 * k else Severity.LOW,
            )

    @staticmethod
    def _window_clones(blocks: list[_Block], k: int, min_nodes: int) -> list[_Clone]:
        norm: list[list[str]] = []
        sizes: list[list[int]] = []
        windows: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for bid, block in enumerate(blocks):
            norm.append([normalize(s) for s in block.stmts])
            sizes.append([node_count(s) for s in block.stmts])
            for i in range(len(block.stmts) - k + 1):
                chunk = block.stmts[i : i + k]
                if all(_is_trivial(s) for s in chunk) or sum(sizes[bid][i : i + k]) < min_nodes:
                    continue
                windows[_digest("|".join(norm[bid][i : i + k]))].append((bid, i))

        group_of: dict[tuple[int, int], tuple[tuple[int, int], ...]] = {}
        key_of: dict[tuple[int, int], str] = {}
        for key, occurrences in windows.items():
            kept: list[tuple[int, int]] = []
            for bid, i in sorted(occurrences):
                if kept and kept[-1][0] == bid and i < kept[-1][1] + k:
                    continue  # overlapping occurrence inside the same block
                kept.append((bid, i))
            if len(kept) >= 2:
                for occ in kept:
                    group_of[occ] = tuple(kept)
                    key_of[occ] = key

        def shifted(group: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
            return tuple((b, i + 1) for b, i in group)

        clones: list[_Clone] = []
        for (bid, i) in sorted(group_of):
            prev = (bid, i - 1)
            if prev in group_of and shifted(group_of[prev]) == group_of[(bid, i)]:
                continue  # continuation of a longer run already handled
            j = i
            while (bid, j + 1) in group_of and shifted(group_of[(bid, j)]) == group_of[(bid, j + 1)]:
                j += 1
            count = k + (j - i)
            block = blocks[bid]
            others = tuple(
                (blocks[ob].module.path, blocks[ob].stmts[oi].lineno)
                for ob, oi in group_of[(bid, i)] if (ob, oi) != (bid, i)
            )
            last = block.stmts[i + count - 1]
            clones.append(_Clone(block.module, block.symbol, block.stmts[i].lineno,
                                 getattr(last, "end_lineno", None) or last.lineno, count, key_of[(bid, i)], others))
        return clones

    @staticmethod
    def _function_clones(funcs: list, min_nodes: int) -> list[_Clone]:
        groups: dict[str, list[tuple[ModuleInfo, str, ast.AST]]] = defaultdict(list)
        for module, symbol, node in funcs:
            if node_count(node) >= min_nodes:
                groups[_digest("F" + normalize(node))].append((module, symbol, node))
        clones: list[_Clone] = []
        for key, members in groups.items():
            if len(members) < 2:
                continue
            for module, symbol, node in members:
                others = tuple((m.path, n.lineno) for m, s, n in members if n is not node)
                clones.append(_Clone(module, symbol, node.lineno, node.end_lineno or node.lineno,
                                     len(node.body), key, others))
        return clones

    @staticmethod
    def _drop_contained(clones: list[_Clone]) -> list[_Clone]:
        kept: list[_Clone] = []
        by_file: dict[str, list[_Clone]] = defaultdict(list)
        for clone in clones:
            by_file[clone.module.path].append(clone)
        for path in sorted(by_file):
            accepted: list[_Clone] = []
            for clone in sorted(by_file[path], key=lambda c: (c.start, -c.end, c.key)):
                if not any(a.start <= clone.start and a.end >= clone.end for a in accepted):
                    accepted.append(clone)
            kept.extend(accepted)
        return kept
