"""Complexity and maintainability metrics.

Cyclomatic complexity (McCabe) used here
----------------------------------------
``CC = 1 + number of decision points`` inside one function scope, where the
decision points are: ``if``/``elif``, ``for``, ``async for``, ``while``,
``except`` handlers, conditional expressions (``a if c else b``), each extra
operand of ``and``/``or``, every comprehension ``for`` clause plus each of
its ``if`` filters, and each ``match`` case (the wildcard ``case _`` is not
counted). Nested functions are measured separately; ``assert``, ``with`` and
``try``/``finally`` do not add paths.

Maintainability index (per function and per module)
---------------------------------------------------
The classic formula, rescaled to 0-100::

    MI = max(0, (171 - 5.2*ln(V) - 0.23*CC - 16.2*ln(LOC)) * 100 / 171)

``V`` is a Halstead volume computed from the tokens (operators = punctuation
and keywords, operands = names/numbers/strings), ``CC`` is the cyclomatic
complexity (module level: sum over all functions) and ``LOC`` counts
non-blank, non-comment lines. Module-level bands used in reports: >=40 good,
20-40 moderate, <20 poor (whole modules score lower than single functions because
size is penalised). Function-level values of ~70 or more are good.
It is an indicator, not a measurement of quality.
"""
from __future__ import annotations

import ast
import io
import keyword
import math
import textwrap
import tokenize
from collections import Counter
from typing import Sequence

from codemind.astutils import FUNCTION_TYPES, child_blocks, walk_local

_MATCH_CASE = getattr(ast, "match_case", None)
_MATCH_AS = getattr(ast, "MatchAs", None)


def cyclomatic_complexity(root: ast.AST) -> int:
    """Cyclomatic complexity of the scope rooted at a function/module/class."""
    complexity = 1
    for node in walk_local(root):
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
        elif _MATCH_CASE is not None and isinstance(node, _MATCH_CASE):
            wildcard = (
                _MATCH_AS is not None
                and isinstance(node.pattern, _MATCH_AS)
                and node.pattern.pattern is None
                and node.guard is None
            )
            if not wildcard:
                complexity += 1
    return complexity


def max_nesting(body: Sequence[ast.stmt], depth: int = 0) -> int:
    """Deepest nesting of control structures; ``elif`` chains are not nested."""
    best = depth
    for stmt in body:
        best = max(best, _stmt_depth(stmt, depth))
    return best


def _stmt_depth(stmt: ast.stmt, depth: int) -> int:
    if isinstance(stmt, (*FUNCTION_TYPES, ast.ClassDef)):
        return depth
    if isinstance(stmt, ast.If):
        inner = depth + 1
        best = max_nesting(stmt.body, inner)
        if len(stmt.orelse) == 1 and isinstance(stmt.orelse[0], ast.If):
            return max(best, _stmt_depth(stmt.orelse[0], depth))
        return max(best, max_nesting(stmt.orelse, inner))
    blocks = child_blocks(stmt)
    if not blocks:
        return depth
    inner = depth + 1
    return max([inner] + [max_nesting(block, inner) for block in blocks])


def count_loc(lines: Sequence[str]) -> int:
    """Non-blank, non-comment-only lines."""
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


def halstead_volume(text: str) -> float:
    """Halstead volume ``N * log2(n)`` from Python tokens (best effort)."""
    operators: Counter[str] = Counter()
    operands: Counter[str] = Counter()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(textwrap.dedent(text)).readline):
            if tok.type == tokenize.OP:
                operators[tok.string] += 1
            elif tok.type == tokenize.NAME:
                (operators if keyword.iskeyword(tok.string) else operands)[tok.string] += 1
            elif tok.type in (tokenize.NUMBER, tokenize.STRING):
                operands[tok.string] += 1
            elif tokenize.tok_name.get(tok.type) == "FSTRING_MIDDLE":
                operands[tok.string] += 1
    except (tokenize.TokenError, SyntaxError):
        pass  # keep whatever was counted before the tokenizer gave up
    total = sum(operators.values()) + sum(operands.values())
    distinct = len(operators) + len(operands)
    return total * math.log2(distinct) if distinct > 1 else 0.0


def maintainability_index(volume: float, complexity: int, loc: int) -> float:
    """Rescaled maintainability index in ``[0, 100]`` (see module docstring)."""
    raw = 171 - 5.2 * math.log(max(volume, 1.0)) - 0.23 * complexity - 16.2 * math.log(max(loc, 1))
    return round(max(0.0, min(100.0, raw * 100 / 171)), 2)


def maintainability_band(value: float) -> str:
    if value >= 40:
        return "good"
    if value >= 20:
        return "moderate"
    return "poor"
