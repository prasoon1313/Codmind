"""AST helpers shared by the parser, complexity metrics and rules."""
from __future__ import annotations

import ast
from typing import Iterator, Optional, Union

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]
FUNCTION_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)
_MATCH = getattr(ast, "Match", None)
_TRY_STAR = getattr(ast, "TryStar", None)
_SKIP_FIELDS = frozenset({"ctx", "type_comment", "name", "lineno", "col_offset"})


def dotted_name(node: ast.AST) -> Optional[str]:
    """Return ``a.b.c`` for Name/Attribute chains, else ``None``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def child_blocks(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Statement lists directly nested in ``stmt`` (function bodies excluded)."""
    if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, (ast.With, ast.AsyncWith, ast.ClassDef)):
        return [stmt.body]
    if isinstance(stmt, ast.Try) or (_TRY_STAR is not None and isinstance(stmt, _TRY_STAR)):
        return [stmt.body, *[h.body for h in stmt.handlers], stmt.orelse, stmt.finalbody]
    if _MATCH is not None and isinstance(stmt, _MATCH):
        return [case.body for case in stmt.cases]
    return []


def walk_local(root: ast.AST) -> Iterator[ast.AST]:
    """Pre-order walk of a scope without descending into nested functions.

    Nested ``def`` nodes are yielded (so callers can see them) but not
    entered. Class bodies are entered because they execute in the enclosing
    flow of control. ``root`` may be a Module, FunctionDef or ClassDef.
    """
    stack: list[ast.AST] = list(reversed(root.body))  # type: ignore[attr-defined]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, FUNCTION_TYPES):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def scope_blocks(root: ast.AST) -> Iterator[list[ast.stmt]]:
    """Yield every statement list that belongs to the scope of ``root``."""
    yield root.body  # type: ignore[attr-defined]
    for node in walk_local(root):
        if isinstance(node, ast.stmt):
            yield from child_blocks(node)


def is_docstring_stmt(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def normalize(node: ast.AST) -> str:
    """Structural fingerprint: identifiers and literal values are abstracted."""
    if isinstance(node, ast.Name):
        return "N"
    if isinstance(node, ast.Constant):
        return "C:" + type(node.value).__name__
    if isinstance(node, ast.arg):
        return "A"
    parts = [type(node).__name__]
    for name, value in ast.iter_fields(node):
        if name in _SKIP_FIELDS:
            continue
        if isinstance(value, list):
            parts.append("[" + ",".join(normalize(v) if isinstance(v, ast.AST) else repr(v) for v in value) + "]")
        elif isinstance(value, ast.AST):
            parts.append(normalize(value))
        elif value is not None:
            parts.append(repr(value))
    return "(" + " ".join(parts) + ")"


def node_count(node: ast.AST) -> int:
    return sum(1 for _ in ast.walk(node))
