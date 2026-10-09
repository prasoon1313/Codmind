"""Helpers shared by rule implementations."""
from __future__ import annotations

import ast
from typing import Iterator, Optional

from codemind.astutils import FUNCTION_TYPES, dotted_name, walk_local
from codemind.models import ModuleInfo


def import_aliases(module: ModuleInfo) -> dict[str, str]:
    """Map local names to the fully qualified object they import."""
    aliases: dict[str, str] = {}
    for imp in module.imports:
        for binding in imp.bindings:
            aliases.setdefault(binding.local, binding.target)
    return aliases


def qualified_name(node: ast.AST, aliases: dict[str, str]) -> Optional[str]:
    """Dotted name with the first segment expanded through the import aliases."""
    dotted = dotted_name(node)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    base = aliases.get(head, head)
    return f"{base}.{rest}" if rest else base


def iter_scopes(module: ModuleInfo) -> Iterator[tuple[str, ast.AST]]:
    """Yield ``(symbol, node)`` for the module scope and every function scope."""
    yield "", module.tree
    for fn in module.functions:
        yield fn.qualname, fn.node


def local_defs(module: ModuleInfo) -> set[str]:
    return {f.name for f in module.functions} | {c.name for c in module.classes}


def is_constant_string(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


__all__ = [
    "FUNCTION_TYPES", "import_aliases", "qualified_name", "iter_scopes", "local_defs",
    "is_constant_string", "walk_local",
]
