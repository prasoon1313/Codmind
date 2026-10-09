"""AST-based extraction of modules, classes, functions, imports and globals."""
from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Optional

from codemind.astutils import FUNCTION_TYPES, child_blocks, dotted_name, walk_local
from codemind.complexity import (
    count_loc,
    cyclomatic_complexity,
    halstead_volume,
    maintainability_index,
    max_nesting,
)
from codemind.models import (
    ClassInfo,
    FunctionInfo,
    GlobalVar,
    ImportBinding,
    ImportInfo,
    ModuleInfo,
)

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def module_name_for(rel_path: str) -> tuple[str, bool]:
    """Dotted module name and package flag for a project-relative POSIX path."""
    parts = list(PurePosixPath(rel_path).with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts) if parts else "__init__", is_package


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _resolve_relative(module_name: str, is_package: bool, level: int, target: Optional[str]) -> str:
    if level == 0:
        return target or ""
    package = module_name.split(".") if is_package else module_name.split(".")[:-1]
    if level > 1:
        package = package[: len(package) - (level - 1)] if len(package) >= level - 1 else []
    base = ".".join(package)
    if target:
        return f"{base}.{target}" if base else target
    return base


def _collect_imports(body: list[ast.stmt], scope: str, info: ModuleInfo) -> None:
    for stmt in body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".")[0]
                target = alias.name if alias.asname else alias.name.split(".")[0]
                info.imports.append(
                    ImportInfo(alias.name, stmt.lineno, 0, False, [], [ImportBinding(local, target)], scope)
                )
        elif isinstance(stmt, ast.ImportFrom):
            module = _resolve_relative(info.name, info.is_package, stmt.level, stmt.module)
            wildcard = any(a.name == "*" for a in stmt.names)
            names = [a.name for a in stmt.names if a.name != "*"]
            bindings = [
                ImportBinding(a.asname or a.name, f"{module}.{a.name}" if module else a.name)
                for a in stmt.names
                if a.name != "*"
            ]
            info.imports.append(ImportInfo(module, stmt.lineno, stmt.level, True, names, bindings, scope, wildcard))
        elif isinstance(stmt, FUNCTION_TYPES):
            _collect_imports(stmt.body, "lazy", info)
        elif isinstance(stmt, ast.If) and _is_type_checking(stmt.test):
            _collect_imports(stmt.body, "type_checking", info)
            _collect_imports(stmt.orelse, scope, info)
        else:
            for block in child_blocks(stmt):
                _collect_imports(block, scope, info)


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _target_names(elt)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _collect_globals(body: list[ast.stmt], info: ModuleInfo) -> None:
    for stmt in body:
        targets: list[ast.expr] = []
        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            targets = [stmt.target]
        for target in targets:
            for name in _target_names(target):
                info.globals.append(GlobalVar(name, stmt.lineno, name.isupper()))
        if not isinstance(stmt, (*FUNCTION_TYPES, ast.ClassDef)):
            for block in child_blocks(stmt):
                _collect_globals(block, info)


def _collect_names(tree: ast.AST, info: ModuleInfo) -> None:
    """Names considered *used* (for imports) and *referenced* (project-wide)."""
    used: set[str] = set()
    referenced: set[str] = set()
    annotation_strings: list[str] = []

    def note_annotation(node: Optional[ast.expr]) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            annotation_strings.append(node.value)
        elif node is not None:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    annotation_strings.append(sub.value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Load, ast.Del)):
                used.add(node.id)
                referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced.add(node.attr)
        elif isinstance(node, ast.arg):
            note_annotation(node.annotation)
        elif isinstance(node, FUNCTION_TYPES):
            note_annotation(node.returns)
        elif isinstance(node, ast.AnnAssign):
            note_annotation(node.annotation)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.isidentifier():
            referenced.add(node.value)
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets) and isinstance(
                node.value, (ast.List, ast.Tuple)
            ):
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        used.add(elt.value)
                        referenced.add(elt.value)
    for text in annotation_strings:
        used.update(_IDENT.findall(text))
    info.used_names = used
    info.referenced_names = referenced


def _function_info(node: ast.FunctionDef | ast.AsyncFunctionDef, prefix: str, class_qual: Optional[str], lines: list[str]) -> FunctionInfo:
    args = node.args
    params = [a.arg for a in (*args.posonlyargs, *args.args)]
    if args.vararg:
        params.append(args.vararg.arg)
    params.extend(a.arg for a in args.kwonlyargs)
    if args.kwarg:
        params.append(args.kwarg.arg)
    decorators = [ast.unparse(d) for d in node.decorator_list]
    is_method = class_qual is not None
    count = len(params)
    if is_method and params and "staticmethod" not in decorators and params[0] in ("self", "cls", "mcs", "mcls"):
        count -= 1
    signature = f"({ast.unparse(args)})" + (f" -> {ast.unparse(node.returns)}" if node.returns else "")
    end = getattr(node, "end_lineno", None) or node.lineno
    segment = lines[node.lineno - 1 : end]
    loc = count_loc(segment)
    complexity = cyclomatic_complexity(node)
    calls = [name for n in walk_local(node) if isinstance(n, ast.Call) for name in [dotted_name(n.func)] if name]
    return FunctionInfo(
        name=node.name,
        qualname=prefix + node.name,
        lineno=node.lineno,
        end_lineno=end,
        signature=signature,
        params=params,
        param_count=count,
        decorators=decorators,
        has_docstring=ast.get_docstring(node) is not None,
        is_method=is_method,
        is_async=isinstance(node, ast.AsyncFunctionDef),
        class_qualname=class_qual,
        loc=loc,
        complexity=complexity,
        max_nesting=max_nesting(node.body),
        maintainability=maintainability_index(halstead_volume("\n".join(segment)), complexity, loc),
        calls=calls,
        node=node,
    )


def _walk_defs(body: list[ast.stmt], prefix: str, class_qual: Optional[str], info: ModuleInfo, lines: list[str]) -> None:
    for stmt in body:
        if isinstance(stmt, FUNCTION_TYPES):
            fn = _function_info(stmt, prefix, class_qual, lines)
            info.functions.append(fn)
            _walk_defs(stmt.body, fn.qualname + ".", None, info, lines)
        elif isinstance(stmt, ast.ClassDef):
            qual = prefix + stmt.name
            end = getattr(stmt, "end_lineno", None) or stmt.lineno
            methods = [s for s in stmt.body if isinstance(s, FUNCTION_TYPES)]
            _walk_defs(stmt.body, qual + ".", qual, info, lines)
            method_cc = sum(f.complexity for f in info.functions if f.class_qualname == qual)
            info.classes.append(
                ClassInfo(
                    name=stmt.name,
                    qualname=qual,
                    lineno=stmt.lineno,
                    end_lineno=end,
                    bases=[ast.unparse(b) for b in stmt.bases],
                    decorators=[ast.unparse(d) for d in stmt.decorator_list],
                    has_docstring=ast.get_docstring(stmt) is not None,
                    methods=[m.name for m in methods],
                    loc=count_loc(lines[stmt.lineno - 1 : end]),
                    complexity=method_cc,
                    node=stmt,
                )
            )
        else:
            for block in child_blocks(stmt):
                _walk_defs(block, prefix, class_qual, info, lines)


def parse_source(source: str, rel_path: str) -> ModuleInfo:
    """Parse ``source`` into a :class:`ModuleInfo`.

    Raises ``SyntaxError``/``ValueError``/``RecursionError`` for unparsable
    input; the scanner converts those into reported issues.
    """
    tree = ast.parse(source, filename=rel_path)
    name, is_package = module_name_for(rel_path)
    lines = source.splitlines()
    info = ModuleInfo(
        path=rel_path,
        name=name,
        is_package=is_package,
        loc=count_loc(lines),
        has_docstring=ast.get_docstring(tree) is not None,
        tree=tree,
        source=source,
    )
    _collect_imports(tree.body, "top", info)
    _collect_globals(tree.body, info)
    _walk_defs(tree.body, "", None, info, lines)
    _collect_names(tree, info)
    module_level = cyclomatic_complexity(tree) - 1
    info.complexity = sum(f.complexity for f in info.functions) + module_level + (0 if info.functions else 1)
    info.maintainability = maintainability_index(halstead_volume(source), info.complexity, info.loc)
    return info
