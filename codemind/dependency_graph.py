"""Import and call graphs built with NetworkX.

* **Import graph** - nodes are project modules; an edge ``a -> b`` means ``a``
  imports ``b``. Edge ``kind`` is ``top`` (module level), ``lazy`` (inside a
  function) or ``type_checking``. Cycles are computed from ``top`` edges only.
* **Call graph** - nodes are ``module:qualname``; edges are statically
  resolvable calls (same-module names, ``self.method``, ``Class.method``,
  imported functions/classes/modules). Dynamic dispatch, inheritance and
  attribute calls on arbitrary objects are not resolved.
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

import networkx as nx

from codemind.models import FunctionInfo, ModuleInfo, ProjectInfo

SOURCE_ROOTS = frozenset({"src", "lib", "source"})
_EDGE_PRIORITY = {"top": 0, "lazy": 1, "type_checking": 2}


@dataclass
class DependencyAnalysis:
    import_graph: nx.DiGraph
    call_graph: nx.DiGraph
    cycles: list[dict[str, Any]] = field(default_factory=list)
    module_metrics: dict[str, dict[str, Any]] = field(default_factory=dict)
    isolated_functions: list[str] = field(default_factory=list)
    external_imports: dict[str, int] = field(default_factory=dict)
    third_party: list[str] = field(default_factory=list)
    total_calls: int = 0
    resolved_calls: int = 0

    def top_modules(self, key: str = "coupling", limit: int = 10) -> list[tuple[str, dict[str, Any]]]:
        ranked = sorted(self.module_metrics.items(), key=lambda kv: (-kv[1][key], kv[0]))
        return ranked[:limit]

    def summary(self) -> dict[str, Any]:
        return {
            "modules": self.import_graph.number_of_nodes(),
            "import_edges": self.import_graph.number_of_edges(),
            "functions": self.call_graph.number_of_nodes(),
            "call_edges": self.call_graph.number_of_edges(),
            "cycles": len(self.cycles),
            "isolated_functions": len(self.isolated_functions),
            "resolved_calls": self.resolved_calls,
            "total_calls": self.total_calls,
            "third_party_packages": list(self.third_party),
        }

    def to_dict(self, kind: str = "both") -> dict[str, Any]:
        data: dict[str, Any] = {"summary": self.summary()}
        if kind in ("both", "imports"):
            data["import_graph"] = _graph_dict(self.import_graph)
            data["cycles"] = self.cycles
            data["module_metrics"] = {k: self.module_metrics[k] for k in sorted(self.module_metrics)}
            data["external_imports"] = dict(sorted(self.external_imports.items()))
        if kind in ("both", "calls"):
            data["call_graph"] = _graph_dict(self.call_graph)
            data["isolated_functions"] = self.isolated_functions
        return data

    def to_graphml(self, kind: str = "imports") -> str:
        graph = self.import_graph if kind == "imports" else self.call_graph
        clean = nx.DiGraph()
        for node, attrs in sorted(graph.nodes(data=True)):
            extra = self.module_metrics.get(node, {}) if kind == "imports" else {}
            clean.add_node(node, **{k: _scalar(v) for k, v in {**attrs, **extra}.items()})
        for src, dst, attrs in sorted(graph.edges(data=True), key=lambda e: (e[0], e[1])):
            clean.add_edge(src, dst, **{k: _scalar(v) for k, v in attrs.items()})
        return "\n".join(nx.generate_graphml(clean)) + "\n"


def _scalar(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool)) else str(value)


def _graph_dict(graph: nx.DiGraph) -> dict[str, Any]:
    return {
        "directed": True,
        "nodes": [{"id": n, **{k: v for k, v in sorted(a.items())}} for n, a in sorted(graph.nodes(data=True))],
        "edges": [
            {"source": s, "target": t, **{k: v for k, v in sorted(a.items())}}
            for s, t, a in sorted(graph.edges(data=True), key=lambda e: (e[0], e[1]))
        ],
    }


class _ModuleResolver:
    """Maps dotted import targets onto project modules."""

    def __init__(self, project: ProjectInfo) -> None:
        self.known = {m.name for m in project.modules}
        self.prefix = project.package_prefix
        self.aliases: dict[str, list[str]] = defaultdict(list)
        for name in self.known:
            parts = name.split(".")
            if len(parts) > 1 and parts[0] in SOURCE_ROOTS:
                self.aliases[".".join(parts[1:])].append(name)

    def exact(self, dotted: str) -> Optional[str]:
        """Module whose name is exactly ``dotted`` (after prefix/source-root handling)."""
        if self.prefix and dotted.startswith(self.prefix + "."):
            dotted = dotted[len(self.prefix) + 1 :]
        if dotted in self.known:
            return dotted
        hits = self.aliases.get(dotted)
        return hits[0] if hits and len(hits) == 1 else None

    def resolve(self, dotted: str) -> Optional[str]:
        """Longest dotted prefix of ``dotted`` that is a project module."""
        if not dotted:
            return None
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            module = self.exact(".".join(parts[:i]))
            if module:
                return module
        return None


def _add_edge(graph: nx.DiGraph, src: str, dst: str, kind: str, line: int) -> None:
    if src == dst:
        return
    if graph.has_edge(src, dst):
        edge = graph[src][dst]
        edge["count"] += 1
        if _EDGE_PRIORITY[kind] < _EDGE_PRIORITY[edge["kind"]] or (kind == edge["kind"] and line < edge["line"]):
            edge["kind"], edge["line"] = kind, line
    else:
        graph.add_edge(src, dst, kind=kind, line=line, count=1)


def _build_import_graph(project: ProjectInfo, resolver: _ModuleResolver) -> tuple[nx.DiGraph, Counter]:
    graph = nx.DiGraph()
    external: Counter = Counter()
    for module in project.modules:
        graph.add_node(module.name, path=module.path, loc=module.loc, is_package=module.is_package)
    for module in project.modules:
        for imp in module.imports:
            targets: set[str] = set()
            if imp.is_from:
                submodules = []
                for name in imp.names:
                    sub = resolver.resolve(f"{imp.module}.{name}" if imp.module else name)
                    exact = sub is not None and sub == (f"{imp.module}.{name}" if imp.module else name)
                    if exact:
                        submodules.append(sub)
                targets.update(s for s in submodules if s)
                if imp.wildcard or len(submodules) < len(imp.names) or not imp.names:
                    base = resolver.resolve(imp.module)
                    if base:
                        targets.add(base)
            else:
                base = resolver.resolve(imp.module)
                if base:
                    targets.add(base)
            if not targets:
                if imp.level == 0 and imp.module:
                    external[imp.module.split(".")[0]] += 1
                continue
            for target in targets:
                _add_edge(graph, module.name, target, imp.scope, imp.lineno)
    return graph, external


def _find_cycles(graph: nx.DiGraph, project: ProjectInfo) -> list[dict[str, Any]]:
    top = nx.DiGraph((s, t) for s, t, a in graph.edges(data=True) if a["kind"] == "top")
    path_of = {m.name: m.path for m in project.modules}
    cycles: list[dict[str, Any]] = []
    for component in nx.strongly_connected_components(top):
        if len(component) < 2:
            continue
        members = sorted(component)
        sub = top.subgraph(component)
        best: Optional[list[str]] = None
        start = members[0]
        for succ in sorted(sub.successors(start)):
            try:
                route = nx.shortest_path(sub, succ, start) if succ != start else [start]
            except nx.NetworkXNoPath:
                continue
            candidate = [start] + [n for n in route if n != start] if route[-1] == start else [start] + route
            if best is None or len(candidate) < len(best):
                best = candidate
        if best is None:  # pragma: no cover - SCC guarantees a cycle
            best = members
        line = graph[best[0]][best[1]]["line"] if len(best) > 1 else 1
        cycles.append({"modules": members, "path": best, "file": path_of.get(best[0], ""), "line": line})
    cycles.sort(key=lambda c: c["modules"])
    return cycles


def _module_metrics(graph: nx.DiGraph) -> dict[str, dict[str, Any]]:
    if graph.number_of_nodes() == 0:
        return {}
    degree_c = nx.degree_centrality(graph)
    size = graph.number_of_nodes()
    between = nx.betweenness_centrality(graph, k=min(size, 300), seed=0) if size > 300 else nx.betweenness_centrality(graph)
    metrics = {}
    for node in sorted(graph.nodes):
        fan_in, fan_out = graph.in_degree(node), graph.out_degree(node)
        metrics[node] = {
            "in_degree": fan_in,
            "out_degree": fan_out,
            "coupling": fan_in + fan_out,
            "instability": round(fan_out / (fan_in + fan_out), 3) if fan_in + fan_out else 0.0,
            "degree_centrality": round(degree_c[node], 4),
            "betweenness": round(between[node], 4),
        }
    return metrics


class _CallResolver:
    def __init__(self, project: ProjectInfo, modules: _ModuleResolver) -> None:
        self.modules = modules
        self.functions: dict[str, dict[str, FunctionInfo]] = {}
        self.classes: dict[str, set[str]] = {}
        self.aliases: dict[str, dict[str, str]] = {}
        for module in project.modules:
            self.functions[module.name] = {f.qualname: f for f in module.functions}
            self.classes[module.name] = {c.qualname for c in module.classes}
            table: dict[str, str] = {}
            for imp in module.imports:
                if imp.scope == "type_checking":
                    continue
                for binding in imp.bindings:
                    table.setdefault(binding.local, binding.target)
            self.aliases[module.name] = table

    @staticmethod
    def node_id(module: str, qualname: str) -> str:
        return f"{module}:{qualname}"

    def _symbol(self, dotted: str) -> Optional[str]:
        """Resolve ``pkg.mod.Class.method`` style targets to a function node id."""
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            module = self.modules.exact(".".join(parts[:i]))
            if module is None:
                continue
            remainder = ".".join(parts[i:])
            if not remainder:
                return None
            funcs = self.functions[module]
            if remainder in funcs:
                return self.node_id(module, remainder)
            if remainder in self.classes[module] and f"{remainder}.__init__" in funcs:
                return self.node_id(module, f"{remainder}.__init__")
        return None

    def resolve(self, module: ModuleInfo, fn: FunctionInfo, call: str) -> Optional[str]:
        funcs, classes = self.functions[module.name], self.classes[module.name]
        aliases = self.aliases[module.name]
        parts = call.split(".")
        head = parts[0]
        if len(parts) == 1:
            pieces = fn.qualname.split(".")
            candidates = [f"{fn.qualname}.{head}"] + [".".join(pieces[:i] + [head]) for i in range(len(pieces) - 1, 0, -1)]
            for cand in candidates:
                target = funcs.get(cand)
                if target is not None and not target.is_method:
                    return self.node_id(module.name, cand)
            if head in funcs and not funcs[head].is_method:
                return self.node_id(module.name, head)
            if head in classes and f"{head}.__init__" in funcs:
                return self.node_id(module.name, f"{head}.__init__")
            if head in aliases:
                return self._symbol(aliases[head])
            return None
        if head in ("self", "cls") and fn.class_qualname and len(parts) == 2:
            qual = f"{fn.class_qualname}.{parts[1]}"
            return self.node_id(module.name, qual) if qual in funcs else None
        if head in classes and len(parts) == 2:
            qual = f"{head}.{parts[1]}"
            return self.node_id(module.name, qual) if qual in funcs else None
        if head in aliases:
            return self._symbol(aliases[head] + "." + ".".join(parts[1:]))
        return None


def _build_call_graph(project: ProjectInfo, modules: _ModuleResolver) -> tuple[nx.DiGraph, int, int]:
    graph = nx.DiGraph()
    resolver = _CallResolver(project, modules)
    for module in project.modules:
        for fn in module.functions:
            graph.add_node(
                resolver.node_id(module.name, fn.qualname),
                module=module.name, qualname=fn.qualname, path=module.path, lineno=fn.lineno,
                decorated=bool(fn.decorators),
            )
    total = resolved = 0
    for module in project.modules:
        for fn in module.functions:
            src = resolver.node_id(module.name, fn.qualname)
            for call in fn.calls:
                total += 1
                dst = resolver.resolve(module, fn, call)
                if dst is None or dst not in graph:
                    continue
                resolved += 1
                if graph.has_edge(src, dst):
                    graph[src][dst]["count"] += 1
                else:
                    graph.add_edge(src, dst, count=1)
    return graph, total, resolved


def _isolated(graph: nx.DiGraph) -> list[str]:
    result = []
    for node, attrs in sorted(graph.nodes(data=True)):
        name = attrs["qualname"].split(".")[-1]
        if name.startswith("__") or name == "main" or name.startswith("test") or attrs.get("decorated"):
            continue
        others_in = [p for p in graph.predecessors(node) if p != node]
        others_out = [s for s in graph.successors(node) if s != node]
        if not others_in and not others_out:
            result.append(node)
    return result


def build_dependency_analysis(project: ProjectInfo) -> DependencyAnalysis:
    """Build both graphs and derive cycles, centrality and isolation metrics."""
    resolver = _ModuleResolver(project)
    import_graph, external = _build_import_graph(project, resolver)
    call_graph, total, resolved = _build_call_graph(project, resolver)
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    third_party = sorted(n for n in external if n not in stdlib and n != "__future__")
    return DependencyAnalysis(
        import_graph=import_graph,
        call_graph=call_graph,
        cycles=_find_cycles(import_graph, project),
        module_metrics=_module_metrics(import_graph),
        isolated_functions=_isolated(call_graph),
        external_imports=dict(external),
        third_party=third_party,
        total_calls=total,
        resolved_calls=resolved,
    )
