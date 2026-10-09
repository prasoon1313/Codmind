import json

import networkx as nx

from codemind.analyzer import analyze
from codemind.dependency_graph import build_dependency_analysis
from codemind.config import Config
from codemind.scanner import scan_project
from helpers import ids, of, write_project


def _graph(tmp_path, files):
    write_project(tmp_path, files)
    return build_dependency_analysis(scan_project(tmp_path, Config()))


def test_circular_import_detected_with_path(tmp_path):
    g = _graph(tmp_path, {"pkg/__init__.py": "", "pkg/a.py": "from pkg import b\n", "pkg/b.py": "from pkg.c import x\n",
                          "pkg/c.py": "import pkg.a\nx = 1\n"})
    assert len(g.cycles) == 1
    cycle = g.cycles[0]
    assert cycle["modules"] == ["pkg.a", "pkg.b", "pkg.c"] and cycle["path"][0] == "pkg.a" and len(cycle["path"]) == 3
    assert cycle["file"] == "pkg/a.py" and cycle["line"] == 1


def test_cycle_finding_is_reported_by_rule(tmp_path):
    write_project(tmp_path, {"a.py": "import b\n", "b.py": "import a\n"})
    found = of(analyze(tmp_path), "CM301")
    assert len(found) == 1 and "a -> b -> a" in found[0].message


def test_lazy_and_type_checking_imports_do_not_form_cycles(tmp_path):
    g = _graph(tmp_path, {
        "a.py": "import b\n",
        "b.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import a\ndef f():\n    import a\n",
    })
    assert g.cycles == []
    assert g.import_graph["b"]["a"]["kind"] == "lazy"


def test_acyclic_project_has_no_cycles(tmp_path):
    g = _graph(tmp_path, {"a.py": "import b\n", "b.py": "import c\n", "c.py": "x = 1\n"})
    assert g.cycles == []


def test_degree_and_centrality_metrics(tmp_path):
    g = _graph(tmp_path, {"hub.py": "x = 1\n", "a.py": "import mid\n", "b.py": "import hub\n", "mid.py": "import hub\n"})
    m = g.module_metrics
    assert (m["hub"]["in_degree"], m["hub"]["out_degree"]) == (2, 0)
    assert (m["a"]["in_degree"], m["a"]["out_degree"]) == (0, 1)
    assert m["hub"]["coupling"] == 2 and m["a"]["instability"] == 1.0 and m["hub"]["instability"] == 0.0
    assert m["mid"]["betweenness"] > 0 and m["hub"]["degree_centrality"] > m["b"]["degree_centrality"]


def test_high_coupling_rule(tmp_path):
    files = {f"m{i}.py": "import hub\n" for i in range(5)}
    files["hub.py"] = "x = 1\n"
    config = Config()
    config.thresholds.max_module_coupling = 4
    write_project(tmp_path, files)
    found = of(analyze(tmp_path, config), "CM302")
    assert [f.symbol for f in found] == ["hub"]


def test_call_graph_resolution_and_isolated_functions(tmp_path):
    g = _graph(tmp_path, {
        "util.py": "def helper():\n    return 1\nclass Tool:\n    def __init__(self): pass\n    def run(self):\n        return self.step()\n    def step(self): return helper2()\ndef helper2(): return 2\n",
        "main.py": "import util\nfrom util import helper\ndef go():\n    helper()\n    util.helper2()\n    t = util.Tool()\n    return t\ndef lonely(): pass\n",
    })
    edges = set(g.call_graph.edges)
    assert ("main:go", "util:helper") in edges and ("main:go", "util:helper2") in edges
    assert ("main:go", "util:Tool.__init__") in edges
    assert ("util:Tool.run", "util:Tool.step") in edges and ("util:Tool.step", "util:helper2") in edges
    assert "main:lonely" in g.isolated_functions and "util:helper" not in g.isolated_functions


def test_src_layout_and_relative_imports(tmp_path):
    g = _graph(tmp_path, {"src/app/__init__.py": "", "src/app/core.py": "from . import util\n", "src/app/util.py": "",
                          "src/app/cli.py": "from app.core import thing\nimport json\n"})
    assert g.import_graph.has_edge("src.app.core", "src.app.util")
    assert g.import_graph.has_edge("src.app.cli", "src.app.core")
    assert g.external_imports == {"json": 1}


def test_stdlib_name_is_not_resolved_to_internal_module(tmp_path):
    g = _graph(tmp_path, {"pkg/json.py": "", "main.py": "import json\n"})
    assert g.import_graph.number_of_edges() == 0 and g.third_party == []


def test_json_export_is_valid_and_deterministic(tmp_path):
    write_project(tmp_path, {"a.py": "import b\ndef f(): pass\n", "b.py": "x = 1\n"})
    g = build_dependency_analysis(scan_project(tmp_path, Config()))
    data = json.loads(json.dumps(g.to_dict()))
    assert {"summary", "import_graph", "call_graph", "cycles", "module_metrics"} <= set(data)
    assert data["import_graph"]["edges"][0] == {"source": "a", "target": "b", "count": 1, "kind": "top", "line": 1}
    assert json.dumps(g.to_dict()) == json.dumps(build_dependency_analysis(scan_project(tmp_path, Config())).to_dict())
    assert set(g.to_dict("imports")) == {"summary", "import_graph", "cycles", "module_metrics", "external_imports"}


def test_graphml_export_roundtrips_through_networkx(tmp_path):
    write_project(tmp_path, {"a.py": "import b\n", "b.py": "def f(): pass\n"})
    g = build_dependency_analysis(scan_project(tmp_path, Config()))
    parsed = nx.parse_graphml(g.to_graphml("imports"))
    assert set(parsed.nodes) == {"a", "b"} and list(parsed.edges) == [("a", "b")]
    assert nx.parse_graphml(g.to_graphml("calls")).number_of_nodes() == 1
