import textwrap

from codemind.complexity import cyclomatic_complexity, max_nesting
from codemind.parser import module_name_for, parse_source

SAMPLE = textwrap.dedent('''
    """Module doc."""
    import os
    import a.b.c as abc
    from typing import TYPE_CHECKING
    from . import sibling
    from ..up import thing as renamed
    from .pkg import *
    if TYPE_CHECKING:
        from heavy import Type

    MAX_SIZE = 10
    counter = 0

    @decorator(1)
    async def fetch(a, b=2, *args, key=None, **kw) -> int:
        """Doc."""
        import json
        return 1

    class Base(Mixin, metaclass=Meta):
        """Doc."""
        @staticmethod
        def helper(x): return x
        def method(self, y):
            if y:
                return 1
            return 0
''')


def test_functions_classes_and_signatures():
    m = parse_source(SAMPLE, "pkg/sub/mod.py")
    fetch = next(f for f in m.functions if f.name == "fetch")
    assert fetch.is_async and fetch.has_docstring and fetch.decorators == ["decorator(1)"]
    assert fetch.signature == "(a, b=2, *args, key=None, **kw) -> int"
    assert fetch.param_count == 5 and fetch.lineno == 16
    method = next(f for f in m.functions if f.qualname == "Base.method")
    assert method.is_method and method.param_count == 1 and method.class_qualname == "Base"
    assert next(f for f in m.functions if f.name == "helper").param_count == 1  # staticmethod keeps its arg
    cls = m.classes[0]
    assert cls.bases == ["Mixin"] and cls.methods == ["helper", "method"] and cls.has_docstring
    assert m.has_docstring


def test_imports_resolution_and_scope():
    m = parse_source(SAMPLE, "pkg/sub/mod.py")
    by_line = {i.lineno: i for i in m.imports}
    assert by_line[4].bindings[0].local == "abc" and by_line[4].bindings[0].target == "a.b.c"
    assert by_line[6].module == "pkg.sub" and by_line[6].names == ["sibling"]
    assert by_line[7].module == "pkg.up" and by_line[7].bindings[0].target == "pkg.up.thing"
    assert by_line[8].wildcard and by_line[8].module == "pkg.sub.pkg"
    scopes = {i.module: i.scope for i in m.imports}
    assert scopes["heavy"] == "type_checking" and scopes["json"] == "lazy" and scopes["os"] == "top"


def test_globals_and_module_names():
    m = parse_source(SAMPLE, "pkg/sub/mod.py")
    assert {(g.name, g.is_constant) for g in m.globals} == {("MAX_SIZE", True), ("counter", False)}
    assert module_name_for("pkg/__init__.py") == ("pkg", True)
    assert module_name_for("top.py") == ("top", False)
    assert module_name_for("__init__.py")[1] is True


def _fn(code):
    return parse_source(textwrap.dedent(code), "m.py").functions[0]


def test_cyclomatic_complexity_documented_method():
    fn = _fn('''
        def f(a, b, items):
            if a and b or a:        # if +1, and/or +2
                pass
            elif b:                 # +1
                pass
            for i in items:         # +1
                while i:            # +1
                    i -= 1
            try:
                pass
            except ValueError:      # +1
                pass
            return [x for x in items if x]  # comprehension +1, filter +1
    ''')
    assert fn.complexity == 1 + 1 + 2 + 1 + 1 + 1 + 1 + 2
    assert _fn("def g():\n    return 1\n").complexity == 1


def test_nested_functions_are_measured_separately():
    m = parse_source("def outer(x):\n    def inner(y):\n        if y:\n            return 1\n        return 0\n    return inner\n", "m.py")
    by = {f.qualname: f for f in m.functions}
    assert by["outer"].complexity == 1 and by["outer.inner"].complexity == 2


def test_nesting_depth_ignores_elif_chains():
    flat = _fn("def f(x):\n    if x == 1:\n        pass\n    elif x == 2:\n        pass\n    elif x == 3:\n        pass\n    else:\n        pass\n")
    deep = _fn("def f(x):\n    for a in x:\n        if a:\n            while a:\n                with a:\n                    pass\n")
    assert flat.max_nesting == 1 and deep.max_nesting == 4


def test_maintainability_index_is_bounded_and_ordered():
    simple = parse_source("def f():\n    return 1\n", "m.py")
    branches = "\n".join(f"    if x == {i}:\n        total += {i} * x\n" for i in range(60))
    heavy = parse_source(f"def f(x):\n    total = 0\n{branches}    return total\n", "m.py")
    assert 0 <= heavy.maintainability < simple.maintainability <= 100


def test_loc_ignores_blank_and_comment_lines():
    m = parse_source("# c\n\nx = 1\n\n# d\ny = 2\n", "m.py")
    assert m.loc == 2


def test_helper_functions_directly():
    import ast
    tree = ast.parse("def f():\n    return a if b else c\n")
    assert cyclomatic_complexity(tree.body[0]) == 2
    assert max_nesting(tree.body[0].body) == 0
