"""Bug-pattern and risky-construct rules (CM1xx)."""
from __future__ import annotations

import ast
from typing import Iterable, Optional

from codemind.astutils import FUNCTION_TYPES, dotted_name, scope_blocks, walk_local
from codemind.models import Confidence, Finding, ModuleInfo, Severity
from codemind.rules.base import Rule, RuleContext, RuleMeta, register
from codemind.rules.util import import_aliases, is_constant_string, iter_scopes, local_defs, qualified_name

_MUTABLE_CALLS = {"list", "dict", "set", "bytearray", "defaultdict", "deque", "Counter", "OrderedDict"}
_BROAD = {"Exception", "BaseException"}


def _is_mutable_default(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        name = dotted_name(node.func)
        return bool(name) and name.split(".")[-1] in _MUTABLE_CALLS
    return False


@register
class MutableDefaultArgument(Rule):
    meta = RuleMeta(
        "CM101", "mutable-default-argument", "bug", Severity.HIGH, Confidence.DEFINITE,
        "A function parameter has a mutable default value.",
        "Defaults are evaluated once at definition time, so the same list/dict/set object is shared "
        "by every call that omits the argument. State can leak between calls.",
        "Use None as the default and create the container inside the function body.",
        "def add(item, bucket=[]):\n    bucket.append(item)\n    return bucket",
        "def add(item, bucket=None):\n    bucket = [] if bucket is None else bucket\n    bucket.append(item)\n    return bucket",
        "Sharing is only harmful if the function mutates or leaks the default; the rule cannot check that.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for fn in module.functions:
            args = fn.node.args
            positional = [*args.posonlyargs, *args.args]
            pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
            pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
            for arg, default in pairs:
                if _is_mutable_default(default):
                    yield self.make(
                        module.path, default.lineno,
                        f"Parameter '{arg.arg}' of '{fn.qualname}' has a mutable default ({ast.unparse(default)}).",
                        symbol=fn.qualname, detail=arg.arg,
                    )


def _is_const(node: ast.AST, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value and type(node.value) is type(value)


@register
class NoneEqualityComparison(Rule):
    meta = RuleMeta(
        "CM102", "none-equality-comparison", "bug", Severity.LOW, Confidence.DEFINITE,
        "Comparison with None using == or !=.",
        "None is a singleton; identity checks are correct and cannot be fooled by custom __eq__ methods.",
        "Use 'is None' / 'is not None'.",
        "if value == None:\n    ...", "if value is None:\n    ...",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for symbol, scope in iter_scopes(module):
            for node in walk_local(scope):
                if isinstance(node, ast.Compare):
                    operands = [node.left, *node.comparators]
                    for i, op in enumerate(node.ops):
                        if isinstance(op, (ast.Eq, ast.NotEq)) and (
                            _is_const(operands[i], None) or _is_const(operands[i + 1], None)
                        ):
                            yield self.make(module.path, node.lineno,
                                            f"Comparison to None with '{'==' if isinstance(op, ast.Eq) else '!='}'.",
                                            symbol=symbol)


@register
class BooleanLiteralEquality(Rule):
    meta = RuleMeta(
        "CM103", "boolean-literal-equality", "bug", Severity.LOW, Confidence.DEFINITE,
        "Equality comparison against True or False.",
        "'x == True' is true for 1 and 1.0 and is redundant for real booleans; it often hides a truthiness mistake.",
        "Test truthiness directly ('if x:' / 'if not x:'), or use 'is True' when the exact bool is required.",
        "if flag == True:\n    ...", "if flag:\n    ...",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for symbol, scope in iter_scopes(module):
            for node in walk_local(scope):
                if isinstance(node, ast.Compare):
                    operands = [node.left, *node.comparators]
                    for i, op in enumerate(node.ops):
                        if isinstance(op, (ast.Eq, ast.NotEq)) and any(
                            _is_const(operands[j], v) for j in (i, i + 1) for v in (True, False)
                        ):
                            yield self.make(module.path, node.lineno,
                                            "Equality comparison with a Boolean literal.", symbol=symbol)


def _handlers(scope: ast.AST) -> Iterable[ast.ExceptHandler]:
    return (n for n in walk_local(scope) if isinstance(n, ast.ExceptHandler))


@register
class BareExcept(Rule):
    meta = RuleMeta(
        "CM104", "bare-except", "bug", Severity.MEDIUM, Confidence.DEFINITE,
        "An 'except:' clause without an exception type.",
        "It also catches KeyboardInterrupt and SystemExit and hides programming errors.",
        "Catch the specific exceptions you can handle (at minimum 'except Exception').",
        "try:\n    run()\nexcept:\n    log()", "try:\n    run()\nexcept ValueError:\n    log()",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for symbol, scope in iter_scopes(module):
            for handler in _handlers(scope):
                if handler.type is None:
                    yield self.make(module.path, handler.lineno, "Bare 'except:' clause.", symbol=symbol)


def _is_noop(stmt: ast.stmt) -> bool:
    if isinstance(stmt, ast.Pass):
        return True
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)  # '...' or docstring-like


def _handler_types(handler: ast.ExceptHandler) -> list[str]:
    if handler.type is None:
        return ["<bare>"]
    nodes = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return [dotted_name(n) or "?" for n in nodes]


@register
class EmptyExceptionHandler(Rule):
    meta = RuleMeta(
        "CM105", "empty-exception-handler", "bug", Severity.MEDIUM, Confidence.DEFINITE,
        "An exception handler whose body does nothing ('pass' or '...').",
        "Silently discarding errors makes failures invisible and debugging very hard.",
        "Log the error, re-raise, or handle it meaningfully. For intentionally ignored errors prefer "
        "contextlib.suppress(SpecificError) with a comment.",
        "try:\n    save()\nexcept Exception:\n    pass", "try:\n    save()\nexcept OSError:\n    logger.exception('save failed')",
        "Narrow handlers such as 'except ImportError: pass' are reported with LOW severity because they are common idioms.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for symbol, scope in iter_scopes(module):
            for handler in _handlers(scope):
                if all(_is_noop(s) for s in handler.body):
                    types = _handler_types(handler)
                    broad = "<bare>" in types or any(t.split(".")[-1] in _BROAD for t in types)
                    yield self.make(
                        module.path, handler.lineno,
                        f"Exception handler for {', '.join(types)} silently ignores the error.",
                        symbol=symbol, detail=",".join(types),
                        severity=self.meta.severity if broad else Severity.LOW,
                    )


@register
class BroadExceptionSwallowed(Rule):
    meta = RuleMeta(
        "CM106", "broad-exception-swallowed", "bug", Severity.LOW, Confidence.MEDIUM,
        "A broad 'except Exception' handler that neither re-raises, logs, nor uses the exception.",
        "Catching everything and carrying on can mask unrelated bugs. Heuristic: the handler body has no "
        "'raise', no call (such as logging) and never reads the bound exception.",
        "Catch narrower exception types, or log/re-raise inside the handler.",
        "try:\n    run()\nexcept Exception:\n    return None", "try:\n    run()\nexcept Exception:\n    logger.exception('run failed')\n    raise",
        "Handlers that report errors through means other than calls or the bound name are not recognised.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for symbol, scope in iter_scopes(module):
            for handler in _handlers(scope):
                types = _handler_types(handler)
                if not any(t.split(".")[-1] in _BROAD for t in types) or all(_is_noop(s) for s in handler.body):
                    continue
                nodes = [n for s in handler.body for n in ast.walk(s)]
                handled = any(isinstance(n, (ast.Raise, ast.Call)) for n in nodes) or (
                    handler.name is not None
                    and any(isinstance(n, ast.Name) and n.id == handler.name for n in nodes)
                )
                if not handled:
                    yield self.make(module.path, handler.lineno,
                                    f"Broad handler for {', '.join(types)} swallows the exception without logging or re-raising.",
                                    symbol=symbol, detail=",".join(types))


_TERMINAL = (ast.Return, ast.Raise, ast.Continue, ast.Break)
_EXIT_CALLS = {"sys.exit", "exit", "quit", "os._exit"}


def _terminates(stmt: ast.stmt, aliases: dict[str, str]) -> Optional[str]:
    """Return 'definite' / 'call' if control cannot flow past ``stmt``."""
    if isinstance(stmt, _TERMINAL):
        return "definite"
    if isinstance(stmt, ast.If) and stmt.orelse and stmt.body:
        if _terminates(stmt.body[-1], aliases) and _terminates(stmt.orelse[-1], aliases):
            return "definite"
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        name = qualified_name(stmt.value.func, aliases)
        if name in _EXIT_CALLS:
            return "call"
    return None


@register
class UnreachableCode(Rule):
    meta = RuleMeta(
        "CM107", "potentially-unreachable-code", "bug", Severity.MEDIUM, Confidence.HIGH,
        "Statements follow a return/raise/break/continue or an exit call in the same block.",
        "Code after an unconditional jump never runs, usually indicating a leftover edit or a logic error.",
        "Remove the dead statements or restructure the control flow.",
        "def f():\n    return 1\n    cleanup()", "def f():\n    cleanup()\n    return 1",
        "Only straight-line, block-local flow is analysed; exit calls such as sys.exit() can be shadowed or patched, "
        "so those cases carry MEDIUM confidence.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        aliases = import_aliases(module)
        for symbol, scope in iter_scopes(module):
            for block in scope_blocks(scope):
                for index, stmt in enumerate(block[:-1]):
                    kind = _terminates(stmt, aliases)
                    if kind:
                        nxt = block[index + 1]
                        yield self.make(
                            module.path, nxt.lineno,
                            f"Statement at line {nxt.lineno} appears unreachable (line {stmt.lineno} always leaves the block).",
                            symbol=symbol,
                            confidence=Confidence.HIGH if kind == "definite" else Confidence.MEDIUM,
                        )
                        break


@register
class UnusedLocalVariable(Rule):
    meta = RuleMeta(
        "CM108", "unused-local-variable", "bug", Severity.LOW, Confidence.HIGH,
        "A local variable is assigned but never read in its function.",
        "Unused assignments are frequently typos or leftovers of refactoring and may hide a missed use.",
        "Remove the assignment (keep the right-hand side if it has side effects) or prefix the name with '_'.",
        "def f():\n    total = compute()\n    return 1", "def f():\n    compute()\n    return 1",
        "Only plain 'name = value' assignments are considered; tuple unpacking, loop variables and "
        "functions using locals()/eval()/exec() are skipped.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for fn in module.functions:
            loads: set[str] = set()
            declared: set[str] = set()
            dynamic = False
            for node in ast.walk(fn.node):
                if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Load, ast.Del)):
                    loads.add(node.id)
                    if node.id in {"locals", "vars", "eval", "exec"}:
                        dynamic = True
                elif isinstance(node, (ast.Global, ast.Nonlocal)):
                    declared.update(node.names)
            if dynamic:
                continue
            seen: set[str] = set()
            for node in walk_local(fn.node):
                targets: list[ast.expr] = []
                if isinstance(node, ast.Assign):
                    targets = [t for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
                    targets = [node.target]
                for target in targets:
                    name = target.id
                    if name.startswith("_") or name in loads or name in declared or name in seen:
                        continue
                    seen.add(name)
                    yield self.make(module.path, target.lineno,
                                    f"Local variable '{name}' in '{fn.qualname}' is assigned but never used.",
                                    symbol=fn.qualname, detail=name)


@register
class DuplicateDefinition(Rule):
    meta = RuleMeta(
        "CM109", "duplicate-definition", "bug", Severity.MEDIUM, Confidence.HIGH,
        "A function or class is defined twice in the same block.",
        "The later definition silently replaces the earlier one, so the first body is dead code.",
        "Rename or remove one of the definitions.",
        "def run(): ...\ndef run(): ...", "def run(): ...\ndef run_again(): ...",
        "Decorated definitions (property setters, overloads, singledispatch) are skipped.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        for symbol, scope in iter_scopes(module):
            for block in scope_blocks(scope):
                first: dict[str, int] = {}
                for stmt in block:
                    if isinstance(stmt, (*FUNCTION_TYPES, ast.ClassDef)):
                        if stmt.decorator_list:
                            first.pop(stmt.name, None)
                            continue
                        if stmt.name in first:
                            yield self.make(
                                module.path, stmt.lineno,
                                f"'{stmt.name}' is defined again; the definition at line {first[stmt.name]} is overridden.",
                                symbol=symbol, detail=stmt.name,
                            )
                        first[stmt.name] = stmt.lineno


@register
class EvalExecUsage(Rule):
    meta = RuleMeta(
        "CM110", "eval-exec-usage", "security", Severity.HIGH, Confidence.HIGH,
        "Use of the eval() or exec() builtins.",
        "Evaluating strings as code can execute attacker-controlled input and defeats static analysis.",
        "Use ast.literal_eval for literals, dispatch tables for behaviour, or a proper parser.",
        "result = eval(user_input)", "import ast\nresult = ast.literal_eval(user_input)",
        "Severity is reduced when the argument is a constant string. Whether input is attacker-controlled is not determined.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        aliases, shadowed = import_aliases(module), local_defs(module)
        for symbol, scope in iter_scopes(module):
            for node in walk_local(scope):
                if (
                    isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in ("eval", "exec")
                    and node.func.id not in aliases and node.func.id not in shadowed
                ):
                    constant = bool(node.args) and is_constant_string(node.args[0])
                    yield self.make(
                        module.path, node.lineno,
                        f"Call to {node.func.id}() "
                        + ("with a constant string." if constant else "with a dynamic argument; verify the input is trusted."),
                        symbol=symbol, detail=node.func.id,
                        severity=Severity.MEDIUM if constant else Severity.HIGH,
                    )


_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
_SHELL_ONLY = {"subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen"}


def _static_command(node: Optional[ast.AST]) -> bool:
    if node is None:
        return False
    if is_constant_string(node):
        return True
    return isinstance(node, (ast.List, ast.Tuple)) and all(is_constant_string(e) for e in node.elts)


@register
class UnsafeSubprocess(Rule):
    meta = RuleMeta(
        "CM111", "unsafe-subprocess", "security", Severity.HIGH, Confidence.HIGH,
        "A shell is used to run a command (shell=True, os.system, os.popen, subprocess.getoutput).",
        "Passing non-constant data to a shell can allow command injection through metacharacters.",
        "Pass an argument list without shell=True and validate or quote untrusted values (shlex.quote).",
        "subprocess.run(f'ls {path}', shell=True)", "subprocess.run(['ls', path], check=True)",
        "The rule cannot see where a variable came from; a dynamic command is a risk indicator, not proof of injection.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        aliases = import_aliases(module)
        for symbol, scope in iter_scopes(module):
            for node in walk_local(scope):
                if not isinstance(node, ast.Call):
                    continue
                name = qualified_name(node.func, aliases)
                if name in _SHELL_ONLY:
                    uses_shell = True
                elif name in _SUBPROCESS:
                    uses_shell = any(k.arg == "shell" and _is_const(k.value, True) for k in node.keywords)
                else:
                    continue
                if not uses_shell:
                    continue
                command = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "args"), None)
                static = _static_command(command)
                yield self.make(
                    module.path, node.lineno,
                    f"{name}() runs through a shell" + (" with a constant command." if static else "; the command is built dynamically."),
                    symbol=symbol, detail=name or "",
                    severity=Severity.MEDIUM if static else Severity.HIGH,
                    confidence=Confidence.HIGH if not static else Confidence.MEDIUM,
                )


_DESERIALIZERS = {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "shelve.open"}


@register
class UnsafeDeserialization(Rule):
    meta = RuleMeta(
        "CM113", "unsafe-deserialization", "security", Severity.MEDIUM, Confidence.MEDIUM,
        "Deserialisation with pickle/marshal/shelve or yaml.load without a safe loader.",
        "These formats can execute arbitrary code when loading data from an untrusted source.",
        "Use json, yaml.safe_load, or verify data integrity (for example an HMAC) before unpickling.",
        "obj = pickle.loads(blob)", "obj = json.loads(blob)",
        "Trusted internal data is legitimate; the rule only highlights the call site.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        aliases = import_aliases(module)
        for symbol, scope in iter_scopes(module):
            for node in walk_local(scope):
                if not isinstance(node, ast.Call):
                    continue
                name = qualified_name(node.func, aliases)
                risky = name in _DESERIALIZERS or (
                    name == "yaml.load" and not any(k.arg == "Loader" for k in node.keywords) and len(node.args) < 2
                )
                if risky:
                    yield self.make(module.path, node.lineno, f"Call to {name}() can execute code from untrusted data.",
                                    symbol=symbol, detail=name or "")


_OPENERS = {"open", "io.open", "codecs.open"}
_OWNERSHIP_CALLS = {"enter_context", "closing", "push", "callback"}


@register
class MissingResourceCleanup(Rule):
    meta = RuleMeta(
        "CM112", "missing-resource-cleanup", "bug", Severity.MEDIUM, Confidence.MEDIUM,
        "A file is opened without a 'with' block and no close() is statically visible.",
        "Unclosed files leak descriptors and may lose buffered writes, especially on non-CPython runtimes or when exceptions occur.",
        "Open files with 'with open(...) as handle:' so they are closed on every path.",
        "f = open(path)\ndata = f.read()", "with open(path) as f:\n    data = f.read()",
        "Only the builtin open()/io.open()/codecs.open() are tracked; closing through helpers or other objects is not seen, "
        "and handles passed to other owners are skipped.",
    )

    def check_module(self, module: ModuleInfo, ctx: RuleContext) -> Iterable[Finding]:
        aliases, shadowed = import_aliases(module), local_defs(module)
        for symbol, scope in iter_scopes(module):
            nodes = list(walk_local(scope))
            parents = {id(c): p for p in nodes for c in ast.iter_child_nodes(p)}
            managed = {
                id(n)
                for w in nodes if isinstance(w, (ast.With, ast.AsyncWith))
                for item in w.items for n in ast.walk(item.context_expr)
            }
            closed, owned = set(), set()
            for n in nodes:
                if isinstance(n, ast.Call):
                    if isinstance(n.func, ast.Attribute) and n.func.attr == "close" and isinstance(n.func.value, ast.Name):
                        closed.add(n.func.value.id)
                    tail = (dotted_name(n.func) or "").split(".")[-1]
                    if tail in _OWNERSHIP_CALLS:
                        owned.update(a.id for a in n.args if isinstance(a, ast.Name))
                elif isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) and isinstance(n.value, ast.Name):
                    owned.add(n.value.id)
            for node in nodes:
                if not isinstance(node, ast.Call) or id(node) in managed:
                    continue
                name = qualified_name(node.func, aliases)
                if name not in _OPENERS or (name == "open" and "open" in shadowed):
                    continue
                parent = parents.get(id(node))
                if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
                    var = parent.targets[0].id
                    if var in closed or var in owned:
                        continue
                    yield self.make(module.path, node.lineno,
                                    f"File opened into '{var}' without a 'with' block and no '{var}.close()' was found.",
                                    symbol=symbol, detail=var)
                elif isinstance(parent, ast.Attribute):
                    yield self.make(module.path, node.lineno,
                                    "File opened and used inline without 'with'; closing depends on garbage collection.",
                                    symbol=symbol, detail="inline", severity=Severity.LOW)
                elif isinstance(parent, ast.Call) and (dotted_name(parent.func) or "").split(".")[-1] not in _OWNERSHIP_CALLS:
                    yield self.make(module.path, node.lineno,
                                    "File opened as a call argument without 'with'; the handle is never explicitly closed.",
                                    symbol=symbol, detail="argument", severity=Severity.LOW)
                elif isinstance(parent, ast.Expr):
                    yield self.make(module.path, node.lineno, "Result of open() is discarded.", symbol=symbol, detail="discarded")
