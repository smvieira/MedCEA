"""apps/iam/compiler/routes_diff.py — the route table against the routes the services serve.

Under IAM_ENFORCE a route the code serves but the table lacks is refused (the service
breaks), and a table route no code serves is policy for nothing. diff(doc) compares
both directions, per service, with medcea_iam.match(), so it agrees with check() on
placeholders, specificity and the trailing-slash retry.

The served routes are read from the source, never imported (the services need Flask,
pg8000 and a cluster):
  flask     @app.route(path, methods=[...]) decorators; <int:id> is a <id> segment
  http      the do_<METHOD> methods of a BaseHTTPRequestHandler class: string constants
            compared with the path (==, !=, in), re.fullmatch/re.match patterns (a group
            of literal alternatives expands, an optional group may be absent, any other
            group is one segment) and startswith('/x/') prefixes. A do_<METHOD> with no
            path test answers every path (reported, not failed: check() refuses what the
            table lacks before the method runs).
  resolver  platform-api dispatches on a function of the path (_resolve), which is run
            alone on probe paths built from its own constants.

Two lists say which differences are planned. REMOVED: served now, removed by plan task
2.6. NOT_BUILT: in the table before their code exists. An entry that no longer applies
fails the diff, so neither list outlives its reason.
"""
import ast
import importlib.util
import os
import re
from urllib.parse import unquote

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

SOURCES = {
    "scheduler":      {"kind": "flask", "file": "apps/scheduler/scheduler-api.py"},
    "monitor":        {"kind": "flask", "file": "apps/monitor/monitor-api.py"},
    "dbmgmt":         {"kind": "http", "file": "apps/frontend/html/dbmgmt-api.py", "cls": "Handler"},
    "access-public":  {"kind": "http", "file": "apps/access/access-api.py", "cls": "Public"},
    "access":         {"kind": "http", "file": "apps/access/access-api.py", "cls": "Admin"},
    # oauth2-proxy forwards /_account/... and the handler strips the prefix.
    "access-profile": {"kind": "http", "file": "apps/access/access-api.py", "cls": "Profile", "mount": "/_account"},
    # do_PUT refuses a path without a file name (`if not fname`), so lists are GET only.
    "platform-api":   {"kind": "http", "file": "apps/frontend/k8s/recipe-fileserver.yaml", "key": "server.py",
                       "cls": "H", "resolver": "_resolve", "resolves": {"GET": ("list", "file"), "PUT": ("file",)}},
}

REMOVED = {
    ("scheduler", "POST /api/logs/delete"): "2.6",
    ("scheduler", "POST /api/logs/compress"): "2.6",
    ("scheduler", "DELETE /api/units/<uid>/algorithm-state"): "2.6",
    ("scheduler", "DELETE /api/units/<uid>/algorithm-state/<algorithm>"): "2.6",
}

NOT_BUILT = {
    ("iam", None): "4.1",
    ("iam-mqttx", None): "3.5",
    ("access", "GET /api/decisions"): "2.7",
    ("access", "POST /api/decisions/<id>/confirm"): "2.7",
    ("access", "GET /api/review"): "2.7",
    ("access", "POST /api/review/<id>/sign-off"): "2.7",
    ("access", "POST /api/users/<id>/person"): "2.7",
}

_PH = re.compile(r"<(?:[^<>:]+:)?([^<>]+)>")


def _medcea_iam():
    spec = importlib.util.spec_from_file_location(
        "medcea_iam", os.path.join(REPO, "apps", "iam", "lib", "medcea_iam.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _source(src):
    path = os.path.join(REPO, src["file"])
    with open(path) as fh:
        text = fh.read()
    if "key" in src:
        for doc in yaml.safe_load_all(text):
            if doc and src["key"] in (doc.get("data") or {}):
                return doc["data"][src["key"]]
        raise ValueError(f"{src['file']}: no data key {src['key']}")
    return text


def _const(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _pattern(node):
    """A regex argument: a string, or 'string' % NAME (a sub-pattern, read as one segment)."""
    if _const(node) is not None:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _const(node.left) is not None:
        return node.left.value.replace("%s", "[^/]+")
    return None


def expand(rx):
    """The path templates a fullmatch pattern accepts."""
    out, i = [""], 0
    while i < len(rx):
        c = rx[i]
        if c == "(":
            depth, j = 1, i + 1
            while depth:
                depth += {"(": 1, ")": -1}.get(rx[j], 0)
                j += 1
            body, opt = rx[i + 1:j - 1], rx[j:j + 1] == "?"
            alts = body.split("|") if re.fullmatch(r"[\w/-]+(\|[\w/-]+)*", body) else ["<x>"]
            if opt:
                alts.append("")
                j += 1
            out = [o + a for o in out for a in alts]
            i = j
        elif c in "\\.^$*+?[]{}|":
            raise ValueError(f"cannot read pattern {rx!r} outside a group")
        else:
            out = [o + c for o in out]
            i += 1
    return out


def _flask(tree):
    served = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        for d in fn.decorator_list:
            if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route"):
                continue
            path = _PH.sub(r"<\1>", _const(d.args[0]))
            methods = ["GET"]
            for kw in d.keywords:
                if kw.arg == "methods":
                    methods = [_const(e) for e in kw.value.elts]
            served |= {(m, path) for m in methods}
    return served, set(), set()


def _resolver(tree, name, resolves):
    """{(method, template)} from running the resolver alone on probe paths."""
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    consts = [n for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)]
    ns = {"unquote": unquote}
    exec(compile(ast.Module(body=consts + [fn], type_ignores=[]), name, "exec"), ns)  # noqa: S102
    prefixes = {s for n in ast.walk(fn) if (s := _const(n)) and s.startswith("/") and s != "/" and not s.endswith("/")}
    bases = {}
    for p in sorted(prefixes) + ["/"]:
        base, _, is_list = ns[name](p)
        if is_list:
            bases.setdefault(base, "" if p == "/" else p)
    served = set()
    for p in ["/", "/f.json"] + [q for p in sorted(prefixes) for q in (p, p + "/", p + "/f.json", p + "/a/b.json")]:
        base, fname, is_list = ns[name](p)
        kind = "list" if is_list else "file" if fname else None
        if kind is None:
            continue
        path = (bases[base] or "/") if kind == "list" else bases[base] + "/<file>"
        served |= {(m, path) for m, kinds in resolves.items() if kind in kinds}
    return served


def _http(tree, src):
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == src["cls"])
    mount = src.get("mount", "")
    served, prefixes, catch_all = set(), set(), set()
    resolved = _resolver(tree, src["resolver"], src["resolves"]) if "resolver" in src else set()
    for fn in cls.body:
        if not (isinstance(fn, ast.FunctionDef) and fn.name.startswith("do_")):
            continue
        m, found = fn.name[3:], set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Compare):
                for side in [n.left] + n.comparators:
                    elts = side.elts if isinstance(side, (ast.Tuple, ast.List, ast.Set)) else [side]
                    found |= {s for e in elts if (s := _const(e)) is not None and (s == "" or s.startswith("/"))}
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.args:
                if n.func.attr in ("fullmatch", "match") and isinstance(n.func.value, ast.Name) and n.func.value.id == "re":
                    rx = _pattern(n.args[0])
                    if rx is None:
                        raise ValueError(f"{src['file']} {src['cls']}.{fn.name}: a pattern that is not a constant")
                    found |= set(expand(rx))
                elif n.func.attr == "startswith" and (s := _const(n.args[0])) and s.endswith("/"):
                    prefixes.add((m, mount + s))
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == src.get("resolver"):
                found.add(None)
        if None in found:
            found.discard(None)
            served |= {r for r in resolved if r[0] == m}
        elif not found and not any(p[0] == m for p in prefixes):
            catch_all.add(m)
        served |= {(m, mount + (p or "/") if mount else p or "/") for p in found}
    return served, prefixes, catch_all


def served(service):
    """(routes, prefixes, catch-all methods) the service's code answers."""
    src = SOURCES[service]
    tree = ast.parse(_source(src))
    return _flask(tree) if src["kind"] == "flask" else _http(tree, src)


def _sample(path):
    return _PH.sub("x1", path)


def diff(doc):
    """{service: {...}} and the list of failures. Per service: matched (count), unlisted
    (served, not in the table), missing (in the table, not served), removed and
    not_built (planned differences), catch_all (methods answered on every path)."""
    iam = _medcea_iam()
    out, failures = {}, []
    used = set()
    tables = {s: dict(d["routes"]) for s, d in doc["services"].items()}
    for s, routes in doc["public"].items():
        if s != "*":
            tables.setdefault(s, {}).update({r: None for r in routes})
    for s in sorted(set(tables) | set(SOURCES)):
        if (s, None) in NOT_BUILT:
            used.add((s, None))
            out[s] = {"not_built_service": NOT_BUILT[(s, None)]}
            if s in SOURCES:
                failures.append(f"{s}: listed as not built (plan {NOT_BUILT[(s, None)]}) but has a source")
            continue
        if s not in SOURCES:
            failures.append(f"{s}: in the route table, but routes_diff.SOURCES does not say where its code is")
            continue
        everywhere = {r: None for r in doc["public"].get("*", [])}
        table = dict(tables.get(s, {}), **everywhere)
        mount = SOURCES[s].get("mount", "")
        code, prefixes, catch_all = served(s)
        code_table = {f"{m} {p}": None for m, p in code}
        r = out[s] = {"matched": 0, "unlisted": [], "missing": [], "removed": [], "not_built": [],
                      "catch_all": sorted(catch_all)}
        for m, p in sorted(code | prefixes):
            key = f"{m} {p}"
            sample = _sample(p) + ("x1" if (m, p) in prefixes else "")
            # A mounted handler also answers without the prefix: the kubelet's /healthz.
            if iam.match(table, m, sample) or (mount and iam.match(everywhere, m, sample[len(mount):])):
                r["matched"] += 1
            elif (s, key) in REMOVED:
                used.add((s, key))
                r["removed"].append((key, REMOVED[(s, key)]))
            else:
                r["unlisted"].append(key)
        for key in sorted(tables.get(s, {})):
            m, _, p = key.partition(" ")
            sample = _sample(p)
            if m in catch_all or iam.match(code_table, m, sample) or any(m == pm and sample.startswith(pp) and len(sample) > len(pp)
                                                       for pm, pp in prefixes):
                continue
            if (s, key) in NOT_BUILT:
                used.add((s, key))
                r["not_built"].append((key, NOT_BUILT[(s, key)]))
            else:
                r["missing"].append(key)
        failures += [f"{s}: {k} is served but not in the route table" for k in r["unlisted"]]
        failures += [f"{s}: {k} is in the route table but no code serves it" for k in r["missing"]]
    for (s, key), phase in {**REMOVED, **NOT_BUILT}.items():
        if (s, key) not in used:
            failures.append(f"{s}: {key or 'the service'} is listed for plan {phase}, but no longer differs; "
                            "drop the entry from routes_diff.py")
    return out, failures
