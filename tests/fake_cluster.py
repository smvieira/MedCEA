#!/usr/bin/env python3
"""tests/fake_cluster.py — a stateful stand-in for microk8s, kubectl, helm and the host
commands the deploy scripts call, for the offline tests of IAM 4.2b's scoped modes
(tests/test_scoped_deploy.py).

Installed as several names in one bin directory (symlinks); argv[0] says which:
  microk8s   status → 0; kubectl ARGS → the fake kubectl; helm3 ARGS → the fake helm
  curl       -w … → prints 200 (wait_for_http); anything else fails (no Keycloak)
  systemctl  --user show-environment → 0; show -p ControlGroup → $FAKE_CGROUP;
             restart → copies $FAKE_PGREP_NEXT over $FAKE_PGREP
  pgrep      prints the file $FAKE_PGREP (the wizard daemon's argv)
  sleep, fuser, loginctl, journalctl, sudo → nothing

FAKE_HELM_FAIL=<release>[:n] (IAM 4.5, tests/test_apply.py): helm upgrade/install of
<release> fails, the first n times only with :n (fault injection, offline only).

FAKE_STATE (JSON: {"kind/name": object}) is the cluster; FAKE_LOG gets one JSON line per
call: {"cmd", "argv", "write", "stdin" (sha256 of what it read, written_at redacted),
"values" (sha256 of each helm --values file)}. A write is anything that would change the
cluster (apply, create without --dry-run, delete, patch, label/annotate without --local,
set, rollout restart, helm upgrade/install/uninstall, systemctl restart).
"""
import base64
import hashlib
import json
import os
import re
import shutil
import sys

import yaml

KINDS = {"cm": "configmap", "configmap": "configmap", "configmaps": "configmap",
         "netpol": "networkpolicy", "networkpolicy": "networkpolicy", "networkpolicies": "networkpolicy",
         "deploy": "deployment", "deployment": "deployment", "deployments": "deployment",
         "secret": "secret", "secrets": "secret", "pod": "pod", "pods": "pod", "po": "pod",
         "node": "node", "nodes": "node", "ingress": "ingress", "ingresses": "ingress",
         "svc": "service", "service": "service", "replicaset": "replicaset", "statefulset": "statefulset"}
KIND_NAME = {"configmap": "ConfigMap", "networkpolicy": "NetworkPolicy", "deployment": "Deployment",
             "secret": "Secret", "pod": "Pod", "node": "Node", "ingress": "Ingress", "service": "Service"}


def load():
    try:
        with open(os.environ["FAKE_STATE"]) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(st):
    with open(os.environ["FAKE_STATE"], "w") as f:
        json.dump(st, f, sort_keys=True)


def redact(text):
    return re.sub(r'written_at[\\"]*:\s*[\\"]*[0-9TZ:-]+[\\"]*', "written_at", text)


def log(cmd, argv, write, stdin=None, values=None):
    rec = {"cmd": cmd, "argv": argv, "write": write}
    if stdin is not None:
        rec["stdin"] = hashlib.sha256(redact(stdin).encode()).hexdigest()[:16]
    if values:
        rec["values"] = values
    with open(os.environ["FAKE_LOG"], "a") as f:
        f.write(json.dumps(rec) + "\n")


# ── jsonpath (the subset the scripts use) ───────────────────────────────────────────────
def _tokens(path):
    toks, cur, i = [], "", 0
    while i < len(path):
        c = path[i]
        if c == "\\" and i + 1 < len(path):
            cur += path[i + 1]
            i += 2
        elif c == ".":
            if cur:
                toks.append(cur)
            cur, i = "", i + 1
        elif c == "[":
            j = path.index("]", i)
            cur += path[i:j + 1]
            i = j + 1
        else:
            cur += c
            i += 1
    if cur:
        toks.append(cur)
    return toks


def _walk(vals, path):
    for tok in _tokens(path):
        name, brackets = re.match(r"([^\[]*)((?:\[[^\]]*\])*)", tok).groups()
        nxt = []
        for v in vals:
            if name:
                if not isinstance(v, dict) or name not in v:
                    continue
                v = v[name]
            cur = [v]
            for b in re.findall(r"\[([^\]]*)\]", brackets):
                out = []
                for x in cur:
                    if not isinstance(x, list):
                        continue
                    if b == "*":
                        out += x
                    elif re.fullmatch(r"\d+", b):
                        if int(b) < len(x):
                            out.append(x[int(b)])
                    else:
                        m = re.fullmatch(r'\?\(@\.(\w+)=="([^"]*)"\)', b)
                        out += [y for y in x if isinstance(y, dict) and m and y.get(m.group(1)) == m.group(2)]
                cur = out
            nxt += cur
        vals = nxt
    return vals


def jsonpath(obj, expr):
    m = re.fullmatch(r'\{range (.+?)\}\{\.name\}=\{\.value\}\{"\\n"\}\{end\}', expr)
    if m:   # the env listing (health grafanarole, pa_grafana)
        return "".join(f"{e.get('name')}={e.get('value', '')}\n" for e in _walk([obj], m.group(1)))
    if expr.startswith("{range"):
        return ""
    out = []
    for part in re.findall(r"\{([^}]*)\}", expr):
        vals = _walk([obj], part)
        out.append(" ".join(v if isinstance(v, str) else json.dumps(v) for v in vals))
    return "".join(out)


# ── kubectl ─────────────────────────────────────────────────────────────────────────────
def parse(args):
    o = {"pos": [], "files": [], "literals": [], "flags": set(), "out": None, "sel": None}
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-n", "--namespace", "-c", "--timeout", "-p", "--type", "--field-selector", "--tail"):
            if a == "-p":
                o["patch"] = args[i + 1]
            i += 2
            continue
        if a == "-o":
            o["out"] = args[i + 1]
            i += 2
            continue
        if a.startswith("-o"):
            o["out"] = a[2:].lstrip("=")
        elif a == "-l":
            o["sel"] = args[i + 1]
            i += 1
        elif a == "-f":
            o["file"] = args[i + 1]
            i += 1
        elif a.startswith("--from-file="):
            o["files"].append(a.split("=", 1)[1])
        elif a.startswith("--from-literal="):
            o["literals"].append(a.split("=", 1)[1])
        elif a.startswith("--"):
            o["flags"].add(a.split("=", 1)[0] + ("=" + a.split("=", 1)[1] if a.startswith("--dry-run") else ""))
        elif a == "--":
            o["pos"] += args[i + 1:]
            break
        else:
            o["pos"].append(a)
        i += 1
    return o


def emit(obj, fmt):
    if fmt is None:
        print(obj["metadata"]["name"])
    elif fmt in ("json", "yaml"):
        print(json.dumps(obj, sort_keys=True))
    elif fmt.startswith("jsonpath="):
        sys.stdout.write(jsonpath(obj, fmt[len("jsonpath="):]))
    elif fmt == "name":
        print(obj["metadata"]["name"])


def sel_match(obj, sel):
    if not sel:
        return True
    labels = obj.get("metadata", {}).get("labels") or {}
    for term in sel.split(","):
        k, _, v = term.partition("=")
        if labels.get(k) != v:
            return False
    return True


def stored(st, obj):
    obj = json.loads(json.dumps(obj))
    if obj.get("kind") == "Secret" and obj.get("stringData"):
        data = obj.setdefault("data", {})
        for k, v in obj.pop("stringData").items():
            data[k] = base64.b64encode(str(v).encode()).decode()
    kind = KINDS.get(obj.get("kind", "").lower(), obj.get("kind", "").lower())
    st[f"{kind}/{obj['metadata']['name']}"] = obj


def docs(text):
    out = []
    for d in yaml.safe_load_all(text):
        if not d:
            continue
        out += d.get("items") or [] if d.get("kind") == "List" else [d]
    return out


def kubectl(args):
    st = load()
    verb = args[0] if args else ""
    o = parse(args[1:])
    stdin = None
    if o.get("file") == "-" or verb == "exec" and "-i" in args or any(f.endswith("/dev/stdin") for f in o["files"]):
        stdin = sys.stdin.read()
    if verb in ("cluster-info", "version", "port-forward", "logs", "describe"):
        log("kubectl", args, False)
        return 0
    if verb == "get":
        log("kubectl", args, False)
        kinds = o["pos"][0].split(",") if o["pos"] else []
        kind = KINDS.get(kinds[0], kinds[0]) if kinds else ""
        if kind == "node":   # one node, its InternalIP (the NetworkPolicies need one)
            sys.stdout.write("192.0.2.10 ")
            return 0
        names = o["pos"][1:]
        if names:
            found = [st[f"{kind}/{n}"] for n in names if f"{kind}/{n}" in st]
            if not found:
                if "--ignore-not-found" in o["flags"]:
                    return 0
                print(f'Error from server (NotFound): {kind} "{names[0]}" not found', file=sys.stderr)
                return 1
            if len(names) == 1:
                emit(found[0], o["out"])
            else:
                emit({"kind": "List", "items": found, "metadata": {"name": "list"}}, o["out"])
            return 0
        items = [v for k, v in sorted(st.items()) if k.startswith(kind + "/") and sel_match(v, o["sel"])]
        emit({"kind": "List", "items": items, "metadata": {"name": "list"}}, o["out"])
        return 0
    if verb == "create" and o["pos"] and o["pos"][0] in ("configmap", "cm"):
        data = {}
        for f in o["files"]:
            k, eq, path = f.partition("=")
            if not eq:   # --from-file=PATH (a file or a directory, keyed by name)
                k, path = os.path.basename(f.rstrip("/")), f
            if path == "/dev/stdin":
                data[k] = stdin
            elif os.path.isdir(path):
                for n in sorted(os.listdir(path)):
                    with open(os.path.join(path, n)) as fh:
                        data[n] = fh.read()
            else:
                with open(path) as fh:
                    data[k] = fh.read()
        for lit in o["literals"]:
            k, _, v = lit.partition("=")
            data[k] = v
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": o["pos"][1]}, "data": data}
        dry = any(f.startswith("--dry-run") for f in o["flags"])
        log("kubectl", args, not dry, stdin)
        if dry:
            print(json.dumps(cm, sort_keys=True))
        else:
            stored(st, cm)
            save(st)
        return 0
    if verb in ("label", "annotate") and "--local" in o["flags"]:
        log("kubectl", args, False, stdin)
        obj = yaml.safe_load(stdin)
        key = "labels" if verb == "label" else "annotations"
        for kv in o["pos"]:
            k, _, v = kv.partition("=")
            obj.setdefault("metadata", {}).setdefault(key, {})[k] = v
        print(json.dumps(obj, sort_keys=True))
        return 0
    if verb == "apply":
        if stdin is None and o.get("file"):
            with open(o["file"]) as fh:
                stdin = fh.read()
        log("kubectl", args, True, stdin)
        for d in docs(stdin or ""):
            stored(st, d)
        save(st)
        return 0
    if verb == "delete":
        log("kubectl", args, True)
        kind = KINDS.get(o["pos"][0], o["pos"][0]) if o["pos"] else ""
        for n in o["pos"][1:]:
            st.pop(f"{kind}/{n}", None)
        if o["sel"]:
            for k in [k for k, v in st.items() if k.startswith(kind + "/") and sel_match(v, o["sel"])]:
                st.pop(k)
        save(st)
        return 0
    if verb == "rollout":
        log("kubectl", args, o["pos"][:1] == ["restart"])
        return 0
    if verb == "exec":
        log("kubectl", args, False, stdin)
        return 0
    log("kubectl", args, verb in ("patch", "set", "label", "annotate", "create", "scale", "replace"), stdin)
    return 0


# ── helm ────────────────────────────────────────────────────────────────────────────────
def setpath(d, path, value):
    keys = re.findall(r"(?:[^.\\]|\\.)+", path)
    keys = [k.replace("\\.", ".") for k in keys]
    for k in keys[:-1]:
        m = re.fullmatch(r"(.+)\[(\d+)\]", k)
        if m:
            lst = d.setdefault(m.group(1), [])
            while len(lst) <= int(m.group(2)):
                lst.append({})
            d = lst[int(m.group(2))]
        else:
            d = d.setdefault(k, {})
    d[keys[-1]] = value


def helm(args):
    if args[:1] not in (["upgrade"], ["install"], ["uninstall"]):
        log("helm", args, False)
        return 0
    rel = [a for a in args[1:] if not a.startswith("-")][0]
    chart = ""
    values, sets, digests = {}, {}, []
    i = 1
    pos = []
    while i < len(args):
        a = args[i]
        if a in ("--values", "-f"):
            with open(args[i + 1]) as fh:
                text = fh.read()
            digests.append(hashlib.sha256(text.encode()).hexdigest()[:16])
            v = yaml.safe_load(text) or {}
            values = merge(values, v)
            i += 2
            continue
        if a == "--set":
            k, _, v = args[i + 1].partition("=")
            sets[k] = v
            i += 2
            continue
        if a in ("--version", "--namespace", "-n", "--timeout"):
            i += 2
            continue
        if not a.startswith("-"):
            pos.append(a)
        i += 1
    if len(pos) > 1:
        chart = pos[1]
    if helm_fails(rel, args[0]):
        log("helm", args, False, values=digests)
        print(f"Error: UPGRADE FAILED: {rel}: injected by FAKE_HELM_FAIL", file=sys.stderr)
        return 1
    log("helm", args, True, values=digests)
    if args[0] == "uninstall":
        return 0
    for k, v in sets.items():
        setpath(values, k, v)
    st = load()
    ann = {k: str(v) for k, v in (values.get("podAnnotations") or {}).items()}
    if "oauth2-proxy" in chart:
        cfg = (values.get("configuration") or {}).get("content") or ""
        st[f"configmap/{rel}"] = {"kind": "ConfigMap", "metadata": {"name": rel}, "data": {"oauth2_proxy.cfg": cfg}}
        st[f"deployment/{rel}"] = {"kind": "Deployment", "metadata": {"name": rel},
                                   "spec": {"template": {"metadata": {"annotations": ann}, "spec": {"containers": []}}}}
    elif "grafana" in chart:
        env = [{"name": k, "value": str(v)} for k, v in (values.get("env") or {}).items()]
        st["deployment/grafana"] = {"kind": "Deployment", "metadata": {"name": "grafana"},
                                    "spec": {"template": {"metadata": {"annotations": ann},
                                                          "spec": {"containers": [{"name": "grafana", "env": env}]}}}}
    elif "jupyterhub" in chart:
        st["secret/hub"] = {"kind": "Secret", "metadata": {"name": "hub"},
                            "data": {"values.yaml": base64.b64encode(yaml.safe_dump(values).encode()).decode()}}
        st["deployment/hub"] = {"kind": "Deployment", "metadata": {"name": "hub"}, "spec": {"template": {"metadata": {}}}}
    save(st)
    return 0


def helm_fails(rel, verb):
    """IAM 4.5's fault injection, offline only (design §14.8.11): FAKE_HELM_FAIL=<release>[:n]
    fails the first n upgrades or installs of <release> (every one without :n); counted from
    FAKE_LOG, so a retry sees its earlier attempts."""
    spec = os.environ.get("FAKE_HELM_FAIL", "")
    if verb == "uninstall" or not spec:
        return False
    name, _, n = spec.partition(":")
    if name != rel:
        return False
    if not n:
        return True
    seen = 0
    try:
        with open(os.environ["FAKE_LOG"]) as f:
            for line in f:
                rec = json.loads(line)
                a = rec.get("argv") or []
                if rec.get("cmd") == "helm" and a[:1] in (["upgrade"], ["install"]) and \
                        [x for x in a[1:] if not x.startswith("-")][:1] == [rel]:
                    seen += 1
    except (KeyError, OSError):
        pass
    return seen < int(n)


def merge(a, b):
    out = dict(a)
    for k, v in b.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def main():
    me = os.path.basename(sys.argv[0])
    args = sys.argv[1:]
    if me == "microk8s":
        if args[:1] == ["status"]:
            return 0
        if args[:1] == ["kubectl"]:
            return kubectl(args[1:])
        if args[:1] == ["helm3"]:
            return helm(args[1:])
        log("microk8s", args, False)
        return 0
    if me == "curl":
        log("curl", args, False)
        if "-w" in args:
            sys.stdout.write("200")
            return 0
        return 7
    if me == "systemctl":
        restart = "restart" in args
        log("systemctl", args, restart)
        if "show" in args and "ControlGroup" in " ".join(args):
            print(os.environ.get("FAKE_CGROUP", ""))
        if restart and os.environ.get("FAKE_PGREP_NEXT"):
            shutil.copy(os.environ["FAKE_PGREP_NEXT"], os.environ["FAKE_PGREP"])
        return 0
    if me == "pgrep":
        try:
            with open(os.environ["FAKE_PGREP"]) as f:
                sys.stdout.write(f.read())
        except (KeyError, OSError):
            return 1
        return 0
    log(me, args, False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
