"""apps/research-model/endpoints_config.py (research Phase 4d): the model endpoints of this install, from config.env.

The shipped apps/research-model/endpoints.json names only `local`. Every other endpoint is configuration, never code:
for an endpoint NAME (lower-case letters, digits, '-'; V = NAME upper-cased with '-' as '_') config.env holds

    RESEARCH_ENDPOINT_<V>_URL            http(s)://host:port of an OpenAI-compatible server (no /v1)
    RESEARCH_ENDPOINT_<V>_MODEL          the model the server serves
    RESEARCH_ENDPOINT_<V>_CONTEXT        its context, in tokens
    RESEARCH_ENDPOINT_<V>_MAX_OUTPUT     optional: at most this many output tokens a turn (the gateway caps it at 1024)
    RESEARCH_ENDPOINT_<V>_DETERMINISTIC  true when the server honours a seed (vLLM does), else false
    RESEARCH_ENDPOINT_<V>_THINKING       optional: false sends enable_thinking false (Qwen3), true sends true
    RESEARCH_ENDPOINT_<V>_TOOLS          native (the server's tool calls) or text (tools in the prompt, Hermes form)
    RESEARCH_ENDPOINT_<V>_KEY            optional: the API key (a secret: it goes into Secret model-gateway-keys only)

and RESEARCH_ENDPOINTS names the endpoints the gateway serves. The deploy exports these variables to this helper
only; it reads them from its environment, never from argv, and never prints a key.

    python3 endpoints_config.py doc BASE ENABLED   the endpoints document (stdout), checked; exit 1 with a message
    python3 endpoints_config.py secret NAMESPACE   Secret model-gateway-keys as JSON (stdout), for kubectl apply -f -
    python3 endpoints_config.py inventory BASE ENABLED PINS
                                                   the enabled endpoints as the scientist's model picker shows them
                                                   (name, model, context, ...; never a URL or a key), base64 JSON
"""
import json
import os
import re
import sys

PREFIX = "RESEARCH_ENDPOINT_"
FIELDS = ("URL", "MODEL", "CONTEXT", "MAX_OUTPUT", "DETERMINISTIC", "THINKING", "TOOLS", "KEY")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
KEY_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{8,512}$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


class ConfigError(Exception):
    pass


def _bool(v, what, optional=False):
    if optional and v == "":
        return None
    if v not in ("true", "false"):
        raise ConfigError("%s is true or false%s, not %r" % (what, " or empty" if optional else "", v))
    return v == "true"


def configured(env):
    """{name: {field: value}} for every RESEARCH_ENDPOINT_<V>_URL in env."""
    out = {}
    for k in sorted(env):
        if not k.startswith(PREFIX) or not k.endswith("_URL"):
            continue
        v = k[len(PREFIX):-len("_URL")]
        name = v.lower().replace("_", "-")
        if not re.match(r"^[A-Z][A-Z0-9_]*$", v) or not NAME_RE.match(name) or name == "local":
            raise ConfigError("%s: an endpoint name is lower-case letters, digits and '-', and not local" % k)
        out[name] = {f: env.get(PREFIX + v + "_" + f, "") for f in FIELDS}
    return out


def entry(name, c):
    w = PREFIX + name.upper().replace("-", "_") + "_"
    if not URL_RE.match(c["URL"]):
        raise ConfigError("%sURL is http(s)://host:port, not %r" % (w, c["URL"]))
    if not c["MODEL"] or len(c["MODEL"]) > 200 or not re.match(r"^[A-Za-z0-9._:/@-]+$", c["MODEL"]):
        raise ConfigError("%sMODEL is the model's name as the server lists it" % w)
    try:
        ctx = int(c["CONTEXT"])
        mo = int(c["MAX_OUTPUT"]) if c["MAX_OUTPUT"] else 1024
    except ValueError:
        raise ConfigError("%sCONTEXT and %sMAX_OUTPUT are whole numbers" % (w, w))
    if not 512 <= ctx <= 1000000 or not 16 <= mo <= 1024:
        raise ConfigError("%sCONTEXT is 512 to 1000000, %sMAX_OUTPUT 16 to 1024" % (w, w))
    tools = c["TOOLS"] or "native"
    if tools not in ("native", "text"):
        raise ConfigError("%sTOOLS is native or text" % w)
    if c["KEY"] and not KEY_RE.match(c["KEY"]):
        raise ConfigError("%sKEY holds characters an API key does not have" % w)
    e = {"kind": "openai", "url": c["URL"], "model": c["MODEL"], "context": ctx, "max_output": mo,
         "deterministic": _bool(c["DETERMINISTIC"], w + "DETERMINISTIC"), "tools": tools,
         "key": "secret" if c["KEY"] else "none"}
    th = _bool(c["THINKING"], w + "THINKING", optional=True)
    if th is not None:
        e["thinking"] = th
    return e


def document(base, env, enabled):
    with open(base, encoding="utf-8") as f:
        doc = json.load(f)
    eps = dict(doc.get("endpoints") or {})
    for name, c in configured(env).items():
        if name in eps:
            raise ConfigError("endpoint %s is defined both in %s and in config.env" % (name, os.path.basename(base)))
        eps[name] = entry(name, c)
    for n in enabled:
        if n not in eps:
            raise ConfigError("RESEARCH_ENDPOINTS names %s, which neither endpoints.json nor config.env "
                              "(RESEARCH_ENDPOINT_%s_URL ...) defines" % (n, n.upper().replace("-", "_")))
    return {"_comment": doc.get("_comment", ""), "endpoints": eps}


LOCAL_MODEL_KEY = "4b"      # apps/research-model/deploy.sh MODEL_KEY
LOCAL_CONTEXT = 4096        # apps/research-model/deploy.sh LLM_CTX (owner decision of 21 Nov 2026)


def local_alias(pins_path):
    """The local model's alias exactly as apps/research-model/deploy.sh makes it (<file stem lower-cased>-<sha12>)."""
    with open(pins_path, encoding="utf-8") as f:
        m = json.load(f)["models"][LOCAL_MODEL_KEY]
    stem = m["file"][:-5] if m["file"].endswith(".gguf") else m["file"]
    return "%s-%s" % (stem.lower(), m["sha256"][:12])


def inventory(base, env, enabled, pins_path):
    """[{name, kind, model, context, deterministic, tools, thinking?, where}] for the enabled endpoints, in the order
    RESEARCH_ENDPOINTS names them: what a scientist chooses from. No URL, address or key: where says only whether
    the model runs on this host."""
    eps = document(base, env, enabled)["endpoints"]
    out = []
    for n in enabled:
        e = eps[n]
        if n == "local":
            out.append({"name": n, "kind": "llama", "model": local_alias(pins_path), "context": LOCAL_CONTEXT,
                        "deterministic": True, "tools": "native", "where": "this host (CPU)"})
            continue
        i = {"name": n, "kind": e["kind"], "model": e["model"], "context": e["context"],
             "deterministic": e["deterministic"], "tools": e.get("tools", "native"), "where": "another server"}
        if "thinking" in e:
            i["thinking"] = e["thinking"]
        out.append(i)
    return out


def secret(ns, env):
    data = {name: c["KEY"] for name, c in configured(env).items() if c["KEY"]}
    for name, k in data.items():
        if not KEY_RE.match(k):
            raise ConfigError("the key of endpoint %s holds characters an API key does not have" % name)
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": "model-gateway-keys", "namespace": ns, "labels": {"app": "model-gateway"}},
            "stringData": data}


def main(argv, env):
    try:
        if len(argv) == 3 and argv[0] == "doc":
            print(json.dumps(document(argv[1], env, argv[2].split()), indent=1, sort_keys=True))
        elif len(argv) == 2 and argv[0] == "secret":
            print(json.dumps(secret(argv[1], env)))
        elif len(argv) == 4 and argv[0] == "inventory":
            import base64
            doc = json.dumps(inventory(argv[1], env, argv[2].split(), argv[3]), separators=(",", ":"), sort_keys=True)
            print(base64.b64encode(doc.encode()).decode())
        else:
            print(__doc__.strip().splitlines()[-2:], file=sys.stderr)
            return 2
    except ConfigError as e:
        print("endpoints: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], os.environ))
