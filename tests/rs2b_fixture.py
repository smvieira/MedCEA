"""tests/rs2b_fixture.py — the access policy of research sandbox Phase 2b's commit B, built
from the factory file, for the tests of commit A's code (and every area's tests).

Commit A does not change apps/iam/policy/defaults.yaml; its code keys on YAML that only
commit B adds (codeplan SPEC §3.1). These builders give the tests that YAML without B:

  b_policy(data=None)          v7 (the factory file, or `data`) plus every commit B change:
                               network.zones.research.internet_except, the zone pods hub,
                               workbench-proxy, notebooks and lake-api with their hops,
                               pod:lake-api on research-postgresql, network.clients.notebooks
                               and config-api's client:notebooks gone, research_workbench's
                               risk text, invariant I19, measurements without the two
                               scientists and analysis: {} (the matrix B carries)
  with_notebooks_client(d)     d with v7's network.clients.notebooks (and config-api's
                               client:notebooks source) back when absent; identity on v7's
                               defaults. Tests that mutate the client go through it, so they
                               keep working once commit B removed it from the factory file.

Both return a new dict (deep copies); neither reads or writes anything but the factory file.
Only area 1 (compiler) edits this module; the other areas import it.
"""
import copy
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(REPO, "apps", "iam") not in sys.path:
    sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
from compiler import model  # noqa: E402

INTERNET_EXCEPT = ["10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"]
HUB_SEL = {"app": "jupyterhub", "component": "hub", "release": "workbench"}
PROXY_SEL = {"app": "jupyterhub", "component": "proxy", "release": "workbench"}
NOTEBOOKS_SEL = {"app": "jupyterhub", "component": "singleuser-server", "release": "workbench"}
LAKE_API_SEL = {"app": "lake-api"}

# v7's network.clients.notebooks (IAM 3.2b), word for word, and where config-api admits it
V7_NOTEBOOKS_CLIENT = {
    "selector": dict(NOTEBOOKS_SEL),
    "token_client": "workbench-notebook",
    "read_only": True,
    "egress": [
        {"pod": "config-api", "port": 3000,
         "why": "PostgREST with the person's own token: the database applies their rr_ role and row security"},
        {"selector": {"app": "keycloak"}, "port": 8080,
         "why": "the device-code sign-in and token refresh (Service keycloak, client workbench-notebook)"},
    ],
    "why": "Reading platform data from a notebook, per person (IAM 3.2b; manual: AI workbench)",
}
V7_CONFIG_API_INDEX = 2   # "client:notebooks" sat third in config-api's port-3000 sources

I19 = {"code": "I19", "kind": "matrix",
       "rule": "On a group with zone research, admin holds nothing, except K on research_workbench.",
       "rationale": "Separation of duties (SoD-3): administering the AI workbench is not doing research in it.",
       "cites": "MedCEA concept, research/production separation; PIC/S PI 041-1 §9.3"}

RISK = ("Notebooks run code. They run in the research zone and read person-free snapshots through "
        "lake-api, which asks for no identity; they reach only the hub, lake-api and the internet on "
        "TCP 443, never a private address. The hub cannot read Secrets, and the zone's namespace "
        "enforces Pod Security baseline.")


def _factory():
    return copy.deepcopy(model.load_defaults().data)


def _config_api_rule(net):
    return next(r for r in net["pods"]["config-api"]["ingress"] if r.get("port") == 3000)


def b_policy(data=None):
    """v7 (the factory file, or a copy of `data`) with every commit B change (SPEC §3.1)."""
    d = copy.deepcopy(data) if data is not None else _factory()
    net = d["network"]
    net.setdefault("zones", {}).setdefault("research", {})
    net["zones"]["research"] = dict(net["zones"]["research"] or {}, internet_except=list(INTERNET_EXCEPT))
    rule = _config_api_rule(net)
    rule["from"] = [s for s in rule["from"] if s != "client:notebooks"]
    pg = net["pods"]["research-postgresql"]["ingress"][0]["from"]
    if "pod:lake-api" not in pg:
        pg.insert(pg.index("node") if "node" in pg else len(pg), "pod:lake-api")
    pods = net["pods"]
    pods["hub"] = {
        "zone": "research", "selector": dict(HUB_SEL), "carries": {},
        "ingress": [{"port": 8081, "from": ["pod:workbench-proxy", "pod:notebooks", "node"],
                     "why": "the proxy forwards /hub/; notebooks call the hub API; kubelet probe"}],
        "egress": [
            {"pod": "workbench-proxy", "port": 8001, "why": "the proxy's REST API (routes)"},
            {"pod": "notebooks", "port": 8888, "why": "server checks"},
            {"platform": {"app": "keycloak"}, "port": 8080,
             "why": "token and userinfo (Service keycloak in the platform namespace)"},
            {"node": True, "port": 16443,
             "why": "the Kubernetes API (KubeSpawner); Calico matches after DNAT of the kubernetes Service"},
        ]}
    pods["workbench-proxy"] = {
        "zone": "research", "selector": dict(PROXY_SEL), "carries": {},
        "ingress": [{"port": 8000, "from": ["ingress", "node"],
                     "why": "ingress-nginx for WORKBENCH_DOMAIN; kubelet probe"},
                    {"port": 8001, "from": ["pod:hub"], "why": "the hub's route updates"}],
        "egress": [{"pod": "hub", "port": 8081, "why": "/hub/"},
                   {"pod": "notebooks", "port": 8888, "why": "/user/<name>/"}]}
    pods["notebooks"] = {
        "zone": "research", "selector": dict(NOTEBOOKS_SEL), "carries": {},
        "ingress": [{"port": 8888, "from": ["pod:hub", "pod:workbench-proxy"],
                     "why": "the hub's server checks; the proxy forwards /user/<name>/"}],
        "egress": [{"pod": "hub", "port": 8081, "why": "the hub API (activity, auth)"},
                   {"pod": "lake-api", "port": 3000, "why": "the snapshot reader"},
                   {"internet": True, "ports": [443], "why": "pip, GitHub over https, the code-server download"}]}
    pods["lake-api"] = {
        "zone": "research", "selector": dict(LAKE_API_SEL), "carries": {},
        "ingress": [{"port": 3000, "from": ["pod:notebooks", "node"],
                     "why": "notebooks; kubelet probe and health rslake from the host"}],
        "egress": [{"pod": "research-postgresql", "port": 5432, "why": "rs_lake_api"}]}
    (net.get("clients") or {}).pop("notebooks", None)
    d["resource_groups"]["research_workbench"]["risk"] = RISK
    if not any(i.get("code") == "I19" for i in d["invariants"]):
        at = next((n + 1 for n, i in enumerate(d["invariants"]) if i.get("code") == "I18"), len(d["invariants"]))
        d["invariants"].insert(at, dict(I19))
    for r in ("bio_scientist", "control_scientist"):
        (d["matrix"].get("measurements") or {}).pop(r, None)
    d["matrix"]["analysis"] = {}
    return d


def with_notebooks_client(d):
    """d (a copy) with v7's network.clients.notebooks and config-api's client:notebooks
    source back when absent; unchanged (a copy) when present."""
    d = copy.deepcopy(d)
    net = d["network"]
    clients = net.setdefault("clients", {})
    if "notebooks" not in clients:
        clients["notebooks"] = copy.deepcopy(V7_NOTEBOOKS_CLIENT)
    rule = _config_api_rule(net)
    if "client:notebooks" not in rule["from"]:
        rule["from"].insert(min(V7_CONFIG_API_INDEX, len(rule["from"])), "client:notebooks")
    return d
