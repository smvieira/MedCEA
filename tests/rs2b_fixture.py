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
  v7_policy(data=None)         the inverse of b_policy: version 7's policy (commit A's factory
                               file, ad420b0) rebuilt from the factory file (or `data`) byte
                               for byte, prose and key order included. Commit A's tests that
                               read "the factory file as version 7" go through it since
                               commit B changed the factory file.
  with_v7_cells(d)             d with v7's cells B's factory matrix lacks: measurements R for
                               bio_scientist and control_scientist and the six analysis cells
                               (Superset's builders and viewers); identity on v7's defaults.
                               Tests of Superset's mapping go through it, since the factory
                               file admits nobody to Superset since commit B (owner O12).

Every builder returns a new dict (deep copies; put_v7_cells works in place); none reads or
writes anything but the factory file. Since commit B the factory file is commit B's itself:
b_policy() is then commit B's policy (prose aside) and v7_policy() version 7's.
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
# v7's cells commit B's factory matrix (= the change version's) drops (owner decisions O12, 19 Nov 2026)
V7_MEASUREMENTS = {"bio_scientist": ["R"], "control_scientist": ["R"]}
V7_ANALYSIS = {"production_manager": ["R"], "qc": ["R"], "qp": ["R"], "engineer": ["R", "C", "U"],
               "bio_scientist": ["R", "C", "U"], "control_scientist": ["R", "C", "U"]}   # "client:notebooks" sat third in config-api's port-3000 sources

I19 = {"code": "I19", "kind": "matrix",
       "rule": "On a group with zone research, admin holds nothing, except K on research_workbench.",
       "rationale": "Separation of duties (SoD-3): administering the AI workbench is not doing research in it.",
       "cites": "MedCEA concept, research/production separation; PIC/S PI 041-1 §9.3"}

RISK = ("Notebooks run code. They run in the research zone (research sandbox Phase 2b) and read "
        "person-free snapshots through lake-api, which asks for no identity; they reach only the hub, "
        "lake-api and the internet on TCP 443, never a private address, and nothing of the platform "
        "namespace. No pod holds a platform database password or a stored token. The hub cannot read "
        "Secrets, and the zone's namespace enforces Pod Security baseline. What a notebook reads can "
        "still leave through its internet access or git (outputs are stripped on commit; code and text "
        "cells are not checked). A hub administrator can stop another person's server or remove their "
        "hub user, never open the server or start one of its own, and removing a hub user keeps the "
        "person's home volume.\n")   # commit B's text, byte for byte (a folded scalar ends in a newline)


V9_LAKE_WHY = "notebooks; kubelet probe and health rslake from the host"
V9_PG_WHY = ("the nightly exporter (rs_export_writer), the nightly backup (rs_backup, pg_read_all_data), the "
             "snapshot reader (rs_lake_api, research sandbox Phase 2b), kubelet probes and the host's psql "
             "(reserve.sh runs inside the pod)")
RS4_PODS = ("research-orchestrator", "research-session", "mcp-sim", "mcp-lake", "agent",
           "model-gateway", "research-llm")   # the last two: Phase 4b's commit B
RS4_SERVICES = ("research-orchestrator", "research-orchestrator-sim", "research-session-agent",
                "research-session-server", "mcp-sim", "mcp-lake", "model-gateway")


def v9_policy(data=None):
    """Version 9's policy (Phase 2b's factory file, before research Phase 4a's commit B) from
    the factory file or a copy of `data`: every 4a-B change undone, in version 9's order and words."""
    d = copy.deepcopy(data) if data is not None else copy.deepcopy(model.load_defaults().data)
    net = d["network"]
    for z in ("research-agents", "research-gw"):
        net["zones"].pop(z, None)
    for pod in RS4_PODS:
        net["pods"].pop(pod, None)
    nb = net["pods"]["notebooks"]
    nb["egress"] = [h for h in nb["egress"] if h.get("pod") != "research-orchestrator"]
    lake = net["pods"]["lake-api"]["ingress"][0]
    if "pod:mcp-lake" in lake["from"]:
        lake["from"] = ["pod:notebooks", "node"]
        lake["why"] = V9_LAKE_WHY
    pg = net["pods"]["research-postgresql"]["ingress"][0]
    if "pod:research-session" in pg["from"]:
        pg["from"].remove("pod:research-session")
        pg["why"] = V9_PG_WHY
    d["public_routes"] = [r for r in d["public_routes"] if r.get("service") not in RS4_SERVICES]
    d["resource_groups"].pop("research_campaigns", None)
    d["matrix"].pop("research_campaigns", None)
    return d


def _factory():
    return v9_policy()


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


def put_v7_cells(d):
    """In place: v7's measurements R for the two scientists and the analysis cells, where
    absent. Returns d."""
    m = d["matrix"]
    meas = m.get("measurements") or {}
    for r, lv in V7_MEASUREMENTS.items():
        meas.setdefault(r, list(lv))
    m["measurements"] = meas
    if not m.get("analysis"):
        m["analysis"] = copy.deepcopy(V7_ANALYSIS)
    return d


def with_v7_cells(d):
    """d (a copy) with v7's cells that commit B's factory matrix lacks; unchanged (a copy)
    on v7's defaults."""
    return put_v7_cells(copy.deepcopy(d))


# version 7's texts commit B rewrote (residue and prose), word for word
V7_RISK = ("Notebooks run code. Their pods are isolated by the chart's NetworkPolicy (no egress to private "
           "addresses) except for two hops compiled from network.clients.notebooks: Keycloak, for a device-code "
           "sign-in on the public client workbench-notebook, and config-api (PostgREST), which a notebook calls "
           "with that person's own token, so the database applies the person's rr_ role and row security, nothing "
           "more; both open only while IAM_POSTGREST_JWT and IAM_DB_ROLES are true. No pod holds a database "
           "password or a stored token. What a person reads into a notebook can still leave through the "
           "notebook's own internet access or git (outputs are stripped on commit; code and text cells are not "
           "checked). A hub administrator can stop another person's server or remove their hub user, never open "
           "the server, and removing a hub user keeps the person's home volume.\n")
V7_CONFIG_API_WHY = ("PostgREST behind the Config UI's /api/; the edge wizard and platform_db.py on the host; kubelet "
                     "probe; workbench notebooks with the person's own token (IAM 3.2b); iam-api forwarding a qa "
                     "person's own token for the four policy approval calls (IAM 4.4; nothing calls before)")
V7_PG_WHY = ("the nightly exporter (rs_export_writer), the nightly backup (rs_backup, pg_read_all_data), kubelet "
             "probes and the host's psql (reserve.sh runs inside the pod)")
B_PODS = ("hub", "workbench-proxy", "notebooks", "lake-api")


def v7_policy(data=None):
    """Version 7's policy from the factory file (or a copy of `data`): every commit B change
    undone, in version 7's key order and words. Identity (a copy) on version 7's file."""
    d = copy.deepcopy(data) if data is not None else _factory()
    net = d["network"]
    research = (net.get("zones") or {}).get("research")
    if isinstance(research, dict):
        research.pop("internet_except", None)
    for pod in B_PODS:
        net["pods"].pop(pod, None)
    pg = net["pods"]["research-postgresql"]["ingress"][0]
    if "pod:lake-api" in pg["from"]:
        pg["from"].remove("pod:lake-api")
        pg["why"] = V7_PG_WHY
    rule = _config_api_rule(net)
    if "client:notebooks" not in rule["from"]:
        rule["why"] = V7_CONFIG_API_WHY
    clients = net.get("clients") or {}
    if "notebooks" not in clients:
        net["clients"] = dict([("notebooks", copy.deepcopy(V7_NOTEBOOKS_CLIENT))] + list(clients.items()))
    d = with_notebooks_client(d)   # config-api's source, in place of version 7
    d["resource_groups"]["research_workbench"]["risk"] = V7_RISK
    d["invariants"] = [i for i in d["invariants"] if i.get("code") != "I19"]
    m = d["matrix"]
    meas = m.get("measurements") or {}
    if any(r not in meas for r in V7_MEASUREMENTS):
        order = list(meas)
        at = order.index("auditor") if "auditor" in order else len(order)
        rebuilt = [(r, meas[r]) for r in order[:at]] + [(r, list(lv)) for r, lv in V7_MEASUREMENTS.items()
                                                        if r not in meas] + [(r, meas[r]) for r in order[at:]]
        m["measurements"] = dict(rebuilt)
    if not m.get("analysis"):
        m["analysis"] = copy.deepcopy(V7_ANALYSIS)
    return d
