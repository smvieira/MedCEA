"""apps/iam/compiler/netpol.py — one NetworkPolicy per application pod, from `network:`.

check(policy) returns the structural errors of the network section (invariants.py calls
it on every check):
  - every source is proxy:<host with a release>, pod:<pod of the section>, ingress or node
  - every proxies key is a host; every port is an integer; selectors are not empty
  - a route-table service is carried by at most one pod, on one port
  - every host reaches each service it serves that a pod carries, on that service's port:
    from its proxy, or through one pod its proxy reaches (config proxy → config-ui →
    config-api); an `unproxied` host as its given source (the edge wizard: node)
  - every proxy but `no_shared_upstreams` reaches each shared upstream (/_account/)
  - a host serving a carried service is in `proxies` or `unproxied`
  - every `clients` entry has a selector and egress hops; a `pod:` hop names a pod of the
    section that admits client:<name> on that port; a pod admitting client:<name> is a
    hop of that client (both sides agree); a client with a `token_client` says
    `read_only` (true or false); a `token_client` is not a host's client, with one
    exception (IAM 4.1): a client may name a host's client when it declares a non-empty
    `only_rpc` list of function names, says `read_only: false`, and no host with that
    client serves config-api (pre_request then lets those tokens call only
    POST /rpc/<name>); `only_rpc` without a `token_client`, or with `read_only: true`,
    is an error

compile(policy, namespace, node_ips) returns a Kubernetes List of NetworkPolicies, named
iam-<pod> and labelled medcea/iam-netpol=true, so `kubectl delete netpol -l
medcea/iam-netpol=true` removes them all (the rollback of IAM plan 1.4). Ingress only:
a pod selected by one admits exactly the listed sources on the listed ports.

egress(policy, client) returns the NetworkPolicyEgressRules of one `clients` entry, for the
chart that owns those pods (the workbench's singleuser.networkPolicy.egress, IAM 3.2b).
token_clients(policy, service) returns the `token_client`s of the clients that reach the
pod carrying `service` (grants.token_clients: config-api's azp list); read_only=True only
those whose client says `read_only: true` (pre_request serves them reads only).
only_rpc(policy, service) returns {token_client: sorted function names} of the clients with
`only_rpc` that reach the pod carrying `service` (pre_request's only_rpc block, IAM 4.1).

Zones (research sandbox Phase 2a). `network.zones` maps a zone name (only `research`, ZONES)
to its settings ({} so far). A pod or client may say `zone: <name>`; without it, it is in
the platform zone, the namespace `compile` is given. Each zone has a namespace of its own
(RESEARCH_NAMESPACE), which denies all ingress and egress by default. Shape:

    network:
      zones: {research: {}}
      pods:
        research-postgresql:
          zone: research
          selector: {app.kubernetes.io/instance: research-postgresql, app.kubernetes.io/name: postgresql}
          ingress:
            - {port: 5432, from: ["client:research-export", "client:backup", node]}
          egress:                       # zone pods only, optional: the hops this pod opens
            - {pod: <a pod of any zone>, port: N}
      clients:
        research-export: {selector: {app: research-export}, egress: [{pod: research-postgresql, port: 5432}]}

Hop forms (research sandbox Phase 2b). A zone pod's `egress` item is exactly one of
(each may carry `why`, prose):

    {pod: P, port: N}                 a pod of the section (any zone) that admits pod:<it>
    {platform: {label: value}, port: N}
                                      pods of the platform namespace that are no network pod
                                      (Keycloak): namespaceSelector + podSelector, AND
    {node: true, port: N}             the node's addresses as /32 ipBlocks (the Kubernetes API:
                                      Calico matches after DNAT of the kubernetes Service)
    {internet: true, ports: [N, ..]}  0.0.0.0/0 except network.zones.<zone>.internet_except
                                      (the private ranges, in YAML order), on those TCP ports

`network.zones.<zone>.internet_except` is a non-empty list of IPv4 networks (strict). A
platform hop may not select a network pod (that pod admits only sources of its own zone).
A zone without a new-form hop compiles byte for byte as before.

A `pod:`/`client:` source in another zone than the pod it reaches resolves to ONE peer
carrying both a namespaceSelector (kubernetes.io/metadata.name = that zone's namespace) and
the podSelector, so both must match (AND); a `proxy:` source is a platform pod. A platform
pod admits only platform sources (its compile knows no zone namespace). A zone pod's egress
hop names a pod that admits `pod:<it>` on that port, and a zone pod admitted elsewhere as
`pod:<x>` must have that hop (its egress is denied otherwise).

compile(policy, namespace, node_ips) compiles the platform zone only: today's output byte for
byte while no pod carries a zone. compile_zone(policy, zone, namespace, platform_namespace,
node_ips) returns the zone's List, labelled medcea/<prefix>-netpol=true (research: rs):
<prefix>-default-deny (every pod, Ingress and Egress, nothing allowed), <prefix>-dns (every
pod may reach kube-system's k8s-app=kube-dns on UDP and TCP 53; Calico matches egress after
DNAT, so the pods, not the ClusterIP) and <prefix>-<pod> per zone pod (Ingress from its
sources, Egress to its hops in list order; the `egress` key only when it has hops, since the API server
drops an empty list). An empty List while the policy has no such zone.
"""

import ipaddress
import re

LABEL = "medcea/iam-netpol"
_RPC = re.compile(r"^[a-z_][a-z0-9_]*$")
KINDS = ("proxy:", "pod:", "client:")
# zone → (name prefix, label key). A zone name not listed here is an error.
ZONES = {"research": ("rs", "medcea/rs-netpol"),
         # research Phase 4a (design rs4 R2): the agent machinery, in a namespace the notebook
         # hub cannot create pods in, and the key and trace holder beside it
         "research-agents": ("ra", "medcea/ra-netpol"),
         "research-gw": ("gw", "medcea/gw-netpol")}
# A research-gw pod (the session key, the trace writer) admits only these zones' pods (R2),
# and the node (kubelet probes); never the research zone, the platform, a proxy or ingress.
GW_ADMITS = ("research-agents", "research-gw")
SOURCE = "apps/iam/policy/defaults.yaml"
DNS_NAMESPACE = "kube-system"
DNS_SELECTOR = {"k8s-app": "kube-dns"}


def _sources(net):
    for name, pd in (net.get("pods") or {}).items():
        for rule in pd.get("ingress") or []:
            for src in rule.get("from") or []:
                yield name, rule, src


def zones(data):
    """The zone names of a policy (a model.Policy or its data dict), in file order."""
    data = getattr(data, "data", data) or {}
    z = (data.get("network") or {}).get("zones")
    return list(z) if isinstance(z, dict) else []


def has_zone(data, zone):
    return zone in zones(data)


# A zone pod's egress hop is exactly one of these forms (research sandbox Phase 2b), each
# with its own keys besides an optional `why` (prose). `port` on an internet hop is let
# through here so that its own check can say what is wrong with it.
HOP_FORMS = {
    "pod": {"pod", "port", "why"},
    "platform": {"platform", "port", "why"},
    "node": {"node", "port", "why"},
    "internet": {"internet", "ports", "port", "why"},
}


def _hop_form(hop):
    """The form of a zone pod's hop (pod, platform, node or internet), None when the hop is
    not a mapping, names none or several of them, or carries a key its form does not take."""
    if not isinstance(hop, dict):
        return None
    forms = [f for f in HOP_FORMS if f in hop]
    if len(forms) != 1 or set(hop) - HOP_FORMS[forms[0]]:
        return None
    return forms[0]


def _ports_ok(ports):
    return (isinstance(ports, list) and bool(ports)
            and all(isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 65535 for x in ports))


def _internet_except(zd):
    """The zone's internet_except list when it is a non-empty list of strict IPv4 networks,
    else None (absent or malformed: an internet hop then has nothing safe to compile to)."""
    if not isinstance(zd, dict):
        return None
    ex = zd.get("internet_except")
    if not isinstance(ex, list) or not ex:
        return None
    for x in ex:
        if not isinstance(x, str):
            return None
        try:
            ipaddress.IPv4Network(x, strict=True)
        except ValueError:
            return None
    return list(ex)


# What an internet hop must never reach, whatever else internet_except lists (review of research
# Phase 2b commit A, 19 Nov 2026): the private ranges (the cluster's pod and service networks
# are in 10/8 on MicroK8s, the LAN in 192.168/16), shared CGNAT space (Tailscale's 100.64/10)
# and link-local (cloud metadata). A list that misses one is refused, not just reviewed.
INTERNET_EXCEPT_REQUIRED = ("10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")


def _except_missing(ex):
    nets = [ipaddress.IPv4Network(x) for x in ex]
    return [r for r in INTERNET_EXCEPT_REQUIRED
            if not any(ipaddress.IPv4Network(r).subnet_of(n) for n in nets)]


def _port_ok(p):
    return isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535


def _zone_of(net, src):
    """The zone of a source (None: the platform zone; a proxy, ingress or node is platform)."""
    if src.startswith("pod:"):
        return ((net.get("pods") or {}).get(src[4:]) or {}).get("zone")
    if src.startswith("client:"):
        return ((net.get("clients") or {}).get(src[7:]) or {}).get("zone")
    return None


def _zone_check(net, errors):
    zs = net.get("zones")
    if zs is not None and not isinstance(zs, dict):
        errors.append("network: zones must map a zone name to its settings")
        zs = {}
    zs = zs or {}
    for z, zd in zs.items():
        if z not in ZONES:
            errors.append(f"network: unknown zone {z!r} (known: {', '.join(ZONES)})")
        if zd is not None and not isinstance(zd, dict):
            errors.append(f"network: zone {z}: settings must be a mapping")
        elif isinstance(zd, dict) and "internet_except" in zd and _internet_except(zd) is None:
            errors.append(f"network: zone {z}: internet_except must be a non-empty list of IPv4 networks")
        elif isinstance(zd, dict) and "internet_except" in zd and _except_missing(zd["internet_except"]):
            errors.append(f"network: zone {z}: internet_except must cover {', '.join(INTERNET_EXCEPT_REQUIRED)} "
                          f"(the cluster's and the LAN's private ranges, CGNAT and link-local); missing: "
                          f"{', '.join(_except_missing(zd['internet_except']))}")
    pods = net.get("pods") or {}
    clients = net.get("clients") or {}
    for kind, entries in (("pod", pods), ("client", clients)):
        for name, d in entries.items():
            if "zone" in d and (not isinstance(d["zone"], str) or d["zone"] not in zs):
                errors.append(f"network: {kind} {name}: zone {d['zone']!r} is not in network.zones")
    for name, rule, src in _sources(net):
        if pods[name].get("zone") == "research-gw" and src != "node" and _zone_of(net, src) not in GW_ADMITS:
            errors.append(f"network: pod {name} port {rule.get('port')}: source {src} is not a pod of "
                          f"{' or '.join(GW_ADMITS)}; a research-gw pod admits only those (and the node)")
    for name, rule, src in _sources(net):
        if pods[name].get("zone") is None and _zone_of(net, src) is not None:
            errors.append(f"network: pod {name} port {rule.get('port')}: source {src} is in zone "
                          f"{_zone_of(net, src)}; a platform pod admits only platform sources")
    for name, pd in pods.items():
        hops = pd.get("egress")
        if hops is None:
            continue
        if pd.get("zone") is None:
            errors.append(f"network: pod {name}: egress hops are compiled only for a zone pod")
            continue
        if not isinstance(hops, list):
            errors.append(f"network: pod {name}: egress must be a list of hops")
            continue
        for hop in hops:
            form = _hop_form(hop)
            if form is None:
                errors.append(f"network: pod {name}: a zone pod's hop is {{pod, port}}, {{platform, port}}, "
                              f"{{node: true, port}} or {{internet: true, ports}}")
                continue
            if form == "internet":
                if hop["internet"] is not True or "port" in hop or not _ports_ok(hop.get("ports")):
                    errors.append(f"network: pod {name}: an internet hop is {{internet: true, ports: [..]}} "
                                  f"(TCP ports, no port key)")
                if _internet_except(zs.get(pd["zone"])) is None:
                    errors.append(f"network: pod {name}: an internet hop needs network.zones.{pd['zone']}"
                                  f".internet_except (the private ranges it must not reach)")
                continue
            if not _port_ok(hop.get("port")):
                errors.append(f"network: pod {name}: hop port {hop.get('port')!r} is not an integer from 1 to 65535")
            if form == "platform":
                sel = hop["platform"]
                if not isinstance(sel, dict) or not sel or not all(
                        isinstance(k, str) and isinstance(v, str) for k, v in sel.items()):
                    errors.append(f"network: pod {name}: a platform hop names a non-empty selector")
                    continue
                for other, od in pods.items():
                    if isinstance(od, dict) and od.get("selector") == sel:
                        errors.append(f"network: pod {name}: platform hop {sel} selects network pod {other}; "
                                      f"a network pod admits only sources of its own zone, so name it with a "
                                      f"zone pod or not at all")
                continue
            if form == "node":
                if hop["node"] is not True:
                    errors.append(f"network: pod {name}: a node hop is {{node: true, port}}")
                continue
            if hop["pod"] not in pods:
                errors.append(f"network: pod {name}: hop to unknown pod {hop['pod']}")
            elif not any(f"pod:{name}" in (r.get("from") or []) and r.get("port") == hop.get("port")
                         for r in pods[hop["pod"]].get("ingress") or []):
                errors.append(f"network: pod {name} reaches pod {hop['pod']} port {hop.get('port')}, "
                              f"which does not admit pod:{name}")
    for name, rule, src in _sources(net):
        if not src.startswith("pod:") or src[4:] not in pods:
            continue
        other = pods[src[4:]]
        if other.get("zone") is None:
            continue
        if not any(isinstance(h, dict) and h.get("pod") == name and h.get("port") == rule.get("port")
                   for h in other.get("egress") or []):
            errors.append(f"network: pod {name} port {rule.get('port')} admits {src}, a zone pod "
                          f"with no egress hop there (its egress is denied by default)")


def check(p):
    errors = []
    net = p.data.get("network")
    if not net:
        return errors
    proxies = net.get("proxies") or {}
    pods = net.get("pods") or {}
    for h in proxies:
        if h not in p.hosts:
            errors.append(f"network: proxy for unknown host {h}")
    _zone_check(net, errors)
    for name, pd in pods.items():
        if not pd.get("selector"):
            errors.append(f"network: pod {name} has no selector")
        if not pd.get("ingress") and not (pd.get("zone") and pd.get("egress")):
            # a zone pod that only sends (the agent Jobs, rs4 R2) may admit nothing
            errors.append(f"network: pod {name} admits nothing (no ingress rules)")
        for rule in pd.get("ingress") or []:
            if not isinstance(rule.get("port"), int):
                errors.append(f"network: pod {name}: port {rule.get('port')!r} is not an integer")
            if not rule.get("from"):
                errors.append(f"network: pod {name} port {rule.get('port')}: no sources")
    for name, rule, src in _sources(net):
        if src in ("node", "ingress"):
            continue
        if src.startswith("proxy:") and src[6:] in proxies:
            continue
        if src.startswith("pod:") and src[4:] in pods:
            continue
        if src.startswith("client:") and src[7:] in (net.get("clients") or {}):
            continue
        errors.append(f"network: pod {name} port {rule.get('port')}: unknown source {src!r}")

    carrier = {}  # service -> (pod, port)
    for name, pd in pods.items():
        carries = pd.get("carries") or {}
        if not isinstance(carries, dict):
            errors.append(f"network: pod {name}: carries must map service to port")
            continue
        for svc, port in carries.items():
            if svc in carrier:
                errors.append(f"network: service {svc} carried by both {carrier[svc][0]} and {name}")
            if not any(r.get("port") == port for r in pd.get("ingress") or []):
                errors.append(f"network: pod {name} carries {svc} on port {port}, which no rule opens")
            carrier[svc] = (name, port)

    def admits(pod, src, port=None):
        return any(src in (r.get("from") or []) and (port is None or r.get("port") == port)
                   for r in pods[pod].get("ingress") or [])

    unproxied = net.get("unproxied") or {}
    for h in list(unproxied) + list(net.get("no_shared_upstreams") or []):
        if h not in p.hosts:
            errors.append(f"network: unknown host {h}")
    for h, hd in p.hosts.items():
        if h in proxies:
            me = f"proxy:{h}"
        elif h in unproxied:
            me = unproxied[h]
        else:
            if any(svc in carrier for svc in hd["serves"]):
                errors.append(f"network: {h} serves {', '.join(s for s in hd['serves'] if s in carrier)} "
                              f"but is in neither network.proxies nor network.unproxied")
            continue
        for svc in hd["serves"]:
            if svc not in carrier:
                continue  # not an application pod of this section (portal, node-red, …)
            pod, port = carrier[svc]
            if admits(pod, me, port):
                continue
            if me.startswith("proxy:") and any(admits(front, me) and admits(pod, f"pod:{front}", port) for front in pods):
                continue
            errors.append(f"network: {h} serves {svc}, but pod {pod} port {port} admits neither {me} nor a pod {me} reaches")
    host_clients = {hd["client"] for hd in p.hosts.values()}
    for c, cd in (net.get("clients") or {}).items():
        if not cd.get("selector"):
            errors.append(f"network: client {c} has no selector")
        if not cd.get("egress"):
            errors.append(f"network: client {c} opens nothing (no egress hops)")
        orpc = cd.get("only_rpc")
        if orpc is not None:
            if not cd.get("token_client"):
                errors.append(f"network: client {c}: only_rpc needs a token_client")
            if not isinstance(orpc, list) or not orpc or not all(isinstance(n, str) and _RPC.match(n) for n in orpc):
                errors.append(f"network: client {c}: only_rpc must be a non-empty list of function names")
            if cd.get("read_only") is True:
                errors.append(f"network: client {c}: only_rpc with read_only: true (an RPC is a POST)")
        if cd.get("token_client") in host_clients:
            serving = sorted(h for h, hd in p.hosts.items()
                             if hd["client"] == cd["token_client"] and "config-api" in hd["serves"])
            if not orpc or not isinstance(orpc, list) or cd.get("read_only") is not False:
                errors.append(f"network: client {c}: token_client {cd['token_client']} is a host's client "
                              f"(allowed only with a non-empty only_rpc and read_only: false)")
            if serving:
                errors.append(f"network: client {c}: token_client {cd['token_client']} is the client of "
                              f"{', '.join(serving)}, which serves config-api (only_rpc would cut its own use)")
        if cd.get("token_client") and not isinstance(cd.get("read_only"), bool):
            errors.append(f"network: client {c}: a token_client needs read_only: true or false")
        hops = set()
        for hop in cd.get("egress") or []:
            if not isinstance(hop.get("port"), int):
                errors.append(f"network: client {c}: port {hop.get('port')!r} is not an integer")
            if ("pod" in hop) == ("selector" in hop):
                errors.append(f"network: client {c}: a hop names either pod or selector")
            elif "pod" in hop:
                if hop["pod"] not in pods:
                    errors.append(f"network: client {c}: unknown pod {hop['pod']}")
                elif not admits(hop["pod"], f"client:{c}", hop.get("port")):
                    errors.append(f"network: client {c} reaches pod {hop['pod']} port {hop.get('port')}, "
                                  f"which does not admit client:{c}")
                hops.add((hop["pod"], hop.get("port")))
        for name, rule, src in _sources(net):
            if src == f"client:{c}" and (name, rule.get("port")) not in hops:
                errors.append(f"network: pod {name} port {rule.get('port')} admits client:{c}, "
                              f"which has no egress hop there")
    skip = set(net.get("no_shared_upstreams") or [])
    for u in p.data.get("shared_upstreams", []):
        if u["service"] not in carrier:
            continue
        pod, port = carrier[u["service"]]
        for h in proxies:
            if h not in skip and not admits(pod, f"proxy:{h}", port):
                errors.append(f"network: proxy:{h} cannot reach shared upstream {u['service']} ({pod} port {port})")
    return errors


def _ns_selector(ns):
    return {"matchLabels": {"kubernetes.io/metadata.name": ns}}


def _in(peer, src_zone, here, namespaces):
    """peer (a podSelector element) as seen from a pod of zone `here`: unchanged within the
    zone, else one element with the source zone's namespaceSelector too (AND)."""
    if src_zone == here:
        return peer
    if namespaces is None or not namespaces.get(src_zone):
        raise ValueError(f"a peer in zone {src_zone or 'platform'} needs that zone's namespace")
    return {"namespaceSelector": _ns_selector(namespaces[src_zone]), **peer}


def _peer(net, src, node_ips, here=None, namespaces=None):
    if src.startswith("proxy:"):
        return [_in({"podSelector": {"matchLabels": {"app.kubernetes.io/instance": net["proxies"][src[6:]]}}},
                    None, here, namespaces)]
    if src.startswith("pod:"):
        pd = net["pods"][src[4:]]
        return [_in({"podSelector": {"matchLabels": dict(pd["selector"])}}, pd.get("zone"), here, namespaces)]
    if src.startswith("client:"):
        cd = net["clients"][src[7:]]
        return [_in({"podSelector": {"matchLabels": dict(cd["selector"])}}, cd.get("zone"), here, namespaces)]
    if src == "ingress":
        return [{"namespaceSelector": _ns_selector(net["ingress_namespace"])}]
    if src == "node":
        return [{"ipBlock": {"cidr": f"{ip}/32"}} for ip in node_ips]
    raise ValueError(src)


def _ingress_rules(net, pd, node_ips, here=None, namespaces=None):
    rules = []
    for rule in pd.get("ingress") or []:
        peers = [peer for src in rule["from"] for peer in _peer(net, src, sorted(set(node_ips)), here, namespaces)]
        rules.append({"from": peers, "ports": [{"protocol": "TCP", "port": rule["port"]}]})
    return rules


def _needs_node(net, zone):
    """True when a pod of `zone` admits `node` or (a zone pod) has a {node: true} hop."""
    if any(src == "node" for name, _, src in _sources(net) if net["pods"][name].get("zone") == zone):
        return True
    return any(isinstance(h, dict) and h.get("node") is True
               for pd in (net.get("pods") or {}).values() if zone is not None and pd.get("zone") == zone
               for h in pd.get("egress") or [])


def compile(p, namespace, node_ips):
    """The Kubernetes List of the platform zone's NetworkPolicies (pods without a zone).
    node_ips: the node's own addresses."""
    net = p.data["network"]
    if not node_ips and _needs_node(net, None):
        raise ValueError("the network section admits `node`, but no node address was given")
    items = []
    for name, pd in net["pods"].items():
        if pd.get("zone") is not None:
            continue
        items.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"iam-{name}", "namespace": namespace, "labels": {LABEL: "true"},
                         "annotations": {"medcea/source": f"{SOURCE} network.pods." + name}},
            "spec": {"podSelector": {"matchLabels": dict(pd["selector"])}, "policyTypes": ["Ingress"],
                     "ingress": _ingress_rules(net, pd, node_ips)},
        })
    return {"apiVersion": "v1", "kind": "List", "items": items}


def zone_label(zone):
    """The label key of a zone's NetworkPolicies (medcea/rs-netpol for research)."""
    if zone not in ZONES:
        raise ValueError(f"unknown zone {zone!r}; known: {', '.join(ZONES)}")
    return ZONES[zone][1]


def compile_zone(p, zone, namespace, platform_namespace, node_ips, zone_namespaces=None):
    """The Kubernetes List of zone `zone`'s NetworkPolicies in `namespace`: the default deny,
    the DNS allow and one per zone pod; empty while the policy has no such zone.
    zone_namespaces: {other zone: its namespace}, needed only for a peer or hop in another
    zone (research Phase 4a); without it such a peer raises."""
    label = zone_label(zone)
    prefix = ZONES[zone][0]
    if not has_zone(p, zone):
        return {"apiVersion": "v1", "kind": "List", "items": []}
    if not namespace or not platform_namespace:
        raise ValueError("a zone's NetworkPolicies need its namespace and the platform namespace")
    net = p.data["network"]
    if not node_ips and _needs_node(net, zone):
        raise ValueError(f"zone {zone} admits `node`, but no node address was given")
    # another zone's namespace comes from zone_namespaces; a peer in a zone not given raises
    namespaces = {**(zone_namespaces or {}), None: platform_namespace, zone: namespace}

    def item(name, src, spec):
        return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": f"{prefix}-{name}", "namespace": namespace, "labels": {label: "true"},
                             "annotations": {"medcea/source": f"{SOURCE} {src}"}},
                "spec": spec}
    items = [
        item("default-deny", f"network.zones.{zone}", {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}),
        item("dns", f"network.zones.{zone}", {
            "podSelector": {}, "policyTypes": ["Egress"],
            "egress": [{"to": [{"namespaceSelector": _ns_selector(DNS_NAMESPACE),
                                "podSelector": {"matchLabels": dict(DNS_SELECTOR)}}],
                        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}]}),
    ]
    for name, pd in net["pods"].items():
        if pd.get("zone") != zone:
            continue
        spec = {"podSelector": {"matchLabels": dict(pd["selector"])}, "policyTypes": ["Ingress", "Egress"],
                "ingress": _ingress_rules(net, pd, node_ips, zone, namespaces)}
        hops = [_zone_hop(net, h, zone, namespaces, node_ips) for h in pd.get("egress") or []]
        if hops:
            spec["egress"] = hops
        items.append(item(name, f"network.pods.{name}", spec))
    return {"apiVersion": "v1", "kind": "List", "items": items}


def _zone_hop(net, h, zone, namespaces, node_ips):
    """One NetworkPolicyEgressRule of a zone pod's hop (HOP_FORMS), TCP only."""
    if "platform" in h:
        to = [{"namespaceSelector": _ns_selector(namespaces[None]),
               "podSelector": {"matchLabels": dict(h["platform"])}}]
    elif "node" in h:
        to = [{"ipBlock": {"cidr": f"{ip}/32"}} for ip in sorted(set(node_ips))]
    elif "internet" in h:
        ex = _internet_except((net.get("zones") or {}).get(zone))
        if ex is None:
            raise ValueError(f"zone {zone}: an internet hop needs network.zones.{zone}.internet_except")
        return {"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ex}}],
                "ports": [{"protocol": "TCP", "port": x} for x in h["ports"]]}
    else:
        pd = net["pods"][h["pod"]]
        to = [_in({"podSelector": {"matchLabels": dict(pd["selector"])}}, pd.get("zone"), zone, namespaces)]
    return {"to": to, "ports": [{"protocol": "TCP", "port": h["port"]}]}


def egress(p, client, namespaces=None):
    """The NetworkPolicyEgressRules of network.clients.<client>: one per hop, TCP only. A hop
    to a pod of another zone than the client's carries that zone's namespaceSelector (AND),
    so it needs namespaces = {zone or None: namespace}."""
    net = p.data.get("network") or {}
    cd = (net.get("clients") or {}).get(client)
    if cd is None:
        raise ValueError(f"no network client {client!r}; known: {', '.join(net.get('clients') or {}) or 'none'}")
    rules = []
    for hop in cd["egress"]:
        if "pod" in hop:
            pd = net["pods"][hop["pod"]]
            peer = _in({"podSelector": {"matchLabels": dict(pd["selector"])}}, pd.get("zone"), cd.get("zone"),
                       namespaces)
        else:
            peer = {"podSelector": {"matchLabels": dict(hop["selector"])}}
        rules.append({"to": [peer], "ports": [{"protocol": "TCP", "port": hop["port"]}]})
    return rules


def egress_zones(p, client):
    """The zones (None: the platform zone) that network.clients.<client>'s egress needs a
    namespace for: its own and every hop pod's, when a hop crosses zones; [] otherwise (a
    client whose hops all stay in its zone compiles without namespaces, as before Phase 2a)."""
    net = p.data.get("network") or {}
    cd = (net.get("clients") or {}).get(client)
    if cd is None:
        raise ValueError(f"no network client {client!r}; known: {', '.join(net.get('clients') or {}) or 'none'}")
    here = cd.get("zone")
    there = {net["pods"][h["pod"]].get("zone") for h in cd.get("egress") or [] if "pod" in h}
    if not there - {here}:
        return []
    return sorted(there | {here}, key=lambda z: (z is not None, z or ""))


def token_clients(p, service, read_only=False):
    """The token_client of every network client with a hop to the pod carrying `service`;
    read_only: only the clients that say `read_only: true`."""
    net = p.data.get("network") or {}
    carriers = {name for name, pd in (net.get("pods") or {}).items() if service in (pd.get("carries") or {})}
    return sorted({cd["token_client"] for cd in (net.get("clients") or {}).values()
                   if cd.get("token_client") and any(h.get("pod") in carriers for h in cd.get("egress") or [])
                   and (cd.get("read_only") is True or not read_only)})


def only_rpc(p, service):
    """{token_client: sorted function names} of the clients declaring `only_rpc` that have a
    hop to the pod carrying `service` (pre_request: those tokens may only POST /rpc/<name>)."""
    net = p.data.get("network") or {}
    carriers = {name for name, pd in (net.get("pods") or {}).items() if service in (pd.get("carries") or {})}
    out = {}
    for cd in (net.get("clients") or {}).values():
        if cd.get("token_client") and isinstance(cd.get("only_rpc"), list) and cd["only_rpc"] \
           and any(h.get("pod") in carriers for h in cd.get("egress") or []):
            out.setdefault(cd["token_client"], set()).update(cd["only_rpc"])
    return {k: sorted(v) for k, v in sorted(out.items())}
