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
    hop of that client (both sides agree); a `token_client` is not a host's client, and
    a client with one says `read_only` (true or false)

compile(policy, namespace, node_ips) returns a Kubernetes List of NetworkPolicies, named
iam-<pod> and labelled medcea/iam-netpol=true, so `kubectl delete netpol -l
medcea/iam-netpol=true` removes them all (the rollback of IAM plan 1.4). Ingress only:
a pod selected by one admits exactly the listed sources on the listed ports.

egress(policy, client) returns the NetworkPolicyEgressRules of one `clients` entry, for the
chart that owns those pods (the workbench's singleuser.networkPolicy.egress, IAM 3.2b).
token_clients(policy, service) returns the `token_client`s of the clients that reach the
pod carrying `service` (grants.token_clients: config-api's azp list); read_only=True only
those whose client says `read_only: true` (pre_request serves them reads only).
"""

LABEL = "medcea/iam-netpol"
KINDS = ("proxy:", "pod:", "client:")


def _sources(net):
    for name, pd in (net.get("pods") or {}).items():
        for rule in pd.get("ingress") or []:
            for src in rule.get("from") or []:
                yield name, rule, src


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
    for name, pd in pods.items():
        if not pd.get("selector"):
            errors.append(f"network: pod {name} has no selector")
        if not pd.get("ingress"):
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
        if cd.get("token_client") in host_clients:
            errors.append(f"network: client {c}: token_client {cd['token_client']} is a host's client")
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


def _peer(net, src, node_ips):
    if src.startswith("proxy:"):
        return [{"podSelector": {"matchLabels": {"app.kubernetes.io/instance": net["proxies"][src[6:]]}}}]
    if src.startswith("pod:"):
        return [{"podSelector": {"matchLabels": dict(net["pods"][src[4:]]["selector"])}}]
    if src.startswith("client:"):
        return [{"podSelector": {"matchLabels": dict(net["clients"][src[7:]]["selector"])}}]
    if src == "ingress":
        return [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": net["ingress_namespace"]}}}]
    if src == "node":
        return [{"ipBlock": {"cidr": f"{ip}/32"}} for ip in node_ips]
    raise ValueError(src)


def compile(p, namespace, node_ips):
    """The Kubernetes List of NetworkPolicies. node_ips: the node's own addresses."""
    net = p.data["network"]
    if not node_ips and any(src == "node" for _, _, src in _sources(net)):
        raise ValueError("the network section admits `node`, but no node address was given")
    items = []
    for name, pd in net["pods"].items():
        rules = []
        for rule in pd["ingress"]:
            peers = [peer for src in rule["from"] for peer in _peer(net, src, sorted(set(node_ips)))]
            rules.append({"from": peers, "ports": [{"protocol": "TCP", "port": rule["port"]}]})
        items.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"iam-{name}", "namespace": namespace, "labels": {LABEL: "true"},
                         "annotations": {"medcea/source": "apps/iam/policy/defaults.yaml network.pods." + name}},
            "spec": {"podSelector": {"matchLabels": dict(pd["selector"])}, "policyTypes": ["Ingress"],
                     "ingress": rules},
        })
    return {"apiVersion": "v1", "kind": "List", "items": items}


def egress(p, client):
    """The NetworkPolicyEgressRules of network.clients.<client>: one per hop, TCP only."""
    net = p.data.get("network") or {}
    cd = (net.get("clients") or {}).get(client)
    if cd is None:
        raise ValueError(f"no network client {client!r}; known: {', '.join(net.get('clients') or {}) or 'none'}")
    rules = []
    for hop in cd["egress"]:
        sel = net["pods"][hop["pod"]]["selector"] if "pod" in hop else hop["selector"]
        rules.append({"to": [{"podSelector": {"matchLabels": dict(sel)}}],
                      "ports": [{"protocol": "TCP", "port": hop["port"]}]})
    return rules


def token_clients(p, service, read_only=False):
    """The token_client of every network client with a hop to the pod carrying `service`;
    read_only: only the clients that say `read_only: true`."""
    net = p.data.get("network") or {}
    carriers = {name for name, pd in (net.get("pods") or {}).items() if service in (pd.get("carries") or {})}
    return sorted({cd["token_client"] for cd in (net.get("clients") or {}).values()
                   if cd.get("token_client") and any(h.get("pod") in carriers for h in cd.get("egress") or [])
                   and (cd.get("read_only") is True or not read_only)})
