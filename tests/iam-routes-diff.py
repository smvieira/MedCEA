#!/usr/bin/env python3
"""tests/iam-routes-diff.py — the route table matches the routes the services serve.

Compiles the route table from apps/iam/policy/defaults.yaml and compares it, per service,
with the routes read from each service's source (apps/iam/compiler/routes_diff.py): a
route served but not in the table would be refused under IAM_ENFORCE, a table route no
code serves is policy for nothing. The planned differences (planned removals, routes
and services whose code comes later) are listed, not failed. Then proves the diff
catches each kind of difference.

Run from the repository root:  python3 tests/iam-routes-diff.py [--strict]
--strict also fails while a planned removal is still served (it would be refused under
IAM_ENFORCE=true): the guide's IAM_ENFORCE enable step runs it. It reads the source on
disk, not the running pods.
Read-only; needs python3-yaml. No cluster, no lock.
"""
import copy
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from compiler import model, routes, routes_diff  # noqa: E402


def main(argv):
    strict = "--strict" in argv[1:]
    doc = routes.compile(model.load(None))
    out, failures = routes_diff.diff(doc)

    print("Route table against the services' code")
    for s, r in out.items():
        if "not_built_service" in r:
            print(f"  {s:15} not built yet (plan {r['not_built_service']})")
            continue
        planned = len(r["removed"]) + len(r["not_built"])
        print(f"  {s:15} {r['matched']:2} served routes in the table" + (f", {planned} planned" if planned else ""))
        for k, phase in r["removed"]:
            print(f"      served, removed by {phase}: {k}")
        for k, phase in r["not_built"]:
            print(f"      in the table, built in {phase}: {k}")
        if r["catch_all"]:
            print(f"      answers {', '.join(r['catch_all'])} on every path; the table decides")

    # The diff catches what it claims to: each mutation must add a failure.
    checks = []
    m = copy.deepcopy(doc)
    del m["services"]["monitor"]["routes"]["GET /api/runs"]
    checks.append(("a served route missing from the table", m, "monitor: GET /api/runs is served"))
    m = copy.deepcopy(doc)
    m["services"]["dbmgmt"]["routes"]["DELETE /objects/<id>"] = {}
    checks.append(("a table route no code serves", m, "dbmgmt: DELETE /objects/<id> is in the route table"))
    m = copy.deepcopy(doc)
    m["services"]["unknown"] = {"clients": [], "routes": {"GET /x": {}}}
    checks.append(("a service without a known source", m, "unknown: in the route table"))
    m = copy.deepcopy(doc)
    m["public"]["access-public"] = [r for r in m["public"]["access-public"] if r != "GET /register"]
    checks.append(("a public route dropped from the table", m, "access-public: GET /register is served"))
    print("\nThe diff catches")
    caught = 0
    for label, mutated, expect in checks:
        _, f = routes_diff.diff(mutated)
        ok = any(x.startswith(expect) for x in f)
        caught += ok
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    # REMOVED is empty since 2.6: prove the stale-entry rule with an injected entry.
    saved = dict(routes_diff.REMOVED)
    routes_diff.REMOVED[("scheduler", "POST /api/logs/delete")] = "2.6"
    try:
        _, f = routes_diff.diff(doc)
    finally:
        routes_diff.REMOVED.clear()
        routes_diff.REMOVED.update(saved)
    ok = any(x.startswith("scheduler: POST /api/logs/delete is listed for plan 2.6") for x in f)
    caught += ok
    print(f"  {'PASS' if ok else 'FAIL'}  a planned removal that is already done")
    for rx, want in (("/api/users/([^/]+)/(status|role)", ["/api/users/<x>/status", "/api/users/<x>/role"]),
                     ("/api/templates/([a-z-]+)(/reset)?", ["/api/templates/<x>/reset", "/api/templates/<x>"])):
        ok = routes_diff.expand(rx) == want
        caught += ok
        print(f"  {'PASS' if ok else 'FAIL'}  pattern {rx}")

    print()
    for f in failures:
        print("  FAIL ", f)
    if failures or caught != len(checks) + 3:
        print("The route table and the code differ." if failures else "The diff missed a difference it should catch.")
        return 1
    still = [f"{s}: {k}" for s, r in out.items() for k, _ in r.get("removed", [])]
    if strict and still:
        for x in still:
            print(f"  FAIL  strict: {x} is still served but not in the table (refused under IAM_ENFORCE)")
        return 1
    print("Every served route is in the table, and every table route is served, but for the planned ones.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
