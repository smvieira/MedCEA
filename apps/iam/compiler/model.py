"""apps/iam/compiler/model.py — load the access policy and answer questions about it.

The policy is apps/iam/policy/defaults.yaml (schema_version 2) or, once Phase 1 has
created iam_policy, the applied version read from the database. Everything else in the
compiler (invariants, host gates, grants, routes, explain) asks this module, so there is
one reading of `implies`, composites, constraints and tool reach.
"""
import os

import yaml

DEFAULTS = os.path.join(os.path.dirname(__file__), "..", "policy", "defaults.yaml")


class Policy:
    def __init__(self, data):
        self.data = data
        self.levels = data["levels"]
        self.roles = data["roles"]
        self.groups = data["resource_groups"]
        self.types = data["resource_types"]
        self.classes = data["classes"]
        self.constraints = data["constraints"]
        self.matrix = data["matrix"]
        self.hosts = data["hosts"]
        self.waivers = data.get("waivers", [])
        self.services = data.get("service_identities", {})

    # ── levels ──────────────────────────────────────────────────────────────────
    def closure(self, levels):
        """Levels plus everything they imply."""
        out, todo = set(levels), list(levels)
        while todo:
            for j in self.levels[todo.pop()]["implies"]:
                if j not in out:
                    out.add(j)
                    todo.append(j)
        return out

    # ── cells ───────────────────────────────────────────────────────────────────
    def cell(self, group, role):
        """(levels, {level: constraint}, constrained levels) of a direct cell, or None for N.

        `constraint: X, applies_to: [...]` narrows the listed levels (default: all of them)
        with X; `constraint: {R: X, O: Y}` names one constraint per level."""
        c = self.matrix.get(group, {}).get(role)
        if c is None:
            return None
        if isinstance(c, list):
            return set(c), {}, set()
        lv = set(c["levels"])
        con = c.get("constraint")
        if isinstance(con, dict):
            cons = dict(con)
        elif con:
            cons = {l: con for l in c.get("applies_to", lv)}
        else:
            cons = {}
        return lv, cons, set(cons)

    def effective_roles(self, role):
        """The role and every role it includes (Keycloak composites), transitively."""
        out, todo = {role}, [role]
        while todo:
            for inc in self.roles[todo.pop()]["includes"]:
                if inc not in out:
                    out.add(inc)
                    todo.append(inc)
        return out

    def direct(self, group, role):
        """(held, free): levels the role holds on the group through itself and its
        composites, and the subset held without a constraint. Cells are closed under
        implies (I16), so a level a cell lists outside applies_to is held freely."""
        held, free = set(), set()
        for r in self.effective_roles(role):
            c = self.cell(group, r)
            if not c:
                continue
            lv, con, applies = c
            lv = self.closure(lv)
            held |= lv
            free |= lv - applies
        return held, free

    def reach(self, tool, role):
        """{group: levels} a role touches through a tool group's own credential.
        A mirroring tool acts with the person's own cells, so it reaches nothing new."""
        held, _ = self.direct(tool, role)
        if not held:
            return {}
        return {g: self.closure(lv) for g, lv in (self.groups[tool].get("reaches") or {}).items()}

    def effective(self, group, role):
        """Levels on a group, directly or through any tool."""
        total = set(self.direct(group, role)[0])
        for tool in self.groups:
            total |= self.reach(tool, role).get(group, set())
        return total

    def group_class(self, group):
        return self.groups[group]["class"]

    # ── widening (qa_dual_control) ──────────────────────────────────────────────────
    def holds(self, role):
        """{(group, level): 'free' | frozenset(constraints)} over effective() — composites,
        implies and tool reach expanded. Reach-only levels count as free. role None -> {}."""
        if role is None:
            return {}
        out = {}
        for g in self.groups:
            held, free = self.direct(g, role)
            for l in held:
                if l in free:
                    out[(g, l)] = "free"
                else:
                    out[(g, l)] = frozenset(self.cell(g, e)[1][l] for e in self.effective_roles(role)
                                            if self.cell(g, e) and l in self.cell(g, e)[1])
        for tool in self.groups:
            for g, lv in self.reach(tool, role).items():
                for l in lv:
                    out[(g, l)] = "free"
        return out

    def widening(self, old, new):
        """Sorted [(group, level)] new holds that old does not hold as freely: old lacks the pair,
        or new holds it free and old only constrained, or new's constraint set is not a subset of
        old's (alternative constraints OR together, so more alternatives is wider)."""
        before, after = self.holds(old), self.holds(new)
        out = []
        for pair, v in after.items():
            o = before.get(pair)
            if o is None:
                out.append(pair)
            elif o != "free" and (v == "free" or not v <= o):
                out.append(pair)
        return sorted(out)


def load(path=None):
    """Load the policy file (the defaults unless a path is given)."""
    with open(path or DEFAULTS) as f:
        return Policy(yaml.safe_load(f))
