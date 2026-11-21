"""apps/research-agents/mcp_lake.py (research Phase 4a, stage 5): mcp-lake, fixed parameterised lake
queries through research/calib/lake.py LakeClient (design 4.5, R30). No credential reaches lake-api
(O2); no raw measurement page reaches the model: `summary` returns at most 200 hourly rows. Every
tag, sensor, uom and code that is not ^[A-Za-z0-9_.%-]{1,48}$ is replaced by '?' and counted."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_common import McpServer, Tool, ToolRefused, clean_code, clean_text  # noqa: E402

SUMMARY_ROWS = 200
SET_ROWS = 100
S = {"type": "object", "properties": {}}
SUMMARY_SCHEMA = {"type": "object", "properties": {
    "snapshot": {"type": "integer"}, "unit": {"type": "string"}, "zone": {"type": "string"}, "tag": {"type": "string"},
    "sensor": {"type": "string"}, "from": {"type": "string"}, "to": {"type": "string"}},
    "required": ["snapshot", "unit", "zone", "tag"]}
SET_SCHEMA = {"type": "object", "properties": {"snapshot": {"type": "integer"}}, "required": ["snapshot"]}


def _int(v, what):
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ToolRefused("%s must be a positive integer" % what)
    return v


def _code(v, what, required=True):
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v or len(v) > 48:
        raise ToolRefused("%s must be a short text" % what)
    return v


class LakeServer:
    def __init__(self, session, lake):
        self.session, self.lake = session, lake
        self.app = McpServer("mcp-lake", "mcp-lake", session, [
            Tool("lake.snapshots", "List the lake's snapshots (id, cut, lineage).", S, self.t_snapshots),
            Tool("lake.summary", "Hourly n/mean/min/max of one tag of a unit and zone, at most 200 hours.", SUMMARY_SCHEMA, self.t_summary),
            Tool("lake.catalogue", "The catalogue of a snapshot.", SET_SCHEMA, self.t_catalogue)])

    def t_snapshots(self, ctx, args):
        n = [0]
        rows = [{"snapshot_id": r["snapshot_id"], "cut_at": clean_text(r.get("cut_at"), 40),
                 "lineage": clean_code(r.get("lineage"), n), "lineage_verified": bool(r.get("lineage_verified")),
                 "rows": (r.get("rows") or {}).get("measurement") if isinstance(r.get("rows"), dict) else None}
                for r in self.lake.snapshots()][-SET_ROWS:]
        return {"snapshots": rows, "replaced": n[0]}

    def t_summary(self, ctx, args):
        snap = _int(args.get("snapshot"), "snapshot")
        unit, zone, tag = _code(args.get("unit"), "unit"), _code(args.get("zone"), "zone"), _code(args.get("tag"), "tag")
        sensor = _code(args.get("sensor"), "sensor", False)
        lo, hi = args.get("from"), args.get("to")
        rows, _ = self.lake.measurements(snap, unit, zone, tag=tag, sensor=sensor)
        n = [0]
        hours = {}
        for r in rows:
            t, v = r["measured_at"], r.get("value")
            if v is None or (lo and t < str(lo)) or (hi and t >= str(hi)):
                continue
            try:
                x = float(v)
            except ValueError:
                continue
            h = hours.setdefault(t[:13], [0, 0.0, x, x])
            h[0] += 1
            h[1] += x
            h[2], h[3] = min(h[2], x), max(h[3], x)
        out = [{"hour": k, "n": h[0], "mean": "%.4g" % (h[1] / h[0]), "min": "%.4g" % h[2], "max": "%.4g" % h[3]}
               for k, h in sorted(hours.items())][:SUMMARY_ROWS]
        uoms = sorted({clean_code(r.get("uom"), n) for r in rows if r.get("uom") is not None})[:5]
        return {"snapshot": snap, "unit": clean_code(unit, n), "zone": clean_code(zone, n), "tag": clean_code(tag, n),
                "uom": uoms, "hours": out, "hours_total": len(hours), "readings": len(rows), "replaced": n[0]}

    def t_catalogue(self, ctx, args):
        snap = _int(args.get("snapshot"), "snapshot")
        n = [0]
        rows = [{clean_text(k, 40): (clean_code(v, n) if isinstance(v, str) else v) for k, v in r.items()}
                for r in self.lake.small_set("catalogue", snap)][:SET_ROWS]
        return {"snapshot": snap, "rows": rows, "replaced": n[0]}


def main():
    """The mcp-lake pod (research Phase 4a, 6b1): RS_SESSION_SERVER_URL, MEDCEA_LAKE (lake-api, no
    credential), RS_MCP_PORT (8111)."""
    from mcp_common import Session, make_http_server
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, root)
    from research.calib.lake import LakeClient
    srv = LakeServer(Session(os.environ["RS_SESSION_SERVER_URL"], "mcp-lake"), LakeClient(os.environ["MEDCEA_LAKE"]))
    port = int(os.environ.get("RS_MCP_PORT", "8111"))
    sys.stderr.write("mcp-lake: port %d\n" % port)
    make_http_server(srv.app, port=port).serve_forever()


if __name__ == "__main__":
    main()
