"""apps/research-agents/replay_main.py (research Phase 4b stage 3): the entry point of a replay-<h(sid)> Job
(python3 apps/research-agents/replay_main.py, cwd = the code bundle root). It builds the tool listing the way an agent
would have seen it, from the two MCP servers' own definitions (sim first, then lake: the order HttpTools.list_tools
uses), without a session or a network, and hands it to research.agents.replay_job, which does the replay. Lives
here because research/ may not import the operational modules."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)


def listing():
    import mcp_lake
    import mcp_sim
    out = []
    for app in (mcp_sim.SimServer(None, None, None, repo_root=ROOT).app, mcp_lake.LakeServer(None, None).app):
        out += [{"name": t["name"], "description": t.get("description", ""), "inputSchema": t.get("inputSchema")}
                for t in app.tools_list()]
    return out


def main():
    from research.agents import replay_job
    return replay_job.main(listing=listing())


if __name__ == "__main__":
    sys.exit(main())
