"""research/agents/run_agent.py (stage 6a): the entrypoint of an agent-<h(sid)> Job (python3 -m research.agents.run_agent, cwd = the code bundle root). Environment:
MEDCEA_SID, MEDCEA_CLAIM (one-time), MEDCEA_PROFILE, MEDCEA_SESSION_URL (research-session agent
port 8101), MEDCEA_MCP_SIM, MEDCEA_MCP_LAKE, and for a profile with backend local MEDCEA_MODEL_GATEWAY. Claims the session token (refused unless this
pod's IP is the one the orchestrator registered), runs the scripted loop with the HTTP tool
client, exits 0 on a stop, 1 on a refusal. Never prints the claim or the token."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main(env=None, transport=None, tool_transport=None, sleep=None, gateway_post=None):
    env = os.environ if env is None else env
    from research.agents import loop
    from research.agents.http_tools import HttpTools
    from research.agents.trace import HttpTransport, TraceClient, TraceRefused
    a = os.path.join(ROOT, "research", "agents")
    name = env["MEDCEA_PROFILE"]
    if not name.replace("_", "").isalnum():
        print("run_agent: bad profile name", file=sys.stderr)
        return 2
    path = os.path.join(a, "profiles", name + ".yaml")
    profile = loop.load_profile(path)
    skill = os.path.join(a, "skills", profile.get("skill", "controller_campaign") + ".md")
    tc = TraceClient(transport or HttpTransport(env["MEDCEA_SESSION_URL"]), env["MEDCEA_SID"])
    try:
        tc.claim(env["MEDCEA_CLAIM"], **({"sleep": sleep} if sleep else {}))
        kw = {"sleep": sleep} if sleep else {}
        tools = HttpTools({"sim": env["MEDCEA_MCP_SIM"], "lake": env["MEDCEA_MCP_LAKE"]}, tc.token,
                          transport=tool_transport, **kw)
        model = None
        if profile["backend"] == "local":
            gw = env.get("MEDCEA_MODEL_GATEWAY")
            if not gw:
                print("run_agent: a local profile needs MEDCEA_MODEL_GATEWAY", file=sys.stderr)
                return 2
            from research.agents.model import GatewayModel
            model = GatewayModel(gw, tc.token, env["MEDCEA_SID"], post=gateway_post, **({"sleep": sleep} if sleep else {}))
        reason = loop.run_profile(path, os.path.join(a, "policy", "standing.md"), skill, tools, tc, model=model)
    except TraceRefused as e:
        print("run_agent: refused (%s)" % e, file=sys.stderr)
        return 1
    print("run_agent: stopped (%s)" % reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
