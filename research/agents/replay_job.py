"""research/agents/replay_job.py (research Phase 4b stage 3; design 4.7): the strict replay as a Job.

The pure part: events from the environment (MEDCEA_EVENTS_N chunks MEDCEA_EVENTS_0.., gzip + base64 of the
session's trace as JSON, which the orchestrator wrote into the Job), the profile, standing text and skill from
the code bundle, and a tool listing the caller supplies; replay.replay(...) and one final line

    REPLAY_RESULT {json}   with {state: done, ok, first_mismatch, events} or {state: failed, error}

The tool listing is the two MCP servers' own (apps/research-agents/replay_main.py builds it, since research/ may
not import operational code). The profile, standing text and skill are those of the bundle this Job runs: replay
checks their sha256 against the recorded ones, so a session run under another commit reports that as its first
mismatch instead of passing. Stdlib + replay.py."""
import base64
import gzip
import json
import os
import sys

MARK = "REPLAY_RESULT "
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EVENTS_MAX = 64 << 20


def read_events(env):
    n = int(env["MEDCEA_EVENTS_N"])
    if not 1 <= n <= 64:
        raise ValueError("bad chunk count")
    packed = base64.b64decode("".join(env["MEDCEA_EVENTS_%d" % i] for i in range(n)))
    raw = gzip.decompress(packed)
    if len(raw) > EVENTS_MAX:
        raise ValueError("the events are over %d bytes" % EVENTS_MAX)
    events = json.loads(raw)
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        raise ValueError("the events are not a list of objects")
    return events


def emit(obj, out=None):
    (out or sys.stdout).write(MARK + json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    (out or sys.stdout).flush()


def main(env=None, listing=None, out=None, bundle=None):
    """listing: the tool listing ([{name, description, inputSchema}]); the apps entry point supplies it.
    bundle: tests only, {profile, standing, skill} instead of the files of the code bundle."""
    env = os.environ if env is None else env
    from research.agents import loop, replay
    try:
        name = env["MEDCEA_PROFILE"]
        if not name.replace("_", "").isalnum():
            raise ValueError("bad profile name")
        if bundle is not None:
            profile, standing, skill = bundle["profile"], bundle["standing"], bundle["skill"]
        else:
            a = os.path.join(ROOT, "research", "agents")
            profile = loop.load_profile(os.path.join(a, "profiles", name + ".yaml"))
            read = lambda p: open(os.path.join(a, p), encoding="utf-8").read()
            standing = read(os.path.join("policy", "standing.md"))
            skill = read(os.path.join("skills", profile.get("skill", "controller_campaign") + ".md"))
        events = read_events(env)
        verdict = replay.replay(events, profile, standing, skill, listing if listing is not None else [])
    except Exception as e:          # a damaged payload or a missing file is a failed replay, never a traceback only
        emit({"state": "failed", "error": ("%s: %s" % (type(e).__name__, e))[:200]}, out)
        return 1
    emit(dict(verdict, state="done"), out)
    return 0                        # a mismatch is a verdict, not a failed Job
