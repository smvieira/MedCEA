"""apps/research-agents/jobs.py (research Phase 4a, stage 6a): Job manifests for agent and sim
Jobs and the Job-backed simulation runner for mcp-sim (the runner interface of mcp_sim.py).
Pure code over the Kubernetes interface of kube.py. Manifests are minimal and carry no
controller ownerReference (design: rsgrants must not trace a Job to the orchestrator). Since 6b2 they carry
the unpack init container, volumes and security context of k8s/agents.yaml (built here).

Stage 3 of 4b adds the estimate Job (R7: estimate-<eid>, FLC and MPC specs; sim_job --estimate) and the replay Job
(replay-<20 hex of sha256(sid)>; the events travel in the Job's environment, gzip + base64 in chunks, so the Job
needs no network at all). The sim and estimate Jobs also install the controller wheels
(requirements-controllers.txt: numpy, scipy, scikit-fuzzy, gekko...), which no Deployment needs.

Research Phase 4e (design rs4e 2.3): the sim Job's command carries --series-every (cfg series_every, the
orchestrator's RS_SIM_SERIES_EVERY, default 60 s; 0 = off), so each run's chamber series is written to
/runs/campaigns/<cid>/series/<n>.json.gz next to results.jsonl, outside every digest and never in the log.

Names: a session id is mixed-case base64url, which a Kubernetes name cannot hold, so the agent
Job is agent-<first 20 hex of sha256(sid)> (design said agent-<sid>); a campaign id is c+20 hex
and keeps sim-<cid>."""
import base64
import gzip
import hashlib
import json
import re

CID = re.compile(r"^c[0-9a-f]{20}$")
EID = re.compile(r"^e[0-9a-f]{20}$")
SIM_MARK = "SIM_RESULT "
EST_MARK = "ESTIMATE_RESULT "
REPLAY_MARK = "REPLAY_RESULT "
EVENT_CHUNK = 90000          # bytes of base64 per env var: Linux caps one environment string at 128 KiB
EVENT_CHUNKS_MAX = 8         # about 720 KB of base64 in the pod spec, which etcd holds at 1.5 MB
SPEC_MAX = 65536
SERIES_EVERY_DEFAULT = 60.0  # design rs4e 2.3 (OD-4e-6): a sim Job's run series every 60 simulated seconds
LOG_MAX = 1 << 20


def agent_job_name(sid):
    return "agent-" + hashlib.sha256(sid.encode()).hexdigest()[:20]


def sim_job_name(cid):
    return "sim-" + cid


def estimate_job_name(eid):
    return "estimate-" + eid


def replay_job_name(sid):
    return "replay-" + hashlib.sha256(sid.encode()).hexdigest()[:20]


_SEC = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
_UNPACK = ("set -e; tar xzf /bundle/code.tgz -C /opt/medcea -m --no-overwrite-dir; python3 -m pip install -q --no-cache-dir "
           "--disable-pip-version-check --no-index --find-links /wheels --require-hashes --no-deps "
           "--target /opt/extra -r /opt/medcea/apps/research-agents/requirements-services.txt")


_CTRL = ("; python3 -m pip install -q --no-cache-dir --disable-pip-version-check --no-index --find-links /wheels "
         "--require-hashes --no-deps --target /opt/extra -r /opt/medcea/apps/research-agents/requirements-controllers.txt")


def _podspec(cfg, container, runs, controllers=False, resources=None):
    """The pod spec shared by agent and sim Jobs: the same unpack init container and security
    context as the Deployments of k8s/agents.yaml; the sim Job also mounts research-runs."""
    mounts = [{"name": "code", "mountPath": "/opt/medcea"}, {"name": "extra", "mountPath": "/opt/extra"},
              {"name": "tmp", "mountPath": "/tmp"}]
    container = dict(container, imagePullPolicy="IfNotPresent", securityContext=dict(_SEC),
                     resources=resources or {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "1Gi"}},
                     env=[{"name": "PYTHONPATH", "value": "/opt/extra"}, {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                          {"name": "PYTHONUNBUFFERED", "value": "1"}] + container["env"],
                     volumeMounts=mounts + ([{"name": "runs", "mountPath": "/runs"}] if runs else []))
    init = {"name": "unpack", "image": cfg["image"], "imagePullPolicy": "IfNotPresent",
            "command": ["sh", "-c", _UNPACK + (_CTRL if controllers else "")], "env": [{"name": "HOME", "value": "/tmp"}],
            "securityContext": dict(_SEC), "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"memory": "512Mi" if controllers else "256Mi"}},
            "volumeMounts": [{"name": "bundle", "mountPath": "/bundle", "readOnly": True},
                             {"name": "wheels", "mountPath": "/wheels", "readOnly": True}] + mounts[:3]}
    vols = [{"name": "bundle", "configMap": {"name": "research-code"}},
            {"name": "wheels", "persistentVolumeClaim": {"claimName": "research-wheels", "readOnly": True}},
            {"name": "code", "emptyDir": {"sizeLimit": "64Mi"}}, {"name": "extra", "emptyDir": {"sizeLimit": "512Mi" if controllers else "128Mi"}},
            {"name": "tmp", "emptyDir": {"sizeLimit": "256Mi" if controllers else "64Mi"}}]
    if runs:
        vols.append({"name": "runs", "persistentVolumeClaim": {"claimName": "research-runs"}})
    return {"restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
            "priorityClassName": "medcea-research-low",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "initContainers": [init], "containers": [container], "volumes": vols}


def _job(cfg, name, labels, container, deadline_s, runs=False, controllers=False, resources=None):
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "labels": dict(labels, **{"app": labels["app"]})},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": int(deadline_s), "ttlSecondsAfterFinished": 3600,
                     "template": {"metadata": {"labels": dict(labels)},
                                  "spec": _podspec(cfg, container, runs, controllers, resources)}}}


def agent_job(cfg, sid, claim, profile, wall_h, endpoint=None):
    """endpoint: {name, context} of the model endpoint the scientist chose (the model picker), else None."""
    env = [("MEDCEA_SID", sid), ("MEDCEA_CLAIM", claim), ("MEDCEA_PROFILE", profile),
           ("MEDCEA_SESSION_URL", cfg["session_url"]), ("MEDCEA_MCP_SIM", cfg["mcp_sim_url"]),
           ("MEDCEA_MCP_LAKE", cfg["mcp_lake_url"]), ("MEDCEA_CODE_COMMIT", cfg["code_commit"])]
    if endpoint:
        env += [("MEDCEA_ENDPOINT", endpoint["name"]), ("MEDCEA_ENDPOINT_CONTEXT", str(int(endpoint["context"])))]
    if cfg.get("model_gateway_url"):
        env.append(("MEDCEA_MODEL_GATEWAY", cfg["model_gateway_url"]))
    c = {"name": "agent", "image": cfg["image"], "workingDir": cfg.get("code_dir", "/opt/medcea"), "command": ["python3", "-m", "research.agents.run_agent"],
         "env": [{"name": k, "value": v} for k, v in env]}
    return _job(cfg, agent_job_name(sid), {"app": "agent", "medcea/sid-sha": hashlib.sha256(sid.encode()).hexdigest()[:20]},
                c, int(wall_h * 3600) + 120)


def series_every(cfg):
    """The run series interval for sim Jobs (research Phase 4e, design rs4e 2.3): cfg["series_every"] (the
    orchestrator's RS_SIM_SERIES_EVERY), default SERIES_EVERY_DEFAULT; 0 = off. Seconds, 0..86400."""
    v = cfg.get("series_every", SERIES_EVERY_DEFAULT)
    if isinstance(v, bool):
        raise ValueError("the series interval must be a number of seconds")
    try:
        v = float(v)
    except (TypeError, ValueError):
        raise ValueError("the series interval must be a number of seconds") from None
    if not 0 <= v <= 86400:
        raise ValueError("the series interval must be 0 (off) to 86400 seconds")
    return v


def sim_job(cfg, cid, spec, cap_h, deadline_s, pool):
    """Each run's chamber series goes to /runs/campaigns/<cid>/series/<n>.json.gz next to results.jsonl
    (--series-every, design rs4e 2.3); never into the log's SIM_RESULT."""
    raw = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > SPEC_MAX:
        raise ValueError("the spec is over %d bytes" % SPEC_MAX)
    every = series_every(cfg)
    c = {"name": "sim", "image": cfg["image"], "workingDir": cfg.get("code_dir", "/opt/medcea"),
         "command": ["python3", "-m", "research.agents.sim_job", "--out", "/runs/campaigns/" + cid,
                     "--jobs", str(int(pool)), "--max-cpu-hours", repr(round(float(cap_h), 6)),
                     "--series-every", ("%g" % every)],
         "env": [{"name": "MEDCEA_SIM_SPEC", "value": base64.b64encode(raw).decode()}]}
    return _job(cfg, sim_job_name(cid), {"app": "sim", "medcea/cid": cid}, c, deadline_s, runs=True, controllers=True,
                resources={"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "2Gi"}})


def estimate_job(cfg, eid, spec):
    """R7: 250m / 512Mi / 1Gi, 10 minutes in all (the unpack included); the tool waits at most 300 s."""
    raw = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > SPEC_MAX:
        raise ValueError("the spec is over %d bytes" % SPEC_MAX)
    c = {"name": "estimate", "image": cfg["image"], "workingDir": cfg.get("code_dir", "/opt/medcea"),
         "command": ["python3", "-m", "research.agents.sim_job", "--estimate"],
         "env": [{"name": "MEDCEA_SIM_SPEC", "value": base64.b64encode(raw).decode()}]}
    return _job(cfg, estimate_job_name(eid), {"app": "estimate", "medcea/eid": eid}, c, 600, controllers=True,
                resources={"requests": {"cpu": "250m", "memory": "512Mi"}, "limits": {"memory": "1Gi"}})


def pack_events(events):
    """The session's events as gzip + base64 chunks for the replay Job's environment (deterministic)."""
    raw = json.dumps(events, sort_keys=True, separators=(",", ":")).encode()
    b = base64.b64encode(gzip.compress(raw, 9, mtime=0)).decode()
    chunks = [b[i:i + EVENT_CHUNK] for i in range(0, len(b), EVENT_CHUNK)] or [""]
    if len(chunks) > EVENT_CHUNKS_MAX:
        raise ValueError("the session's trace is too large to replay as a Job (%d KB packed; the limit is %d KB): "
                         "replay it on the host" % (len(b) // 1000, EVENT_CHUNK * EVENT_CHUNKS_MAX // 1000))
    return chunks


def replay_job(cfg, sid, profile, events):
    """The strict replay (design 4.7): no network, no Secret, no volume but the code and the emptyDirs. The events
    are in the environment because the Job may not reach research-session (the policy admits only the
    orchestrator and the two tool servers there); the profile, standing text and skill come from the bundle."""
    chunks = pack_events(events)
    env = [("MEDCEA_PROFILE", profile), ("MEDCEA_EVENTS_N", str(len(chunks)))] + [("MEDCEA_EVENTS_%d" % i, c) for i, c in enumerate(chunks)]
    c = {"name": "replay", "image": cfg["image"], "workingDir": cfg.get("code_dir", "/opt/medcea"),
         "command": ["python3", "apps/research-agents/replay_main.py"],
         "env": [{"name": k, "value": v} for k, v in env]}
    return _job(cfg, replay_job_name(sid), {"app": "replay", "medcea/sid-sha": hashlib.sha256(sid.encode()).hexdigest()[:20]},
                c, 600, resources={"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}})


def parse_result(log, mark=SIM_MARK):
    """The last `mark` line of a Job's log (SIM_RESULT by default), or None."""
    for line in reversed((log or "").splitlines()):
        if line.startswith(mark):
            try:
                r = json.loads(line[len(mark):])
            except ValueError:
                return None
            return r if isinstance(r, dict) else None
    return None


class JobSimRunner:
    """mcp_sim's runner interface over Jobs: start / status / pool. Results come from the Job's
    log (one SIM_RESULT line); manifest.result_digest is the digest of results.jsonl on the
    results volume, so the copy in the log is checkable against the volume."""

    def __init__(self, kube, cfg, pool=2):
        self.kube, self.cfg, self.pool = kube, cfg, int(pool)
        self.final, self.owner = {}, {}

    def start(self, cid, spec, cap_h, deadline_s, sid=None):
        if not CID.match(cid or ""):
            raise ValueError("bad campaign id")
        if not (0 < cap_h <= 24) or not (0 < deadline_s <= 7 * 24 * 3600):
            raise ValueError("cap or deadline out of range")
        self.kube.create_job(sim_job(self.cfg, cid, spec, cap_h, deadline_s, self.pool))
        if sid:
            self.owner[cid] = sid

    def status(self, cid):
        if cid in self.final:
            return self.final[cid]
        js = self.kube.job_status(sim_job_name(cid))
        if js is None:
            return {"state": "failed", "error": "the simulation Job is gone"}
        if js["succeeded"] or js["failed"]:
            pod = self.kube.pod_of_job(sim_job_name(cid))
            res = None
            if pod:
                try:
                    res = parse_result(self.kube.pod_log(pod["name"], LOG_MAX))
                except Exception:
                    res = None
            if res and res.get("state") in ("done", "failed"):
                out = {k: res[k] for k in ("state", "cpu_hours", "manifest", "rows", "error") if k in res}
            elif js["failed"]:
                out = {"state": "failed", "error": "deadline" if js.get("reason") == "DeadlineExceeded" else "the Job failed"}
            else:
                out = {"state": "failed", "error": "the Job ended without a result"}
            self.final[cid] = out
            return out
        return {"state": "running"}

    def delete(self, cid):
        self.final.pop(cid, None)
        return self.kube.delete_job(sim_job_name(cid))
