"""apps/research-agents/jobs.py (research Phase 4a, stage 6a): Job manifests for agent and sim
Jobs and the Job-backed simulation runner for mcp-sim (the runner interface of mcp_sim.py).
Pure code over the Kubernetes interface of kube.py. Manifests are minimal and carry no
controller ownerReference (design: rsgrants must not trace a Job to the orchestrator). Since 6b2 they carry
the unpack init container, volumes and security context of k8s/agents.yaml (built here).

Names: a session id is mixed-case base64url, which a Kubernetes name cannot hold, so the agent
Job is agent-<first 20 hex of sha256(sid)> (design said agent-<sid>); a campaign id is c+20 hex
and keeps sim-<cid>."""
import base64
import hashlib
import json
import re

CID = re.compile(r"^c[0-9a-f]{20}$")
SIM_MARK = "SIM_RESULT "
SPEC_MAX = 65536
LOG_MAX = 1 << 20


def agent_job_name(sid):
    return "agent-" + hashlib.sha256(sid.encode()).hexdigest()[:20]


def sim_job_name(cid):
    return "sim-" + cid


_SEC = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
_UNPACK = ("set -e; tar xzf /bundle/code.tgz -C /opt/medcea -m --no-overwrite-dir; python3 -m pip install -q --no-cache-dir "
           "--disable-pip-version-check --no-index --find-links /wheels --require-hashes --no-deps "
           "--target /opt/extra -r /opt/medcea/apps/research-agents/requirements-services.txt")


def _podspec(cfg, container, runs):
    """The pod spec shared by agent and sim Jobs: the same unpack init container and security
    context as the Deployments of k8s/agents.yaml; the sim Job also mounts research-runs."""
    mounts = [{"name": "code", "mountPath": "/opt/medcea"}, {"name": "extra", "mountPath": "/opt/extra"},
              {"name": "tmp", "mountPath": "/tmp"}]
    container = dict(container, imagePullPolicy="IfNotPresent", securityContext=dict(_SEC),
                     resources={"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "1Gi"}},
                     env=[{"name": "PYTHONPATH", "value": "/opt/extra"}, {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                          {"name": "PYTHONUNBUFFERED", "value": "1"}] + container["env"],
                     volumeMounts=mounts + ([{"name": "runs", "mountPath": "/runs"}] if runs else []))
    init = {"name": "unpack", "image": cfg["image"], "imagePullPolicy": "IfNotPresent",
            "command": ["sh", "-c", _UNPACK], "env": [{"name": "HOME", "value": "/tmp"}],
            "securityContext": dict(_SEC), "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"memory": "256Mi"}},
            "volumeMounts": [{"name": "bundle", "mountPath": "/bundle", "readOnly": True},
                             {"name": "wheels", "mountPath": "/wheels", "readOnly": True}] + mounts[:3]}
    vols = [{"name": "bundle", "configMap": {"name": "research-code"}},
            {"name": "wheels", "persistentVolumeClaim": {"claimName": "research-wheels", "readOnly": True}},
            {"name": "code", "emptyDir": {"sizeLimit": "64Mi"}}, {"name": "extra", "emptyDir": {"sizeLimit": "128Mi"}},
            {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}]
    if runs:
        vols.append({"name": "runs", "persistentVolumeClaim": {"claimName": "research-runs"}})
    return {"restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
            "priorityClassName": "medcea-research-low",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "initContainers": [init], "containers": [container], "volumes": vols}


def _job(cfg, name, labels, container, deadline_s, runs=False):
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "labels": dict(labels, **{"app": labels["app"]})},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": int(deadline_s), "ttlSecondsAfterFinished": 3600,
                     "template": {"metadata": {"labels": dict(labels)},
                                  "spec": _podspec(cfg, container, runs)}}}


def agent_job(cfg, sid, claim, profile, wall_h):
    env = [("MEDCEA_SID", sid), ("MEDCEA_CLAIM", claim), ("MEDCEA_PROFILE", profile),
           ("MEDCEA_SESSION_URL", cfg["session_url"]), ("MEDCEA_MCP_SIM", cfg["mcp_sim_url"]),
           ("MEDCEA_MCP_LAKE", cfg["mcp_lake_url"]), ("MEDCEA_CODE_COMMIT", cfg["code_commit"])]
    c = {"name": "agent", "image": cfg["image"], "workingDir": cfg.get("code_dir", "/opt/medcea"), "command": ["python3", "-m", "research.agents.run_agent"],
         "env": [{"name": k, "value": v} for k, v in env]}
    return _job(cfg, agent_job_name(sid), {"app": "agent", "medcea/sid-sha": hashlib.sha256(sid.encode()).hexdigest()[:20]},
                c, int(wall_h * 3600) + 120)


def sim_job(cfg, cid, spec, cap_h, deadline_s, pool):
    raw = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > SPEC_MAX:
        raise ValueError("the spec is over %d bytes" % SPEC_MAX)
    c = {"name": "sim", "image": cfg["image"], "workingDir": cfg.get("code_dir", "/opt/medcea"),
         "command": ["python3", "-m", "research.agents.sim_job", "--out", "/runs/campaigns/" + cid,
                     "--jobs", str(int(pool)), "--max-cpu-hours", repr(round(float(cap_h), 6))],
         "env": [{"name": "MEDCEA_SIM_SPEC", "value": base64.b64encode(raw).decode()}]}
    return _job(cfg, sim_job_name(cid), {"app": "sim", "medcea/cid": cid}, c, deadline_s, runs=True)


def parse_result(log):
    """The last SIM_RESULT line of a Job's log, or None."""
    for line in reversed((log or "").splitlines()):
        if line.startswith(SIM_MARK):
            try:
                r = json.loads(line[len(SIM_MARK):])
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
