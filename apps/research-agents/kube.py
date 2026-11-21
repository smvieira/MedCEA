"""apps/research-agents/kube.py (research Phase 4a, stage 6a): the orchestrator's Kubernetes
interface and its urllib implementation (in-cluster service account). Tests use a fake with the
same five methods; nothing here is exercised against a cluster offline.

  create_job(manifest) -> None            (409 = already there is an error: names are per session/campaign)
  job_status(name)     -> None | {active, succeeded, failed, reason}
  pod_of_job(name)     -> None | {name, phase, ip}      (newest pod of the Job)
  delete_job(name)     -> bool            (propagationPolicy Background: its pods go too)
  pod_log(pod, limit)  -> str             (the last `limit` bytes)
"""
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

SA = "/var/run/secrets/kubernetes.io/serviceaccount"


class KubeError(Exception):
    pass


class KubeClient:
    def __init__(self, namespace, base="https://kubernetes.default.svc", token_file=SA + "/token",
                 ca_file=SA + "/ca.crt", timeout=15):
        self.ns, self.base, self.token_file, self.timeout = namespace, base.rstrip("/"), token_file, timeout
        self.ctx = ssl.create_default_context(cafile=ca_file)

    def _req(self, method, path, body=None, raw=False):
        with open(self.token_file) as f:           # re-read: the token is rotated
            token = f.read().strip()
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data, method=method,
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                b = r.read()
                return r.status, (b.decode("utf-8", "replace") if raw else json.loads(b or b"{}"))
        except urllib.error.HTTPError as e:
            return e.code, {}
        except (OSError, ValueError) as e:
            raise KubeError("the Kubernetes API is not reachable (%s)" % type(e).__name__)

    def create_job(self, manifest):
        st, _ = self._req("POST", "/apis/batch/v1/namespaces/%s/jobs" % self.ns, manifest)
        if st not in (200, 201):
            raise KubeError("create job refused (%s)" % st)

    def job_status(self, name):
        st, j = self._req("GET", "/apis/batch/v1/namespaces/%s/jobs/%s" % (self.ns, urllib.parse.quote(name)))
        if st == 404:
            return None
        if st != 200:
            raise KubeError("get job failed (%s)" % st)
        s = j.get("status") or {}
        reason = ""
        for c in s.get("conditions") or []:
            if c.get("status") == "True" and c.get("type") == "Failed":
                reason = c.get("reason") or "Failed"
        return {"active": int(s.get("active") or 0), "succeeded": int(s.get("succeeded") or 0),
                "failed": int(s.get("failed") or 0), "reason": reason}

    def pod_of_job(self, name):
        st, j = self._req("GET", "/api/v1/namespaces/%s/pods?labelSelector=%s" % (
            self.ns, urllib.parse.quote("job-name=" + name)))
        if st != 200:
            raise KubeError("list pods failed (%s)" % st)
        items = sorted(j.get("items") or [], key=lambda p: p["metadata"].get("creationTimestamp", ""))
        if not items:
            return None
        p = items[-1]
        return {"name": p["metadata"]["name"], "phase": (p.get("status") or {}).get("phase", ""),
                "ip": (p.get("status") or {}).get("podIP", "")}

    def delete_job(self, name):
        st, _ = self._req("DELETE", "/apis/batch/v1/namespaces/%s/jobs/%s" % (self.ns, urllib.parse.quote(name)),
                          {"propagationPolicy": "Background"})
        return st in (200, 202)

    def pod_log(self, pod, limit=262144):
        st, text = self._req("GET", "/api/v1/namespaces/%s/pods/%s/log?limitBytes=%d" % (
            self.ns, urllib.parse.quote(pod), limit), raw=True)
        if st != 200:
            raise KubeError("pod log failed (%s)" % st)
        return text
