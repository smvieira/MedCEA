#!/usr/bin/env python3
"""tests/test_dockerhub.py — infra/lib-dockerhub.sh, offline (17 Nov 2026).

deploy-infra used to decide with two `sudo grep`s whether to rewrite MicroK8s's
certs.d/docker.io/hosts.toml and restart containerd; a mistyped sudo password made both
greps fail, so the file was rewritten unchanged and containerd restarted, which on kernel
7.0.0-43 left every running pod on the stock AppArmor profile. Now:

- dockerhub_hosts_sync against a scratch directory and a fake sudo: 0 when the file holds
  exactly the rendered content (nothing written), 10 when it is absent or differs (written,
  mode 600, through a temp file in the same directory), 1 when sudo refuses (nothing
  written, and never "differs"), 1 without credentials, 1 when the comparison's sudo fails;
  the content is byte for byte what deploy-infra and the bootstrap wrote before, so an
  existing install restarts nothing; the password is never in any argv.
- Wiring: neither deploy-infra.sh nor infra/bootstrap-infra.sh restarts containerd, both
  call dockerhub_hosts_sync, and no script restarts containerd (systemctl or snap restart of
  microk8s.daemon-containerd, snap restart microk8s, microk8s stop/start/restart).

Run: python3 tests/test_dockerhub.py
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(REPO, "infra", "lib-dockerhub.sh")
USER, PASS = "medceauser", "s3cr3t-Pass_1"

# What deploy-infra.sh's heredoc wrote until 17 Nov 2026 (and the bootstrap's).
OLD = f'''server = "https://registry-1.docker.io"

[host."https://registry-1.docker.io"]
  capabilities = ["pull", "resolve"]
  [host."https://registry-1.docker.io".auth]
    username = "{USER}"
    password = "{PASS}"
'''


class Sync(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="medcea-dh-")
        self.addCleanup(shutil.rmtree, self.t)
        self.dir = os.path.join(self.t, "certs.d", "docker.io")
        self.file = os.path.join(self.dir, "hosts.toml")
        self.log = os.path.join(self.t, "argv.log")
        self.sudo = os.path.join(self.t, "sudo")
        with open(self.sudo, "w") as f:
            f.write(f'''#!/bin/bash
printf '%s\\n' "$*" >> "{self.log}"
if [[ "$1" == -p && "$3" == -v ]]; then exit "${{FAKE_SUDO_V:-0}}"; fi
if [[ "$1" == -p ]]; then
    [[ -n "${{FAKE_SUDO_RUN_FAIL:-}}" ]] && exit 1
    shift 2; exec "$@"
fi
exit 99
''')
        os.chmod(self.sudo, 0o755)

    def run_sync(self, user=USER, pw=PASS, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("DOCKERHUB", "FAKE_"))}
        e.update(DOCKERHUB_SUDO=self.sudo, DOCKERHUB_HOSTS_DIR=self.dir,
                 DOCKERHUB_USER=user, DOCKERHUB_PASS=pw, **env)
        return subprocess.run(["bash", "-c", 'source "$1"; dockerhub_hosts_sync "prompt %u: "', "x", LIB],
                              env=e, capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def write_existing(self, text):
        os.makedirs(self.dir, exist_ok=True)
        with open(self.file, "w") as f:
            f.write(text)
        st = os.stat(self.file)
        return st.st_mtime_ns, st.st_ino

    def test_unchanged_file_is_left_alone(self):
        before = self.write_existing(OLD)
        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        st = os.stat(self.file)
        self.assertEqual((st.st_mtime_ns, st.st_ino), before, "nothing written")

    def test_absent_file_is_written(self):
        r = self.run_sync()
        self.assertEqual(r.returncode, 10, r.stderr)
        with open(self.file) as f:
            self.assertEqual(f.read(), OLD)
        self.assertEqual(os.stat(self.file).st_mode & 0o777, 0o600)
        self.assertEqual(os.listdir(self.dir), ["hosts.toml"], "no temp file left")

    def test_changed_password_is_written(self):
        self.write_existing(OLD.replace(PASS, "old-pass"))
        r = self.run_sync()
        self.assertEqual(r.returncode, 10, r.stderr)
        with open(self.file) as f:
            self.assertEqual(f.read(), OLD)
        # a second run: unchanged
        self.assertEqual(self.run_sync().returncode, 0)

    def test_extra_line_counts_as_different(self):
        # two substring greps called this "configured"; the whole file must match
        self.write_existing(OLD + 'mirror = "x"\n')
        self.assertEqual(self.run_sync().returncode, 10)

    def test_refused_sudo_is_not_a_difference(self):
        before = self.write_existing(OLD.replace(PASS, "old-pass"))
        r = self.run_sync(FAKE_SUDO_V="1")
        self.assertEqual(r.returncode, 1)
        st = os.stat(self.file)
        self.assertEqual((st.st_mtime_ns, st.st_ino), before)
        with open(self.log) as f:
            self.assertEqual(len(f.read().splitlines()), 1, "nothing after a refused -v")

    def test_failing_comparison_sudo_is_not_a_difference(self):
        r = self.run_sync(FAKE_SUDO_RUN_FAIL="1")
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(self.file))

    def test_without_credentials(self):
        self.assertEqual(self.run_sync(user="").returncode, 1)
        self.assertEqual(self.run_sync(pw="").returncode, 1)
        self.assertFalse(os.path.exists(self.log), "sudo never asked")

    def test_password_never_in_argv(self):
        self.run_sync()
        self.write_existing(OLD.replace(PASS, "old-pass"))
        self.run_sync()
        with open(self.log) as f:
            argv = f.read()
        self.assertIn("prompt %u: ", argv)
        # every call carries the prompt (no -n): a sudo without a timestamp asks again
        self.assertTrue(all(l.startswith("-p prompt %u: ") for l in argv.splitlines()), argv)
        self.assertNotIn(PASS, argv)
        self.assertNotIn(USER, argv)


class Wiring(unittest.TestCase):
    def code(self, path):
        with open(os.path.join(REPO, path)) as f:
            return "\n".join(l for l in f.read().splitlines() if not l.lstrip().startswith("#"))

    def test_no_script_restarts_containerd(self):
        for p in ("deploy-infra.sh", "infra/bootstrap-infra.sh"):
            t = self.code(p)
            self.assertIn("dockerhub_hosts_sync", t, p)
            self.assertNotIn("DOCKER_CERTS_DIR", t, p)
        hits = []
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in (".git", "tests", "logs", "node_modules", ".venv", "research")]
            for n in files:
                if n.endswith(".sh"):
                    p = os.path.join(root, n)
                    if re.search(r"restart\s+snap\.microk8s\.daemon-containerd|microk8s\.daemon-containerd\s+restart"
                                 r"|snap\s+restart\s+microk8s|(^|[\s;&|(])(\$MK8S|mk8s|microk8s)\s+(stop|start|restart)\b",
                                 self.code(os.path.relpath(p, REPO))):
                        hits.append(os.path.relpath(p, REPO))
        self.assertEqual(hits, [], "a containerd restart on a running cluster leaves pods on the stock AppArmor profile")


if __name__ == "__main__":
    unittest.main(verbosity=1)
