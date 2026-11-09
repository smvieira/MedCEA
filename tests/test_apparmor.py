#!/usr/bin/env python3
"""tests/test_apparmor.py — the AppArmor rules for containers (infra/lib-apparmor.sh,
infra/apparmor/), offline.

On Ubuntu kernels from 7.0.0-41 a container's processes are labelled
"cri-containerd.apparmor.d//&unconfined", which MicroK8s's profile does not name, so
signals inside a container are denied (8 Nov 2026, containerd#14485).

- containerd-apparmor.sh (the root-run watcher) against a scratch /etc/apparmor.d, a fake
  securityfs and a fake apparmor_parser: MicroK8s's profile (the fixture is the 1.29 snap's
  file) kept line for line, the four rules added before its closing brace, loaded with -r;
  a second run writes nothing; a profile without its closing brace, one that already
  carries the rules, or a parser that refuses the result: exit 1 and the file untouched;
  no AppArmor or no MicroK8s: exit 0 and nothing written. Host profile mosquitto: disabled
  (symlink, recorded, unloaded) while the host lacks /usr/sbin/mosquitto, left on with a
  warning when it has it.
- lib-apparmor.sh aa_containerd_fix with a fake sudo/systemctl/install: installs the
  root-owned copy and both units (rendered: the service runs the copy, the path unit watches
  the profile), enables them, runs the service once; a second call asks sudo for nothing;
  a changed script is installed again; without AppArmor nothing. aa_containerd_remove puts
  a disabled host profile back and removes what it installed.
- aa_status: SKIP without AppArmor or MicroK8s; FAIL when not installed, when the profile
  lacks the rules, when the last run failed, on a signal denial since the run (the kernel
  log), and on a host profile stacked on a container process (a fake /proc); OK otherwise,
  and a stacked "unconfined" (probes, exec) is not a collision.
- Wiring: deploy-infra.sh installs it before the bootstrap and removes it in --uninstall
  after MicroK8s; health-checks.conf runs it first; lib-prereqs knows apparmor_parser.

Run: python3 tests/test_apparmor.py
"""
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "infra", "apparmor", "containerd-apparmor.sh")
LIB = os.path.join(REPO, "infra", "lib-apparmor.sh")
FIXTURE = os.path.join(REPO, "tests", "fixtures", "apparmor", "microk8s-containerd-profile")
MARKER = "# medcea: stacked-peer rules (containerd#14485)"
RULES = [
    "signal (send,receive) peer=cri-containerd.apparmor.d,",
    "signal (send,receive) peer=cri-containerd.apparmor.d//&unconfined,",
    "ptrace (trace,tracedby,read,readby) peer=cri-containerd.apparmor.d,",
    "ptrace (trace,tracedby,read,readby) peer=cri-containerd.apparmor.d//&unconfined,",
]
MOSQUITTO = textwrap.dedent("""\
    abi <abi/5.0>,
    include <tunables/global>

    profile mosquitto /usr/sbin/mosquitto {
      include <abstractions/base>
    }
    """)


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


class Scratch(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="medcea-aa-")
        self.etc = os.path.join(self.t, "etc", "apparmor.d")
        self.secfs = os.path.join(self.t, "secfs")
        self.state = os.path.join(self.t, "state")
        self.host = os.path.join(self.t, "host")
        self.bin = os.path.join(self.t, "bin")
        self.log = os.path.join(self.t, "calls.log")
        for d in (self.etc, os.path.join(self.secfs, "policy", "profiles"), self.state, self.host, self.bin):
            os.makedirs(d, exist_ok=True)
        self.src = os.path.join(self.t, "snap", "containerd-profile")
        write(self.src, read(FIXTURE))
        write(os.path.join(self.etc, "mosquitto"), MOSQUITTO)
        os.makedirs(os.path.join(self.secfs, "policy", "profiles", "mosquitto.3"))
        self.dst = os.path.join(self.etc, "cri-containerd.apparmor.d")
        shutil.copy(self.src, self.dst)  # what MicroK8s's wrapper leaves there
        # the fake parser: -Q fails when FAKE_PARSE_FAIL is set, -r/-R are logged
        write(os.path.join(self.bin, "apparmor_parser"), textwrap.dedent(f"""\
            #!/bin/sh
            echo "apparmor_parser $*" >> {self.log}
            case "$1" in -Q) [ -z "${{FAKE_PARSE_FAIL:-}}" ] || {{ echo "syntax error" >&2; exit 1; }};; esac
            exit 0
            """), 0o755)

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def env(self, **extra):
        e = {
            "PATH": self.bin + ":" + os.environ["PATH"],
            "AA_SRC": self.src, "AA_DIR": self.etc, "AA_SECURITYFS": self.secfs,
            "AA_PARSER": os.path.join(self.bin, "apparmor_parser"), "AA_STATE_DIR": self.state,
            "AA_HOST_ROOT": self.host, "AA_SETTLE": "0", "AA_WAIT_MAX": "0",
        }
        e.update(extra)
        return e

    def reapply(self, **extra):
        return subprocess.run(["sh", SCRIPT], env=self.env(**extra), capture_output=True, text=True)

    def calls(self):
        return read(self.log).splitlines() if os.path.exists(self.log) else []


class Reapply(Scratch):
    def test_microk8s_profile_kept_and_rules_added_before_the_brace(self):
        r = self.reapply()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = read(self.dst)
        lines = out.rstrip("\n").splitlines()
        self.assertEqual(lines[-1], "}")
        orig = read(FIXTURE).rstrip()
        self.assertTrue(orig.endswith("}"))
        self.assertTrue(out.startswith(orig[:-1].rstrip()), "MicroK8s's lines must stay as they are")
        tail = [l.strip() for l in lines[-6:-1]]
        self.assertEqual(tail, [MARKER] + RULES)
        self.assertEqual(out.count("profile cri-containerd.apparmor.d"), 1)
        self.assertIn(f"-r -I {self.etc} {self.dst}", "\n".join(self.calls()))

    def test_second_run_writes_nothing(self):
        self.reapply()
        st = os.stat(self.dst)
        os.utime(self.dst, (st.st_atime, st.st_mtime - 100))
        before = os.stat(self.dst).st_mtime
        r = self.reapply()
        self.assertEqual(r.returncode, 0)
        self.assertIn("already carries the rules", r.stdout)
        self.assertEqual(os.stat(self.dst).st_mtime, before)

    def test_refusals_leave_the_file_alone(self):
        orig = read(self.dst)
        for name, setup, extra in (
            ("no brace", lambda: write(self.src, "profile x {\n  network,\n"), {}),
            ("already ours", lambda: write(self.src, read(FIXTURE).rstrip()[:-1] + f"  {MARKER}\n}}"), {}),
            ("parser refuses", lambda: write(self.src, read(FIXTURE)), {"FAKE_PARSE_FAIL": "1"}),
        ):
            with self.subTest(name):
                setup()
                r = self.reapply(**extra)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("ERROR", r.stdout)
                self.assertEqual(read(self.dst), orig)
                self.assertFalse(any(" -r " in c for c in self.calls()))

    def test_nothing_without_apparmor_or_microk8s(self):
        orig = read(self.dst)
        for extra in ({"AA_SECURITYFS": os.path.join(self.t, "none")}, {"AA_SRC": os.path.join(self.t, "none")}):
            r = self.reapply(**extra)
            self.assertEqual(r.returncode, 0)
            self.assertIn("nothing to do", r.stdout)
            self.assertEqual(read(self.dst), orig)
        self.assertEqual(self.calls(), [])

    def test_host_profile_disabled_while_the_host_lacks_the_binary(self):
        r = self.reapply()
        self.assertEqual(r.returncode, 0, r.stdout)
        link = os.path.join(self.etc, "disable", "mosquitto")
        self.assertEqual(os.readlink(link), os.path.join(self.etc, "mosquitto"))
        self.assertEqual(read(os.path.join(self.state, "disabled-profiles")), "mosquitto\n")
        self.assertIn(f"apparmor_parser -R {self.etc}/mosquitto", self.calls())
        self.reapply()
        self.assertEqual(read(os.path.join(self.state, "disabled-profiles")), "mosquitto\n")

    def test_host_profile_kept_when_the_host_runs_mosquitto(self):
        write(os.path.join(self.host, "usr", "sbin", "mosquitto"), "", 0o755)
        r = self.reapply()
        self.assertEqual(r.returncode, 0)
        self.assertIn("WARNING: /usr/sbin/mosquitto is installed on this host", r.stdout)
        self.assertFalse(os.path.lexists(os.path.join(self.etc, "disable", "mosquitto")))
        self.assertFalse(any(c.startswith("apparmor_parser -R") for c in self.calls()))


class Lib(Scratch):
    def setUp(self):
        super().setUp()
        self.units = os.path.join(self.t, "systemd")
        self.libroot = os.path.join(self.t, "usrlocallib")
        os.makedirs(self.units)
        self.sysstate = os.path.join(self.t, "sysstate")
        os.makedirs(self.sysstate)
        # fake sudo: drops "-p PROMPT", logs, runs the rest
        write(os.path.join(self.bin, "sudo"), textwrap.dedent(f"""\
            #!/bin/bash
            [[ "$1" == -p ]] && shift 2
            echo "sudo $*" >> {self.log}
            exec "$@"
            """), 0o755)
        # fake install: drops -o/-g (the tests do not run as root)
        write(os.path.join(self.bin, "install"), textwrap.dedent("""\
            #!/bin/bash
            a=(); while (( $# )); do case "$1" in -o|-g) shift 2;; *) a+=("$1"); shift;; esac; done
            exec /usr/bin/install "${a[@]}"
            """), 0o755)
        # fake systemctl: state in files
        write(os.path.join(self.bin, "systemctl"), textwrap.dedent(f"""\
            #!/bin/bash
            S={self.sysstate}
            echo "systemctl $*" >> {self.log}
            a=(); for x in "$@"; do [[ "$x" == --* ]] || a+=("$x"); done
            case "${{a[0]}}" in
              daemon-reload) ;;
              enable) for u in "${{a[@]:1}}"; do touch "$S/$u.enabled"; done
                      if [[ " $* " == *" --now "* ]]; then for u in "${{a[@]:1}}"; do touch "$S/$u.active"; done; fi ;;
              disable) for u in "${{a[@]:1}}"; do rm -f "$S/$u.enabled" "$S/$u.active"; done ;;
              start) echo success > "$S/${{a[1]}}.result"; date -u '+%a %Y-%m-%d %H:%M:%S UTC' > "$S/${{a[1]}}.exit"
                     [[ -n "${{FAKE_START:-}}" ]] && $FAKE_START ;;
              is-enabled) [[ -e "$S/${{a[1]}}.enabled" ]] && echo enabled || {{ echo disabled; exit 1; }} ;;
              is-active) [[ -e "$S/${{a[1]}}.active" ]] && echo active || {{ echo inactive; exit 3; }} ;;
              show) case "$*" in *Result*) cat "$S/${{a[-1]}}.result" 2>/dev/null || echo "" ;;
                                 *ExecMainExitTimestamp*) cat "$S/${{a[-1]}}.exit" 2>/dev/null || echo "" ;; esac ;;
            esac
            """), 0o755)

    def bash(self, code, **extra):
        env = self.env(AA_SYSTEMD_DIR=self.units, AA_LIB_ROOT=self.libroot, AA_SYSTEMCTL="systemctl",
                       PROJECT_NAME="medcea", **extra)
        return subprocess.run(["bash", "-c", f"source {LIB}; {code}"], env=env, capture_output=True, text=True)

    def test_install_then_nothing_to_do(self):
        # the service's start runs the real watcher, as systemd would
        start = f"env AA_SRC={self.src} AA_DIR={self.etc} AA_SECURITYFS={self.secfs} AA_PARSER={self.bin}/apparmor_parser AA_STATE_DIR={self.libroot}/medcea-apparmor AA_HOST_ROOT={self.host} AA_SETTLE=0 AA_WAIT_MAX=0 sh {self.libroot}/medcea-apparmor/reapply"
        r = self.bash("aa_containerd_fix", FAKE_START=start)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.access(os.path.join(self.libroot, "medcea-apparmor", "reapply"), os.X_OK))
        svc = read(os.path.join(self.units, "medcea-containerd-apparmor.service"))
        path = read(os.path.join(self.units, "medcea-containerd-apparmor.path"))
        self.assertIn(f"ExecStart={self.libroot}/medcea-apparmor/reapply", svc)
        self.assertIn("Type=oneshot", svc)
        self.assertIn("PathChanged=/etc/apparmor.d/cri-containerd.apparmor.d", path)
        self.assertIn("Unit=medcea-containerd-apparmor.service", path)
        self.assertNotIn("${", svc + path)
        self.assertIn(MARKER, read(self.dst))
        calls = "\n".join(self.calls())
        self.assertIn("enable medcea-containerd-apparmor.service", calls.replace("--quiet ", ""))
        self.assertIn("start medcea-containerd-apparmor.service", calls)
        open(self.log, "w").close()
        r = self.bash("aa_containerd_fix")
        self.assertIn("already in place", r.stdout)
        self.assertFalse([c for c in self.calls() if c.startswith("sudo")], "nothing changed: no sudo")
        # a changed watcher in the repository is installed again: simulated by changing the copy
        with open(os.path.join(self.libroot, "medcea-apparmor", "reapply"), "a") as f:
            f.write("# old\n")
        r = self.bash("aa_containerd_fix", FAKE_START=start)
        self.assertTrue([c for c in self.calls() if c.startswith("sudo install")])

    def test_failed_start_warns_and_returns_1(self):
        r = self.bash("aa_containerd_fix", FAKE_START="false")
        self.assertEqual(r.returncode, 1)
        self.assertIn("WARNING: the AppArmor rules for containers are not in place", r.stderr)

    def test_no_apparmor_nothing(self):
        r = self.bash("aa_containerd_fix", AA_SECURITYFS=os.path.join(self.t, "none"))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_remove_puts_the_host_profile_back(self):
        d = os.path.join(self.libroot, "medcea-apparmor")
        os.makedirs(d)
        write(os.path.join(d, "reapply"), "x")
        write(os.path.join(d, "disabled-profiles"), "mosquitto\n../evil\n")
        write(os.path.join(self.units, "medcea-containerd-apparmor.path"), "x")
        os.makedirs(os.path.join(self.etc, "disable"))
        os.symlink(os.path.join(self.etc, "mosquitto"), os.path.join(self.etc, "disable", "mosquitto"))
        r = self.bash("aa_containerd_remove")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.lexists(os.path.join(self.etc, "disable", "mosquitto")))
        self.assertFalse(os.path.exists(d))
        self.assertFalse(os.listdir(self.units))
        self.assertIn(f"sudo {self.bin}/apparmor_parser -r {self.etc}/mosquitto", self.calls())
        self.assertIn("Re-enabled host AppArmor profile mosquitto", r.stdout)

    # --- aa_status -----------------------------------------------------------------
    def installed(self, result="success", marker=True):
        for u in ("medcea-containerd-apparmor.path", "medcea-containerd-apparmor.service"):
            open(os.path.join(self.sysstate, u + ".enabled"), "w").close()
        open(os.path.join(self.sysstate, "medcea-containerd-apparmor.path.active"), "w").close()
        write(os.path.join(self.sysstate, "medcea-containerd-apparmor.service.result"), result + "\n")
        write(os.path.join(self.sysstate, "medcea-containerd-apparmor.service.exit"), "Sun 2026-11-08 23:10:00 UTC\n")
        if marker:
            with open(self.dst, "a") as f:
                f.write(f"\n  {MARKER}\n")

    def proc(self, pid, label, cgroup="0::/kubepods/burstable/pod1/abc", comm="x"):
        p = os.path.join(self.t, "proc", str(pid))
        write(os.path.join(p, "attr", "apparmor", "current"), label + "\n")
        write(os.path.join(p, "cgroup"), cgroup + "\n")
        write(os.path.join(p, "comm"), comm + "\n")

    def status(self, journal="", **extra):
        write(os.path.join(self.bin, "journalctl"), "#!/bin/sh\ncat <<'EOF'\n" + journal + "\nEOF\n", 0o755)
        os.makedirs(os.path.join(self.t, "proc"), exist_ok=True)
        r = self.bash("aa_status", AA_PROC=os.path.join(self.t, "proc"),
                      AA_JOURNALCTL=os.path.join(self.bin, "journalctl"), **extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_status_skip(self):
        self.assertTrue(self.status(AA_SECURITYFS="/nonexistent").startswith("SKIP|AppArmor is not enabled"))
        self.assertTrue(self.status(AA_SRC="/nonexistent").startswith("SKIP|MicroK8s is not installed"))

    def test_status_not_installed(self):
        self.assertIn("FAIL|medcea-containerd-apparmor is not installed", self.status())

    def test_status_ok_and_probe_labels_are_not_collisions(self):
        self.installed()
        self.proc(10, "cri-containerd.apparmor.d (enforce)", comm="postgres")
        self.proc(11, "cri-containerd.apparmor.d//&unconfined (enforce)", comm="check-status")
        self.proc(12, "snap.foo//&bar (enforce)", cgroup="0::/user.slice", comm="other")
        s = self.status()
        self.assertTrue(s.startswith("OK|"), s)
        self.assertIn("no signal denials since", s)

    def test_status_failures(self):
        denial = ('Nov 08 23:12:00 h kernel: audit: apparmor="DENIED" operation="signal" class="signal" '
                  'profile="cri-containerd.apparmor.d" pid=1 comm="postgres" requested_mask="send" '
                  'denied_mask="send" signal=urg peer="cri-containerd.apparmor.d//&unconfined"')
        self.installed()
        s = self.status(journal=denial)
        self.assertTrue(s.startswith("FAIL|") and "1 signal denial(s)" in s, s)
        self.proc(20, "cri-containerd.apparmor.d//&mosquitto (enforce)", comm="mosquitto")
        s = self.status()
        self.assertIn("host profile attached inside a container: mosquitto (mosquitto)", s)
        shutil.rmtree(os.path.join(self.t, "proc"))
        shutil.copy(self.src, self.dst)
        self.assertIn("lacks the rules", self.status())
        self.installed(result="exit-code")
        self.assertIn("its last run ended 'exit-code'", self.status())


class Wiring(unittest.TestCase):
    def test_deploy_infra(self):
        s = read(os.path.join(REPO, "deploy-infra.sh"))
        fix, boot = s.index("aa_containerd_fix"), s.index("bash ./infra/bootstrap-infra.sh")
        self.assertLess(fix, boot, "installed before the bootstrap, so a fresh install's first containerd start is covered")
        un = s.index('if [[ "${1:-}" == "--uninstall" ]]')
        rm = s.index("aa_containerd_remove")
        self.assertLess(s.index("remove_microk8s", un), rm)

    def test_health_and_prereqs(self):
        conf = [l for l in read(os.path.join(REPO, "health-checks.conf")).splitlines() if l.strip() and not l.startswith("#")]
        self.assertTrue(conf[0].startswith("Container AppArmor") and "| apparmor" in conf[0])
        hc = read(os.path.join(REPO, "health-check.sh"))
        self.assertIn('apparmor)     check_apparmor "$name" ;;', hc)
        self.assertIn("|apparmor|", read(os.path.join(REPO, "infra", "lib-prereqs.sh")))

    def _prereqs(self, entries, logs_env):
        """check_prereqs from a scratch copy of lib-prereqs.sh, _PREREQS replaced."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(os.path.join(d, "infra"))
        lib = os.path.join(d, "infra", "lib-prereqs.sh")
        shutil.copy(os.path.join(REPO, "infra", "lib-prereqs.sh"), lib)
        arr = " ".join("'%s'" % e for e in entries)
        env = {k: v for k, v in os.environ.items() if not k.startswith("MEDCEA_")}
        env.update(logs_env)
        r = subprocess.run(["bash", "-c", 'source "$1"; _PREREQS=(%s); check_prereqs; echo reached' % arr, "x", lib],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env)
        logs = os.path.join(d, "logs")
        found = sorted(os.listdir(logs)) if os.path.isdir(logs) else []
        return r, d, found

    def test_every_prereq_entry_has_three_fields_and_passes_here(self):
        # A '|' inside a test broke the split: "ERROR:  is still missing" (9 Nov 2026).
        out = subprocess.run(["bash", "-c", 'source infra/lib-prereqs.sh; for e in "${_PREREQS[@]}"; do '
                              'IFS="|" read -r t p w x <<<"$e"; printf "%s\\t%s\\t%s\\t%s\\n" "$t" "$p" "$w" "$x"; done'],
                             cwd=REPO, capture_output=True, text=True).stdout
        for line in out.splitlines():
            t, p, w, extra = line.split("\t")
            self.assertTrue(t and p and w and not extra, line)
        r = subprocess.run(["bash", "-c", 'source infra/lib-prereqs.sh; for e in "${_PREREQS[@]}"; do '
                            'IFS="|" read -r t p w <<<"$e"; [[ $p == apparmor ]] && { eval "$t"; exit; }; done; exit 9'],
                           cwd=REPO)
        self.assertEqual(r.returncode, 0, "the apparmor entry passes on a host with apparmor_parser")

    def test_a_missing_package_is_logged(self):
        r, d, found = self._prereqs(["false|nosuchpkg|the test"], {})
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("reached", r.stdout)
        self.assertEqual(len(found), 1, found)
        self.assertTrue(found[0].startswith("prereqs-"))
        path = os.path.join(d, "logs", found[0])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        text = read(path)
        self.assertIn("nosuchpkg", text)
        self.assertIn("no terminal to ask on", text)

    def test_the_callers_log_is_used_and_nothing_logged_when_all_present(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        own = os.path.join(d, "own.log")
        r, _, found = self._prereqs(["false|nosuchpkg|the test"], {"MEDCEA_LOG_FILE": own})
        self.assertEqual((r.returncode, found), (1, []))
        self.assertIn("nosuchpkg", read(own))
        r, _, found = self._prereqs(["true|x|y"], {})
        self.assertEqual((r.returncode, found), (0, []))
        self.assertIn("reached", r.stdout)
        r, _, found = self._prereqs(["false|nosuchpkg|the test"], {"MEDCEA_NO_LOG": "1"})
        self.assertEqual((r.returncode, found), (1, []))

    def test_watcher_is_posix_sh(self):
        for sh in ("sh", "dash", "busybox"):
            if shutil.which(sh):
                args = [sh, "sh", "-n", SCRIPT] if sh == "busybox" else [sh, "-n", SCRIPT]
                self.assertEqual(subprocess.run(args).returncode, 0, sh)


if __name__ == "__main__":
    unittest.main(verbosity=1)
