#!/usr/bin/env python3
"""tests/test_install.py — Superset installed by default (owner decision of 8 Nov 2026,
option B), offline: install.sh, deploy-infra.sh's wheel cache step and config.env.example's
default, in scratch trees with stub scripts. No cluster, no sudo, no lock on the repository.

  Default      config.env.example: IAM_DB_SERVICE_ROLES="true" (a new config.env; an
               existing one keeps its value, configure.sh carries it over), one active line.
  Install      install.sh with stub deploy-infra/deploy-apps/health-check: while the switch
               is true deploy-infra runs a second time after the applications (the switch's
               enable recipe: Grafana and pgAdmin onto their roles), under the same lock and
               MEDCEA_INSTALLER, with a line saying why; false, missing or ambiguous: once.
               A failed second run stops like any stage. The Superset "Still to do" hint
               stays for a config.env whose switch is false.
  WheelCache   deploy-infra.sh's _superset_wheel_cache from its own source text, with
               apps/superset/lib-superset.sh's shared check (superset_wheel_dir_ok, the one
               copy deploy.sh calls too): created mode 700 as the account, through sudo -p
               with a prompt saying why when the parent is not writable; refused (exit 1,
               nothing created, no sudo) inside or around the volumes' directory; as root
               nothing created and no sudo; placed after the bootstrap and the API wait.
  Uninstall    install.sh --uninstall-all (on a pty, stub deploy-infra) removes the cache's
               wheels and the folder, and /var/lib/<project> when that is left empty (the
               function from its source text, /var/lib/ pointed into the scratch tree); a
               folder holding anything else is kept.

  python3 tests/test_install.py
"""
import os
import pty
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env  # noqa: E402


def read(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


def function_text(src, name):
    """The shell function NAME as SRC defines it (up to its closing brace at column 0)."""
    m = re.search(r"^%s\(\) \{\n.*?^\}\n" % re.escape(name), src, re.S | re.M)
    assert m, name
    return m.group(0)


def write(path, text, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


# A stub stage: logs its argv and the installer conventions it inherited.
STAGE = r'''#!/usr/bin/env bash
echo "$(basename "$0") $* installer=${MEDCEA_INSTALLER:-} lock=${MEDCEA_LOCK_HELD:+held}" >> "$STUB_LOG"
n="$(grep -c "^$(basename "$0") " "$STUB_LOG")" || true
[[ "${STUB_FAIL:-}" == "$(basename "$0"):$n" ]] && exit 7
exit 0
'''

# sudo: logs the prompt and the command, then runs it (as this account).
SUDO = r'''#!/usr/bin/env bash
prompt=""
[[ "${1:-}" == -p ]] && { prompt="$2"; shift 2; }
printf '%s\t%s\n' "$prompt" "$*" >> "$STUB_SUDO_LOG"
SUDO_STUB=1 exec "$@"
'''

# install: the account cannot create the folder itself (a root-owned parent) unless sudo runs it.
INSTALL = r'''#!/usr/bin/env bash
[[ -n "${STUB_PLAIN_INSTALL_FAILS:-}" && -z "${SUDO_STUB:-}" ]] && exit 1
args=()
while [[ $# -gt 0 ]]; do
    case "$1" in -o|-g) shift ;; *) args+=("$1") ;; esac   # owner/group: this account anyway
    shift
done
exec /usr/bin/install "${args[@]}"
'''


class Default(unittest.TestCase):
    def test_service_roles_default_true(self):
        lines = [l for l in read("config.env.example").splitlines() if re.match(r"\s*IAM_DB_SERVICE_ROLES=", l)]
        self.assertEqual(lines, ['IAM_DB_SERVICE_ROLES="true"'])

    def test_configure_carries_an_existing_value_over(self):
        """configure.sh rebuilds config.env on the template with every existing value kept:
        an install whose config.env says false keeps false (only a new config.env changes)."""
        src = read("infra/configure.sh")
        m = re.search(r"    awk '\n(.*?)' <\(", src, re.S)
        self.assertTrue(m)
        d = tempfile.mkdtemp(prefix="medcea-install-")
        try:
            old = os.path.join(d, "config.env")
            with open(old, "w") as f:
                f.write('IAM_DB_SERVICE_ROLES="false"\n')
            out = subprocess.run(["awk", m.group(1), old, os.path.join(REPO, "config.env.example")],
                                 capture_output=True, text=True, check=True).stdout
            self.assertIn('IAM_DB_SERVICE_ROLES="false"', out.splitlines())
            self.assertNotIn('IAM_DB_SERVICE_ROLES="true"', out.splitlines())
        finally:
            shutil.rmtree(d)

    def merge(self, config):
        """configure.sh's rebase of an existing config.env, from its own source text."""
        src = read("infra/configure.sh")
        start = src.index("    _KEPT_OFF=()\n")
        end = src.index("    fi\n", src.index("had no IAM_DB_SERVICE_ROLES line")) + len("    fi\n")
        d = tempfile.mkdtemp(prefix="medcea-install-")
        try:
            cfg = os.path.join(d, "config.env")
            with open(cfg, "w") as f:
                f.write(config)
            script = "GREEN= YELLOW= NC=\nCONFIG_FILE=%s\nEXAMPLE_FILE=%s\n%s" % (
                cfg, os.path.join(REPO, "config.env.example"), src[start:end])
            p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                               stdin=subprocess.DEVNULL, env=clean_env())
            with open(cfg) as f:
                return p, f.read().splitlines()
        finally:
            shutil.rmtree(d)

    def test_an_existing_config_without_the_line_keeps_false(self):
        """A config.env from before Phase 2.5 ran with false: the rebase writes false, not the
        new template default, and says so once (review of 8 Nov 2026)."""
        for config in ('PROJECT_NAME=medcea\n', 'PROJECT_NAME=medcea', '# IAM_DB_SERVICE_ROLES="true"\nPROJECT_NAME=x\n'):
            with self.subTest(config=config):
                p, lines = self.merge(config)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual([l for l in lines if l.startswith("IAM_DB_SERVICE_ROLES=")],
                                 ['IAM_DB_SERVICE_ROLES="false"'])
                self.assertIn("had no IAM_DB_SERVICE_ROLES line; it is set to false", p.stdout)
                self.assertNotIn("Kept from the previous config.env", "\n".join(lines))
                self.assertIn('PROJECT_NAME=', "\n".join(lines))

    def test_an_existing_line_is_kept_and_nothing_is_said(self):
        for v in ("true", "false"):
            with self.subTest(v):
                p, lines = self.merge('IAM_DB_SERVICE_ROLES="%s"\n' % v)
                self.assertEqual([l for l in lines if l.startswith("IAM_DB_SERVICE_ROLES=")],
                                 ['IAM_DB_SERVICE_ROLES="%s"' % v])
                self.assertNotIn("had no IAM_DB_SERVICE_ROLES line", p.stdout)

    def test_a_new_config_env_is_the_template(self):
        src = read("infra/configure.sh")
        self.assertIn('cp "$EXAMPLE_FILE" "$CONFIG_FILE"', src[:src.index("_KEPT_OFF=()")])


class Tree:
    """install.sh with stub stages and the real lock, in a scratch directory."""

    def __init__(self, config):
        self.root = tempfile.mkdtemp(prefix="medcea-install-")
        shutil.copy(os.path.join(REPO, "install.sh"), self.path("install.sh"))
        os.makedirs(self.path("infra"))
        shutil.copy(os.path.join(REPO, "infra", "lib-lock.sh"), self.path("infra", "lib-lock.sh"))
        os.makedirs(self.path("apps", "superset"))
        shutil.copy(os.path.join(REPO, "apps", "superset", "lib-superset.sh"),
                    self.path("apps", "superset", "lib-superset.sh"))
        # the credentials box writes to /dev/tty: not under test here
        write(self.path("infra", "lib-credentials.sh"),
              "show_ca_trust() { :; }\nlatest_credentials() { echo credentials-x.txt; }\nshow_credentials() { :; }\n", 0o644)
        for s in ("deploy-infra.sh", "deploy-apps.sh", "health-check.sh"):
            write(self.path(s), STAGE)
        self.bin = self.path(".stub", "bin")
        write(os.path.join(self.bin, "sudo"), SUDO)
        # never the host's: the live onboarding wizard's user service, MicroK8s
        for name in ("systemctl", "microk8s"):
            write(os.path.join(self.bin, name), "#!/bin/sh\nexit 1\n")
        shutil.copy(os.path.join(REPO, "infra", "lib-data-volumes.sh"), self.path("infra", "lib-data-volumes.sh"))
        write(self.path("config.env"), config, 0o600)
        self.log = self.path(".stub", "stages.log")
        self.sudo_log = self.path(".stub", "sudo.log")

    def path(self, *p):
        return os.path.join(self.root, *p)

    def env(self, **extra):
        e = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], STUB_LOG=self.log,
                      STUB_SUDO_LOG=self.sudo_log, HOME=self.root)
        for k in ("MEDCEA_INSTALLER", "MEDCEA_CONFIRMED", "MEDCEA_LOG_FILE"):
            e.pop(k, None)
        e.update(extra)
        return e

    def run(self, *args, **env):
        return subprocess.run(["bash", self.path("install.sh"), *args], capture_output=True, text=True,
                              env=self.env(**env), cwd=self.root, stdin=subprocess.DEVNULL, timeout=120,
                              start_new_session=True)

    def run_pty(self, *args, answers="", **env):
        """install.sh on a pseudo-terminal (its uninstall confirm needs one); ANSWERS typed."""
        master, slave = pty.openpty()
        p = subprocess.Popen(["bash", self.path("install.sh"), *args], stdin=slave, stdout=slave, stderr=slave,
                             env=self.env(**env), cwd=self.root, start_new_session=True)
        os.close(slave)
        os.write(master, answers.encode())
        out, deadline = b"", time.time() + 120
        while time.time() < deadline:
            r, _, _ = select.select([master], [], [], 0.5)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            elif p.poll() is not None:
                break
        p.wait(timeout=10)
        os.close(master)
        return p.returncode, out.decode(errors="replace")

    def stages(self):
        try:
            with open(self.log) as f:
                return [l.split() for l in f.read().splitlines()]
        except FileNotFoundError:
            return []

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


CONFIG = 'PROJECT_NAME=medcea\nNAMESPACE=medcea\nPORTAL_DOMAIN=portal.example.test\n'
WHY = "IAM_DB_SERVICE_ROLES is true: the infrastructure runs once more"


class Install(unittest.TestCase):
    def install(self, switch_lines, **env):
        t = Tree(CONFIG + switch_lines)
        try:
            p = t.run(**env)
            return p, t.stages()
        finally:
            t.close()

    def test_true_runs_deploy_infra_again_after_the_applications(self):
        p, st = self.install('IAM_DB_SERVICE_ROLES="true"\n')
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertEqual([s[0] for s in st], ["deploy-infra.sh", "deploy-apps.sh", "deploy-infra.sh", "health-check.sh"])
        # the second run: no --configure, the installer's conventions, under the lock install.sh holds
        self.assertEqual(st[2][1:], ["installer=1", "lock=held"])
        self.assertEqual(st[1][1], "--all")
        self.assertIn(WHY, p.stdout)
        self.assertIn("Grafana and pgAdmin", p.stdout)
        self.assertLess(p.stdout.index("2/3  Applications"), p.stdout.index(WHY))
        self.assertLess(p.stdout.index(WHY), p.stdout.index("3/3  Health check"))

    def test_configure_goes_to_the_first_run_only(self):
        t = Tree(CONFIG + 'IAM_DB_SERVICE_ROLES=true\n')
        try:
            p = t.run("--configure")
            st = t.stages()
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            self.assertEqual(st[0][:2], ["deploy-infra.sh", "--configure"])
            self.assertEqual(st[2][:2], ["deploy-infra.sh", "installer=1"])
        finally:
            t.close()

    def test_false_missing_or_ambiguous_runs_it_once(self):
        for lines in ('IAM_DB_SERVICE_ROLES="false"\n', "",
                      'IAM_DB_SERVICE_ROLES="true"\nIAM_DB_SERVICE_ROLES="true"\n',
                      'IAM_DB_SERVICE_ROLES="yes"\n', '# IAM_DB_SERVICE_ROLES="true"\n'):
            with self.subTest(lines=lines):
                p, st = self.install(lines)
                self.assertEqual(p.returncode, 0, p.stderr[-2000:])
                self.assertEqual([s[0] for s in st], ["deploy-infra.sh", "deploy-apps.sh", "health-check.sh"])
                self.assertNotIn(WHY, p.stdout)

    def test_a_failed_second_run_stops_the_install(self):
        p, st = self.install('IAM_DB_SERVICE_ROLES="true"\n', STUB_FAIL="deploy-infra.sh:2")
        self.assertEqual(p.returncode, 7)
        self.assertEqual([s[0] for s in st], ["deploy-infra.sh", "deploy-apps.sh", "deploy-infra.sh"])
        self.assertIn('Stopped: "2/3  Infrastructure again', p.stdout)
        self.assertNotIn("MedCEA is installed", p.stdout)

    def test_infra_only_and_apps_only_run_one_stage(self):
        for mode, want in (("--infra-only", ["deploy-infra.sh"]), ("--apps-only", ["deploy-apps.sh"])):
            with self.subTest(mode):
                t = Tree(CONFIG + 'IAM_DB_SERVICE_ROLES="true"\n')
                try:
                    p = t.run(mode)
                    self.assertEqual(p.returncode, 0, p.stderr[-2000:])
                    self.assertEqual([s[0] for s in t.stages()], want)
                finally:
                    t.close()

    def test_the_superset_hint_stays_for_a_false_switch(self):
        """A reinstall that kept its config.env (switch false) still skips Superset: the hint
        points to the switch (critique 7)."""
        t = Tree(CONFIG + 'IAM_DB_SERVICE_ROLES="false"\n')
        try:
            os.makedirs(t.path("logs"))
            with open(t.path("logs", "deploy-apps-20261108-120000.log"), "w") as f:
                f.write("[superset] skipped: Superset needs IAM_DB_SERVICE_ROLES=true (its data connection is svc_superset)\n")
            p = t.run()
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            self.assertIn("Still to do: Superset was skipped, it needs IAM_DB_SERVICE_ROLES=true", p.stdout)
        finally:
            t.close()
        self.assertIn("superset_skip_hint || true", read("install.sh"))

    def test_the_superset_hint_for_the_version_guard(self):
        """The iam bootstrap waited: Superset skipped at its version-N guard, and the install
        says to run its deploy once version 1 is applied."""
        for mode in ((), ("--apps-only",)):
            with self.subTest(mode):
                t = Tree(CONFIG + 'IAM_DB_SERVICE_ROLES="true"\n')
                try:
                    os.makedirs(t.path("logs"))
                    with open(t.path("logs", "deploy-apps-20261108-120000.log"), "w") as f:
                        f.write("[superset] skipped: no version of the access policy is applied yet (state empty), "
                                "and Superset deploys only from an applied one: run ./apps/superset/deploy.sh ...\n")
                    p = t.run(*mode)
                    self.assertEqual(p.returncode, 0, p.stderr[-2000:])
                    self.assertIn("Still to do: Superset was skipped, no version of the access policy is applied yet. "
                                  "Once ./apps/iam/deploy.sh has applied version 1", p.stdout)
                    self.assertIn("run ./apps/superset/deploy.sh", p.stdout)
                    self.assertNotIn("it needs IAM_DB_SERVICE_ROLES=true", p.stdout)
                finally:
                    t.close()

    def test_apps_only_says_to_run_deploy_infra_under_true(self):
        """--apps-only runs no infrastructure: under true it names the second deploy-infra the
        full install would run; under false it says nothing about it."""
        for v, want in (("true", True), ("false", False)):
            with self.subTest(v):
                t = Tree(CONFIG + 'IAM_DB_SERVICE_ROLES="%s"\n' % v)
                try:
                    p = t.run("--apps-only")
                    self.assertEqual(p.returncode, 0, p.stderr[-2000:])
                    self.assertEqual([s[0] for s in t.stages()], ["deploy-apps.sh"])
                    line = "./deploy-infra.sh, so Grafana and pgAdmin move onto their own database roles"
                    self.assertEqual(line in p.stdout, want, p.stdout[-1500:])
                finally:
                    t.close()


class WheelCache(unittest.TestCase):
    SRC = read("deploy-infra.sh")

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="medcea-wheelcache-")
        self.bin = os.path.join(self.root, "bin")
        write(os.path.join(self.bin, "sudo"), SUDO)
        write(os.path.join(self.bin, "install"), INSTALL)
        self.pvdir = os.path.join(self.root, "pv")
        os.makedirs(self.pvdir)
        # kubectl: the StorageClass's pvDir
        write(os.path.join(self.bin, "kubectl"),
              '#!/bin/sh\n[ "$1 $2 $3" = "get storageclass microk8s-hostpath" ] && printf %%s "%s"\n' % self.pvdir)
        self.parent = os.path.join(self.root, "var-lib-medcea")
        self.cache = os.path.join(self.parent, "superset-wheels")
        self.sudo_log = os.path.join(self.root, "sudo.log")

    def tearDown(self):
        for dp, dn, _ in os.walk(self.root):
            for d in dn:
                try:
                    os.chmod(os.path.join(dp, d), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.root, ignore_errors=True)

    def run_step(self, wheel_dir, **env):
        script = "\n".join([
            "RED= GREEN= YELLOW= NC=",
            'KUBECTL=kubectl',
            'source "%s"' % os.path.join(REPO, "apps", "superset", "lib-superset.sh"),
            function_text(self.SRC, "_superset_wheel_cache"),
            "_superset_wheel_cache",
        ])
        e = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], STUB_SUDO_LOG=self.sudo_log,
                      SUPERSET_WHEEL_DIR=wheel_dir, PROJECT_NAME="medcea", **env)
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=60,
                              stdin=subprocess.DEVNULL)

    def sudo_calls(self):
        try:
            with open(self.sudo_log) as f:
                return [l.split("\t") for l in f.read().splitlines()]
        except FileNotFoundError:
            return []

    def test_created_mode_700_through_sudo_with_a_prompt_that_says_why(self):
        p = self.run_step(self.cache, STUB_PLAIN_INSTALL_FAILS="1")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        st = os.stat(self.cache)
        self.assertTrue(stat.S_ISDIR(st.st_mode))
        self.assertEqual(st.st_mode & 0o777, 0o700)
        self.assertEqual(st.st_uid, os.getuid())
        calls = self.sudo_calls()
        self.assertEqual(len(calls), 1, calls)
        prompt, cmd = calls[0]
        self.assertEqual(prompt, "[sudo] password for %%u (to create %s for Superset's wheels): " % self.cache)
        self.assertEqual(cmd, "install -d -m 700 -o %d -g %d %s" % (os.getuid(), os.getgid(), self.cache))
        self.assertIn("Superset wheel cache: " + self.cache, p.stdout)

    def test_a_writable_parent_needs_no_sudo_and_an_existing_folder_is_kept(self):
        p = self.run_step(self.cache)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.sudo_calls(), [])
        with open(os.path.join(self.cache, "a.whl"), "w") as f:
            f.write("x")
        os.chmod(self.cache, 0o755)
        p = self.run_step(self.cache, STUB_PLAIN_INSTALL_FAILS="1")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.sudo_calls(), [])
        self.assertEqual(os.stat(self.cache).st_mode & 0o777, 0o700)
        self.assertTrue(os.path.exists(os.path.join(self.cache, "a.whl")))

    def test_refused_inside_or_around_the_volumes_directory(self):
        for d, why in ((os.path.join(self.pvdir, "wheels"), "is inside the volumes' directory"),
                       (self.root, "contains the volumes' directory")):
            with self.subTest(d):
                p = self.run_step(d)
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                self.assertIn("ERROR: SUPERSET_WHEEL_DIR=%s %s %s" % (d, why, self.pvdir), p.stdout)
                self.assertEqual(self.sudo_calls(), [])
        self.assertFalse(os.path.exists(os.path.join(self.pvdir, "wheels")))

    def test_a_bad_path_is_refused(self):
        p = self.run_step("relative/wheels")
        self.assertEqual(p.returncode, 1)
        self.assertIn("must be an absolute path", p.stdout)

    def test_as_root_nothing_is_created(self):
        write(os.path.join(self.bin, "id"),
              '#!/bin/sh\ncase "$1" in -u|-g) echo 0 ;; -un) echo root ;; *) exec /usr/bin/id "$@" ;; esac\n')
        p = self.run_step(self.cache)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("Running as root: Superset's wheel cache is not created here", p.stdout)
        self.assertFalse(os.path.exists(self.cache))
        self.assertEqual(self.sudo_calls(), [])

    def test_a_folder_of_another_owner_is_reported_not_changed(self):
        os.makedirs(self.cache, mode=0o755)
        write(os.path.join(self.bin, "stat"),
              '#!/bin/sh\n[ "$1 $2 $3 $4" = "-L -c %%u %s" ] && { echo 4242; exit 0; }\nexec /usr/bin/stat "$@"\n' % self.cache)
        p = self.run_step(self.cache)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("belongs to uid 4242", p.stdout)
        self.assertEqual(os.stat(self.cache).st_mode & 0o777, 0o755)

    def test_the_step_runs_after_the_bootstrap_and_the_api_wait(self):
        s = self.SRC
        call = s.index("_superset_wheel_cache || exit 1")
        self.assertLess(s.index("bash ./infra/bootstrap-infra.sh"), call)
        self.assertLess(s.index('KUBECTL="$MK8S kubectl"\npolicy_source_init "$NAMESPACE" --precheck'), call)
        self.assertLess(s.index('source "$SCRIPT_DIR/apps/superset/lib-superset.sh"'), call)

    def test_the_check_is_shared_not_copied(self):
        lib = read("apps/superset/lib-superset.sh")
        dep = read("apps/superset/deploy.sh")
        self.assertIn("superset_wheel_dir_ok() {", lib)
        self.assertIn("superset_wheel_owner_ok() {", lib)
        self.assertIn("_wheel_dir_ok() { superset_wheel_dir_ok; }", dep)
        self.assertIn("_wheel_owner_ok() { superset_wheel_owner_ok; }", dep)
        for src in (dep, self.SRC):
            self.assertNotIn("is inside the volumes' directory", src)
            self.assertNotIn("get storageclass microk8s-hostpath", src)
        self.assertIn("superset_wheel_dir_ok ||", function_text(self.SRC, "_superset_wheel_cache"))


class Uninstall(unittest.TestCase):
    def test_uninstall_all_removes_the_cache(self):
        t = Tree(CONFIG)
        try:
            cache = t.path("cache", "superset-wheels")
            with open(t.path("config.env"), "a") as f:
                f.write('SUPERSET_WHEEL_DIR="%s"\n' % cache)
            os.makedirs(cache, mode=0o700)
            for n in ("authlib-1.9.5-py2.py3-none-any.whl", "joserfc-1.7.7-py3-none-any.whl"):
                with open(os.path.join(cache, n), "w") as f:
                    f.write("w")
            # uninstall, keep the CA (none here) and config.env
            rc, out = t.run_pty("--uninstall-all", answers="uninstall\nn\n")
            self.assertEqual(rc, 0, out[-3000:])
            self.assertEqual([s[:2] for s in t.stages()], [["deploy-infra.sh", "--uninstall"]])
            self.assertFalse(os.path.exists(cache))
            self.assertIn("removed Superset's wheel cache " + cache, out)
            # not /var/lib/<project>: the parent of a configured folder elsewhere stays
            self.assertTrue(os.path.isdir(t.path("cache")))
            self.assertIn("Superset's wheel cache (SUPERSET_WHEEL_DIR", out)
        finally:
            t.close()

    def run_fn(self, root, cache):
        """install.sh's remove_wheel_cache with /var/lib/ pointed at ROOT/var/lib/."""
        fn = function_text(read("install.sh"), "remove_wheel_cache").replace('"/var/lib/', '"%s/var/lib/' % root)
        os.makedirs(os.path.join(root, "apps", "superset"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "apps", "superset", "lib-superset.sh"),
                    os.path.join(root, "apps", "superset", "lib-superset.sh"))
        with open(os.path.join(root, "config.env"), "w") as f:
            f.write('PROJECT_NAME=medcea\nSUPERSET_WHEEL_DIR="%s"\n' % cache)
        bin_ = os.path.join(root, "bin")
        write(os.path.join(bin_, "sudo"), SUDO)
        script = "YELLOW= NC=\nSCRIPT_DIR=%s\n%s\nremove_wheel_cache\n" % (root, fn)
        e = clean_env(PATH=bin_ + os.pathsep + os.environ["PATH"], STUB_SUDO_LOG=os.path.join(root, "sudo.log"))
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, cwd=root,
                              timeout=60, stdin=subprocess.DEVNULL)

    def test_the_project_folder_goes_when_left_empty(self):
        root = tempfile.mkdtemp(prefix="medcea-uninstall-")
        try:
            parent = os.path.join(root, "var", "lib", "medcea")
            cache = os.path.join(parent, "superset-wheels")
            os.makedirs(cache)
            with open(os.path.join(cache, "a.whl"), "w") as f:
                f.write("w")
            p = self.run_fn(root, cache)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertFalse(os.path.exists(parent))
            self.assertIn("removed %s (empty)" % parent, p.stdout)
            # the parent with something else in it stays
            os.makedirs(cache)
            os.makedirs(os.path.join(parent, "other"))
            p = self.run_fn(root, cache)
            self.assertFalse(os.path.exists(cache))
            self.assertTrue(os.path.isdir(os.path.join(parent, "other")))
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_a_folder_holding_anything_else_is_kept(self):
        root = tempfile.mkdtemp(prefix="medcea-uninstall-")
        try:
            cache = os.path.join(root, "var", "lib", "medcea", "superset-wheels")
            os.makedirs(cache)
            for n in ("a.whl", "notes.txt"):
                with open(os.path.join(cache, n), "w") as f:
                    f.write("w")
            p = self.run_fn(root, cache)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(os.listdir(cache), ["notes.txt"])
            self.assertIn("kept %s: it holds more than Superset's wheels" % cache, p.stdout)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_sudo_is_asked_with_a_reason_when_the_parent_is_not_writable(self):
        root = tempfile.mkdtemp(prefix="medcea-uninstall-")
        parent = os.path.join(root, "var", "lib", "medcea")
        try:
            cache = os.path.join(parent, "superset-wheels")
            os.makedirs(cache)
            os.chmod(parent, 0o555)
            # the stub sudo cannot gain root: the rmdir it runs fails too, and the uninstall goes on
            p = self.run_fn(root, cache)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            with open(os.path.join(root, "sudo.log")) as f:
                calls = [l.split("\t") for l in f.read().splitlines()]
            self.assertEqual(calls, [["[sudo] password for %%u (to remove Superset's wheel cache %s): " % cache,
                                      "rmdir " + cache]])
            self.assertIn("could not remove " + cache, p.stdout)
        finally:
            os.chmod(parent, 0o755)
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
