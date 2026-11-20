#!/usr/bin/env python3
"""tests/test_domain_dns.py — a domain of your own that never resolved (fresh install on
another server, 20 Nov 2026), offline: scratch directories and fake binaries on PATH, no
cluster, no sudo, no DNS, never the repository's config.env or state/.

  WaitResolve   infra/lib-wait.sh wait_for_http against a fake curl recording its argv:
                a platform name (DOMAIN, or *.DOMAIN) is connected to at PLATFORM_IP
                (--resolve host:443 and :80, or the URL's own port), the CA kept; another
                host, a loopback URL, no DOMAIN or a non-IPv4 PLATFORM_IP get none.
  NamesCheck    infra/lib-dns.sh dns_names_check with a fake getent and tailscale: OK when
                the names resolve to PLATFORM_IP or another own address; otherwise
                DNS_CHECK_TODO names the case: split DNS to this server with nothing on
                port 53 (the affected host), split DNS elsewhere, nothing at all, LOCAL_DNS
                true; a hanging lookup is cut at DNS_CHECK_TIMEOUT and said.
  DomainDns     infra/configure.sh domain_dns, from its own source text, on answers piped
                in: LOCAL_DNS, USE_TAILSCALE and the PLATFORM_IP line for nip.io, the
                project name and a custom domain (split DNS to this server: no question;
                platform/elsewhere × Tailscale/LAN); a hand-set PLATFORM_IP is kept.
  Verdict       install.sh's closing line: "MedCEA is installed." only without a "Problem:"
                line in the newest deploy-infra log and without a failed health check.
  Wiring        deploy-infra.sh runs the check after its DNS section, lists problems
                instead of SUCCESS; config.env.example's PLATFORM_IP line is the one
                configure.sh restores.

  python3 tests/test_domain_dns.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env  # noqa: E402
import test_install  # noqa: E402


def read(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


def write(path, text, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def function_text(src, name):
    """NAME's definition in SRC: a block up to its closing brace at column 0, or one line."""
    m = (re.search(r"^%s\(\) \{\n.*?^\}\n" % re.escape(name), src, re.S | re.M)
         or re.search(r"^%s\(\)\s*\{ .*\}\n" % re.escape(name), src, re.M))
    assert m, name
    return m.group(0)


class Scratch(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="medcea-dns-")
        self.bin = os.path.join(self.d, "bin")
        os.makedirs(self.bin)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def bash(self, script, stdin="", **env):
        e = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], HOME=self.d)
        e.update(env)
        return subprocess.run(["bash", "-c", script], input=stdin, capture_output=True, text=True,
                              env=e, cwd=self.d, timeout=60)


CURL = r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_CURL_LOG"
printf 200
'''


class WaitResolve(Scratch):
    def calls(self, url, domain="medcea.ai", ip="100.103.255.4", ca=True):
        write(os.path.join(self.bin, "curl"), CURL)
        log = os.path.join(self.d, "curl.log")
        if os.path.exists(log):
            os.remove(log)
        if ca:
            write(os.path.join(self.d, ".ca", "ca.crt"), "x", 0o644)
        p = self.bash('source "%s/infra/lib-wait.sh"; REPO_ROOT="%s" DOMAIN="$D" PLATFORM_IP="$I" '
                      'wait_for_http "$U" 5 test' % (REPO, self.d),
                      D=domain, I=ip, U=url, STUB_CURL_LOG=log)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(log) as f:
            return f.read().split("\n")[0].split()

    def test_a_platform_name_goes_to_platform_ip(self):
        argv = self.calls("https://ai-workbench.medcea.ai/hub/login")
        self.assertIn("--resolve", argv)
        self.assertIn("ai-workbench.medcea.ai:443:100.103.255.4", argv)
        self.assertIn("ai-workbench.medcea.ai:80:100.103.255.4", argv)
        self.assertIn("--cacert", argv)
        self.assertEqual(argv[-1], "https://ai-workbench.medcea.ai/hub/login")

    def test_the_bare_domain_case_and_an_explicit_port(self):
        self.assertIn("medcea.ai:443:10.0.0.5", self.calls("https://MEDCEA.ai/", ip="10.0.0.5"))
        argv = self.calls("http://x.medcea.ai:8443/a", ip="10.0.0.5")
        self.assertEqual([a for a in argv if a.startswith("x.medcea.ai:")], ["x.medcea.ai:8443:10.0.0.5"])

    def test_other_hosts_get_none(self):
        for url, kw in (("http://127.0.0.1:8090/", {}),
                        ("https://notmedcea.ai/", {}),
                        ("https://grafana.medcea.ai.evil.example/", {}),
                        ("https://grafana.medcea.ai/", {"domain": ""}),
                        ("https://grafana.medcea.ai/", {"ip": "fd00::1"}),
                        ("https://grafana.medcea.ai/", {"ip": ""})):
            with self.subTest(url=url, **kw):
                self.assertNotIn("--resolve", self.calls(url, **kw))


GETENT = r'''#!/usr/bin/env bash
# getent ahostsv4 NAME: from STUB_GETENT ("name addr" lines); "hang" sleeps
[[ "$1" == ahostsv4 ]] || exit 2
while read -r n a; do
    if [[ "$n" == "$2" ]]; then
        [[ "$a" == hang ]] && exec sleep 30
        printf '%s      STREAM %s\n%s      DGRAM\n' "$a" "$2" "$a"; exit 0
    fi
done <<<"${STUB_GETENT:-}"
exit 2
'''

TAILSCALE = r'''#!/usr/bin/env bash
if [[ "$1 $2" == "ip -4" && -n "${STUB_TS_IP:-}" ]]; then echo "$STUB_TS_IP"; exit 0; fi
[[ "$1 $2" == "dns status" ]] || exit 1
echo "Split DNS Routes:"
[[ -n "${STUB_ROUTE:-}" ]] && echo "  - ${STUB_ROUTE}"
echo "Other:"
'''


IP = r'''#!/usr/bin/env bash
# "ip route get 8.8.8.8": the default route's source address
echo "8.8.8.8 via 192.168.1.1 dev eth0 src ${STUB_LAN_IP:-192.168.1.99} uid 1000"
'''


class NamesCheck(Scratch):
    def check(self, getent, route="", local_dns="false", dnsq_rc=1, timeout="5"):
        write(os.path.join(self.bin, "getent"), GETENT)
        write(os.path.join(self.bin, "tailscale"), TAILSCALE)
        script = ('source "%s/infra/lib-dns.sh"\n'
                  'dns_query() { return "$STUB_DNSQ_RC"; }\n'
                  'dns_names_check medcea.ai 100.103.255.4 portal.medcea.ai keycloak.medcea.ai; '
                  'echo RC=$?\necho "TODO=$DNS_CHECK_TODO"\n' % REPO)
        p = self.bash(script, STUB_GETENT=getent, STUB_ROUTE=route, LOCAL_DNS=local_dns,
                      STUB_DNSQ_RC=str(dnsq_rc), DNS_OWN_ADDRS="192.168.1.99 100.103.255.4",
                      DNS_CHECK_TIMEOUT=timeout)
        self.assertEqual(p.returncode, 0, p.stderr)
        rc = re.search(r"^RC=(\d)$", p.stdout, re.M).group(1)
        todo = re.search(r"^TODO=(.*)$", p.stdout, re.M).group(1)
        return rc, todo, p.stdout

    def test_resolving_to_this_server(self):
        rc, todo, out = self.check("portal.medcea.ai 100.103.255.4\nkeycloak.medcea.ai 192.168.1.99")
        self.assertEqual((rc, todo), ("0", ""))
        self.assertIn("✓ portal.medcea.ai → 100.103.255.4", out)

    def test_split_dns_to_this_server_with_nothing_on_port_53(self):
        """The affected host: the route points here, LOCAL_DNS false, nothing answers."""
        rc, todo, out = self.check("", route="medcea.ai -> 100.103.255.4")
        self.assertEqual(rc, "1")
        self.assertIn("sends 'medcea.ai' to this server (100.103.255.4), but nothing answers DNS on 100.103.255.4:53", todo)
        self.assertIn('set LOCAL_DNS="true" in config.env and run ./deploy-infra.sh', todo)
        self.assertIn("✗ portal.medcea.ai: does not resolve", out)

    def test_a_hung_lookup_is_cut_and_said(self):
        rc, todo, out = self.check("portal.medcea.ai hang\nkeycloak.medcea.ai hang",
                                   route="medcea.ai. -> 100.103.255.4", timeout="1")
        self.assertEqual(rc, "1")
        self.assertIn("did not finish within 1s", out)
        self.assertIn("a lookup hung", todo)
        self.assertIn("nothing answers DNS", todo)

    def test_split_dns_elsewhere_nothing_and_local_dns_true(self):
        rc, todo, _ = self.check("", route="medcea.ai -> 100.64.0.9")
        self.assertIn("to 100.64.0.9, not to this server", todo)
        # every name resolves, to another address (a public address forwarding here):
        # a warning, rc 2, never a problem
        rc, todo, _ = self.check("portal.medcea.ai 203.0.113.7\nkeycloak.medcea.ai 203.0.113.7")
        self.assertEqual(rc, "2")
        self.assertIn("resolves to 203.0.113.7", todo)
        self.assertIn("port forwarding", todo)
        rc, todo, _ = self.check("")
        self.assertEqual(rc, "1")
        self.assertIn('either set LOCAL_DNS="true"', todo)
        self.assertIn("create an A record for every <service>.medcea.ai", todo)
        rc, todo, _ = self.check("", local_dns="true")
        self.assertIn("although LOCAL_DNS is true", todo)
        self.assertIn("files before dns", todo)


class DomainDns(Scratch):
    """domain_dns from configure.sh's own text, with its helpers."""

    def run_dd(self, config, args, answers="", route="", ts_ip="", lan_ip="192.168.1.99"):
        src = read("infra/configure.sh")
        block = src[src.index("PLATFORM_IP_TS_LINE="):src.index("EOF_LAN\n") + len("EOF_LAN\n")]
        funcs = "".join(function_text(src, n) for n in (
            "die", "cfg_get", "cfg_set", "cfg_set_line", "ask", "info", "platform_ip_follow", "domain_dns"))
        write(os.path.join(self.bin, "tailscale"), TAILSCALE)
        write(os.path.join(self.bin, "ip"), IP)
        cfg = os.path.join(self.d, "config.env")
        write(cfg, config, 0o600)
        script = ('RED= YELLOW= GREEN= CYAN= BOLD= NC=\nCONFIG_FILE=config.env\nEXAMPLE_FILE="%s/config.env.example"\n'
                  'source "%s/infra/lib-dns.sh"\n%s%s\ndomain_dns "$@"\n' % (REPO, REPO, funcs, block))
        e = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], HOME=self.d, STUB_ROUTE=route,
                      STUB_TS_IP=ts_ip, STUB_LAN_IP=lan_ip)
        p = subprocess.run(["bash", "-c", script, "configure", *args], input=answers, capture_output=True,
                           text=True, env=e, cwd=self.d, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        with open(cfg) as f:
            lines = f.read().splitlines()
        vals = {l.split("=", 1)[0]: l.split("=", 1)[1] for l in lines if "=" in l and not l.startswith("#")}
        return p.stdout, vals

    TS_LINE = [l for l in read("config.env.example").splitlines() if l.startswith("PLATFORM_IP=")][0]
    BASE = None

    def base(self, **over):
        lines = [self.TS_LINE, 'LOCAL_DNS="false"', 'USE_TAILSCALE=""', 'DOMAIN="x"']
        for k, v in over.items():
            lines = [l for l in lines if not l.startswith(k + "=")] + ["%s=%s" % (k, v)]
        return "\n".join(lines) + "\n"

    def test_custom_domain_split_dns_to_this_server_asks_nothing(self):
        out, v = self.run_dd(self.base(), ["medcea.ai", "", "medcea", "100.103.255.4", "192.168.1.99"],
                             answers="", route="medcea.ai -> 100.103.255.4")
        self.assertEqual((v["LOCAL_DNS"], v["USE_TAILSCALE"]), ('"true"', '"true"'))
        self.assertEqual("PLATFORM_IP=" + v["PLATFORM_IP"], self.TS_LINE)
        self.assertIn("already sends 'medcea.ai' to this server", out)
        self.assertNotIn("Who answers DNS", out)

    def test_custom_domain_answers(self):
        for answers, want_local, want_ts in (("1\n1\n", "true", "true"),
                                             ("\n\n", "true", "true"),        # the defaults
                                             ("1\n2\n", "true", "false"),
                                             ("2\n1\n", "false", "true"),
                                             ("2\n2\n", "false", "false")):
            with self.subTest(answers=answers):
                out, v = self.run_dd(self.base(), ["medcea.ai", "", "medcea", "100.103.255.4", "192.168.1.99"],
                                     answers=answers)
                self.assertIn("Who answers DNS for *.medcea.ai", out)
                self.assertEqual(v["LOCAL_DNS"], '"%s"' % want_local)
                self.assertEqual(v["USE_TAILSCALE"], '"%s"' % want_ts)
                if want_ts == "true":
                    self.assertEqual("PLATFORM_IP=" + v["PLATFORM_IP"], self.TS_LINE)
                else:
                    self.assertIn("ip route get 8.8.8.8", v["PLATFORM_IP"])
                    self.assertNotIn("tailscale", v["PLATFORM_IP"])

    def test_without_tailscale_one_question_and_lan(self):
        out, v = self.run_dd(self.base(), ["lab.example.org", "", "medcea", "", "192.168.1.99"], answers="1\n")
        self.assertEqual((v["LOCAL_DNS"], v["USE_TAILSCALE"]), ('"true"', '"false"'))
        self.assertNotIn("Which address", out)
        self.assertIn("LAN router must send lookups for lab.example.org", out)

    def test_keeping_the_current_domain_defaults_to_its_current_answers(self):
        cfg = self.base(LOCAL_DNS='"false"', USE_TAILSCALE='"false"')
        out, v = self.run_dd(cfg, ["medcea.ai", "medcea.ai", "medcea", "100.103.255.4", "192.168.1.99"], answers="\n\n")
        self.assertEqual((v["LOCAL_DNS"], v["USE_TAILSCALE"]), ('"false"', '"false"'))

    def test_keeping_a_domain_whose_platform_ip_is_tailscale_stays_on_tailscale(self):
        # configure before 21 Nov 2026 wrote USE_TAILSCALE=false for every custom domain
        # while the template line gave the Tailscale address: Enter must keep that address.
        cfg = self.base(LOCAL_DNS='"false"', USE_TAILSCALE='"false"')
        out, v = self.run_dd(cfg, ["medcea.ai", "medcea.ai", "medcea", "100.103.255.4", "192.168.1.99"],
                             answers="\n\n", ts_ip="100.103.255.4")
        self.assertEqual((v["LOCAL_DNS"], v["USE_TAILSCALE"]), ('"false"', '"true"'))
        self.assertEqual("PLATFORM_IP=" + v["PLATFORM_IP"], self.TS_LINE)

    def test_nip_io_and_the_project_name(self):
        _, v = self.run_dd(self.base(), ["100.103.255.4.nip.io", "", "medcea", "100.103.255.4", "192.168.1.99"])
        self.assertEqual((v["LOCAL_DNS"], v["USE_TAILSCALE"]), ('"false"', '"true"'))
        self.assertEqual("PLATFORM_IP=" + v["PLATFORM_IP"], self.TS_LINE)
        _, v = self.run_dd(self.base(), ["192.168.1.99.nip.io", "", "medcea", "100.103.255.4", "192.168.1.99"])
        self.assertEqual((v["LOCAL_DNS"], v["USE_TAILSCALE"]), ('"false"', '"false"'))
        self.assertIn("ip route get", v["PLATFORM_IP"])
        _, v = self.run_dd(self.base(), ["medcea", "", "medcea", "100.103.255.4", "192.168.1.99"])
        self.assertEqual((v["LOCAL_DNS"], v["USE_TAILSCALE"]), ('"true"', '"true"'))

    def test_a_lan_nip_io_name_of_another_address_keeps_the_line(self):
        # two LAN addresses: the nip.io name was made from the one the default route does
        # not use; the LAN line would move PLATFORM_IP (and an expression DOMAIN) off it
        out, v = self.run_dd(self.base(), ["192.168.1.99.nip.io", "", "medcea", "100.103.255.4", "192.168.1.99"],
                             lan_ip="10.0.0.5")
        self.assertEqual(v["USE_TAILSCALE"], '"false"')
        self.assertEqual("PLATFORM_IP=" + v["PLATFORM_IP"], self.TS_LINE)
        self.assertIn("PLATFORM_IP is left as it is", out)

    def test_back_to_tailscale_restores_the_template_line_and_a_hand_set_one_stays(self):
        src = read("infra/configure.sh")
        lan = re.search(r"^PLATFORM_IP=.*ip route get.*$", src, re.M).group(0)
        _, v = self.run_dd(self.base(PLATFORM_IP=lan.split("=", 1)[1]),
                           ["100.103.255.4.nip.io", "", "medcea", "100.103.255.4", "192.168.1.99"])
        self.assertEqual("PLATFORM_IP=" + v["PLATFORM_IP"], self.TS_LINE)
        out, v = self.run_dd(self.base(PLATFORM_IP='"10.1.2.3"'),
                             ["192.168.1.99.nip.io", "", "medcea", "100.103.255.4", "192.168.1.99"])
        self.assertEqual(v["PLATFORM_IP"], '"10.1.2.3"')
        self.assertIn("PLATFORM_IP is set by hand", out)


class DomainNotes(Scratch):
    """configure.sh domain_notes, from its own text: notes only, never a change."""

    def notes(self, config, getent="", ts_ip="100.103.255.4"):
        src = read("infra/configure.sh")
        funcs = "".join(function_text(src, n) for n in ("cfg_get", "domain_notes"))
        for name, text in (("tailscale", TAILSCALE), ("getent", GETENT)):
            write(os.path.join(self.bin, name), text)
        cfg = os.path.join(self.d, "config.env")
        write(cfg, config, 0o600)
        script = ('RED= YELLOW= GREEN= CYAN= BOLD= NC=\nCONFIG_FILE=config.env\n'
                  'source "%s/infra/lib-dns.sh"\n%sdomain_notes\n' % (REPO, funcs))
        p = self.bash(script, STUB_TS_IP=ts_ip, STUB_GETENT=getent, DNS_OWN_ADDRS="192.168.1.99 100.103.255.4")
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(cfg) as f:
            self.assertEqual(f.read(), config)          # never a change
        return p.stdout

    def test_tailscale_address_with_use_tailscale_false(self):
        out = self.notes('DOMAIN="medcea.ai"\nPLATFORM_IP="100.103.255.4"\nUSE_TAILSCALE="false"\n'
                         'LOCAL_DNS="true"\n')
        self.assertIn("PLATFORM_IP is this machine's Tailscale address (100.103.255.4)", out)
        self.assertNotIn("does not resolve", out)

    def test_a_custom_domain_that_does_not_resolve(self):
        out = self.notes('DOMAIN="medcea.ai"\nPLATFORM_IP="192.168.1.99"\nUSE_TAILSCALE="false"\n'
                         'LOCAL_DNS="false"\n')
        self.assertIn("portal.medcea.ai does not resolve to this server", out)
        self.assertNotIn("Tailscale address", out)

    def test_silent_when_all_is_well(self):
        for cfg, getent in (
                ('DOMAIN="192.168.1.99.nip.io"\nPLATFORM_IP="192.168.1.99"\nUSE_TAILSCALE="false"\nLOCAL_DNS="false"\n', ""),
                ('DOMAIN="medcea.ai"\nPLATFORM_IP="192.168.1.99"\nUSE_TAILSCALE="false"\nLOCAL_DNS="true"\n', ""),
                ('DOMAIN="medcea.ai"\nPLATFORM_IP="192.168.1.99"\nUSE_TAILSCALE="false"\nLOCAL_DNS="false"\n',
                 "portal.medcea.ai 192.168.1.99")):
            with self.subTest(cfg=cfg):
                self.assertEqual(self.notes(cfg, getent).strip(), "")


class Verdict(unittest.TestCase):
    def run_install(self, log_text, fail_health=False, mode=()):
        t = test_install.Tree(test_install.CONFIG)
        try:
            if log_text is not None:
                os.makedirs(t.path("logs"))
                with open(t.path("logs", "deploy-infra-20261120-120000.log"), "w") as f:
                    f.write(log_text)
            env = {"STUB_FAIL": "health-check.sh:1"} if fail_health else {}
            return t.run(*mode, **env)
        finally:
            t.close()

    def test_clean(self):
        for log in (None, " SUCCESS: medcea is live!\n"):
            p = self.run_install(log)
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            self.assertIn("MedCEA is installed.", p.stdout)
            self.assertNotIn("Finished with problems", p.stdout)

    def test_a_problem_line_or_a_failed_health_check(self):
        log = ("\x1b[0;31m FINISHED WITH PROBLEMS: medcea is deployed, but\x1b[0m\n"
               "\x1b[0;31mProblem: *.medcea.ai does not resolve to this server (100.103.255.4): either set "
               "LOCAL_DNS=\"true\"\x1b[0m\n")
        p = self.run_install(log)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertNotIn("MedCEA is installed.", p.stdout)
        self.assertIn("Finished with problems.", p.stdout)
        self.assertIn('Still to do: *.medcea.ai does not resolve to this server (100.103.255.4): either set LOCAL_DNS="true"',
                      p.stdout)
        p = self.run_install(None, fail_health=True)
        self.assertNotIn("MedCEA is installed.", p.stdout)
        self.assertIn("Still to do: the health check found failures", p.stdout)

    def test_infra_only_lists_them(self):
        p = self.run_install("Problem: the AI workbench failed to deploy (exit 1, output above)\n", mode=("--infra-only",))
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertIn("Still to do: the AI workbench failed to deploy", p.stdout)


class Wiring(unittest.TestCase):
    def test_deploy_infra(self):
        s = read("deploy-infra.sh")
        dns = s.index("# NAME-BASED DOMAIN (LOCAL_DNS=true)")
        check = s.index('dns_names_check "$DOMAIN" "$PLATFORM_IP" "$PORTAL_DOMAIN" "$KEYCLOAK_DOMAIN"')
        self.assertLess(dns, check)
        self.assertLess(check, s.index("[1/10] Deploying Postgres"))
        self.assertIn('_PROBLEMS+=("$DNS_CHECK_TODO")', s)
        self.assertIn('echo -e "${RED}Problem: ${_p}${NC}"', s)
        self.assertIn("FINISHED WITH PROBLEMS", s)
        self.assertIn('if [[ ${#_PROBLEMS[@]} -eq 0 ]]; then', s)

    def test_configure_restores_the_template_line(self):
        src = read("infra/configure.sh")
        self.assertIn("PLATFORM_IP_TS_LINE=\"$(grep -m1 '^PLATFORM_IP=' \"$EXAMPLE_FILE\")\"", src)
        ex = [l for l in read("config.env.example").splitlines() if l.startswith("PLATFORM_IP=")]
        self.assertEqual(len(ex), 1)
        self.assertIn("tailscale ip -4", ex[0])

    def test_the_report_checks_use_the_same_address(self):
        s = read("apps/report/deploy.sh")
        self.assertIn('platform_resolve "$GRAFANA_URL"; CA_ARGS+=("${resolve[@]}")', s)
        self.assertLess(s.index("lib-wait.sh"), s.index('platform_resolve "$GRAFANA_URL"'))

    def test_lookups_are_bounded(self):
        s = read("infra/lib-dns.sh")
        self.assertIn('timeout "$t" getent ahostsv4', s)
        self.assertIn("timeout 5 tailscale dns status", s)


if __name__ == "__main__":
    unittest.main()
