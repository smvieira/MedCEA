"""tests/test_keycloak_clients.py — deploy-infra.sh's Keycloak clients, rendered offline.

deploy-infra.sh's _create_client is run from its own source text in bash, against a fake
curl that records every request body, so the redirect and post-logout URIs it registers are
read from what Keycloak would receive, not from a regex over the call. Nothing reaches a
cluster or Keycloak; no access policy is compiled.

  ClientBodies   Superset's client (stage C, F2/N4): the origin is stripped of
                 /oauth-authorized/*, both return addresses of superset_logout_return are
                 registered, the secret is read back (never rotated); every other client's
                 origin is what it was
  Scopes         every confidential client deploy-infra creates is in the groups/
                 medcea-identity scope loop, superset included
  Domains        SUPERSET_DOMAIN (default superset.$DOMAIN) is in _SVC_DOMAINS: the
                 certificate's SANs, the hosts block and the alias redirects
  Config         SUPERSET_CLIENT_SECRET is upserted into config.env and in config.env.example;
                 every secret is written through _config_env_set (awk's environment, never argv)
  InstallHint    install.sh's "Still to do" line names IAM_DB_SERVICE_ROLES when the newest
                 deploy-apps log holds Superset's skip for it, and says nothing otherwise
  PolicyTokenClients  research Phase 2b (D2): KC_POLICY_TOKEN_CLIENTS is workbench-notebook and
                 the two lists keep it, in their order; deploy-infra creates (or brings back) it
                 only while `cli.py has-token-client` says 0, disables an existing one by
                 read-modify-write when it says 1 (a missing one is never created), changes
                 nothing when the policy cannot be read; kc_client_disable PUTs back exactly what
                 it read but enabled (serviceAccountsEnabled as read), says absent or
                 already-disabled without a write, and fails on a refused PUT; deploy-infra
                 reports deploy-workbench's exit 4 as "Still to do", not as a failure

    python3 tests/test_keycloak_clients.py
"""
import json
import os
import re
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAINS = dict(DOMAIN="medcea", SUPERSET_DOMAIN="superset.medcea", PORTAL_DOMAIN="portal.medcea",
               WORKBENCH_DOMAIN="ai-workbench.medcea", GRAFANA_DOMAIN="grafana.medcea",
               NODE_RED_DOMAIN="node-red.medcea", PGADMIN_DOMAIN="pgadmin.medcea",
               CONFIG_DOMAIN="config.medcea", POLICY_DOMAIN="policy.medcea", ACCESS_DOMAIN="access.medcea",
               MONITOR_DOMAIN="monitor.medcea", SCHEDULER_DOMAIN="scheduler.medcea",
               DBMGMT_DOMAIN="dbmgmt.medcea", MQTTX_DOMAIN="mqtt-explorer.medcea", KEYCLOAK_REALM="medcea")


def read(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


SRC = read("deploy-infra.sh")


def function_text(name):
    """The shell function NAME as deploy-infra.sh defines it (up to its closing brace)."""
    m = re.search(r"^%s\(\) \{\n.*?^\}\n" % re.escape(name), SRC, re.S | re.M)
    return m.group(0)


def client_call(client):
    """deploy-infra.sh's $(_create_client "CLIENT" …) call, continuation lines joined."""
    m = re.search(r'\$\((_create_client "%s" (?:[^()]|\\\n)*?)\)' % re.escape(client), SRC)
    return m.group(1).replace("\\\n", " ")


# A fake curl: records METHOD URL BODY (one JSON line per call) and answers the two reads
# _create_client makes (the client's UUID, its secret).
FAKE_CURL = r'''
curl() {
    local m=GET url="" body="" a
    while (( $# )); do
        case "$1" in
            -X) m="$2"; shift ;;
            -d|--data|--data-binary) body="$2"; shift ;;
            -H|-o) shift ;;
            http*) url="$1" ;;
        esac
        shift
    done
    python3 -c 'import json, sys; print(json.dumps({"m": sys.argv[1], "url": sys.argv[2], "body": sys.argv[3]}))' \
        "$m" "$url" "$body" >>"$CURL_LOG"
    case "$m $url" in
        "GET "*"/clients?clientId="*) echo '[{"id": "uuid-1"}]' ;;
        "GET "*"/client-secret") echo '{"type": "secret", "value": "read-back-secret"}' ;;
    esac
}
_kc_token() { echo token; }
'''


def run_client(call, **env):
    """Runs CALL (a deploy-infra _create_client call) → (secret printed, the POST and PUT bodies)."""
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "curl.log")
        script = (FAKE_CURL + function_text("_create_client")
                  + '_HUB_LOGOUT_URI="https://${WORKBENCH_DOMAIN}/hub/logout"\n'
                  + 'printf "%%s" "$(%s)"\n' % call)
        e = dict(os.environ, CURL_LOG=log, **DOMAINS)
        e.update(env)
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, check=True).stdout
        with open(log) as f:
            calls = [json.loads(line) for line in f]
    writes = [json.loads(c["body"]) for c in calls if c["m"] in ("POST", "PUT")]
    return out, writes, calls


def matches(pattern, uri):
    """Keycloak's redirect URI rule for these clients: a trailing /* is a prefix, else exact."""
    return uri.startswith(pattern[:-1]) if pattern.endswith("/*") else uri == pattern


class ClientBodies(unittest.TestCase):

    def test_superset(self):
        out, writes, calls = run_client(client_call("superset"))
        self.assertEqual(out, "read-back-secret")
        # POST (409 for an existing client) and the PUT that re-applies the URIs, same body
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[0], writes[1])
        body = writes[0]
        self.assertEqual(body["clientId"], "superset")
        self.assertIs(body["serviceAccountsEnabled"], False)
        self.assertEqual(body["redirectUris"], ["https://superset.medcea/oauth-authorized/keycloak",
                                                "https://superset.medcea/_account/*"])
        post = body["attributes"]["post.logout.redirect.uris"].split("##")
        self.assertEqual(post, ["https://superset.medcea/*", "https://ai-workbench.medcea/hub/logout",
                                "https://portal.medcea/*"])
        # the secret is read back, never regenerated (no POST to client-secret)
        self.assertFalse([c for c in calls if c["url"].endswith("/client-secret") and c["m"] != "GET"])

    def test_superset_logout_return_is_registered_either_way(self):
        _, writes, _ = run_client(client_call("superset"))
        post = writes[0]["attributes"]["post.logout.redirect.uris"].split("##")
        lib = os.path.join(REPO, "infra", "lib-oauth2-proxy.sh")
        seen = set()
        for wb in ("true", "false"):
            uri = subprocess.run(["bash", "-c", 'source "$0"; superset_logout_return', lib],
                                 capture_output=True, text=True, check=True,
                                 env=dict(os.environ, WORKBENCH_ENABLED=wb, **DOMAINS)).stdout.strip()
            self.assertTrue(uri.startswith("https://"), uri)
            self.assertTrue(any(matches(p, uri) for p in post), (wb, uri, post))
            seen.add(uri)
        self.assertEqual(seen, {"https://ai-workbench.medcea/hub/logout",
                                "https://portal.medcea/oauth2/sign_out?rd=%2F"})

    def test_other_origins_unchanged(self):
        """The /oauth-authorized/ strip moves no other client's origin."""
        for client, origin in (("grafana", "https://grafana.medcea"), ("workbench", "https://ai-workbench.medcea"),
                               ("portal", "https://portal.medcea"), ("node-red", "https://node-red.medcea"),
                               ("pgadmin", "https://pgadmin.medcea"), ("policy", "https://policy.medcea")):
            with self.subTest(client):
                _, writes, _ = run_client(client_call(client))
                self.assertEqual(writes[0]["redirectUris"][1], origin + "/_account/*")
                self.assertEqual(writes[0]["attributes"]["post.logout.redirect.uris"].split("##")[0], origin + "/*")


def lib_array(name):
    """An array of infra/lib-keycloak-clients.sh, as bash reads it (Phase 5, G2)."""
    p = subprocess.run(["bash", "-c", 'source "$1"; printf "%s\\n" "${' + name + '[@]}"', "_",
                        os.path.join(REPO, "infra", "lib-keycloak-clients.sh")],
                       capture_output=True, text=True, check=True)
    return p.stdout.split()


class Scopes(unittest.TestCase):

    def test_every_client_gets_the_groups_scope(self):
        self.assertRegex(SRC, r'(?m)^    for _c in "\$\{KC_SCOPE_CLIENTS\[@\]\}"; do$')
        loop = lib_array("KC_SCOPE_CLIENTS")
        self.assertIn("superset", loop)
        made = set(re.findall(r'_create_client(?:_multi)? "([a-z-]+)"', SRC))
        made |= set(re.findall(r'_create_public_device_client "([a-z-]+)"', SRC))
        self.assertIn("superset", made)
        self.assertEqual(made - set(loop), set())


class SharedClientList(unittest.TestCase):
    """Phase 5 (G2): deploy-infra.sh's scope loop and health-check.sh's kcscopes read one list,
    infra/lib-keycloak-clients.sh; the loop's clients and their order are what they were."""

    BEFORE = ("portal access policy config monitor scheduler dbmgmt mqtt-explorer pgadmin edge-wizard node-red "
              "workbench grafana superset workbench-notebook").split()

    def test_the_loop_is_unchanged(self):
        self.assertEqual(lib_array("KC_SCOPE_CLIENTS"), self.BEFORE)

    def test_deploy_infra_sources_it_before_the_loop(self):
        src = SRC.index('source "$SCRIPT_DIR/infra/lib-keycloak-clients.sh"')
        loop = SRC.index('for _c in "${KC_SCOPE_CLIENTS[@]}"; do')
        self.assertLess(src, loop)
        self.assertNotRegex(SRC, r"for _c in portal access ")

    def test_health_check_reads_the_same_list(self):
        hc = read("health-check.sh")
        body = re.search(r"(?ms)^check_kcscopes\(\) \{.*?^\}", hc).group(0)
        self.assertIn('source "$SCRIPT_DIR/infra/lib-keycloak-clients.sh"', body)
        self.assertIn('"${KC_SCOPE_CLIENTS[*]}"', body)
        self.assertIn('"${KC_API_CLIENTS[*]}"', body)
        self.assertNotRegex(body, r"\bportal access\b")
        conf = read("health-checks.conf")
        self.assertRegex(conf, r"(?m)^Keycloak client scopes\s*\| kcscopes \| \$KEYCLOAK_REALM\s*\|")

    def test_api_clients(self):
        """KC_API_CLIENTS: every HOST_CLIENTS client of the access deploy, every token client of
        config-api, the edge wizard; the rest of the loop signs people in to a tool only."""
        loop, api = lib_array("KC_SCOPE_CLIENTS"), lib_array("KC_API_CLIENTS")
        self.assertLessEqual(set(api), set(loop))
        dep = read("apps/access/deploy.sh")
        hosts = set(re.findall(r"=([a-z-]+)(?:[,\"])", "".join(l for l in dep.splitlines() if l.startswith("HOST_CLIENTS"))))
        self.assertTrue(hosts)
        self.assertLessEqual(hosts, set(api))
        import sys
        sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
        from compiler import grants, model
        self.assertLessEqual(set(grants.token_clients(model.load_defaults())), set(api))
        self.assertEqual(set(loop) - set(api), {"pgadmin", "node-red", "workbench", "grafana", "superset"})


class Domains(unittest.TestCase):

    def svc_domains(self, **env):
        start = SRC.index("_SVC_DOMAINS=()")
        block = SRC[start:SRC.index("\ndone\n", start) + 6]
        e = {k: v for k, v in os.environ.items() if not k.endswith("_DOMAIN")}
        e.update(env)
        out = subprocess.run(["bash", "-c", block + 'printf "%s\\n" "${_SVC_DOMAINS[@]}"'],
                             capture_output=True, text=True, env=e, check=True).stdout
        return out.split()

    def test_superset_is_a_san(self):
        self.assertIn("superset.medcea", self.svc_domains(DOMAIN="medcea"))          # the default
        self.assertIn("bi.example.org", self.svc_domains(DOMAIN="medcea", SUPERSET_DOMAIN="bi.example.org"))


class Config(unittest.TestCase):

    def test_secret_upserted(self):
        self.assertIn('"SUPERSET_CLIENT_SECRET=${_SUPERSET_SECRET}"', SRC)
        self.assertLess(SRC.index('_SUPERSET_SECRET=$(_create_client "superset"'),
                        SRC.index('"SUPERSET_CLIENT_SECRET=${_SUPERSET_SECRET}"'))
        self.assertEqual(re.findall(r"^SUPERSET_CLIENT_SECRET=.*$", read("config.env.example"), re.M),
                         ['SUPERSET_CLIENT_SECRET=""'])


    def test_secrets_never_in_argv(self):
        """config.env's client secrets go to awk in its environment, never as a sed argument."""
        for line in SRC.splitlines():
            if re.match(r"\s*sed -i", line):
                self.assertNotRegex(line, r"SECRET|_kv|PASS", line)
        with tempfile.TemporaryDirectory() as d:
            secret = "s3cr|et&\\x"
            conf = os.path.join(d, "config.env")
            with open(conf, "w") as f:
                f.write('A="1"\nSUPERSET_CLIENT_SECRET=""\nSUPERSET_CLIENT_SECRET_X="keep"\nB="2"\n')
            os.chmod(conf, 0o640)
            # an awk on PATH that records its argv, then runs the real one
            real = subprocess.run(["bash", "-c", "command -v awk"], capture_output=True, text=True).stdout.strip()
            spy = os.path.join(d, "bin")
            os.mkdir(spy)
            with open(os.path.join(spy, "awk"), "w") as f:
                f.write('#!/bin/bash\nprintf "%%s\\n" "$@" >>"$ARGV_LOG"\nexec %s "$@"\n' % real)
            os.chmod(os.path.join(spy, "awk"), 0o755)
            log = os.path.join(d, "argv.log")
            for key in ("SUPERSET_CLIENT_SECRET", "ABSENT_SECRET"):
                r = subprocess.run(["bash", "-c", "RED= NC=\n" + function_text("_config_env_set")
                                    + '_config_env_set "$1" "$2"', "x", key, secret],
                                   capture_output=True, text=True, cwd=d,
                                   env=dict(os.environ, PATH=spy + ":" + os.environ["PATH"], ARGV_LOG=log))
                self.assertEqual(r.returncode, 0, r.stderr)
            with open(conf) as f:
                self.assertEqual(f.read(), 'A="1"\nSUPERSET_CLIENT_SECRET="%s"\nSUPERSET_CLIENT_SECRET_X="keep"\n'
                                           'B="2"\n' % secret)   # an absent key adds nothing, as sed did
            self.assertEqual(os.stat(conf).st_mode & 0o777, 0o640)
            with open(log) as f:
                self.assertNotIn(secret, f.read())
            self.assertEqual(sorted(os.listdir(d)), ["argv.log", "bin", "config.env"])   # no temporary left


class InstallHint(unittest.TestCase):

    def hint(self, log_text):
        src = read("install.sh")
        fn = re.search(r"^superset_skip_hint\(\) \{\n.*?^\}\n", src, re.S | re.M).group(0)
        with tempfile.TemporaryDirectory() as d:
            if log_text is not None:
                os.mkdir(os.path.join(d, "logs"))
                with open(os.path.join(d, "logs", "deploy-apps-20261107-000000.log"), "w") as f:
                    f.write(log_text)
            r = subprocess.run(["bash", "-c", "YELLOW= NC=\n" + fn + "superset_skip_hint"],
                               capture_output=True, text=True, cwd=d)
        self.assertEqual(r.returncode, 0)
        return r.stdout

    def test_named_only_after_that_skip(self):
        # the line apps/superset/deploy.sh logs (plan A2b)
        out = self.hint("[superset] skipped: Superset needs IAM_DB_SERVICE_ROLES=true (its data connection is svc_superset)\n")
        self.assertIn("Still to do: Superset was skipped, it needs IAM_DB_SERVICE_ROLES=true", out)
        self.assertEqual(self.hint("[superset] skipped: Superset is not in the applied access policy\n"), "")
        self.assertEqual(self.hint(None), "")


# a fake curl for the token clients: records METHOD URL BODY (the body read from stdin for
# --data-binary @-), answers the client list from $KC_EXISTS (1: present) and the client's
# representation from $KC_REP, prints -w's code ($KC_PUT_CODE for a PUT, else 200/201)
TC_CURL = r'''
curl() {
    local m=GET url="" body="" w="" a
    while (( $# )); do
        case "$1" in
            -X) m="$2"; shift ;;
            -d|--data) body="$2"; shift ;;
            --data-binary) [[ "$2" == "@-" ]] && body="$(cat)" || body="$2"; shift ;;
            -w) w=1; shift ;;
            -H|-o) shift ;;
            http*) url="$1" ;;
        esac
        shift
    done
    python3 -c 'import json, sys; print(json.dumps({"m": sys.argv[1], "url": sys.argv[2], "body": sys.argv[3]}))' \
        "$m" "$url" "$body" >>"$CURL_LOG"
    case "$m $url" in
        "GET "*"/clients?clientId="*) if [[ "$KC_EXISTS" == 1 ]]; then echo "[{\"id\": \"uuid-1\", \"clientId\": \"${url##*clientId=}\"}]"; else echo '[]'; fi ;;
        "GET "*"/clients/uuid-1") printf '%s' "$KC_REP" ;;
        "PUT "*) [[ -n "$w" ]] && printf '%s' "${KC_PUT_CODE:-204}" ;;
        *) [[ -n "$w" ]] && printf 201 ;;
    esac
}
'''
REP = {"id": "uuid-1", "clientId": "workbench-notebook", "enabled": True, "publicClient": True,
       "serviceAccountsEnabled": False, "standardFlowEnabled": False,
       "attributes": {"oauth2.device.authorization.grant.enabled": "true"}, "redirectUris": []}


def token_client_block():
    """deploy-infra.sh's loop over KC_POLICY_TOKEN_CLIENTS (up to its done)"""
    i = SRC.index('for _c in "${KC_POLICY_TOKEN_CLIENTS[@]}"; do')
    return SRC[i:SRC.index("\ndone\n", i) + 6]


class PolicyTokenClients(unittest.TestCase):

    def test_the_lists(self):
        self.assertEqual(lib_array("KC_POLICY_TOKEN_CLIENTS"), ["workbench-notebook"])
        self.assertIn("workbench-notebook", lib_array("KC_SCOPE_CLIENTS"))
        self.assertIn("workbench-notebook", lib_array("KC_API_CLIENTS"))

    def run_block(self, cli_rc, exists, rep=None, put_code="204"):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "curl.log")
            os.makedirs(os.path.join(d, "apps", "iam", "compiler"))
            with open(os.path.join(d, "apps", "iam", "compiler", "cli.py"), "w") as f:
                f.write("import sys\nopen(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')\nsys.exit(%d)\n"
                        % (os.path.join(d, "cli.log"), cli_rc))
            script = ("RED= YELLOW= NC=\n" + TC_CURL + function_text("_create_public_device_client")
                      + 'source "$LIB/infra/lib-keycloak-admin.sh"\nsource "$LIB/infra/lib-keycloak-clients.sh"\n'
                      + "kc_admin_token() { echo tok; }\n_kc_token() { echo tok; }\n" + token_client_block())
            e = dict(os.environ, CURL_LOG=log, KEYCLOAK_REALM="medcea", SCRIPT_DIR=d, LIB=REPO, KC_EXISTS=exists,
                     KC_REP=json.dumps(rep or REP), KC_PUT_CODE=put_code)
            r = subprocess.run(["bash", "-c", "set -e\n" + script], capture_output=True, text=True, env=e)
            calls = []
            if os.path.exists(log):
                with open(log) as f:
                    calls = [json.loads(line) for line in f]
            with open(os.path.join(d, "cli.log")) as f:
                asked = f.read()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(asked, "has-token-client workbench-notebook\n")
        return r, calls

    def test_named_by_the_policy_it_is_created(self):
        r, calls = self.run_block(0, "1")
        writes = [c for c in calls if c["m"] in ("POST", "PUT")]
        self.assertEqual([c["m"] for c in writes], ["POST", "PUT"])
        body = json.loads(writes[0]["body"])
        self.assertEqual((body["clientId"], body["enabled"], body["publicClient"]), ("workbench-notebook", True, True))
        self.assertEqual(body["attributes"], {"oauth2.device.authorization.grant.enabled": "true"})
        self.assertIn("Creating public client 'workbench-notebook'", r.stdout)

    def test_not_named_an_existing_one_is_disabled(self):
        r, calls = self.run_block(1, "1")
        self.assertFalse([c for c in calls if c["m"] == "POST"], "never created")
        puts = [c for c in calls if c["m"] == "PUT"]
        self.assertEqual(len(puts), 1)
        self.assertTrue(puts[0]["url"].endswith("/admin/realms/medcea/clients/uuid-1"))
        self.assertEqual(json.loads(puts[0]["body"]), dict(REP, enabled=False))   # read-modify-write
        self.assertIn("not in the access policy any more, disabled", r.stdout)
        self.assertFalse([c for c in calls if c["m"] == "DELETE"])

    def test_not_named_a_fresh_install_creates_nothing(self):
        r, calls = self.run_block(1, "0")
        self.assertEqual([c["m"] for c in calls], ["GET"])
        self.assertIn("not in the access policy, not created", r.stdout)

    def test_already_disabled_writes_nothing(self):
        r, calls = self.run_block(1, "1", rep=dict(REP, enabled=False))
        self.assertFalse([c for c in calls if c["m"] != "GET"])
        self.assertIn("not in the access policy, disabled", r.stdout)

    def test_a_refused_put_is_a_warning(self):
        r, calls = self.run_block(1, "1", put_code="403")
        self.assertIn("could not be disabled", r.stderr)
        self.assertIn("HTTP 403", r.stderr)

    def test_a_broken_policy_changes_nothing(self):
        r, calls = self.run_block(2, "1")
        self.assertEqual(calls, [])
        self.assertIn("cannot tell whether the access policy names client 'workbench-notebook'", r.stderr)

    def test_the_old_unconditional_create_is_gone(self):
        code = "\n".join(l for l in SRC.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(code, r'(?m)^_create_public_device_client "workbench-notebook"')
        self.assertLess(SRC.index('source "$SCRIPT_DIR/infra/lib-keycloak-clients.sh"'), SRC.index(token_client_block()))


class WorkbenchStillToDo(unittest.TestCase):
    """deploy-infra's workbench section: exit 4 of deploy-workbench is a step still to do"""

    def section(self):
        i = SRC.index('    _WB_OUT="$(mktemp)"')
        return SRC[i:SRC.index('    rm -f "$_WB_OUT"\n', i) + len('    rm -f "$_WB_OUT"\n')]

    def run_section(self, rc, line):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "infra"))
            stub = os.path.join(d, "infra", "deploy-workbench.sh")
            with open(stub, "w") as f:
                f.write(f'#!/bin/bash\necho -e "\\033[0;32m[workbench]\\033[0m {line}"\nexit {rc}\n')
            os.chmod(stub, 0o755)
            r = subprocess.run(["bash", "-c", "set -e\nRED= YELLOW= NC=\nexec 9>/dev/null\n" + self.section() + "echo END"],
                               capture_output=True, text=True, env=dict(os.environ, SCRIPT_DIR=d))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.rstrip().endswith("END"))
        return r

    def test_exit_4(self):
        for line in ("the AI workbench moves with ./infra/deploy-workbench.sh --move",
                     "the AI workbench moves back with ./infra/deploy-workbench.sh --move"):
            r = self.run_section(4, line)
            self.assertIn("Still to do: " + line, r.stdout)
            self.assertNotIn("failed", r.stdout + r.stderr)

    def test_other_exits(self):
        r = self.run_section(1, "boom")
        self.assertIn("The workbench failed to deploy", r.stdout)
        r = self.run_section(0, "fine")
        self.assertNotIn("Still to do", r.stdout)
        self.assertNotIn("failed", r.stdout)


if __name__ == "__main__":
    unittest.main()
