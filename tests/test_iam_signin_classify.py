#!/usr/bin/env python3
"""tests/test_iam_signin_classify.py — iam_signin_flow.py's pgAdmin verdicts, offline: no
cluster, no lock, no config.env.

The bodies are pgAdmin 9's login page as render_page.html renders it (dpage/pgadmin4:9):
window.renderSecurityPage(page, page_props|tojson, other_props|tojson), other_props holding
"messages", get_flashed_messages(with_categories=true). pgAdmin's MessageType.ERROR is the
one-element tuple ('Error',), so its claims refusal (authenticate/oauth2.py, flash(msg,
MessageType.ERROR)) is serialised [["Error"], "The user is not authorized ..."], which a
regex expecting a quoted lowercase category never matched. Flask's tojson is compact in
production and escapes ' as \\u0027; both forms are tried.

  python3 tests/test_iam_signin_classify.py
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import iam_signin_flow as flow  # noqa: E402

DOMAIN = "pgadmin.medcea.example.org"
LOGIN = f"https://{DOMAIN}/login?next=%2Fbrowser%2F"
REFUSAL = ("The user is not authorized to login based on your identity profile. "
           "Please contact your administrator.")


def page(messages, compact=True):
    """pgAdmin's login page with these flashed (category, message) pairs, as Flask renders it."""
    seps = (",", ":") if compact else (", ", ": ")
    dump = lambda v: json.dumps(v, separators=seps, sort_keys=True).replace("'", "\\u0027")
    props = dump({"csrfToken": "abc", "loginBanner": "", "oauth2Config": [{"OAUTH2_NAME": "keycloak"}]})
    other = dump({"messages": [[list(c) if isinstance(c, tuple) else c, m] for c, m in messages]})
    return ("<!DOCTYPE html><html><head><title>pgAdmin 4</title></head><body>"
            '<div id="root" style="height: 100%"></div><script>try {require(["security.pages"],'
            f"function() {{window.renderSecurityPage('login.html', {props},\n                {other});}}"
            ");} catch (err) {console.log(err);}</script></body></html>")


class PgadminClassify(unittest.TestCase):
    def verdict(self, body, url=LOGIN, status=200):
        return flow.classify_pgadmin(DOMAIN, status, url, body)

    def test_claims_refusal_with_tuple_category_is_refused(self):
        for compact in (True, False):
            body = page([(("Error",), REFUSAL)], compact)
            self.assertIn('[["Error"],', body.replace(", ", ","))
            self.assertEqual(self.verdict(body), ("refused", ""), compact)

    def test_claims_refusal_found_among_other_messages(self):
        body = page([("Info", "Please log in to access this page."), (("Error",), REFUSAL)])
        self.assertEqual(self.verdict(body), ("refused", ""))

    def test_other_flash_is_an_error_in_pgadmins_words(self):
        msg = "'admin@medcea.invalid' does not appear to be a valid email address."
        outcome, why = self.verdict(page([(("Error",), msg)]))
        self.assertEqual(outcome, "error")
        self.assertIn("pgAdmin refused the sign-in: ", why)
        self.assertIn("does not appear to be a valid email address", why)
        self.assertIn("'admin@medcea.invalid'", why)   # ' decoded, not shown raw

    def test_string_category_still_read(self):
        outcome, why = self.verdict(page([("Warning", "Login session expired. Please try again.")]))
        self.assertEqual(outcome, "error")
        self.assertIn("Login session expired", why)

    def test_no_flash_on_login_page(self):
        outcome, why = self.verdict(page([]))
        self.assertEqual(outcome, "error")
        self.assertIn("without a flashed message", why)

    def test_browser_is_in(self):
        self.assertEqual(self.verdict("<html></html>", f"https://{DOMAIN}/browser/"), ("in", ""))

    def test_flash_on_another_host_is_not_read(self):
        outcome, why = self.verdict(page([(("Error",), REFUSAL)]), "https://kc.example.org/realms/x")
        self.assertEqual(outcome, "error")
        self.assertNotIn("refused the sign-in", why)

    def test_broken_json_is_not_fatal(self):
        self.assertEqual(flow.pgadmin_flashes('{"messages": [[["Error"], "unterminated'), [])


if __name__ == "__main__":
    unittest.main()
