#!/usr/bin/env python3
"""IAM 2.8, offline: the gate of `apps/iam/units.sh assign --bootstrap`.

--bootstrap puts a unit in effect before any check, so it is allowed only while no
enabled qa account other than the --by account and the subject — by id or by person —
could confirm it. apps/iam/units_bootstrap.py is that filter; units.sh feeds it each
qa holder's full representation, read by id. Canned Keycloak JSON, no cluster.

Run: python3 tests/test_units_bootstrap.py
"""
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'apps', 'iam', 'units_bootstrap.py')
sys.path.insert(0, os.path.join(ROOT, 'apps', 'iam'))
import units_bootstrap as UB  # noqa: E402

BY = '11111111-1111-1111-1111-111111111111'        # svieira (qa), runs units.sh
SUBJ = '22222222-2222-2222-2222-222222222222'      # op2, the subject
OTHER = '33333333-3333-3333-3333-333333333333'     # another qa person
ALT = '44444444-4444-4444-4444-444444444444'       # a second account


def user(uid, name, enabled=True, person=None):
    u = {'id': uid, 'username': name, 'enabled': enabled}
    if person is not None:
        u['attributes'] = {'person_id': [person]}
    return u


def run(users, by=BY, byp=BY, subj=SUBJ, subp=SUBJ):
    """The script as units.sh runs it: JSON on stdin, ids in the environment."""
    env = dict(os.environ, BY=by, BYP=byp, SUBJ=subj, SUBP=subp)
    p = subprocess.run([sys.executable, SCRIPT], input=json.dumps(users), env=env,
                       capture_output=True, text=True, check=True)
    return p.stdout.split()


class Gate(unittest.TestCase):
    def test_no_other_qa_allows(self):
        self.assertEqual(run([user(BY, 'svieira', person=BY)]), [])
        self.assertEqual(run([]), [])

    def test_another_enabled_qa_refuses_and_is_named(self):
        self.assertEqual(run([user(BY, 'svieira', person=BY), user(OTHER, 'qa2', person=OTHER)]), ['qa2'])

    def test_another_qa_without_person_id_counts(self):
        # no person_id yet: the account is its own person
        self.assertEqual(run([user(OTHER, 'qa2')]), ['qa2'])

    def test_disabled_qa_allows(self):
        self.assertEqual(run([user(OTHER, 'qa2', enabled=False, person=OTHER)]), [])

    def test_by_and_subject_accounts_do_not_count(self):
        self.assertEqual(run([user(BY, 'svieira'), user(SUBJ, 'op2')]), [])

    def test_same_person_as_by_does_not_count(self):
        # sergio_qa: a second account of the --by person (person_id = svieira's sub)
        self.assertEqual(run([user(ALT, 'sergio_qa', person=BY)]), [])
        # the --by account's person_id differs from its id: matched by person, not id
        self.assertEqual(run([user(ALT, 'sergio_qa', person='p-sergio')], byp='p-sergio'), [])

    def test_same_person_as_subject_does_not_count(self):
        self.assertEqual(run([user(ALT, 'op2_qa', person='p-op2')], subp='p-op2'), [])

    def test_compares_ids_not_usernames_and_ignores_case(self):
        # an account whose username looks like the --by id is still someone else
        self.assertEqual(run([user(OTHER, BY, person=OTHER)]), [BY])
        self.assertEqual(run([user(BY.upper(), 'svieira')]), [])
        self.assertEqual(run([user(ALT, 'sergio_qa', person=BY.upper())]), [])

    def test_empty_person_env_falls_back_to_the_id(self):
        self.assertEqual(UB.other_qa([user(ALT, 'x', person=BY)], BY, '', SUBJ, ''), [])
        self.assertEqual(UB.other_qa([user(ALT, 'x', person=SUBJ)], BY, '', SUBJ, ''), [])


class Wiring(unittest.TestCase):
    """units.sh reads every qa holder in full by id (person_id in its attributes, whatever
    the role listing returns) and refuses with exit 2 naming who could confirm."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, 'apps', 'iam', 'units.sh')) as f:
            cls.src = f.read()
        cls.gate = cls.src[cls.src.index('if [[ "$BOOTSTRAP" == true ]]; then'):cls.src.index('ASSIGN=false;')]

    def test_reads_each_holder_by_id(self):
        self.assertIn('roles/qa/users', self.gate)
        self.assertIn('kc_ok "realms/$R/users/$_q"', self.gate)
        self.assertNotIn('briefRepresentation', self.gate)

    def test_runs_the_filter_with_by_and_subject(self):
        self.assertIn('python3 apps/iam/units_bootstrap.py', self.gate)
        for env in ('BY="$BY_SUB"', 'BYP="$BY_PID"', 'SUBJ="$SUB"', 'SUBP="${PID:-$SUB}"'):
            self.assertIn(env, self.gate)

    def test_refuses_with_exit_2_naming_them(self):
        self.assertTrue(re.search(r'die 2 "--bootstrap refused: .*\$_others', self.gate))

    def test_gate_runs_before_the_write(self):
        self.assertLess(self.src.index('if [[ "$BOOTSTRAP" == true ]]; then'),
                        self.src.index('-f - < apps/iam/units.sql'))


if __name__ == '__main__':
    unittest.main()
