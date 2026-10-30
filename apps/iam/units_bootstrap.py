#!/usr/bin/env python3
"""apps/iam/units_bootstrap.py — the gate of `units.sh assign --bootstrap` (IAM 2.8).

--bootstrap puts a unit in effect before any check, so it is allowed only while nobody
else could ever confirm the assignment: no enabled account holding realm role qa that is
neither the --by account nor the subject, nor another account of either one's person
(rule 5: the checker is never the maker or the subject, by sub or by person_id).

Input on stdin: a JSON list of full UserRepresentations (id, username, enabled,
attributes.person_id), one per direct holder of realm role qa — units.sh reads each by
its id, so a brief representation without attributes cannot reach here. Environment:
BY (the --by account's id), BYP (its person_id, else its id), SUBJ (the subject's id),
SUBP (its person_id, else its id). Prints the username of every account that could
confirm instead, one per line; nothing means --bootstrap is allowed.

Tests: tests/test_units_bootstrap.py (offline).
"""
import json
import os
import sys


def person_of(u):
    """An account's person: its person_id attribute, else its id (the person_id it gets
    on first enable)."""
    pid = ((u.get('attributes') or {}).get('person_id') or [''])[0]
    return (pid or u['id']).lower()


def other_qa(users, by_sub, by_person, subject_sub, subject_person):
    """The usernames of enabled qa accounts that are neither the maker nor the subject,
    by id or by person."""
    skip_ids = {by_sub.lower(), subject_sub.lower()}
    skip_persons = {(by_person or by_sub).lower(), (subject_person or subject_sub).lower()}
    return [u['username'] for u in users
            if u.get('enabled') and u['id'].lower() not in skip_ids and person_of(u) not in skip_persons]


if __name__ == '__main__':
    e = os.environ
    for name in other_qa(json.load(sys.stdin), e['BY'], e.get('BYP', ''), e['SUBJ'], e.get('SUBP', '')):
        print(name)
