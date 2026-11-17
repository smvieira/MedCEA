"""The research sandbox's virtualenv: pinned, hash-checked, gitignored.

Offline: reads research/requirements.txt, research/lib-venv.sh and
.gitignore, and runs `bash -n` on the script. It never builds the venv.
"""

import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQ = os.path.join(ROOT, "research", "requirements.txt")
LIB = os.path.join(ROOT, "research", "lib-venv.sh")

# name==version --hash=sha256:<64 hex>, nothing else on the line.
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.]*) "
                 r"--hash=sha256:([0-9a-f]{64})$")

EXPECTED = {"gekko", "networkx", "numpy", "packaging", "pyyaml", "scikit-fuzzy", "scipy"}


def _requirement_lines():
    with open(REQ, encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")]


class Requirements(unittest.TestCase):
    def test_every_line_is_pinned_with_a_sha256(self):
        lines = _requirement_lines()
        self.assertTrue(lines)
        for ln in lines:
            self.assertRegex(ln, PIN)

    def test_the_package_set(self):
        names = {PIN.match(ln).group(1).lower() for ln in _requirement_lines()}
        self.assertEqual(names, EXPECTED)

    def test_no_package_twice(self):
        names = [PIN.match(ln).group(1).lower() for ln in _requirement_lines()]
        self.assertEqual(len(names), len(set(names)))


class LibVenv(unittest.TestCase):
    def setUp(self):
        with open(LIB, encoding="utf-8") as fh:
            self.text = fh.read()

    def test_installs_hash_checked_binary_wheels(self):
        self.assertIn("--require-hashes", self.text)
        self.assertIn("--only-binary=:all:", self.text)
        self.assertIn("requirements.txt", self.text)

    def test_returns_instead_of_exiting(self):
        self.assertIn("ensure_research_venv()", self.text)
        self.assertNotRegex(self.text, r"(?m)^\s*[^#\n]*\bexit\b")
        self.assertIn("return 1", self.text)

    def test_venv_in_research(self):
        self.assertIn('/.venv"', self.text)
        self.assertIn("python3 -m venv", self.text)

    def test_bash_syntax(self):
        r = subprocess.run(["bash", "-n", LIB], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class GitIgnore(unittest.TestCase):
    def test_venv_is_ignored(self):
        r = subprocess.run(
            ["git", "-C", ROOT, "check-ignore", "-q", "--no-index",
             "research/.venv/bin/python"],
            capture_output=True, text=True)
        if r.returncode == 128:
            self.skipTest("not a git checkout: " + r.stderr.strip())
        self.assertEqual(r.returncode, 0, "research/.venv is not gitignored")


if __name__ == "__main__":
    unittest.main()
