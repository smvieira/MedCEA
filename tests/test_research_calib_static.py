"""research/calib is standard library + PyYAML (design §9 R14).

The research sandbox's calibration package reads the lake over HTTP (urllib) and writes
YAML and JSON; it imports nothing else from outside the standard library but `yaml`, and
from the repository only research/ (relatively). research/twin_plant stays standard
library only (tests/test_research_plant.py Static). tests/test_research_contract.py's
isolation checks (no SQL text, no psql/kubectl, subprocesses read-only git, no aliased
process or import primitive) walk research/calib too.

Offline. Run:
    python3 -m unittest tests.test_research_calib_static
"""
import ast
import os
import sys
import unittest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CALIB = os.path.join(REPO, "research", "calib")


def calib_py():
    out = []
    for root, dirs, files in os.walk(CALIB):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        out += [os.path.join(root, f) for f in sorted(files) if f.endswith(".py")]
    return out


class Static(unittest.TestCase):
    def test_the_package_exists(self):
        names = {os.path.basename(p) for p in calib_py()}
        self.assertLessEqual({"__init__.py", "__main__.py", "cli.py", "lake.py", "pgtext.py", "dataset.py",
                              "extract.py", "segments.py", "stats.py", "sensor_fit.py", "plant_fit.py",
                              "calibfile.py"}, names)

    def test_stdlib_and_yaml_only(self):
        allowed = set(sys.stdlib_module_names) | {"__future__", "yaml"}
        for path in calib_py():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue        # research/ itself (relative)
                    mods = [node.module]
                else:
                    continue
                for m in mods:
                    self.assertIn(m.split(".")[0], allowed, "%s imports %s" % (os.path.relpath(path, REPO), m))

    def test_relative_imports_stay_in_research(self):
        for path in calib_py():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level:
                    self.assertLessEqual(node.level, 2, "%s:%d leaves research/" % (path, node.lineno))

    def test_no_subprocess(self):
        """research/calib starts no process: the lake is HTTP, and the git state a
        calibration file records comes through research/harness/algorithms_loader."""
        for path in calib_py():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            name = os.path.basename(path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertNotIn("subprocess", [a.name for a in node.names], name)


if __name__ == "__main__":
    unittest.main()
