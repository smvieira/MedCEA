"""algorithms_loader.bundle_state: the pods' code bundle has no git, so BUNDLE.json's blob SHAs pin it
(E48, 22 Nov 2026: every sim tool answered LoaderError "not a git repository")."""
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from research.harness import algorithms_loader as al  # noqa: E402


class BundleState(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        files = {}
        for rel, text in (("schd/cea/a.py", "x = 1\n"), ("research/b.py", "y = 2\n"), ("other/c.txt", "z\n")):
            os.makedirs(os.path.join(self.d, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(self.d, rel), "w") as f:
                f.write(text)
            files[rel] = al.blob_sha(self.d, rel)
        os.makedirs(os.path.join(self.d, "research", "__pycache__"))
        with open(os.path.join(self.d, "research", "__pycache__", "b.pyc"), "w") as f:
            f.write("cache")
        with open(os.path.join(self.d, "BUNDLE.json"), "w") as f:
            json.dump({"commit": "c" * 40, "dirty": False, "files": files}, f)

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_clean(self):
        st = al.git_state(self.d, ("schd/cea", "research"))
        self.assertEqual(st, {"commit": "c" * 40, "dirty": False, "dirty_files": []})

    def test_changed_and_extra_files(self):
        with open(os.path.join(self.d, "schd/cea/a.py"), "a") as f:
            f.write("# edited\n")
        with open(os.path.join(self.d, "research/new.py"), "w") as f:
            f.write("")
        st = al.git_state(self.d, ("schd/cea", "research"))
        self.assertTrue(st["dirty"])
        self.assertEqual(st["dirty_files"], ["research/new.py", "schd/cea/a.py"])

    def test_without_bundle(self):
        os.remove(os.path.join(self.d, "BUNDLE.json"))
        self.assertEqual(al.git_state(self.d, ("research",))["dirty_files"], ["(not a git repository)"])


if __name__ == "__main__":
    unittest.main()
