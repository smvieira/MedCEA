"""Load production's controller code and loop rules by path, never through `import cea`.

`import cea` runs schd/cea/__init__.py, which imports psycopg2 and paho (absent in the
sandbox and irrelevant to it). Instead a synthetic package whose __path__ is schd/cea is
registered in sys.modules, and only its `algorithms` subpackage and `loop_resolver`
module are imported from it (the way tests/test_loop_resolver.py does). Importing
<pkg>.algorithms runs schd/cea/algorithms/__init__.py and nothing else of cea.

The coupling contract's metadata is read from the same tree, never copied:
- apps/database/recipe_types.yaml   the quantity catalogue (loop codes, tags, ranges,
                                    commands, command_map, phase, loopable);
- edge/templates/esp32-control.json the actuator command semantics of the relay board.
- apps/research/db/lake_api.sql     lake-api's read functions (Phase 3), pinned like the
                                    rest: a dirty copy refuses a campaign.

load() records the git blob SHA (`git hash-object`, the bytes actually loaded) of every
file it reads and HEAD's commit, and refuses a tree whose contract sources differ from
HEAD (a result must name the code that produced it) unless allow_dirty. The sandbox's
own code (research/, but research/.venv and research/runs) is pinned the same way: its
Python files, scenarios, campaign specs and requirements.txt are in the blob SHAs and a
change to any of them counts as dirty, because they produce the numbers too. The
manifest also names contract.CONTRACT_VERSION. git is only read (rev-parse, status):
nothing is written to the repository.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import subprocess
import sys
import types

import yaml

from .. import contract
from ..twin_plant import sensors

# The contract's sources, relative to the repository root (plan, "Coupling contract" 3).
ALGORITHMS_DIR = "schd/cea/algorithms"
LOOP_RESOLVER = "schd/cea/loop_resolver.py"
CATALOGUE = "apps/database/recipe_types.yaml"
CONTROL_TEMPLATE = "edge/templates/esp32-control.json"
CONTROL_DRIVER = "relay8"
# lake-api's read functions (Phase 3: research/calib reads snapshots through them).
LAKE_API = "apps/research/db/lake_api.sql"
# Paths whose working copy must equal HEAD unless allow_dirty.
DIRTY_PATHS = ("schd/cea", CATALOGUE, CONTROL_TEMPLATE, LAKE_API)
# The sandbox's own tree (the checkout this module runs from) and its pinned paths.
SANDBOX_ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SANDBOX_DIR = "research"
SANDBOX_SKIP = (".venv", "runs", "__pycache__")
# Evidence written into research/ that shapes no result: the local model's daily bench
# report (apps/research-model/bench.sh, research Phase 4b step 0). Left out of the dirty
# check so a bench on the live checkout does not make every campaign and calibration
# refuse until it is committed; its README (and any other file there) still counts.
SANDBOX_EVIDENCE = ("agents/bench/*.json",)
SANDBOX_PATHS = ((SANDBOX_DIR,) + tuple(":(exclude)%s/%s" % (SANDBOX_DIR, d) for d in SANDBOX_SKIP[:2])
                 + tuple(":(exclude,glob)%s/%s" % (SANDBOX_DIR, g) for g in SANDBOX_EVIDENCE))
SANDBOX_SUFFIXES = (".py", ".yaml", ".txt", ".sh")

# The libraries whose versions a manifest names (distribution names).
LIBRARIES = ("numpy", "scipy", "scikit-fuzzy", "gekko", "packaging", "networkx", "PyYAML")

LIBRARY_CODES = ("FLC", "MPC")       # the controllers that fall back to bang-bang without a library


class LoaderError(Exception):
    """The code cannot be loaded as asked (dirty tree, unknown code, bad parameters)."""


def _git(repo_root, *args):
    """stdout of a read-only git command, or None when git or the repository is absent."""
    try:
        r = subprocess.run(["git", "-C", repo_root, *args], capture_output=True, text=True,
                           timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def blob_sha(repo_root, rel):
    """git's blob SHA of the file's current bytes (git hash-object; works outside git too)."""
    with open(os.path.join(repo_root, rel), "rb") as f:
        data = f.read()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def git_state(repo_root, paths=DIRTY_PATHS):
    """{commit, dirty, dirty_files}. commit None outside a git repository (then dirty is
    True: nothing pins the code)."""
    head = _git(repo_root, "rev-parse", "HEAD")
    if head is None:
        return {"commit": None, "dirty": True, "dirty_files": ["(not a git repository)"]}
    status = _git(repo_root, "status", "--porcelain", "--untracked-files=all", "--", *paths)
    if status is None:
        return {"commit": head.strip(), "dirty": True, "dirty_files": ["(git status failed)"]}
    files = sorted(line[3:] for line in status.splitlines() if line.strip())
    return {"commit": head.strip(), "dirty": bool(files), "dirty_files": files}


def sandbox_files(root=SANDBOX_ROOT):
    """research/'s files that shape a result (code, scenarios, specs, pins), sorted,
    relative to ROOT; never .venv, runs or caches."""
    out = []
    base = os.path.join(root, SANDBOX_DIR)
    for dirpath, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in SANDBOX_SKIP)
        out += [os.path.relpath(os.path.join(dirpath, f), root) for f in sorted(files)
                if f.endswith(SANDBOX_SUFFIXES)]
    return sorted(out)


def sandbox_state(repo_root):
    """git_state of the sandbox's own tree (research/ of SANDBOX_ROOT). When the contract
    root is another checkout, its dirty files are named "sandbox:<path>"."""
    st = git_state(SANDBOX_ROOT, SANDBOX_PATHS)
    if os.path.realpath(repo_root) != SANDBOX_ROOT:
        st = dict(st, dirty_files=["sandbox:" + f for f in st["dirty_files"]])
    return st


def library_versions():
    out = {}
    for name in LIBRARIES:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = None
    return out


def _quantities(catalogue, recipe_type):
    """The unit type's quantities in loop_resolver's shape (medcea._loop_quantities() of
    migration 011): {code: {tag, sense_uoms, commands, command_map?, phase, loopable}},
    in the catalogue's order, plus each one's min/max/unit for the setpoint checks."""
    types_ = {t["code"]: t for t in catalogue["recipe_types"]}
    if recipe_type not in types_:
        raise LoaderError("unknown recipe type %r (known: %s)" % (recipe_type, ", ".join(sorted(types_))))
    wanted = types_[recipe_type]["quantities"]
    out = {}
    for q in catalogue["quantities"]:
        if q["code"] not in wanted:
            continue
        e = {"tag": q["default_tag"], "sense_uoms": list(q["sense_uoms"]), "commands": list(q["commands"]),
             "phase": q["phase"], "loopable": bool(q["loopable"]), "min": q["min"], "max": q["max"],
             "unit": q.get("unit"), "required": bool(wanted[q["code"]])}
        if q.get("command_map"):
            e["command_map"] = dict(q["command_map"])
        out[q["code"]] = e
    return out


class Loaded:
    """The loaded code and metadata. Attributes:
    algorithms   the schd/cea/algorithms package (ALGORITHM_NAMES, the modules pid, q_learning…)
    lr           schd/cea/loop_resolver
    params       schd/cea/algorithms/params (None when absent from this tree)
    catalogue    recipe_types.yaml as a dict
    actuators    the relay board's actuator definitions (template's driver relay8)
    git          {commit, dirty, dirty_files}
    blobs        {path: blob sha} of every file read
    libraries    {code: {present, reason}} for FLC and MPC
    """

    def __init__(self, repo_root, pkg, algorithms, lr, params, catalogue, actuators, git, blobs,
                 sandbox=None):
        self.repo_root = repo_root
        self.pkg = pkg
        self.algorithms = algorithms
        self.lr = lr
        self.params = params
        self.catalogue = catalogue
        self.actuators = actuators
        self.git = git
        self.blobs = blobs
        self.sandbox = sandbox or {}
        self.pid = sys.modules[pkg + ".algorithms.pid"]
        self.q_learning = sys.modules[pkg + ".algorithms.q_learning"]
        self.libraries = self._library_presence()

    def codes(self):
        return sorted(self.algorithms.ALGORITHM_NAMES)

    def _library_presence(self):
        out = {}
        names = self.algorithms.ALGORITHM_NAMES
        if "FLC" in names:
            a = names["FLC"](0.0, 1.0)
            out["FLC"] = {"present": getattr(a, "_ctrl", None) is not None,
                          "reason": getattr(a, "_import_error", None)}
        if "MPC" in names:
            a = names["MPC"](0.0, 1.0)
            out["MPC"] = {"present": bool(getattr(a, "_gekko", None)),
                          "reason": getattr(a, "_import_error", None)}
            close = getattr(a, "close", None)       # the probe's GEKKO temp directory
            if callable(close):
                close()
        return out

    def check(self, code, params=None):
        """Refuse an unknown code (get_algorithm would silently run bang-bang) and, where
        this tree has params.py, a parameter set its schema refuses."""
        if code not in self.algorithms.ALGORITHM_NAMES:
            raise LoaderError("unknown algorithm code %r (known: %s)" % (code, ", ".join(self.codes())))
        if self.params is not None:
            problems = self.params.validate_params(code, params or {})
            if problems:
                raise LoaderError("; ".join(problems))

    def make(self, code, lower, upper, params=None):
        """One controller instance, through ALGORITHM_NAMES itself (never get_algorithm)."""
        self.check(code, params)
        return self.algorithms.ALGORITHM_NAMES[code](lower, upper, **(params or {}))

    def quantities(self, recipe_type):
        return _quantities(self.catalogue, recipe_type)

    def manifest(self):
        return {"commit": self.git["commit"], "dirty": self.git["dirty"],
                "dirty_files": self.git["dirty_files"], "blobs": dict(sorted(self.blobs.items())),
                "libraries": library_versions(), "controller_libraries": self.libraries,
                "python": sys.version.split()[0], "contract_version": contract.CONTRACT_VERSION,
                "sensor_model_version": sensors.SENSOR_MODEL_VERSION,
                "sandbox": dict(self.sandbox)}


_CACHE = {}


def load(repo_root, allow_dirty=False):
    """Load the contract code and metadata of REPO_ROOT (cached per root and process).

    Refuses (LoaderError) a tree whose contract sources differ from HEAD, unless
    allow_dirty; the dirty files are then recorded in the manifest."""
    repo_root = os.path.realpath(repo_root)
    git = git_state(repo_root)
    sb = sandbox_state(repo_root)
    if sb["dirty"]:
        git = dict(git, dirty=True, dirty_files=sorted(set(git["dirty_files"]) | set(sb["dirty_files"])))
    if git["dirty"] and not allow_dirty:
        raise LoaderError("the contract sources or the sandbox's code differ from HEAD (%s): "
                          "commit them, or pass --allow-dirty (allow_dirty=True from Python) to "
                          "record them as dirty" % ", ".join(git["dirty_files"]))
    if repo_root in _CACHE:
        return _CACHE[repo_root]

    pkg = "medcea_rs_cea_" + hashlib.sha256(repo_root.encode()).hexdigest()[:12]
    if pkg not in sys.modules:
        mod = types.ModuleType(pkg)
        mod.__path__ = [os.path.join(repo_root, "schd", "cea")]
        sys.modules[pkg] = mod
    algorithms = importlib.import_module(pkg + ".algorithms")
    lr = importlib.import_module(pkg + ".loop_resolver")
    try:
        params = importlib.import_module(pkg + ".algorithms.params")
    except ImportError:
        params = None

    with open(os.path.join(repo_root, CATALOGUE), encoding="utf-8") as f:
        catalogue = yaml.safe_load(f)
    with open(os.path.join(repo_root, CONTROL_TEMPLATE), encoding="utf-8") as f:
        template = json.load(f)
    drivers = {d["id"]: d for d in template["drivers"]}
    if CONTROL_DRIVER not in drivers:
        raise LoaderError("%s has no driver %s" % (CONTROL_TEMPLATE, CONTROL_DRIVER))
    actuators = drivers[CONTROL_DRIVER]["actuators"]

    files = sorted(os.path.relpath(m.__file__, repo_root) for name, m in sys.modules.items()
                   if (name == pkg + ".algorithms" or name.startswith(pkg + "."))
                   and getattr(m, "__file__", None))
    files += [CATALOGUE, CONTROL_TEMPLATE]
    files += [p for p in contract.SOURCES if os.path.exists(os.path.join(repo_root, p))]
    blobs = {rel: blob_sha(repo_root, rel) for rel in sorted(set(files))}
    # The sandbox's own files, from its own tree (the code that is running).
    sandbox = {"root_is_repo": SANDBOX_ROOT == repo_root, "commit": sb["commit"]}
    for rel in sandbox_files():
        key = rel if SANDBOX_ROOT == repo_root else "sandbox:" + rel
        blobs[key] = blob_sha(SANDBOX_ROOT, rel)
    loaded = Loaded(repo_root, pkg, algorithms, lr, params, catalogue, actuators, git, blobs, sandbox)
    _CACHE[repo_root] = loaded
    return loaded
