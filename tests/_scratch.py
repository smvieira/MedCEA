"""tests/_scratch.py — a scratch copy of the parts of the repository that compile the access
policy (IAM Phase 4, design §14.4.15), for offline tests that run cli.py or the shell
libraries in a subprocess.

On the live host itself state/policy-applied.yaml exists once a version is applied, and
every compile reads it (compiler/source.py). A test that ran the repository's own cli.py
would then depend on that file, and a test that wrote one would change the platform. In a
scratch tree source.HOST_FILE, source.LOCK_FILE and state/ resolve inside the copy, so a
test may write them freely; no test writes state/ in the repository.

    root = scratch_repo()          # a mktemp -d copy; the caller removes it
    clean_env(**extra)             # os.environ without MEDCEA_POLICY_* and MEDCEA_LOCK_HELD
"""
import os
import shutil
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DIRS = ("apps/iam/compiler", "apps/iam/policy", "apps/iam/lib", "tests/golden")
FILES = ("apps/database/lib-db-apply.sh", "apps/iam/apply_check.py")   # cli.py bootstrap-targets imports it


def scratch_repo(prefix="medcea-scratch-"):
    """A mktemp -d copy of apps/iam/{compiler,policy,lib}, apps/iam/apply_check.py,
    infra/lib-*.sh, apps/database/lib-db-apply.sh and tests/golden (no .git, no state/)."""
    root = tempfile.mkdtemp(prefix=prefix)
    for d in DIRS:
        src = os.path.join(REPO, d)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(root, d), ignore=shutil.ignore_patterns("__pycache__"))
    os.makedirs(os.path.join(root, "infra"))
    for f in sorted(os.listdir(os.path.join(REPO, "infra"))):
        if f.startswith("lib-") and f.endswith(".sh"):
            shutil.copy(os.path.join(REPO, "infra", f), os.path.join(root, "infra", f))
    for f in FILES:
        os.makedirs(os.path.dirname(os.path.join(root, f)), exist_ok=True)
        shutil.copy(os.path.join(REPO, f), os.path.join(root, f))
    return root


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("MEDCEA_POLICY") and k != "MEDCEA_LOCK_HELD"}
    env.update(extra)
    return env
