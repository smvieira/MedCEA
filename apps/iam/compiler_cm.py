#!/usr/bin/env python3
"""apps/iam/compiler_cm.py — ConfigMap iam-compiler for the Policy UI (IAM 4.3).

    python3 compiler_cm.py APPS_IAM_DIR NAMESPACE OUT_DIR

Writes OUT_DIR/configmap.json (apps/iam/compiler/*.py and policy/defaults.yaml, keys
compiler__<f>.py and policy__defaults.yaml, its sha256 as annotation medcea/compiler-sha256),
OUT_DIR/sha256 and OUT_DIR/items.json (the volume `items` that lay the keys out as compiler/
and policy/ under the mount). Refuses a ConfigMap over 900 KiB (the object limit is 1 MiB).
"""
import glob
import hashlib
import json
import os
import sys

LIMIT = 900 * 1024


def build(root, ns):
    files = {"compiler__" + os.path.basename(f): f for f in sorted(glob.glob(os.path.join(root, "compiler", "*.py")))}
    files["policy__defaults.yaml"] = os.path.join(root, "policy", "defaults.yaml")
    data = {}
    for k, f in files.items():
        with open(f, encoding="utf-8") as fh:
            data[k] = fh.read()
    sha = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    items = [{"key": k, "path": k.replace("__", "/", 1)} for k in sorted(data)]
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": "iam-compiler", "namespace": ns, "annotations": {"medcea/compiler-sha256": sha}},
          "data": data}
    return cm, sha, items


def main(argv):
    root, ns, out = argv[1:4]
    cm, sha, items = build(root, ns)
    body = json.dumps(cm)
    if len(body.encode()) > LIMIT:
        print(f"ConfigMap iam-compiler is {len(body.encode()) // 1024} KiB, over {LIMIT // 1024} KiB", file=sys.stderr)
        return 1
    for name, text in (("configmap.json", body), ("sha256", sha), ("items.json", json.dumps(items, separators=(",", ":")))):
        with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
