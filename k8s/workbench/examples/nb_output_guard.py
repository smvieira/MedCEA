"""nb_output_guard — git's pre-commit hook in every AI workbench server (IAM 3.2b).

Refuses a commit while a staged notebook still holds cell outputs or execution counts.
nbstripout, the global git filter, normally removes them as a notebook is staged; this
hook is the check behind it, for when the filter is not there (it could not be installed
at the server's start) or a repository's own .gitattributes turns it off. It reads only
what git would store (the staged blobs), writes nothing and prints file names only.

The server's start points git's global core.hooksPath at ~/.config/git/hooks, whose
pre-commit runs this file from the read-only medcea-examples folder.
"""
import json
import subprocess
import sys


def staged_notebooks():
    out = subprocess.run(["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"],
                         capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8", "replace").split("\0") if p.endswith(".ipynb")]


def has_outputs(raw):
    """True when the notebook JSON holds an output or an execution count (or is no notebook)."""
    try:
        nb = json.loads(raw.decode("utf-8"))
        cells = nb.get("cells") or []
    except (ValueError, AttributeError):
        return True
    return any(c.get("outputs") or c.get("execution_count") is not None
               for c in cells if isinstance(c, dict) and c.get("cell_type") == "code")


def main():
    bad = [p for p in staged_notebooks()
           if has_outputs(subprocess.run(["git", "show", ":" + p], capture_output=True, check=True).stdout)]
    if not bad:
        return 0
    sys.stderr.write("Commit refused: these notebooks still hold cell outputs, which may carry platform data:\n"
                     + "".join("  %s\n" % p for p in bad)
                     + "Clear them (Edit > Clear Outputs of All Cells, save), stage them again and commit;\n"
                       "or in a terminal: python3 -m nbstripout <file>. See medcea-examples/SAVE_TO_GIT.md.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
