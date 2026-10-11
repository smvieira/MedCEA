#!/usr/bin/env bash
# Build the standalone channel-map editor.
#
# The editor itself lives in edge/src/host/ui/ and is inlined into the wizard's
# page at request time. This script inlines the SAME two files into a page that
# needs no server, so the map can be inspected or hand-corrected on a laptop that
# has never seen the platform — and so there is exactly one implementation to
# fix when the rules change.
#
#   ./edge/tools/build-editor.sh [output.html]
#
# Defaults to edge/tools/actuator-config-editor.html. Re-run it after editing
# channelmap.js, channelmap.css, or the CONTROL template.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EDGE="$(dirname "$HERE")"
OUT="${1:-$HERE/actuator-config-editor.html}"
SHELL_HTML="$HERE/editor-shell.html"
UI="$EDGE/src/host/ui"
# The config the chambers are actually running. Seeding the page with it rather
# than with the clean reference is deliberate: it is what proves the validator
# earns its place.
SHIPPED="${SHIPPED_CONFIG:-$EDGE/../temp_esp32/control/actuator_config.json}"

for f in "$SHELL_HTML" "$UI/channelmap.css" "$UI/channelmap.js"; do
  [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }
done

SPEC="$(python3 "$EDGE/src/host/device_template.py" channelmap CONTROL relay8)" \
  || { echo "could not build the channel map spec" >&2; exit 1; }

SHELL_HTML="$SHELL_HTML" UI="$UI" SPEC="$SPEC" SHIPPED="$SHIPPED" OUT="$OUT" python3 - <<'PY'
import json, os, sys

e = os.environ
page = open(e["SHELL_HTML"], encoding="utf-8").read()
css = open(os.path.join(e["UI"], "channelmap.css"), encoding="utf-8").read()
js = open(os.path.join(e["UI"], "channelmap.js"), encoding="utf-8").read()
spec = json.loads(e["SPEC"])

try:
    shipped = json.load(open(e["SHIPPED"], encoding="utf-8"))
except (OSError, ValueError):
    # No chamber file to hand: fall back to the template's own wiring so the
    # page still opens on something real rather than an empty form.
    shipped = spec["reference"]
    print("note: %s unreadable, seeding with the reference wiring" % e["SHIPPED"],
          file=sys.stderr)

# str.replace, not %-formatting or f-strings: the CSS and JS are full of braces
# and percent signs that any format call would try to interpret.
for token, value in (("__CHANNELMAP_CSS__", css),
                     ("__CHANNELMAP_JS__", js),
                     ("__SPEC__", json.dumps(spec)),
                     ("__SHIPPED__", json.dumps(shipped)),
                     ("__FAMILY__", spec.get("family", "")),
                     ("__ROLE__", spec.get("role", "")),
                     ("__DRIVER__", spec.get("driver", {}).get("name", ""))):
    if token not in page:
        raise SystemExit("the shell has no %s placeholder" % token)
    page = page.replace(token, value)

open(e["OUT"], "w", encoding="utf-8").write(page)
print("wrote %s (%d bytes)" % (e["OUT"], len(page)))
PY
