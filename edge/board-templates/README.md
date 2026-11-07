# Saved board templates

A board template is a SENSE board's wiring document with a name: which bus is on
which GPIO, which hub, which sensor on which channel and address, and the tag
each reading is published under. The wizard's wiring screen saves one here when
the operator ticks "Save as a board template", and offers every valid one as
"Start from a saved board: <title>" on the next onboarding.

- One file per template: `<slug>.json`, slug `^[a-z][a-z0-9-]{1,40}$`, written by
  `edge/src/host/device_template.py save-board-template` (atomically, mode 644):

  ```json
  {"slug": "...", "title": "...", "description": "...", "variant": "esp32s3",
   "saved_by": "<keycloak username>", "saved_at": "2026-11-06T12:00:00Z",
   "replaced_at": "... (only when an existing one was replaced)",
   "wiring": { "version": 1, "board": {...}, "buses": [...], "hubs": [...],
               "sensors": [...], "layout": {...} }}
  ```

- A template is checked by `edge/src/host/wiring.py` when it is saved (one with an
  error is refused) and again whenever it is listed or used: one that does not
  fit the chip on the bench is listed greyed out, with its first error.
- The shipped templates are in `edge/templates/boards/`; a saved one cannot take a
  shipped name, and an existing saved one is replaced only with `--replace`.
- This folder is tracked in git on purpose, so a saved board can be reviewed and
  shared. It is not in the database: a new table would widen the access policy.
- Tests point `CEA_BOARD_TEMPLATES_DIR` at a temporary folder instead.

List them: `python3 edge/src/host/device_template.py board-templates SENSE`.
