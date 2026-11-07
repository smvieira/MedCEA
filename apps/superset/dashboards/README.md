# apps/superset/dashboards/

Dashboards as code for Superset. **Empty on purpose**: importing dashboards is not built
(owner decision N9, 7 Nov 2026: deferred; dashboards are made in Superset's UI), and
`apps/superset/deploy.sh` refuses while this folder holds any file but this README
("importing dashboards is not built").

What the importer will have to respect (read from Superset 6.1.0's code, 6 Nov 2026):

- **A bundle must carry `databases/MedCEA.yaml`**, with `uuid: 51fcabb4-6cd4-598e-8013-26d95b9172e1`
  (`DB_UUID` in `apps/superset/bootstrap.py`) and a `sqlalchemy_uri` without a password.
  `ImportDashboardsCommand` imports a dataset only when its `database_uuid` is among the
  bundle's `databases/*.yaml`, so a bundle without it drops every dataset and chart
  without an error. Because the row already exists with that uuid, the importer
  (`import_database(overwrite=False)`) returns it untouched: the URI, the password and
  the flags `bootstrap.py` states are never rewritten from the bundle.
- **Never `superset import-directory`**: it skips the permission checks and the unsafe-URI
  check, and `--overwrite` rewrites the connection row.
- `ImportDashboardsCommand(overwrite=True)` replaces dashboards only; changed charts or
  datasets need `ImportChartsCommand` / `ImportDatasetsCommand(overwrite=True)`.
- Every importer checks `can_write` for `g.user`. There is no local admin and nobody
  holds Admin (bootstrap.py removes it), so the import needs a decision on which user it
  runs as before it is built.

Export a dashboard from Superset (Dashboards → … → Export) to get a bundle; strip the
password from `databases/MedCEA.yaml` (Superset exports it masked) before committing.
