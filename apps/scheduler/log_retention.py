#!/usr/bin/env python3
"""
log_retention.py — run-log compression, the scheduler's system job sys_log_retention (IAM 2.6)

No person compresses or deletes a run log. The scheduler gzips the run logs of finished
runs after log_compress_days (at least MIN_COMPRESS_DAYS) and never deletes one: a run
log is part of the run record. log_delete_days stays a setting (qa-approved, >= 30) but
nothing reads it here.

LOG_DIR is the host's ${REPO_ROOT}/logs, which also holds the deploy logs
(deploy-infra-*.log, deploy-apps-*.log, the audit trail of superuser and kubeconfig use):
only names matching RUN_LOG are ever touched. A change to scheduler-api.py's _log_path
naming must change RUN_LOG with it.

Stdlib only (no Flask, no psycopg2), so tests/test_log_retention.py runs it offline.
"""

import os, re, gzip, shutil, time

RUN_LOG = re.compile(r'^run_recipe_.+\.log(\.gz)?$')
_RUN_ID = re.compile(r'_(\d+)\.log(\.gz)?$')
_TMP    = re.compile(r'^run_recipe_.+\.log\.gz\.tmp$')

# must match medcea.approve_change and scheduler_config_retention_chk (008b enforce)
MIN_COMPRESS_DAYS = 1
MIN_DELETE_DAYS   = 30

DAY = 86400


def run_id_of(fname):
    """The trailing _<digits> before .log, or None (a legacy name without a run id)."""
    m = _RUN_ID.search(fname)
    return int(m.group(1)) if m else None


def plan(entries, now, compress_days, runs, active_ids):
    """[(action, fname, reason)], action in {'compress', 'keep'}, for each run log in
    entries ((fname, mtime) pairs; any other file is left out).

    runs maps run_id to {'status', 'basename'}; basename is the .log name _log_path
    builds for that run. A file is attributed to its run only when the basename matches
    too (a legacy recipe name may end in _<digits>). A .log is compressed once it is
    compress_days old (never below MIN_COMPRESS_DAYS) and its run is C or F, or it is
    unattributed and no active run carries that id. A run in S or R, or one this
    process is running, keeps its log as it is."""
    compress_days = max(MIN_COMPRESS_DAYS, int(compress_days))
    out = []
    for fname, mtime in entries:
        if not RUN_LOG.match(fname):
            continue
        if fname.endswith('.gz'):
            out.append(('keep', fname, 'compressed'))
            continue
        rid = run_id_of(fname)
        if rid is not None and rid in active_ids:
            out.append(('keep', fname, 'run active'))
            continue
        run = runs.get(rid) if rid is not None else None
        attributed = run is not None and run.get('basename') == fname
        if attributed and run.get('status') not in ('C', 'F'):
            out.append(('keep', fname, f"run in {run.get('status')}"))
            continue
        if now - mtime < compress_days * DAY:
            out.append(('keep', fname, 'younger than log_compress_days'))
            continue
        out.append(('compress', fname, 'finished run' if attributed else 'unattributed'))
    return out


def compress(path):
    """path -> path.gz. An existing .gz (a retried run's earlier attempt) is kept: the
    new content goes in as another gzip member, which gzip readers return in order.
    Written to .gz.tmp and renamed, so a crash leaves the .log and any old .gz whole;
    the .gz keeps the .log's mtime."""
    st = os.stat(path)
    gz, tmp = path + '.gz', path + '.gz.tmp'
    with open(tmp, 'wb') as out:
        if os.path.exists(gz):
            with open(gz, 'rb') as old:
                shutil.copyfileobj(old, out)
        with open(path, 'rb') as f_in, gzip.open(out, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.replace(tmp, gz)
    os.utime(gz, (st.st_atime, st.st_mtime))
    os.remove(path)


def apply(log_dir, actions, log, still_idle=None, stats=None):
    """Carry out a plan; never raises. still_idle(run_id) is asked right before each
    compress (a retry may have started the run since the plan); stats maps fname to
    the (mtime, size) the plan saw, and a file that changed since is skipped. A
    run_recipe_*.log.gz.tmp older than a day (a crash) is removed."""
    res = {'compressed': 0, 'kept': 0, 'errors': 0}
    for action, fname, reason in actions:
        if action != 'compress':
            res['kept'] += 1
            continue
        path = os.path.join(log_dir, fname)
        try:
            rid = run_id_of(fname)
            st = os.stat(path)
            if (stats is not None and stats.get(fname) != (st.st_mtime, st.st_size)) or \
               (still_idle is not None and rid is not None and not still_idle(rid)):
                res['kept'] += 1
                continue
            compress(path)
            res['compressed'] += 1
            log.info(f'log retention: compressed {fname} ({reason})')
        except Exception as e:  # noqa: BLE001
            res['errors'] += 1
            log.error(f'log retention: cannot compress {fname}: {type(e).__name__}: {e}')
    try:
        for fname in os.listdir(log_dir):
            if _TMP.match(fname):
                path = os.path.join(log_dir, fname)
                if time.time() - os.stat(path).st_mtime > DAY:
                    os.remove(path)
                    log.info(f'log retention: removed stale {fname}')
    except OSError as e:
        res['errors'] += 1
        log.error(f'log retention: cannot clean {log_dir}: {e}')
    return res
