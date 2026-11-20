"""Synthetic lake datasets for the research calibration tests (research Phase 3).

make_dataset() builds rows the way the live data looks (snapshot 1 of UNIT01/ZONE01, read
20 Nov 2026): one SENSE board, an SHT45 (sht45_1) and an SCD30 (scd30_1) publishing every
~3 s in one shared cycle, measured_at truncated to the whole second and shared by every
tag of the cycle, ingested_at a little later per tag, the SCD30 reading +2.04 C and
-7.03 %RH against the SHT45. The messages come from twin_plant.sensors.SensorBank (so a
known spec is what the fit must recover) sampling a slowly wandering truth (an AR(1)
process per tag). The SCD30's CO2 gets a fast component with momentum, as the live
series has (its first differences are positively autocorrelated), unless co2_momentum is
False.

write_dataset() writes it as research/calib/dataset.py writes a fetched one, with a header
whose snapshot digest recomputes, so dataset.verify() and the CLI accept it.
"""
import datetime
import math
import os
import random
import sys

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from research.calib import dataset  # noqa: E402
from research.twin_plant.sensors import SensorBank, SensorSpec  # noqa: E402

START = datetime.datetime(2026, 11, 14, 19, 52, 44, tzinfo=datetime.timezone.utc)
LINEAGE = "a" * 64

SHT45 = dict(noise_sd={"air_temperature": 0.012, "air_humidity": 0.016},
             quantisation={"air_temperature": 0.01, "air_humidity": 0.01},
             latency_s=0.8, dropout_p=0.0)
SCD30 = dict(noise_sd={"co2": 4.0, "air_temperature": 0.012, "air_humidity": 0.02},
             quantisation={"co2": 0.01, "air_temperature": 0.01, "air_humidity": 0.01},
             bias={"air_temperature": 2.04, "air_humidity": -7.03},
             latency_s=1.2, dropout_p=0.0)


def _ts(seconds):
    d = START + datetime.timedelta(microseconds=int(round(seconds * 1e6)))
    return d.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ar(rng, n, tau, sd, mean):
    phi = math.exp(-1.0 / tau)
    k = sd * math.sqrt(1 - phi * phi)
    x, out = 0.0, []
    for _ in range(n):
        x = phi * x + k * rng.gauss(0.0, 1.0)
        out.append(mean + x)
    return out


def make_rows(hours=3.0, seed=1, interval=2.988, sht45=None, scd30=None, outages=(), process_sd=None,
              co2_momentum=True, unit="UNIT01", zone="ZONE01"):
    """Rows (dataset.COLUMNS dicts) of a synthetic board. sht45/scd30 update the specs
    above (False drops that sensor); outages: [(from_s, to_s)] with no publish."""
    rng = random.Random("synth:%d" % seed)
    n = int(hours * 3600) + 2
    ps = {"air_temperature": 0.1, "air_humidity": 0.4, "co2": 40.0}
    ps.update(process_sd or {})
    truth = {"air_temperature": _ar(rng, n, 1800.0, ps["air_temperature"], 26.1),
             "air_humidity": _ar(rng, n, 1800.0, ps["air_humidity"], 53.3),
             "co2": _ar(rng, n, 1800.0, ps["co2"], 700.0)}
    specs, lat = [], {}
    for sid, kind, tags, base, over in (("sht45_1", "sht45", ("air_temperature", "air_humidity"), SHT45, sht45),
                                        ("scd30_1", "scd30", ("co2", "air_temperature", "air_humidity"), SCD30,
                                         scd30)):
        if over is False:
            continue
        kw = dict(base)
        kw.update(over or {})
        specs.append(SensorSpec(sid, kind, tags, publish_interval_s=interval, start_offset_s=0.37, **kw))
        lat[sid] = kw.get("latency_s", 0.0)
    bank = SensorBank(specs, seed)
    msgs = []
    for t in range(n - 1):
        tr = {k: v[t] for k, v in truth.items()}
        msgs.extend(bank.readings_due(float(t), tr))
    # the SCD30's CO2: a fast component with momentum (filtered, positively autocorrelated steps)
    fast = {}
    if co2_momentum:
        u = z = 0.0
        frng = random.Random("synth-co2:%d" % seed)
        cycles = sorted({round(arr - lat["scd30_1"], 6) for tag, sid, v, arr in msgs if sid == "scd30_1"})
        for c in cycles:
            u = 0.6 * u + frng.gauss(0.0, 6.0)
            z = 0.97 * z + u
            fast[c] = z
    rows = []
    order = {"air_temperature": 0, "air_humidity": 1, "co2": 0}
    for tag, sid, v, arrival in msgs:
        pub = arrival - lat[sid]
        if any(a <= pub < b for a, b in outages):
            continue
        if sid == "scd30_1" and tag == "co2" and fast:
            v = round(v + fast[round(pub, 6)], 2)
        offset = (0.0 if sid == "sht45_1" else 0.25) + 0.1 * order[tag]
        rows.append({"measured_at": _ts(math.floor(pub + 0.0)), "ingested_at": _ts(arrival + offset),
                     "unit_code": unit, "zone_code": zone, "tag": tag, "sensor": sid, "value": "%.2f" % v,
                     "uom": {"air_temperature": "C", "air_humidity": "RH%", "co2": "ppm"}[tag], "snapshot_id": 1})
    rows.sort(key=dataset._key)
    return rows


def header_for(rows, unit="UNIT01", zone="ZONE01", cut_at=None, lineage=LINEAGE):
    digest = dataset.snapshot_digests(rows).get(1)
    cut = cut_at or rows[-1]["ingested_at"]
    return {"medcea_dataset": 1, "calib_version": 1,
            "lake": {"contract_version": 1, "snapshot_id": 1, "cut_at": cut, "lineage": lineage,
                     "lineage_verified": True,
                     "snapshots": [{"id": 1, "cut_at": cut, "previous_cut_at": None, "digest_measurement": digest,
                                    "rows_measurement": len(rows), "rows_fetched": len(rows), "complete": True,
                                    "missing": 0, "digest_verified": True}]},
            "query": {"fn": "measurements", "p_snapshot": 1, "p_unit": unit, "p_zone": zone, "p_tag": None,
                      "p_sensor": None, "page_size": 5000, "pages": 1},
            "rows": len(rows), "series": dataset.series_counts(rows), "columns": list(dataset.COLUMNS),
            "content_sha256": dataset.content_sha256(rows)}


def write_dataset(folder, rows, **kw):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, dataset.FILE)
    dataset.write(path, header_for(rows, **kw), rows)
    return path


# ── a synthetic snapshot extract ────────────────────────────────────────────────────
def make_extract(lines=None, snapshot_id=1, lineage=LINEAGE, catalogue_change=None):
    """An extract document whose digests recompute: recipe 2 (FUNGI, approved) with LINES
    ([(seq, light_type, on, off, setpoints dict)]) and git's catalogue (each quantity's min
    and max; CATALOGUE_CHANGE = (code, key, value) alters one)."""
    import yaml
    from research.calib import extract, pgtext
    with open(os.path.join(REPO, "apps", "database", "recipe_types.yaml"), encoding="utf-8") as f:
        cat = yaml.safe_load(f)
    N = pgtext.Num
    lines = lines or [(1, "DARK", 1, 1, {"co2": {"lower": 1000, "upper": 5000},
                                         "air_humidity": {"lower": 90, "upper": 95},
                                         "air_temperature": {"lower": 20, "upper": 25},
                                         "substrate_temperature": {"lower": 21, "upper": 24}}),
                      (3, "RED", 1, 1, {"co2": {"lower": 500, "upper": 1000},
                                        "air_humidity": {"lower": 80, "upper": 85},
                                        "air_temperature": {"lower": 10, "upper": 21},
                                        "substrate_temperature": {"lower": 16, "upper": 18}})]

    def num(v):
        if isinstance(v, dict):
            return {k: num(x) for k, x in v.items()}
        return N(str(v)) if isinstance(v, (int, float)) and not isinstance(v, bool) else v
    raw = {"recipes": [{"recipe_id": N("2"), "recipe_type": "FUNGI", "status": "approved"}],
           "recipe_lines": [{"recipe_id": N("2"), "seq": N(str(seq)), "cycle_number": N(str(seq)),
                             "light_type": lt, "light_on_minutes": N(str(on)), "light_off_minutes": N(str(off)),
                             "setpoints": num(sp)} for seq, lt, on, off, sp in lines],
           "catalogue": []}
    for q in cat["quantities"]:
        doc = {"min": q["min"], "max": q["max"], "default_tag": q["default_tag"]}
        if catalogue_change and catalogue_change[0] == q["code"]:
            doc[catalogue_change[1]] = catalogue_change[2]
        raw["catalogue"].append({"kind": "quantity", "code": q["code"], "doc": num(doc)})
    doc = {"medcea_extract": 1, "lake": {"contract_version": 1, "snapshot_id": snapshot_id,
                                         "cut_at": "2026-11-19T09:10:33.868995Z", "lineage": lineage},
           "digests": {}}
    sets = {}
    for fn in extract.SETS:
        rows = [extract.text_row(fn, r) for r in raw[fn]]
        doc["digests"][fn] = extract.digest_of(fn, rows)
        sets[fn] = rows
    doc.update(sets)
    extract.verify_doc(doc)
    return doc


# ── a synthetic calibration file ────────────────────────────────────────────────────
MAP = {"sht45": "sht45_1", "scd30": "scd30_1"}
CODE = {"commit": "0" * 40, "dirty": False, "dirty_files": [], "python": "3.x", "blobs": {}}
_FITS = {}


def make_calibration(folder, name="unit01-zone01-test", hours=1.5, humidity_model="constant_offset", code=None,
                     **kw):
    """(path, sha256, doc) of a calibration file fitted to a synthetic dataset and written
    into FOLDER (the fit is cached per arguments)."""
    from research.calib import calibfile, sensor_fit
    key = (hours, humidity_model, repr(sorted(kw.items())))
    if key not in _FITS:
        rows = make_rows(hours=hours, **kw)
        h = header_for(rows)
        _FITS[key] = (h, rows, sensor_fit.fit(h, rows, MAP, humidity_model=humidity_model))
    h, rows, fit = _FITS[key]
    doc = calibfile.build(h, fit, name, MAP, "sht45", dict(code or CODE), rows)
    path = os.path.join(folder, name + ".yaml")
    sha = calibfile.dump(doc, path)
    return path, sha, doc
