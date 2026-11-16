#!/usr/bin/env python3
"""HB and TS messages, offline: the ingest side (Node-RED and the database).

- Node-RED's "Stringify JSON" function (apps/node-red/flows/message-processing.json,
  the one feeding the medcea.measurement INSERT) under node (skipped without node):
  <root>/<unit>/<zone>/sense/_health is stored as HB and .../sense/_test or
  .../control_setpoint/_test as TS, whatever msg_type the payload claims; a CONTROL pin
  report labelled _test or _health stays SP; any other topic claiming HB or TS is
  dropped (with a node.warn); otherwise, and for a payload that is not an object, it
  behaves exactly as the function in git HEAD did.
- Six-segment reading topics (feedback control Phase 1, Q12):
  <root>/<unit>/<zone>/sense/<tag>/<sensor> is stored as the board sent it (AP, its
  `sensor` key kept) with no flow change; the five-segment form still works and gains no
  `sensor` (the views supply 'default'); an instance segment never makes HB or TS, and
  such a topic claiming HB or TS is dropped; the `mqtt in` node subscribes every depth.
- Migration 009 (apps/database/medcea_db_migrations.sql): the last block, its own
  transaction after 008c's COMMIT, the exact list, NOT VALID then VALIDATE with a
  WARNING on old rows, and nothing altered or scanned once it is in place.
- medcea_db_ddl.sql: a fresh install's domain CHECK is the same exact list.

Run: python3 tests/test_msg_types.py
"""
import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLOW = os.path.join("apps", "node-red", "flows", "message-processing.json")
DB = os.path.join(ROOT, "apps", "database")
TYPES = ["AP", "CT", "SP", "HB", "TS"]
NODE_ID = "7a4d2b4b6f0c828c"

# Node-RED runs a function body inside a function of msg in a vm context (sloppy mode).
RUNNER = r"""
const vm = require('vm');
const {func, cases} = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = cases.map(c => {
    const warned = [];
    const node = {warn: m => warned.push(String(m))};
    const ctx = vm.createContext({msg: c, node});
    try {
        const r = vm.runInContext('(function (msg) {\n' + func + '\n})(msg)', ctx);
        return {ok: true, out: r === undefined ? null : JSON.parse(JSON.stringify(r)), warned};
    } catch (e) {
        return {ok: false, error: e.name};
    }
});
process.stdout.write(JSON.stringify(out));
"""


def flow_nodes(text=None):
    if text is None:
        with open(os.path.join(ROOT, FLOW), encoding="utf-8") as f:
            text = f.read()
    return json.loads(text)


def feeder(nodes):
    """The one function node wired to the medcea.measurement INSERT."""
    insert = [n for n in nodes if n.get("type") == "postgresql" and "medcea.measurement" in n.get("query", "")]
    assert len(insert) == 1, insert
    fns = [n for n in nodes if n.get("type") == "function" and any(insert[0]["id"] in w for w in n.get("wires", []))]
    assert len(fns) == 1, fns
    return fns[0], insert[0]


def run_func(func, cases):
    r = subprocess.run(["node", "-e", RUNNER], input=json.dumps({"func": func, "cases": cases}),
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout)


def reading(**kw):
    p = {"unit_code": "UNIT01", "zone_code": "ZONE01", "msg_type": "AP", "timestamp": "2026-11-06 10:00:00",
         "device_id": "a0b1c2d3e4f5", "device_dns": "unit01-s-zone01", "tag": "co2", "value": 600, "UoM": "ppm"}
    p.update(kw)
    return p


class FlowShapeTest(unittest.TestCase):

    def test_the_node_keeps_its_id_name_and_wiring(self):
        fn, insert = feeder(flow_nodes())
        self.assertEqual((fn["id"], fn["name"]), (NODE_ID, "Stringify JSON"))
        self.assertEqual(fn["wires"], [["189630c72c0f3dac", insert["id"]]])
        self.assertEqual(fn["outputs"], 1)

    def test_the_insert_stores_the_type_the_function_set(self):
        _, insert = feeder(flow_nodes())
        self.assertIn("'{{msg.payload.msg_type}}'", insert["query"])
        self.assertIn("'{{{msg.payload.fullmsg}}}'", insert["query"])

    def test_subscribes_every_depth(self):
        # a six-segment reading topic reaches the function: the one subscription is root/#
        subs = [n for n in flow_nodes() if n.get("type") == "mqtt in"]
        self.assertEqual([(n["topic"], n["wires"]) for n in subs], [("__TOPIC_ROOT__/#", [[NODE_ID]])])

    def test_the_only_drop_is_a_false_hb_or_ts_claim(self):
        fn, _ = feeder(flow_nodes())
        self.assertEqual(fn["func"].count("return null"), 1)
        drop = fn["func"].index("return null")
        self.assertIn("msg.payload.msg_type === 'HB' || msg.payload.msg_type === 'TS'", fn["func"][:drop])


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class IngestFunctionTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.func = feeder(flow_nodes())[0]["func"]
        try:
            head = subprocess.run(["git", "-C", ROOT, "show", "HEAD:" + FLOW],
                                  capture_output=True, text=True, check=True).stdout
            cls.head = feeder(flow_nodes(head))[0]["func"]
        except (OSError, subprocess.CalledProcessError, ValueError, AssertionError):
            cls.head = None

    def stored(self, topic, payload):
        r = run_func(self.func, [{"topic": topic, "payload": payload}])[0]
        self.assertTrue(r["ok"], r)
        self.assertIsNotNone(r["out"], "dropped: %s" % r["warned"])
        self.assertEqual(r["warned"], [])
        p = r["out"]["payload"]
        full = json.loads(p.pop("fullmsg"))
        self.assertEqual(full, p, "fullmsg is the payload as stored")
        return p

    def test_health_is_hb(self):
        p = self.stored("medcea/UNIT01/ZONE01/sense/_health",
                        reading(msg_type="HB", tag="_health", value=None, sensors=[{"id": "sht45", "ok": True, "err": ""}]))
        self.assertEqual(p["msg_type"], "HB")
        self.assertEqual(p["sensors"], [{"id": "sht45", "ok": True, "err": ""}])

    def test_test_is_ts_on_sense_and_control(self):
        for topic in ("medcea/UNIT01/ZONE01/sense/_test", "medcea/UNIT01/ZONE01/control_setpoint/_test"):
            with self.subTest(topic=topic):
                p = self.stored(topic, reading(msg_type="TS", tag="_test", source="board-boot"))
                self.assertEqual(p["msg_type"], "TS")
                self.assertEqual(p["source"], "board-boot")

    def test_the_topic_wins_over_the_payload(self):
        # a _test message sent as a reading is still stored as TS, and so on
        for topic, claim, want in (("medcea/U/Z/sense/_test", "AP", "TS"), ("medcea/U/Z/sense/_test", "HB", "TS"),
                                   ("medcea/U/Z/sense/_health", "AP", "HB"), ("medcea/U/Z/sense/_health", "TS", "HB"),
                                   ("medcea/U/Z/sense/_test", None, "TS")):
            with self.subTest(topic=topic, claim=claim):
                payload = reading(tag=topic.rsplit("/", 1)[1])
                if claim is None:
                    del payload["msg_type"]
                else:
                    payload["msg_type"] = claim
                self.assertEqual(self.stored(topic, payload)["msg_type"], want)

    def test_only_the_boards_own_topic_counts(self):
        for topic in ("medcea/U/Z/sense/_health/x", "medcea/U/Z/sense/my_test", "medcea/U/Z/sense/_testing",
                      "medcea/U/Z/sense/co2_health", "_test", "medcea/U/Z/sense/_TEST",
                      "medcea/U/Z/sense/x/_test", "U/Z/sense/_test", "medcea/U/Z/control/_test",
                      "medcea/U/Z/control_setpoint/_health", "x/medcea/U/Z/sense/_health"):
            with self.subTest(topic=topic):
                self.assertEqual(self.stored(topic, reading())["msg_type"], "AP")

    def test_a_pin_labelled_test_or_health_stays_sp(self):
        # cea_control publishes each pin report on control_setpoint/<tag>/<pin description>,
        # and the description is free text from the channel-map editor
        for leaf in ("_test", "_health"):
            with self.subTest(leaf=leaf):
                topic = "medcea/UNIT01/ZONE01/control_setpoint/light/" + leaf
                payload = reading(msg_type="SP", tag="light", value=1)
                self.assertEqual(self.stored(topic, dict(payload)), payload)

    def test_no_other_topic_may_claim_hb_or_ts(self):
        for topic in ("medcea/U/Z/sense/co2", "medcea/U/Z/control_setpoint/_health",
                      "medcea/U/Z/control_setpoint/light/_test", "medcea/U/Z/control/_test",
                      "medcea/U/Z/control/fan", "medcea/U/Z/sense/x/_health", None):
            for claim in ("HB", "TS"):
                with self.subTest(topic=topic, claim=claim):
                    case = {"payload": reading(msg_type=claim)}
                    if topic is not None:
                        case["topic"] = topic
                    r = run_func(self.func, [case])[0]
                    self.assertTrue(r["ok"], r)
                    self.assertIsNone(r["out"])
                    self.assertEqual(r["warned"], ["dropped: %s is not allowed on %s" % (claim, topic or "")])

    def test_readings_and_setpoints_are_unchanged(self):
        for topic, payload in (("medcea/UNIT01/ZONE01/sense/co2", reading()),
                               ("medcea/UNIT01/ZONE01/control_setpoint/fan", reading(msg_type="SP", tag="fan", value=1)),
                               ("medcea/UNIT01/ZONE01/control/fan", reading(msg_type="CT", tag="fan", value=1))):
            with self.subTest(topic=topic):
                self.assertEqual(self.stored(topic, dict(payload)), payload)

    def test_a_six_segment_reading_is_stored_as_sent(self):
        # <root>/<unit>/<zone>/sense/<tag>/<sensor>: the board's record, unchanged, AP
        for sensor, value in (("sht45_1", 91.4), ("scd30", 88.0)):
            with self.subTest(sensor=sensor):
                payload = reading(tag="air_humidity", sensor=sensor, value=value, UoM="RH%")
                p = self.stored("medcea/UNIT01/ZONE01/sense/air_humidity/" + sensor, dict(payload))
                self.assertEqual(p, payload)
                self.assertEqual((p["msg_type"], p["sensor"]), ("AP", sensor))
        # the five-segment form of a board flashed before Phase 1: stored as sent, and
        # Node-RED adds no sensor (the views' COALESCE gives 'default')
        p = self.stored("medcea/UNIT01/ZONE01/sense/co2", reading())
        self.assertEqual(p, reading())
        self.assertNotIn("sensor", p)

    def test_an_instance_segment_never_makes_hb_or_ts(self):
        topics = ("medcea/U/Z/sense/_health/sht45_1", "medcea/U/Z/sense/_test/scd30",
                  "medcea/U/Z/sense/co2/_health", "medcea/U/Z/sense/co2/_test")
        for topic in topics:
            with self.subTest(topic=topic):
                self.assertEqual(self.stored(topic, reading(sensor="scd30"))["msg_type"], "AP")
            for claim in ("HB", "TS"):
                with self.subTest(topic=topic, claim=claim):
                    r = run_func(self.func, [{"topic": topic, "payload": reading(msg_type=claim)}])[0]
                    self.assertTrue(r["ok"], r)
                    self.assertIsNone(r["out"])
                    self.assertEqual(r["warned"], ["dropped: %s is not allowed on %s" % (claim, topic)])

    def test_same_as_head_off_the_two_suffixes(self):
        # any other topic not claiming HB or TS, and any payload that is not an object, behaves as before:
        # the same result, or the same error (a null payload throws, as it always did)
        if not self.head:
            self.skipTest("git show HEAD unavailable")
        cases = [{"topic": "medcea/U/Z/sense/co2", "payload": reading()},
                 {"topic": "medcea/U/Z/sense/air_humidity/sht45_1",
                  "payload": reading(tag="air_humidity", sensor="sht45_1")},
                 {"topic": "medcea/U/Z/sense/co2", "payload": reading(msg_type="SP")},
                 {"topic": "medcea/U/Z/control_setpoint/light/_test", "payload": reading(msg_type="SP")},
                 {"topic": "medcea/U/Z/control/fan", "payload": reading(msg_type="CT")},
                 {"payload": reading()},
                 {"topic": "medcea/U/Z/sense/_health", "payload": "not json"},
                 {"topic": "medcea/U/Z/sense/_test", "payload": 42},
                 {"topic": "medcea/U/Z/sense/_test", "payload": None},
                 {"topic": "medcea/U/Z/sense/co2", "payload": None},
                 {"topic": "medcea/U/Z/sense/co2", "payload": "plain"}]
        self.assertEqual(run_func(self.func, cases), run_func(self.head, cases))


def read(name):
    with open(os.path.join(DB, name), encoding="utf-8") as f:
        return f.read()


def in_list(text):
    """The quoted two-letter values of a CHECK's list, in order."""
    return re.findall(r"'([A-Z]{2})'", text)


class Migration009Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        text = read("medcea_db_migrations.sql")
        cls.full = text
        start = text.index("-- ── Migration 009")
        cls.block = text[start:text.index("-- ── Migration 010")]   # 010 (feedback control) follows
        cls.before = text[:start]

    def test_last_and_after_008c(self):
        self.assertTrue(self.before.rstrip().endswith("COMMIT;"), "009 follows 008c's COMMIT")
        self.assertIn("'008c:last_nonce'", self.before)
        self.assertEqual(self.full.count("Migration 009"), 1)
        self.assertTrue(self.block.rstrip().endswith("COMMIT;"), "009 ends with its COMMIT, before 010")

    def test_its_own_transaction(self):
        stmts = [x for x in re.sub(r"--[^\n]*", "", self.block).split("\n") if x.strip()]
        self.assertEqual(stmts[0], "BEGIN;")
        self.assertEqual(stmts[1], "SET LOCAL lock_timeout = '5s';")
        self.assertEqual(stmts[-1], "COMMIT;")
        self.assertEqual(self.block.count("BEGIN;"), 1)
        self.assertEqual(self.block.count("DO $$"), 1)
        self.assertEqual(self.block.count("END $$;"), 1)
        # no nonce, no grant, no new object: the policy skeleton stays equal
        for word in ("deploy_nonce", "GRANT", "REVOKE", "CREATE ", "platform_setting"):
            self.assertNotIn(word, self.block)

    def test_the_exact_list(self):
        add = re.search(r"ADD CONSTRAINT msg_type_check\s+CHECK \(VALUE IN \(([^)]*)\)\) NOT VALID;", self.block)
        self.assertIsNotNone(add)
        self.assertEqual(in_list(add.group(1)), TYPES)
        self.assertNotIn("~", add.group(0))
        warn_query = re.search(r"NOT IN \(([^)]*)\)", self.block)
        self.assertEqual(in_list(warn_query.group(1).replace("''", "'")), TYPES)
        self.assertIn("AP, CT, SP, HB, TS", self.block)

    def test_altered_only_while_hb_is_refused(self):
        body = self.block[self.block.index("DO $$"):]
        probe = body.index("PERFORM 'HB'::medcea.msg_type, 'TS'::medcea.msg_type;")
        branch = body.index("IF NOT in_place THEN")
        drop = body.index("ALTER DOMAIN medcea.msg_type DROP CONSTRAINT IF EXISTS msg_type_check;")
        add = body.index("ALTER DOMAIN medcea.msg_type ADD CONSTRAINT msg_type_check")
        self.assertLess(probe, branch)
        self.assertLess(branch, drop)
        self.assertLess(drop, add)
        self.assertLess(add, body.index("END IF;", branch))
        self.assertIn("EXCEPTION WHEN check_violation THEN\n        in_place := false;", body)
        self.assertEqual(body.count("ALTER DOMAIN"), 3)

    def test_validated_only_while_not_valid_and_old_rows_only_warn(self):
        body = self.block[self.block.index("DO $$"):]
        guard = body.index("AND NOT convalidated) THEN\n        RETURN;")
        validate = body.index("ALTER DOMAIN medcea.msg_type VALIDATE CONSTRAINT msg_type_check;")
        self.assertLess(guard, validate)
        handler = body.index("EXCEPTION WHEN check_violation THEN", validate)
        self.assertLess(validate, handler)
        self.assertIn("RAISE WARNING 'medcea.msg_type: msg_type_check stays NOT VALID", body[handler:])
        self.assertNotIn("RAISE EXCEPTION", body)
        # a deploy against an older install without the domain is a no-op too
        self.assertIn("IF pg_catalog.to_regtype('medcea.msg_type') IS NULL THEN\n        RETURN;", body)


class DdlDomainTest(unittest.TestCase):

    def test_fresh_install_check_is_the_exact_list(self):
        ddl = read("medcea_db_ddl.sql")
        lines = [x for x in ddl.splitlines() if "msg_type_check" in x]
        self.assertEqual(len(lines), 1)
        self.assertNotIn("~", lines[0])
        self.assertIn("(VALUE)::text = ANY", lines[0])
        self.assertEqual(in_list(lines[0]), TYPES)
        self.assertIn("CREATE DOMAIN medcea.msg_type AS character varying(2)",
                      ddl[:ddl.index(lines[0])].rsplit("\n", 2)[-2])


if __name__ == "__main__":
    unittest.main()
