#!/usr/bin/env python3
"""edge/src/host/platform_db.py's broker credential (5 Nov 2026), offline: register_mqtt_credential
v2 (device id, the board's serial, the hash) is what onboarding calls; v1 (user, hash, device,
role, topic from the client) only where v2 cannot be called at all (IAM_DB_ROLES=false, where
the legacy anon holds v1 alone). Under IAM_DB_ROLES=true only v2 is granted, and the wizard's
v1 call was refused "permission denied for function register_mqtt_credential" (found live)."""
import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PDB = os.path.join(ROOT, "edge", "src", "host", "platform_db.py")

SPEC = {"mqtt_username": "unit01-s-zone01", "mqtt_password_hash": "$7$101$c2FsdA==$aGFzaA==",
        "device_type": "SENSE", "topic_base": "medcea/UNIT01/ZONE01", "serial_number": "A4CB8FDE739C"}


def load():
    spec = importlib.util.spec_from_file_location("platform_db_t", PDB)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class RegisterCredential(unittest.TestCase):
    def run_with(self, answers):
        """answers: values, or a str starting with 'ERR:' for a PlatformError of this module."""
        m = load()
        calls = []

        def fake(base, path, method="GET", body=None):
            calls.append(body)
            a = answers[len(calls) - 1]
            if isinstance(a, str) and a.startswith("ERR:"):
                raise m.PlatformError(a[4:])
            return a
        m._request = fake
        return m, calls

    def test_v2_with_the_boards_serial(self):
        m, calls = self.run_with(["unit01-s-zone01"])
        m._register_credential("http://x", 7, SPEC)
        self.assertEqual(calls, [{"p_device_id": 7, "p_serial": "a4cb8fde739c", "p_hash": SPEC["mqtt_password_hash"]}])

    def test_v1_only_when_v2_cannot_be_called(self):
        denied = ('ERR:POST /rpc/register_mqtt_credential -> HTTP 401 {"code":"42501","message":'
                  '"permission denied for function register_mqtt_credential"}')
        m, calls = self.run_with([denied, None])
        m._register_credential("http://x", 7, SPEC)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]["p_username"], "unit01-s-zone01")
        self.assertEqual(calls[1]["p_topic_base"], "medcea/UNIT01/ZONE01")

    def test_a_refusal_of_v2_itself_is_not_retried_as_v1(self):
        """v2's own refusals (another board's serial, an inactive device) must not be routed
        round its checks through v1."""
        refused = ('ERR:POST /rpc/register_mqtt_credential -> HTTP 401 {"code":"42501","message":'
                   '"register_mqtt_credential: serial x is not device 7\'s board"}')
        m, calls = self.run_with([refused])
        with self.assertRaises(m.PlatformError):
            m._register_credential("http://x", 7, SPEC)
        self.assertEqual(len(calls), 1)

    def test_a_name_the_board_was_not_given_is_an_error(self):
        m, calls = self.run_with(["unit01-s-zone01-3"])
        with self.assertRaises(m.PlatformError) as e:
            m._register_credential("http://x", 7, SPEC)
        self.assertIn("onboard it again", str(e.exception))



class ReOnboarding(unittest.TestCase):
    def test_old_components_are_retired_not_deleted(self):
        """No person holds DELETE on platform data (level D: records are retired); the
        re-onboarding of a registered slot was refused "permission denied for table
        component" under IAM_DB_ROLES=true (5 Nov 2026)."""
        m = load()
        calls = []
        retire = ("PATCH", "/component?device_id=eq.1&is_active=eq.Y", {"is_active": "N"})

        def fake(base, path, method="GET", body=None):
            calls.append((method, path, body))
            if method == "GET" and path.startswith("/device?select=device_id"):
                return [{"device_id": 1}]
            if path.startswith("/rpc/register_mqtt_credential"):
                return "unit01-s-zone01"
            return []
        m._request = fake
        m._insert_component = lambda base, comp: calls.append(("INSERT", "/component", comp))
        spec = dict(SPEC, dns_name="unit01-s-zone01", zone_id=1, model="ESP32-S3",
                    components=[{"component_type": "SENSOR", "parameters": {}}])
        self.assertEqual(m.register("http://x", spec), (1, "updated"))
        self.assertNotIn("DELETE", [c[0] for c in calls])
        self.assertIn(retire, calls)
        insert = [i for i, c in enumerate(calls) if c[0] == "INSERT"][0]
        self.assertLess(calls.index(retire), insert)        # retired first, then the new rows


if __name__ == "__main__":
    unittest.main()
