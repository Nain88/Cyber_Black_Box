"""Self-contained unit + live loopback tests. No external targets or dependencies."""
import base64
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controller"))
sys.path.insert(0, str(ROOT / "kali"))
sys.path.insert(0, str(ROOT / "relay"))
from controller import State, validate_kali_url, SCENARIOS, run_scenario
from target import EvidenceStore, HmacAuth, DecoyHTTP, LabHTTPServer
from relay import signed_header, make_wire, canonical, validate_target, sync_once, get_kali_events
from unittest.mock import patch


class TestContracts(unittest.TestCase):
    def test_cancel_before_start_sends_nothing(self):
        cancel = threading.Event()
        cancel.set()
        with patch("controller.request") as request, patch("controller.socket.create_connection") as connect:
            for scenario in SCENARIOS:
                self.assertEqual(run_scenario("http://192.168.56.101:8088", scenario, cancel), [])
            request.assert_not_called()
            connect.assert_not_called()

    def test_stop_cancels_remaining_requests(self):
        state = State("http://192.168.56.101:8088", "long-unique-demo-password")
        entered, release = threading.Event(), threading.Event()
        def request(*args):
            entered.set()
            release.wait(2)
            return {"ok": True, "status": 401}
        with patch("controller.request", side_effect=request) as mocked:
            state.start("login-failures")
            self.assertTrue(entered.wait(2))
            self.assertTrue(state.stop()["stopping"])
            with self.assertRaises(RuntimeError): state.start("web-probes")
            release.set()
            import time
            deadline = time.monotonic() + 3
            while state.snapshot()["running"] and time.monotonic() < deadline:
                time.sleep(.01)
            snapshot = state.snapshot()
            self.assertFalse(snapshot["running"])
            self.assertEqual(snapshot["runs"][0]["state"], "STOPPED")
            self.assertEqual(mocked.call_count, 1)
            self.assertFalse(state.stop()["stopping"])

    def test_private_target_only(self):
        self.assertEqual(validate_kali_url("http://192.168.56.101:8088"), "http://192.168.56.101:8088")
        self.assertEqual(validate_target("http://10.0.0.2:8088"), "http://10.0.0.2:8088")
        for url in ("http://8.8.8.8:8088", "http://127.0.0.1:8088", "http://192.168.1.9:22", "https://192.168.1.9:8088", "http://example.org:8088"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_kali_url(url)

    def test_auth_replay_and_wrong_signature(self):
        auth = HmacAuth("LOCAL-ONLY-32-CHARACTER-TEST-SECRET")
        path = "/api/events?after=2&limit=20"
        headers = signed_header("LOCAL-ONLY-32-CHARACTER-TEST-SECRET", path)
        self.assertTrue(auth.verify("GET", path, headers["X-Lab-Timestamp"], headers["X-Lab-Nonce"], headers["X-Lab-Signature"]))
        self.assertFalse(auth.verify("GET", path, headers["X-Lab-Timestamp"], headers["X-Lab-Nonce"], headers["X-Lab-Signature"]))
        self.assertFalse(auth.verify("GET", path, "0", "anothernonce123456", "invalid"))

    def test_session_auth_and_cooldown(self):
        state = State("http://192.168.56.101:8088", "long-unique-demo-password")
        self.assertIsNone(state.login("127.0.0.1", "bad"))
        result = state.login("127.0.0.1", "long-unique-demo-password")
        self.assertIsNotNone(result)
        sid, csrf = result
        self.assertEqual(state.session(sid), csrf)
        state.logout(sid)
        self.assertIsNone(state.session(sid))
        self.assertEqual(len(SCENARIOS), 3)

    def test_persisted_events_and_wire_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp))
            event_id = store.add(category="lab.auth.failure", summary="LAB observed failed decoy login", source_ip="192.168.1.44", port=8088, details={"username": "lab-user"})
            self.assertEqual(event_id, 1)
            result = store.read(0, 20)[0]
            wire = make_wire(store.target_id, result)
            self.assertEqual(wire["source_type"], "lab.fixture")
            self.assertEqual(wire["source_seq"], "1")
            self.assertEqual(wire["boot_id"], store.target_id)
            self.assertEqual(make_wire(store.target_id, result), wire)  # Retries must be byte-for-byte identical
            self.assertEqual(json.loads(base64.b64decode(wire["raw_base64"]))["lab_simulation"], True)
            target_id = store.target_id
            store.conn.close()
            store = EvidenceStore(Path(tmp))
            self.assertEqual(store.target_id, target_id)
            self.assertEqual(store.count(), 1)
            store.conn.close()

    def test_observed_http_requests_require_hmac_for_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp))
            auth = HmacAuth("LOCAL-ONLY-32-CHARACTER-TEST-SECRET")
            server = LabHTTPServer(("127.0.0.1", 0), DecoyHTTP)
            server.store, server.auth = store, auth
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with self.assertRaises(HTTPError) as exc:
                    urlopen(base + "/.env", timeout=3)
                self.assertEqual(exc.exception.code, 404)
                req = Request(base + "/api/login", method="POST", data=canonical({"username": "demo", "password": "DONOTSTORE"}), headers={"Content-Type": "application/json"})
                with self.assertRaises(HTTPError) as exc:
                    urlopen(req, timeout=3)
                self.assertEqual(exc.exception.code, 401)
                self.assertEqual(store.count(), 2)
                path = "/api/events?after=0&limit=80"
                with self.assertRaises(HTTPError) as exc:
                    urlopen(base + path, timeout=3)
                self.assertEqual(exc.exception.code, 401)
                headers = signed_header("LOCAL-ONLY-32-CHARACTER-TEST-SECRET", path)
                with urlopen(Request(base + path, headers=headers), timeout=3) as resp:
                    items = json.loads(resp.read())["items"]
                self.assertEqual(len(items), 2)
                self.assertEqual(len(get_kali_events(base, "LOCAL-ONLY-32-CHARACTER-TEST-SECRET", 0)["items"]), 2)
                with self.assertRaises(RuntimeError):
                    get_kali_events(base, "WRONG-LOCAL-ONLY-32-CHARACTER-TEST-SECRET", 0)
                self.assertNotIn("DONOTSTORE", json.dumps(items))
                self.assertEqual(items[0]["event"]["event_type"], "lab.http.probe")
                self.assertEqual(items[1]["event"]["event_type"], "lab.auth.failure")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                store.conn.close()

    def test_end_to_end_http_scenarios_are_observed_on_kali(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp))
            auth = HmacAuth("LOCAL-ONLY-32-CHARACTER-TEST-SECRET")
            server = LabHTTPServer(("127.0.0.1", 0), DecoyHTTP)
            server.store, server.auth = store, auth
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            target = f"http://127.0.0.1:{server.server_port}"
            try:
                login = run_scenario(target, "login-failures")
                web = run_scenario(target, "web-probes")
                self.assertEqual(len(login), 6)
                self.assertEqual(len(web), 5)
                self.assertTrue(all(x["ok"] for x in login + web))
                self.assertEqual(store.count(), 11)
                self.assertEqual(len(store.read(0, 100)), 11)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                store.conn.close()

    def test_cursor_only_advances_after_durable_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            store = EvidenceStore(data)
            store.add(category="lab.port.probe", summary="LAB probe", source_ip="192.168.5.6", port=8089, details={"port": 8089})
            cfg = {"kali_base": "http://192.168.56.101:8088", "kali_key": "LOCAL-ONLY-32-CHARACTER-TEST-SECRET", "cloudbox_base": "http://127.0.0.1:8765", "collector_token": "test-token", "target_id": store.target_id, "cursor": 0}
            state = data / "config.json"
            with patch("relay.get_kali_events", return_value={"target_id": store.target_id, "items": store.read(0, 80)}):
                with patch("relay.api", side_effect=[{"items": [{"source_seq": "1", "outcome": "accepted", "preservation_state": "STAGED"}]}, {"signed_configuration": {}}]):
                    result = sync_once(cfg, state)
                    self.assertEqual(result["new_records"], 1)
                    self.assertEqual(json.loads(state.read_text())["cursor"], 1)
            store.conn.close()


if __name__ == "__main__":
    unittest.main()
