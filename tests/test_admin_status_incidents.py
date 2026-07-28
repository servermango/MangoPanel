import json
import tempfile
import unittest
from pathlib import Path

from mangopanel.app import MangoHandler, create_jwt
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data


class AdminStatusIncidentsTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "mangopanel.sqlite3"
        seed_dev_data(self.db_path, Path(self.tmp_dir.name) / "accounts")

        self.config = Config()
        self.config.db_path = self.db_path
        self.config.data_dir = Path(self.tmp_dir.name)
        self.config.user_files_dir = Path(self.tmp_dir.name) / "accounts"
        self.config.agent_mode = "simulate"
        self.config.dev_auth_test_mode = True

        import mangopanel.app as app_mod
        self.orig_config = app_mod.CONFIG
        app_mod.CONFIG = self.config

        with connect(self.db_path) as conn:
            admin = conn.execute("SELECT * FROM admins LIMIT 1").fetchone()
            self.admin_id = admin["id"]

        self.admin_jwt = create_jwt({"sub": self.admin_id, "actor_type": "admin", "purpose": "access"}, self.config.jwt_secret, 3600)

    def tearDown(self):
        import mangopanel.app as app_mod
        app_mod.CONFIG = self.orig_config
        self.tmp_dir.cleanup()

    def make_handler(self, auth_header=None):
        handler = MangoHandler.__new__(MangoHandler)
        handler.headers = {}
        if auth_header:
            handler.headers["Authorization"] = auth_header
        handler.query_params = {}
        handler.client_address = ("127.0.0.1", 12345)
        handler.server = type("Server", (), {"panel": "admin"})()
        handler.send_header = lambda k, v: None
        handler.send_response = lambda code: None
        handler.end_headers = lambda: None
        return handler

    def test_incident_lifecycle(self):
        handler = self.make_handler(auth_header=f"Bearer {self.admin_jwt}")
        actor = handler.require_auth("admin")

        # 1. Create Incident
        body = json.dumps({
            "title": "Database Latency Investigation",
            "severity": "minor",
            "state": "investigating",
            "message": "Investigating high query latency.",
            "published": True
        }).encode("utf-8")
        handler.headers["Content-Length"] = str(len(body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("POST", "/api/admin/status/incidents", {}, actor)
        handler.wfile.seek(0)
        resp = json.loads(handler.wfile.read().decode("utf-8"))
        inc_id = resp["incident_id"]

        # 2. List Incidents
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("GET", "/api/admin/status/incidents", {}, actor)
        handler.wfile.seek(0)
        list_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertTrue(any(i["id"] == inc_id for i in list_resp["incidents"]))

        # 3. Post Update (state: identified)
        upd_body = json.dumps({"state": "identified", "message": "Root cause identified as index lock."}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(upd_body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(upd_body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("POST", f"/api/admin/status/incidents/{inc_id}/updates", {}, actor)
        handler.wfile.seek(0)
        upd_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertEqual(upd_resp["status"], "updated")

        # 4. Post Update (state: resolved)
        res_body = json.dumps({"state": "resolved", "message": "Fix applied and verified."}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(res_body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(res_body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("POST", f"/api/admin/status/incidents/{inc_id}/updates", {}, actor)

        # Verify incident is resolved in list
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("GET", "/api/admin/status/incidents", {}, actor)
        handler.wfile.seek(0)
        list_resp = json.loads(handler.wfile.read().decode("utf-8"))
        target_inc = next(i for i in list_resp["incidents"] if i["id"] == inc_id)
        self.assertEqual(target_inc["state"], "resolved")
        self.assertEqual(len(target_inc["updates"]), 3)

        # 5. Delete Incident
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("DELETE", f"/api/admin/status/incidents/{inc_id}", {}, actor)
        handler.wfile.seek(0)
        del_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertTrue(del_resp["deleted"])

    def test_queue_worker_component_override(self):
        handler = self.make_handler(auth_header=f"Bearer {self.admin_jwt}")
        actor = handler.require_auth("admin")

        # Update queue-worker component status to operational
        qw_body = json.dumps({"status": "operational"}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(qw_body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(qw_body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("PATCH", "/api/admin/status/components/queue-worker", {}, actor)
        handler.wfile.seek(0)
        resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertEqual(resp["component"]["status"], "operational")


if __name__ == "__main__":
    unittest.main()
