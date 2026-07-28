import json
import tempfile
import unittest
from pathlib import Path

from mangopanel.app import MangoHandler, create_jwt
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data


class PlanAPIToggleAndAdminTokensTests(unittest.TestCase):
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
            user = conn.execute("SELECT * FROM users LIMIT 1").fetchone()
            self.user_id = user["id"]
            self.user_acc = conn.execute("SELECT * FROM hosting_accounts WHERE user_id = ? LIMIT 1", (self.user_id,)).fetchone()
            admin = conn.execute("SELECT * FROM admins LIMIT 1").fetchone()
            self.admin_id = admin["id"]

        self.user_jwt = create_jwt({"sub": self.user_id, "actor_type": "user", "purpose": "access"}, self.config.jwt_secret, 3600)
        self.admin_jwt = create_jwt({"sub": self.admin_id, "actor_type": "admin", "purpose": "access"}, self.config.jwt_secret, 3600)

    def tearDown(self):
        import mangopanel.app as app_mod
        app_mod.CONFIG = self.orig_config
        self.tmp_dir.cleanup()

    def make_handler(self, auth_header=None, query=None):
        handler = MangoHandler.__new__(MangoHandler)
        handler.headers = {}
        if auth_header:
            handler.headers["Authorization"] = auth_header
        handler.query_params = query or {}
        handler.client_address = ("127.0.0.1", 12345)
        handler.server = type("Server", (), {"panel": "admin"})()
        handler.send_header = lambda k, v: None
        handler.send_response = lambda code: None
        handler.end_headers = lambda: None
        return handler

    def test_plan_api_access_disabled_blocks_token_creation_and_api_use(self):
        # 1. Ensure account's plan has allow_api_access = 0 (Off by default)
        with connect(self.db_path) as conn:
            conn.execute("UPDATE plans SET allow_api_access = 0 WHERE id = ?", (self.user_acc["plan_id"],))

        handler = self.make_handler(auth_header=f"Bearer {self.user_jwt}")
        actor = handler.require_auth("user")

        # Attempt to create API token when disabled
        with self.assertRaises(Exception) as cm:
            body = json.dumps({"name": "Test Token"}).encode("utf-8")
            handler.headers["Content-Length"] = str(len(body))
            handler.rfile = tempfile.SpooledTemporaryFile()
            handler.rfile.write(body)
            handler.rfile.seek(0)
            handler.client_api("POST", "/api/client/api-tokens", {}, actor)
        self.assertIn("api_access_disabled_for_plan", str(cm.exception))

        # 2. Enable allow_api_access = 1 on plan
        with connect(self.db_path) as conn:
            conn.execute("UPDATE plans SET allow_api_access = 1 WHERE id = ?", (self.user_acc["plan_id"],))

        # Now creation succeeds
        body = json.dumps({"name": "Allowed Token"}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("POST", "/api/client/api-tokens", {}, actor)
        handler.wfile.seek(0)
        resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("token", resp)
        raw_token = resp["token"]

        # Token auth works while plan allows API access
        handler.headers = {"Authorization": f"Bearer {raw_token}"}
        actor = handler.require_auth("user")
        self.assertEqual(actor["id"], self.user_id)

        # Disable API access again on plan
        with connect(self.db_path) as conn:
            conn.execute("UPDATE plans SET allow_api_access = 0 WHERE id = ?", (self.user_acc["plan_id"],))

        # Existing token now fails authentication
        with self.assertRaises(Exception) as cm:
            handler.require_auth("user")
        self.assertIn("api_access_disabled_for_plan", str(cm.exception))

    def test_admin_api_token_creation_and_granular_permissions(self):
        handler = self.make_handler(auth_header=f"Bearer {self.admin_jwt}")
        actor = handler.require_auth("admin")

        # 1. Create Admin API Token with granular permissions ["clients.manage"]
        body = json.dumps({"name": "Client Manager Token", "permissions": ["clients.manage"]}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("POST", "/api/admin/api-tokens", {}, actor)
        handler.wfile.seek(0)
        resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("token", resp)
        admin_token = resp["token"]
        self.assertTrue(admin_token.startswith("mp_admin_"))

        # 2. Authenticate using Admin API Token
        handler.headers = {"Authorization": f"Bearer {admin_token}"}
        token_actor = handler.require_auth("admin")
        self.assertEqual(token_actor["id"], self.admin_id)
        self.assertEqual(token_actor["permissions"], ["clients.manage"])

        # 3. Allowed operation (clients.manage) passes
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.admin_api("GET", "/api/admin/clients", {}, token_actor)
        handler.wfile.seek(0)
        clients_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("clients", clients_resp)

        # 4. Disallowed operation (system.manage) fails with insufficient_admin_permissions
        with self.assertRaises(Exception) as cm:
            handler.admin_api("POST", "/api/admin/storage/cleanup", {}, token_actor)
        self.assertIn("insufficient_admin_permissions", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
