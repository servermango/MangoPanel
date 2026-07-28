import json
import tempfile
import unittest
from pathlib import Path

from mangopanel.app import MangoHandler, create_jwt
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data


class APITokenAuthTests(unittest.TestCase):
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

    def tearDown(self):
        import mangopanel.app as app_mod
        app_mod.CONFIG = self.orig_config
        self.tmp_dir.cleanup()

    def test_api_token_authentication_flow(self):
        with connect(self.db_path) as conn:
            conn.execute("UPDATE plans SET allow_api_access = 1")
            user = conn.execute("SELECT * FROM users LIMIT 1").fetchone()
            user_id = user["id"]

        jwt_token = create_jwt(
            {"sub": user_id, "actor_type": "user", "purpose": "access"},
            self.config.jwt_secret,
            3600,
        )

        handler = MangoHandler.__new__(MangoHandler)
        handler.query_params = {}
        handler.client_address = ("127.0.0.1", 12345)
        handler.server = type("Server", (), {"panel": "client"})()
        handler.send_header = lambda k, v: None
        handler.send_response = lambda code: None
        handler.end_headers = lambda: None

        # 1. Create an API token using JWT auth
        token_payload = json.dumps({"name": "Test Automation Key"}).encode("utf-8")
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(token_payload)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.headers = {"Authorization": f"Bearer {jwt_token}", "Content-Length": str(len(token_payload))}
        
        actor = handler.require_auth("user")
        handler.client_api("POST", "/api/client/api-tokens", {}, actor)
        handler.wfile.seek(0)
        create_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("token", create_resp)
        api_token = create_resp["token"]
        self.assertTrue(api_token.startswith("mp_"))

        # 2. Authenticate using the new API token via Authorization Bearer header
        handler.headers = {"Authorization": f"Bearer {api_token}"}
        actor = handler.require_auth("user")
        self.assertEqual(actor["id"], user_id)
        self.assertIsNotNone(actor.get("api_token_account_id"))

        # Test GET /api/client/home using API token
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("GET", "/api/client/home", {}, actor)
        handler.wfile.seek(0)
        home_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("user", home_resp)

        # 3. Authenticate using X-API-Key header
        handler.headers = {"X-API-Key": api_token}
        actor = handler.require_auth("user")
        self.assertEqual(actor["id"], user_id)

        # 4. Authenticate using query param ?api_key=mp_...
        handler.headers = {}
        handler.query_params = {"api_key": [api_token]}
        actor = handler.require_auth("user")
        self.assertEqual(actor["id"], user_id)

        # 5. Test invalid API token rejection
        handler.headers = {"Authorization": "Bearer mp_invalid00000000000000000000000000000000000000000000000000000000000000"}
        handler.query_params = {}
        with self.assertRaises(Exception):
            handler.require_auth("user")


if __name__ == "__main__":
    unittest.main()
