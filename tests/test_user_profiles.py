import json
import tempfile
import unittest
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.app import MangoHandler, create_jwt
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from mangopanel.security import totp_code


class UserProfileSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.config = Config()
        self.config.db_path = root / "mangopanel.sqlite3"
        self.config.data_dir = root
        self.config.user_files_dir = root / "accounts"
        self.config.agent_mode = "simulate"
        self.config.dev_auth_test_mode = True
        seed_dev_data(self.config.db_path, self.config.user_files_dir)
        self.original_config = app_module.CONFIG
        app_module.CONFIG = self.config
        with connect(self.config.db_path) as conn:
            self.user = conn.execute("SELECT * FROM users WHERE email = ?", ("owner@example.mango.test",)).fetchone()
            self.admin = conn.execute("SELECT * FROM admins WHERE email = ?", ("admin@mango.test",)).fetchone()
        self.user_token = create_jwt({"sub": self.user["id"], "actor_type": "user", "purpose": "access", "jti": "profile-user"}, self.config.jwt_secret, 3600)
        self.admin_token = create_jwt({"sub": self.admin["id"], "actor_type": "admin", "purpose": "access", "jti": "profile-admin"}, self.config.jwt_secret, 3600)

    def tearDown(self):
        app_module.CONFIG = self.original_config
        self.tmp.cleanup()

    def handler(self, panel, token):
        handler = MangoHandler.__new__(MangoHandler)
        handler.headers = {"Authorization": f"Bearer {token}"}
        handler.client_address = ("127.0.0.1", 12345)
        handler.server = type("Server", (), {"panel": panel})()
        handler.send_header = lambda *_args: None
        handler.send_response = lambda *_args: None
        handler.end_headers = lambda: None
        return handler

    def call(self, handler, method, path, body=None):
        if body is not None:
            encoded = json.dumps(body).encode()
            handler.headers["Content-Length"] = str(len(encoded))
            handler.rfile = tempfile.SpooledTemporaryFile()
            handler.rfile.write(encoded)
            handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        actor = handler.require_auth("user" if handler.server.panel == "client" else "admin")
        if handler.server.panel == "client":
            handler.client_api(method, path, {}, actor)
        else:
            handler.admin_api(method, path, {}, actor)
        handler.wfile.seek(0)
        return json.loads(handler.wfile.read().decode())

    def test_user_profile_billing_and_sensitive_email_change(self):
        handler = self.handler("client", self.user_token)
        profile = self.call(handler, "GET", "/api/client/profile")["profile"]
        self.assertFalse(profile["billing"]["company_name"])
        self.assertNotIn("password_hash", profile)
        self.assertNotIn("totp_secret", profile)

        with self.assertRaises(Exception) as exc:
            self.call(handler, "PATCH", "/api/client/profile", {"email": "new@example.mango.test"})
        self.assertIn("current_password_required_for_email_change", str(exc.exception))

        with connect(self.config.db_path) as conn:
            conn.execute(
                "INSERT INTO sessions(actor_type, actor_id, token_id, expires_at) VALUES ('user', ?, 'profile-session', 9999999999)",
                (self.user["id"],),
            )
        updated = self.call(
            handler,
            "PATCH",
            "/api/client/profile",
            {
                "email": "new@example.mango.test",
                "full_name": "Updated Owner",
                "billing": {"company_name": "Mango Labs", "country": "India"},
                "current_password": "ChangeMe-DevOnly-123!",
                "totp_code": totp_code(self.user["totp_secret"]),
            },
        )
        self.assertTrue(updated["reauth_required"])
        self.assertEqual(updated["profile"]["billing"]["company_name"], "Mango Labs")
        with connect(self.config.db_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM sessions WHERE actor_type = 'user' AND actor_id = ?", (self.user["id"],)).fetchone()["c"], 0)

    def test_admin_profile_requires_reauthentication_and_can_manage_2fa(self):
        handler = self.handler("admin", self.admin_token)
        with self.assertRaises(Exception) as exc:
            self.call(handler, "PATCH", f"/api/admin/clients/{self.user['id']}/profile", {"full_name": "Nope"})
        self.assertIn("admin_reauthentication_failed", str(exc.exception))

        updated = self.call(
            handler,
            "PATCH",
            f"/api/admin/clients/{self.user['id']}/profile",
            {
                "full_name": "Admin Updated Owner",
                "email": self.user["email"],
                "billing": {"tax_id": "IN-TAX-123"},
                "admin_password": "ChangeMe-DevOnly-123!",
                "admin_totp_code": totp_code(self.admin["totp_secret"]),
            },
        )
        self.assertEqual(updated["profile"]["full_name"], "Admin Updated Owner")
        self.assertEqual(updated["profile"]["billing"]["tax_id"], "IN-TAX-123")

        rotated = self.call(
            handler,
            "POST",
            f"/api/admin/clients/{self.user['id']}/2fa",
            {
                "action": "rotate",
                "admin_password": "ChangeMe-DevOnly-123!",
                "admin_totp_code": totp_code(self.admin["totp_secret"]),
            },
        )
        self.assertTrue(rotated["enabled"])
        self.assertTrue(rotated["totp_secret"])


if __name__ == "__main__":
    unittest.main()
