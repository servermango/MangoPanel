import json
import tempfile
import unittest
from pathlib import Path

from mangopanel.app import MangoHandler, create_jwt
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data


class ComprehensiveClientAPISecurityTests(unittest.TestCase):
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

        # Create two distinct users for tenant isolation testing
        with connect(self.db_path) as conn:
            conn.execute("UPDATE plans SET allow_api_access = 1")
            user1 = conn.execute("SELECT * FROM users ORDER BY id LIMIT 1").fetchone()
            self.user1_id = user1["id"]
            self.user1_acc = conn.execute("SELECT * FROM hosting_accounts WHERE user_id = ? LIMIT 1", (self.user1_id,)).fetchone()

            user2 = conn.execute("SELECT * FROM users WHERE id != ? LIMIT 1", (self.user1_id,)).fetchone()
            if not user2:
                cur = conn.execute(
                    "INSERT INTO users (email, password_hash, full_name, status) VALUES ('user2@test.com', 'hash', 'User Two', 'active')"
                )
                user2_id = cur.lastrowid
                plan = conn.execute("SELECT id FROM plans LIMIT 1").fetchone()
                node = conn.execute("SELECT id FROM nodes LIMIT 1").fetchone()
                cur_acc = conn.execute(
                    "INSERT INTO hosting_accounts (user_id, plan_id, node_id, username, base_path, status) VALUES (?, ?, ?, 'u000002', ?, 'active')",
                    (user2_id, plan["id"], node["id"], str(Path(self.tmp_dir.name) / "accounts" / "u000002")),
                )
                self.user2_id = user2_id
                self.user2_acc = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (cur_acc.lastrowid,)).fetchone()
            else:
                self.user2_id = user2["id"]
                self.user2_acc = conn.execute("SELECT * FROM hosting_accounts WHERE user_id = ? LIMIT 1", (self.user2_id,)).fetchone()

        self.user1_jwt = create_jwt({"sub": self.user1_id, "actor_type": "user", "purpose": "access"}, self.config.jwt_secret, 3600)
        self.user2_jwt = create_jwt({"sub": self.user2_id, "actor_type": "user", "purpose": "access"}, self.config.jwt_secret, 3600)

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
        handler.server = type("Server", (), {"panel": "client"})()
        handler.send_header = lambda k, v: None
        handler.send_response = lambda code: None
        handler.end_headers = lambda: None
        return handler

    def test_unauthenticated_requests_rejected(self):
        handler = self.make_handler(auth_header=None)
        protected_endpoints = [
            ("GET", "/api/client/home"),
            ("GET", "/api/client/websites"),
            ("GET", "/api/client/dns-records"),
            ("GET", "/api/client/databases"),
            ("GET", "/api/client/mailboxes"),
            ("GET", "/api/client/cron-jobs"),
            ("GET", "/api/client/ssh"),
            ("GET", "/api/client/resource-usage"),
            ("GET", "/api/client/api-tokens"),
        ]
        for method, endpoint in protected_endpoints:
            with self.assertRaises(Exception) as cm:
                handler.require_auth("user")
            self.assertIn("missing_bearer_token", str(cm.exception))

    def test_tenant_isolation_x_account_header_forgery_blocked(self):
        handler = self.make_handler(auth_header=f"Bearer {self.user1_jwt}")
        handler.headers["X-Hosting-Account-ID"] = str(self.user2_acc["id"])
        actor = handler.require_auth("user")
        with self.assertRaises(Exception) as cm:
            handler.client_api("GET", "/api/client/websites", {}, actor)
        self.assertIn("hosting_account_access_denied", str(cm.exception))

    def test_maintenance_mode_blocks_mutations(self):
        with connect(self.db_path) as conn:
            conn.execute("UPDATE hosting_accounts SET status = 'rebuilding' WHERE id = ?", (self.user1_acc["id"],))

        handler = self.make_handler(auth_header=f"Bearer {self.user1_jwt}")
        actor = handler.require_auth("user")

        with self.assertRaises(Exception) as cm:
            body = json.dumps({"domain": "newsite.com"}).encode("utf-8")
            handler.headers["Content-Length"] = str(len(body))
            handler.rfile = tempfile.SpooledTemporaryFile()
            handler.rfile.write(body)
            handler.rfile.seek(0)
            handler.client_api("POST", "/api/client/websites", {}, actor)
        self.assertIn("account_maintenance_in_progress", str(cm.exception))

        with connect(self.db_path) as conn:
            conn.execute("UPDATE hosting_accounts SET status = 'active' WHERE id = ?", (self.user1_acc["id"],))

    def test_comprehensive_endpoint_crud_flow(self):
        handler = self.make_handler(auth_header=f"Bearer {self.user1_jwt}")
        actor = handler.require_auth("user")

        # 1. Overview & Home
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("GET", "/api/client/home", {}, actor)
        handler.wfile.seek(0)
        home = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("resources", home)

        # 2. Websites CRUD
        site_body = json.dumps({"domain": "mysecuresite.test", "php_version": "8.3"}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(site_body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(site_body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("POST", "/api/client/websites", {}, actor)
        handler.wfile.seek(0)
        site_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("website", site_resp)
        site_id = site_resp["website"]["id"]
        domain_id = site_resp["website"]["domain_record"]["id"]

        # 3. DNS Records CRUD
        dns_body = json.dumps({"domain_id": domain_id, "name": "api", "type": "A", "value": "127.0.0.1", "ttl": 300}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(dns_body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(dns_body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("POST", "/api/client/dns-records", {}, actor)
        handler.wfile.seek(0)
        dns_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("dns_record_id", dns_resp)
        rec_id = dns_resp["dns_record_id"]

        # Delete DNS record
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("DELETE", f"/api/client/dns-records/{rec_id}", {}, actor)
        handler.wfile.seek(0)
        del_dns = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertTrue(del_dns.get("deleted"))

        # 4. Databases CRUD
        db_body = json.dumps({"name": "appdb"}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(db_body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(db_body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("POST", "/api/client/databases", {}, actor)
        handler.wfile.seek(0)
        db_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("database_id", db_resp)
        db_id = db_resp["database_id"]

        # Delete database
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("DELETE", f"/api/client/databases/{db_id}", {}, actor)
        handler.wfile.seek(0)
        del_db = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertTrue(del_db.get("deleted"))

        # 5. Mailboxes CRUD
        mail_body = json.dumps({"email": "hello@mysecuresite.test", "password": "Password123!", "quota_mb": 512}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(mail_body))
        handler.rfile = tempfile.SpooledTemporaryFile()
        handler.rfile.write(mail_body)
        handler.rfile.seek(0)
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("POST", "/api/client/mailboxes", {}, actor)
        handler.wfile.seek(0)
        mail_resp = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertIn("mailbox", mail_resp)
        mail_id = mail_resp["mailbox"]["id"]

        # Delete mailbox
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("DELETE", f"/api/client/mailboxes/{mail_id}", {}, actor)
        handler.wfile.seek(0)
        del_mail = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertTrue(del_mail.get("deleted"))

        # 6. Delete website
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api("DELETE", f"/api/client/websites/{site_id}", {}, actor)
        handler.wfile.seek(0)
        del_site = json.loads(handler.wfile.read().decode("utf-8"))
        self.assertTrue(del_site.get("deleted"))


if __name__ == "__main__":
    unittest.main()
