import json
import tempfile
import unittest
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.app import (
    MangoHandler,
    create_jwt,
    get_collaborator_scope,
    require_collaborator_permission,
    require_owned_database,
    require_owned_website,
)
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data


class DatabaseAdminAndCollaboratorOwnershipTests(unittest.TestCase):
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
            self.owner = conn.execute("SELECT * FROM users WHERE email = ?", ("owner@example.mango.test",)).fetchone()
            self.admin = conn.execute("SELECT * FROM admins LIMIT 1").fetchone()
            self.account = conn.execute(
                "SELECT * FROM hosting_accounts WHERE user_id = ? ORDER BY id LIMIT 1",
                (self.owner["id"],),
            ).fetchone()
            collab = conn.execute(
                "INSERT INTO users(email, password_hash, full_name, status) VALUES (?, ?, ?, 'active')",
                ("creator@example.mango.test", "hash", "Creator"),
            )
            self.collab_id = collab.lastrowid
            perms = {
                "all_websites": False,
                "website_ids": [],
                "all_databases": False,
                "database_ids": [],
                "allowed_menus": ["websites", "files", "databases"],
                "can_create_websites": True,
                "can_edit_websites": False,
                "can_delete_websites": False,
                "can_create_databases": True,
                "can_edit_databases": False,
                "can_delete_databases": False,
            }
            conn.execute(
                """
                INSERT INTO collaborators(
                    owner_user_id, invited_email, invited_name, target_user_id,
                    hosting_account_id, permissions_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, 'active')
                """,
                (
                    self.owner["id"],
                    "creator@example.mango.test",
                    "Creator",
                    self.collab_id,
                    self.account["id"],
                    json.dumps(perms),
                ),
            )
            self.website_id = conn.execute(
                """
                INSERT INTO websites(account_id, domain, document_root, created_by_user_id)
                VALUES (?, 'creator.example.test', '/tmp/creator', ?)
                """,
                (self.account["id"], self.collab_id),
            ).lastrowid
            self.database_id = conn.execute(
                """
                INSERT INTO databases(account_id, name, username, created_by_user_id)
                VALUES (?, 'creator_db', 'creator_db', ?)
                """,
                (self.account["id"], self.collab_id),
            ).lastrowid
            conn.execute(
                """
                INSERT INTO script_installs(
                    website_id, script_id, database_id, site_title,
                    admin_username, admin_email, status
                ) VALUES (?, 'test-script', ?, 'Creator site', 'admin', 'creator@example.mango.test', 'installed')
                """,
                (self.website_id, self.database_id),
            )
            self.other_website_id = conn.execute(
                "INSERT INTO websites(account_id, domain, document_root) VALUES (?, 'owner.example.test', '/tmp/owner')",
                (self.account["id"],),
            ).lastrowid
            self.other_database_id = conn.execute(
                "INSERT INTO databases(account_id, name, username) VALUES (?, 'owner_db', 'owner_db')",
                (self.account["id"],),
            ).lastrowid

    def tearDown(self):
        app_module.CONFIG = self.original_config
        self.tmp.cleanup()

    def test_collaborator_created_resources_are_visible_and_fully_manageable(self):
        scope = get_collaborator_scope(self._conn(), self.collab_id, self.account["id"])
        self.assertIn(self.website_id, scope["allowed_website_ids"])
        self.assertIn(self.database_id, scope["allowed_database_ids"])
        self.assertIn(self.website_id, scope["owned_website_ids"])
        self.assertIn(self.database_id, scope["owned_database_ids"])

        require_owned_website(self._conn(), self.account["id"], self.website_id, self.collab_id)
        require_owned_database(self._conn(), self.account["id"], self.database_id, self.collab_id)
        require_collaborator_permission(
            self._conn(), self.collab_id, self.account["id"], "can_delete_websites",
            resource_type="website", resource_id=self.website_id,
        )
        require_collaborator_permission(
            self._conn(), self.collab_id, self.account["id"], "can_delete_databases",
            resource_type="database", resource_id=self.database_id,
        )
        with self.assertRaises(Exception):
            require_owned_website(self._conn(), self.account["id"], self.other_website_id, self.collab_id)
        with self.assertRaises(Exception):
            require_owned_database(self._conn(), self.account["id"], self.other_database_id, self.collab_id)

    def test_admin_can_list_and_delete_database_and_queue_cleanup(self):
        token = create_jwt(
            {"sub": self.admin["id"], "actor_type": "admin", "purpose": "access"},
            self.config.jwt_secret,
            3600,
        )
        handler = self._handler(token)
        listed = self._call(handler, "GET", f"/api/admin/hosting-accounts/{self.account['id']}/databases")
        ids = {item["id"] for item in listed["databases"]}
        self.assertIn(self.database_id, ids)

        deleted = self._call(handler, "DELETE", f"/api/admin/databases/{self.database_id}")
        self.assertTrue(deleted["deleted"])
        with connect(self.config.db_path) as conn:
            self.assertIsNone(conn.execute("SELECT id FROM databases WHERE id = ?", (self.database_id,)).fetchone())
            self.assertIsNone(conn.execute(
                "SELECT database_id FROM script_installs WHERE website_id = ?",
                (self.website_id,),
            ).fetchone()["database_id"])
            job = conn.execute("SELECT * FROM jobs WHERE id = ?", (deleted["job_id"],)).fetchone()
            self.assertEqual(job["type"], "delete_database")
            self.assertEqual(json.loads(job["payload"])["name"], "creator_db")

    def test_client_database_delete_clears_script_install_reference(self):
        handler = self._handler("")
        handler.server = type("Server", (), {"panel": "client"})()
        deleted = self._call_client(
            handler,
            "DELETE",
            f"/api/client/databases/{self.database_id}",
            {"id": self.owner["id"], "actor_type": "user"},
        )
        self.assertTrue(deleted["deleted"])
        with connect(self.config.db_path) as conn:
            self.assertIsNone(conn.execute("SELECT id FROM databases WHERE id = ?", (self.database_id,)).fetchone())
            self.assertIsNone(conn.execute(
                "SELECT database_id FROM script_installs WHERE website_id = ?",
                (self.website_id,),
            ).fetchone()["database_id"])

    def _conn(self):
        return connect(self.config.db_path)

    def _handler(self, token):
        handler = MangoHandler.__new__(MangoHandler)
        handler.headers = {"Authorization": f"Bearer {token}"}
        handler.client_address = ("127.0.0.1", 12345)
        handler.server = type("Server", (), {"panel": "admin"})()
        handler.send_header = lambda *_args: None
        handler.send_response = lambda *_args: None
        handler.end_headers = lambda: None
        return handler

    def _call(self, handler, method, path):
        handler.wfile = tempfile.SpooledTemporaryFile()
        actor = handler.require_auth("admin")
        handler.admin_api(method, path, {}, actor)
        handler.wfile.seek(0)
        return json.loads(handler.wfile.read().decode())

    def _call_client(self, handler, method, path, actor):
        handler.wfile = tempfile.SpooledTemporaryFile()
        handler.client_api(method, path, {}, actor)
        handler.wfile.seek(0)
        return json.loads(handler.wfile.read().decode())


if __name__ == "__main__":
    unittest.main()
