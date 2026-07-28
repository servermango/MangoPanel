import tempfile
import unittest
from pathlib import Path

from mangopanel.app import admin_clients_payload, delete_client
from mangopanel.db import connect, seed_dev_data


class AdminClientTests(unittest.TestCase):
    def test_admin_clients_payload_includes_accounts_and_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                clients = admin_clients_payload(conn)

            owner_client = next(c for c in clients if c["email"] == "owner@example.mango.test")
            self.assertIsNotNone(owner_client)
            self.assertEqual(owner_client["email"], "owner@example.mango.test")
            self.assertEqual(len(owner_client["accounts"]), 1)
            self.assertEqual(owner_client["accounts"][0]["plan_name"], "Dev Shared Starter")
            self.assertEqual(owner_client["accounts"][0]["website_count"], 1)

    def test_delete_client_removes_dependent_panel_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                for user in conn.execute("SELECT id FROM users").fetchall():
                    delete_client(conn, user["id"])

                self.assertEqual(conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) AS count FROM hosting_accounts").fetchone()["count"], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) AS count FROM websites").fetchone()["count"], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) AS count FROM domains").fetchone()["count"], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) AS count FROM dns_records").fetchone()["count"], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) AS count FROM activity_logs").fetchone()["count"], 0)


if __name__ == "__main__":
    unittest.main()
