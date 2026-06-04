import tempfile
import unittest
from pathlib import Path

from mangopanel.db import connect, ensure_schema, seed_dev_data
from mangopanel.providers import ACME_PROVIDER_LOCAL, DNS_PROVIDER_LOCAL, MAIL_EDGE_PROVIDER_SHARED


class DatabaseTests(unittest.TestCase):
    def test_seed_creates_foundation_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")
            with connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"], 1)
                self.assertGreaterEqual(conn.execute("SELECT COUNT(*) AS c FROM status_components").fetchone()["c"], 1)
                self.assertGreaterEqual(conn.execute("SELECT COUNT(*) AS c FROM hosting_accounts").fetchone()["c"], 1)
                self.assertGreaterEqual(conn.execute("SELECT COUNT(*) AS c FROM jobs WHERE status = 'queued'").fetchone()["c"], 1)

    def test_phase1_provider_seed_rows_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")
            with connect(db_path) as conn:
                zone = conn.execute("SELECT * FROM dns_zones WHERE zone_name = ?", ("example.mango.test",)).fetchone()
                self.assertIsNotNone(zone)
                self.assertEqual(zone["provider"], DNS_PROVIDER_LOCAL)
                self.assertIn("ns1.mango.test", zone["nameservers_json"])

                order = conn.execute("SELECT * FROM acme_certificate_orders WHERE domain = ?", ("example.mango.test",)).fetchone()
                self.assertIsNotNone(order)
                self.assertEqual(order["provider"], ACME_PROVIDER_LOCAL)
                self.assertEqual(order["status"], "issued")
                self.assertTrue(order["certificate_id"])

                route = conn.execute("SELECT * FROM mail_edge_routes WHERE domain = ?", ("example.mango.test",)).fetchone()
                self.assertIsNotNone(route)
                self.assertEqual(route["provider"], MAIL_EDGE_PROVIDER_SHARED)
                self.assertEqual(route["edge_host"], "mail.mango.test")
                self.assertIn("hello@example.mango.test", route["manifest_json"])

                token = conn.execute("SELECT * FROM mailbox_launch_tokens WHERE token_id = ?", ("dev-webmail-u000001-hello",)).fetchone()
                self.assertIsNotNone(token)
                self.assertEqual(token["purpose"], "webmail")
                self.assertEqual(token["status"], "active")

    def test_phase1_schema_is_additive_for_existing_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")
            with connect(db_path) as conn:
                ensure_schema(conn)
                for table in ("dns_zones", "acme_certificate_orders", "mail_edge_routes", "mailbox_launch_tokens"):
                    row = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (table,),
                    ).fetchone()
                    self.assertIsNotNone(row, table)


if __name__ == "__main__":
    unittest.main()
