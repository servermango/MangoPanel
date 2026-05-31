import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path

from mangopanel.app import ApiError, require_active_account, require_plan_capacity
from mangopanel.db import connect, seed_dev_data


class PlanLimitTests(unittest.TestCase):
    def test_website_limit_blocks_second_site_when_plan_allows_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                conn.execute("UPDATE plans SET max_websites = 1 WHERE id = ?", (account["plan_id"],))

                with self.assertRaises(ApiError) as raised:
                    require_plan_capacity(conn, account["id"], "websites", "max_websites", "website_limit_reached")

                self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)
                self.assertEqual(raised.exception.message, "website_limit_reached")

    def test_website_limit_allows_more_sites_when_under_plan_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                conn.execute("UPDATE plans SET max_websites = 2 WHERE id = ?", (account["plan_id"],))

                require_plan_capacity(conn, account["id"], "websites", "max_websites", "website_limit_reached")

    def test_database_limit_blocks_when_at_plan_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                used = conn.execute("SELECT COUNT(*) AS count FROM databases WHERE account_id = ?", (account["id"],)).fetchone()["count"]
                conn.execute("UPDATE plans SET max_databases = ? WHERE id = ?", (used, account["plan_id"]))

                with self.assertRaises(ApiError) as raised:
                    require_plan_capacity(conn, account["id"], "databases", "max_databases", "database_limit_reached")

                self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)
                self.assertEqual(raised.exception.message, "database_limit_reached")

    def test_suspended_account_blocks_client_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                conn.execute("UPDATE hosting_accounts SET status = 'suspended' WHERE id = ?", (account["id"],))
                suspended = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account["id"],)).fetchone()

                with self.assertRaises(ApiError) as raised:
                    require_active_account(suspended)

                self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)
                self.assertEqual(raised.exception.message, "hosting_account_suspended")


if __name__ == "__main__":
    unittest.main()
