import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path

from mangopanel.app import ApiError, client_home, collect_resource_usage_sample, require_active_account, require_inode_capacity, require_plan_capacity
from mangopanel.agent import Agent, path_usage
from mangopanel.config import load_config
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

    def test_inode_quota_blocks_when_exceeded(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                conn.execute("UPDATE hosting_accounts SET inodes_used = 1500 WHERE id = ?", (account["id"],))
                conn.execute("UPDATE plans SET inode_limit = 1000 WHERE id = ?", (account["plan_id"],))

                with self.assertRaises(ApiError) as raised:
                    require_inode_capacity(conn, account["id"])

                self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)
                self.assertEqual(raised.exception.message, "inode_quota_exceeded")

    def test_recalculate_usage_job_updates_inode_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "mangopanel.sqlite3"
            account_root = tmp_path / "accounts"
            seed_dev_data(db_path, account_root)

            cfg = load_config()
            cfg.db_path = db_path
            cfg.account_root = account_root
            agent = Agent(cfg)

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                base_path = Path(account["base_path"])
                base_path.mkdir(parents=True, exist_ok=True)
                (base_path / "file1.txt").write_text("hello")
                (base_path / "file2.txt").write_text("world")

                res = agent.recalculate_usage(conn, {"target_type": "account", "target_id": account["id"], "payload": "{}"})
                self.assertTrue(res["ok"])

                updated = conn.execute("SELECT inodes_used FROM hosting_accounts WHERE id = ?", (account["id"],)).fetchone()
                self.assertGreater(updated["inodes_used"], 0)

                home = client_home(conn, account["user_id"])
                self.assertEqual(home["resources"]["inodes_used"], updated["inodes_used"])
                self.assertNotEqual(home["resources"]["inodes_used"], 1250)

    def test_client_recalculate_usage_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "mangopanel.sqlite3"
            account_root = tmp_path / "accounts"
            seed_dev_data(db_path, account_root)

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                base_path = Path(account["base_path"])
                base_path.mkdir(parents=True, exist_ok=True)
                (base_path / "test_file.txt").write_text("content")

                collect_resource_usage_sample(conn, account, force=True)
                sample = conn.execute("SELECT inodes_used FROM resource_usage_samples WHERE account_id = ? ORDER BY sampled_at DESC LIMIT 1", (account["id"],)).fetchone()
                self.assertGreater(sample["inodes_used"], 0)


if __name__ == "__main__":
    unittest.main()
