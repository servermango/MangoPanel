import tempfile
import unittest
from pathlib import Path

from mangopanel.app import MangoHandler, client_home
from mangopanel.db import connect, seed_dev_data
from mangopanel.security import create_jwt, hash_password


class MultiAccountSwitcherTests(unittest.TestCase):
    def test_client_home_and_api_scoping_by_account_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            accounts_dir = Path(tmp) / "accounts"
            seed_dev_data(db_path, accounts_dir)

            with connect(db_path) as conn:
                user = conn.execute("SELECT * FROM users LIMIT 1").fetchone()
                user_id = user["id"]
                plan = conn.execute("SELECT * FROM plans LIMIT 1").fetchone()
                node = conn.execute("SELECT * FROM nodes LIMIT 1").fetchone()

                # Ensure user has 2 hosting accounts
                existing_accs = conn.execute("SELECT * FROM hosting_accounts WHERE user_id = ?", (user_id,)).fetchall()
                acc1 = existing_accs[0]

                acc2_cur = conn.execute(
                    """
                    INSERT INTO hosting_accounts(user_id, plan_id, node_id, username, base_path, status)
                    VALUES (?, ?, ?, ?, ?, 'active')
                    """,
                    (user_id, plan["id"], node["id"], "u000999_second", str(accounts_dir / "u000999_second")),
                )
                acc2_id = acc2_cur.lastrowid
                acc2 = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (acc2_id,)).fetchone()

                # Add distinct website to acc2
                conn.execute(
                    """
                    INSERT INTO websites(account_id, domain, document_root, php_version, ssl_status, status)
                    VALUES (?, 'second-site.com', '/tmp/second', '8.3', 'active', 'active')
                    """,
                    (acc2["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO databases(account_id, name, username) VALUES (?, 'acc2_db', 'acc2_usr')
                    """,
                    (acc2["id"],),
                )

                # Insert distinct resource samples for acc1 and acc2
                conn.execute(
                    """
                    INSERT INTO resource_usage_samples(account_id, sampled_at, storage_mb, storage_limit_mb, inodes_used, inodes_limit, cpu_percent, memory_mb, memory_limit_mb)
                    VALUES (?, '2026-07-27 12:00:00', 150, 5000, 1200, 50000, 15.0, 256, 1024)
                    """,
                    (acc1["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO resource_usage_samples(account_id, sampled_at, storage_mb, storage_limit_mb, inodes_used, inodes_limit, cpu_percent, memory_mb, memory_limit_mb)
                    VALUES (?, '2026-07-27 12:00:00', 850, 20000, 8400, 200000, 85.0, 950, 1024)
                    """,
                    (acc2["id"],),
                )

                # Test client_home scoping
                home1 = client_home(conn, user_id, active_account_id=acc1["id"])
                self.assertEqual(len(home1["accounts"]), 2)
                site_domains_1 = [w["domain"] for w in home1["websites"]]
                self.assertNotIn("second-site.com", site_domains_1)
                self.assertEqual(home1["resources"]["disk_used_mb"], 150)
                self.assertEqual(home1["resources"]["inodes_used"], 1200)

                home2 = client_home(conn, user_id, active_account_id=acc2["id"])
                self.assertEqual(len(home2["accounts"]), 2)
                site_domains_2 = [w["domain"] for w in home2["websites"]]
                self.assertIn("second-site.com", site_domains_2)
                self.assertEqual(home2["resources"]["disk_used_mb"], 850)
                self.assertEqual(home2["resources"]["inodes_used"], 8400)

    def test_dynamic_provisioning_test_domain(self):
        from mangopanel.app import create_initial_hosting_account, get_provisioning_test_domain, resolve_panel_base_domain

        self.assertEqual(resolve_panel_base_domain({"Host": "seeds.servermango.com"}), "seeds.servermango.com")
        self.assertEqual(resolve_panel_base_domain({"Host": "seeds.servermango.com:8443"}), "seeds.servermango.com")
        self.assertEqual(resolve_panel_base_domain({"Host": "127.0.0.1:8000"}), "mango.test")

        domain = get_provisioning_test_domain("u004395", {"Host": "seeds.servermango.com"})
        self.assertEqual(domain, "u004395.seeds.servermango.com")

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            accounts_dir = Path(tmp) / "accounts"
            seed_dev_data(db_path, accounts_dir)

            with connect(db_path) as conn:
                new_user_id = conn.execute(
                    "INSERT INTO users(email, password_hash, full_name) VALUES ('newuser@example.com', 'hash', 'New User')"
                ).lastrowid
                payload = create_initial_hosting_account(conn, new_user_id, request_headers={"Host": "seeds.servermango.com:8443"})
                created_web = conn.execute("SELECT * FROM websites WHERE account_id = ?", (payload["id"],)).fetchone()
                self.assertEqual(created_web["domain"], "u000002.seeds.servermango.com")

    def test_db_locking_and_retry_resilience(self):
        import sqlite3
        from mangopanel.db import connect, with_db_retry

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            accounts_dir = Path(tmp) / "accounts"
            seed_dev_data(db_path, accounts_dir)

            with connect(db_path) as conn:
                res = conn.execute("PRAGMA journal_mode").fetchone()[0]
                self.assertEqual(res.lower(), "wal")

            attempts = 0
            def flaky_db_op():
                nonlocal attempts
                attempts += 1
                if attempts < 3:
                    raise sqlite3.OperationalError("database is locked")
                return "success"

            result = with_db_retry(flaky_db_op, max_retries=5, initial_delay=0.01)
            self.assertEqual(result, "success")
            self.assertEqual(attempts, 3)

    def test_single_account_client_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            accounts_dir = Path(tmp) / "accounts"
            seed_dev_data(db_path, accounts_dir)

            with connect(db_path) as conn:
                user = conn.execute("SELECT * FROM users LIMIT 1").fetchone()
                user_id = user["id"]
                accs = conn.execute("SELECT * FROM hosting_accounts WHERE user_id = ?", (user_id,)).fetchall()
                self.assertGreaterEqual(len(accs), 1)

                home = client_home(conn, user_id, active_account_id=accs[0]["id"])
                self.assertIn("accounts", home)
                self.assertEqual(home["accounts"][0]["id"], accs[0]["id"])

    def test_client_home_without_account_header_resolves_default_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            accounts_dir = Path(tmp) / "accounts"
            seed_dev_data(db_path, accounts_dir)

            with connect(db_path) as conn:
                user = conn.execute("SELECT * FROM users ORDER BY id DESC LIMIT 1").fetchone()
                user_id = user["id"]
                home = client_home(conn, user_id, active_account_id=None)
                self.assertIn("accounts", home)
                self.assertGreaterEqual(len(home["accounts"]), 1)


if __name__ == "__main__":
    unittest.main()

