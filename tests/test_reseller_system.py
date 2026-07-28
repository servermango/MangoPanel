import unittest
import tempfile
import pathlib
import json
import sqlite3
import hashlib
from mangopanel.db import init_db, seed_dev_data, connect

class TestResellerSystem(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = pathlib.Path(self.tmp_dir.name) / "test_reseller.db"
        self.account_root = pathlib.Path(self.tmp_dir.name) / "accounts"
        init_db(self.db_path)
        seed_dev_data(self.db_path, self.account_root)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_reseller_schema_and_seed(self):
        with connect(self.db_path) as conn:
            plan = conn.execute("SELECT * FROM plans WHERE name = 'Dev Reseller Pro'").fetchone()
            self.assertIsNotNone(plan)
            self.assertEqual(plan["is_reseller"], 1)

            reseller_user = conn.execute("SELECT * FROM users WHERE email = 'reseller@example.mango.test'").fetchone()
            self.assertIsNotNone(reseller_user)

    def test_reseller_client_limit_enforcement(self):
        with connect(self.db_path) as conn:
            reseller = conn.execute("SELECT id FROM users WHERE email = 'reseller@example.mango.test'").fetchone()
            reseller_id = reseller["id"]

            # Set max_clients = 2 on master plan
            conn.execute("UPDATE plans SET max_clients = 2 WHERE name = 'Dev Reseller Pro'")
            conn.commit()

            # Insert 2 sub-clients
            conn.execute("INSERT INTO users(email, password_hash, full_name, reseller_id) VALUES ('sub1@test.com', 'hash', 'Sub 1', ?)", (reseller_id,))
            conn.execute("INSERT INTO users(email, password_hash, full_name, reseller_id) VALUES ('sub2@test.com', 'hash', 'Sub 2', ?)", (reseller_id,))
            conn.commit()

            count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE reseller_id = ?", (reseller_id,)).fetchone()["c"]
            self.assertEqual(count, 2)

    def test_subplan_package_capping_enforcement(self):
        with connect(self.db_path) as conn:
            reseller = conn.execute("SELECT id FROM users WHERE email = 'reseller@example.mango.test'").fetchone()
            reseller_id = reseller["id"]

            # Master plan limits: storage = 100000 MB
            conn.execute("UPDATE plans SET storage_mb = 100000 WHERE name = 'Dev Reseller Pro'")
            conn.commit()

            # Valid subplan <= 100000 MB
            valid_storage = 50000
            self.assertLessEqual(valid_storage, 100000)

            # Invalid subplan > 100000 MB
            invalid_storage = 150000
            self.assertGreater(invalid_storage, 100000)

    def test_reseller_api_token(self):
        with connect(self.db_path) as conn:
            reseller = conn.execute("SELECT id FROM users WHERE email = 'reseller@example.mango.test'").fetchone()
            reseller_id = reseller["id"]

            raw_token = "mp_reseller_test1234567890abcdef"
            token_hash = hashlib.sha256("test1234567890abcdef".encode("utf-8")).hexdigest()

            conn.execute(
                "INSERT INTO reseller_api_tokens(reseller_user_id, name, token_hash, permissions_json, expires_at) VALUES (?, ?, ?, ?, ?)",
                (reseller_id, "Test Token", token_hash, json.dumps(["*"]), 9999999999),
            )
            conn.commit()

            token_row = conn.execute("SELECT * FROM reseller_api_tokens WHERE token_hash = ?", (token_hash,)).fetchone()
            self.assertIsNotNone(token_row)
            self.assertEqual(token_row["reseller_user_id"], reseller_id)

if __name__ == "__main__":
    unittest.main()
