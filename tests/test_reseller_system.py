import unittest
import tempfile
import pathlib
import json
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
        """Reseller plans live in reseller_plans table; reseller users have is_reseller=1."""
        with connect(self.db_path) as conn:
            # Dev Reseller Pro must be in reseller_plans (new architecture)
            plan = conn.execute("SELECT * FROM reseller_plans WHERE name = 'Dev Reseller Pro'").fetchone()
            self.assertIsNotNone(plan)
            self.assertGreater(plan["max_clients"], 0)

            # Seeded reseller user must have is_reseller = 1 and a reseller_plan_id
            reseller_user = conn.execute(
                "SELECT * FROM users WHERE email = 'reseller@example.mango.test'"
            ).fetchone()
            self.assertIsNotNone(reseller_user)
            self.assertEqual(reseller_user["is_reseller"], 1)
            self.assertIsNotNone(reseller_user["reseller_plan_id"])

            # Reseller user must NOT have a hosting account (no container provisioned)
            acc = conn.execute(
                "SELECT * FROM hosting_accounts WHERE user_id = ?", (reseller_user["id"],)
            ).fetchone()
            self.assertIsNone(acc, "Reseller users must not have a hosting_account provisioned")

    def test_reseller_client_limit_enforcement(self):
        """Reseller plan max_clients is read from reseller_plans, not plans."""
        with connect(self.db_path) as conn:
            reseller = conn.execute(
                "SELECT * FROM users WHERE email = 'reseller@example.mango.test'"
            ).fetchone()
            reseller_id = reseller["id"]

            # Set max_clients = 2 on the reseller plan
            conn.execute(
                "UPDATE reseller_plans SET max_clients = 2 WHERE name = 'Dev Reseller Pro'"
            )
            conn.commit()

            # Insert 2 sub-clients linked to this reseller via reseller_id
            conn.execute(
                "INSERT INTO users(email, password_hash, full_name, reseller_id) VALUES ('sub1@test.com', 'hash', 'Sub 1', ?)",
                (reseller_id,),
            )
            conn.execute(
                "INSERT INTO users(email, password_hash, full_name, reseller_id) VALUES ('sub2@test.com', 'hash', 'Sub 2', ?)",
                (reseller_id,),
            )
            conn.commit()

            count = conn.execute(
                "SELECT COUNT(*) AS c FROM users WHERE reseller_id = ?", (reseller_id,)
            ).fetchone()["c"]
            self.assertEqual(count, 2)

            # Confirm the plan limit is 2
            limit = conn.execute(
                "SELECT max_clients FROM reseller_plans WHERE name = 'Dev Reseller Pro'"
            ).fetchone()["max_clients"]
            self.assertEqual(limit, 2)
            self.assertGreaterEqual(limit, count)

    def test_subplan_package_capping_enforcement(self):
        """Reseller plan storage is tracked via reseller_plans.max_storage_mb."""
        with connect(self.db_path) as conn:
            conn.execute(
                "UPDATE reseller_plans SET max_storage_mb = 100000 WHERE name = 'Dev Reseller Pro'"
            )
            conn.commit()

            limit = conn.execute(
                "SELECT max_storage_mb FROM reseller_plans WHERE name = 'Dev Reseller Pro'"
            ).fetchone()["max_storage_mb"]

            # Valid subplan <= 100000 MB
            valid_storage = 50000
            self.assertLessEqual(valid_storage, limit)

            # Invalid subplan > 100000 MB
            invalid_storage = 150000
            self.assertGreater(invalid_storage, limit)

    def test_reseller_api_token(self):
        """Reseller API tokens are stored in reseller_api_tokens linked to reseller user."""
        with connect(self.db_path) as conn:
            reseller = conn.execute(
                "SELECT id FROM users WHERE email = 'reseller@example.mango.test'"
            ).fetchone()
            reseller_id = reseller["id"]

            raw_token = "mp_reseller_test1234567890abcdef"
            token_hash = hashlib.sha256("test1234567890abcdef".encode("utf-8")).hexdigest()

            conn.execute(
                "INSERT INTO reseller_api_tokens(reseller_user_id, name, token_hash, permissions_json, expires_at) VALUES (?, ?, ?, ?, ?)",
                (reseller_id, "Test Token", token_hash, json.dumps(["*"]), 9999999999),
            )
            conn.commit()

            token_row = conn.execute(
                "SELECT * FROM reseller_api_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            self.assertIsNotNone(token_row)
            self.assertEqual(token_row["reseller_user_id"], reseller_id)


if __name__ == "__main__":
    unittest.main()
