import tempfile
import unittest
from pathlib import Path
from http import HTTPStatus

from mangopanel.db import connect, seed_dev_data
from mangopanel.security import verify_password, hash_password
from mangopanel.app import ApiError, validate_password

class SettingsTests(unittest.TestCase):
    def test_validate_password_requires_ten_chars(self):
        with self.assertRaises(ApiError) as raised:
            validate_password("short")
        self.assertEqual(raised.exception.status, HTTPStatus.BAD_REQUEST)
        self.assertEqual(raised.exception.message, "password_too_short")
        
        validated = validate_password("alongenoughpassword")
        self.assertEqual(validated, "alongenoughpassword")

    def test_change_password_db_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                user = conn.execute("SELECT id, password_hash FROM users LIMIT 1").fetchone()
                user_id = user["id"]
                
                # Check current hash verifies default password
                self.assertTrue(verify_password("ChangeMe-DevOnly-123!", user["password_hash"]))
                
                # Simulate password change operation
                new_password = "anothernewsupersecretpassword"
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_password(new_password), user_id),
                )
                
                updated_user = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
                self.assertTrue(verify_password(new_password, updated_user["password_hash"]))
                self.assertFalse(verify_password("ChangeMe-DevOnly-123!", updated_user["password_hash"]))

if __name__ == "__main__":
    unittest.main()
