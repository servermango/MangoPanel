import tempfile
import unittest
from pathlib import Path

from mangopanel.db import connect, seed_dev_data


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


if __name__ == "__main__":
    unittest.main()
