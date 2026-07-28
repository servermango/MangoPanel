import tempfile
import unittest
from pathlib import Path

from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import connect, create_job, seed_dev_data


class TestRecalculateUsageRow(unittest.TestCase):
    def test_recalculate_usage_with_sqlite_row_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "mangopanel.sqlite3"
            account_root = root / "user_files" / "accounts"
            seed_dev_data(db_path, account_root)

            config = Config()
            config.db_path = db_path
            config.account_root = account_root
            agent = Agent(config)

            with connect(db_path) as conn:
                job_id = create_job(conn, "recalculate_usage", "hosting_account", 1, {"reason": "test"})
                job_row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()

                # Passing raw sqlite3.Row object to recalculate_usage should NOT raise AttributeError
                result = agent.recalculate_usage(conn, job_row)
                self.assertTrue(result["ok"])
                self.assertGreaterEqual(result["recalculated_accounts_count"], 1)


if __name__ == "__main__":
    unittest.main()
