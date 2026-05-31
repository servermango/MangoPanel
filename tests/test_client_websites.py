import tempfile
import unittest
from pathlib import Path

from mangopanel.app import delete_client_website
from mangopanel.db import connect, seed_dev_data


class ClientWebsiteTests(unittest.TestCase):
    def test_delete_client_website_removes_panel_record_and_queues_stack_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                website = conn.execute("SELECT * FROM websites WHERE account_id = ? LIMIT 1", (account["id"],)).fetchone()

                job_id = delete_client_website(conn, account, website)

                self.assertIsNone(conn.execute("SELECT id FROM websites WHERE id = ?", (website["id"],)).fetchone())
                domain = conn.execute("SELECT linked_website_id FROM domains WHERE name = ?", (website["domain"],)).fetchone()
                self.assertIsNotNone(domain)
                self.assertIsNone(domain["linked_website_id"])
                job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
                self.assertEqual(job["type"], "delete_website")
                self.assertEqual(job["status"], "succeeded")
                self.assertEqual(job["target_type"], "hosting_account")
                self.assertEqual(job["target_id"], account["id"])
                artifact = Path(account["base_path"]) / ".runtime" / "simulated" / "deleted-websites" / "{}.json".format(website["domain"])
                self.assertTrue(artifact.exists())


if __name__ == "__main__":
    unittest.main()
