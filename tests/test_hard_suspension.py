import tempfile
import unittest
from pathlib import Path

from mangopanel.agent import Agent
from mangopanel.app import ApiError, client_home, require_active_account
from mangopanel.config import load_config
from mangopanel.db import connect, seed_dev_data
from mangopanel.stack import ACCOUNT_SUSPENSION_MARKER


class HardSuspensionTests(unittest.TestCase):
    def test_hard_suspend_stops_stack_and_unsuspend_starts_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "mangopanel.sqlite3"
            account_root = root / "accounts"
            seed_dev_data(db_path, account_root)
            cfg = load_config()
            cfg.db_path = db_path
            cfg.account_root = account_root
            cfg.agent_mode = "simulate"
            agent = Agent(cfg)

            with connect(db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                compose_path = account_root / account["username"] / ".runtime" / "stack" / "docker-compose.yml"
                compose_path.parent.mkdir(parents=True, exist_ok=True)
                compose_path.write_text("services: {}\n", encoding="utf-8")
                conn.execute(
                    "INSERT INTO account_stacks(account_id, compose_path, mode, status) VALUES (?, ?, ?, ?)",
                    (account["id"], str(compose_path), "simulate", "generated"),
                )
                conn.execute("UPDATE hosting_accounts SET status = 'hard_suspended' WHERE id = ?", (account["id"],))

                result = agent.dispatch(conn, {"type": "hard_suspend_account", "target_id": account["id"]})
                self.assertEqual(result["status"], "hard_suspended")
                self.assertEqual(result["stack"]["status"], "stopped")
                self.assertEqual(conn.execute("SELECT status FROM account_stacks WHERE account_id = ?", (account["id"],)).fetchone()["status"], "stopped")
                self.assertTrue((Path(account["base_path"]) / ACCOUNT_SUSPENSION_MARKER).exists())
                suspended = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account["id"],)).fetchone()
                with self.assertRaises(ApiError) as raised:
                    require_active_account(suspended)
                self.assertEqual(raised.exception.message, "hosting_account_hard_suspended")

                home = client_home(conn, account["user_id"])
                self.assertTrue(home["hosting_account_suspended"])
                self.assertEqual(home["hosting_account_suspension_mode"], "hard")
                self.assertTrue(any(w["kind"] == "suspension" for w in home["warnings"]))

                result = agent.dispatch(conn, {"type": "unsuspend_account", "target_id": account["id"]})
                self.assertEqual(result["status"], "active")
                self.assertEqual(result["stack"]["status"], "generated")
                self.assertFalse((Path(account["base_path"]) / ACCOUNT_SUSPENSION_MARKER).exists())


if __name__ == "__main__":
    unittest.main()
