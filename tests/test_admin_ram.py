import tempfile
import unittest
from pathlib import Path

from mangopanel.agent import get_live_ram_io, get_system_ram_history
from mangopanel.config import load_config
from mangopanel.db import connect, seed_dev_data


class AdminRamUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.db_path = self.root / "mangopanel.sqlite3"
        self.account_root = self.root / "user_files"
        self.config = load_config()
        self.config.db_path = self.db_path
        self.config.user_files_dir = self.account_root
        seed_dev_data(self.db_path, self.account_root)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_get_live_ram_io_structure(self):
        with connect(self.db_path) as conn:
            ram_data = get_live_ram_io(conn)
            self.assertIn("total_mb", ram_data)
            self.assertIn("used_mb", ram_data)
            self.assertIn("used_pct", ram_data)
            self.assertIn("top_ram_users", ram_data)
            self.assertIsInstance(ram_data["used_pct"], (int, float))
            self.assertIsInstance(ram_data["top_ram_users"], list)

    def test_get_system_ram_history_72h(self):
        with connect(self.db_path) as conn:
            hist = get_system_ram_history(conn, "72h")
            self.assertEqual(hist["hours"], 72)
            self.assertGreaterEqual(hist["total_points"], 200)
            self.assertIn("points", hist)
            self.assertIn("avg_used_pct", hist)
            self.assertIn("peak_used_pct", hist)
            self.assertIn("min_used_pct", hist)
            self.assertIn("avg_used_mb", hist)


if __name__ == "__main__":
    unittest.main()
