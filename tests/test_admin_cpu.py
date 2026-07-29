import tempfile
import unittest
from pathlib import Path

from mangopanel.agent import get_live_cpu_io
from mangopanel.config import load_config
from mangopanel.db import connect, seed_dev_data


class AdminCpuUnitTests(unittest.TestCase):
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

    def test_get_live_cpu_io_structure(self):
        with connect(self.db_path) as conn:
            cpu_data = get_live_cpu_io(conn)
            self.assertIn("sys_cpu_pct", cpu_data)
            self.assertIn("num_cpus", cpu_data)
            self.assertIn("load_avg_1m", cpu_data)
            self.assertIn("load_avg_5m", cpu_data)
            self.assertIn("load_avg_15m", cpu_data)
            self.assertIn("top_cpu_users", cpu_data)
            self.assertIn("timestamp", cpu_data)
            self.assertIsInstance(cpu_data["sys_cpu_pct"], (int, float))
            self.assertGreaterEqual(cpu_data["num_cpus"], 1)
            self.assertIsInstance(cpu_data["top_cpu_users"], list)

    def test_get_live_cpu_io_with_reseller(self):
        with connect(self.db_path) as conn:
            cpu_data = get_live_cpu_io(conn, reseller_id=1)
            self.assertIn("sys_cpu_pct", cpu_data)
            self.assertIn("top_cpu_users", cpu_data)

    def test_get_system_cpu_history_72h(self):
        from mangopanel.agent import get_system_cpu_history
        with connect(self.db_path) as conn:
            hist = get_system_cpu_history(conn, "72h")
            self.assertEqual(hist["hours"], 72)
            self.assertGreaterEqual(hist["total_points"], 200)
            self.assertIn("points", hist)
            self.assertIn("avg_cpu_pct", hist)
            self.assertIn("peak_cpu_pct", hist)
            self.assertIn("min_cpu_pct", hist)
            self.assertIn("avg_load_1m", hist)


if __name__ == "__main__":
    unittest.main()
