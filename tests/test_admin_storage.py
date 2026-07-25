import json
import tempfile
import unittest
from pathlib import Path

from mangopanel.agent import (
    get_account_storage_quotas,
    get_df_storage,
    get_live_disk_io,
    get_path_size_breakdown,
    get_storage_alert_settings,
    run_storage_cleanup,
    save_storage_alert_settings,
)
from mangopanel.config import load_config
from mangopanel.db import connect, seed_dev_data


class AdminStorageUnitTests(unittest.TestCase):
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

    def test_get_df_storage(self):
        data = get_df_storage()
        self.assertIn("filesystems", data)
        self.assertIn("root_capacity_pct", data)
        self.assertIsInstance(data["filesystems"], list)
        if len(data["filesystems"]) > 0:
            first = data["filesystems"][0]
            self.assertIn("mounted_on", first)
            self.assertIn("use_percent", first)
            self.assertIn("is_overlay", first)

    def test_get_live_disk_io(self):
        with connect(self.db_path) as conn:
            data = get_live_disk_io(conn)
            self.assertIn("capacity_total_bytes", data)
            self.assertIn("read_rate_kbs", data)
            self.assertIn("write_rate_kbs", data)
            self.assertIn("top_writers", data)
            self.assertIsInstance(data["top_writers"], list)

    def test_get_account_storage_quotas(self):
        with connect(self.db_path) as conn:
            data = get_account_storage_quotas(conn, self.config)
            self.assertIn("accounts", data)
            self.assertGreater(len(data["accounts"]), 0)
            acct = data["accounts"][0]
            self.assertIn("username", acct)
            self.assertIn("used_storage_mb", acct)
            self.assertIn("storage_pct", acct)
            self.assertIn("used_inodes", acct)

    def test_get_path_size_breakdown(self):
        data = get_path_size_breakdown(self.config)
        self.assertIn("paths", data)
        self.assertIn("total_scanned_mb", data)
        self.assertGreater(len(data["paths"]), 0)

    def test_run_storage_cleanup(self):
        res = run_storage_cleanup(clean_docker=False, clean_logs=True, clean_tmp=True)
        self.assertTrue(res["ok"])
        self.assertIn("reclaimed_bytes", res)
        self.assertIn("actions", res)

    def test_storage_alert_settings(self):
        with connect(self.db_path) as conn:
            defaults = get_storage_alert_settings(conn)
            self.assertEqual(defaults["warning_threshold_pct"], 85)

            new_settings = {
                "warning_threshold_pct": 80,
                "critical_threshold_pct": 92,
                "inode_warning_pct": 75,
                "notify_email": "alerts@mango.test",
                "enabled": True,
            }
            save_storage_alert_settings(conn, new_settings)
            updated = get_storage_alert_settings(conn)
            self.assertEqual(updated["warning_threshold_pct"], 80)
            self.assertEqual(updated["notify_email"], "alerts@mango.test")


if __name__ == "__main__":
    unittest.main()
