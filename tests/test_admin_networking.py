import json
import tempfile
import unittest
from pathlib import Path

from mangopanel.agent import (
    add_server_ip,
    assign_account_ip,
    delete_server_ip,
    get_live_network_io,
    get_network_overview,
    get_server_ips,
    update_server_ip,
    AgentError,
)
from mangopanel.config import load_config
from mangopanel.db import connect, seed_dev_data


class AdminNetworkingUnitTests(unittest.TestCase):
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

    def test_get_network_overview(self):
        with connect(self.db_path) as conn:
            overview = get_network_overview(conn)
            self.assertIn("primary_ip", overview)
            self.assertIn("interfaces", overview)
            self.assertIn("service_ports", overview)
            self.assertGreaterEqual(overview["total_registered_ips"], 1)

    def test_add_and_get_server_ips(self):
        with connect(self.db_path) as conn:
            res = add_server_ip(conn, {
                "ip_address": "198.51.100.42",
                "ip_type": "ipv4",
                "netmask_cidr": "/24",
                "interface": "ens160",
                "label": "Secondary Dedicated IP Pool",
            })
            self.assertTrue(res["ok"])
            self.assertIn("id", res)

            ips = get_server_ips(conn)
            added = next((ip for ip in ips if ip["ip_address"] == "198.51.100.42"), None)
            self.assertIsNotNone(added)
            self.assertEqual(added["label"], "Secondary Dedicated IP Pool")

    def test_invalid_ip_format_rejected(self):
        with connect(self.db_path) as conn:
            with self.assertRaises(AgentError):
                add_server_ip(conn, {"ip_address": "999.888.777.666"})

    def test_update_server_ip_and_set_primary(self):
        with connect(self.db_path) as conn:
            res = add_server_ip(conn, {
                "ip_address": "198.51.100.43",
                "label": "Test IP",
                "is_primary": True,
            })
            ip_id = res["id"]

            ips = get_server_ips(conn)
            primary = next((ip for ip in ips if ip["is_primary"]), None)
            self.assertIsNotNone(primary)
            self.assertEqual(primary["ip_address"], "198.51.100.43")

            update_server_ip(conn, ip_id, {"label": "Updated Label"})
            updated = next((ip for ip in get_server_ips(conn) if ip["id"] == ip_id), None)
            self.assertEqual(updated["label"], "Updated Label")

    def test_assign_account_ip_updates_dns(self):
        with connect(self.db_path) as conn:
            # Get an account ID
            acct = conn.execute("SELECT id FROM hosting_accounts LIMIT 1").fetchone()
            self.assertIsNotNone(acct)
            acct_id = acct["id"]

            # Add dedicated IP
            res = add_server_ip(conn, {
                "ip_address": "198.51.100.50",
                "label": "Dedicated IP for Client",
            })
            ip_id = res["id"]

            # Assign IP to account
            assign_res = assign_account_ip(conn, acct_id, ip_id)
            self.assertTrue(assign_res["ok"])
            self.assertEqual(assign_res["active_ip"], "198.51.100.50")

            # Check server_ips record shows assignment
            ip_rec = conn.execute("SELECT assigned_account_id FROM server_ips WHERE id = ?", (ip_id,)).fetchone()
            self.assertEqual(ip_rec["assigned_account_id"], acct_id)

            # Unassign IP
            unassign_res = assign_account_ip(conn, acct_id, None)
            self.assertTrue(unassign_res["ok"])
            ip_rec_unassigned = conn.execute("SELECT assigned_account_id FROM server_ips WHERE id = ?", (ip_id,)).fetchone()
            self.assertIsNone(ip_rec_unassigned["assigned_account_id"])

    def test_delete_server_ip_safeguards(self):
        with connect(self.db_path) as conn:
            # Primary IP deletion attempt should fail
            primary_ip = conn.execute("SELECT id FROM server_ips WHERE is_primary = 1").fetchone()
            if primary_ip:
                with self.assertRaises(AgentError):
                    delete_server_ip(conn, primary_ip["id"])

            # Add unassigned IP and delete
            res = add_server_ip(conn, {"ip_address": "198.51.100.99"})
            ip_id = res["id"]
            del_res = delete_server_ip(conn, ip_id)
            self.assertTrue(del_res["ok"])

    def test_get_live_network_io(self):
        with connect(self.db_path) as conn:
            live = get_live_network_io(conn)
            self.assertIn("rx_rate_kbs", live)
            self.assertIn("tx_rate_kbs", live)
            self.assertIn("top_network_users", live)
            self.assertIsInstance(live["top_network_users"], list)
            self.assertIn("timestamp", live)


if __name__ == "__main__":
    unittest.main()
