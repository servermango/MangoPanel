"""Website-list TLS probes must not disable provisioned HTTPS routes."""
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mangopanel import app as app_module
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from mangopanel.stack import build_account_runtime, render_compose


class WebsiteSslStatusTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.config = Config()
        self.config.db_path = root / "mangopanel.sqlite3"
        self.config.data_dir = root
        self.config.account_root = root / "accounts"
        self.config.agent_mode = "simulate"
        seed_dev_data(self.config.db_path, self.config.account_root)
        patcher = mock.patch.object(app_module, "CONFIG", self.config)
        patcher.start()
        self.addCleanup(patcher.stop)
        with connect(self.config.db_path) as conn:
            self.account = dict(conn.execute("SELECT * FROM hosting_accounts WHERE user_id = 1 LIMIT 1").fetchone())
            self.plan = dict(conn.execute("SELECT * FROM plans WHERE id = ?", (self.account["plan_id"],)).fetchone())
            self.site_id = conn.execute("SELECT id FROM websites WHERE account_id = ? LIMIT 1", (self.account["id"],)).fetchone()["id"]
            conn.execute("UPDATE websites SET domain = 'ssl-regression.example.com' WHERE id = ?", (self.site_id,))
        self.handler = app_module.MangoHandler.__new__(app_module.MangoHandler)
        self.handler.headers = {"X-Hosting-Account-ID": str(self.account["id"])}
        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.json_response = lambda payload: payload

    def set_status(self, status):
        with connect(self.config.db_path) as conn:
            conn.execute("UPDATE websites SET ssl_status = ? WHERE id = ?", (status, self.site_id))
            conn.execute("UPDATE ssl_certificates SET status = ? WHERE website_id = ?", (status, self.site_id))

    def list_sites(self):
        with mock.patch.object(app_module, "get_host_public_ip", return_value="203.0.113.10"):
            return self.handler.client_api("GET", "/api/client/websites", {}, {"id": 1, "actor_type": "user"})["websites"]

    def assert_status(self, sites, expected):
        site = next(w for w in sites if w["id"] == self.site_id)
        self.assertEqual(site["ssl_status"], expected)
        with connect(self.config.db_path) as conn:
            self.assertEqual(conn.execute("SELECT ssl_status FROM websites WHERE id = ?", (self.site_id,)).fetchone()["ssl_status"], expected)
            certificates = conn.execute("SELECT status FROM ssl_certificates WHERE website_id = ?", (self.site_id,)).fetchall()
            self.assertTrue(certificates)
            self.assertTrue(all(c["status"] == expected for c in certificates))
        return site

    def test_connection_failures_preserve_status_and_https_routes(self):
        for status in ("active", "pending", "missing"):
            for failure in (socket.timeout("probe timed out"), ConnectionRefusedError("edge restarting")):
                with self.subTest(status=status, failure=type(failure).__name__):
                    self.set_status(status)
                    with mock.patch.object(app_module.socket, "create_connection", side_effect=failure):
                        # Repeated page refreshes must not erode provisioned state.
                        self.list_sites()
                        sites = self.list_sites()
                    site = self.assert_status(sites, status)
                    compose = render_compose(self.account, self.plan, [site], build_account_runtime(self.account))
                    if status in ("active", "pending"):
                        self.assertIn("https://ssl-regression.example.com", compose)
                        self.assertIn("https://www.ssl-regression.example.com", compose)
                    else:
                        self.assertNotIn("https://ssl-regression.example.com", compose)

    def test_handshake_failure_preserves_active_certificate(self):
        self.set_status("active")
        with mock.patch.object(app_module.socket, "create_connection"), mock.patch.object(app_module.ssl, "create_default_context") as context:
            context.return_value.wrap_socket.side_effect = ssl.SSLError("temporary handshake failure")
            self.assert_status(self.list_sites(), "active")

    def test_successful_probe_promotes_pending_and_missing(self):
        for status in ("pending", "missing"):
            with self.subTest(status=status):
                self.set_status(status)
                with mock.patch.object(app_module.socket, "create_connection"), mock.patch.object(app_module.ssl, "create_default_context"):
                    self.assert_status(self.list_sites(), "active")

    def test_custom_certificate_is_not_probed_or_changed(self):
        self.set_status("custom")
        with mock.patch.object(app_module.socket, "create_connection") as connection:
            self.assert_status(self.list_sites(), "custom")
        connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
