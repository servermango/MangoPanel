import tempfile
import unittest
from pathlib import Path

from mangopanel.app import client_analytics_payload, parse_combined_access_log
from mangopanel.db import connect, seed_dev_data


class AnalyticsTest(unittest.TestCase):
    def test_client_analytics_aggregates_access_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            seed_dev_data(db_path, Path(tmp) / "accounts")
            with connect(db_path) as conn:
                account = conn.execute("SELECT id FROM hosting_accounts WHERE username = ?", ("u000001",)).fetchone()
                website = conn.execute("SELECT id, domain FROM websites WHERE account_id = ?", (account["id"],)).fetchone()
                conn.executemany(
                    """
                    INSERT INTO access_logs(
                      account_id, website_id, domain, method, path, status_code,
                      bytes_sent, ip_address, country, user_agent, referer
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (account["id"], website["id"], website["domain"], "GET", "/", 200, 1024, "203.0.113.10", "India", "test", ""),
                        (account["id"], website["id"], website["domain"], "GET", "/missing", 404, 512, "203.0.113.10", "India", "test", ""),
                        (account["id"], website["id"], website["domain"], "POST", "/api", 500, 256, "198.51.100.20", "United States", "test", ""),
                    ],
                )

                payload = client_analytics_payload(conn, account["id"], website["id"], "top-countries")

            self.assertEqual(payload["domain"], website["domain"])
            self.assertEqual(payload["summary"]["total_requests"], 3)
            self.assertEqual(payload["summary"]["unique_ip_addresses"], 2)
            self.assertEqual(payload["summary"]["bandwidth_bytes"], 1792)
            self.assertEqual(payload["summary"]["error_4xx"], 1)
            self.assertEqual(payload["summary"]["error_5xx"], 1)
            self.assertEqual(payload["top_countries"][0]["country"], "India")
            self.assertEqual(payload["top_countries"][0]["requests"], 2)

    def test_parse_combined_access_log(self):
        parsed = parse_combined_access_log(
            '203.0.113.10 - - [30/May/2026:10:15:30 +0530] "GET /index.php HTTP/1.1" 200 664 '
            '"-" "Mozilla/5.0"'
        )

        self.assertEqual(parsed["ip_address"], "203.0.113.10")
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["path"], "/index.php")
        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["bytes_sent"], 664)


if __name__ == "__main__":
    unittest.main()
