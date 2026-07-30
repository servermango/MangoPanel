import os
import tempfile
import unittest
from pathlib import Path
from http import HTTPStatus

from mangopanel import app as app_module
from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from tests.test_phase3_routes import ClientApiServer


class FixPermissionsTargetedTests(unittest.TestCase):
    def make_config(self, root):
        config = Config()
        config.db_path = root / "mangopanel.sqlite3"
        config.data_dir = root
        config.account_root = root / "accounts"
        config.agent_mode = "simulate"
        config.agent_inline = True
        config.dev_auth_test_mode = True
        return config

    def prepared_server(self, root):
        config = self.make_config(root)
        seed_dev_data(config.db_path, config.account_root)
        Agent(config).run_all()
        return config, ClientApiServer(config)

    def test_fix_ownership_api_all_sites_and_specific_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                token = server.login()

                # Test 1: Fix permissions for all sites (website_id = null / default)
                res_all = server.request("POST", "/api/client/fix-ownership", body={}, token=token)
                self.assertTrue(res_all.get("fixed"))
                self.assertIn("job_id", res_all)
                self.assertIsNone(res_all.get("website_id"))

                # Create two websites for this account
                site1_res = server.request("POST", "/api/client/websites", body={"domain": "site1.test"}, token=token)
                site2_res = server.request("POST", "/api/client/websites", body={"domain": "site2.test"}, token=token)
                site1_id = site1_res["website"]["id"]

                # Test 2: Fix permissions for a specific website
                res_site1 = server.request("POST", "/api/client/fix-ownership", body={"website_id": site1_id}, token=token)
                self.assertTrue(res_site1.get("fixed"))
                self.assertEqual(res_site1.get("website_id"), site1_id)

                # Test 3: Fix permissions for invalid website_id -> 404
                err_code, _, err_body = server.request_raw("POST", "/api/client/fix-ownership", body={"website_id": 999999}, token=token)
                self.assertEqual(err_code, HTTPStatus.NOT_FOUND)
                self.assertEqual(err_body.get("error"), "website_not_found")

    def test_agent_fix_ownership_targeted_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            agent = Agent(config)

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                acc_base = Path(tmp) / "accounts" / account["username"]
                acc_base.mkdir(parents=True, exist_ok=True)
                acc_base = acc_base.resolve()
                conn.execute("UPDATE hosting_accounts SET base_path = ? WHERE id = ?", (str(acc_base), account["id"]))
                
                # Create fake domain directories and files
                site1_dir = (acc_base / "domains" / "alpha.com" / "public_html").resolve()
                site2_dir = (acc_base / "domains" / "beta.com" / "public_html").resolve()
                site1_dir.mkdir(parents=True, exist_ok=True)
                site2_dir.mkdir(parents=True, exist_ok=True)

                file1 = (site1_dir / "index.php").resolve()
                file2 = (site2_dir / "index.php").resolve()
                file1.write_text("<?php echo 'alpha';")
                file2.write_text("<?php echo 'beta';")

                # Set restricted 0600 permissions on file1 and file2
                os.chmod(file1, 0o600)
                os.chmod(file2, 0o600)

                # Register site1 in DB
                cur = conn.execute(
                    "INSERT INTO websites (account_id, domain, document_root, created_at) VALUES (?, ?, ?, 1000) RETURNING id",
                    (account["id"], "alpha.com", str(site1_dir))
                )
                site1_id = cur.fetchone()[0]
                conn.commit()

                # Run fix_file_ownership targeted to site1_id
                res = agent.fix_file_ownership(conn, account["id"], payload={"website_id": site1_id})

                self.assertTrue(res["fixed"])
                self.assertEqual(res["website_id"], site1_id)
                self.assertEqual(res["target_domain"], "alpha.com")

                # Verify file1 was fixed to 0666
                stat1 = os.stat(file1)
                self.assertEqual(oct(stat1.st_mode & 0o777), "0o666")

                # file2 (untargeted) should NOT have been changed by targeted run (remains 0600)
                stat2 = os.stat(file2)
                self.assertEqual(oct(stat2.st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
