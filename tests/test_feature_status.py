import tempfile
import unittest
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.agent import Agent
from mangopanel.db import seed_dev_data
from tests.test_phase3_routes import ClientApiServer


class FeatureStatusTests(unittest.TestCase):
    def make_config(self, root):
        config = app_module.load_config()
        config.db_path = root / "mangopanel.sqlite3"
        config.data_dir = root
        config.account_root = root / "accounts"
        config.agent_mode = "simulate"
        config.agent_inline = True
        config.dev_auth_test_mode = True
        return config

    def test_client_feature_status_contract_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_config(root)
            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with ClientApiServer(config) as server:
                token = server.login()
                payload = server.request("GET", "/api/client/feature-status", token=token)

        features = payload["features"]
        valid_statuses = {"functional", "simulated", "read_only", "disabled"}
        for target, meta in features.items():
            self.assertIn(meta["status"], valid_statuses, target)
            self.assertTrue(meta["label"], target)

        self.assertEqual(features["dns-zone-editor"]["status"], "functional")
        self.assertEqual(features["webalizer"]["status"], "disabled")
        self.assertEqual(features["analytics"]["status"], "functional")
        self.assertEqual(features["performance"]["status"], "read_only")
        self.assertEqual(features["php-info"]["status"], "read_only")
        self.assertEqual(features["activity"]["status"], "read_only")
        self.assertEqual(features["disk-usage"]["status"], "read_only")
        self.assertEqual(features["resource-usage"]["status"], "read_only")
        self.assertEqual(features["visitors"]["status"], "read_only")
        self.assertEqual(features["errors"]["status"], "read_only")
        self.assertEqual(features["bandwidth"]["status"], "read_only")
        self.assertEqual(features["raw-access"]["status"], "read_only")
        self.assertEqual(features["website"]["status"], "functional")
        self.assertEqual(features["files"]["status"], "functional")
        self.assertEqual(features["ftp-accounts"]["status"], "functional")
        self.assertEqual(features["password-protect-directories"]["status"], "functional")
        self.assertEqual(features["hotlink-protection"]["status"], "functional")
        self.assertEqual(features["folder-index-manager"]["status"], "functional")
        self.assertEqual(features["cache-manager"]["status"], "functional")
        self.assertEqual(features["fix-file-ownership"]["status"], "functional")
        self.assertEqual(features["services"]["status"], "functional")
        self.assertEqual(features["modsecurity"]["status"], "functional")
        self.assertEqual(features["backups"]["status"], "functional")
        self.assertEqual(features["cron-jobs"]["status"], "functional")
        self.assertEqual(features["git"]["status"], "functional")
        self.assertEqual(features["images"]["status"], "functional")
        self.assertEqual(features["remote-mysql"]["status"], "functional")
        self.assertEqual(features["postgresql-databases"]["status"], "functional")
        self.assertEqual(features["postgresql-database-wizard"]["status"], "functional")
        self.assertEqual(features["site-builder"]["status"], "functional")
        self.assertEqual(features["ssl-tls"]["status"], "functional")
        self.assertEqual(features["installer"]["status"], "functional")

    def test_client_sync_jobs_show_owned_simulated_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_config(root)
            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with ClientApiServer(config) as server:
                token = server.login()
                domains = server.request("GET", "/api/client/domains", token=token)["domains"]
                server.request(
                    "POST",
                    "/api/client/dns-records",
                    {"domain_id": domains[0]["id"], "type": "TXT", "name": "_phase6", "value": "ok", "ttl": 300},
                    token,
                )
                payload = server.request("GET", "/api/client/sync-jobs", token=token)

        dns_jobs = [job for job in payload["jobs"] if job["type"] == "sync_dns_record"]
        self.assertTrue(dns_jobs)
        self.assertEqual(dns_jobs[0]["status"], "succeeded")
        self.assertTrue(dns_jobs[0]["artifact"]["exists"])
        self.assertIn(".runtime/dns/", dns_jobs[0]["artifact"]["path"])
        self.assertNotIn(str(config.account_root), dns_jobs[0]["artifact"]["path"])


if __name__ == "__main__":
    unittest.main()
