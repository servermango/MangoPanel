import tempfile
import unittest
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.agent import Agent
from mangopanel.db import seed_dev_data
from tests.test_phase3_routes import ClientApiServer


class NameserversSaveTests(unittest.TestCase):
    def test_save_nameservers_updates_domain_when_no_registrar_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = app_module.load_config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"
            config.agent_inline = True
            config.dev_auth_test_mode = True
            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with ClientApiServer(config) as server:
                token = server.login()
                domains = server.request("GET", "/api/client/domains", token=token)["domains"]
                domain_id = domains[0]["id"]

                # Post custom nameservers for domain without a registrar_provider_id
                res = server.request(
                    "POST",
                    f"/api/client/domains/{domain_id}/nameservers",
                    body={"source": "custom", "nameservers": ["ns1.example.com", "ns2.example.com"]},
                    token=token,
                )
                domain = res["domain"]
                self.assertEqual(domain["nameservers"], ["ns1.example.com", "ns2.example.com"])
                self.assertEqual(domain["nameserver_source"], "custom")

                # Verify warning is now gone
                warning_codes = [w["code"] for w in domain.get("dns_warnings", [])]
                self.assertNotIn("missing_nameservers", warning_codes)

                # Test 'default' source (Use recommended nameservers)
                res_def = server.request(
                    "POST",
                    f"/api/client/domains/{domain_id}/nameservers",
                    body={"source": "default", "nameservers": []},
                    token=token,
                )
                domain_def = res_def["domain"]
                self.assertTrue(len(domain_def["nameservers"]) >= 2)
                self.assertEqual(domain_def["nameserver_source"], "default")
                warning_codes_def = [w["code"] for w in domain_def.get("dns_warnings", [])]
                self.assertNotIn("missing_nameservers", warning_codes_def)


if __name__ == "__main__":
    unittest.main()
