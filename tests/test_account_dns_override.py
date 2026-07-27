import tempfile
import unittest
import uuid
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from mangopanel.providers import DNS_PROVIDER_CLOUDFLARE, DNS_PROVIDER_LOCAL_POWERDNS
from mangopanel.security import encrypt_secret
from tests.test_phase3_routes import ClientApiServer, PASSWORD


class AccountDnsOverrideTests(unittest.TestCase):
    def make_config(self, root):
        config = Config()
        config.db_path = root / "mangopanel.sqlite3"
        config.data_dir = root
        config.account_root = root / "accounts"
        config.agent_mode = "simulate"
        config.agent_inline = True
        config.dev_auth_test_mode = True
        return config

    def admin_token(self, config):
        return app_module.create_jwt(
            {"sub": 1, "actor_type": "admin", "purpose": "access", "jti": uuid.uuid4().hex},
            config.jwt_secret,
            config.token_ttl_seconds,
        )

    def test_dns_precedence_account_plan_global(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with connect(config.db_path) as conn:
                # Setup active Cloudflare provider account ID = 1
                acc_id = conn.execute(
                    """
                    INSERT INTO dns_provider_accounts(provider_id, display_name, account_name, external_account_id, status)
                    VALUES (2, 'CF Primary', 'Main Account', 'cf-acc-1', 'active')
                    """
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO dns_provider_credentials(provider_account_id, credential_kind, secret_label, encrypted_secret, status)
                    VALUES (?, 'api_token', 'token:secret', ?, 'stored')
                    """,
                    (acc_id, encrypt_secret("secret-val", config.jwt_secret)),
                )

                # 1. Initially: No account override, Plan is local_powerdns -> Global/Plan resolves to local_powerdns
                policy = app_module.account_dns_policy(conn, 1)
                self.assertEqual(policy["dns_provider"], DNS_PROVIDER_LOCAL_POWERDNS)

                # 2. Update Plan to Cloudflare -> Plan precedence takes effect (source = "plan")
                conn.execute("UPDATE plans SET dns_default_provider = ?, dns_default_provider_account_id = ? WHERE id = 1", (DNS_PROVIDER_CLOUDFLARE, acc_id))
                policy_plan = app_module.account_dns_policy(conn, 1)
                self.assertEqual(policy_plan["dns_provider"], DNS_PROVIDER_CLOUDFLARE)
                self.assertEqual(policy_plan["source"], "plan")
                self.assertIn("CF Primary", policy_plan["display_label"])

                # 3. Update Hosting Account override to local_powerdns -> Account precedence overrides Plan (source = "account")
                conn.execute("UPDATE hosting_accounts SET dns_provider = ? WHERE id = 1", (DNS_PROVIDER_LOCAL_POWERDNS,))
                policy_acct = app_module.account_dns_policy(conn, 1)
                self.assertEqual(policy_acct["dns_provider"], DNS_PROVIDER_LOCAL_POWERDNS)
                self.assertEqual(policy_acct["source"], "account")
                self.assertIn("from account", policy_acct["display_label"])

    def test_admin_api_account_dns_override_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with connect(config.db_path) as conn:
                acc_id = conn.execute(
                    """
                    INSERT INTO dns_provider_accounts(provider_id, display_name, account_name, external_account_id, status)
                    VALUES (2, 'CF Secondary', 'Secondary Account', 'cf-acc-2', 'active')
                    """
                ).lastrowid

            token = self.admin_token(config)

            with ClientApiServer(config, panel="admin") as server:
                # 1. Update account 1 to use Cloudflare via API endpoint
                patch_res = server.request(
                    "PATCH",
                    "/api/admin/hosting-accounts/1/dns-provider",
                    {"dns_provider": "cloudflare", "dns_provider_account_id": acc_id},
                    token,
                )
                self.assertEqual(patch_res["dns_provider"], "cloudflare")
                # 2. Check GET /api/admin/clients payload includes effective DNS label and source
                clients_res = server.request("GET", "/api/admin/clients", token=token)
                account_item = clients_res["clients"][0]["accounts"][0]
                self.assertEqual(account_item["dns_source"], "account")
                self.assertIn("CF Secondary", account_item["effective_dns_label"])

                # 3. Check GET /api/admin/dns-settings includes hosting_account_count and zone_count
                dns_res = server.request("GET", "/api/admin/dns-settings", token=token)
                cf_acc = next(a for a in dns_res["dns_settings"]["accounts"] if a["id"] == acc_id)
                self.assertGreaterEqual(cf_acc["hosting_account_count"], 1)

    def test_cloudflare_account_creation_fetches_and_caches_remote_zones(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            token = self.admin_token(config)

            from tests.test_providers import FakeCloudflareHandler, FakeHTTPServer
            FakeCloudflareHandler.zones = [
                {"id": "zone_1", "name": "example1.com", "name_servers": ["ns1.cf.test"], "status": "active"},
                {"id": "zone_2", "name": "example2.com", "name_servers": ["ns1.cf.test"], "status": "active"},
                {"id": "zone_3", "name": "example3.com", "name_servers": ["ns1.cf.test"], "status": "active"},
            ]
            with FakeHTTPServer(FakeCloudflareHandler) as fake_cf:
                config.cloudflare_api_base = f"{fake_cf.base_url}/client/v4"
                with ClientApiServer(config, panel="admin") as server:
                    # 1. Create new Cloudflare account - should immediately query and cache remote_zone_count (3)
                    res = server.request(
                        "POST",
                        "/api/admin/dns-providers/cloudflare/accounts",
                        {
                            "display_name": "CF Cache Account",
                            "account_name": "Cached Test",
                            "external_account_id": "cf-account-1",
                            "api_token": "valid-cf-token-123",
                        },
                        token=token,
                    )
                    acc_id = res["account_id"]
                    cf_acc = next(a for a in res["dns_settings"]["accounts"] if a["id"] == acc_id)
                    self.assertEqual(cf_acc["zone_count"], 3)
                    self.assertEqual(cf_acc["metadata"].get("remote_zone_count"), 3)

                    # 2. Change base URL to invalid endpoint to ensure subsequent GET /api/admin/dns-settings reads cached zone_count without making network calls
                    config.cloudflare_api_base = "http://invalid-endpoint-should-not-be-called.test"
                    dns_res = server.request("GET", "/api/admin/dns-settings", token=token)
                    cf_acc_cached = next(a for a in dns_res["dns_settings"]["accounts"] if a["id"] == acc_id)
                    self.assertEqual(cf_acc_cached["zone_count"], 3)


if __name__ == "__main__":
    unittest.main()
