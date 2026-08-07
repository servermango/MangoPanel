import tempfile
import unittest
import uuid
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from mangopanel.providers import DNS_PROVIDER_CLOUDFLARE, DNS_PROVIDER_LOCAL_POWERDNS
from mangopanel.security import encrypt_secret
from tests.test_phase3_routes import ClientApiServer
from tests.test_providers import FakeCloudflareHandler, FakeHTTPServer


class DomainDnsCheckTests(unittest.TestCase):
    def make_config(self, root):
        config = Config()
        config.db_path = root / "mangopanel.sqlite3"
        config.data_dir = root
        config.account_root = root / "accounts"
        config.agent_mode = "simulate"
        config.agent_inline = True
        config.dev_auth_test_mode = True
        return config

    def client_token(self, config, user_id=1):
        return app_module.create_jwt(
            {"sub": user_id, "actor_type": "user", "purpose": "access", "jti": uuid.uuid4().hex},
            config.jwt_secret,
            config.token_ttl_seconds,
        )

    def test_local_dns_domain_check_and_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with ClientApiServer(config, panel="client") as server:
                token = server.login()
                # 1. Non-existent domain should return exists: False
                res = server.request("POST", "/api/client/dns/check-domain", {"domain": "new-unique-domain.mango.test"}, token)
                self.assertFalse(res["exists"])

                # 2. Existing domain in DB (e.g. example.mango.test) should return exists: True, blocked: True
                res_exist = server.request("POST", "/api/client/dns/check-domain", {"domain": "example.mango.test"}, token)
                self.assertTrue(res_exist["exists"])
                self.assertTrue(res_exist.get("blocked"))
                self.assertIn("exists on another account on this hosting", res_exist["error_message"])

                # 3. Trying to create website for existing domain should be blocked with HTTP 409 and exact message
                status, error_res = server.request_error("POST", "/api/client/websites", {"domain": "example.mango.test"}, token)
                self.assertEqual(status, 409)
                self.assertIn("exists on another account on this hosting", str(error_res))

    def test_subdomain_dns_consent_updates_existing_a_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT id FROM hosting_accounts WHERE user_id = 1 LIMIT 1").fetchone()
                parent = conn.execute("SELECT id, name FROM domains WHERE account_id = ? LIMIT 1", (account["id"],)).fetchone()
                conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl, system_record, locked) VALUES (?, 'A', ?, '192.0.2.44', 300, 0, 0)",
                    (parent["id"], "consented-subdomain"),
                )

            with ClientApiServer(config, panel="client") as server:
                token = server.login()
                response = server.request(
                    "POST",
                    "/api/client/subdomains",
                    {
                        "subdomain": "consented-subdomain",
                        "parent_domain_id": parent["id"],
                        "configure_dns": True,
                    },
                    token,
                )
                self.assertEqual(response["subdomain"]["domain"], "consented-subdomain." + parent["name"])

            with connect(config.db_path) as conn:
                record = conn.execute(
                    "SELECT value, system_record, locked FROM dns_records WHERE domain_id = ? AND type = 'A' AND name = ?",
                    (parent["id"], "consented-subdomain"),
                ).fetchone()
                self.assertEqual(record["value"], app_module.get_host_public_ip(conn))
                self.assertEqual(record["system_record"], 1)
                self.assertEqual(record["locked"], 1)

    def test_cloudflare_dns_domain_check_and_choices(self):
        FakeCloudflareHandler.zones = [
            {
                "id": "cf-zone-123",
                "name": "existing-cf.mango.test",
                "status": "active",
                "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
            }
        ]
        FakeCloudflareHandler.dns_records = {
            "cf-zone-123": [
                {"id": "rec-1", "type": "A", "name": "existing-cf.mango.test", "content": "1.2.3.4", "ttl": 300, "proxied": True},
                {"id": "rec-2", "type": "TXT", "name": "existing-cf.mango.test", "content": "custom-txt-val", "ttl": 300, "proxied": False},
            ]
        }
        with FakeHTTPServer(FakeCloudflareHandler) as cf_server:
            with tempfile.TemporaryDirectory() as tmp:
                config = self.make_config(Path(tmp))
                config.cloudflare_api_base = f"{cf_server.base_url}/client/v4"
                seed_dev_data(config.db_path, config.account_root)

                with connect(config.db_path) as conn:
                    # Set plan DNS policy to Cloudflare
                    conn.execute("UPDATE plans SET dns_default_provider = ?, dns_default_provider_account_id = 1 WHERE id = 1", (DNS_PROVIDER_CLOUDFLARE,))
                    # Setup active Cloudflare account & credentials
                    acc_id = conn.execute(
                        """
                        INSERT INTO dns_provider_accounts(provider_id, display_name, account_name, external_account_id, status)
                        VALUES (2, 'CF Main', 'CF Account', 'cf-acc-1', 'active')
                        """
                    ).lastrowid
                    conn.execute(
                        """
                        INSERT INTO dns_provider_credentials(provider_account_id, credential_kind, secret_label, encrypted_secret, status)
                        VALUES (?, 'api_token', 'token:secret', ?, 'stored')
                        """,
                        (acc_id, encrypt_secret("secret-token-value", config.jwt_secret)),
                    )

                with ClientApiServer(config, panel="client") as server:
                    token = server.login()
                    # 1. Check existing Cloudflare domain
                    check_res = server.request("POST", "/api/client/dns/check-domain", {"domain": "existing-cf.mango.test"}, token)
                    self.assertTrue(check_res["exists"])
                    self.assertEqual(check_res["dns_provider"], "cloudflare")
                    self.assertTrue(check_res["blocked"])
                    self.assertNotIn("remote_records", check_res)
                    status, error_res = server.request_error(
                        "POST",
                        "/api/client/websites",
                        {"domain": "existing-cf.mango.test", "dns_action": "keep"},
                        token,
                    )
                    self.assertEqual(status, 409)
                    self.assertIn("not assigned to your hosting account", str(error_res))

                    # A remote zone is not enough to prove ownership. Once the
                    # domain is assigned to this account, the DNS choices and
                    # remote record import become available.
                    with connect(config.db_path) as conn:
                        account = conn.execute("SELECT id FROM hosting_accounts WHERE user_id = 1 LIMIT 1").fetchone()
                        conn.execute(
                            "INSERT INTO domains(account_id, name, kind, status) VALUES (?, ?, 'managed', 'active')",
                            (account["id"], "existing-cf.mango.test"),
                        )

                    check_res = server.request("POST", "/api/client/dns/check-domain", {"domain": "existing-cf.mango.test"}, token)
                    self.assertTrue(check_res["exists"])
                    self.assertEqual(len(check_res["remote_records"]), 2)

                    # 2. Add website with dns_action: 'keep'
                    create_res = server.request("POST", "/api/client/websites", {"domain": "existing-cf.mango.test", "dns_action": "keep"}, token)
                    self.assertEqual(create_res["website"]["domain"], "existing-cf.mango.test")

                # Verify remote records were saved locally in dns_records table
                with connect(config.db_path) as conn:
                    domain_row = conn.execute("SELECT id FROM domains WHERE name = ?", ("existing-cf.mango.test",)).fetchone()
                    records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ?", (domain_row["id"],)).fetchall()
                    rec_types = [r["type"] for r in records]
                    self.assertIn("A", rec_types)
                    self.assertIn("TXT", rec_types)

                    txt_record = next(r for r in records if r["type"] == "TXT" and r["name"] == "@")
                    self.assertEqual(txt_record["value"], "custom-txt-val")

    def test_sync_cloudflare_acme_rules_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with ClientApiServer(config, panel="client") as server:
                token = server.login()
                res = server.request("POST", "/api/client/dns/sync-cloudflare-rules", {}, token)
                self.assertTrue(res["success"])
                self.assertIsInstance(res["results"], list)


if __name__ == "__main__":
    unittest.main()
