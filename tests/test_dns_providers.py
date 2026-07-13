import tempfile
import unittest
import uuid
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import connect, create_job, seed_dev_data
from mangopanel.providers import DNS_PROVIDER_CLOUDFLARE, DNS_PROVIDER_LOCAL, DNS_PROVIDER_LOCAL_POWERDNS
from mangopanel.security import encrypt_secret
from tests.test_phase3_routes import ClientApiServer
from tests.test_providers import FakeCloudflareHandler, FakePowerDNSHandler, FakeHTTPServer


class DNSProviderFoundationTests(unittest.TestCase):
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

    def test_admin_dns_settings_and_cloudflare_account_foundation(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            token = self.admin_token(config)

            with ClientApiServer(config, panel="admin") as server:
                settings = server.request("GET", "/api/admin/dns-settings", token=token)["dns_settings"]
                self.assertEqual(settings["global_mode"], DNS_PROVIDER_LOCAL_POWERDNS)
                self.assertTrue(any(provider["key"] == DNS_PROVIDER_CLOUDFLARE for provider in settings["providers"]))

                updated = server.request(
                    "PATCH",
                    "/api/admin/dns-settings",
                    {
                        "global_mode": DNS_PROVIDER_LOCAL_POWERDNS,
                        "local": {
                            "nameservers": ["ns1.example.test", "ns2.example.test"],
                            "public_ipv4": "127.0.0.1",
                            "public_ipv6": "",
                            "soa_email": "hostmaster.example.test",
                            "default_ttl": 300,
                        },
                    },
                    token,
                )["dns_settings"]
                self.assertEqual(updated["local"]["nameservers"], ["ns1.example.test", "ns2.example.test"])

                created = server.request(
                    "POST",
                    "/api/admin/dns-providers/cloudflare/accounts",
                    {
                        "display_name": "Main Cloudflare",
                        "account_name": "Example Hosting",
                        "external_account_id": "cf-account-1",
                        "api_token": "secret-token-value",
                    },
                    token,
                )
                account = next(item for item in created["dns_settings"]["accounts"] if item["id"] == created["account_id"])
                self.assertTrue(account["has_secret"])
                self.assertNotIn("secret-token-value", str(account))

                provider = next(item for item in created["dns_settings"]["providers"] if item["key"] == DNS_PROVIDER_CLOUDFLARE)
                health = server.request(
                    "POST",
                    "/api/admin/dns-providers/{}/test".format(provider["id"]),
                    {"provider_account_id": created["account_id"]},
                    token,
                )
                self.assertEqual(health["status"], "configured")

            with connect(config.db_path) as conn:
                credential = conn.execute("SELECT encrypted_secret FROM dns_provider_credentials LIMIT 1").fetchone()
                self.assertNotIn("secret-token-value", credential["encrypted_secret"])

    def test_plan_dns_policy_limits_client_record_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                conn.execute(
                    """
                    UPDATE plans
                    SET dns_allowed_record_types_json = ?, dns_min_ttl = ?, dns_max_records_per_domain = ?
                    WHERE id = ?
                    """,
                    ('["TXT"]', 600, 100, account["plan_id"]),
                )

            with ClientApiServer(config) as server:
                token = server.login()
                domain = server.request("GET", "/api/client/domains", token=token)["domains"][0]
                self.assertEqual(
                    server.request_error(
                        "POST",
                        "/api/client/dns-records",
                        {"domain_id": domain["id"], "type": "A", "name": "blocked", "value": "127.0.0.1", "ttl": 600},
                        token,
                    )[0],
                    400,
                )
                self.assertEqual(
                    server.request_error(
                        "POST",
                        "/api/client/dns-records",
                        {"domain_id": domain["id"], "type": "TXT", "name": "_lowttl", "value": "ok", "ttl": 300},
                        token,
                    )[0],
                    400,
                )

    def test_agent_delegates_cloudflare_dns_sync_and_saves_nameservers(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.agent_inline = False
            seed_dev_data(config.db_path, config.account_root)
            FakeCloudflareHandler.created_zone = None
            FakeCloudflareHandler.created_records = []

            with FakeHTTPServer(FakeCloudflareHandler) as fake_cf:
                config.cloudflare_api_base = fake_cf.base_url + "/client/v4"
                with connect(config.db_path) as conn:
                    provider = conn.execute("SELECT * FROM dns_providers WHERE key = ?", (DNS_PROVIDER_CLOUDFLARE,)).fetchone()
                    account_id = conn.execute(
                        """
                        INSERT INTO dns_provider_accounts(provider_id, display_name, account_name, external_account_id, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (provider["id"], "Main Cloudflare", "Example Hosting", "account-1", "active"),
                    ).lastrowid
                    conn.execute(
                        """
                        INSERT INTO dns_provider_credentials(provider_account_id, credential_kind, secret_label, encrypted_secret, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (account_id, "api_token", "token:...alue", encrypt_secret("secret-token-value", config.jwt_secret), "stored"),
                    )
                    domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()
                    conn.execute(
                        """
                        UPDATE domains
                        SET dns_provider = ?, dns_provider_account_id = ?, nameservers_json = '[]', dns_status = 'pending_provider_sync'
                        WHERE id = ?
                        """,
                        (DNS_PROVIDER_CLOUDFLARE, account_id, domain["id"]),
                    )
                    job_id = create_job(conn, "sync_dns_zone", "domain", domain["id"], {})

                result = Agent(config).run_job_by_id(job_id)

            self.assertEqual(result["status"], "succeeded")
            self.assertTrue(FakeCloudflareHandler.created_records)
            with connect(config.db_path) as conn:
                zone = conn.execute("SELECT * FROM dns_zones WHERE zone_name = ?", ("example.mango.test",)).fetchone()
                domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()
                self.assertEqual(zone["provider"], DNS_PROVIDER_CLOUDFLARE)
                self.assertIn("abby.ns.cloudflare.com", zone["nameservers_json"])
                self.assertEqual(domain["provider_zone_id"], "cf-zone-1")

    def test_admin_migrates_domain_to_cloudflare_and_exports_zone(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            token = self.admin_token(config)
            FakeCloudflareHandler.created_zone = None
            FakeCloudflareHandler.created_records = []

            with FakeHTTPServer(FakeCloudflareHandler) as fake_cf:
                config.cloudflare_api_base = fake_cf.base_url + "/client/v4"
                with connect(config.db_path) as conn:
                    provider = conn.execute("SELECT * FROM dns_providers WHERE key = ?", (DNS_PROVIDER_CLOUDFLARE,)).fetchone()
                    account_id = conn.execute(
                        """
                        INSERT INTO dns_provider_accounts(provider_id, display_name, account_name, external_account_id, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (provider["id"], "Main Cloudflare", "Example Hosting", "account-1", "active"),
                    ).lastrowid
                    conn.execute(
                        """
                        INSERT INTO dns_provider_credentials(provider_account_id, credential_kind, secret_label, encrypted_secret, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (account_id, "api_token", "token:...alue", encrypt_secret("secret-token-value", config.jwt_secret), "stored"),
                    )
                    domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()

                with ClientApiServer(config, panel="admin") as server:
                    migrated = server.request(
                        "POST",
                        "/api/admin/domains/{}/dns/migrate-provider".format(domain["id"]),
                        {"dns_provider": DNS_PROVIDER_CLOUDFLARE, "dns_provider_account_id": account_id},
                        token,
                    )
                    self.assertEqual(migrated["domain"]["dns_provider"], DNS_PROVIDER_CLOUDFLARE)
                    self.assertIn("abby.ns.cloudflare.com", migrated["domain"]["nameservers"])
                    self.assertEqual(migrated["domain"]["dns_status"], "pending_nameserver")

                    exported = server.request("GET", "/api/admin/domains/{}/dns/export".format(domain["id"]), token=token)
                    self.assertEqual(exported["dns_zone_export"]["domain"]["name"], "example.mango.test")
                    self.assertTrue(exported["dns_zone_export"]["records"])

            with connect(config.db_path) as conn:
                domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()
                self.assertEqual(domain["previous_dns_provider"], DNS_PROVIDER_LOCAL_POWERDNS)
                self.assertIn("pending_nameserver", domain["dns_migration_state_json"])

    def test_client_dns_validation_blocks_cname_conflicts_and_locked_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with ClientApiServer(config) as server:
                token = server.login()
                domain = server.request("GET", "/api/client/domains", token=token)["domains"][0]
                self.assertEqual(
                    server.request_error(
                        "POST",
                        "/api/client/dns-records",
                        {"domain_id": domain["id"], "type": "CNAME", "name": "@", "value": "target.example.test", "ttl": 300},
                        token,
                    )[0],
                    409,
                )
                created = server.request(
                    "POST",
                    "/api/client/dns-records",
                    {"domain_id": domain["id"], "type": "CNAME", "name": "api", "value": "example.mango.test", "ttl": 300},
                    token,
                )
                self.assertEqual(
                    server.request_error(
                        "POST",
                        "/api/client/dns-records",
                        {"domain_id": domain["id"], "type": "A", "name": "api", "value": "127.0.0.1", "ttl": 300},
                        token,
                    )[0],
                    409,
                )

                with connect(config.db_path) as conn:
                    conn.execute("UPDATE dns_records SET locked = 1 WHERE id = ?", (created["dns_record_id"],))

                self.assertEqual(
                    server.request_error("DELETE", "/api/client/dns-records/{}".format(created["dns_record_id"]), token=token)[0],
                    403,
                )

    def test_client_can_export_dns_zone_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with ClientApiServer(config) as server:
                token = server.login()
                domain = server.request("GET", "/api/client/domains", token=token)["domains"][0]
                payload = server.request("GET", "/api/client/domains/{}/dns/export".format(domain["id"]), token=token)
                self.assertEqual(payload["dns_zone_export"]["domain"]["id"], domain["id"])
                self.assertTrue(payload["dns_zone_export"]["records"])


if __name__ == "__main__":
    unittest.main()


class LocalPowerDNSAgentTests(unittest.TestCase):
    """Integration tests for the local_powerdns (PowerDNS) DNS provider through the agent layer."""

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

    def setUp(self):
        FakePowerDNSHandler.patched_rrsets = []
        FakePowerDNSHandler.deleted_zones = []
        FakePowerDNSHandler.zone_exists = False

    # ------------------------------------------------------------------
    # Agent dispatches sync_dns_zone using the live PowerDNS provider
    # ------------------------------------------------------------------

    def test_agent_syncs_zone_via_local_powerdns_provider(self):
        """When powerdns_api_url and powerdns_api_key are configured, the agent
        uses PowerDNSProvider (not LocalDNSProvider) to publish the zone and
        records the correct provider key in the dns_zones table."""
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.agent_inline = False
            seed_dev_data(config.db_path, config.account_root)
            FakePowerDNSHandler.patched_rrsets = []
            FakePowerDNSHandler.zone_exists = False

            with FakeHTTPServer(FakePowerDNSHandler) as fake_pdns:
                config.powerdns_api_url = fake_pdns.base_url + "/api/v1"
                config.powerdns_api_key = "dev-test-key"

                with connect(config.db_path) as conn:
                    # Find the domain seeded in dev data; ensure it uses local_powerdns
                    domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()
                    conn.execute(
                        "UPDATE domains SET dns_provider = ? WHERE id = ?",
                        (DNS_PROVIDER_LOCAL_POWERDNS, domain["id"]),
                    )
                    job_id = create_job(conn, "sync_dns_zone", "domain", domain["id"], {})

                result = Agent(config).run_job_by_id(job_id)

            self.assertEqual(result["status"], "succeeded")
            # At least one PATCH was sent to the fake PowerDNS server
            self.assertTrue(
                FakePowerDNSHandler.patched_rrsets,
                "Agent should have sent at least one PATCH to the PowerDNS API",
            )
            # The dns_zones table should record the correct provider
            with connect(config.db_path) as conn:
                zone = conn.execute("SELECT * FROM dns_zones WHERE zone_name = ?", ("example.mango.test",)).fetchone()
            self.assertIsNotNone(zone)
            self.assertEqual(zone["provider"], DNS_PROVIDER_LOCAL_POWERDNS)
            # The zone state returned by the job should identify the provider
            self.assertEqual(result["result"]["provider"], DNS_PROVIDER_LOCAL_POWERDNS)

    # ------------------------------------------------------------------
    # Fallback: no PowerDNS credentials → uses LocalDNSProvider
    # ------------------------------------------------------------------

    def test_agent_falls_back_to_local_provider_when_powerdns_not_configured(self):
        """When powerdns_api_url / powerdns_api_key are empty, the agent falls
        back to LocalDNSProvider and the zone is still published successfully as
        the local-dev-dns provider."""
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.agent_inline = False
            # Explicitly leave PowerDNS credentials empty
            config.powerdns_api_url = ""
            config.powerdns_api_key = ""
            seed_dev_data(config.db_path, config.account_root)

            with connect(config.db_path) as conn:
                domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()
                conn.execute(
                    "UPDATE domains SET dns_provider = ? WHERE id = ?",
                    (DNS_PROVIDER_LOCAL_POWERDNS, domain["id"]),
                )
                job_id = create_job(conn, "sync_dns_zone", "domain", domain["id"], {})

            result = Agent(config).run_job_by_id(job_id)

        self.assertEqual(result["status"], "succeeded")
        # Fallback uses the local dev provider
        self.assertEqual(result["result"]["provider"], DNS_PROVIDER_LOCAL)
        # No HTTP call to a real PowerDNS server should have happened
        self.assertFalse(
            FakePowerDNSHandler.patched_rrsets,
            "No PowerDNS HTTP calls should have been made in fallback mode",
        )

    # ------------------------------------------------------------------
    # Admin health test for local_powerdns always reports "configured"
    # ------------------------------------------------------------------

    def test_admin_health_test_reports_configured_for_local_powerdns(self):
        """The admin DNS provider test endpoint should return status='configured'
        for local_powerdns without needing any external credentials."""
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            token = self.admin_token(config)

            with ClientApiServer(config, panel="admin") as server:
                # Retrieve the local_powerdns provider row from dns-settings
                settings = server.request("GET", "/api/admin/dns-settings", token=token)["dns_settings"]
                local_provider = next(
                    (p for p in settings["providers"] if p["key"] == DNS_PROVIDER_LOCAL_POWERDNS),
                    None,
                )
                self.assertIsNotNone(local_provider, "local_powerdns provider should be seeded")
                provider_id = local_provider["id"]

                # Call the health-check test endpoint (no provider_account_id needed for local)
                health = server.request(
                    "POST",
                    "/api/admin/dns-providers/{}/test".format(provider_id),
                    {},
                    token,
                )

            self.assertEqual(health["status"], "configured")

    # ------------------------------------------------------------------
    # Custom nameservers from admin settings propagate to the zone state
    # ------------------------------------------------------------------

    def test_custom_nameservers_from_dns_settings_propagate_to_zone(self):
        """Nameservers stored in the local_powerdns provider config_json should
        be used when publishing the zone through the agent."""
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.agent_inline = False
            seed_dev_data(config.db_path, config.account_root)
            token = self.admin_token(config)
            FakePowerDNSHandler.patched_rrsets = []
            FakePowerDNSHandler.zone_exists = False

            with FakeHTTPServer(FakePowerDNSHandler) as fake_pdns:
                config.powerdns_api_url = fake_pdns.base_url + "/api/v1"
                config.powerdns_api_key = "dev-test-key"

                # Update nameservers via the admin API
                with ClientApiServer(config, panel="admin") as server:
                    server.request(
                        "PATCH",
                        "/api/admin/dns-settings",
                        {
                            "global_mode": DNS_PROVIDER_LOCAL_POWERDNS,
                            "local": {
                                "nameservers": ["ns1.custom.example.test", "ns2.custom.example.test"],
                                "public_ipv4": "127.0.0.1",
                                "public_ipv6": "",
                                "soa_email": "admin.custom.example.test",
                                "default_ttl": 300,
                            },
                        },
                        token,
                    )

                with connect(config.db_path) as conn:
                    domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()
                    conn.execute(
                        "UPDATE domains SET dns_provider = ? WHERE id = ?",
                        (DNS_PROVIDER_LOCAL_POWERDNS, domain["id"]),
                    )
                    job_id = create_job(conn, "sync_dns_zone", "domain", domain["id"], {})

                result = Agent(config).run_job_by_id(job_id)

            self.assertEqual(result["status"], "succeeded")
            # The NS rrset pushed to PowerDNS should contain the custom nameservers
            rrsets = FakePowerDNSHandler.patched_rrsets[0]["rrsets"]
            ns_rrset = next((r for r in rrsets if r["type"] == "NS"), None)
            self.assertIsNotNone(ns_rrset, "NS rrset should be present")
            ns_contents = [rec["content"] for rec in ns_rrset["records"]]
            self.assertTrue(
                any("ns1.custom.example.test" in c for c in ns_contents),
                "Custom nameserver ns1.custom.example.test should appear in the NS rrset",
            )

