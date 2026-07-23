import tempfile
import unittest
import uuid
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from mangopanel.app import default_domain_dns_assignment
from mangopanel.providers import DNS_PROVIDER_CLOUDFLARE, DNS_PROVIDER_LOCAL_POWERDNS
from tests.test_phase3_routes import ClientApiServer


class DomainMigrationUITests(unittest.TestCase):
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

    def client_token(self, config, user_id=2):
        return app_module.create_jwt(
            {"sub": user_id, "actor_type": "user", "purpose": "access", "jti": uuid.uuid4().hex},
            config.jwt_secret,
            config.token_ttl_seconds,
        )

    def test_plan_update_migrates_existing_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            token = self.admin_token(config)

            with ClientApiServer(config, panel="admin") as server:
                with connect(config.db_path) as conn:
                    plan = conn.execute("SELECT * FROM plans LIMIT 1").fetchone()
                    domain = conn.execute("SELECT * FROM domains LIMIT 1").fetchone()

                response = server.request(
                    "PATCH",
                    "/api/admin/plans/{}".format(plan["id"]),
                    body={
                        "name": plan["name"],
                        "cpu_limit": plan["cpu_limit"],
                        "memory_mb": plan["memory_mb"],
                        "storage_mb": plan["storage_mb"],
                        "inode_limit": plan["inode_limit"],
                        "max_websites": plan["max_websites"],
                        "max_databases": plan["max_databases"],
                        "max_mailboxes": plan["max_mailboxes"],
                        "max_cron_jobs": plan["max_cron_jobs"],
                        "daily_email_limit": plan["daily_email_limit"],
                        "backup_retention_days": plan["backup_retention_days"],
                        "max_processes": plan["max_processes"],
                        "php_workers": plan["php_workers"],
                        "bandwidth_mb": plan["bandwidth_mb"],
                        "nameserver_1": plan["nameserver_1"],
                        "nameserver_2": plan["nameserver_2"],
                        "backup_location": plan["backup_location"],
                        "frontend_frameworks": plan["frontend_frameworks"],
                        "backend_frameworks": plan["backend_frameworks"],
                        "nodejs_versions": plan["nodejs_versions"],
                        "package_managers": plan["package_managers"],
                        "dns_default_provider": DNS_PROVIDER_LOCAL_POWERDNS,
                        "dns_default_provider_account_id": None,
                        "migrate_existing_domains": True,
                    },
                    token=token,
                )
                self.assertIn("migrated_domain_count", response)

    def test_bulk_migrate_all_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)
            token = self.admin_token(config)

            with ClientApiServer(config, panel="admin") as server:
                response = server.request(
                    "POST",
                    "/api/admin/domains/dns/bulk-migrate-provider",
                    body={
                        "all": True,
                        "dns_provider": DNS_PROVIDER_LOCAL_POWERDNS,
                    },
                    token=token,
                )
                self.assertIn("jobs", response)
                self.assertIn("domains", response)

    def test_client_migrate_domain_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                domain = conn.execute("SELECT * FROM domains WHERE account_id = ?", (account["id"],)).fetchone()
                user_id = account["user_id"]

            token = self.client_token(config, user_id=user_id)

            with ClientApiServer(config, panel="client") as server:
                response = server.request(
                    "POST",
                    "/api/client/domains/{}/dns/migrate-provider".format(domain["id"]),
                    body={
                        "dns_provider": DNS_PROVIDER_LOCAL_POWERDNS,
                    },
                    token=token,
                )
                self.assertIn("job_id", response)
                self.assertEqual(response["domain"]["dns_provider"], DNS_PROVIDER_LOCAL_POWERDNS)

    def test_client_set_default_dns_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()
                domain = conn.execute("SELECT * FROM domains WHERE account_id = ?", (account["id"],)).fetchone()
                user_id = account["user_id"]

            token = self.client_token(config, user_id=user_id)

            with ClientApiServer(config, panel="client") as server:
                response = server.request(
                    "POST",
                    "/api/client/domains/{}/dns/set-default-records".format(domain["id"]),
                    body={},
                    token=token,
                )
                self.assertIn("job_id", response)
                self.assertIn("public_ip", response)
                with connect(config.db_path) as conn:
                    records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ?", (domain["id"],)).fetchall()
                    types = {r["type"] for r in records}
                    self.assertIn("A", types)
                    self.assertIn("CNAME", types)
                    self.assertIn("MX", types)
                    self.assertIn("TXT", types)

    def test_multiple_plans_with_different_dns_providers_coexist(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            seed_dev_data(config.db_path, config.account_root)

            with connect(config.db_path) as conn:
                conn.execute("UPDATE plans SET dns_default_provider = ? WHERE id = 1", (DNS_PROVIDER_CLOUDFLARE,))
                conn.execute(
                    """
                    INSERT INTO plans(name, cpu_limit, memory_mb, storage_mb, inode_limit, max_websites, max_databases, max_mailboxes, max_cron_jobs, daily_email_limit, backup_retention_days, max_processes, php_workers, bandwidth_mb, nameserver_1, nameserver_2, backup_location, frontend_frameworks, backend_frameworks, nodejs_versions, package_managers, dns_default_provider)
                    VALUES('Local Plan', '1.0', 1024, 10240, 50000, 5, 5, 5, 5, 500, 7, 20, 2, 0, 'ns1.mango.test', 'ns2.mango.test', 'local', '', '', '', '', ?)
                    """,
                    (DNS_PROVIDER_LOCAL_POWERDNS,),
                )
                plan2_id = conn.execute("SELECT id FROM plans WHERE name = 'Local Plan'").fetchone()["id"]
                account1 = conn.execute("SELECT * FROM hosting_accounts LIMIT 1").fetchone()

                conn.execute("UPDATE hosting_accounts SET plan_id = 1 WHERE id = ?", (account1["id"],))

                cur = conn.execute(
                    "INSERT INTO hosting_accounts(user_id, plan_id, node_id, username, base_path, status) VALUES(?, ?, ?, ?, ?, ?)",
                    (account1["user_id"], plan2_id, account1["node_id"], "u000099", "/root/MangoPanel/user_files/accounts/u000099", "active"),
                )
                account2_id = cur.lastrowid

                assign_cf = default_domain_dns_assignment(conn, account1["id"])
                assign_local = default_domain_dns_assignment(conn, account2_id)

                self.assertEqual(assign_cf["dns_provider"], DNS_PROVIDER_CLOUDFLARE)
                self.assertEqual(assign_local["dns_provider"], DNS_PROVIDER_LOCAL_POWERDNS)
