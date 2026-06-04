import tempfile
import unittest
import uuid
import subprocess
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from tests.test_phase3_routes import ClientApiServer, PASSWORD


class Phase6HardeningTests(unittest.TestCase):
    def make_config(self, root):
        config = Config()
        config.db_path = root / "mangopanel.sqlite3"
        config.data_dir = root
        config.account_root = root / "accounts"
        config.agent_mode = "simulate"
        config.agent_inline = True
        config.dev_auth_test_mode = True
        return config

    def create_peer_account_token(self, config):
        email = "phase6-{}@example.mango.test".format(uuid.uuid4().hex)
        with connect(config.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO users(email, password_hash, full_name, totp_secret) VALUES (?, ?, ?, ?)",
                (email, app_module.hash_password(PASSWORD), "Phase Six Peer", app_module.generate_totp_secret()),
            )
            user_id = cur.lastrowid
            account_payload = app_module.create_initial_hosting_account(conn, user_id)
            token = app_module.create_jwt(
                {"sub": user_id, "actor_type": "user", "purpose": "access", "jti": uuid.uuid4().hex},
                config.jwt_secret,
                config.token_ttl_seconds,
            )
            return token, account_payload

    def prepared_server(self, root):
        config = self.make_config(root)
        seed_dev_data(config.db_path, config.account_root)
        Agent(config).run_all()
        return config, ClientApiServer(config)

    def test_metadata_and_sync_jobs_auth_and_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)

                self.assertEqual(server.request_error("GET", "/api/client/feature-status")[0], 401)
                self.assertIn("website", server.request("GET", "/api/client/feature-status", token=owner_token)["features"])

                self.assertEqual(server.request_error("GET", "/api/client/sync-jobs")[0], 401)
                domains = server.request("GET", "/api/client/domains", token=owner_token)["domains"]
                server.request(
                    "POST",
                    "/api/client/dns-records",
                    {"domain_id": domains[0]["id"], "type": "TXT", "name": "_phase6", "value": "ok", "ttl": 300},
                    owner_token,
                )
                owner_jobs = server.request("GET", "/api/client/sync-jobs", token=owner_token)["jobs"]
                other_jobs = server.request("GET", "/api/client/sync-jobs", token=other_token)["jobs"]

        self.assertTrue(any(job["type"] == "sync_dns_record" for job in owner_jobs))
        self.assertFalse(any(job["type"] == "sync_dns_record" for job in other_jobs))
        artifact = next(job["artifact"] for job in owner_jobs if job["type"] == "sync_dns_record")
        self.assertTrue(artifact["exists"])
        self.assertNotIn(str(config.account_root), artifact["path"])

    def test_phase2_provider_state_is_visible_to_client_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                domains = server.request("GET", "/api/client/domains", token=owner_token)["domains"]
                websites = server.request("GET", "/api/client/home", token=owner_token)["websites"]

                dns_payload = server.request(
                    "POST",
                    "/api/client/dns-records",
                    {"domain_id": domains[0]["id"], "type": "TXT", "name": "_phase2", "value": "provider-state", "ttl": 300},
                    owner_token,
                )
                self.assertEqual(dns_payload["dns_zones"][0]["provider"], "local-dev-dns")
                self.assertEqual(dns_payload["dns_zones"][0]["status"], "published")
                self.assertTrue(dns_payload["dns_zones"][0]["provider_state"]["records"])

                ssl_payload = server.request("POST", "/api/client/ssl/issue", {"website_id": websites[0]["id"]}, owner_token)
                self.assertEqual(ssl_payload["acme_order"]["provider"], "local-dev-acme")
                self.assertEqual(ssl_payload["acme_order"]["status"], "issued")
                self.assertEqual(ssl_payload["acme_order"]["provider_state"]["status"], "issued")

                mail_payload = server.request("GET", "/api/client/mail-routing", token=owner_token)
                self.assertTrue(mail_payload["mail_edge_routes"])
                self.assertEqual(mail_payload["mail_edge_routes"][0]["provider"], "shared-mail-edge")
                self.assertTrue(mail_payload["mail_edge_routes"][0]["manifest"]["mailboxes"])

                manifest, _ = server.request_with_headers("GET", "/api/public/mail-edge/manifest", host="mail.mango.test")
                self.assertEqual(manifest["provider"], "shared-mail-edge")
                self.assertTrue(manifest["accounts"][0]["mail_edge_routes"])

    def test_phase3_provider_routes_validate_auth_ownership_input_and_host_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                Agent(config).run_all()
                owner_domains = server.request("GET", "/api/client/domains", token=owner_token)["domains"]
                other_domains = server.request("GET", "/api/client/domains", token=other_token)["domains"]
                owner_site = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]
                other_site = server.request("GET", "/api/client/home", token=other_token)["websites"][0]
                owner_records = server.request("GET", f"/api/client/dns-records?domain_id={owner_domains[0]['id']}", token=owner_token)["dns_records"]
                other_records = server.request("GET", f"/api/client/dns-records?domain_id={other_domains[0]['id']}", token=other_token)["dns_records"]

                self.assertEqual(server.request_error("GET", "/api/client/dns-records")[0], 401)
                self.assertEqual(server.request_error("GET", "/api/client/dns-records?domain_id=abc", token=owner_token)[0], 400)
                self.assertEqual(server.request_error("GET", f"/api/client/dns-records?domain_id={other_domains[0]['id']}", token=owner_token)[0], 404)
                self.assertEqual(server.request_error("POST", "/api/client/dns-records", {"domain_id": owner_domains[0]["id"], "type": "TXT", "name": "_x", "value": "ok"})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/dns-records", {"domain_id": "abc", "type": "TXT", "name": "_x", "value": "ok"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/dns-records", {"domain_id": owner_domains[0]["id"], "type": "BAD", "name": "_x", "value": "ok"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/dns-records", {"domain_id": owner_domains[0]["id"], "type": "TXT", "name": "bad/name", "value": "ok"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/dns-records", {"domain_id": owner_domains[0]["id"], "type": "TXT", "name": "_x", "value": ""}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/dns-records", {"domain_id": owner_domains[0]["id"], "type": "TXT", "name": "_x", "value": "ok", "ttl": 1}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/dns-records", {"domain_id": other_domains[0]["id"], "type": "TXT", "name": "_x", "value": "ok"}, owner_token)[0], 404)
                self.assertEqual(server.request_error("DELETE", f"/api/client/dns-records/{other_records[0]['id']}", token=owner_token)[0], 404)
                deleted = server.request("DELETE", f"/api/client/dns-records/{owner_records[0]['id']}", token=owner_token)
                self.assertEqual(deleted["dns_zones"][0]["provider"], "local-dev-dns")

                self.assertEqual(server.request_error("POST", "/api/client/ssl/issue", {"website_id": owner_site["id"]})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/ssl/issue", {"website_id": "abc"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/ssl/issue", {"website_id": other_site["id"]}, owner_token)[0], 404)
                issued = server.request("POST", "/api/client/ssl/issue", {"website_id": owner_site["id"]}, owner_token)
                self.assertEqual(issued["acme_order"]["provider"], "local-dev-acme")

                self.assertEqual(server.request_error("GET", "/api/client/mail-routing")[0], 401)
                owner_mail = server.request("GET", "/api/client/mail-routing", token=owner_token)
                other_mail = server.request("GET", "/api/client/mail-routing", token=other_token)
                self.assertTrue(owner_mail["mail_edge_routes"])
                self.assertTrue(other_mail["mail_edge_routes"])
                self.assertNotEqual(owner_mail["mail_edge_routes"][0]["account_id"], other_mail["mail_edge_routes"][0]["account_id"])

                wrong_host_status, _, wrong_host_payload = server.request_raw(
                    "GET",
                    "/api/public/mail-edge/manifest",
                    host="files-u000001.localhost",
                )
                self.assertEqual(wrong_host_status, 404)
                self.assertEqual(wrong_host_payload["error"], "unknown_public_route")

    def test_phase3_browser_entry_pages_are_served_for_client_admin_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_config(root)
            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with ClientApiServer(config, panel="client") as client_server:
                client_status, client_headers, client_body = client_server.request_bytes("GET", "/client")
                status_status, status_headers, status_body = client_server.request_bytes("GET", "/status")
            with ClientApiServer(config, panel="admin") as admin_server:
                admin_status, admin_headers, admin_body = admin_server.request_bytes("GET", "/admin")

        self.assertEqual(client_status, 200)
        self.assertEqual(admin_status, 200)
        self.assertEqual(status_status, 200)
        self.assertEqual(client_headers["Content-Type"].split(";")[0], "text/html")
        self.assertEqual(admin_headers["Content-Type"].split(";")[0], "text/html")
        self.assertEqual(status_headers["Content-Type"].split(";")[0], "text/html")
        self.assertIn(b'id="client-app"', client_body)
        self.assertIn(b"MangoPanel Admin", admin_body)
        self.assertIn(b'id="status-app"', status_body)

    def test_postgresql_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)

                self.assertEqual(server.request_error("POST", "/api/client/pg-databases", {"name": "bad-name"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/pg-databases", {"name": "u000001_pg"}, None)[0], 401)
                created = server.request("POST", "/api/client/pg-databases", {"name": "u000001_phase6"}, owner_token)
                self.assertEqual(server.request_error("DELETE", "/api/client/pg-databases/{}".format(created["pg_database_id"]), token=other_token)[0], 404)

                self.assertEqual(server.request_error("POST", "/api/client/pg-databases/users", {"username": "u000001_user", "password": "short"}, owner_token)[0], 400)
                user = server.request("POST", "/api/client/pg-databases/users", {"username": "u000001_phase6_user", "password": "StrongPass123"}, owner_token)
                self.assertEqual(
                    server.request_error(
                        "POST",
                        "/api/client/pg-databases/users/grants",
                        {"database_id": created["pg_database_id"], "user_id": user["pg_user_id"], "privileges": "ROOT"},
                        owner_token,
                    )[0],
                    400,
                )
                self.assertEqual(server.request_error("DELETE", "/api/client/pg-databases/users/{}".format(user["pg_user_id"]), token=other_token)[0], 404)

    def test_custom_ssl_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                website_id = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]["id"]

                self.assertEqual(server.request_error("POST", "/api/client/ssl/custom", {"website_id": website_id, "crt": "x", "key": "y"})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/ssl/custom", {"website_id": website_id, "crt": "x", "key": ""}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/ssl/custom", {"website_id": website_id, "crt": "x", "key": "y"}, other_token)[0], 404)
                payload = server.request("POST", "/api/client/ssl/custom", {"website_id": website_id, "crt": "x", "key": "y"}, owner_token)
                self.assertEqual(payload["ssl_status"], "custom")

    def test_folder_index_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                website_id = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]["id"]

                self.assertEqual(server.request_error("PATCH", f"/api/client/websites/{website_id}", {"index_enabled": 1})[0], 401)
                self.assertEqual(server.request_error("PATCH", f"/api/client/websites/{website_id}", {"index_enabled": 2}, owner_token)[0], 400)
                self.assertEqual(server.request_error("PATCH", f"/api/client/websites/{website_id}", {"index_enabled": 1}, other_token)[0], 404)

                payload = server.request("PATCH", f"/api/client/websites/{website_id}", {"index_enabled": 1}, owner_token)
                self.assertEqual(payload["website"]["index_enabled"], 1)
                payload = server.request("PATCH", f"/api/client/websites/{website_id}", {"index_enabled": 0}, owner_token)
                self.assertEqual(payload["website"]["index_enabled"], 0)

    def test_analytics_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                website_id = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]["id"]

                self.assertEqual(server.request_error("PATCH", f"/api/client/websites/{website_id}", {"analytics_enabled": 2}, owner_token)[0], 400)
                self.assertEqual(server.request_error("PATCH", f"/api/client/websites/{website_id}", {"analytics_enabled": 0})[0], 401)
                self.assertEqual(server.request_error("PATCH", f"/api/client/websites/{website_id}", {"analytics_enabled": 0}, other_token)[0], 404)

                payload = server.request("PATCH", f"/api/client/websites/{website_id}", {"analytics_enabled": 0}, owner_token)
                self.assertEqual(payload["website"]["analytics_enabled"], 0)
                payload = server.request("PATCH", f"/api/client/websites/{website_id}", {"analytics_enabled": 1}, owner_token)
                self.assertEqual(payload["website"]["analytics_enabled"], 1)
                jobs = server.request("GET", "/api/client/sync-jobs", token=owner_token)["jobs"]
                self.assertTrue(any(job["type"] == "sync_website_analytics" and int(job["target_id"]) == website_id for job in jobs))

    def test_fix_ownership_route_is_account_scoped_and_auth_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, other_account = self.create_peer_account_token(config)
                owner_home = server.request("GET", "/api/client/home", token=owner_token)
                owner_account_id = owner_home["accounts"][0]["id"]

                self.assertEqual(server.request_error("POST", "/api/client/fix-ownership")[0], 401)
                owner_payload = server.request("POST", "/api/client/fix-ownership", token=owner_token)
                other_payload = server.request("POST", "/api/client/fix-ownership", token=other_token)
                owner_jobs = server.request("GET", "/api/client/sync-jobs", token=owner_token)["jobs"]
                other_jobs = server.request("GET", "/api/client/sync-jobs", token=other_token)["jobs"]

                owner_job = next(job for job in owner_jobs if job["id"] == owner_payload["job_id"])
                other_job = next(job for job in other_jobs if job["id"] == other_payload["job_id"])

                self.assertEqual(owner_job["target_id"], owner_account_id)
                self.assertEqual(other_job["target_id"], other_account["id"])

    def test_cache_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                website_id = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]["id"]

                self.assertEqual(server.request_error("POST", "/api/client/cache/purge")[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/cache/purge", {"website_id": "abc"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/cache/purge", {"website_id": website_id}, other_token)[0], 404)

                payload = server.request("POST", "/api/client/cache/purge", {"website_id": website_id}, owner_token)
                self.assertEqual(payload["status"], "queued")

                self.assertEqual(server.request_error("POST", "/api/client/cache/opcache/reset")[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/cache/opcache/reset", {"website_id": "abc"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/cache/opcache/reset", {"website_id": website_id}, other_token)[0], 404)
                opcode = server.request("POST", "/api/client/cache/opcache/reset", {"website_id": website_id}, owner_token)
                self.assertEqual(opcode["status"], "queued")

                self.assertEqual(server.request_error("POST", "/api/client/cache/object-cache/flush")[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/cache/object-cache/flush", {"website_id": "abc"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/cache/object-cache/flush", {"website_id": website_id}, other_token)[0], 404)
                object_cache = server.request("POST", "/api/client/cache/object-cache/flush", {"website_id": website_id}, owner_token)
                self.assertEqual(object_cache["status"], "queued")

    def test_cron_routes_validate_auth_ownership_and_schedule(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)

                self.assertEqual(server.request_error("GET", "/api/client/cron-jobs")[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/cron-jobs", {"schedule": "bad schedule", "command": "php cron.php"}, owner_token)[0], 400)

                created = server.request("POST", "/api/client/cron-jobs", {"schedule": "*/15 * * * *", "command": "php /home/u000001/domains/example.mango.test/public_html/cron.php"}, owner_token)
                cron_id = created["cron_job_id"]
                jobs = server.request("GET", "/api/client/cron-jobs", token=owner_token)["cron_jobs"]
                self.assertTrue(any(job["id"] == cron_id and job["next_run_at"] for job in jobs))

                self.assertEqual(server.request_error("PATCH", f"/api/client/cron-jobs/{cron_id}", {"status": "enabled"}, token=other_token)[0], 404)
                self.assertEqual(server.request_error("DELETE", f"/api/client/cron-jobs/{cron_id}", token=other_token)[0], 404)

    def test_git_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "dev@example.test"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Dev"], check=True)
            (repo / "README.md").write_text("git route test\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True, text=True)

            config, server_ctx = self.prepared_server(root)
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)

                self.assertEqual(server.request_error("POST", "/api/client/git-deployments", {"branch": "main"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/git-deployments", {"repository_url": str(repo), "branch": "main", "deploy_path": "../../etc"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/git-deployments", {"repository_url": str(repo), "branch": "main"}, None)[0], 401)
                created = server.request("POST", "/api/client/git-deployments", {"repository_url": str(repo), "branch": "main", "deploy_path": "git/route-test"}, owner_token)
                self.assertIn("job_id", created)
                self.assertEqual(server.request_error("DELETE", f"/api/client/git-deployments/{created['git_deployment_id']}", token=other_token)[0], 404)

    def test_services_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)

                self.assertEqual(server.request_error("GET", "/api/client/services/status")[0], 401)
                self.assertEqual(server.request_error("GET", "/api/client/services/status?service=../../etc/passwd", token=owner_token)[0], 400)

                owner_payload = server.request("GET", "/api/client/services/status", token=owner_token)
                other_payload = server.request("GET", "/api/client/services/status", token=other_token)
                self.assertEqual(owner_payload["account_id"], 1)
                self.assertNotEqual(owner_payload["account_id"], other_payload["account_id"])
                self.assertTrue(owner_payload["services"])

                service_payload = server.request("GET", "/api/client/services/status?service=web", token=owner_token)
                self.assertEqual(len(service_payload["services"]), 1)
                self.assertEqual(service_payload["services"][0]["service"], "web")

    def test_resource_usage_route_is_live_and_returns_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                payload = server.request("GET", "/api/client/resource-usage?range=30m", token=owner_token)

        self.assertEqual(payload["range"], "30m")
        self.assertTrue(payload["current"])
        self.assertIn("samples", payload)
        self.assertIsInstance(payload["samples"], list)

    def test_php_info_and_disk_usage_routes_are_live_and_access_controlled(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                website = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]

                self.assertEqual(server.request_error("GET", "/api/client/php-info")[0], 401)
                self.assertEqual(server.request_error("GET", "/api/client/php-info?website_id=abc", token=owner_token)[0], 400)
                self.assertEqual(server.request_error("GET", f"/api/client/php-info?website_id={website['id']}", token=other_token)[0], 404)

                php_info = server.request("GET", f"/api/client/php-info?website_id={website['id']}", token=owner_token)
                self.assertEqual(php_info["website"]["id"], website["id"])
                self.assertEqual(php_info["website"]["domain"], website["domain"])
                self.assertTrue(php_info["extensions"])
                self.assertIn("memory_limit", php_info["directives"])
                self.assertIn("web_container", php_info["runtime"])

                self.assertEqual(server.request_error("GET", "/api/client/disk-usage")[0], 401)
                disk_usage = server.request("GET", "/api/client/disk-usage", token=owner_token)
                self.assertTrue(disk_usage["usage"])
                self.assertTrue(all(item["path"].startswith("/domains/") for item in disk_usage["usage"]))

    def test_modsecurity_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                website_id = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]["id"]

                self.assertEqual(server.request_error("POST", f"/api/client/websites/{website_id}/modsec")[0], 401)
                self.assertEqual(server.request_error("POST", f"/api/client/websites/{website_id}/modsec", {"enabled": "maybe"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", f"/api/client/websites/{website_id}/modsec", {"enabled": True}, other_token)[0], 404)

                payload = server.request("POST", f"/api/client/websites/{website_id}/modsec", {"enabled": False}, owner_token)
                self.assertFalse(payload["enabled"])
                self.assertIn("job_id", payload)

    def test_backup_routes_validate_auth_ownership_and_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                created = server.request("POST", "/api/client/backups", token=owner_token)
                backup_id = created["backup_id"]
                backups = server.request("GET", "/api/client/backups", token=owner_token)["backups"]
                self.assertTrue(any(backup["id"] == backup_id and backup["status"] == "completed" for backup in backups))

                self.assertEqual(server.request_error("GET", f"/api/client/backups/{backup_id}/download")[0], 401)
                self.assertEqual(server.request_error("GET", f"/api/client/backups/{backup_id}/download", token=other_token)[0], 404)
                status, headers, body = server.request_bytes("GET", f"/api/client/backups/{backup_id}/download", token=owner_token)

        self.assertEqual(status, 200)
        self.assertIn("Content-Disposition", headers)
        self.assertTrue(body.startswith(b"\x1f\x8b"))

    def test_mail_brand_svg_is_public_and_rebranded(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                status, headers, body = server.request_bytes("GET", "/api/public/mail-brand.svg")

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"].split(";")[0], "image/svg+xml")
        self.assertIn(b"MangoPanel", body)

    def test_mailbox_routes_require_password_and_skip_webmail_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)

                self.assertEqual(server.request_error("POST", "/api/client/mailboxes", {"email": "missing-password@example.mango.test", "quota_mb": 1024}, owner_token)[0], 400)
                created = server.request(
                    "POST",
                    "/api/client/mailboxes",
                    {
                        "email": "mailbox-route@example.mango.test",
                        "quota_mb": 1024,
                        "password": "MailboxPass123",
                        "confirm_password": "MailboxPass123",
                    },
                    owner_token,
                )
                self.assertIn("mailbox_id", created)

                mailboxes = server.request("GET", "/api/client/mailboxes", token=owner_token)["mailboxes"]
                self.assertTrue(mailboxes)
                created_mailbox = next(mailbox for mailbox in mailboxes if mailbox["id"] == created["mailbox_id"])
                self.assertNotIn("password_hash", created_mailbox)
                self.assertIn("storage_path", created_mailbox)
                self.assertIn("storage_bytes", created_mailbox)
                self.assertTrue(created_mailbox["storage_path"].endswith("mailbox-route"))
                self.assertTrue((config.account_root / "u000001" / "mail" / "example.mango.test" / "mailbox-route").exists())

                self.assertEqual(server.request_error("GET", f"/api/client/mailboxes/{created['mailbox_id']}/webmail/launch", token=other_token)[0], 404)
                self.assertEqual(server.request("GET", f"/api/client/mailboxes/{created['mailbox_id']}/webmail/launch", token=owner_token)["expires_in"], 3600)

                self.assertEqual(server.request_error("PATCH", f"/api/client/mailboxes/{created['mailbox_id']}", {"password": "short"}, owner_token)[0], 400)
                updated = server.request(
                    "PATCH",
                    f"/api/client/mailboxes/{created['mailbox_id']}",
                    {"password": "MailboxPass456", "confirm_password": "MailboxPass456"},
                    owner_token,
                )
                self.assertEqual(updated["mailbox"]["email"], "mailbox-route@example.mango.test")
                original_storage = config.account_root / "u000001" / "mail" / "example.mango.test" / "mailbox-route"
                renamed = server.request(
                    "PATCH",
                    f"/api/client/mailboxes/{created['mailbox_id']}",
                    {"email": "mailbox-route-renamed@example.mango.test"},
                    owner_token,
                )
                renamed_storage = config.account_root / "u000001" / "mail" / "example.mango.test" / "mailbox-route-renamed"
                self.assertFalse(original_storage.exists())
                self.assertTrue(renamed_storage.exists())
                self.assertEqual(renamed["mailbox"]["email"], "mailbox-route-renamed@example.mango.test")
                deleted = server.request("DELETE", f"/api/client/mailboxes/{created['mailbox_id']}", token=owner_token)
                self.assertTrue(deleted["deleted"])
                self.assertFalse(renamed_storage.exists())
                jobs = server.request("GET", "/api/client/sync-jobs", token=owner_token)["jobs"]
                self.assertTrue(any(job["type"] == "sync_mailboxes" for job in jobs))

    def test_mail_routing_phase_two_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()

                routing = server.request("GET", "/api/client/mail-routing", token=owner_token)
                self.assertIn("daily_email_limit", routing)
                self.assertTrue(routing["mail_domains"])
                domain = routing["mail_domains"][0]

                created_mailbox = server.request(
                    "POST",
                    "/api/client/mailboxes",
                    {
                        "email": "phase2-mailbox@example.mango.test",
                        "quota_mb": 1024,
                        "password": "MailboxPass123",
                        "confirm_password": "MailboxPass123",
                    },
                    owner_token,
                )
                mailbox_id = created_mailbox["mailbox_id"]
                self.assertIn("webmail_login_url", created_mailbox["mailbox"])
                self.assertIn("mailbox_login_url", created_mailbox["mailbox"])
                self.assertIn("mail_edge_host", created_mailbox["mailbox"])

                mailboxes = server.request("GET", "/api/client/mailboxes", token=owner_token)["mailboxes"]
                self.assertTrue(any(mailbox["webmail_login_url"] for mailbox in mailboxes))
                self.assertTrue(any(mailbox["mailbox_login_url"] for mailbox in mailboxes))
                self.assertTrue(any(mailbox["mail_edge_url"] for mailbox in mailboxes))
                self.assertTrue(any(mailbox["jmap_url"] for mailbox in mailboxes))

                launch = server.request("GET", f"/api/client/mailboxes/{mailbox_id}/webmail/launch", token=owner_token)
                self.assertIn("/webmail", launch["launch_url"])
                self.assertIn("launch=", launch["launch_url"])
                launch_host = launch["launch_url"].split("/", 3)[2]
                launch_path = launch["launch_url"].replace(f"http://{launch_host}", "")
                status, headers, _ = server.request_raw("GET", launch_path, host=launch_host)
                self.assertEqual(status, 302)
                self.assertIn("Location", headers)
                self.assertEqual(headers["Location"], f"http://{launch_host}/webmail")

                launch_token = launch["launch_url"].split("launch=", 1)[1]
                exchange_status, headers, exchange_payload = server.request_raw(
                    "POST",
                    "/api/public/webmail/exchange",
                    {"launch_token": launch_token},
                    host=launch_host,
                )
                self.assertEqual(exchange_status, 200)
                self.assertTrue(exchange_payload["exchanged"])
                self.assertIn("Set-Cookie", headers)
                self.assertIn("mp_mail_token=", headers["Set-Cookie"])
                mail_cookie = headers["Set-Cookie"].split("mp_mail_token=", 1)[1].split(";", 1)[0]
                webmail_status, _, session_payload = server.request_raw(
                    "GET",
                    "/api/public/webmail/session",
                    host=launch_host,
                    extra_headers={"Cookie": f"mp_mail_token={mail_cookie}"},
                )
                self.assertEqual(webmail_status, 200)
                self.assertEqual(session_payload["mailbox"]["email"], "phase2-mailbox@example.mango.test")
                initial_remaining = session_payload["remaining_today"]

                edge_status, edge_headers, edge_payload = server.request_raw(
                    "GET",
                    "/api/public/mail-edge/manifest",
                    host="mail.mango.test",
                )
                self.assertEqual(edge_status, 200)
                self.assertEqual(edge_headers["Content-Type"].split(";")[0], "application/json")
                self.assertEqual(edge_payload["provider"], "shared-mail-edge")
                self.assertEqual(edge_payload["edge_host"], "mail.mango.test")
                self.assertTrue(edge_payload["accounts"])
                self.assertTrue(any(account["mailboxes"] for account in edge_payload["accounts"]))
                self.assertTrue(any(account["mailboxes"][0]["jmap_url"] for account in edge_payload["accounts"] if account["mailboxes"]))

                login_status, login_headers, _ = server.request_raw(
                    "GET",
                    f"/webmail/login/{mailbox_id}",
                    host=launch_host,
                )
                self.assertEqual(login_status, 302)
                self.assertIn("Location", login_headers)
                self.assertEqual(login_headers["Location"], f"http://{launch_host}/webmail")
                direct_login_status, direct_login_headers, direct_login_payload = server.request_raw(
                    "POST",
                    "/api/public/webmail/login",
                    {"mailbox_id": mailbox_id, "password": "MailboxPass123"},
                    host=launch_host,
                )
                self.assertEqual(direct_login_status, 200)
                self.assertTrue(direct_login_payload["logged_in"])
                self.assertIn("Set-Cookie", direct_login_headers)
                direct_cookie = direct_login_headers["Set-Cookie"].split("mp_mail_token=", 1)[1].split(";", 1)[0]
                direct_session_status, _, direct_session_payload = server.request_raw(
                    "GET",
                    "/api/public/webmail/session",
                    host=launch_host,
                    extra_headers={"Cookie": f"mp_mail_token={direct_cookie}"},
                )
                self.assertEqual(direct_session_status, 200)
                self.assertEqual(direct_session_payload["mailbox"]["id"], mailbox_id)
                jmap_status, _, jmap_payload = server.request_raw(
                    "GET",
                    "/api/public/mail-jmap",
                    host=launch_host,
                    extra_headers={"Cookie": f"mp_mail_token={direct_cookie}"},
                )
                self.assertEqual(jmap_status, 200)
                self.assertTrue(jmap_payload["enabled"])
                self.assertEqual(jmap_payload["mailbox"]["email"], "phase2-mailbox@example.mango.test")
                self.assertTrue(jmap_payload["mailbox"]["jmap_url"])

                send_status, _, send_payload = server.request_raw(
                    "POST",
                    "/api/public/webmail/send",
                    {"to": "external@example.com", "subject": "Hello", "body": "Hello from webmail"},
                    host=launch_host,
                    extra_headers={"Cookie": f"mp_mail_token={mail_cookie}"},
                )
                self.assertEqual(send_status, 201)
                self.assertTrue(send_payload["sent"])
                self.assertEqual(send_payload["remaining_today"], max(0, initial_remaining - 1))
                messages_status, _, messages_payload = server.request_raw(
                    "GET",
                    "/api/public/webmail/messages",
                    host=launch_host,
                    extra_headers={"Cookie": f"mp_mail_token={mail_cookie}"},
                )
                self.assertEqual(messages_status, 200)
                self.assertTrue(messages_payload["messages"])

                updated = server.request(
                    "PATCH",
                    f"/api/client/mail-domains/{domain['mail_domain_id']}",
                    {
                        "dkim_selector": "mango2",
                        "spf_policy": "v=spf1 mx -all",
                        "dmarc_policy": "v=DMARC1; p=quarantine",
                        "catch_all_enabled": True,
                        "catch_all_destination": "catchall@example.mango.test",
                        "status": "active",
                        "regenerate_dkim": True,
                    },
                    owner_token,
                )
                self.assertTrue(updated["mail"]["mail_domains"][0]["catch_all_enabled"])
                self.assertIn("job_id", updated)

                alias = server.request(
                    "POST",
                    "/api/client/mail-aliases",
                    {
                        "source_email": "info@example.mango.test",
                        "destination_email": "owner@example.mango.test",
                    },
                    owner_token,
                )
                self.assertIn("mail_alias_id", alias)
                self.assertIn("job_id", alias)

                forwarder = server.request(
                    "POST",
                    "/api/client/mail-forwarders",
                    {
                        "source_email": "sales@example.mango.test",
                        "destination_email": "external@example.com",
                    },
                    owner_token,
                )
                self.assertIn("mail_forwarder_id", forwarder)
                self.assertIn("job_id", forwarder)

                autoresponder = server.request(
                    "POST",
                    "/api/client/mail-autoresponders",
                    {
                        "mailbox_id": mailbox_id,
                        "subject": "Auto reply",
                        "body": "We got your message.",
                        "enabled": True,
                    },
                    owner_token,
                )
                self.assertIn("mail_autoresponder_id", autoresponder)
                self.assertIn("job_id", autoresponder)

                logs = server.request("GET", "/api/client/mail-logs", token=owner_token)["mail"]["mail_delivery_logs"]
                self.assertTrue(any(log["action"] == "alias_created" for log in logs))
                self.assertTrue(any(log["action"] == "forwarder_created" for log in logs))
                self.assertTrue(any(log["action"] == "autoresponder_created" for log in logs))

                rotated = server.request("POST", f"/api/client/mail-domains/{domain['mail_domain_id']}/dkim/rotate", token=owner_token)
                self.assertIn("mail", rotated)
                refreshed = server.request("GET", "/api/client/mail-routing", token=owner_token)
                self.assertTrue(refreshed["mail_domains"][0]["auth"]["dkim"]["configured"])
                jobs = server.request("GET", "/api/client/sync-jobs", token=owner_token)["jobs"]
                self.assertTrue(any(job["type"] == "sync_mail_policy" for job in jobs))

    def test_forward_auth_tools_refresh_shared_cookie_on_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                token = server.login()
                files_payload, files_headers = server.request_with_headers("GET", "/api/client/files/launch", token=token, host="localhost:8000")
                pma_payload, pma_headers = server.request_with_headers("GET", "/api/client/phpmyadmin/launch", token=token, host="localhost:8000")

        self.assertIn("/auth/", files_payload["launch_url"])
        self.assertIn("/auth/", pma_payload["launch_url"])
        self.assertEqual(files_payload["expires_in"], 600)
        self.assertEqual(pma_payload["expires_in"], 600)

    def test_auth_verify_accepts_host_only_forwarded_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                token = server.login()
                launch = server.request("GET", "/api/client/files/launch", token=token)
                status, headers, payload = server.request_raw(
                    "GET",
                    "/api/public/auth-verify",
                    host="files-u000001.localhost",
                    extra_headers={"X-Forwarded-Host": "files-u000001.localhost", "X-Forwarded-Uri": launch["launch_url"].replace("http://files-u000001.localhost", "")},
                )

        self.assertEqual(status, 302)
        self.assertIn("Set-Cookie", headers)
        self.assertIn("Location", headers)
        self.assertIn("/auth/", launch["launch_url"])

    def test_tool_launch_endpoint_accepts_magic_path_and_redirects_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                token = server.login()
                launch = server.request("GET", "/api/client/phpmyadmin/launch", token=token)
                path = launch["launch_url"].replace("http://pma-u000001.localhost", "")
                status, headers, _ = server.request_raw(
                    "GET",
                    "/api/public/tool-launch/phpmyadmin/auth/{}".format(path.split("/auth/", 1)[1].strip("/")),
                    host="pma-u000001.localhost",
                    extra_headers={"X-Forwarded-Host": "pma-u000001.localhost"},
                )

        self.assertEqual(status, 302)
        self.assertIn("Set-Cookie", headers)
        self.assertEqual(headers["Location"], "http://pma-u000001.localhost/db/")

    def test_tool_launch_endpoint_preserves_tool_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                token = server.login()
                launch = server.request("GET", "/api/client/files/launch", token=token)
                magic = launch["launch_url"].replace("http://files-u000001.localhost", "")
                status, headers, _ = server.request_raw(
                    "GET",
                    "/api/public/tool-launch/filebrowser/auth/{}{}".format(magic.split("/auth/", 1)[1].strip("/"), "/files/domains/"),
                    host="files-u000001.localhost",
                    extra_headers={"X-Forwarded-Host": "files-u000001.localhost"},
                )

        self.assertEqual(status, 302)
        self.assertIn("Set-Cookie", headers)
        self.assertEqual(headers["Location"], "http://files-u000001.localhost/files/domains")

    def test_browser_facing_auth_path_is_supported_directly(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                token = server.login()
                launch = server.request("GET", "/api/client/files/launch", token=token)
                magic = launch["launch_url"].replace("http://files-u000001.localhost", "")
                status, headers, _ = server.request_raw(
                    "GET",
                    magic + "/files",
                    host="files-u000001.localhost",
                    extra_headers={"X-Forwarded-Host": "files-u000001.localhost"},
                )

        self.assertEqual(status, 302)
        self.assertIn("Set-Cookie", headers)
        self.assertEqual(headers["Location"], "http://files-u000001.localhost/files")

    def test_files_ftp_and_directory_privacy_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                home = server.request("GET", "/api/client/home", token=owner_token)
                website = home["websites"][0]

                self.assertEqual(server.request_error("GET", "/api/client/files/launch")[0], 401)
                self.assertEqual(server.request_error("GET", "/api/client/files/launch?path=/../../etc/passwd", token=owner_token)[0], 400)
                raw_logs = server.request("GET", f"/api/client/logs/raw?domain={website['domain']}", token=owner_token)
                self.assertEqual(
                    raw_logs["download_url"],
                    f"/api/client/files/launch?path=/domains/{website['domain']}/logs/access.log",
                )
                file_launch = server.request("GET", f"/api/client/files/launch?path=/domains/{website['domain']}/logs/access.log", token=owner_token)
                self.assertIn(f"/files/domains/{website['domain']}/logs/access.log", file_launch["launch_url"])

                self.assertEqual(server.request_error("POST", "/api/client/ftp-accounts", {"username": "phase6", "password": "StrongPass123", "path": "../../etc"})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/ftp-accounts", {"username": "phase6 bad", "password": "StrongPass123", "path": "domains/uploads"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/ftp-accounts", {"username": "phase6", "password": "short", "path": "domains/uploads"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/ftp-accounts", {"username": "phase6", "password": "StrongPass123", "path": "../../etc"}, owner_token)[0], 400)
                ftp = server.request(
                    "POST",
                    "/api/client/ftp-accounts",
                    {"username": "phase6", "password": "StrongPass123", "path": f"domains/{website['domain']}/public_html/uploads"},
                    owner_token,
                )
                self.assertTrue(ftp["success"])
                self.assertEqual(server.request_error("DELETE", f"/api/client/ftp-accounts/{ftp['ftp_account']['id']}", token=other_token)[0], 404)

                self.assertEqual(server.request_error("POST", "/api/client/protected-directories", {"path": f"/domains/{website['domain']}/public_html/private", "username": "phase6_priv", "password": "StrongPass123"})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/protected-directories", {"path": f"/domains/{website['domain']}/public_html/private", "username": "bad name", "password": "StrongPass123"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/protected-directories", {"path": f"/domains/{website['domain']}/public_html/private", "username": "phase6_priv", "password": "short"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/protected-directories", {"path": "../../etc", "username": "phase6_priv", "password": "StrongPass123"}, owner_token)[0], 400)
                protected = server.request(
                    "POST",
                    "/api/client/protected-directories",
                    {"path": f"/domains/{website['domain']}/public_html/private", "username": "phase6_priv", "password": "StrongPass123"},
                    owner_token,
                )
                self.assertEqual(server.request_error("DELETE", f"/api/client/protected-directories/{protected['id']}", token=other_token)[0], 404)

    def test_simulated_sync_routes_validate_auth_ownership_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                owner_token = server.login()
                other_token, _ = self.create_peer_account_token(config)
                website = server.request("GET", "/api/client/home", token=owner_token)["websites"][0]

                self.assertEqual(server.request_error("POST", "/api/client/hotlink-protection", {"enabled": True})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/hotlink-protection", {"enabled": True, "allowed_domains": "https://bad.example"}, owner_token)[0], 400)
                self.assertTrue(server.request("POST", "/api/client/hotlink-protection", {"enabled": True, "allowed_domains": "example.mango.test"}, owner_token)["success"])

                self.assertEqual(server.request_error("POST", "/api/client/site-builder/install", {"website_id": website["id"], "template_id": "portfolio"})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/site-builder/install", {"template_id": "portfolio"}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/site-builder/install", {"website_id": website["id"], "template_id": "portfolio"}, other_token)[0], 404)
                self.assertTrue(server.request("POST", "/api/client/site-builder/install", {"website_id": website["id"], "template_id": "portfolio"}, owner_token)["success"])

                self.assertEqual(server.request_error("POST", "/api/client/images/optimize", {"path": "."})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/images/optimize", {}, owner_token)[0], 400)
                self.assertEqual(server.request_error("POST", "/api/client/images/optimize", {"website_id": website["id"]}, other_token)[0], 404)
                self.assertTrue(server.request("POST", "/api/client/images/optimize", {"website_id": website["id"]}, owner_token)["success"])

                self.assertEqual(server.request_error("POST", "/api/client/remote-mysql", {"host_ip": "203.0.113.10"})[0], 401)
                self.assertEqual(server.request_error("POST", "/api/client/remote-mysql", {"host_ip": "not-an-ip"}, owner_token)[0], 400)
                host = server.request("POST", "/api/client/remote-mysql", {"host_ip": "203.0.113.10"}, owner_token)
                self.assertTrue(host["success"])
                self.assertEqual(server.request_error("DELETE", "/api/client/remote-mysql/{}".format(host["id"]), token=other_token)[0], 404)


if __name__ == "__main__":
    unittest.main()
