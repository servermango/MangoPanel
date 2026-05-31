import tempfile
import unittest
import uuid
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
        self.assertEqual(headers["Location"], launch["launch_url"].split("/auth/", 1)[0] + "/")

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
