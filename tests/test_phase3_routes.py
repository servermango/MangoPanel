import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import connect, seed_dev_data
from mangopanel.providers import DNS_PROVIDER_CLOUDFLARE
from mangopanel.security import encrypt_secret
from tests.test_providers import FakeCloudflareHandler, FakeHTTPServer


PASSWORD = "ChangeMe-DevOnly-123!"


class ClientApiServer:
    def __init__(self, config, panel="client"):
        self.previous_config = app_module.CONFIG
        app_module.CONFIG = config
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), app_module.MangoHandler)
        self.httpd.panel = panel
        self.base_url = "http://127.0.0.1:{}".format(self.httpd.server_address[1])
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        app_module.CONFIG = self.previous_config

    def request(self, method, path, body=None, token=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer {}".format(token)
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raise AssertionError("{} {} failed: {} {}".format(method, path, exc.code, exc.read().decode("utf-8"))) from exc

    def request_with_headers(self, method, path, body=None, token=None, host=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer {}".format(token)
        if host:
            headers["Host"] = host
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raw = response.read().decode("utf-8")
                payload = json.loads(raw) if raw else {}
                return payload, response.headers
        except urllib.error.HTTPError as exc:
            raise AssertionError("{} {} failed: {} {}".format(method, path, exc.code, exc.read().decode("utf-8"))) from exc

    def request_raw(self, method, path, body=None, token=None, host=None, extra_headers=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer {}".format(token)
        if host:
            headers["Host"] = host
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(urllib.request.HTTPHandler, NoRedirectHandler)
        try:
            with opener.open(req, timeout=10) as response:
                raw = response.read().decode("utf-8")
                return response.status, dict(response.headers), json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            return exc.code, dict(exc.headers), json.loads(raw) if raw else {}

    def request_bytes(self, method, path, body=None, token=None, host=None, extra_headers=None):
        data = None
        headers = {"Accept": "application/octet-stream"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer {}".format(token)
        if host:
            headers["Host"] = host
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(urllib.request.HTTPHandler, NoRedirectHandler)
        try:
            with opener.open(req, timeout=10) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def request_error(self, method, path, body=None, token=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer {}".format(token)
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raise AssertionError("{} {} unexpectedly succeeded: {}".format(method, path, response.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            return exc.code, json.loads(raw) if raw else {}

    def login(self):
        challenge = self.request("POST", "/api/client/auth/login", {"email": "owner@example.mango.test", "password": PASSWORD})
        payload = self.request("POST", "/api/client/auth/totp/verify", {"challenge_token": challenge["challenge_token"], "code": "000000"})
        return payload["access_token"]


class Phase3RouteTests(unittest.TestCase):
    def make_config(self, root):
        config = Config()
        config.db_path = root / "mangopanel.sqlite3"
        config.data_dir = root
        config.account_root = root / "accounts"
        config.agent_mode = "simulate"
        config.agent_inline = True
        config.dev_auth_test_mode = True
        return config

    def test_postgresql_crud_routes_sync_simulated_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_config(root)
            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with ClientApiServer(config) as server:
                token = server.login()
                created_db = server.request("POST", "/api/client/pg-databases", {"name": "u000001_pgapp"}, token)
                db_id = created_db["pg_database_id"]
                created_user = server.request("POST", "/api/client/pg-databases/users", {"username": "u000001_pguser", "password": "StrongPass123"}, token)
                user_id = created_user["pg_user_id"]
                created_grant = server.request(
                    "POST",
                    "/api/client/pg-databases/users/grants",
                    {"database_id": db_id, "user_id": user_id, "privileges": "READ_WRITE"},
                    token,
                )
                grant_id = created_grant["pg_grant_id"]

                server.request("POST", "/api/client/pg-databases/users/password", {"user_id": user_id, "password": "NewStrong123"}, token)
                server.request("DELETE", "/api/client/pg-databases/users/grants/{}".format(grant_id), token=token)
                server.request("DELETE", "/api/client/pg-databases/users/{}".format(user_id), token=token)
                server.request("DELETE", "/api/client/pg-databases/{}".format(db_id), token=token)

            artifact = config.account_root / "u000001" / ".runtime" / "postgresql" / "report.json"
            self.assertTrue(artifact.exists())
            with connect(config.db_path) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM pg_databases").fetchone()["c"], 0)
                self.assertGreater(conn.execute("SELECT COUNT(*) AS c FROM jobs WHERE type = 'sync_pg_databases' AND status = 'succeeded'").fetchone()["c"], 0)

    def test_custom_ssl_route_writes_simulated_certificate_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_config(root)
            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with ClientApiServer(config) as server:
                token = server.login()
                home = server.request("GET", "/api/client/home", token=token)
                website_id = home["websites"][0]["id"]
                payload = server.request(
                    "POST",
                    "/api/client/ssl/custom",
                    {"website_id": website_id, "crt": "-----BEGIN CERTIFICATE-----\ndev\n-----END CERTIFICATE-----", "key": "-----BEGIN PRIVATE KEY-----\ndev\n-----END PRIVATE KEY-----"},
                    token,
                )
                self.assertEqual(payload["ssl_status"], "custom")

            cert_path = config.account_root / "u000001" / "ssl" / "example.mango.test" / "custom.crt"
            artifact = config.account_root / "u000001" / ".runtime" / "simulated" / "ssl" / "example.mango.test-custom.json"
            self.assertTrue(cert_path.exists())
            self.assertTrue(artifact.exists())
            with connect(config.db_path) as conn:
                website = conn.execute("SELECT ssl_status FROM websites WHERE id = ?", (website_id,)).fetchone()
                self.assertEqual(website["ssl_status"], "custom")

    def test_create_website_surfaces_cloudflare_nameservers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_config(root)
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
                    plan = conn.execute("SELECT * FROM plans ORDER BY id LIMIT 1").fetchone()
                    conn.execute(
                        "UPDATE plans SET dns_default_provider = ?, dns_default_provider_account_id = ? WHERE id = ?",
                        (DNS_PROVIDER_CLOUDFLARE, account_id, plan["id"]),
                    )

                with ClientApiServer(config) as server:
                    token = server.login()
                    payload = server.request("POST", "/api/client/websites", {"domain": "cloudflare-example.mango.test"}, token)
                    website = payload["website"]
                    self.assertTrue(website["nameservers"])
                    self.assertIn("abby.ns.cloudflare.com", website["nameservers"])
                    self.assertEqual(website["dns_provider_label"], "Cloudflare")

                with connect(config.db_path) as conn:
                    domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("cloudflare-example.mango.test",)).fetchone()
                    self.assertIsNotNone(domain)
                    self.assertIn("abby.ns.cloudflare.com", domain["nameservers_json"])

    def test_create_website_seeds_dns_records_for_apex_www_and_mail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_config(root)
            seed_dev_data(config.db_path, config.account_root)

            with ClientApiServer(config) as server:
                token = server.login()
                payload = server.request("POST", "/api/client/websites", {"domain": "dns-records-example.mango.test"}, token)
                website = payload["website"]

            with connect(config.db_path) as conn:
                domain = conn.execute("SELECT * FROM domains WHERE name = ?", ("dns-records-example.mango.test",)).fetchone()
                self.assertIsNotNone(domain)
                records = conn.execute(
                    "SELECT type, name, value FROM dns_records WHERE domain_id = ? ORDER BY type, name",
                    (domain["id"],),
                ).fetchall()
                record_set = {(row["type"], row["name"], row["value"]) for row in records}
                self.assertIn(("A", "@", "127.0.0.1"), record_set)
                self.assertIn(("CNAME", "www", "@"), record_set)
                self.assertTrue(any(row["type"] == "MX" and row["name"] == "@" for row in records))
                self.assertTrue(any(row["type"] == "TXT" and row["name"] == "@" for row in records))
                self.assertTrue(any(row["type"] == "TXT" and row["name"] == "_dmarc" for row in records))
                self.assertTrue(any(row["type"] == "TXT" and row["name"] == "mango._domainkey" for row in records))
                self.assertTrue(website["nameservers"])


if __name__ == "__main__":
    unittest.main()
