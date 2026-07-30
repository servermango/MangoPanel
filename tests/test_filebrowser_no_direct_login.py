import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path

from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import seed_dev_data
from tests.test_phase3_routes import ClientApiServer


class FilebrowserNoDirectLoginTests(unittest.TestCase):
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

    def test_filebrowser_login_endpoint_access_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                # Test URL: https://files-u004395.seeds.servermango.com/files/login?redirect=/files
                status, headers, body = server.request_raw(
                    "GET",
                    "/files/login?redirect=/files",
                    host="files-u004395.seeds.servermango.com",
                    extra_headers={"X-Forwarded-Host": "files-u004395.seeds.servermango.com"},
                )
                self.assertEqual(status, HTTPStatus.FORBIDDEN)
                self.assertEqual(body.get("error"), "access_denied")

    def test_filebrowser_proxy_login_endpoint_access_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                status, headers, body = server.request_raw(
                    "GET",
                    "/api/public/filebrowser/proxy/files/login?redirect=/files",
                    host="files-u004395.seeds.servermango.com",
                    extra_headers={"X-Forwarded-Host": "files-u004395.seeds.servermango.com"},
                )
                self.assertEqual(status, HTTPStatus.FORBIDDEN)
                self.assertEqual(body.get("error"), "access_denied")

    def test_filebrowser_root_login_on_files_subdomain_access_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                status, headers, body = server.request_raw(
                    "GET",
                    "/login",
                    host="files-u004395.seeds.servermango.com",
                    extra_headers={"X-Forwarded-Host": "files-u004395.seeds.servermango.com"},
                )
                self.assertEqual(status, HTTPStatus.FORBIDDEN)
                self.assertEqual(body.get("error"), "access_denied")

    def test_forward_auth_filebrowser_login_access_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                status, headers, body = server.request_raw(
                    "GET",
                    "/api/public/auth-verify",
                    host="files-u004395.seeds.servermango.com",
                    extra_headers={
                        "X-Forwarded-Host": "files-u004395.seeds.servermango.com",
                        "X-Forwarded-Uri": "/files/login?redirect=/files",
                    },
                )
                self.assertEqual(status, HTTPStatus.FORBIDDEN)
                self.assertEqual(body.get("error"), "access_denied")


from tests.test_file_manager import FileManagerComprehensiveTests


if __name__ == "__main__":
    unittest.main()
