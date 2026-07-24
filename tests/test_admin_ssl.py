import ssl
import tempfile
import threading
import urllib.request
import unittest
from pathlib import Path

from mangopanel import app as app_module
from mangopanel.db import seed_dev_data


class AdminSslTests(unittest.TestCase):
    def test_dual_server_handles_both_http_and_https(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = app_module.load_config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.ssl_cert_path = root / "ssl" / "admin.crt"
            config.ssl_key_path = root / "ssl" / "admin.key"
            config.enable_ssl = True
            seed_dev_data(config.db_path, config.account_root)

            # Bind to 127.0.0.1 on port 0 to get an OS-assigned free port
            server = app_module.MangoDualServer(
                ("127.0.0.1", 0),
                app_module.MangoHandler,
                ssl_cert_path=config.ssl_cert_path,
                ssl_key_path=config.ssl_key_path,
                enable_ssl=True,
            )
            server.panel = "admin"
            port = server.server_address[1]

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                # 1. Plain HTTP request to /health
                http_url = f"http://127.0.0.1:{port}/health"
                req_http = urllib.request.Request(http_url)
                with urllib.request.urlopen(req_http, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn(b"mangopanel-api", resp.read())

                # 2. HTTPS request to /health with unverified context (self-signed cert)
                https_url = f"https://127.0.0.1:{port}/health"
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                req_https = urllib.request.Request(https_url)
                with urllib.request.urlopen(req_https, context=ssl_ctx, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn(b"mangopanel-api", resp.read())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_idle_tcp_connection_does_not_block_server(self):
        import socket
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = app_module.load_config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.ssl_cert_path = root / "ssl" / "admin.crt"
            config.ssl_key_path = root / "ssl" / "admin.key"
            config.enable_ssl = True
            seed_dev_data(config.db_path, config.account_root)

            server = app_module.MangoDualServer(
                ("127.0.0.1", 0),
                app_module.MangoHandler,
                ssl_cert_path=config.ssl_cert_path,
                ssl_key_path=config.ssl_key_path,
                enable_ssl=True,
            )
            server.panel = "admin"
            port = server.server_address[1]

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            idle_sock = None
            try:
                # Open an idle TCP connection that sends no data
                idle_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                idle_sock.connect(("127.0.0.1", port))

                # Verify server can still process concurrent HTTP requests without hanging
                http_url = f"http://127.0.0.1:{port}/health"
                req_http = urllib.request.Request(http_url)
                with urllib.request.urlopen(req_http, timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn(b"mangopanel-api", resp.read())
            finally:
                if idle_sock:
                    idle_sock.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
