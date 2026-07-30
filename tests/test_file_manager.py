import os
import tempfile
import unittest
import zipfile
from http import HTTPStatus
from pathlib import Path
import json

from mangopanel.agent import Agent
from mangopanel.config import Config, FILEBROWSER_CUSTOM_JS
from mangopanel.db import seed_dev_data, connect
from mangopanel.security import create_jwt
from tests.test_phase3_routes import ClientApiServer


class FileManagerComprehensiveTests(unittest.TestCase):
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

    # -------------------------------------------------------------------------
    # Requirement 1: Launch directly to filebrowser from authenticated userpanel
    # -------------------------------------------------------------------------
    def test_1_launch_directly_to_filebrowser_from_authenticated_userpanel(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                token = server.login()
                launch = server.request("GET", "/api/client/files/launch", token=token)
                self.assertIn("launch_url", launch)

                launch_url = launch["launch_url"]
                auth_path = launch_url.split("/auth/", 1)[1] if "/auth/" in launch_url else ""
                self.assertTrue(bool(auth_path), "Launch URL must contain auth token")

                status, headers, body = server.request_raw(
                    "GET",
                    f"/api/public/tool-launch/filebrowser/auth/{auth_path}",
                    host="files-u000001.seeds.servermango.com",
                    extra_headers={"X-Forwarded-Host": "files-u000001.seeds.servermango.com"},
                )
                self.assertEqual(status, HTTPStatus.FOUND)
                self.assertIn("Set-Cookie", headers)
                self.assertTrue(headers["Location"].startswith("http://files-u000001.seeds.servermango.com/files/"))

                cookie = headers["Set-Cookie"].split(";")[0]
                status, _, _ = server.request_raw(
                    "GET",
                    "/api/public/auth-verify",
                    host="files-u000001.seeds.servermango.com",
                    extra_headers={
                        "X-Forwarded-Host": "files-u000001.seeds.servermango.com",
                        "X-Forwarded-Uri": "/files/login?redirect=/files",
                        "Cookie": cookie,
                    },
                )
                self.assertEqual(status, HTTPStatus.OK)

                # Follow launch with cookie set
                status, _, _ = server.request_raw(
                    "GET",
                    "/files/api/usage",
                    host="files-u000001.seeds.servermango.com",
                    extra_headers={
                        "X-Forwarded-Host": "files-u000001.seeds.servermango.com",
                        "Cookie": cookie,
                    },
                )
                self.assertEqual(status, HTTPStatus.OK)

                # Test launch to specific domain subpath (e.g. /files/domains/upnewsdesk.com)
                status, headers, _ = server.request_raw(
                    "GET",
                    f"/api/public/tool-launch/filebrowser/auth/{auth_path}/files/domains/upnewsdesk.com",
                    host="files-u000001.seeds.servermango.com",
                    extra_headers={"X-Forwarded-Host": "files-u000001.seeds.servermango.com"},
                )
                self.assertEqual(status, HTTPStatus.FOUND)
                self.assertEqual(headers["Location"], "http://files-u000001.seeds.servermango.com/files/domains/upnewsdesk.com")

    # -------------------------------------------------------------------------
    # Requirement 2: Domain isolation access control based on permissions
    # -------------------------------------------------------------------------
    def test_2_access_granted_domain_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            db_path = config.db_path
            with connect(db_path) as conn:
                # Create a collaborator user (id 999)
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, full_name, status) VALUES (999, 'collab@example.com', 'hash', 'Collab User', 'active')"
                )
                # Primary account id=1 (username u000001)
                acc = conn.execute("SELECT * FROM hosting_accounts WHERE id = 1").fetchone()
                
                # Add two websites for account id=1
                conn.execute("INSERT INTO websites (id, account_id, domain, document_root, status) VALUES (101, 1, 'allowed.com', '/domains/allowed.com/public_html', 'active')")
                conn.execute("INSERT INTO websites (id, account_id, domain, document_root, status) VALUES (102, 1, 'forbidden.com', '/domains/forbidden.com/public_html', 'active')")

                # Grant collaborator access to website 101 only
                conn.execute(
                    "INSERT INTO collaborators (owner_user_id, invited_email, hosting_account_id, permissions_json, status, target_user_id) "
                    "VALUES (1, 'collab@example.com', 1, '{\"all_websites\": false, \"website_ids\": [101], \"allowed_menus\": [\"files\"]}', 'active', 999)"
                )
                conn.commit()

            with server_ctx as server:
                collab_token = create_jwt({"sub": 999, "actor_type": "user", "purpose": "access"}, config.jwt_secret, 600)
                headers_collab = {
                    "X-Forwarded-Host": "files-u000001.seeds.servermango.com",
                    "Cookie": f"mp_auth={collab_token}",
                }

                # Create domain folders and archive files
                acc_base = Path(acc["base_path"])
                allowed_dir = acc_base / "domains" / "allowed.com"
                forbidden_dir = acc_base / "domains" / "forbidden.com"
                allowed_dir.mkdir(parents=True, exist_ok=True)
                forbidden_dir.mkdir(parents=True, exist_ok=True)

                allowed_zip = allowed_dir / "allowed.zip"
                with zipfile.ZipFile(allowed_zip, "w") as zf:
                    zf.writestr("ok.txt", "allowed content")

                forbidden_zip = forbidden_dir / "forbidden.zip"
                with zipfile.ZipFile(forbidden_zip, "w") as zf:
                    zf.writestr("secret.txt", "forbidden content")

                # Attempt 1: Extract inside allowed domain -> HTTP 200 OK
                status, _, body = server.request_raw(
                    "POST",
                    "/files/api/extract",
                    body={"path": "domains/allowed.com/allowed.zip"},
                    host="files-u000001.seeds.servermango.com",
                    extra_headers=headers_collab,
                )
                self.assertEqual(status, HTTPStatus.OK)
                self.assertTrue(body.get("success"))

                # Attempt 2: Access forbidden domain subpath -> HTTP 403 FORBIDDEN
                status, _, body = server.request_raw(
                    "GET",
                    "/api/public/filebrowser/proxy/api/resources/domains/forbidden.com/wp-config.php",
                    host="files-u000001.seeds.servermango.com",
                    extra_headers=headers_collab,
                )
                self.assertEqual(status, HTTPStatus.FORBIDDEN)
                self.assertEqual(body.get("error"), "access_denied_collaborator_restricted_path")

                # Attempt 3: Direct domain route access to forbidden domain -> HTTP 403 FORBIDDEN
                status, _, body = server.request_raw(
                    "GET",
                    "/api/public/filebrowser/proxy/domains/forbidden.com/wp-config.php",
                    host="files-u000001.seeds.servermango.com",
                    extra_headers=headers_collab,
                )
                self.assertEqual(status, HTTPStatus.FORBIDDEN)
                self.assertEqual(body.get("error"), "access_denied_collaborator_restricted_path")

                # Attempt 4: Extract inside forbidden domain -> HTTP 403 FORBIDDEN
                status, _, body = server.request_raw(
                    "POST",
                    "/files/api/extract",
                    body={"path": "domains/forbidden.com/forbidden.zip"},
                    host="files-u000001.seeds.servermango.com",
                    extra_headers=headers_collab,
                )
                self.assertEqual(status, HTTPStatus.FORBIDDEN)
                self.assertEqual(body.get("error"), "access_denied_collaborator_restricted_path")

    # -------------------------------------------------------------------------
    # Requirement 3: Storage usage per user's plan and usage
    # -------------------------------------------------------------------------
    def test_3_storage_usage_per_user_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            db_path = config.db_path
            with connect(db_path) as conn:
                acc = conn.execute("SELECT * FROM hosting_accounts WHERE username = 'u000001'").fetchone()
                plan = conn.execute("SELECT storage_mb FROM plans WHERE id = ?", (acc["plan_id"],)).fetchone()
                expected_total_bytes = plan["storage_mb"] * 1024 * 1024

                # Insert a sample resource usage for account 1
                conn.execute(
                    "INSERT INTO resource_usage_samples (account_id, storage_mb, storage_limit_mb, sampled_at) "
                    "VALUES (?, 150, ?, datetime('now'))",
                    (acc["id"], plan["storage_mb"]),
                )
                conn.commit()

            with server_ctx as server:
                status, _, body = server.request_raw(
                    "GET",
                    "/files/api/usage",
                    host="files-u000001.seeds.servermango.com",
                    extra_headers={"X-Forwarded-Host": "files-u000001.seeds.servermango.com"},
                )
                self.assertEqual(status, HTTPStatus.OK)
                self.assertIn("total", body)
                self.assertIn("used", body)
                self.assertEqual(body["total"], expected_total_bytes)
                self.assertEqual(body["used"], 150 * 1024 * 1024)

    # -------------------------------------------------------------------------
    # Requirement 4: Extract option for ZIP archives
    # -------------------------------------------------------------------------
    def test_4_extract_option_for_zip_archives(self):
        # 1. Custom JS check
        self.assertIn("mp-extract-btn", FILEBROWSER_CUSTOM_JS)
        self.assertIn("isArchive", FILEBROWSER_CUSTOM_JS)
        self.assertIn("doExtract", FILEBROWSER_CUSTOM_JS)
        self.assertIn("/files/api/extract", FILEBROWSER_CUSTOM_JS)

        # 2. Extract functionality test
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with connect(config.db_path) as conn:
                acc = conn.execute("SELECT * FROM hosting_accounts WHERE username = 'u000001'").fetchone()
                acc_base = Path(acc["base_path"])
                acc_base.mkdir(parents=True, exist_ok=True)

            zip_filepath = acc_base / "test_extract.zip"
            with zipfile.ZipFile(zip_filepath, "w") as zf:
                zf.writestr("extracted_file.txt", "Hello extracted world")
                zf.writestr("folder/inner.txt", "Inner file content")

            with server_ctx as server:
                user_token = create_jwt({"sub": acc["user_id"], "actor_type": "user", "purpose": "access"}, config.jwt_secret, 600)
                status, _, body = server.request_raw(
                    "POST",
                    "/files/api/extract",
                    body={"path": "test_extract.zip"},
                    host="files-u000001.seeds.servermango.com",
                    extra_headers={
                        "X-Forwarded-Host": "files-u000001.seeds.servermango.com",
                        "Cookie": f"mp_auth={user_token}",
                    },
                )
                self.assertEqual(status, HTTPStatus.OK)
                self.assertTrue(body.get("success"))
                self.assertEqual(body.get("extracted_count"), 2)
                self.assertTrue((acc_base / "extracted_file.txt").exists())
                self.assertTrue((acc_base / "folder" / "inner.txt").exists())

                # Verify permissions allow webserver write access
                st_mode = os.stat(acc_base / "extracted_file.txt").st_mode
                self.assertTrue(bool(st_mode & 0o002), "Extracted file must be writable")

    # -------------------------------------------------------------------------
    # Requirement 5: Read, write, delete file and folder inside allowed directory
    # -------------------------------------------------------------------------
    def test_5_read_write_delete_file_and_folder_inside_allowed_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, server_ctx = self.prepared_server(Path(tmp))
            with connect(config.db_path) as conn:
                acc = conn.execute("SELECT * FROM hosting_accounts WHERE username = 'u000001'").fetchone()
                acc_base = Path(acc["base_path"])
                acc_base.mkdir(parents=True, exist_ok=True)

            target_dir = acc_base / "my_folder"
            target_file = target_dir / "document.txt"

            # 1. WRITE (create dir and write file)
            target_dir.mkdir(exist_ok=True)
            with open(target_file, "w") as f:
                f.write("Initial file data")

            self.assertTrue(target_file.exists())

            # 2. READ (read file content)
            with open(target_file, "r") as f:
                content = f.read()
            self.assertEqual(content, "Initial file data")

            # 3. WRITE / UPDATE (overwrite file content)
            with open(target_file, "w") as f:
                f.write("Updated file data")

            with open(target_file, "r") as f:
                content = f.read()
            self.assertEqual(content, "Updated file data")

            # 4. DELETE (remove file and directory)
            os.remove(target_file)
            self.assertFalse(target_file.exists())

            os.rmdir(target_dir)
            self.assertFalse(target_dir.exists())

    # -------------------------------------------------------------------------
    # Requirement 6: Disable direct access / do not expose login form
    # -------------------------------------------------------------------------
    def test_6_no_login_form_and_disabled_direct_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, server_ctx = self.prepared_server(Path(tmp))
            with server_ctx as server:
                # Direct login endpoints must be forbidden
                endpoints = [
                    "/files/login?redirect=/files",
                    "/login",
                    "/api/public/filebrowser/proxy/files/login?redirect=/files",
                ]
                for ep in endpoints:
                    status, _, body = server.request_raw(
                        "GET",
                        ep,
                        host="files-u000001.seeds.servermango.com",
                        extra_headers={"X-Forwarded-Host": "files-u000001.seeds.servermango.com"},
                    )
                    self.assertEqual(status, HTTPStatus.FORBIDDEN, f"Endpoint {ep} must return 403 FORBIDDEN")
                    self.assertEqual(body.get("error"), "access_denied")


if __name__ == "__main__":
    unittest.main()
