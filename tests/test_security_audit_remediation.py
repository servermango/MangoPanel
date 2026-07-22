import json
import time
import unittest
from http import HTTPStatus

from mangopanel.app import MangoHandler
from mangopanel.config import Config
from mangopanel.db import connect, init_db
from mangopanel.security import (
    create_jwt,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    validate_git_branch,
    validate_git_repository_url,
    verify_jwt,
)


class MockServer:
    def __init__(self, config):
        self.config = config
        self.db_path = config.db_path
        self.panel = "combined"


class SecurityAuditRemediationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmp_dir = tempfile.TemporaryDirectory()
        root = Path(self.tmp_dir.name)
        self.config = Config()
        self.config.db_path = root / "test_security.sqlite3"
        self.config.data_dir = root
        self.config.account_root = root / "accounts"
        self.config.env = "production"
        self.config.expose_internal_errors = False
        from mangopanel.app import CONFIG
        self.old_db_path = CONFIG.db_path
        self.old_jwt_secret = CONFIG.jwt_secret
        self.old_env = CONFIG.env
        self.old_dev_mode = getattr(CONFIG, "dev_auth_test_mode", False)
        self.old_agent_mode = CONFIG.agent_mode
        self.old_expose = CONFIG.expose_internal_errors

        CONFIG.db_path = self.config.db_path
        CONFIG.jwt_secret = self.config.jwt_secret
        CONFIG.dev_auth_test_mode = True
        CONFIG.agent_mode = "simulate"
        init_db(self.config.db_path)

        with connect(self.config.db_path) as conn:
            # Seed super admin
            conn.execute(
                "INSERT INTO admins(id, email, password_hash, full_name, role, status) VALUES (1, 'super@mango.test', ?, 'Super Admin', 'super_admin', 'active')",
                (hash_password("SuperSecret123!"),),
            )
            # Seed support admin
            conn.execute(
                "INSERT INTO admins(id, email, password_hash, full_name, role, status) VALUES (2, 'support@mango.test', ?, 'Support Admin', 'support_admin', 'active')",
                (hash_password("SupportSecret123!"),),
            )
            # Seed user
            conn.execute(
                "INSERT INTO users(id, email, password_hash, full_name, status) VALUES (1, 'user@mango.test', ?, 'User One', 'active')",
                (hash_password("UserSecret123!"),),
            )

    def tearDown(self):
        from mangopanel.app import CONFIG
        CONFIG.db_path = self.old_db_path
        CONFIG.jwt_secret = self.old_jwt_secret
        CONFIG.env = self.old_env
        CONFIG.dev_auth_test_mode = self.old_dev_mode
        CONFIG.agent_mode = self.old_agent_mode
        CONFIG.expose_internal_errors = self.old_expose
        self.tmp_dir.cleanup()


    def test_secret_encryption_v2_and_v1_fallback(self, master="test-master-key", secret_text="my-super-secret-smtp-password"):
        # New encryption uses v2 format
        v2_token = encrypt_secret(secret_text, master)
        self.assertTrue(v2_token.startswith("djI6") or "v2:" in str(v2_token))
        decrypted = decrypt_secret(v2_token, master)
        self.assertEqual(decrypted, secret_text)

        # Legacy v1 format decryption fallback test
        import base64, os, hmac, hashlib
        from mangopanel.security import _secret_key, _xor_bytes
        key = _secret_key(master)
        nonce = os.urandom(16)
        raw = secret_text.encode("utf-8")
        stream = bytearray()
        block = 0
        while len(stream) < len(raw):
            stream.extend(hmac.new(key, nonce + block.to_bytes(4, "big"), hashlib.sha256).digest())
            block += 1
        ciphertext = _xor_bytes(raw, bytes(stream[:len(raw)]))
        mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        v1_token = base64.urlsafe_b64encode(nonce + mac + ciphertext).decode("ascii")
        self.assertEqual(decrypt_secret(v1_token, master), secret_text)


    def test_git_repository_url_and_branch_validation(self):
        # Production mode URL checks
        self.assertTrue(validate_git_repository_url("https://github.com/example/repo.git", is_development=False))
        self.assertFalse(validate_git_repository_url("http://github.com/example/repo.git", is_development=False))
        self.assertFalse(validate_git_repository_url("file:///etc/passwd", is_development=False))
        self.assertFalse(validate_git_repository_url("ssh://git@github.com/repo.git", is_development=False))
        self.assertFalse(validate_git_repository_url("git://github.com/repo.git", is_development=False))
        self.assertFalse(validate_git_repository_url("https://127.0.0.1/repo.git", is_development=False))
        self.assertFalse(validate_git_repository_url("https://localhost/repo.git", is_development=False))

        # Dev mode URL checks
        self.assertTrue(validate_git_repository_url("http://localhost:8080/repo.git", is_development=True))
        self.assertTrue(validate_git_repository_url("file:///tmp/repo.git", is_development=True))
        self.assertTrue(validate_git_repository_url("/tmp/repo", is_development=True))

        # Branch validation checks
        self.assertTrue(validate_git_branch("main"))
        self.assertTrue(validate_git_branch("feature/security-fix"))
        self.assertFalse(validate_git_branch("-oProxyCommand=calc.exe"))
        self.assertFalse(validate_git_branch("../invalid"))

    def test_admin_rbac_permissions(self):
        super_admin = {"id": 1, "email": "super@mango.test", "role": "super_admin"}
        support_admin = {"id": 2, "email": "support@mango.test", "role": "support_admin"}

        from mangopanel.app import require_admin_permission, ApiError

        # Super admin has all permissions
        self.assertTrue(require_admin_permission(super_admin, "admins.manage"))
        self.assertTrue(require_admin_permission(super_admin, "impersonate"))
        self.assertTrue(require_admin_permission(super_admin, "clients.manage"))

        # Support admin has limited permissions
        self.assertTrue(require_admin_permission(support_admin, "clients.read"))
        with self.assertRaises(ApiError) as ctx:
            require_admin_permission(support_admin, "admins.manage")
        self.assertEqual(ctx.exception.status, HTTPStatus.FORBIDDEN)

        with self.assertRaises(ApiError) as ctx:
            require_admin_permission(support_admin, "impersonate")
        self.assertEqual(ctx.exception.status, HTTPStatus.FORBIDDEN)

    def test_impersonation_token_single_use(self):
        # Create single-use token
        token_id = "test_jti_123"
        imp_token = create_jwt(
            {"sub": 1, "actor_type": "user", "purpose": "impersonation_exchange", "admin_id": 1, "jti": token_id},
            self.config.jwt_secret,
            60,
        )
        import hashlib
        token_hash = hashlib.sha256(imp_token.encode("utf-8")).hexdigest()
        now = int(time.time())

        with connect(self.config.db_path) as conn:
            conn.execute(
                "INSERT INTO impersonation_tokens(token_hash, user_id, admin_id, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, 1, 1, now + 60),
            )

        handler = MangoHandler.__new__(MangoHandler)
        handler.server = MockServer(self.config)
        handler.client_address = ("127.0.0.1", 12345)
        handler.headers = {"Host": "localhost"}
        handler.read_json = lambda: {"impersonation_token": imp_token}

        sent = []
        handler.send_response = lambda status: sent.append(status)
        handler.send_header = lambda k, v: None
        handler.end_headers = lambda: None
        handler.wfile = type("WFile", (), {"write": lambda self, b: None})()

        # First exchange succeeds
        handler.exchange_impersonation()
        self.assertEqual(sent[0], HTTPStatus.OK)

        # Second exchange fails (token spent)
        from mangopanel.app import ApiError
        with self.assertRaises(ApiError) as ctx:
            handler.exchange_impersonation()
        self.assertEqual(ctx.exception.status, HTTPStatus.UNAUTHORIZED)

    def test_multi_account_ownership_boundary(self):
        with connect(self.config.db_path) as conn:
            conn.execute("INSERT OR IGNORE INTO nodes(id, name, hostname) VALUES (1, 'node1', 'node1.test')")
            plan_id = conn.execute(
                """
                INSERT INTO plans(name, cpu_limit, memory_mb, storage_mb, inode_limit, max_websites, max_databases, max_mailboxes, max_cron_jobs, daily_email_limit, backup_retention_days)
                VALUES ('Basic', '1 vCPU', 1024, 10240, 100000, 5, 5, 5, 5, 100, 7)
                """
            ).lastrowid
            # Account 1 owned by User 1
            conn.execute(
                "INSERT INTO hosting_accounts(id, user_id, plan_id, node_id, username, base_path, status) VALUES (1, 1, ?, 1, 'u1', '/tmp/u1', 'active')",
                (plan_id,),
            )
            # Account 2 owned by User 2
            conn.execute(
                "INSERT INTO users(id, email, password_hash, full_name, status) VALUES (2, 'user2@mango.test', 'hash', 'User Two', 'active')"
            )
            conn.execute(
                "INSERT INTO hosting_accounts(id, user_id, plan_id, node_id, username, base_path, status) VALUES (2, 2, ?, 1, 'u2', '/tmp/u2', 'active')",
                (plan_id,),
            )


        handler = MangoHandler.__new__(MangoHandler)
        handler.server = MockServer(self.config)
        handler.headers = {"X-Hosting-Account-ID": "2"}  # User 1 requesting User 2's account
        user1 = {"id": 1, "email": "user@mango.test"}

        from mangopanel.app import ApiError
        with self.assertRaises(ApiError) as ctx:
            handler.client_api("GET", "/api/client/home", {}, user1)
        self.assertEqual(ctx.exception.status, HTTPStatus.FORBIDDEN)


if __name__ == "__main__":
    unittest.main()

