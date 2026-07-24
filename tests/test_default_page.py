import tempfile
import unittest
from pathlib import Path
from http import HTTPStatus

from mangopanel.db import connect, init_db, get_system_setting, set_system_setting
from mangopanel.default_page import DEFAULT_PAGE_CONTENT
from mangopanel.stack import ensure_account_layout
from mangopanel.installers import WordPressInstaller


class DefaultPageTests(unittest.TestCase):
    def test_db_system_settings_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            init_db(db_path)

            with connect(db_path) as conn:
                # Default is None if missing
                self.assertIsNone(get_system_setting(conn, "default_page_content"))

                # Set custom value
                custom_tmpl = "<h1>Custom site: {domain}</h1>"
                set_system_setting(conn, "default_page_content", custom_tmpl)

                self.assertEqual(get_system_setting(conn, "default_page_content"), custom_tmpl)

    def test_ensure_account_layout_generates_default_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            account = {"id": 1, "username": "u000001", "base_path": str(root / "u000001"), "status": "active"}
            plan = {
                "id": 1, "name": "Basic", "cpu_limit": "1", "memory_mb": 1024, "storage_mb": 10000,
                "inode_limit": 100000, "max_websites": 10, "max_databases": 10, "max_mailboxes": 10,
                "max_cron_jobs": 10, "daily_email_limit": 100, "backup_retention_days": 7
            }
            node = {"id": 1, "name": "node-1", "hostname": "localhost", "quota_backend": "dev-simulator"}
            doc_root = root / "u000001" / "domains" / "test.example.com" / "public_html"
            websites = [{"id": 1, "domain": "test.example.com", "document_root": str(doc_root), "php_version": "8.3", "status": "active", "ssl_status": "missing"}]

            # Layout with default template
            ensure_account_layout(account, plan, node, websites, default_page_content=None)

            index_php = doc_root / "index.php"
            self.assertTrue(index_php.exists())
            content = index_php.read_text(encoding="utf-8")
            self.assertIn("Welcome to <span class=\"domain-highlight\">test.example.com</span>", content)
            self.assertIn("<!-- MangoPanel default page -->", content)

    def test_ensure_account_layout_generates_custom_default_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            account = {"id": 2, "username": "u000002", "base_path": str(root / "u000002"), "status": "active"}
            plan = {
                "id": 1, "name": "Basic", "cpu_limit": "1", "memory_mb": 1024, "storage_mb": 10000,
                "inode_limit": 100000, "max_websites": 10, "max_databases": 10, "max_mailboxes": 10,
                "max_cron_jobs": 10, "daily_email_limit": 100, "backup_retention_days": 7
            }
            node = {"id": 1, "name": "node-1", "hostname": "localhost", "quota_backend": "dev-simulator"}
            doc_root = root / "u000002" / "domains" / "custom.test" / "public_html"
            websites = [{"id": 2, "domain": "custom.test", "document_root": str(doc_root), "php_version": "8.3", "status": "active", "ssl_status": "missing"}]

            custom_tmpl = "<!-- MangoPanel default page -->\n<html><body>Site {domain} created</body></html>"
            ensure_account_layout(account, plan, node, websites, default_page_content=custom_tmpl)

            index_php = doc_root / "index.php"
            self.assertTrue(index_php.exists())
            content = index_php.read_text(encoding="utf-8")
            self.assertIn("Site custom.test created", content)

    def test_wordpress_installer_recognizes_default_page_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            doc_root = root / "public_html"
            doc_root.mkdir(parents=True, exist_ok=True)

            # Write default page
            index_php = doc_root / "index.php"
            index_php.write_text(DEFAULT_PAGE_CONTENT.replace("{domain}", "myblog.test"), encoding="utf-8")

            website = {"document_root": str(doc_root)}
            with connect(root / "test.db") as conn:
                # Should not raise document_root_not_empty because default page is recognized as placeholder
                WordPressInstaller.verify_empty_root(conn, website, allow_overwrite=False)

            # verify_empty_root should unlink the placeholder index.php
            self.assertFalse(index_php.exists())


if __name__ == "__main__":
    unittest.main()
