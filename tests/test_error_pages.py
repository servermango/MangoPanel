import unittest
import tempfile
from pathlib import Path
from mangopanel.error_pages import DEFAULT_ERROR_PAGES, generate_error_page_html
from mangopanel.stack import ensure_account_layout, render_ols_vhconf


class TestErrorPages(unittest.TestCase):
    def test_default_error_pages_dictionary(self):
        for code in ["403", "404", "500", "502", "503"]:
            self.assertIn(code, DEFAULT_ERROR_PAGES)
            html = DEFAULT_ERROR_PAGES[code]
            self.assertIn(f"Error {code}", html)
            self.assertIn("MangoPanel Web Server", html)

    def test_ensure_account_layout_generates_error_pages(self):
        with tempfile.TemporaryDirectory() as tmp:
            account = {"id": 10, "username": "u000010", "base_path": tmp, "status": "active"}
            websites = [{"id": 1, "domain": "example.com", "document_root": f"{tmp}/domains/example.com/public_html", "php_version": "8.3", "status": "active", "ssl_status": "missing"}]

            plan = {
                "id": 1, "name": "Basic", "cpu_limit": "1", "memory_mb": 1024, "storage_mb": 10000,
                "inode_limit": 100000, "max_websites": 10, "max_databases": 10, "max_mailboxes": 10,
                "max_cron_jobs": 10, "daily_email_limit": 100, "backup_retention_days": 7
            }
            node = {"id": 1, "name": "node-1", "hostname": "localhost", "public_host": "localhost", "quota_backend": "dev-simulator"}
            paths = ensure_account_layout(account, plan, node, websites=websites)
            errors_dir = paths["stack"] / "errors"

            self.assertTrue(errors_dir.exists())
            for code in ["403", "404", "500", "502", "503"]:
                err_file = errors_dir / f"{code}.html"
                self.assertTrue(err_file.exists(), f"{code}.html should exist in errors dir")
                content = err_file.read_text(encoding="utf-8")
                self.assertIn(f"Error {code}", content)

    def test_render_ols_vhconf_includes_errorpage_directives(self):
        account = {"id": 10, "username": "u000010", "base_path": "/tmp/u000010"}
        website = {"domain": "example.com", "document_root": "/tmp/u000010/domains/example.com/public_html"}

        vhconf = render_ols_vhconf(account, website)

        self.assertIn("errorpage 403", vhconf)
        self.assertIn("errorpage 404", vhconf)
        self.assertIn("errorpage 502", vhconf)
        self.assertIn("url                     /_mangopanel_errors/404.html", vhconf)
        self.assertIn("context /_mangopanel_errors/", vhconf)
        self.assertIn("location                /usr/local/lsws/mangopanel_errors/", vhconf)


if __name__ == "__main__":
    unittest.main()
