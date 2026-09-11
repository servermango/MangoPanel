import unittest
from mangopanel.stack import build_account_runtime, expand_domain_aliases, render_compose, render_openlitespeed_httpd_config, render_apache_vhosts


class TestWwwCnameSsl(unittest.TestCase):
    def test_expand_domain_aliases(self):
        # Normal apex domain should produce [domain, www.domain]
        self.assertEqual(
            expand_domain_aliases(["navekinternational.com"]),
            ["navekinternational.com", "www.navekinternational.com"],
        )

        # Domain already starting with www. should not duplicate or add www.www.
        self.assertEqual(
            expand_domain_aliases(["www.navekinternational.com"]),
            ["www.navekinternational.com"],
        )

        # IP address should not have www. prepended
        self.assertEqual(
            expand_domain_aliases(["157.15.203.66", "127.0.0.1"]),
            ["157.15.203.66", "127.0.0.1"],
        )

        # Wildcard should not have www. prepended
        self.assertEqual(
            expand_domain_aliases(["*.example.com"]),
            ["*.example.com"],
        )

        # Both apex and www in input should deduplicate
        self.assertEqual(
            expand_domain_aliases(["example.com", "www.example.com"]),
            ["example.com", "www.example.com"],
        )

        # Whitespace and empty strings handled
        self.assertEqual(
            expand_domain_aliases(["  example.com  ", ""]),
            ["example.com", "www.example.com"],
        )

    def test_render_compose_includes_www_in_caddy_labels(self):
        account = {
            "id": 4395,
            "username": "u004395",
            "base_path": "/home/u004395",
            "reverse_proxy_cache_enabled": 0,
        }
        plan = {
            "name": "Starter",
            "storage_mb": 10240,
            "inode_limit": 1000000,
            "backup_retention_days": 7,
            "memory_mb": 1024,
            "cpu_limit": 1.0,
        }
        websites = [
            {"domain": "navekinternational.com", "document_root": "/home/u004395/domains/navekinternational.com/public_html"},
            {"domain": "sub.mysite.org", "document_root": "/home/u004395/domains/sub.mysite.org/public_html"},
        ]
        runtime = build_account_runtime(account)

        compose_text = render_compose(account, plan, websites, runtime)

        # caddy_0 must include both http://domain and http://www.domain
        self.assertIn("http://navekinternational.com", compose_text)
        self.assertIn("http://www.navekinternational.com", compose_text)
        self.assertIn("http://sub.mysite.org", compose_text)
        self.assertIn("http://www.sub.mysite.org", compose_text)

        # caddy_1 must include both https://domain and https://www.domain
        self.assertIn("https://navekinternational.com", compose_text)
        self.assertIn("https://www.navekinternational.com", compose_text)
        self.assertIn("https://sub.mysite.org", compose_text)
        self.assertIn("https://www.sub.mysite.org", compose_text)

    def test_openlitespeed_map_includes_www(self):
        account = {"id": 1, "username": "u001", "base_path": "/home/u001"}
        websites = [{"domain": "navekinternational.com", "document_root": "/home/u001/domains/navekinternational.com/public_html"}]
        ols_conf = render_openlitespeed_httpd_config(account, websites)
        self.assertIn("map                     navekinternational.com navekinternational.com, www.navekinternational.com", ols_conf)

    def test_apache_vhosts_includes_server_alias(self):
        account = {"id": 1, "username": "u001", "base_path": "/home/u001"}
        websites = [{"domain": "navekinternational.com", "document_root": "/home/u001/domains/navekinternational.com/public_html"}]
        apache_conf = render_apache_vhosts(account, websites)
        self.assertIn("ServerName navekinternational.com", apache_conf)
        self.assertIn("ServerAlias www.navekinternational.com", apache_conf)


if __name__ == "__main__":
    unittest.main()
