import tempfile
import unittest
from pathlib import Path

from mangopanel.agent import Agent
from mangopanel.config import Config
from mangopanel.db import connect, create_job, seed_dev_data


class AgentTests(unittest.TestCase):
    def test_agent_generates_account_stack_from_seed_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            results = Agent(config).run_all()

            self.assertTrue(results)
            compose_path = config.account_root / "u000001" / ".runtime" / "stack" / "docker-compose.yml"
            self.assertTrue(compose_path.exists())
            compose_text = compose_path.read_text(encoding="utf-8")
            self.assertIn("mp-u000001-web", compose_text)
            self.assertIn("127.0.0.1:", compose_text)
            self.assertIn('cpus: "1"', compose_text)
            self.assertIn('mangopanel.storage_mb: "10240"', compose_text)
            self.assertIn('mangopanel.inode_limit: "100000"', compose_text)
            self.assertIn('mangopanel.backup_retention_days: "7"', compose_text)
            self.assertTrue((config.account_root / "u000001" / "account.json").exists())
            cron_text = (config.account_root / "u000001" / ".runtime" / "stack" / "cron").read_text(encoding="utf-8")
            self.assertIn("php /home/u000001/domains/example.mango.test/public_html/cron.php", cron_text)
            quota_text = (config.account_root / "u000001" / ".runtime" / "stack" / "quota.json").read_text(encoding="utf-8")
            self.assertIn('"storage_mb": 10240', quota_text)
            self.assertIn('"inode_limit": 100000', quota_text)
            self.assertIn('"backup_retention_days": 7', quota_text)

            with connect(config.db_path) as conn:
                stack = conn.execute("SELECT * FROM account_stacks WHERE account_id = 1").fetchone()
                self.assertIsNotNone(stack)
                self.assertEqual(stack["status"], "generated")

    def test_simulated_sync_jobs_write_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts ORDER BY id LIMIT 1").fetchone()
                website = conn.execute("SELECT * FROM websites WHERE account_id = ? ORDER BY id LIMIT 1", (account["id"],)).fetchone()
                domain = conn.execute("SELECT * FROM domains WHERE account_id = ? ORDER BY id LIMIT 1", (account["id"],)).fetchone()
                record = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY id LIMIT 1", (domain["id"],)).fetchone()

                jobs = [
                    create_job(conn, "sync_dns_record", "dns_record", record["id"], {}),
                    create_job(conn, "issue_ssl", "website", website["id"], {}),
                    create_job(conn, "install_site_builder", "website", website["id"], {"template_id": "portfolio"}),
                    create_job(conn, "optimize_images", "account", account["id"], {"path": "."}),
                    create_job(conn, "sync_cron_jobs", "hosting_account", account["id"], {}),
                ]
                conn.execute("INSERT INTO remote_mysql_hosts(account_id, host_ip) VALUES (?, ?)", (account["id"], "203.0.113.10"))
                jobs.append(create_job(conn, "sync_remote_mysql", "account", account["id"], {}))
                conn.execute(
                    "INSERT INTO hotlink_settings(account_id, enabled, allowed_domains) VALUES (?, ?, ?)",
                    (account["id"], 1, "example.mango.test"),
                )
                jobs.append(create_job(conn, "sync_hotlink_protection", "hosting_account", account["id"], {}))
                conn.commit()

                results = [Agent(config).run_job_by_id(job_id) for job_id in jobs]

                for result in results:
                    self.assertEqual(result["status"], "succeeded")
                    artifact_path = result["result"].get("artifact_path")
                    self.assertTrue(artifact_path, result)
                    self.assertTrue(Path(artifact_path).exists(), artifact_path)

                simulated_dir = config.account_root / "u000001" / ".runtime" / "simulated"
                self.assertTrue((simulated_dir / "dns" / "example.mango.test.zone").exists())
                self.assertTrue((simulated_dir / "ssl" / "example.mango.test.json").exists())
                self.assertTrue((simulated_dir / "remote-mysql.json").exists())
                self.assertTrue((simulated_dir / "hotlink.conf").exists())
                self.assertTrue((simulated_dir / "image-optimization-report.json").exists())
                self.assertTrue((simulated_dir / "cron.json").exists())
                self.assertTrue(Path(website["document_root"], "index.html").exists())

    def test_wordpress_installs_over_fresh_mangopanel_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with connect(config.db_path) as conn:
                website = conn.execute("SELECT * FROM websites ORDER BY id LIMIT 1").fetchone()
                database_id = conn.execute(
                    "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                    (website["account_id"], "u000001_wp_1", "u000001_wp", "active"),
                ).lastrowid
                install_id = conn.execute(
                    """
                    INSERT INTO wordpress_installs(website_id, database_id, site_title, admin_username, admin_email, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (website["id"], database_id, "Example WP", "admin", "admin@example.test", "installing"),
                ).lastrowid
                job_id = create_job(
                    conn,
                    "install_wordpress",
                    "wordpress_install",
                    install_id,
                    {
                        "database_name": "u000001_wp_1",
                        "database_user": "u000001_wp",
                        "database_password": "secret",
                        "database_host": "db",
                        "site_title": "Example WP",
                        "admin_username": "admin",
                        "admin_email": "admin@example.test",
                    },
                )
                conn.commit()

                result = Agent(config).run_job_by_id(job_id)
                self.assertEqual(result["status"], "succeeded")

                document_root = Path(website["document_root"])
                index_text = (document_root / "index.php").read_text(encoding="utf-8")
                config_text = (document_root / "wp-config.php").read_text(encoding="utf-8")
                self.assertIn("WordPress development install is ready", index_text)
                self.assertIn("define('DB_PASSWORD', 'secret');", config_text)
                install = conn.execute("SELECT * FROM wordpress_installs WHERE id = ?", (install_id,)).fetchone()
                self.assertEqual(install["status"], "installed")

    def test_wordpress_refuses_non_empty_document_root_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with connect(config.db_path) as conn:
                website = conn.execute("SELECT * FROM websites ORDER BY id LIMIT 1").fetchone()
                document_root = Path(website["document_root"])
                (document_root / "keep.txt").write_text("do not replace me\n", encoding="utf-8")
                database_id = conn.execute(
                    "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                    (website["account_id"], "u000001_wp_1", "u000001_wp", "active"),
                ).lastrowid
                install_id = conn.execute(
                    """
                    INSERT INTO wordpress_installs(website_id, database_id, site_title, admin_username, admin_email, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (website["id"], database_id, "Example WP", "admin", "admin@example.test", "installing"),
                ).lastrowid
                job_id = create_job(
                    conn,
                    "install_wordpress",
                    "wordpress_install",
                    install_id,
                    {"site_title": "Example WP", "admin_username": "admin", "admin_email": "admin@example.test"},
                )
                conn.commit()

                result = Agent(config).run_job_by_id(job_id)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["error"], "document_root_not_empty")
                install = conn.execute("SELECT * FROM wordpress_installs WHERE id = ?", (install_id,)).fetchone()
                self.assertEqual(install["status"], "failed")

    def test_joomla_installer_creates_configuration_and_index_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with connect(config.db_path) as conn:
                website = conn.execute("SELECT * FROM websites ORDER BY id LIMIT 1").fetchone()
                
                install_id = conn.execute(
                    """
                    INSERT INTO script_installs(website_id, script_id, site_title, admin_username, admin_email, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (website["id"], "joomla", "Example Joomla", "admin", "admin@example.test", "installing"),
                ).lastrowid
                
                job_id = create_job(
                    conn,
                    "install_script",
                    "script_install",
                    install_id,
                    {
                        "script_id": "joomla",
                        "site_title": "Example Joomla",
                        "admin_username": "admin",
                        "admin_email": "admin@example.test",
                    },
                )
                conn.commit()

                result = Agent(config).run_job_by_id(job_id)
                self.assertEqual(result["status"], "succeeded")

                document_root = Path(website["document_root"])
                index_text = (document_root / "index.php").read_text(encoding="utf-8")
                config_text = (document_root / "configuration.php").read_text(encoding="utf-8")
                self.assertIn("Joomla development install is ready", index_text)
                self.assertIn("class JConfig", config_text)
                self.assertIn("public $sitename = 'Example Joomla';", config_text)
                
                install = conn.execute("SELECT * FROM script_installs WHERE id = ?", (install_id,)).fetchone()
                self.assertEqual(install["status"], "installed")


if __name__ == "__main__":
    unittest.main()
