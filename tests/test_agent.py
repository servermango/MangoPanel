import json
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mangopanel.agent import Agent, cron_next_run_at
from mangopanel.config import Config
from mangopanel.db import connect, create_job, seed_dev_data
from mangopanel.mail import mailbox_storage_path
from mangopanel.stack import build_account_runtime


class AgentTests(unittest.TestCase):
    def test_local_mail_ports_are_unique_per_account(self):
        first = build_account_runtime({"id": 1, "username": "u000001"})
        second = build_account_runtime({"id": 2, "username": "u000002"})

        self.assertEqual(first["smtp_port"], 1587)
        self.assertEqual(first["imap_port"], 1143)
        self.assertNotEqual(first["smtp_port"], second["smtp_port"])
        self.assertNotEqual(first["smtp_tls_port"], second["smtp_tls_port"])
        self.assertNotEqual(first["imap_port"], second["imap_port"])
        self.assertNotEqual(first["imap_tls_port"], second["imap_tls_port"])
        self.assertNotEqual(first["pop_port"], second["pop_port"])
        self.assertNotEqual(first["pop_tls_port"], second["pop_tls_port"])
        self.assertNotEqual(first["sieve_port"], second["sieve_port"])

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
            self.assertIn("mp-u000001-redis", compose_text)
            self.assertIn("mp-u000001-mailserver", compose_text)
            self.assertIn("djmaze/snappymail:latest@sha256:", compose_text)
            self.assertIn("docker-mailserver/docker-mailserver", compose_text)
            self.assertIn("127.0.0.1:", compose_text)
            self.assertIn('cpus: "1"', compose_text)
            self.assertIn('mangopanel.storage_mb: "10240"', compose_text)
            self.assertIn('mangopanel.inode_limit: "100000"', compose_text)
            self.assertIn('mangopanel.backup_retention_days: "7"', compose_text)
            self.assertTrue((config.account_root / "u000001" / "account.json").exists())
            web_dockerfile = (config.account_root / "u000001" / ".runtime" / "stack" / "web" / "Dockerfile").read_text(encoding="utf-8")
            self.assertIn("lsphp83-opcache", web_dockerfile)
            self.assertIn("lsphp82-opcache", web_dockerfile)
            self.assertIn("lsphp84-opcache", web_dockerfile)
            with connect(config.db_path) as conn:
                cron_job = conn.execute("SELECT * FROM cron_jobs WHERE account_id = 1 ORDER BY id LIMIT 1").fetchone()
                self.assertIsNotNone(cron_job)
                cron_script_path = config.account_root / "u000001" / ".runtime" / "cron" / "jobs" / f"job-{cron_job['id']}.sh"
                cron_text = (config.account_root / "u000001" / ".runtime" / "stack" / "cron").read_text(encoding="utf-8")
                self.assertIn(f"/home/u000001/.runtime/cron/jobs/job-{cron_job['id']}.sh", cron_text)
                cron_script = cron_script_path.read_text(encoding="utf-8")
                self.assertIn("php /home/u000001/domains/example.mango.test/public_html/cron.php", cron_script)
                mailboxes_json = json.loads((config.account_root / "u000001" / "mail" / "mailboxes.json").read_text(encoding="utf-8"))
                self.assertTrue(any(mailbox["email"] == "hello@example.mango.test" for mailbox in mailboxes_json))
                mailbox_root = config.account_root / "u000001" / "mail" / "example.mango.test" / "hello"
                self.assertTrue(mailbox_root.exists())
                self.assertTrue((mailbox_root / "cur").exists())
                self.assertTrue((mailbox_root / "new").exists())
                self.assertTrue((mailbox_root / "tmp").exists())
            quota_text = (config.account_root / "u000001" / ".runtime" / "stack" / "quota.json").read_text(encoding="utf-8")
            self.assertIn('"storage_mb": 10240', quota_text)
            self.assertIn('"inode_limit": 100000', quota_text)
            self.assertIn('"backup_retention_days": 7', quota_text)
            account_json = (config.account_root / "u000001" / "account.json").read_text(encoding="utf-8")
            self.assertIn('"mail_webmail_login_url": "http://mail-u000001.localhost/webmail/login"', account_json)
            self.assertIn('"mail_edge_host": "mail.mango.test"', account_json)
            self.assertTrue((config.account_root / "u000001" / "mail" / "plane.json").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "mail-edge.json").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "snappymail" / "snappymail.json").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "snappymail" / "themes" / "MangoPanel" / "styles.css").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "snappymail" / "themes" / "MangoPanel" / "images" / "wind.png").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "snappymail" / "themes" / "MangoPanel" / "images" / "windz-wordmark.svg").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "snappymail" / "themes" / "MangoPanel" / "fonts" / "roboto-500.ttf").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "mailserver" / "config" / "postfix-accounts.cf").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "mailserver" / "config" / "dovecot-quotas.cf").exists())
            accounts_text = (config.account_root / "u000001" / ".runtime" / "stack" / "mailserver" / "config" / "postfix-accounts.cf").read_text(encoding="utf-8")
            self.assertRegex(accounts_text, r"hello@example\.mango\.test\|\$6\$[^\n]+\$[^\n]+")
            quotas_text = (config.account_root / "u000001" / ".runtime" / "stack" / "mailserver" / "config" / "dovecot-quotas.cf").read_text(encoding="utf-8")
            self.assertIn("hello@example.mango.test:1073741824", quotas_text)
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "mailserver" / "config" / "ssl" / "mail-u000001.localhost-cert.pem").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "mailserver" / "config" / "ssl" / "mail-u000001.localhost-key.pem").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "stack" / "mailserver" / "config" / "ssl" / "demoCA" / "cacert.pem").exists())
            application_ini = (config.account_root / "u000001" / ".runtime" / "stack" / "snappymail" / "_data_" / "_default_" / "configs" / "application.ini").read_text(encoding="utf-8")
            self.assertIn('favicon_url = "/snappymail/v/2.38.2/themes/MangoPanel/images/wind.png"', application_ini)
            self.assertNotIn("https://servermango.com", application_ini)
            default_domain_json = (config.account_root / "u000001" / ".runtime" / "stack" / "snappymail" / "_data_" / "_default_" / "domains" / "default.json").read_text(encoding="utf-8")
            self.assertIn('"host": "mailserver"', default_domain_json)
            self.assertIn('"port": 993', default_domain_json)
            policy_json = json.loads((config.account_root / "u000001" / "mail" / "policy.json").read_text(encoding="utf-8"))
            self.assertEqual(policy_json["provider"], "snappymail")
            self.assertEqual(policy_json["daily_email_limit"], 250)
            routing_text = (config.account_root / "u000001" / "mail" / "routing.json").read_text(encoding="utf-8")
            self.assertIn('"mail_host"', routing_text)
            self.assertNotIn('"mail_plane_url"', routing_text)
            generated_compose = compose_path.read_text(encoding="utf-8")
            self.assertIn("/snappymail/snappymail/v/2.38.2/themes/MangoPanel:ro", generated_compose)
            self.assertIn("mp-u000001-mailproxy", generated_compose)
            self.assertIn("mailserver-state:/var/mail-state", generated_compose)
            self.assertIn("name: mp-u000001-mailserver-state", generated_compose)
            self.assertNotIn("/.runtime/stack/mailserver/state:/var/mail-state", generated_compose)
            self.assertIn("http://mail.mango.test", generated_compose)
            dev_compose = (Path(__file__).resolve().parent.parent / "docker-compose.dev.yml").read_text(encoding="utf-8")
            self.assertIn("mangopanel:", dev_compose)
            self.assertNotIn("stalwart", dev_compose)

            with connect(config.db_path) as conn:
                stack = conn.execute("SELECT * FROM account_stacks WHERE account_id = 1").fetchone()
                self.assertIsNotNone(stack)
                self.assertEqual(stack["status"], "generated")
                route = conn.execute("SELECT * FROM mail_edge_routes WHERE account_id = 1 AND domain = ?", ("example.mango.test",)).fetchone()
                self.assertIsNotNone(route)
                self.assertEqual(route["provider"], "shared-mail-edge")
                route_manifest = json.loads(route["manifest_json"])
                self.assertEqual(route_manifest["edge_host"], "mail.mango.test")
                self.assertTrue(route_manifest["mailboxes"])

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
                conn.execute(
                    """
                    INSERT INTO mailboxes(account_id, email, local_part, domain, storage_path, mail_domain_id, quota_mb, status, password_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account["id"],
                        "second@example.mango.test",
                        "second",
                        "example.mango.test",
                        str(mailbox_storage_path(account["base_path"], "second@example.mango.test")),
                        conn.execute("SELECT id FROM mail_domains WHERE account_id = ? LIMIT 1", (account["id"],)).fetchone()["id"],
                        1024,
                        "active",
                        "pbkdf2_sha256$1$abc$def",
                    ),
                )
                jobs.append(create_job(conn, "sync_mailboxes", "hosting_account", account["id"], {}))
                conn.commit()

                results = [Agent(config).run_job_by_id(job_id) for job_id in jobs]

                for result in results:
                    self.assertEqual(result["status"], "succeeded")
                    artifact_path = result["result"].get("artifact_path") or result["result"].get("state_path") or result["result"].get("compose_path")
                    self.assertTrue(artifact_path, result)
                    self.assertTrue(Path(artifact_path).exists(), artifact_path)

                self.assertTrue((config.account_root / "u000001" / ".runtime" / "dns" / "example.mango.test.json").exists())
                self.assertTrue((config.account_root / "u000001" / ".runtime" / "ssl" / "example.mango.test-issued.json").exists())
                dns_zone = conn.execute("SELECT * FROM dns_zones WHERE domain_id = ?", (domain["id"],)).fetchone()
                self.assertIsNotNone(dns_zone)
                self.assertEqual(dns_zone["provider"], "local-dev-dns")
                self.assertEqual(dns_zone["status"], "published")
                dns_state = json.loads(dns_zone["provider_state_json"])
                self.assertEqual(dns_state["zone_name"], "example.mango.test")
                self.assertTrue(any(record["type"] == "A" for record in dns_state["records"]))
                acme_order = conn.execute("SELECT * FROM acme_certificate_orders WHERE website_id = ? AND domain = ?", (website["id"], website["domain"])).fetchone()
                self.assertIsNotNone(acme_order)
                self.assertEqual(acme_order["provider"], "local-dev-acme")
                self.assertEqual(acme_order["status"], "issued")
                self.assertEqual(json.loads(acme_order["provider_state_json"])["status"], "issued")
                route = conn.execute("SELECT * FROM mail_edge_routes WHERE account_id = ? AND domain = ?", (account["id"], domain["name"])).fetchone()
                self.assertIsNotNone(route)
                self.assertEqual(route["provider"], "shared-mail-edge")
                self.assertEqual(route["status"], "active")
                self.assertTrue(any(item["email"] == "second@example.mango.test" for item in json.loads(route["manifest_json"])["mailboxes"]))
                self.assertTrue((config.account_root / "u000001" / ".runtime" / "mysql-remote" / "report.json").exists())
                self.assertTrue((config.account_root / "u000001" / ".runtime" / "images" / "report.json").exists())
                self.assertTrue((config.account_root / "u000001" / ".runtime" / "cron" / "report.json").exists())
                mailboxes_json = json.loads((config.account_root / "u000001" / "mail" / "mailboxes.json").read_text(encoding="utf-8"))
                self.assertTrue(any(mailbox["email"] == "second@example.mango.test" for mailbox in mailboxes_json))
                self.assertTrue((config.account_root / "u000001" / "mail" / "example.mango.test" / "second").exists())
                policy_json = json.loads((config.account_root / "u000001" / "mail" / "policy.json").read_text(encoding="utf-8"))
                self.assertTrue(policy_json["domains"])
                self.assertEqual(policy_json["domains"][0]["name"], "example.mango.test")
                self.assertTrue(Path(website["document_root"], "index.html").exists())
                hotlink_htaccess = Path(website["document_root"]) / ".htaccess"
                hotlink_text = hotlink_htaccess.read_text(encoding="utf-8")
                self.assertIn("# BEGIN MangoPanel Hotlink", hotlink_text)
                self.assertIn("RewriteCond %{HTTP_REFERER} !^https?://(?:[^/]+\\.)?example\\.mango\\.test(?:/|$)", hotlink_text)

    def test_provider_sync_jobs_fail_closed_for_missing_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            with connect(config.db_path) as conn:
                jobs = [
                    create_job(conn, "sync_dns_zone", "domain", 999999, {}),
                    create_job(conn, "issue_ssl", "website", 999999, {}),
                    create_job(conn, "sync_mailboxes", "hosting_account", 999999, {}),
                ]
                conn.commit()

            results = [Agent(config).run_job_by_id(job_id) for job_id in jobs]

            self.assertEqual([result["status"] for result in results], ["failed", "failed", "failed"])
            self.assertEqual(results[0]["error"], "domain_not_found")
            self.assertEqual(results[1]["error"], "website_not_found")
            self.assertEqual(results[2]["error"], "hosting_account_not_found")

    def test_analytics_sync_toggles_access_logs_in_stack_artifacts(self):
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
                website = conn.execute("SELECT * FROM websites WHERE account_id = 1 ORDER BY id LIMIT 1").fetchone()
                conn.execute("UPDATE websites SET analytics_enabled = 0 WHERE id = ?", (website["id"],))
                disable_job = create_job(conn, "sync_website_analytics", "website", website["id"], {})
                conn.commit()

            disable_result = Agent(config).run_job_by_id(disable_job)
            self.assertEqual(disable_result["status"], "succeeded")
            stack_root = config.account_root / "u000001" / ".runtime" / "stack"
            apache_vhosts = (stack_root / "apache-vhosts.conf").read_text(encoding="utf-8")
            ols_vhost = (stack_root / "vhosts" / website["domain"] / "vhconf.conf").read_text(encoding="utf-8")
            self.assertNotIn("CustomLog", apache_vhosts)
            self.assertNotIn("accesslog", ols_vhost)

            analytics_artifact = config.account_root / "u000001" / ".runtime" / "analytics" / f"{website['domain']}.json"
            self.assertTrue(analytics_artifact.exists())
            self.assertEqual(json.loads(analytics_artifact.read_text(encoding="utf-8"))["analytics_enabled"], 0)

            with connect(config.db_path) as conn:
                conn.execute("UPDATE websites SET analytics_enabled = 1 WHERE id = ?", (website["id"],))
                enable_job = create_job(conn, "sync_website_analytics", "website", website["id"], {})
                conn.commit()

            enable_result = Agent(config).run_job_by_id(enable_job)
            self.assertEqual(enable_result["status"], "succeeded")
            apache_vhosts = (stack_root / "apache-vhosts.conf").read_text(encoding="utf-8")
            ols_vhost = (stack_root / "vhosts" / website["domain"] / "vhconf.conf").read_text(encoding="utf-8")
            self.assertIn("CustomLog", apache_vhosts)
            self.assertIn("accesslog", ols_vhost)
            self.assertEqual(json.loads(analytics_artifact.read_text(encoding="utf-8"))["analytics_enabled"], 1)

    def test_git_deploy_clones_updates_and_rolls_back_real_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_repo = root / "source"
            source_repo.mkdir()
            subprocess.run(["git", "init", "-b", "main", str(source_repo)], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(source_repo), "config", "user.email", "dev@example.test"], check=True)
            subprocess.run(["git", "-C", str(source_repo), "config", "user.name", "Dev"], check=True)
            (source_repo / "README.md").write_text("version 1\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source_repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(source_repo), "commit", "-m", "initial"], check=True, capture_output=True, text=True)
            first_commit = subprocess.run(["git", "-C", str(source_repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()

            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts ORDER BY id LIMIT 1").fetchone()
                deploy_path = f"git/{source_repo.name}"
                deployment_id = conn.execute(
                    "INSERT INTO git_deployments(account_id, repository_url, branch, deploy_path, status) VALUES (?, ?, ?, ?, ?)",
                    (account["id"], str(source_repo), "main", deploy_path, "configured"),
                ).lastrowid
                deploy_job = create_job(conn, "git_deploy", "git_deployment", deployment_id, {})
                conn.commit()

            deploy_result = Agent(config).run_job_by_id(deploy_job)
            self.assertEqual(deploy_result["status"], "succeeded")
            deploy_root = config.account_root / "u000001" / "git" / source_repo.name
            self.assertTrue((deploy_root / ".git").exists())
            self.assertEqual((deploy_root / "README.md").read_text(encoding="utf-8"), "version 1\n")

            (source_repo / "README.md").write_text("version 2\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source_repo), "commit", "-am", "update"], check=True, capture_output=True, text=True)
            second_commit = subprocess.run(["git", "-C", str(source_repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()

            with connect(config.db_path) as conn:
                deploy_job_2 = create_job(conn, "git_deploy", "git_deployment", deployment_id, {})
                conn.commit()
            deploy_result_2 = Agent(config).run_job_by_id(deploy_job_2)
            self.assertEqual(deploy_result_2["status"], "succeeded")
            self.assertEqual((deploy_root / "README.md").read_text(encoding="utf-8"), "version 2\n")

            with connect(config.db_path) as conn:
                rollback_job = create_job(conn, "git_rollback", "git_deployment", deployment_id, {})
                conn.commit()
            rollback_result = Agent(config).run_job_by_id(rollback_job)
            self.assertEqual(rollback_result["status"], "succeeded")
            self.assertEqual((deploy_root / "README.md").read_text(encoding="utf-8"), "version 1\n")
            self.assertEqual(subprocess.run(["git", "-C", str(deploy_root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip(), first_commit)

    def test_cron_sync_writes_wrappers_next_run_and_runtime_state(self):
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
                cron_id = conn.execute(
                    "INSERT INTO cron_jobs(account_id, schedule, command, status, next_run_at) VALUES (?, ?, ?, ?, ?)",
                    (account["id"], "*/15 * * * *", "php /home/u000001/domains/example.mango.test/public_html/cron.php", "enabled", "2030-01-01T00:15:00Z"),
                ).lastrowid
                job_id = create_job(conn, "sync_cron_jobs", "hosting_account", account["id"], {})
                conn.commit()

            script_path = config.account_root / "u000001" / ".runtime" / "cron" / "jobs" / f"job-{cron_id}.sh"
            log_path = config.account_root / "u000001" / ".runtime" / "cron" / "logs" / f"job-{cron_id}.log"
            state_path = config.account_root / "u000001" / ".runtime" / "cron" / "state" / f"job-{cron_id}.state"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text("cron ran ok\n", encoding="utf-8")
            state_path.write_text(
                "\n".join(
                    [
                        f"job_id={cron_id}",
                        "account_id=1",
                        "username=u000001",
                        "schedule=*/15 * * * *",
                        "command=php /home/u000001/domains/example.mango.test/public_html/cron.php",
                        "started_at=2030-01-01T00:00:00Z",
                        "last_run_at=2030-01-01T00:15:00Z",
                        "finished_at=2030-01-01T00:15:01Z",
                        "last_exit_code=0",
                        f"log_path=/home/u000001/.runtime/cron/logs/job-{cron_id}.log",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            result = Agent(config).run_job_by_id(job_id)

            self.assertEqual(result["status"], "succeeded")
            self.assertTrue(script_path.exists())
            self.assertEqual(script_path.stat().st_mode & 0o777, 0o755)
            self.assertIn("/home/u000001/.runtime/cron/jobs/job-{}".format(cron_id), (config.account_root / "u000001" / ".runtime" / "stack" / "cron").read_text(encoding="utf-8"))
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "cron" / "report.json").exists())

            with connect(config.db_path) as conn:
                cron = conn.execute("SELECT * FROM cron_jobs WHERE id = ?", (cron_id,)).fetchone()
                self.assertEqual(cron["last_run_at"], "2030-01-01T00:15:00Z")
                self.assertEqual(cron["last_exit_code"], 0)
                self.assertIn("cron ran ok", cron["last_output"])
                self.assertTrue(cron["next_run_at"])
                self.assertTrue(cron["next_run_at"].endswith("Z"))

    def test_images_optimize_creates_derivative_files_and_report(self):
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
                image_path = Path(account["base_path"]) / "photo.png"
                from PIL import Image

                img = Image.new("RGB", (2400, 1600), "blue")
                img.save(image_path)
                job_id = create_job(conn, "optimize_images", "account", account["id"], {"path": "photo.png"})
                conn.commit()

            result = Agent(config).run_job_by_id(job_id)
            self.assertEqual(result["status"], "succeeded")
            report = config.account_root / "u000001" / ".runtime" / "images" / "report.json"
            self.assertTrue(report.exists())
            derivative = config.account_root / "u000001" / ".runtime" / "images" / "optimized" / "photo.webp"
            self.assertTrue(derivative.exists())
            self.assertLess(derivative.stat().st_size, image_path.stat().st_size)

    def test_remote_mysql_and_postgresql_sync_write_native_reports(self):
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
                conn.execute("INSERT INTO remote_mysql_hosts(account_id, host_ip) VALUES (?, ?)", (account["id"], "203.0.113.10"))
                conn.execute("INSERT INTO pg_databases(account_id, name) VALUES (?, ?)", (account["id"], "u000001_app"))
                conn.execute("INSERT INTO pg_users(account_id, username, password) VALUES (?, ?, ?)", (account["id"], "u000001_app_user", "StrongPass123"))
                database_id = conn.execute("SELECT id FROM pg_databases WHERE account_id = ?", (account["id"],)).fetchone()["id"]
                user_id = conn.execute("SELECT id FROM pg_users WHERE account_id = ?", (account["id"],)).fetchone()["id"]
                conn.execute("INSERT INTO pg_grants(database_id, user_id, privileges) VALUES (?, ?, ?)", (database_id, user_id, "ALL"))
                mysql_job = create_job(conn, "sync_remote_mysql", "account", account["id"], {})
                pg_job = create_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                conn.commit()

            mysql_result = Agent(config).run_job_by_id(mysql_job)
            pg_result = Agent(config).run_job_by_id(pg_job)

            self.assertEqual(mysql_result["status"], "succeeded")
            self.assertEqual(pg_result["status"], "succeeded")
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "mysql-remote" / "report.json").exists())
            self.assertTrue((config.account_root / "u000001" / ".runtime" / "postgresql" / "report.json").exists())

    def test_ftp_and_protected_directory_sync_write_native_files(self):
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
                website_domain = website["domain"]
                ftp_path = f"domains/{website['domain']}/public_html/uploads"
                protected_path = f"domains/{website['domain']}/public_html/private"

                conn.execute(
                    "INSERT INTO ftp_accounts(account_id, username, password, path) VALUES (?, ?, ?, ?)",
                    (account["id"], "u000001_phase6", "StrongPass123", ftp_path),
                )
                conn.execute(
                    "INSERT INTO protected_directories(account_id, path, username, password_hash) VALUES (?, ?, ?, ?)",
                    (account["id"], protected_path, "phase6_priv", "managed_by_agent"),
                )
                ftp_job = create_job(conn, "sync_ftp_accounts", "hosting_account", account["id"], {})
                protect_job = create_job(
                    conn,
                    "sync_protected_directories",
                    "hosting_account",
                    account["id"],
                    {"path": protected_path, "username": "phase6_priv", "password": "StrongPass123"},
                )
                conn.commit()

            ftp_result = Agent(config).run_job_by_id(ftp_job)
            protect_result = Agent(config).run_job_by_id(protect_job)

            self.assertEqual(ftp_result["status"], "succeeded")
            self.assertEqual(protect_result["status"], "succeeded")

            account_base = config.account_root / "u000001"
            sftp_conf = (account_base / ".runtime" / "stack" / "sftp_users.conf").read_text(encoding="utf-8")
            self.assertIn(f"{ftp_path}", sftp_conf)

            protected_dir = account_base / "domains" / website["domain"] / "public_html" / "private"
            htaccess = protected_dir / ".htaccess"
            htpasswd = protected_dir / ".htpasswd"
            self.assertTrue(htaccess.exists())
            self.assertTrue(htpasswd.exists())
            self.assertIn("/home/u000001/domains/{}/public_html/private/.htpasswd".format(website_domain), htaccess.read_text(encoding="utf-8"))
            self.assertNotIn("StrongPass123", htpasswd.read_text(encoding="utf-8"))

    def test_service_status_and_restart_report_real_container_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config()
            config.db_path = root / "mangopanel.sqlite3"
            config.data_dir = root
            config.account_root = root / "accounts"
            config.agent_mode = "simulate"

            seed_dev_data(config.db_path, config.account_root)
            Agent(config).run_all()
            config.agent_mode = "docker"

            with connect(config.db_path) as conn:
                account = conn.execute("SELECT * FROM hosting_accounts ORDER BY id LIMIT 1").fetchone()
                job_id = create_job(conn, "restart_service", "hosting_account", account["id"], {"service": "web"})
                stack = conn.execute("SELECT * FROM account_stacks WHERE account_id = ?", (account["id"],)).fetchone()
                conn.commit()

            def fake_run(args, check=False, capture_output=False, text=False, timeout=None):
                command = " ".join(args)
                if "compose" in args and "restart" in args:
                    return type("Result", (), {"returncode": 0, "stdout": "restarted\n", "stderr": ""})()
                if args[:2] == ["/usr/bin/docker", "inspect"]:
                    return type("Result", (), {"returncode": 0, "stdout": "running|healthy|true\n", "stderr": ""})()
                raise AssertionError(command)

            with patch("mangopanel.agent.shutil.which", return_value="/usr/bin/docker"), patch("mangopanel.agent.subprocess.run", side_effect=fake_run) as run:
                result = Agent(config).run_job_by_id(job_id)
                status = Agent(config).service_status(
                    {"id": account["id"], "username": account["username"]},
                    {"compose_path": stack["compose_path"]},
                    "web",
                )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["result"]["service"], "web")
            self.assertEqual(result["result"]["state"]["status"], "running")
            self.assertEqual(status["services"][0]["status"], "running")
            self.assertEqual(status["services"][0]["health"], "healthy")
            self.assertEqual(status["services"][0]["container"], "mp-u000001-web")

    def test_hotlink_sync_writes_real_htaccess_and_removes_it_on_disable(self):
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
                conn.execute(
                    "INSERT INTO hotlink_settings(account_id, enabled, allowed_domains) VALUES (?, ?, ?)",
                    (account["id"], 1, "cdn.example.test"),
                )
                job_id = create_job(conn, "sync_hotlink_protection", "hosting_account", account["id"], {})
                conn.commit()

            result = Agent(config).run_job_by_id(job_id)
            self.assertEqual(result["status"], "succeeded")
            htaccess = Path(website["document_root"]) / ".htaccess"
            text = htaccess.read_text(encoding="utf-8")
            self.assertIn("# BEGIN MangoPanel Hotlink", text)
            self.assertIn("cdn\\.example\\.test", text)
            self.assertNotIn("simulated hotlink", text.lower())

            with connect(config.db_path) as conn:
                conn.execute(
                    "UPDATE hotlink_settings SET enabled = 0, allowed_domains = '' WHERE account_id = ?",
                    (account["id"],),
                )
                disable_job = create_job(conn, "sync_hotlink_protection", "hosting_account", account["id"], {})
                conn.commit()

            disable_result = Agent(config).run_job_by_id(disable_job)
            self.assertEqual(disable_result["status"], "succeeded")
            if htaccess.exists():
                self.assertNotIn("# BEGIN MangoPanel Hotlink", htaccess.read_text(encoding="utf-8"))

    def test_folder_index_sync_writes_real_htaccess_and_toggles_listing(self):
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
                conn.execute("UPDATE websites SET index_enabled = 1 WHERE id = ?", (website["id"],))
                enable_job = create_job(conn, "sync_website_index", "website", website["id"], {})
                conn.commit()

            enable_result = Agent(config).run_job_by_id(enable_job)
            self.assertEqual(enable_result["status"], "succeeded")
            htaccess = Path(website["document_root"]) / ".htaccess"
            text = htaccess.read_text(encoding="utf-8")
            self.assertIn("# BEGIN MangoPanel Index Rules", text)
            self.assertIn("Options +Indexes", text)

            with connect(config.db_path) as conn:
                conn.execute("UPDATE websites SET index_enabled = 0 WHERE id = ?", (website["id"],))
                disable_job = create_job(conn, "sync_website_index", "website", website["id"], {})
                conn.commit()

            disable_result = Agent(config).run_job_by_id(disable_job)
            self.assertEqual(disable_result["status"], "succeeded")
            text = htaccess.read_text(encoding="utf-8")
            self.assertIn("Options -Indexes", text)
            self.assertNotIn("Options +Indexes", text)

    def test_modsecurity_sync_writes_real_htaccess_and_toggles_rule_engine(self):
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
                conn.execute("UPDATE websites SET modsec_enabled = 1 WHERE id = ?", (website["id"],))
                enable_job = create_job(conn, "sync_website_modsec", "website", website["id"], {})
                conn.commit()

            enable_result = Agent(config).run_job_by_id(enable_job)
            self.assertEqual(enable_result["status"], "succeeded")
            htaccess = Path(website["document_root"]) / ".htaccess"
            text = htaccess.read_text(encoding="utf-8")
            self.assertIn("# BEGIN MangoPanel ModSec", text)
            self.assertIn("SecRuleEngine On", text)

            with connect(config.db_path) as conn:
                conn.execute("UPDATE websites SET modsec_enabled = 0 WHERE id = ?", (website["id"],))
                disable_job = create_job(conn, "sync_website_modsec", "website", website["id"], {})
                conn.commit()

            disable_result = Agent(config).run_job_by_id(disable_job)
            self.assertEqual(disable_result["status"], "succeeded")
            text = htaccess.read_text(encoding="utf-8")
            self.assertIn("SecRuleEngine Off", text)
            self.assertNotIn("SecRuleEngine On", text)

    def test_fix_file_ownership_normalizes_account_tree_and_preserves_config_permissions(self):
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
                account_base = Path(account["base_path"])

                public_file = account_base / "public.txt"
                public_file.write_text("public\n", encoding="utf-8")
                public_file.chmod(0o600)

                config_file = account_base / "config.php"
                config_file.write_text("<?php echo 'config';\n", encoding="utf-8")
                config_file.chmod(0o600)

                htaccess = account_base / ".htaccess"
                htaccess.write_text("Deny from all\n", encoding="utf-8")
                htaccess.chmod(0o600)

                nested_dir = account_base / "nested"
                nested_dir.mkdir(parents=True, exist_ok=True)
                nested_dir.chmod(0o700)

                outside = root / "outside.txt"
                outside.write_text("outside\n", encoding="utf-8")
                symlink = account_base / "escape-link"
                try:
                    symlink.symlink_to(outside)
                except (AttributeError, NotImplementedError, OSError):
                    symlink = None

                job_id = create_job(conn, "fix_file_ownership", "hosting_account", account["id"], {})
                conn.commit()

            result = Agent(config).run_job_by_id(job_id)
            self.assertEqual(result["status"], "succeeded")
            self.assertTrue(Path(result["result"]["artifact_path"]).exists())
            self.assertEqual(public_file.stat().st_mode & 0o777, 0o644)
            self.assertEqual(nested_dir.stat().st_mode & 0o777, 0o755)
            self.assertEqual(config_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(htaccess.stat().st_mode & 0o777, 0o600)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
            if symlink is not None:
                self.assertTrue(symlink.exists())
                self.assertEqual(os.readlink(symlink), str(outside))

    def test_cache_purge_clears_native_cache_dirs_and_keeps_outside_files_safe(self):
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

                account_cache = Path(account["base_path"]) / ".runtime" / "cache"
                account_cache.mkdir(parents=True, exist_ok=True)
                (account_cache / "opcache.bin").write_text("cache\n", encoding="utf-8")

                website_cache = Path(website["document_root"]) / "wp-content" / "cache"
                website_cache.mkdir(parents=True, exist_ok=True)
                (website_cache / "page-cache.html").write_text("cache\n", encoding="utf-8")

                outside = root / "outside-cache.txt"
                outside.write_text("outside\n", encoding="utf-8")
                escape_link = website_cache / "escape-link"
                try:
                    escape_link.symlink_to(outside)
                except (AttributeError, NotImplementedError, OSError):
                    escape_link = None

                job_id = create_job(conn, "purge_cache", "hosting_account", account["id"], {"website_id": website["id"]})
                conn.commit()

            result = Agent(config).run_job_by_id(job_id)
            self.assertEqual(result["status"], "succeeded")
            self.assertTrue(Path(result["result"]["artifact_path"]).exists())
            self.assertFalse((account_cache / "opcache.bin").exists())
            self.assertFalse((website_cache / "page-cache.html").exists())
            self.assertTrue(account_cache.exists())
            self.assertTrue(website_cache.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
            if escape_link is not None:
                self.assertFalse(escape_link.exists())

    def test_opcache_reset_and_object_cache_flush_write_reports_and_clear_scope(self):
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

                account_cache = Path(account["base_path"]) / ".runtime" / "cache"
                account_cache.mkdir(parents=True, exist_ok=True)
                opcache_dir = account_cache / "opcache"
                opcache_dir.mkdir(parents=True, exist_ok=True)
                (opcache_dir / "state.bin").write_text("cache\n", encoding="utf-8")
                object_cache_dir = account_cache / "object-cache"
                object_cache_dir.mkdir(parents=True, exist_ok=True)
                (object_cache_dir / "state.bin").write_text("cache\n", encoding="utf-8")

                website_cache = Path(website["document_root"]) / "wp-content" / "cache"
                website_cache.mkdir(parents=True, exist_ok=True)
                (website_cache / "page-cache.html").write_text("cache\n", encoding="utf-8")

                reset_job = create_job(conn, "reset_opcache", "hosting_account", account["id"], {"website_id": website["id"]})
                flush_job = create_job(conn, "flush_object_cache", "hosting_account", account["id"], {"website_id": website["id"]})
                conn.commit()

            reset_result = Agent(config).run_job_by_id(reset_job)
            flush_result = Agent(config).run_job_by_id(flush_job)

            self.assertEqual(reset_result["status"], "succeeded")
            self.assertEqual(flush_result["status"], "succeeded")
            self.assertTrue(Path(reset_result["result"]["artifact_path"]).exists())
            self.assertTrue(Path(flush_result["result"]["artifact_path"]).exists())
            self.assertFalse((opcache_dir / "state.bin").exists())
            self.assertFalse((object_cache_dir / "state.bin").exists())
            self.assertFalse((website_cache / "page-cache.html").exists())

    def test_manual_backup_creates_real_archive_and_restore_rejects_path_traversal(self):
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
                doc_root = Path(website["document_root"])
                doc_root.mkdir(parents=True, exist_ok=True)
                (doc_root / "backup-proof.txt").write_text("backup\n", encoding="utf-8")
                backup_id = conn.execute(
                    "INSERT INTO backups(account_id, kind, status) VALUES (?, ?, ?)",
                    (account["id"], "manual", "queued"),
                ).lastrowid
                job_id = create_job(conn, "manual_backup", "backup", backup_id, {})
                conn.commit()

            result = Agent(config).run_job_by_id(job_id)
            self.assertEqual(result["status"], "succeeded")
            artifact = Path(result["result"]["artifact_path"])
            self.assertTrue(artifact.exists())

            with tarfile.open(artifact, "r:gz") as tar:
                names = tar.getnames()
            self.assertIn("account.json", names)
            self.assertTrue(any(name.endswith("backup-proof.txt") for name in names))

            malicious = root / "malicious-backup.tar.gz"
            with tarfile.open(malicious, "w:gz") as tar:
                info = tarfile.TarInfo("../escape.txt")
                data = b"evil\n"
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

            with connect(config.db_path) as conn:
                restore_backup_id = conn.execute(
                    "INSERT INTO backups(account_id, kind, status, artifact_path) VALUES (?, ?, ?, ?)",
                    (account["id"], "manual", "completed", str(malicious)),
                ).lastrowid
                restore_job = create_job(conn, "restore_backup", "backup", restore_backup_id, {})
                conn.commit()

            restore_result = Agent(config).run_job_by_id(restore_job)
            self.assertEqual(restore_result["status"], "failed")
            self.assertFalse((root / "escape.txt").exists())

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
