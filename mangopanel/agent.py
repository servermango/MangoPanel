import json
import shutil
import subprocess
import time
import tarfile
import os

def is_within_directory(directory, target):
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    prefix = os.path.commonprefix([abs_directory, abs_target])
    return prefix == abs_directory

def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not is_within_directory(path, member_path):
            raise Exception("Attempted Path Traversal in Tar File")
    tar.extractall(path, members, numeric_owner=numeric_owner)

from pathlib import Path
import subprocess
import time
from pathlib import Path

from .config import load_config
from .db import connect, log_job_event, row_to_dict, rows_to_dicts
from .stack import STACK_SERVICES, build_account_runtime, ensure_account_layout, render_crontab, stack_summary


class AgentError(Exception):
    pass


MANGOPANEL_PLACEHOLDER_PREFIX = "<?php\nheader('Content-Type: text/plain');\necho \"MangoPanel dev site:"


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg"}


class Agent:
    def __init__(self, config=None):
        self.config = config or load_config()

    def run_once(self):
        with connect(self.config.db_path) as conn:
            job = self.claim_next_job(conn)
            if not job:
                return None
            return self.run_claimed_job(conn, job)

    def run_all(self, limit=25):
        results = []
        for _ in range(limit):
            result = self.run_once()
            if result is None:
                break
            results.append(result)
        return results

    def apply_all_accounts(self):
        results = []
        with connect(self.config.db_path) as conn:
            rows = conn.execute("SELECT id FROM hosting_accounts ORDER BY id").fetchall()
            for row in rows:
                results.append(self.provision_hosting_account(conn, row["id"]))
        return results

    def down_all_accounts(self):
        results = []
        with connect(self.config.db_path) as conn:
            rows = conn.execute("SELECT compose_path FROM account_stacks ORDER BY id").fetchall()
            for row in rows:
                results.append(self.compose_down(row["compose_path"]))
        return results

    def run_job_by_id(self, job_id):
        with connect(self.config.db_path) as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if not job:
                raise AgentError("job_not_found")
            if job["status"] not in {"queued", "running"}:
                return row_to_dict(job)
            conn.execute(
                """
                UPDATE jobs
                SET status = 'running', attempts = attempts + 1, claimed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (job_id,),
            )
            job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self.run_claimed_job(conn, job)

    def claim_next_job(self, conn):
        job = conn.execute("SELECT * FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
        if not job:
            return None
        conn.execute(
            """
            UPDATE jobs
            SET status = 'running', attempts = attempts + 1, claimed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'queued'
            """,
            (job["id"],),
        )
        return conn.execute("SELECT * FROM jobs WHERE id = ?", (job["id"],)).fetchone()

    def run_claimed_job(self, conn, job):
        log_job_event(conn, job["id"], "Agent claimed job", metadata={"type": job["type"]})
        try:
            result = self.dispatch(conn, job)
            conn.execute(
                """
                UPDATE jobs
                SET status = 'succeeded', result = ?, updated_at = CURRENT_TIMESTAMP, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (json.dumps(result), job["id"]),
            )
            log_job_event(conn, job["id"], "Agent completed job", metadata=result)
            return {"job_id": job["id"], "status": "succeeded", "result": result}
        except Exception as exc:
            conn.execute(
                """
                UPDATE jobs
                SET status = 'failed', result = ?, updated_at = CURRENT_TIMESTAMP, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (json.dumps({"error": str(exc)}), job["id"]),
            )
            log_job_event(conn, job["id"], "Agent failed job", level="error", metadata={"error": str(exc)})
            return {"job_id": job["id"], "status": "failed", "error": str(exc)}

    def dispatch(self, conn, job):
        job_type = job["type"]
        if job_type == "provision_hosting_account":
            return self.provision_hosting_account(conn, job["target_id"])
        if job_type == "create_website":
            website = conn.execute("SELECT * FROM websites WHERE id = ?", (job["target_id"],)).fetchone()
            if not website:
                raise AgentError("website_not_found")
            return self.provision_hosting_account(conn, website["account_id"], touched_website_id=website["id"])
        if job_type == "delete_website":
            return self.delete_website(conn, job)
        if job_type == "issue_ssl":
            return self.issue_ssl(conn, job["target_id"])
        if job_type == "sync_dns_record":
            return self.sync_dns_record(conn, job["target_id"])
        if job_type == "sync_dns_zone":
            return self.sync_dns_zone(conn, job["target_id"])
        if job_type == "create_database":
            database = conn.execute("SELECT * FROM databases WHERE id = ?", (job["target_id"],)).fetchone()
            if not database:
                raise AgentError("database_not_found")
            return self.provision_hosting_account(conn, database["account_id"])
        if job_type == "create_mailbox":
            mailbox = conn.execute("SELECT * FROM mailboxes WHERE id = ?", (job["target_id"],)).fetchone()
            if not mailbox:
                raise AgentError("mailbox_not_found")
            return self.provision_hosting_account(conn, mailbox["account_id"])
        if job_type == "manual_backup":
            return self.manual_backup(conn, job["target_id"])
        if job_type == "restore_backup":
            return self.restore_backup(conn, job["target_id"])
        if job_type == "fix_file_ownership":
            return self.fix_file_ownership(conn, job["target_id"])
        if job_type == "sync_ip_rules":
            return self.sync_ip_rules(conn, job["target_id"])
        if job_type == "sync_website_index":
            return self.sync_website_index(conn, job["target_id"])
        if job_type == "sync_protected_directories":
            return self.sync_protected_directories(conn, job["target_id"], job["payload"])
        if job_type == "sync_redirects":
            return self.sync_redirects(conn, job["target_id"])
        if job_type == "sync_website_modsec":
            return self.sync_website_modsec(conn, job["target_id"])
        if job_type == "sync_ftp_accounts":
            return self.sync_ftp_accounts(conn, job["target_id"])
        if job_type == "sync_remote_mysql":
            return self.sync_remote_mysql(conn, job["target_id"])
        if job_type == "sync_hotlink_protection":
            return self.sync_hotlink_protection(conn, job["target_id"])
        if job_type == "install_site_builder":
            return self.install_site_builder(conn, job)
        if job_type == "optimize_images":
            return self.optimize_images(conn, job)
        if job_type == "sync_cron_jobs":
            return self.sync_cron_jobs(conn, job["target_id"])
        if job_type == "sync_pg_databases":
            return self.sync_pg_databases(conn, job["target_id"])
        if job_type == "install_custom_ssl":
            return self.install_custom_ssl(conn, job)
        if job_type == "restart_service":
            return self.restart_service(conn, job)
        if job_type == "kill_all_processes":
            return self.kill_all_processes(conn, job["target_id"])
        if job_type == "update_website_php":
            return self.update_website_php(conn, job["target_id"])
        if job_type == "purge_cache":
            return self.purge_cache(conn, job)
        if job_type == "create_cron_job":
            cron = conn.execute("SELECT * FROM cron_jobs WHERE id = ?", (job["target_id"],)).fetchone()
            if not cron:
                raise AgentError("cron_job_not_found")
            return self.sync_cron_jobs(conn, cron["account_id"])
        if job_type == "git_deploy":
            deployment = conn.execute("SELECT * FROM git_deployments WHERE id = ?", (job["target_id"],)).fetchone()
            if not deployment:
                raise AgentError("git_deployment_not_found")
            Path(deployment["deploy_path"]).mkdir(parents=True, exist_ok=True)
            marker = Path(deployment["deploy_path"]) / ".mangopanel-git-deploy"
            marker.write_text("repository={}\nbranch={}\n".format(deployment["repository_url"], deployment["branch"]), encoding="utf-8")
            return {"deployment_id": deployment["id"], "marker": str(marker)}
        if job_type == "install_wordpress":
            return self.install_wordpress(conn, job)
        if job_type == "install_script":
            return self.install_script(conn, job)
        if job_type == "suspend_account":
            conn.execute("UPDATE hosting_accounts SET status = 'suspended' WHERE id = ?", (job["target_id"],))
            return {"account_id": job["target_id"], "status": "suspended"}
        if job_type == "unsuspend_account":
            conn.execute("UPDATE hosting_accounts SET status = 'active' WHERE id = ?", (job["target_id"],))
            return {"account_id": job["target_id"], "status": "active"}
        if job_type == "update_database":
            database = conn.execute("SELECT id, name, status FROM databases WHERE id = ?", (job["target_id"],)).fetchone()
            if not database:
                raise AgentError("database_not_found")
            return {"database_id": database["id"], "name": database["name"], "status": database["status"], "synced": True}
        if job_type == "delete_database":
            # Database row already removed by API; agent would drop the MySQL database in production.
            return {"database_id": job["target_id"], "deleted": True}
        if job_type == "create_database_user":
            db_user = conn.execute("SELECT id, username FROM database_users WHERE id = ?", (job["target_id"],)).fetchone()
            if not db_user:
                raise AgentError("database_user_not_found")
            return {"database_user_id": db_user["id"], "username": db_user["username"], "created": True}
        if job_type == "update_database_user":
            db_user = conn.execute("SELECT id, username, status FROM database_users WHERE id = ?", (job["target_id"],)).fetchone()
            if not db_user:
                raise AgentError("database_user_not_found")
            return {"database_user_id": db_user["id"], "username": db_user["username"], "status": db_user["status"], "synced": True}
        if job_type == "delete_database_user":
            # Database user row already removed by API; agent would drop MySQL user in production.
            return {"database_user_id": job["target_id"], "deleted": True}
        if job_type == "grant_database_user":
            grant = conn.execute("SELECT id, database_id, user_id, privileges FROM database_grants WHERE id = ?", (job["target_id"],)).fetchone()
            if not grant:
                raise AgentError("database_grant_not_found")
            return {"grant_id": grant["id"], "database_id": grant["database_id"], "user_id": grant["user_id"], "privileges": grant["privileges"], "granted": True}
        if job_type == "update_database_grant":
            grant = conn.execute("SELECT id, database_id, user_id, privileges, status FROM database_grants WHERE id = ?", (job["target_id"],)).fetchone()
            if not grant:
                raise AgentError("database_grant_not_found")
            return {"grant_id": grant["id"], "privileges": grant["privileges"], "status": grant["status"], "synced": True}
        if job_type == "revoke_database_user":
            # Grant row already removed by API; agent would run REVOKE in production.
            return {"grant_id": job["target_id"], "revoked": True}
        raise AgentError("unsupported_job_type: {}".format(job_type))

    def job_payload(self, job):
        payload = job["payload"] or {}
        if isinstance(payload, str):
            return json.loads(payload) if payload else {}
        return payload

    def account_simulated_dir(self, account, *parts):
        path = Path(account["base_path"]) / ".runtime" / "simulated"
        for part in parts:
            path = path / str(part)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def write_simulated_json(self, account, name, payload):
        path = self.account_simulated_dir(account, name)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return str(path)

    def issue_ssl(self, conn, website_id):
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        conn.execute("UPDATE websites SET ssl_status = 'local-dev' WHERE id = ?", (website_id,))
        conn.execute(
            """
            INSERT INTO ssl_certificates(account_id, website_id, domain, status, issued_at, expires_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime('now', '+90 days'))
            """,
            (account["id"], website_id, website["domain"], "local-dev"),
        )
        artifact = self.write_simulated_json(
            account,
            "ssl/{}.json".format(website["domain"]),
            {"mode": "simulate", "domain": website["domain"], "status": "local-dev", "website_id": website_id},
        )
        return {"mode": "simulate", "ssl_status": "local-dev", "website_id": website_id, "artifact_path": artifact}

    def sync_dns_record(self, conn, record_id):
        record = conn.execute("SELECT * FROM dns_records WHERE id = ?", (record_id,)).fetchone()
        if not record:
            raise AgentError("dns_record_not_found")
        result = self.sync_dns_zone(conn, record["domain_id"])
        result["record_id"] = record["id"]
        return result

    def sync_dns_zone(self, conn, domain_id):
        domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
        if not domain:
            raise AgentError("domain_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (domain["account_id"],)).fetchone()
        records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name, id", (domain["id"],)).fetchall()
        zone_lines = [
            "$ORIGIN {}.".format(domain["name"]),
            "$TTL 300",
            "; MangoPanel simulated DNS zone",
        ]
        for item in records:
            priority = "{} ".format(item["priority"]) if item["priority"] is not None else ""
            zone_lines.append("{} {} IN {} {}{}".format(item["name"], item["ttl"], item["type"], priority, item["value"]))
        artifact = self.account_simulated_dir(account, "dns", "{}.zone".format(domain["name"]))
        artifact.write_text("\n".join(zone_lines) + "\n", encoding="utf-8")
        return {"mode": "simulate", "domain_id": domain["id"], "domain": domain["name"], "synced": True, "artifact_path": str(artifact)}

    def sync_remote_mysql(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        hosts = rows_to_dicts(conn.execute("SELECT id, host_ip, created_at FROM remote_mysql_hosts WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        artifact = self.write_simulated_json(account, "remote-mysql.json", {"mode": "simulate", "hosts": hosts})
        return {"mode": "simulate", "synced": True, "account_id": account_id, "hosts_count": len(hosts), "artifact_path": artifact}

    def sync_hotlink_protection(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        settings = conn.execute("SELECT * FROM hotlink_settings WHERE account_id = ?", (account_id,)).fetchone()
        enabled = bool(settings["enabled"]) if settings else False
        allowed = [line.strip() for line in (settings["allowed_domains"] if settings else "").splitlines() if line.strip()]
        lines = [
            "# MangoPanel simulated hotlink protection",
            "enabled={}".format(str(enabled).lower()),
            "allowed_domains={}".format(",".join(allowed)),
        ]
        artifact = self.account_simulated_dir(account, "hotlink.conf")
        artifact.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"mode": "simulate", "synced": True, "account_id": account_id, "enabled": enabled, "artifact_path": str(artifact)}

    def install_site_builder(self, conn, job):
        payload = self.job_payload(job)
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (job["target_id"],)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        template_id = payload.get("template_id", "business")
        root = Path(website["document_root"])
        root.mkdir(parents=True, exist_ok=True)
        index = root / "index.html"
        index.write_text(
            "<!doctype html>\n"
            "<html><head><meta charset=\"utf-8\"><title>{domain}</title></head>\n"
            "<body><h1>{domain}</h1><p>MangoPanel simulated {template} site builder template.</p></body></html>\n".format(
                domain=website["domain"], template=template_id
            ),
            encoding="utf-8",
        )
        artifact = self.write_simulated_json(
            account,
            "site-builder/{}-{}.json".format(website["id"], template_id),
            {"mode": "simulate", "website_id": website["id"], "domain": website["domain"], "template_id": template_id, "written_files": [str(index)]},
        )
        return {"mode": "simulate", "installed": True, "website_id": website["id"], "template_id": template_id, "artifact_path": artifact}

    def optimize_images(self, conn, job):
        payload = self.job_payload(job)
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        requested = payload.get("path") or payload.get("directory") or "."
        base = Path(account["base_path"]).resolve()
        requested_path = Path(str(requested))
        target = requested_path.resolve() if requested_path.is_absolute() else (base / requested_path).resolve()
        try:
            target.relative_to(base)
        except ValueError:
            raise AgentError("invalid_image_path")
        images = []
        if target.exists():
            candidates = [target] if target.is_file() else target.rglob("*")
            for item in candidates:
                if item.is_file() and item.suffix.lower() in IMAGE_EXTENSIONS:
                    images.append({"path": str(item), "size_bytes": item.stat().st_size})
        total_bytes = sum(item["size_bytes"] for item in images)
        artifact = self.write_simulated_json(
            account,
            "image-optimization-report.json",
            {"mode": "simulate", "requested_path": requested, "images": images, "total_bytes": total_bytes},
        )
        return {"mode": "simulate", "optimized": False, "images_count": len(images), "total_bytes": total_bytes, "artifact_path": artifact}

    def sync_cron_jobs(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        cron_jobs = rows_to_dicts(conn.execute("SELECT * FROM cron_jobs WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        cron_path = Path(account["base_path"]) / ".runtime" / "stack" / "cron"
        cron_path.parent.mkdir(parents=True, exist_ok=True)
        cron_path.write_text(render_crontab(row_to_dict(account), cron_jobs), encoding="utf-8")
        artifact = self.write_simulated_json(account, "cron.json", {"mode": "simulate", "jobs": cron_jobs, "crontab_path": str(cron_path)})
        return {"mode": "simulate", "synced": True, "account_id": account_id, "jobs_count": len(cron_jobs), "artifact_path": artifact, "crontab_path": str(cron_path)}

    def sync_pg_databases(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        databases = rows_to_dicts(conn.execute("SELECT * FROM pg_databases WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        users = rows_to_dicts(conn.execute("SELECT id, account_id, username, created_at FROM pg_users WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        grants = rows_to_dicts(
            conn.execute(
                """
                SELECT pg.*, d.name AS database_name, pu.username
                FROM pg_grants pg
                JOIN pg_databases d ON d.id = pg.database_id
                JOIN pg_users pu ON pu.id = pg.user_id
                WHERE d.account_id = ?
                ORDER BY d.name, pu.username
                """,
                (account_id,),
            ).fetchall()
        )
        artifact = self.write_simulated_json(
            account,
            "postgresql.json",
            {"mode": "simulate", "databases": databases, "users": users, "grants": grants},
        )
        return {
            "mode": "simulate",
            "synced": True,
            "account_id": account_id,
            "databases_count": len(databases),
            "users_count": len(users),
            "grants_count": len(grants),
            "artifact_path": artifact,
        }

    def install_custom_ssl(self, conn, job):
        payload = self.job_payload(job)
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (job["target_id"],)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        cert_dir = Path(account["base_path"]) / "ssl" / website["domain"]
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_path = cert_dir / "custom.crt"
        key_path = cert_dir / "custom.key"
        cert_path.write_text(payload.get("crt", ""), encoding="utf-8")
        key_path.write_text(payload.get("key", ""), encoding="utf-8")
        conn.execute("UPDATE websites SET ssl_status = 'custom' WHERE id = ?", (website["id"],))
        artifact = self.write_simulated_json(
            account,
            "ssl/{}-custom.json".format(website["domain"]),
            {"mode": "simulate", "domain": website["domain"], "status": "custom", "cert_path": str(cert_path), "key_path": str(key_path)},
        )
        return {"mode": "simulate", "installed": True, "website_id": website["id"], "ssl_status": "custom", "artifact_path": artifact}

    def delete_website(self, conn, job):
        payload = self.job_payload(job)
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        summary = self.provision_hosting_account(conn, account["id"])
        artifact = self.write_simulated_json(
            account,
            "deleted-websites/{}.json".format(payload.get("domain") or payload.get("removed_website_id") or "unknown"),
            {
                "mode": "simulate",
                "account_id": account["id"],
                "removed_website_id": payload.get("removed_website_id"),
                "domain": payload.get("domain"),
                "stack_status": summary.get("status"),
            },
        )
        return {
            "mode": "simulate",
            "deleted": True,
            "account_id": account["id"],
            "removed_website_id": payload.get("removed_website_id"),
            "domain": payload.get("domain"),
            "artifact_path": artifact,
            "stack_status": summary.get("status"),
        }

    def provision_hosting_account(self, conn, account_id, touched_website_id=None):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        plan = conn.execute("SELECT * FROM plans WHERE id = ?", (account["plan_id"],)).fetchone()
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (account["node_id"],)).fetchone()
        websites = conn.execute("SELECT * FROM websites WHERE account_id = ? ORDER BY id", (account_id,)).fetchall()
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        paths = ensure_account_layout(row_to_dict(account), row_to_dict(plan), row_to_dict(node), rows_to_dicts(websites), runtime)
        cron_jobs = rows_to_dicts(conn.execute("SELECT * FROM cron_jobs WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        (paths["stack"] / "cron").write_text(render_crontab(row_to_dict(account), cron_jobs), encoding="utf-8")
        apply_result = self.apply_stack(paths["compose"], account["username"])
        

        services_json = json.dumps(STACK_SERVICES)
        runtime_json = json.dumps(runtime)
        conn.execute(
            """
            INSERT INTO account_stacks(account_id, compose_path, mode, status, services_json, runtime_json, generated_at, last_applied_at, last_error)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL)
            ON CONFLICT(account_id) DO UPDATE SET
              compose_path = excluded.compose_path,
              mode = excluded.mode,
              status = excluded.status,
              services_json = excluded.services_json,
              runtime_json = excluded.runtime_json,
              generated_at = CURRENT_TIMESTAMP,
              last_applied_at = CURRENT_TIMESTAMP,
              last_error = NULL
            """,
            (account_id, str(paths["compose"]), self.config.agent_mode, apply_result["status"], services_json, runtime_json),
        )
        if account["status"] == "provisioning":
            conn.execute("UPDATE hosting_accounts SET status = 'active' WHERE id = ?", (account_id,))
        summary = stack_summary(paths)
        summary.update(apply_result)
        summary["runtime"] = runtime
        if touched_website_id:
            summary["website_id"] = touched_website_id
        return summary

    def apply_stack(self, compose_path, username=None):
        if self.config.agent_mode == "simulate":
            state_path = Path(compose_path).with_suffix(".agent-state.json")
            state = {
                "mode": "simulate",
                "status": "generated",
                "compose_path": str(compose_path),
                "services": STACK_SERVICES,
                "updated_at": int(time.time()),
            }
            state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
            return {"status": "generated", "mode": "simulate", "state_path": str(state_path)}
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if not docker:
                raise AgentError("docker_not_found")
            result = subprocess.run(
                [docker, "compose", "-f", str(compose_path), "up", "-d", "--remove-orphans", "--force-recreate"],
                check=False,
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode != 0:
                raise AgentError(result.stderr.strip() or result.stdout.strip() or "docker_compose_failed")
            if username:
                # No post‑compose actions needed – custom Docker image already includes required PHP binaries
                pass
            return {"status": "applied", "mode": "docker", "output": result.stdout.strip()}
        raise AgentError("unknown_agent_mode: {}".format(self.config.agent_mode))

    def compose_down(self, compose_path):
        docker = shutil.which("docker")
        if not docker:
            raise AgentError("docker_not_found")
        result = subprocess.run(
            [docker, "compose", "-f", str(compose_path), "down", "--remove-orphans"],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            raise AgentError(result.stderr.strip() or result.stdout.strip() or "docker_compose_down_failed")
        return {"compose_path": str(compose_path), "status": "stopped", "output": result.stdout.strip()}

    def install_wordpress(self, conn, job):
        payload = json.loads(job["payload"]) if isinstance(job["payload"], str) else job["payload"]
        install_id = job["target_id"]
        install = conn.execute("SELECT * FROM wordpress_installs WHERE id = ?", (install_id,)).fetchone()
        if not install:
            raise AgentError("wordpress_install_not_found")
        
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (install["website_id"],)).fetchone()
        if not website:
            raise AgentError("website_not_found")
            
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")

        from .installers import INSTALLERS
        try:
            INSTALLERS["wordpress"].install(conn, website, account, payload, install_id)
        except Exception as exc:
            if str(exc) == "document_root_not_empty":
                conn.execute(
                    "UPDATE wordpress_installs SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (install_id,),
                )
                raise AgentError("document_root_not_empty")
            raise exc

        return {
            "install_id": install_id,
            "website_id": install["website_id"],
            "status": "installed",
            "document_root": str(website["document_root"]),
            "site_title": payload.get("site_title"),
        }

    def install_script(self, conn, job):
        payload = json.loads(job["payload"]) if isinstance(job["payload"], str) else job["payload"]
        script_id = payload.get("script_id")
        install_id = job["target_id"]
        
        install = conn.execute("SELECT * FROM script_installs WHERE id = ?", (install_id,)).fetchone()
        if not install:
            raise AgentError("script_install_not_found")
            
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (install["website_id"],)).fetchone()
        if not website:
            raise AgentError("website_not_found")
            
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
            
        from .installers import INSTALLERS
        installer = INSTALLERS.get(script_id)
        if not installer:
            raise AgentError("unsupported_script: {}".format(script_id))
            
        try:
            installer.verify_empty_root(conn, website, bool(payload.get("allow_overwrite")))
        except Exception as exc:
            if str(exc) == "document_root_not_empty":
                conn.execute(
                    "UPDATE script_installs SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (install_id,),
                )
                raise AgentError("document_root_not_empty")
            raise exc

        # Auto-create database if not exists
        db_name = f"{account['username']}_{script_id}_{install['website_id']}"
        db_user = f"{account['username']}_{script_id}"
        
        # Check if database already exists, if not, create it
        existing_db = conn.execute("SELECT id FROM databases WHERE name = ?", (db_name,)).fetchone()
        if existing_db:
            database_id = existing_db["id"]
        else:
            cur_db = conn.execute(
                "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                (account["id"], db_name, db_user, "active"),
            )
            database_id = cur_db.lastrowid
            # Log and trigger job
            from .db import create_job
            create_job(conn, "create_database", "database", database_id, {"name": db_name})
            
            # Sync database id in install record
            conn.execute(
                "UPDATE script_installs SET database_id = ? WHERE id = ?",
                (database_id, install_id)
            )

        payload["database_name"] = db_name
        payload["database_user"] = db_user
        payload["database_password"] = "dev-db-password-change-me"
        payload["database_host"] = "db"

        # Run script installation
        try:
            installer.install(conn, website, account, payload, install_id)
        except Exception as exc:
            conn.execute(
                "UPDATE script_installs SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (install_id,),
            )
            raise exc

        conn.execute(
            "UPDATE script_installs SET status = 'installed', installed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (install_id,)
        )
        
        return {
            "install_id": install_id,
            "website_id": install["website_id"],
            "status": "installed",
            "document_root": str(website["document_root"]),
            "site_title": payload.get("site_title"),
        }

    def mangopanel_placeholder_index(self, document_root):
        index_php = document_root / "index.php"
        if not index_php.exists():
            return None
        try:
            if index_php.read_text(encoding="utf-8").startswith(MANGOPANEL_PLACEHOLDER_PREFIX):
                return index_php
        except UnicodeDecodeError:
            return None
        return None

    def manual_backup(self, conn, backup_id):
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise AgentError("backup_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (backup["account_id"],)).fetchone()
        plan = conn.execute("SELECT * FROM plans WHERE id = ?", (account["plan_id"],)).fetchone()
        
        base_path = Path(account["base_path"])
        backup_dir = base_path / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        usage = path_usage(base_path)
        if usage["bytes"] > int(plan["storage_mb"]) * 1024 * 1024:
            conn.execute("UPDATE backups SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?", (backup_id,))
            raise AgentError("storage_quota_exceeded")
        if usage["inodes"] > int(plan["inode_limit"]):
            conn.execute("UPDATE backups SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?", (backup_id,))
            raise AgentError("inode_quota_exceeded")
            
        artifact_path = backup_dir / f"backup-{backup_id}.tar.gz"
        
        # Create tar archive
        with tarfile.open(artifact_path, "w:gz") as tar:
            # 1. Add domains/ directory
            domains_dir = base_path / "domains"
            if domains_dir.exists():
                tar.add(domains_dir, arcname="domains")
                
            # 2. Add simulated .sql dumps for each database
            databases = conn.execute("SELECT * FROM databases WHERE account_id = ?", (account["id"],)).fetchall()
            if databases:
                temp_db_dir = backup_dir / f"temp_db_dumps_{backup_id}"
                temp_db_dir.mkdir(exist_ok=True)
                try:
                    for db in databases:
                        db_name = db["name"]
                        dump_file = temp_db_dir / f"{db_name}.sql"
                        dump_content = f"-- MangoPanel Simulated MySQL Dump\n-- Database: {db_name}\n-- Generated for backup #{backup_id}\n\nCREATE TABLE IF NOT EXISTS `example_table` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n  `data` varchar(255) DEFAULT NULL,\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
                        dump_file.write_text(dump_content, encoding="utf-8")
                        tar.add(dump_file, arcname=f"databases/{db_name}.sql")
                finally:
                    # Clean up temporary DB dumps
                    shutil.rmtree(temp_db_dir, ignore_errors=True)

        self.prune_expired_backups(conn, account["id"], int(plan["backup_retention_days"]))
        
        conn.execute(
            "UPDATE backups SET status = 'completed', artifact_path = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (str(artifact_path), backup_id),
        )
        return {"backup_id": backup_id, "artifact_path": str(artifact_path), "status": "completed"}

    def restore_backup(self, conn, backup_id):
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise AgentError("backup_not_found")
        if backup["status"] != "completed":
            raise AgentError("backup_not_completed")
            
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (backup["account_id"],)).fetchone()
        artifact_path = Path(backup["artifact_path"])
        
        if not artifact_path.exists():
            raise AgentError("backup_artifact_missing")
            
        base_path = Path(account["base_path"])
        domains_dir = base_path / "domains"
        
        # Extract archive
        # In a real environment, this might involve careful handling, 
        # clearing old domains, and importing databases using mysql client.
        try:
            with tarfile.open(artifact_path, "r:gz") as tar:
                # We'll just extract over the existing directories
                tar.extractall(path=base_path)
                
                # Check for database dumps to log simulation
                db_members = [m for m in tar.getmembers() if m.name.startswith("databases/")]
                for db_member in db_members:
                    # Simulated import log
                    pass
        except Exception as e:
            raise AgentError(f"restore_failed: {str(e)}")
            
        return {"backup_id": backup_id, "restored": True}

    def update_website_php(self, conn, website_id):
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
            
        # Re-provision account to update config
        summary = self.provision_hosting_account(conn, account["id"], touched_website_id=website_id)
        
        php_ini_dict = json.loads(website["php_ini"] if "php_ini" in website.keys() and website["php_ini"] else "{}")
        ini_content = ""
        for key, val in php_ini_dict.items():
            ini_content += f"{key} = {val}\n"
            
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                if ini_content:
                    script = f"""
                    cat << 'EOF' > /var/www/vhosts/{website['domain']}/{website['document_root']}/.user.ini
{ini_content}EOF
                    chown www-data:www-data /var/www/vhosts/{website['domain']}/{website['document_root']}/.user.ini
                    """
                    subprocess.run(
                        [docker, "exec", "-i", f"mp-{account['username']}-web", "bash", "-c", script],
                        check=False
                    )
                else:
                    subprocess.run(
                        [docker, "exec", f"mp-{account['username']}-web", "rm", "-f", f"/var/www/vhosts/{website['domain']}/{website['document_root']}/.user.ini"],
                        check=False
                    )

                subprocess.run(
                    [docker, "exec", f"mp-{account['username']}-web", "/usr/local/lsws/bin/lswsctrl", "restart"],
                    check=False
                )
            
        summary["php_version"] = website["php_version"]
        return summary

    def purge_cache(self, conn, job):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
            
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                subprocess.run(
                    [docker, "exec", f"mp-{account['username']}-web", "sh", "-c", "rm -rf /usr/local/lsws/cachedata/*"],
                    check=False
                )
                
        return {"account_id": account["id"], "purged": True}

    def prune_expired_backups(self, conn, account_id, retention_days):
        rows = conn.execute(
            """
            SELECT id, artifact_path FROM backups
            WHERE account_id = ?
              AND status = 'completed'
              AND completed_at IS NOT NULL
              AND completed_at < datetime('now', ?)
            """,
            (account_id, "-{} days".format(retention_days)),
        ).fetchall()
        for row in rows:
            artifact_path = row["artifact_path"]
            if artifact_path:
                artifact = Path(artifact_path)
                if artifact.exists() and artifact.is_file():
                    artifact.unlink()
            conn.execute("UPDATE backups SET status = 'expired' WHERE id = ?", (row["id"],))

    def restart_service(self, conn, job):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        service_name = self.job_payload(job).get("service")
        
        stack = conn.execute("SELECT compose_path FROM account_stacks WHERE account_id = ?", (account["id"],)).fetchone()
        if not stack:
            raise AgentError("stack_not_found")
            
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                result = subprocess.run(
                    [docker, "compose", "-f", stack["compose_path"], "restart", service_name],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode != 0:
                    raise AgentError(result.stderr.strip() or "docker_restart_failed")
                    
        return {"service": service_name, "restarted": True}

    def fix_file_ownership(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
            
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                # Assuming www-data is used internally in the openlitespeed container
                subprocess.run(
                    [docker, "exec", f"mp-{account['username']}-web", "chown", "-R", "www-data:www-data", "/var/www/vhosts"],
                    check=False
                )
                
        return {"fixed": True, "account_id": account["id"]}

    def sync_ip_rules(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        
        rules = conn.execute("SELECT * FROM ip_rules WHERE account_id = ?", (account_id,)).fetchall()
        
        htaccess_snippet = "# BEGIN MangoPanel IP Rules\n"
        if rules:
            htaccess_snippet += "Order Allow,Deny\n"
            for rule in rules:
                directive = "Allow" if rule["type"] == "allow" else "Deny"
                htaccess_snippet += f"{directive} from {rule['ip']}\n"
            # Always allow everything else if we are just blocking, but if there's only allows, it defaults to deny.
            # Actually, standard way is just append Deny from X, and Allow from Y. 
            # But let's keep it simple: 
            htaccess_snippet += "Allow from all\n"
        htaccess_snippet += "# END MangoPanel IP Rules\n"
        
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                # We need to insert this snippet into /var/www/vhosts/.htaccess
                # We'll use a bash script to replace or append the block.
                script = f"""
                touch /var/www/vhosts/.htaccess
                chown www-data:www-data /var/www/vhosts/.htaccess
                sed -i '/# BEGIN MangoPanel IP Rules/,/# END MangoPanel IP Rules/d' /var/www/vhosts/.htaccess
                echo "{htaccess_snippet}" >> /var/www/vhosts/.htaccess
                """
                subprocess.run(
                    [docker, "exec", "-i", f"mp-{account['username']}-web", "bash", "-c", script],
                    check=False
                )
                
        return {"synced": True, "account_id": account["id"], "rules_count": len(rules)}

    def sync_website_index(self, conn, website_id):
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
            
        index_enabled = website["index_enabled"] if "index_enabled" in website.keys() and website["index_enabled"] is not None else 0
        directive = "Options +Indexes" if index_enabled else "Options -Indexes"
        
        htaccess_snippet = "# BEGIN MangoPanel Index Rules\n"
        htaccess_snippet += f"{directive}\n"
        htaccess_snippet += "# END MangoPanel Index Rules\n"
        
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                script = f"""
                touch /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                chown www-data:www-data /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                sed -i '/# BEGIN MangoPanel Index Rules/,/# END MangoPanel Index Rules/d' /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                echo "{htaccess_snippet}" >> /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                """
                subprocess.run(
                    [docker, "exec", "-i", f"mp-{account['username']}-web", "bash", "-c", script],
                    check=False
                )
        return {"synced": True, "website_id": website_id, "index_enabled": index_enabled}

    def sync_protected_directories(self, conn, account_id, payload):
        if isinstance(payload, str):
            payload = json.loads(payload) if payload else {}
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
            
        path = payload.get("path")
        remove = payload.get("remove", False)
        username = payload.get("username", "")
        password = payload.get("password", "")
        
        if not path:
            return {"synced": False, "error": "No path provided"}
            
        # Ensure path does not contain ..
        if ".." in path:
            return {"synced": False, "error": "Invalid path"}
            
        full_path = f"/var/www/vhosts{path}"
        
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                container = f"mp-{account['username']}-web"
                if remove:
                    script = f"""
                    rm -f {full_path}/.htpasswd
                    if [ -f {full_path}/.htaccess ]; then
                        sed -i '/# BEGIN MangoPanel Auth/,/# END MangoPanel Auth/d' {full_path}/.htaccess
                    fi
                    """
                else:
                    auth_name = f"Protected Area {path}"
                    htaccess_snippet = f"""# BEGIN MangoPanel Auth
AuthType Basic
AuthName "{auth_name}"
AuthUserFile {full_path}/.htpasswd
Require valid-user
# END MangoPanel Auth
"""
                    script = f"""
                    mkdir -p {full_path}
                    # apt-get install -y apache2-utils should be in the container, or use pure-pw, or openssl
                    # Alpine might use `htpasswd` from `apache2-utils`
                    # If htpasswd is not found, we use openssl
                    htpasswd -bc {full_path}/.htpasswd "{username}" "{password}" || echo "{username}:$(openssl passwd -crypt '{password}')" > {full_path}/.htpasswd
                    
                    touch {full_path}/.htaccess
                    sed -i '/# BEGIN MangoPanel Auth/,/# END MangoPanel Auth/d' {full_path}/.htaccess
                    echo "{htaccess_snippet}" >> {full_path}/.htaccess
                    chown -R www-data:www-data {full_path}/.htpasswd {full_path}/.htaccess
                    """
                subprocess.run(
                    [docker, "exec", "-i", container, "bash", "-c", script],
                    check=False
                )
        return {"synced": True, "path": path, "removed": remove}

    def sync_redirects(self, conn, website_id):
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        
        redirects = conn.execute("SELECT * FROM redirects WHERE website_id = ?", (website_id,)).fetchall()
        
        htaccess_snippet = "# BEGIN MangoPanel Redirects\n"
        htaccess_snippet += "RewriteEngine On\n"
        for r in redirects:
            # Handle exact vs wildcard match types
            path_pattern = r["source_path"]
            if r["match_type"] == "wildcard":
                path_pattern = path_pattern.rstrip("/") + "/(.*)"
                target = r["target_url"].rstrip("/") + "/$1"
            else:
                path_pattern = f"^{path_pattern.lstrip('/')}$"
                target = r["target_url"]
                
            htaccess_snippet += f"RewriteRule {path_pattern} {target} [R={r['type']},L]\n"
        htaccess_snippet += "# END MangoPanel Redirects\n"
        
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                container = f"mp-{account['username']}-web"
                script = f"""
                touch /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                chown www-data:www-data /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                sed -i '/# BEGIN MangoPanel Redirects/,/# END MangoPanel Redirects/d' /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                echo "{htaccess_snippet}" >> /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                """
                subprocess.run(
                    [docker, "exec", "-i", container, "bash", "-c", script],
                    check=False
                )
        return {"synced": True, "website_id": website_id, "redirects_count": len(redirects)}

    def sync_website_modsec(self, conn, website_id):
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        
        modsec_enabled = website["modsec_enabled"] if "modsec_enabled" in website.keys() and website["modsec_enabled"] is not None else 1
        directive = "SecRuleEngine On" if modsec_enabled else "SecRuleEngine Off"
        
        htaccess_snippet = "# BEGIN MangoPanel ModSec\n"
        htaccess_snippet += f"<IfModule mod_security2.c>\n"
        htaccess_snippet += f"    {directive}\n"
        htaccess_snippet += f"</IfModule>\n"
        htaccess_snippet += "# END MangoPanel ModSec\n"
        
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                container = f"mp-{account['username']}-web"
                script = f"""
                touch /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                chown www-data:www-data /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                sed -i '/# BEGIN MangoPanel ModSec/,/# END MangoPanel ModSec/d' /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                echo "{htaccess_snippet}" >> /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess
                """
                subprocess.run(
                    [docker, "exec", "-i", container, "bash", "-c", script],
                    check=False
                )
        return {"synced": True, "website_id": website_id, "modsec_enabled": modsec_enabled}

    def sync_ftp_accounts(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        
        # We need the runtime for the default sftp_password
        runtime = account_runtime(conn, account_id)
        
        ftp_accounts = conn.execute("SELECT * FROM ftp_accounts WHERE account_id = ?", (account_id,)).fetchall()
        
        lines = []
        # Default user (uid 1001)
        lines.append(f"{account['username']}:{runtime.get('sftp_password', 'dev-sftp-password')}:1001")
        
        # Additional users (uid 1001 as well, so they map to the same base permissions? No, wait:
        # atmoz/sftp accepts: USER:PASS:UID:GID:DIR
        # If we use UID 1001 (which is mapped to the host directory owner), they all write as the same user.
        # But we can restrict their DIR. DIR is relative to /home/USER (wait, atmoz/sftp chroots to /home/USERNAME).
        # Actually, if we just give them USER:PASS:1001:1001, atmoz will create them.
        for fa in ftp_accounts:
            # We can map DIR relative to their home. 
            # In stack.py we mapped `- {base_path}:/home/{username}`
            # For additional users, we can name them as `account['username']_ftpuser`
            # And DIR can be set to their specific directory if we use the format:
            # user:pass:1001:1001:dir
            lines.append(f"{fa['username']}:{fa['password']}:1001:1001:{fa['path']}")
            
        sftp_conf = Path(account["base_path"]) / ".runtime" / "stack" / "sftp_users.conf"
        with open(sftp_conf, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
            
        return {"synced": True, "account_id": account_id, "count": len(ftp_accounts)}

    def kill_all_processes(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
            
        stack = conn.execute("SELECT compose_path FROM account_stacks WHERE account_id = ?", (account["id"],)).fetchone()
        if not stack:
            raise AgentError("stack_not_found")
            
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                result = subprocess.run(
                    [docker, "compose", "-f", stack["compose_path"], "restart"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode != 0:
                    raise AgentError(result.stderr.strip() or "docker_reboot_failed")
                    
        return {"rebooted": True}


def run_agent_once(config=None):
    return Agent(config).run_once()


def run_agent_all(config=None, limit=25):
    return Agent(config).run_all(limit=limit)


def path_usage(root):
    total_bytes = 0
    inodes = 0
    if not root.exists():
        return {"bytes": 0, "inodes": 0}
    for path in root.rglob("*"):
        try:
            stat = path.stat()
        except OSError:
            continue
        inodes += 1
        if path.is_file():
            total_bytes += stat.st_size
    return {"bytes": total_bytes, "inodes": inodes}
