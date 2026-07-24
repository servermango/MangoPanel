import json
import calendar
import re
import pwd
import shutil
import subprocess
import time
import tarfile
import os
import shlex
from datetime import datetime, timedelta

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
from .providers import (
    ACME_PROVIDER_LOCAL,
    DNS_PROVIDER_CLOUDFLARE,
    DNS_PROVIDER_LOCAL,
    DNS_PROVIDER_LOCAL_POWERDNS,
    MAIL_EDGE_PROVIDER_SHARED,
    ACMECertificateIntent,
    CloudflareDNSProvider,
    DNSProviderError,
    DNSRecordIntent,
    DNSZoneIntent,
    LocalACMEProvider,
    LocalDNSProvider,
    PowerDNSProvider,
    MailDomainRouteIntent,
    MailboxRouteIntent,
    SharedMailEdgeProvider,
)
from .security import decrypt_secret
from .stack import STACK_SERVICES, build_account_runtime, container_path, ensure_account_layout, render_crontab, stack_summary


class AgentError(Exception):
    pass


MANGOPANEL_PLACEHOLDER_PREFIX = "<?php\nheader('Content-Type: text/plain');\necho \"MangoPanel dev site:"


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg"}
IMAGE_OPTIMIZE_FORMAT = "WEBP"
CRON_SPECIAL_SCHEDULES = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}


def _parse_cron_field(field, minimum, maximum, *, day_of_week=False):
    text = str(field).strip()
    if not text:
        raise AgentError("invalid_cron_schedule")
    values = set()
    wildcard = False
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise AgentError("invalid_cron_schedule")
        step = None
        if "/" in chunk:
            base, raw_step = chunk.split("/", 1)
            if not raw_step.isdigit():
                raise AgentError("invalid_cron_schedule")
            step = int(raw_step)
            if step <= 0:
                raise AgentError("invalid_cron_schedule")
        else:
            base = chunk
        if base == "*":
            start = minimum
            end = maximum
            wildcard = True
        elif "-" in base:
            start_text, end_text = base.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise AgentError("invalid_cron_schedule")
            start = int(start_text)
            end = int(end_text)
        else:
            if not base.isdigit():
                raise AgentError("invalid_cron_schedule")
            start = end = int(base)
        if start < minimum or end > maximum or start > end:
            raise AgentError("invalid_cron_schedule")
        for value in range(start, end + 1, step or 1):
            if day_of_week and value == 7:
                value = 0
            values.add(value)
    if day_of_week and 0 in values:
        values.add(7)
    return {"values": values, "wildcard": wildcard}


def parse_cron_schedule(schedule):
    text = str(schedule or "").strip()
    if not text:
        raise AgentError("invalid_cron_schedule")
    lower = text.lower()
    if lower in CRON_SPECIAL_SCHEDULES:
        text = CRON_SPECIAL_SCHEDULES[lower]
    elif lower == "@reboot":
        return {"special": "@reboot", "original": text}
    parts = text.split()
    if len(parts) != 5:
        raise AgentError("invalid_cron_schedule")
    return {
        "special": None,
        "original": text,
        "minute": _parse_cron_field(parts[0], 0, 59),
        "hour": _parse_cron_field(parts[1], 0, 23),
        "dom": _parse_cron_field(parts[2], 1, 31),
        "month": _parse_cron_field(parts[3], 1, 12),
        "dow": _parse_cron_field(parts[4], 0, 7, day_of_week=True),
    }


def validate_cron_schedule(schedule):
    return parse_cron_schedule(schedule)["original"]


def cron_matches_schedule(parsed, moment):
    if parsed.get("special") == "@reboot":
        return False
    minute = moment.minute
    hour = moment.hour
    dom = moment.day
    month = moment.month
    dow = (moment.isoweekday()) % 7
    if minute not in parsed["minute"]["values"]:
        return False
    if hour not in parsed["hour"]["values"]:
        return False
    if month not in parsed["month"]["values"]:
        return False
    dom_match = dom in parsed["dom"]["values"]
    dow_match = dow in parsed["dow"]["values"]
    if parsed["dom"]["wildcard"] or parsed["dow"]["wildcard"]:
        if not dom_match or not dow_match:
            return False
    else:
        if not (dom_match or dow_match):
            return False
    return True


def cron_next_run_at(schedule, from_time=None):
    parsed = parse_cron_schedule(schedule)
    if parsed.get("special") == "@reboot":
        return None
    candidate = (from_time or datetime.utcnow()).replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = candidate + timedelta(days=366 * 4)
    while candidate <= limit:
        if cron_matches_schedule(parsed, candidate):
            return candidate.isoformat(timespec="seconds") + "Z"
        candidate += timedelta(minutes=1)
    return None


def cron_runtime_paths(account):
    base = Path(account["base_path"]) / ".runtime" / "cron"
    return {
        "base": base,
        "jobs": base / "jobs",
        "logs": base / "logs",
        "state": base / "state",
        "report": base / "report.json",
    }


def cron_container_base_path(account):
    return str(Path("/home") / account["username"])


def cron_container_to_host_path(account, container_path_text):
    if not container_path_text:
        return None
    container_root = cron_container_base_path(account).rstrip("/")
    text = str(container_path_text)
    if text.startswith(container_root + "/"):
        relative = text[len(container_root) + 1 :]
        return str(Path(account["base_path"]) / relative)
    if text == container_root:
        return account["base_path"]
    return text


def cron_runner_paths(account, cron_job):
    runtime = cron_runtime_paths(account)
    job_id = int(cron_job["id"])
    script_path = runtime["jobs"] / f"job-{job_id}.sh"
    log_path = runtime["logs"] / f"job-{job_id}.log"
    state_path = runtime["state"] / f"job-{job_id}.state"
    container_script = container_path(account, str(script_path))
    return {
        "script_path": script_path,
        "runner_command": container_script,
        "log_path": log_path,
        "state_path": state_path,
        "container_base": cron_container_base_path(account),
    }


def read_key_value_file(path):
    data = {}
    file_path = Path(path)
    if not file_path.exists():
        return data
    for line in file_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def read_cron_runtime_state(account, cron_job):
    cron_job = dict(cron_job)
    paths = cron_runner_paths(account, cron_job)
    state = read_key_value_file(paths["state_path"])
    log_path = Path(cron_container_to_host_path(account, state.get("log_path")) or paths["log_path"])
    last_output = ""
    if log_path.exists() and log_path.is_file():
        last_output = log_path.read_text(encoding="utf-8", errors="replace")[-4096:]
    merged = {
        "runner_path": str(paths["script_path"]),
        "runner_command": paths["runner_command"],
        "log_path": str(log_path),
        "state_path": str(paths["state_path"]),
        "last_output": last_output,
    }
    if state.get("last_run_at"):
        merged["last_run_at"] = state["last_run_at"]
    if state.get("finished_at"):
        merged["finished_at"] = state["finished_at"]
    if state.get("last_exit_code") is not None and state.get("last_exit_code") != "":
        try:
            merged["last_exit_code"] = int(state["last_exit_code"])
        except ValueError:
            merged["last_exit_code"] = state["last_exit_code"]
    return merged


def cron_wrapper_script(account, cron_job):
    paths = cron_runner_paths(account, cron_job)
    job_id = int(cron_job["id"])
    account_id = int(account["id"])
    username = account["username"]
    base_path = paths["container_base"]
    command = str(cron_job["command"]).replace("\n", " ").strip()
    schedule = str(cron_job["schedule"]).replace("\n", " ").strip()
    return "\n".join(
        [
            "#!/bin/sh",
            "set -u",
            f"JOB_ID={job_id}",
            f"ACCOUNT_ID={account_id}",
            f"USERNAME={shlex.quote(username)}",
            f"BASE_PATH={shlex.quote(base_path)}",
            f"CRON_COMMAND={shlex.quote(command)}",
            f"SCHEDULE={shlex.quote(schedule)}",
            'CRON_ROOT="$BASE_PATH/.runtime/cron"',
            'LOG_PATH="$CRON_ROOT/logs/job-$JOB_ID.log"',
            'STATE_PATH="$CRON_ROOT/state/job-$JOB_ID.state"',
            'mkdir -p "$CRON_ROOT/logs" "$CRON_ROOT/state"',
            'cd "$BASE_PATH" || exit 1',
            'STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"',
            ': > "$LOG_PATH"',
            'if /bin/sh -lc "$CRON_COMMAND" >>"$LOG_PATH" 2>&1; then',
            "  EXIT_CODE=0",
            "else",
            "  EXIT_CODE=$?",
            "fi",
            'FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"',
            'printf "job_id=%s\\naccount_id=%s\\nusername=%s\\nschedule=%s\\ncommand=%s\\nstarted_at=%s\\nlast_run_at=%s\\nfinished_at=%s\\nlast_exit_code=%s\\nlog_path=%s\\n" "$JOB_ID" "$ACCOUNT_ID" "$USERNAME" "$SCHEDULE" "$CRON_COMMAND" "$STARTED_AT" "$FINISHED_AT" "$FINISHED_AT" "$EXIT_CODE" "$LOG_PATH" > "$STATE_PATH"',
            'exit "$EXIT_CODE"',
            "",
        ]
    )


def write_account_json(account, relative_path, payload):
    path = Path(account["base_path"]) / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def ensure_cron_runtime_artifacts(account, cron_jobs):
    runtime = cron_runtime_paths(account)
    runtime["jobs"].mkdir(parents=True, exist_ok=True)
    runtime["logs"].mkdir(parents=True, exist_ok=True)
    runtime["state"].mkdir(parents=True, exist_ok=True)
    managed_jobs = []
    for job in cron_jobs:
        job = dict(job)
        paths = cron_runner_paths(account, job)
        script_text = cron_wrapper_script(account, job)
        paths["script_path"].write_text(script_text, encoding="utf-8")
        paths["script_path"].chmod(0o755)
        job.update(
            {
                "runner_command": paths["runner_command"],
                "runner_path": str(paths["script_path"]),
                "log_path": str(paths["log_path"]),
                "state_path": str(paths["state_path"]),
                "next_run_at": None if job["status"] != "enabled" else cron_next_run_at(job["schedule"]),
            }
        )
        state = read_key_value_file(paths["state_path"])
        if state.get("last_run_at"):
            job["last_run_at"] = state["last_run_at"]
        if state.get("last_exit_code") not in (None, ""):
            try:
                job["last_exit_code"] = int(state["last_exit_code"])
            except ValueError:
                job["last_exit_code"] = state["last_exit_code"]
        if paths["log_path"].exists():
            job["last_output"] = paths["log_path"].read_text(encoding="utf-8", errors="replace")[-4096:]
        managed_jobs.append(job)
    crontab_path = Path(account["base_path"]) / ".runtime" / "stack" / "cron"
    crontab_path.parent.mkdir(parents=True, exist_ok=True)
    crontab_path.write_text(render_crontab(account, managed_jobs), encoding="utf-8")
    return runtime, managed_jobs, crontab_path


def decorate_cron_jobs(account, cron_jobs):
    return [dict(job, **read_cron_runtime_state(account, job)) for job in cron_jobs]


def sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def git_runtime_dir(account):
    return Path(account["base_path"]) / ".runtime" / "git"


def git_metadata_path(account, deployment_id):
    return git_runtime_dir(account) / f"deployment-{deployment_id}.json"


def mysql_remote_runtime_dir(account):
    return Path(account["base_path"]) / ".runtime" / "mysql-remote"


def postgres_runtime_dir(account):
    return Path(account["base_path"]) / ".runtime" / "postgresql"


def image_runtime_dir(account):
    return Path(account["base_path"]) / ".runtime" / "images"


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
        job = conn.execute(
            """
            SELECT * FROM jobs
            WHERE status = 'queued'
              AND (not_before_at IS NULL OR not_before_at <= CURRENT_TIMESTAMP)
            ORDER BY id
            LIMIT 1
            """
        ).fetchone()
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
            is_dns_job = job["type"] in {"sync_dns_record", "sync_dns_zone"}
            attempts = int(job["attempts"] or 0)
            max_attempts = int(job["max_attempts"] if "max_attempts" in job.keys() and job["max_attempts"] is not None else 3)
            error_text = str(exc)
            retryable_dns_error = is_dns_job and not error_text.endswith("_not_found")
            if retryable_dns_error and attempts < max_attempts:
                delay_seconds = min(300, 30 * (2 ** max(0, attempts - 1)))
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = 'queued', result = ?, not_before_at = datetime('now', ?), updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        json.dumps({"error": error_text, "retry_scheduled": True, "retry_after_seconds": delay_seconds}),
                        "+{} seconds".format(delay_seconds),
                        job["id"],
                    ),
                )
                log_job_event(conn, job["id"], "Agent scheduled DNS retry", level="warning", metadata={"error": error_text, "retry_after_seconds": delay_seconds})
                return {"job_id": job["id"], "status": "queued", "retry_after_seconds": delay_seconds, "error": error_text}
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
            account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (database["account_id"],)).fetchone()
            sql = [f"CREATE DATABASE IF NOT EXISTS `{database['name']}`;"]
            if account:
                runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
                sql.append(f"GRANT ALL PRIVILEGES ON *.* TO {sql_literal(runtime['db_user'])}@'%';")
                sql.append("FLUSH PRIVILEGES;")
            self.execute_mariadb_sql(conn, database["account_id"], sql)
            return self.provision_hosting_account(conn, database["account_id"])
        if job_type == "create_mailbox":
            mailbox = conn.execute("SELECT * FROM mailboxes WHERE id = ?", (job["target_id"],)).fetchone()
            if not mailbox:
                raise AgentError("mailbox_not_found")
            return self.provision_hosting_account(conn, mailbox["account_id"])
        if job_type == "sync_mailboxes":
            return self.sync_mailboxes(conn, job["target_id"])
        if job_type == "sync_mail_policy":
            return self.sync_mailboxes(conn, job["target_id"])
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
        if job_type == "sync_website_analytics":
            return self.sync_website_analytics(conn, job["target_id"])
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
        if job_type == "reset_opcache":
            return self.reset_opcache(conn, job)
        if job_type == "flush_object_cache":
            return self.flush_object_cache(conn, job)
        if job_type == "create_cron_job":
            cron = conn.execute("SELECT * FROM cron_jobs WHERE id = ?", (job["target_id"],)).fetchone()
            if not cron:
                raise AgentError("cron_job_not_found")
            return self.sync_cron_jobs(conn, cron["account_id"])
        if job_type == "git_deploy":
            deployment = conn.execute("SELECT * FROM git_deployments WHERE id = ?", (job["target_id"],)).fetchone()
            if not deployment:
                raise AgentError("git_deployment_not_found")
            return self.deploy_git_repository(conn, deployment["id"])
        if job_type == "git_rollback":
            deployment = conn.execute("SELECT * FROM git_deployments WHERE id = ?", (job["target_id"],)).fetchone()
            if not deployment:
                raise AgentError("git_deployment_not_found")
            return self.rollback_git_repository(conn, deployment["id"])
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
            payload = self.job_payload(job)
            db_name = payload.get("name")
            account_id = payload.get("account_id")
            if db_name and account_id:
                self.execute_mariadb_sql(conn, account_id, [f"DROP DATABASE IF EXISTS `{db_name}`;"])
            return {"database_id": job["target_id"], "deleted": True}
        if job_type == "create_database_user":
            db_user = conn.execute("SELECT id, account_id, username FROM database_users WHERE id = ?", (job["target_id"],)).fetchone()
            if not db_user:
                raise AgentError("database_user_not_found")
            payload = self.job_payload(job)
            password = payload.get("password")
            if password:
                sql = [
                    f"CREATE USER IF NOT EXISTS {sql_literal(db_user['username'])}@'%' IDENTIFIED BY {sql_literal(password)};",
                    f"ALTER USER {sql_literal(db_user['username'])}@'%' IDENTIFIED BY {sql_literal(password)};",
                    "FLUSH PRIVILEGES;",
                ]
                self.execute_mariadb_sql(conn, db_user["account_id"], sql)
            return {"database_user_id": db_user["id"], "username": db_user["username"], "created": True}
        if job_type == "update_database_user":
            db_user = conn.execute("SELECT id, account_id, username, status FROM database_users WHERE id = ?", (job["target_id"],)).fetchone()
            if not db_user:
                raise AgentError("database_user_not_found")
            payload = self.job_payload(job)
            password = payload.get("password")
            sql = []
            if password:
                sql.append(f"ALTER USER {sql_literal(db_user['username'])}@'%' IDENTIFIED BY {sql_literal(password)};")
            if db_user["status"] == "suspended":
                sql.append(f"ALTER USER {sql_literal(db_user['username'])}@'%' ACCOUNT LOCK;")
            elif db_user["status"] == "active":
                sql.append(f"ALTER USER {sql_literal(db_user['username'])}@'%' ACCOUNT UNLOCK;")
            if sql:
                sql.append("FLUSH PRIVILEGES;")
                self.execute_mariadb_sql(conn, db_user["account_id"], sql)
            return {"database_user_id": db_user["id"], "username": db_user["username"], "status": db_user["status"], "synced": True}
        if job_type == "delete_database_user":
            payload = self.job_payload(job)
            username = payload.get("username")
            account_id = payload.get("account_id")
            if username and account_id:
                self.execute_mariadb_sql(conn, account_id, [f"DROP USER IF EXISTS {sql_literal(username)}@'%';", "FLUSH PRIVILEGES;"])
            return {"database_user_id": job["target_id"], "deleted": True}
        if job_type == "grant_database_user":
            grant = conn.execute("SELECT id, database_id, user_id, privileges FROM database_grants WHERE id = ?", (job["target_id"],)).fetchone()
            if not grant:
                raise AgentError("database_grant_not_found")
            database = conn.execute("SELECT account_id, name FROM databases WHERE id = ?", (grant["database_id"],)).fetchone()
            db_user = conn.execute("SELECT username FROM database_users WHERE id = ?", (grant["user_id"],)).fetchone()
            if database and db_user:
                priv = "ALL PRIVILEGES" if grant["privileges"] == "ALL" else grant["privileges"]
                sql = [
                    f"GRANT {priv} ON `{database['name']}`.* TO {sql_literal(db_user['username'])}@'%';",
                    "FLUSH PRIVILEGES;",
                ]
                self.execute_mariadb_sql(conn, database["account_id"], sql)
            return {"grant_id": grant["id"], "database_id": grant["database_id"], "user_id": grant["user_id"], "privileges": grant["privileges"], "granted": True}
        if job_type == "update_database_grant":
            grant = conn.execute("SELECT id, database_id, user_id, privileges, status FROM database_grants WHERE id = ?", (job["target_id"],)).fetchone()
            if not grant:
                raise AgentError("database_grant_not_found")
            database = conn.execute("SELECT account_id, name FROM databases WHERE id = ?", (grant["database_id"],)).fetchone()
            db_user = conn.execute("SELECT username FROM database_users WHERE id = ?", (grant["user_id"],)).fetchone()
            if database and db_user:
                priv = "ALL PRIVILEGES" if grant["privileges"] == "ALL" else grant["privileges"]
                sql = [
                    f"GRANT {priv} ON `{database['name']}`.* TO {sql_literal(db_user['username'])}@'%';",
                    "FLUSH PRIVILEGES;",
                ]
                self.execute_mariadb_sql(conn, database["account_id"], sql)
            return {"grant_id": grant["id"], "privileges": grant["privileges"], "status": grant["status"], "synced": True}
        if job_type == "revoke_database_user":
            payload = self.job_payload(job)
            db_id = payload.get("database_id")
            user_id = payload.get("user_id")
            account_id = payload.get("account_id")
            if db_id and user_id:
                database = conn.execute("SELECT account_id, name FROM databases WHERE id = ?", (db_id,)).fetchone()
                db_user = conn.execute("SELECT username FROM database_users WHERE id = ?", (user_id,)).fetchone()
                if database and db_user:
                    sql = [
                        f"REVOKE ALL PRIVILEGES ON `{database['name']}`.* FROM {sql_literal(db_user['username'])}@'%';",
                        "FLUSH PRIVILEGES;",
                    ]
                    self.execute_mariadb_sql(conn, database["account_id"] if database else account_id, sql)
            return {"grant_id": job["target_id"], "revoked": True}
        raise AgentError("unsupported_job_type: {}".format(job_type))

    def job_payload(self, job):
        payload = job["payload"] or {}
        if isinstance(payload, str):
            return json.loads(payload) if payload else {}
        return payload

    def account_identity(self, account):
        uid = getattr(os, "getuid", lambda: None)()
        gid = getattr(os, "getgid", lambda: None)()
        try:
            entry = pwd.getpwnam(account["username"])
            uid = entry.pw_uid
            gid = entry.pw_gid
        except Exception:
            pass
        return uid, gid

    def account_simulated_dir(self, account, *parts):
        path = Path(account["base_path"]) / ".runtime" / "simulated"
        for part in parts:
            path = path / str(part)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def account_runtime_dir(self, account, *parts):
        path = Path(account["base_path"]) / ".runtime"
        for part in parts:
            path = path / str(part)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def cache_report_path(self, account):
        return self.account_runtime_dir(account, "cache", "last_action.json")

    def php_binary_for_version(self, version):
        raw = str(version or "8.3").strip().replace(".", "")
        if raw not in {"82", "83", "84"}:
            raw = "83"
        return f"/usr/local/lsws/lsphp{raw}/bin/lsphp"

    def cache_scope_websites(self, conn, account, payload):
        website_id = payload.get("website_id")
        if website_id:
            website = conn.execute(
                "SELECT * FROM websites WHERE id = ? AND account_id = ?",
                (website_id, account["id"]),
            ).fetchone()
            if not website:
                raise AgentError("website_not_found")
            return [website]
        return conn.execute(
            "SELECT * FROM websites WHERE account_id = ? ORDER BY id",
            (account["id"],),
        ).fetchall()

    def write_cache_action_report(self, account, action, payload, websites, purged_paths):
        report = {
            "account_id": account["id"],
            "action": action,
            "scope": payload.get("scope", "all"),
            "website_id": payload.get("website_id"),
            "mode": self.config.agent_mode,
            "website_count": len(websites),
            "purged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "purged_paths": purged_paths,
        }
        report_path = self.cache_report_path(account)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return str(report_path)

    def clear_cache_directories(self, base_path, websites):
        purged_paths = []
        account_cache_dirs = [
            base_path / ".runtime" / "cache",
            base_path / ".runtime" / "cachedata",
        ]
        for cache_dir in account_cache_dirs:
            removed = self.clear_directory_contents(cache_dir)
            if removed:
                purged_paths.extend(removed)
            cache_dir.mkdir(parents=True, exist_ok=True)

        for website in websites:
            root = Path(website["document_root"]).resolve()
            website_cache_dirs = [
                root / "cache",
                root / ".cache",
                root / "tmp" / "cache",
                root / "wp-content" / "cache",
                root / "storage" / "framework" / "cache",
            ]
            for cache_dir in website_cache_dirs:
                try:
                    cache_dir.relative_to(base_path)
                except ValueError:
                    continue
                purged_paths.extend(self.clear_directory_contents(cache_dir))
        return purged_paths

    def reset_opcache_backend(self, account, websites):
        commands = []
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                for website in websites:
                    php_bin = self.php_binary_for_version(website.get("php_version"))
                    script = f"{php_bin} -d opcache.enable_cli=1 -r 'function_exists(\"opcache_reset\") ? opcache_reset() : false;'"
                    subprocess.run(
                        [docker, "exec", f"mp-{account['username']}-web", "sh", "-lc", script],
                        check=False,
                    )
                    commands.append({"php_binary": php_bin, "website_id": website["id"]})
        return commands

    def flush_object_cache_backend(self, account):
        result = {"backend": "redis", "flushed": True, "mode": "filesystem"}
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                exec_result = subprocess.run(
                    [docker, "exec", f"mp-{account['username']}-redis", "redis-cli", "FLUSHDB"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                result["mode"] = "redis"
                result["flushed"] = exec_result.returncode == 0
                if exec_result.returncode != 0:
                    raise AgentError(exec_result.stderr.strip() or exec_result.stdout.strip() or "redis_flush_failed")
        return result

    def account_relative_path(self, account, raw_path, require_subpath=False):
        base_path = Path(account["base_path"]).resolve()
        text = str(raw_path or "").strip()
        if not text:
            raise AgentError("path_required")
        candidate = (base_path / text.lstrip("/")).resolve()
        try:
            rel = candidate.relative_to(base_path)
        except ValueError as exc:
            raise AgentError("invalid_account_path") from exc
        relative = "" if str(rel) == "." else rel.as_posix()
        if require_subpath and not relative:
            raise AgentError("invalid_account_path")
        return candidate, relative

    def replace_managed_block(self, content, begin_marker, end_marker, block):
        pattern = re.compile(r"{}.*?{}\n?".format(re.escape(begin_marker), re.escape(end_marker)), re.S)
        if block:
            if pattern.search(content):
                updated = pattern.sub(block, content)
            else:
                stripped = content.rstrip()
                updated = block if not stripped else stripped + "\n\n" + block
            return updated.rstrip() + "\n"
        updated = pattern.sub("", content)
        stripped = updated.rstrip()
        return (stripped + "\n") if stripped else ""

    def is_preserved_config_file(self, path):
        name = path.name.lower()
        if name in {".htaccess", ".htpasswd", ".user.ini", ".env"}:
            return True
        if name in {"wp-config.php", "configuration.php", "config.php", "settings.php"}:
            return True
        if "config" in name or "configuration" in name or "settings" in name:
            return True
        if name.endswith(".ini") or name.endswith(".conf"):
            return True
        return False

    def apply_account_metadata(self, path, account, preserve_permissions=False):
        uid, gid = self.account_identity(account)
        try:
            if uid is not None and gid is not None and hasattr(os, "chown"):
                os.chown(path, uid, gid)
        except PermissionError as exc:
            raise AgentError("ownership_fix_failed") from exc
        except OSError as exc:
            raise AgentError("ownership_fix_failed") from exc

        if not preserve_permissions:
            path_obj = Path(path).resolve()
            base_path = Path(account["base_path"]).resolve()
            domains_path = base_path / "domains"
            is_domain_file = False
            try:
                is_domain_file = domains_path in path_obj.parents or path_obj == domains_path
            except Exception:
                pass

            if is_domain_file:
                if path_obj.is_dir():
                    mode = 0o777
                else:
                    st_mode = path_obj.stat().st_mode if path_obj.exists() else 0
                    mode = 0o777 if (st_mode & 0o111) else 0o666
            else:
                mode = 0o755 if path_obj.is_dir() else 0o644

            try:
                os.chmod(path, mode)
            except OSError as exc:
                raise AgentError("ownership_fix_failed") from exc

    def clear_directory_contents(self, directory):
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            return []
        removed = []
        for item in directory.iterdir():
            try:
                if item.is_symlink() or item.is_file():
                    item.unlink()
                    removed.append(str(item))
                elif item.is_dir():
                    shutil.rmtree(item)
                    removed.append(str(item))
            except FileNotFoundError:
                continue
        return removed

    def htpasswd_hash(self, password):
        try:
            import crypt
            method = getattr(crypt, "METHOD_SHA512", None)
            salt = crypt.mksalt(method) if method is not None else crypt.mksalt()
            hashed = crypt.crypt(password, salt)
            if hashed and not hashed.startswith("*"):
                return hashed
        except Exception:
            pass
        openssl = shutil.which("openssl")
        if openssl:
            result = subprocess.run(
                [openssl, "passwd", "-apr1", password],
                check=False,
                capture_output=True,
                text=True,
            )
            hashed = result.stdout.strip()
            if result.returncode == 0 and hashed:
                return hashed
        raise AgentError("password_hashing_unavailable")

    def hotlink_pattern(self, domain):
        escaped = re.escape(domain)
        return r"^https?://(?:[^/]+\.)?{}(?:/|$)".format(escaped)

    def write_simulated_json(self, account, name, payload):
        path = self.account_simulated_dir(account, name)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return str(path)

    def json_field(self, value, fallback=None):
        try:
            return json.loads(value) if value else (fallback if fallback is not None else {})
        except (TypeError, json.JSONDecodeError):
            return fallback if fallback is not None else {}

    def row_get(self, row, key, fallback=None):
        return row[key] if row is not None and key in row.keys() else fallback

    def dns_local_config(self, conn):
        provider = conn.execute("SELECT * FROM dns_providers WHERE key = ?", (DNS_PROVIDER_LOCAL_POWERDNS,)).fetchone()
        config = self.json_field(self.row_get(provider, "config_json"), {})
        config.setdefault("nameservers", ["ns1.mango.test", "ns2.mango.test"])
        return config

    def resolve_dns_provider(self, conn, domain):
        provider_key = self.row_get(domain, "dns_provider", None) or DNS_PROVIDER_LOCAL
        if provider_key == DNS_PROVIDER_LOCAL_POWERDNS:
            local_config = self.dns_local_config(conn)
            nameservers = local_config.get("nameservers") or ["ns1.mango.test", "ns2.mango.test"]
            if self.config.powerdns_api_url and self.config.powerdns_api_key:
                return (
                    PowerDNSProvider(
                        self.config.powerdns_api_url,
                        self.config.powerdns_api_key,
                        server_id=self.config.powerdns_server_id,
                        nameservers=nameservers,
                    ),
                    provider_key,
                    self.row_get(domain, "dns_provider_account_id"),
                    nameservers,
                )
            return LocalDNSProvider(), DNS_PROVIDER_LOCAL, self.row_get(domain, "dns_provider_account_id"), nameservers
        if provider_key == DNS_PROVIDER_CLOUDFLARE:
            account_id = self.row_get(domain, "dns_provider_account_id")
            if not account_id:
                raise AgentError("cloudflare_provider_account_missing")
            account = conn.execute(
                """
                SELECT a.*, c.encrypted_secret
                FROM dns_provider_accounts a
                LEFT JOIN dns_provider_credentials c ON c.provider_account_id = a.id
                WHERE a.id = ?
                """,
                (account_id,),
            ).fetchone()
            if not account:
                raise AgentError("cloudflare_provider_account_not_found")
            api_token = decrypt_secret(account["encrypted_secret"], self.config.jwt_secret)
            if not api_token:
                raise AgentError("cloudflare_provider_secret_missing")
            return (
                CloudflareDNSProvider(
                    api_token,
                    account_id=account["external_account_id"] or None,
                    api_base=self.config.cloudflare_api_base,
                ),
                DNS_PROVIDER_CLOUDFLARE,
                account_id,
                [],
            )
        return LocalDNSProvider(), DNS_PROVIDER_LOCAL, self.row_get(domain, "dns_provider_account_id"), ["ns1.local.mango.test", "ns2.local.mango.test"]

    def publish_dns_zone_state(self, conn, account, domain, records, zone_path):
        zone_intent = DNSZoneIntent(
            account_id=account["id"],
            domain_id=domain["id"],
            zone_name=domain["name"],
            records=[
                DNSRecordIntent(
                    name=record["name"],
                    type=record["type"],
                    value=record["value"],
                    ttl=record["ttl"],
                    priority=record["priority"],
                )
                for record in records
            ],
        )
        existing = conn.execute("SELECT * FROM dns_zones WHERE domain_id = ?", (domain["id"],)).fetchone()
        serial = int(existing["serial"]) + 1 if existing else 1
        previous_state = self.json_field(self.row_get(existing, "provider_state_json"), {})
        provider, provider_key, provider_account_id, default_nameservers = self.resolve_dns_provider(conn, domain)
        try:
            if isinstance(provider, LocalDNSProvider):
                provider_state = provider.publish_zone(zone_intent, artifact_path=str(zone_path), nameservers=default_nameservers, serial=serial)
                provider_key = provider.provider_name
            else:
                provider_state = provider.publish_zone(zone_intent, previous_state=previous_state)
        except DNSProviderError as exc:
            error_state = dict(previous_state or {})
            error_state.update(
                {
                    "provider": provider_key,
                    "provider_account_id": provider_account_id,
                    "status": "provider_failed",
                    "last_error": str(exc),
                    "failed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )
            conn.execute(
                """
                INSERT INTO dns_zones(
                  account_id, domain_id, zone_name, provider, status, serial,
                  nameservers_json, provider_state_json, provider_account_id,
                  provider_zone_id, dns_status, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(domain_id) DO UPDATE SET
                  provider = excluded.provider,
                  status = excluded.status,
                  serial = excluded.serial,
                  provider_state_json = excluded.provider_state_json,
                  provider_account_id = excluded.provider_account_id,
                  dns_status = excluded.dns_status,
                  updated_at = CURRENT_TIMESTAMP
                """
                ,
                (
                    account["id"],
                    domain["id"],
                    domain["name"],
                    provider_key,
                    "provider_failed",
                    serial,
                    json.dumps(default_nameservers),
                    json.dumps(error_state, sort_keys=True),
                    provider_account_id,
                    self.row_get(domain, "provider_zone_id"),
                    "provider_failed",
                ),
            )
            conn.execute(
                """
                UPDATE domains
                SET dns_status = ?, provider_state_json = ?, last_dns_sync_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                ("provider_failed", json.dumps(error_state, sort_keys=True), domain["id"]),
            )
            raise AgentError(str(exc)) from exc
        nameservers = provider_state.get("nameservers") or default_nameservers
        provider_zone_id = provider_state.get("provider_zone_id")
        zone_status = provider_state.get("status", "published")
        migration_state = self.json_field(self.row_get(domain, "dns_migration_state_json"), {})
        dns_status = zone_status
        if migration_state.get("status") == "pending_provider_sync":
            migration_state["status"] = "pending_nameserver"
            migration_state["published_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            migration_state["new_nameservers"] = nameservers
            provider_state["migration"] = migration_state
            dns_status = "pending_nameserver"
        conn.execute(
            """
            INSERT INTO dns_zones(
              account_id, domain_id, zone_name, provider, status, serial, nameservers_json,
              provider_state_json, provider_account_id, provider_zone_id, dns_status,
              last_synced_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(domain_id) DO UPDATE SET
              account_id = excluded.account_id,
              zone_name = excluded.zone_name,
              provider = excluded.provider,
              status = excluded.status,
              serial = excluded.serial,
              nameservers_json = excluded.nameservers_json,
              provider_state_json = excluded.provider_state_json,
              provider_account_id = excluded.provider_account_id,
              provider_zone_id = excluded.provider_zone_id,
              dns_status = excluded.dns_status,
              last_synced_at = CURRENT_TIMESTAMP,
              updated_at = CURRENT_TIMESTAMP
            """,
            (
                account["id"],
                domain["id"],
                domain["name"],
                provider_key,
                zone_status,
                int(provider_state.get("serial") or serial),
                json.dumps(nameservers),
                json.dumps(provider_state, sort_keys=True),
                provider_account_id,
                provider_zone_id,
                dns_status,
            ),
        )
        conn.execute(
            """
            UPDATE domains
            SET dns_provider = ?, dns_provider_account_id = ?, provider_zone_id = ?,
                nameservers_json = ?, dns_status = ?, last_dns_sync_at = CURRENT_TIMESTAMP,
                provider_state_json = ?
            WHERE id = ?
            """,
            (
                provider_key if provider_key != DNS_PROVIDER_LOCAL else self.row_get(domain, "dns_provider", DNS_PROVIDER_LOCAL),
                provider_account_id,
                provider_zone_id,
                json.dumps(nameservers),
                dns_status,
                json.dumps(provider_state, sort_keys=True),
                domain["id"],
            ),
        )
        if migration_state:
            conn.execute(
                "UPDATE domains SET dns_migration_state_json = ? WHERE id = ?",
                (json.dumps(migration_state, sort_keys=True), domain["id"]),
            )
        return provider_state

    def publish_acme_order_state(self, conn, account, website, certificate_id, cert_path, key_path):
        domain = conn.execute(
            "SELECT id FROM domains WHERE account_id = ? AND name = ?",
            (account["id"], website["domain"]),
        ).fetchone()
        domain_id = domain["id"] if domain else None
        intent = ACMECertificateIntent(
            account_id=account["id"],
            website_id=website["id"],
            domain_id=domain_id,
            domain=website["domain"],
        )
        provider_state = LocalACMEProvider().request_certificate(
            intent,
            cert_path=str(cert_path),
            key_path=str(key_path),
            certificate_id=certificate_id,
        )
        conn.execute(
            """
            INSERT INTO acme_certificate_orders(
              account_id, website_id, domain_id, certificate_id, domain, provider, status,
              challenge_type, challenge_token, challenge_value, issued_at, expires_at, provider_state_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, datetime('now', '+90 days'), ?)
            ON CONFLICT(account_id, domain, provider) DO UPDATE SET
              website_id = excluded.website_id,
              domain_id = excluded.domain_id,
              certificate_id = excluded.certificate_id,
              status = excluded.status,
              challenge_type = excluded.challenge_type,
              challenge_token = excluded.challenge_token,
              challenge_value = excluded.challenge_value,
              issued_at = CURRENT_TIMESTAMP,
              expires_at = datetime('now', '+90 days'),
              provider_state_json = excluded.provider_state_json
            """,
            (
                account["id"],
                website["id"],
                domain_id,
                certificate_id,
                website["domain"],
                ACME_PROVIDER_LOCAL,
                provider_state["status"],
                provider_state["challenge_type"],
                provider_state["challenge_token"],
                provider_state["challenge_value"],
                json.dumps(provider_state, sort_keys=True),
            ),
        )
        return provider_state

    def publish_mail_edge_state(self, conn, account, runtime, mailboxes, mail_policy):
        edge_host = runtime.get("mail_edge_host") or runtime.get("mail_host") or ""
        mailbox_routes_by_domain = {}
        for mailbox in mailboxes:
            route = MailboxRouteIntent(
                mailbox_id=mailbox["id"],
                email=mailbox["email"],
                storage_path=mailbox.get("storage_path") or "",
                quota_mb=int(mailbox.get("quota_mb") or 0),
                status=mailbox.get("status") or "active",
            )
            mailbox_routes_by_domain.setdefault(mailbox.get("domain") or mailbox["email"].split("@", 1)[-1], []).append(route)
        route_intents = []
        for domain in mail_policy["domains"]:
            route_intents.append(
                MailDomainRouteIntent(
                    account_id=account["id"],
                    mail_domain_id=domain["mail_domain_id"],
                    domain=domain["name"],
                    edge_host=edge_host,
                    mailboxes=mailbox_routes_by_domain.get(domain["name"], []),
                )
            )
        manifest = SharedMailEdgeProvider().publish_routes(route_intents)
        active_ids = []
        for route in route_intents:
            route_payload = route.payload()
            domain_id = next((item.get("domain_id") for item in mail_policy["domains"] if item["mail_domain_id"] == route.mail_domain_id), None)
            conn.execute(
                """
                INSERT INTO mail_edge_routes(
                  account_id, mail_domain_id, domain_id, domain, provider, edge_host,
                  smtp_enabled, pop_enabled, imap_enabled, jmap_enabled, webmail_enabled,
                  manifest_json, status, last_synced_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1, 1, 1, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(mail_domain_id) DO UPDATE SET
                  account_id = excluded.account_id,
                  domain_id = excluded.domain_id,
                  domain = excluded.domain,
                  provider = excluded.provider,
                  edge_host = excluded.edge_host,
                  smtp_enabled = excluded.smtp_enabled,
                  pop_enabled = excluded.pop_enabled,
                  imap_enabled = excluded.imap_enabled,
                  jmap_enabled = excluded.jmap_enabled,
                  webmail_enabled = excluded.webmail_enabled,
                  manifest_json = excluded.manifest_json,
                  status = excluded.status,
                  last_synced_at = CURRENT_TIMESTAMP,
                  updated_at = CURRENT_TIMESTAMP
                """,
                (
                    account["id"],
                    route.mail_domain_id,
                    domain_id,
                    route.domain,
                    MAIL_EDGE_PROVIDER_SHARED,
                    edge_host,
                    json.dumps({**route_payload, "provider": MAIL_EDGE_PROVIDER_SHARED}, sort_keys=True),
                    "active",
                ),
            )
            active_ids.append(route.mail_domain_id)
        if active_ids:
            placeholders = ",".join("?" for _ in active_ids)
            conn.execute(
                f"DELETE FROM mail_edge_routes WHERE account_id = ? AND mail_domain_id NOT IN ({placeholders})",
                [account["id"], *active_ids],
            )
        else:
            conn.execute("DELETE FROM mail_edge_routes WHERE account_id = ?", (account["id"],))
        return manifest

    def issue_ssl(self, conn, website_id):
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        cert_dir = Path(account["base_path"]) / "ssl" / website["domain"]
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_path = cert_dir / "issued.crt"
        key_path = cert_dir / "issued.key"
        openssl = shutil.which("openssl")
        if openssl:
            subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-days",
                    "90",
                    "-subj",
                    f"/CN={website['domain']}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        else:
            cert_path.write_text("-----BEGIN CERTIFICATE-----\ndev\n-----END CERTIFICATE-----\n", encoding="utf-8")
            key_path.write_text("-----BEGIN PRIVATE KEY-----\ndev\n-----END PRIVATE KEY-----\n", encoding="utf-8")
        conn.execute("UPDATE websites SET ssl_status = 'active' WHERE id = ?", (website_id,))
        existing_cert = conn.execute("SELECT id FROM ssl_certificates WHERE website_id = ?", (website_id,)).fetchone()
        if existing_cert:
            conn.execute(
                "UPDATE ssl_certificates SET status = 'active', issued_at = CURRENT_TIMESTAMP, expires_at = datetime('now', '+90 days') WHERE id = ?",
                (existing_cert["id"],),
            )
            cert_id = existing_cert["id"]
        else:
            cur = conn.execute(
                """
                INSERT INTO ssl_certificates(account_id, website_id, domain, status, issued_at, expires_at)
                VALUES (?, ?, ?, 'active', CURRENT_TIMESTAMP, datetime('now', '+90 days'))
                """,
                (account["id"], website_id, website["domain"]),
            )
            cert_id = cur.lastrowid
        provider_state = self.publish_acme_order_state(conn, account, website, cert_id, cert_path, key_path)
        artifact = write_account_json(
            account,
            Path(".runtime") / "ssl" / f"{website['domain']}-issued.json",
            {"mode": "native", "domain": website["domain"], "status": "active", "website_id": website_id, "cert_path": str(cert_path), "key_path": str(key_path), "provider_state": provider_state},
        )
        return {"mode": "native", "ssl_status": "active", "website_id": website_id, "artifact_path": artifact, "cert_path": str(cert_path), "key_path": str(key_path), "provider": ACME_PROVIDER_LOCAL, "provider_state": provider_state}

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
            "; MangoPanel managed DNS zone",
        ]
        for item in records:
            priority = "{} ".format(item["priority"]) if item["priority"] is not None else ""
            zone_lines.append("{} {} IN {} {}{}".format(item["name"], item["ttl"], item["type"], priority, item["value"]))
        artifact = Path(account["base_path"]) / ".runtime" / "dns" / "zones" / "{}.zone".format(domain["name"])
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("\n".join(zone_lines) + "\n", encoding="utf-8")
        provider_state = self.publish_dns_zone_state(conn, account, domain, records, artifact)
        report = write_account_json(
            account,
            Path(".runtime") / "dns" / f"{domain['name']}.json",
            {"mode": "native", "domain_id": domain["id"], "domain": domain["name"], "synced": True, "zone_path": str(artifact), "provider_state": provider_state},
        )
        return {"mode": "native", "domain_id": domain["id"], "domain": domain["name"], "synced": True, "artifact_path": report, "zone_path": str(artifact), "provider": provider_state.get("provider", DNS_PROVIDER_LOCAL), "provider_state": provider_state}

    def sync_remote_mysql(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        hosts = rows_to_dicts(conn.execute("SELECT id, host_ip, created_at FROM remote_mysql_hosts WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        sql = []
        sql.append(f"CREATE USER IF NOT EXISTS {sql_literal(runtime['db_user'])}@'%' IDENTIFIED BY {sql_literal(runtime['db_password'])};")
        sql.append(f"GRANT ALL PRIVILEGES ON `{runtime['db_name']}`.* TO {sql_literal(runtime['db_user'])}@'%';")
        for host in hosts:
            sql.append(f"CREATE USER IF NOT EXISTS {sql_literal(runtime['db_user'])}@{sql_literal(host['host_ip'])} IDENTIFIED BY {sql_literal(runtime['db_password'])};")
            sql.append(f"GRANT ALL PRIVILEGES ON `{runtime['db_name']}`.* TO {sql_literal(runtime['db_user'])}@{sql_literal(host['host_ip'])};")
        sql.append("FLUSH PRIVILEGES;")
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                subprocess.run(
                    [
                        docker,
                        "exec",
                        f"mp-{account['username']}-db",
                        "mariadb",
                        "-uroot",
                        f"-p{runtime['db_root_password']}",
                        "-e",
                        "\n".join(sql),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
        artifact = write_account_json(
            account,
            Path(".runtime") / "mysql-remote" / "report.json",
            {"mode": "native", "hosts": hosts, "sql": sql},
        )
        return {"mode": "native", "synced": True, "account_id": account_id, "hosts_count": len(hosts), "artifact_path": artifact}

    def execute_mariadb_sql(self, conn, account_id, sql_statements):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account or not sql_statements:
            return
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                sql_body = "\n".join(sql_statements)
                subprocess.run(
                    [
                        docker,
                        "exec",
                        f"mp-{account['username']}-db",
                        "mariadb",
                        "-uroot",
                        f"-p{runtime['db_root_password']}",
                        "-e",
                        sql_body,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

    def sync_hotlink_protection(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        settings = conn.execute("SELECT * FROM hotlink_settings WHERE account_id = ?", (account_id,)).fetchone()
        enabled = bool(settings["enabled"]) if settings else False
        allowed = [line.strip() for line in (settings["allowed_domains"] if settings else "").splitlines() if line.strip()]
        websites = conn.execute("SELECT * FROM websites WHERE account_id = ? ORDER BY id", (account_id,)).fetchall()
        if not websites:
            return {"synced": True, "account_id": account_id, "enabled": enabled, "artifact_path": str(Path(account["base_path"]) / ".htaccess"), "artifacts": []}

        managed_domains = {website["domain"] for website in websites}
        managed_domains.update(allowed)
        managed_domains = sorted(domain for domain in managed_domains if domain)

        block_lines = [
            "# BEGIN MangoPanel Hotlink",
            "RewriteEngine On",
            "RewriteCond %{REQUEST_FILENAME} -s [OR]",
            "RewriteCond %{REQUEST_FILENAME} -d",
            "RewriteRule ^ - [L]",
        ]
        if enabled:
            block_lines.append(r"RewriteCond %{REQUEST_URI} \.(?:jpe?g|png|gif|webp|avif|svg|bmp|ico)$ [NC]")
            if managed_domains:
                block_lines.append(r"RewriteCond %{HTTP_REFERER} !^$ [NC]")
                for domain in managed_domains:
                    block_lines.append(f"RewriteCond %{{HTTP_REFERER}} !{self.hotlink_pattern(domain)}")
                block_lines.append("RewriteRule ^ - [F,L]")
            else:
                block_lines.append(r"RewriteCond %{HTTP_REFERER} !^$ [NC]")
                block_lines.append("RewriteRule ^ - [F,L]")
        block_lines.append("# END MangoPanel Hotlink")
        block_text = "\n".join(block_lines) + "\n"

        artifact_paths = []
        for website in websites:
            root = Path(website["document_root"])
            root.mkdir(parents=True, exist_ok=True)
            htaccess = root / ".htaccess"
            current = htaccess.read_text(encoding="utf-8") if htaccess.exists() else ""
            updated = self.replace_managed_block(current, "# BEGIN MangoPanel Hotlink", "# END MangoPanel Hotlink", block_text if enabled else "")
            if updated:
                htaccess.write_text(updated, encoding="utf-8")
                htaccess.chmod(0o644)
                artifact_paths.append(str(htaccess))
            elif htaccess.exists():
                htaccess.unlink()
                artifact_paths.append(str(htaccess))

        artifact_path = artifact_paths[0] if artifact_paths else str(Path(account["base_path"]) / ".htaccess")
        return {
            "synced": True,
            "account_id": account_id,
            "enabled": enabled,
            "artifact_path": artifact_path,
            "artifacts": artifact_paths,
        }

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
            "<body><h1>{domain}</h1><p>MangoPanel {template} site builder template.</p></body></html>\n".format(
                domain=website["domain"], template=template_id
            ),
            encoding="utf-8",
        )
        artifact = write_account_json(
            account,
            Path(".runtime") / "site-builder" / f"{website['id']}-{template_id}.json",
            {"mode": "native", "website_id": website["id"], "domain": website["domain"], "template_id": template_id, "written_files": [str(index)]},
        )
        return {"mode": "native", "installed": True, "website_id": website["id"], "template_id": template_id, "artifact_path": artifact}

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
        derivatives = []
        if target.exists():
            candidates = [target] if target.is_file() else target.rglob("*")
            for item in candidates:
                if item.is_file() and item.suffix.lower() in IMAGE_EXTENSIONS:
                    size_bytes = item.stat().st_size
                    images.append({"path": str(item), "size_bytes": size_bytes})
                    derivative = image_runtime_dir(account) / "optimized" / item.relative_to(base)
                    if item.suffix.lower() == ".svg":
                        derivative = derivative.with_suffix(".svg")
                        derivative.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(item, derivative)
                    else:
                        derivative = derivative.with_suffix(".webp")
                        derivative.parent.mkdir(parents=True, exist_ok=True)
                        from PIL import Image, ImageOps

                        with Image.open(item) as img:
                            img = ImageOps.exif_transpose(img)
                            img.thumbnail((1600, 1600))
                            if img.mode not in {"RGB", "L"}:
                                img = img.convert("RGB")
                            img.save(derivative, format=IMAGE_OPTIMIZE_FORMAT, quality=82, method=6, optimize=True)
                    derivatives.append({"source": str(item), "derivative": str(derivative), "size_bytes": derivative.stat().st_size})
        total_bytes = sum(item["size_bytes"] for item in images)
        artifact = write_account_json(
            account,
            Path(".runtime") / "images" / "report.json",
            {"mode": "native", "requested_path": requested, "images": images, "derivatives": derivatives, "total_bytes": total_bytes},
        )
        return {"mode": "native", "optimized": bool(images), "images_count": len(images), "total_bytes": total_bytes, "artifact_path": artifact, "derivatives": derivatives}

    def sync_cron_jobs(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        cron_jobs = rows_to_dicts(conn.execute("SELECT * FROM cron_jobs WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        runtime, managed_jobs, cron_path = ensure_cron_runtime_artifacts(row_to_dict(account), cron_jobs)
        for job in managed_jobs:
            conn.execute(
                """
                UPDATE cron_jobs
                SET next_run_at = ?, last_run_at = COALESCE(?, last_run_at), last_exit_code = COALESCE(?, last_exit_code), last_output = COALESCE(?, last_output)
                WHERE id = ?
                """,
                (
                    job.get("next_run_at"),
                    job.get("last_run_at"),
                    job.get("last_exit_code"),
                    job.get("last_output"),
                    job["id"],
                ),
            )
        artifact = write_account_json(
            row_to_dict(account),
            ".runtime/cron/report.json",
            {
                "mode": "native",
                "jobs": managed_jobs,
                "crontab_path": str(cron_path),
                "runtime": {k: str(v) for k, v in runtime.items()},
            },
        )
        return {"mode": "native", "synced": True, "account_id": account_id, "jobs_count": len(cron_jobs), "artifact_path": artifact, "crontab_path": str(cron_path)}

    def sync_pg_databases(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        databases = rows_to_dicts(conn.execute("SELECT * FROM pg_databases WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        users = rows_to_dicts(conn.execute("SELECT id, account_id, username, password, created_at FROM pg_users WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
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
        sql = []
        docker = shutil.which("docker") if self.config.agent_mode == "docker" else None
        if docker:
            for user in users:
                sql.append(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{user['username']}') THEN CREATE ROLE {user['username']} LOGIN PASSWORD {sql_literal(user['password'])}; ELSE ALTER ROLE {user['username']} LOGIN PASSWORD {sql_literal(user['password'])}; END IF; END $$;")
                subprocess.run(
                    [
                        docker,
                        "exec",
                        f"mp-{account['username']}-pg",
                        "psql",
                        "-U",
                        runtime["db_user"],
                        "-d",
                        "postgres",
                        "-v",
                        "ON_ERROR_STOP=1",
                        "-c",
                        sql[-1],
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            for database in databases:
                exists = subprocess.run(
                    [
                        docker,
                        "exec",
                        f"mp-{account['username']}-pg",
                        "psql",
                        "-U",
                        runtime["db_user"],
                        "-d",
                        "postgres",
                        "-tAc",
                        f"SELECT 1 FROM pg_database WHERE datname = '{database['name']}';",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if "1" not in (exists.stdout or ""):
                    create_db = subprocess.run(
                        [
                            docker,
                            "exec",
                            f"mp-{account['username']}-pg",
                            "createdb",
                            "-U",
                            runtime["db_user"],
                            "-O",
                            users[0]["username"] if users else runtime["db_user"],
                            database["name"],
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    if create_db.returncode != 0:
                        raise AgentError(create_db.stderr.strip() or create_db.stdout.strip() or "postgres_create_database_failed")
                sql.append(f"CREATE DATABASE {database['name']};")
            for grant in grants:
                privileges = "ALL PRIVILEGES" if grant["privileges"] == "ALL" else "CONNECT"
                grant_sql = "GRANT {} ON DATABASE {} TO {};".format(
                    privileges,
                    grant["database_name"],
                    grant["username"],
                )
                sql.append(grant_sql)
                subprocess.run(
                    [
                        docker,
                        "exec",
                        f"mp-{account['username']}-pg",
                        "psql",
                        "-U",
                        runtime["db_user"],
                        "-d",
                        "postgres",
                        "-v",
                        "ON_ERROR_STOP=1",
                        "-c",
                        grant_sql,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
        artifact = write_account_json(
            account,
            Path(".runtime") / "postgresql" / "report.json",
            {"mode": "native", "databases": databases, "users": users, "grants": grants, "sql": sql},
        )
        return {
            "mode": "native",
            "synced": True,
            "account_id": account_id,
            "databases_count": len(databases),
            "users_count": len(users),
            "grants_count": len(grants),
            "artifact_path": artifact,
        }

    def git_deploy_metadata(self, account, deployment_id):
        path = git_metadata_path(account, deployment_id)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def write_git_deploy_metadata(self, account, deployment_id, payload):
        path = git_metadata_path(account, deployment_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return str(path)

    def git_run(self, args, cwd=None):
        env = dict(os.environ)
        env["GIT_TERMINAL_PROMPT"] = "0"
        result = subprocess.run(args, cwd=cwd, check=False, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise AgentError(result.stderr.strip() or result.stdout.strip() or "git_operation_failed")
        return result

    def deploy_git_repository(self, conn, deployment_id):
        deployment = conn.execute("SELECT * FROM git_deployments WHERE id = ?", (deployment_id,)).fetchone()
        if not deployment:
            raise AgentError("git_deployment_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (deployment["account_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        from .security import validate_git_branch, validate_git_repository_url
        if not validate_git_repository_url(deployment["repository_url"], is_development=self.config.is_development):
            raise AgentError("disallowed_repository_scheme")
        if not validate_git_branch(deployment["branch"]):
            raise AgentError("invalid_branch")
        deploy_path = Path(account["base_path"]) / deployment["deploy_path"]

        deploy_path.parent.mkdir(parents=True, exist_ok=True)
        metadata = self.git_deploy_metadata(row_to_dict(account), deployment_id)
        previous_commit = metadata.get("current_commit")
        if deploy_path.exists() and (deploy_path / ".git").exists():
            status = subprocess.run(["git", "-C", str(deploy_path), "status", "--porcelain"], check=False, capture_output=True, text=True)
            if status.stdout.strip():
                raise AgentError("dirty_worktree")
            self.git_run(["git", "-C", str(deploy_path), "fetch", "--prune", "origin"])
            self.git_run(["git", "-C", str(deploy_path), "checkout", deployment["branch"]])
            self.git_run(["git", "-C", str(deploy_path), "reset", "--hard", f"origin/{deployment['branch']}"])
        else:
            if deploy_path.exists() and any(deploy_path.iterdir()):
                raise AgentError("dirty_worktree")
            self.git_run(["git", "clone", "--branch", deployment["branch"], "--single-branch", deployment["repository_url"], str(deploy_path)])
        current_commit = subprocess.run(["git", "-C", str(deploy_path), "rev-parse", "HEAD"], check=False, capture_output=True, text=True)
        if current_commit.returncode != 0:
            raise AgentError(current_commit.stderr.strip() or current_commit.stdout.strip() or "git_head_lookup_failed")
        current_commit = current_commit.stdout.strip()
        report = self.write_git_deploy_metadata(
            row_to_dict(account),
            deployment_id,
            {
                "deployment_id": deployment_id,
                "repository_url": deployment["repository_url"],
                "branch": deployment["branch"],
                "deploy_path": str(deploy_path),
                "previous_commit": previous_commit,
                "current_commit": current_commit,
                "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        )
        conn.execute(
            "UPDATE git_deployments SET status = 'deployed', last_commit = ?, previous_commit = ?, last_deployed_at = CURRENT_TIMESTAMP, last_error = NULL WHERE id = ?",
            (current_commit, previous_commit, deployment_id),
        )
        return {"deployment_id": deployment_id, "deploy_path": str(deploy_path), "current_commit": current_commit, "previous_commit": previous_commit, "artifact_path": report, "status": "deployed"}

    def rollback_git_repository(self, conn, deployment_id):
        deployment = conn.execute("SELECT * FROM git_deployments WHERE id = ?", (deployment_id,)).fetchone()
        if not deployment:
            raise AgentError("git_deployment_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (deployment["account_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        metadata = self.git_deploy_metadata(row_to_dict(account), deployment_id)
        rollback_commit = metadata.get("previous_commit")
        if not rollback_commit:
            raise AgentError("rollback_not_available")
        deploy_path = Path(account["base_path"]) / deployment["deploy_path"]
        if not (deploy_path / ".git").exists():
            raise AgentError("git_repository_missing")
        self.git_run(["git", "-C", str(deploy_path), "reset", "--hard", rollback_commit])
        current_commit = subprocess.run(["git", "-C", str(deploy_path), "rev-parse", "HEAD"], check=False, capture_output=True, text=True)
        if current_commit.returncode != 0:
            raise AgentError(current_commit.stderr.strip() or current_commit.stdout.strip() or "git_head_lookup_failed")
        current_commit = current_commit.stdout.strip()
        new_previous = metadata.get("current_commit")
        report = self.write_git_deploy_metadata(
            row_to_dict(account),
            deployment_id,
            {
                "deployment_id": deployment_id,
                "repository_url": deployment["repository_url"],
                "branch": deployment["branch"],
                "deploy_path": str(deploy_path),
                "previous_commit": new_previous,
                "current_commit": current_commit,
                "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "rolled_back_from": rollback_commit,
            },
        )
        conn.execute(
            "UPDATE git_deployments SET status = 'rolled_back', last_commit = ?, previous_commit = ?, last_deployed_at = CURRENT_TIMESTAMP, last_error = NULL WHERE id = ?",
            (current_commit, new_previous, deployment_id),
        )
        return {"deployment_id": deployment_id, "deploy_path": str(deploy_path), "current_commit": current_commit, "rolled_back_from": rollback_commit, "artifact_path": report, "status": "rolled_back"}

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
        mailboxes = rows_to_dicts(conn.execute("SELECT * FROM mailboxes WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        for mailbox in mailboxes:
            mailbox["password"] = decrypt_secret(mailbox.get("password_secret", ""), self.config.jwt_secret)
        mail_domains = conn.execute(
            """
            SELECT md.*, d.name AS domain_name, d.status AS domain_status
            FROM mail_domains md
            JOIN domains d ON d.id = md.domain_id
            WHERE md.account_id = ?
            ORDER BY d.name
            """,
            (account_id,),
        ).fetchall()
        aliases = conn.execute("SELECT * FROM mail_aliases WHERE account_id = ? ORDER BY id", (account_id,)).fetchall()
        forwarders = conn.execute("SELECT * FROM mail_forwarders WHERE account_id = ? ORDER BY id", (account_id,)).fetchall()
        autoresponders = conn.execute(
            """
            SELECT ma.*, m.email AS mailbox_email
            FROM mail_autoresponders ma
            JOIN mailboxes m ON m.id = ma.mailbox_id
            WHERE ma.account_id = ?
            ORDER BY ma.id
            """,
            (account_id,),
        ).fetchall()
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        mail_policy = {
            "daily_email_limit": int(plan["daily_email_limit"] or 0),
            "domains": [],
            "aliases": rows_to_dicts(aliases),
            "forwarders": rows_to_dicts(forwarders),
            "autoresponders": rows_to_dicts(autoresponders),
        }
        for row in rows_to_dicts(mail_domains):
            mail_policy["domains"].append(
                {
                    "mail_domain_id": row["id"],
                    "domain_id": row["domain_id"],
                    "name": row["domain_name"],
                    "domain_status": row["domain_status"],
                    "status": row["status"],
                    "spf_policy": row["spf_policy"],
                    "dkim_selector": row["dkim_selector"],
                    "dmarc_policy": row["dmarc_policy"],
                    "catch_all_enabled": int(row["catch_all_enabled"] or 0),
                    "catch_all_destination": row["catch_all_destination"] or "",
                }
            )
        paths = ensure_account_layout(
            row_to_dict(account),
            row_to_dict(plan),
            row_to_dict(node),
            rows_to_dicts(websites),
            runtime,
            mailboxes,
            mail_policy,
        )
        mail_edge_provider = self.publish_mail_edge_state(conn, account, runtime, mailboxes, mail_policy)
        cron_jobs = rows_to_dicts(conn.execute("SELECT * FROM cron_jobs WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        ensure_cron_runtime_artifacts(row_to_dict(account), cron_jobs)
        apply_result = self.apply_stack(paths["compose"], account["username"])
        self.sync_account_databases(conn, account_id)
        ssh_status = dict(account).get("ssh_access") or "disabled"
        try:
            self.set_ssh_access(conn, account_id, ssh_status)
        except Exception:
            pass
        

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
        summary["mail_edge_provider"] = mail_edge_provider
        if touched_website_id:
            summary["website_id"] = touched_website_id
        return summary

    def sync_account_databases(self, conn, account_id):
        databases = conn.execute("SELECT id, name FROM databases WHERE account_id = ? AND status = 'active'", (account_id,)).fetchall()
        if not databases:
            return
        sql = []
        for db in databases:
            sql.append(f"CREATE DATABASE IF NOT EXISTS `{db['name']}`;")

        grants = conn.execute(
            """
            SELECT g.id, g.privileges, d.name AS database_name, u.username
            FROM database_grants g
            JOIN databases d ON d.id = g.database_id
            JOIN database_users u ON u.id = g.user_id
            WHERE d.account_id = ? AND g.status = 'active' AND u.status = 'active'
            """,
            (account_id,),
        ).fetchall()

        for grant in grants:
            priv = "ALL PRIVILEGES" if grant["privileges"] == "ALL" else grant["privileges"]
            sql.append(f"GRANT {priv} ON `{grant['database_name']}`.* TO {sql_literal(grant['username'])}@'%';")

        if sql:
            sql.append("FLUSH PRIVILEGES;")
            try:
                self.execute_mariadb_sql(conn, account_id, sql)
            except Exception as exc:
                print(f"Warning: sync_account_databases failed for account {account_id}: {exc}")

    def sync_mailboxes(self, conn, account_id):
        return self.provision_hosting_account(conn, account_id)

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
        roots = [
            "account.json",
            "domains",
            "databases",
            "mail",
            "git",
            "ssl",
            "pg_databases",
            ".runtime/stack",
        ]
        with tarfile.open(artifact_path, "w:gz") as tar:
            for rel in roots:
                source = base_path / rel
                if source.exists():
                    tar.add(source, arcname=rel)

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
        restore_roots = [
            base_path / "domains",
            base_path / "databases",
            base_path / "mail",
            base_path / "git",
            base_path / "ssl",
            base_path / "pg_databases",
            base_path / ".runtime" / "stack",
        ]
        try:
            with tarfile.open(artifact_path, "r:gz") as tar:
                for target in restore_roots:
                    if target.exists():
                        self.clear_directory_contents(target)
                account_json = base_path / "account.json"
                if account_json.exists():
                    account_json.unlink()
                safe_extract(tar, path=base_path)
        except Exception as e:
            raise AgentError(f"restore_failed: {str(e)}")

        return {"backup_id": backup_id, "restored": True, "artifact_path": str(artifact_path)}

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
        payload = self.job_payload(job)
        base_path = Path(account["base_path"]).resolve()
        websites = self.cache_scope_websites(conn, account, payload)
        purged_paths = self.clear_cache_directories(base_path, websites)
        self.reset_opcache_backend(account, websites)
        self.flush_object_cache_backend(account)
        report_path = self.write_cache_action_report(account, "purge_all", payload, websites, purged_paths)
        return {
            "account_id": account["id"],
            "website_id": payload.get("website_id"),
            "purged": True,
            "purged_paths": purged_paths,
            "artifact_path": report_path,
        }

    def reset_opcache(self, conn, job):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        payload = self.job_payload(job)
        websites = self.cache_scope_websites(conn, account, payload)
        commands = self.reset_opcache_backend(account, websites)
        opcache_dir = Path(account["base_path"]).resolve() / ".runtime" / "cache" / "opcache"
        opcache_dir.mkdir(parents=True, exist_ok=True)
        opcache_purged = self.clear_directory_contents(opcache_dir)
        report_path = self.write_cache_action_report(account, "reset_opcache", payload, websites, [])
        return {
            "account_id": account["id"],
            "website_id": payload.get("website_id"),
            "reset": True,
            "commands": commands,
            "purged_paths": opcache_purged,
            "artifact_path": report_path,
        }

    def flush_object_cache(self, conn, job):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        payload = self.job_payload(job)
        websites = self.cache_scope_websites(conn, account, payload)
        result = self.flush_object_cache_backend(account)
        base_path = Path(account["base_path"]).resolve()
        object_cache_dir = base_path / ".runtime" / "cache" / "object-cache"
        object_cache_dir.mkdir(parents=True, exist_ok=True)
        purged_paths = self.clear_directory_contents(object_cache_dir)
        purged_paths.extend(self.clear_cache_directories(base_path, websites))
        report_path = self.write_cache_action_report(account, "flush_object_cache", payload, websites, purged_paths)
        result.update(
            {
                "account_id": account["id"],
                "website_id": payload.get("website_id"),
                "purged": True,
                "purged_paths": purged_paths,
                "artifact_path": report_path,
            }
        )
        return result

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
        if service_name not in STACK_SERVICES:
            raise AgentError("invalid_service")
        
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
        state = self.inspect_service_state(account, service_name)
        return {"service": service_name, "restarted": True, "state": state}

    def service_container_name(self, account, service_name):
        return "mp-{}-{}".format(account["username"], service_name)

    def inspect_service_state(self, account, service_name):
        state = {
            "service": service_name,
            "container": self.service_container_name(account, service_name),
            "mode": self.config.agent_mode,
            "supported": service_name in STACK_SERVICES,
            "status": "unknown",
            "health": "unknown",
            "running": False,
        }
        if self.config.agent_mode != "docker":
            state["status"] = "simulated"
            return state
        docker = shutil.which("docker")
        if not docker:
            state["status"] = "docker_unavailable"
            return state
        result = subprocess.run(
            [
                docker,
                "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.Running}}",
                state["container"],
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            state["status"] = "missing"
            return state
        payload = result.stdout.strip().split("|")
        if len(payload) >= 3:
            state["status"] = payload[0] or "unknown"
            state["health"] = payload[1] or "none"
            state["running"] = payload[2].strip().lower() == "true"
        return state

    def service_status(self, account, stack, service_name=None):
        if service_name and service_name not in STACK_SERVICES:
            raise AgentError("invalid_service")
        services = [service_name] if service_name else STACK_SERVICES
        service_rows = [self.inspect_service_state(account, service) for service in services]
        return {
            "account_id": account["id"],
            "username": account["username"],
            "compose_path": stack.get("compose_path") if isinstance(stack, dict) else stack["compose_path"],
            "mode": self.config.agent_mode,
            "services": service_rows,
        }

    def fix_file_ownership(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        base_path = Path(account["base_path"]).resolve()
        if not base_path.exists():
            raise AgentError("account_path_not_found")

        try:
            os.chmod(base_path, 0o755)
        except Exception:
            pass

        directories_fixed = 0
        files_fixed = 0
        preserved_files = 0
        skipped_symlinks = 0

        for root, dirs, files in os.walk(base_path):
            current = Path(root)
            if current.is_symlink():
                skipped_symlinks += 1
                continue
            self.apply_account_metadata(current, account, preserve_permissions=False)
            directories_fixed += 1
            for directory in dirs:
                path = current / directory
                if path.is_symlink():
                    skipped_symlinks += 1
                    continue
                self.apply_account_metadata(path, account, preserve_permissions=False)
                directories_fixed += 1
            for filename in files:
                path = current / filename
                if path.is_symlink():
                    skipped_symlinks += 1
                    continue
                preserve = self.is_preserved_config_file(path)
                self.apply_account_metadata(path, account, preserve_permissions=preserve)
                if preserve:
                    preserved_files += 1
                else:
                    files_fixed += 1

        domains_dir = base_path / "domains"
        if domains_dir.exists():
            for root, dirs, files in os.walk(domains_dir):
                if "wp-config.php" in files:
                    wp_cfg_path = Path(root) / "wp-config.php"
                    try:
                        text = wp_cfg_path.read_text(encoding="utf-8")
                        if "FS_METHOD" not in text:
                            text = text.replace("<?php", "<?php\ndefine('FS_METHOD', 'direct');\n", 1)
                            wp_cfg_path.write_text(text, encoding="utf-8")
                    except Exception:
                        pass
                    try:
                        mu_dir = Path(root) / "wp-content" / "mu-plugins"
                        mu_dir.mkdir(parents=True, exist_ok=True)
                        mu_file = mu_dir / "mangopanel-compat.php"
                        mu_file.write_text("<?php\n// MangoPanel Compatibility\nadd_filter('wp_signature_hosts', '__return_empty_array', 999);\n", encoding="utf-8")
                    except Exception:
                        pass

        stack_path = base_path / ".runtime" / "stack"
        if stack_path.exists():
            try:
                for root, dirs, files in os.walk(stack_path):
                    for d in dirs:
                        try: os.chmod(os.path.join(root, d), 0o777)
                        except Exception: pass
                    for f in files:
                        try: os.chmod(os.path.join(root, f), 0o777)
                        except Exception: pass
                os.chmod(stack_path, 0o777)
            except Exception:
                pass

        report_path = self.account_runtime_dir(account, "ownership", "last_fix.json")
        report = {
            "account_id": account["id"],
            "username": account["username"],
            "directories_fixed": directories_fixed,
            "files_fixed": files_fixed,
            "preserved_files": preserved_files,
            "skipped_symlinks": skipped_symlinks,
            "fixed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return {
            "fixed": True,
            "account_id": account["id"],
            "directories_fixed": directories_fixed,
            "files_fixed": files_fixed,
            "preserved_files": preserved_files,
            "skipped_symlinks": skipped_symlinks,
            "artifact_path": str(report_path),
        }

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

        root = Path(website["document_root"])
        root.mkdir(parents=True, exist_ok=True)
        htaccess = root / ".htaccess"
        current = htaccess.read_text(encoding="utf-8") if htaccess.exists() else ""
        updated = self.replace_managed_block(current, "# BEGIN MangoPanel Index Rules", "# END MangoPanel Index Rules", htaccess_snippet)
        htaccess.write_text(updated, encoding="utf-8")
        htaccess.chmod(0o644)

        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                script = f"chown www-data:www-data /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess"
                subprocess.run(
                    [docker, "exec", "-i", f"mp-{account['username']}-web", "bash", "-c", script],
                    check=False
                )
        return {"synced": True, "website_id": website_id, "index_enabled": index_enabled, "artifact_path": str(htaccess)}

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
            raise AgentError("path_required")

        _, relative_path = self.account_relative_path(account, path, require_subpath=True)
        host_path = Path(account["base_path"]) / relative_path
        container_path = Path("/home") / account["username"] / relative_path
        htpasswd_path = host_path / ".htpasswd"
        htaccess_path = host_path / ".htaccess"

        if remove:
            if htpasswd_path.exists():
                htpasswd_path.unlink()
            if htaccess_path.exists():
                current = htaccess_path.read_text(encoding="utf-8")
                updated = self.replace_managed_block(current, "# BEGIN MangoPanel Auth", "# END MangoPanel Auth", "")
                if updated:
                    htaccess_path.write_text(updated, encoding="utf-8")
                else:
                    htaccess_path.unlink()
            return {"synced": True, "path": relative_path, "removed": True, "artifact_path": str(host_path)}

        if not username or not password:
            raise AgentError("credentials_required")

        host_path.mkdir(parents=True, exist_ok=True)
        htpasswd_path.write_text("{}:{}\n".format(username, self.htpasswd_hash(password)), encoding="utf-8")
        htpasswd_path.chmod(0o640)
        auth_name = f"Protected Area {relative_path}".replace('"', "'")
        htaccess_block = (
            "# BEGIN MangoPanel Auth\n"
            "AuthType Basic\n"
            f'AuthName "{auth_name}"\n'
            f"AuthUserFile {container_path / '.htpasswd'}\n"
            "Require valid-user\n"
            "# END MangoPanel Auth\n"
        )
        current = htaccess_path.read_text(encoding="utf-8") if htaccess_path.exists() else ""
        updated = self.replace_managed_block(current, "# BEGIN MangoPanel Auth", "# END MangoPanel Auth", htaccess_block)
        htaccess_path.write_text(updated, encoding="utf-8")
        htaccess_path.chmod(0o644)
        return {"synced": True, "path": relative_path, "removed": False, "artifact_path": str(host_path)}

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

        root = Path(website["document_root"])
        root.mkdir(parents=True, exist_ok=True)
        htaccess = root / ".htaccess"
        current = htaccess.read_text(encoding="utf-8") if htaccess.exists() else ""
        updated = self.replace_managed_block(current, "# BEGIN MangoPanel ModSec", "# END MangoPanel ModSec", htaccess_snippet)
        htaccess.write_text(updated, encoding="utf-8")
        htaccess.chmod(0o644)

        if self.config.agent_mode == "docker":
            docker = shutil.which("docker")
            if docker:
                script = f"chown www-data:www-data /var/www/vhosts/{website['domain']}/{website['document_root']}/.htaccess"
                subprocess.run(
                    [docker, "exec", "-i", f"mp-{account['username']}-web", "bash", "-c", script],
                    check=False
                )
        return {"synced": True, "website_id": website_id, "modsec_enabled": modsec_enabled, "artifact_path": str(htaccess)}

    def sync_website_analytics(self, conn, website_id):
        website = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        if not website:
            raise AgentError("website_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (website["account_id"],)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        summary = self.provision_hosting_account(conn, account["id"], touched_website_id=website_id)
        analytics_enabled = website["analytics_enabled"] if "analytics_enabled" in website.keys() and website["analytics_enabled"] is not None else 1
        artifact = write_account_json(
            account,
            Path(".runtime") / "analytics" / f"{website['domain']}.json",
            {
                "mode": "native",
                "website_id": website["id"],
                "domain": website["domain"],
                "analytics_enabled": int(analytics_enabled),
                "document_root": website["document_root"],
            },
        )
        summary.update(
            {
                "synced": True,
                "website_id": website_id,
                "analytics_enabled": int(analytics_enabled),
                "artifact_path": artifact,
            }
        )
        return summary

    def sync_ftp_accounts(self, conn, account_id):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        
        # We need the runtime for the default sftp_password
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        
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
            _, rel_path = self.account_relative_path(account, fa["path"], require_subpath=True)
            lines.append(f"{fa['username']}:{fa['password']}:1001:1001:{rel_path}")
            
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

    def set_ssh_access(self, conn, account_id, status):
        if status not in {"enabled", "disabled"}:
            raise AgentError("invalid_ssh_status")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        conn.execute("UPDATE hosting_accounts SET ssh_access = ? WHERE id = ?", (status, account_id))
        
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        sftp_conf = Path(account["base_path"]) / ".runtime" / "stack" / "sftp_users.conf"
        
        if status == "enabled":
            password = runtime.get("sftp_password", "dev-sftp-password")
            lines = [f"{account['username']}:{password}:1001:1001::/bin/ash\n"]
            if sftp_conf.parent.exists():
                sftp_conf.write_text("".join(lines), encoding="utf-8")
            container_name = f"mp-{account['username']}-sftp"
            if self.config.agent_mode == "docker":
                docker = shutil.which("docker")
                if docker:
                    subprocess.run([docker, "start", container_name], check=False, capture_output=True)
        else:
            if sftp_conf.parent.exists():
                sftp_conf.write_text(f"# SSH/SFTP access disabled for {account['username']}\n", encoding="utf-8")
            container_name = f"mp-{account['username']}-sftp"
            if self.config.agent_mode == "docker":
                docker = shutil.which("docker")
                if docker:
                    subprocess.run([docker, "stop", container_name], check=False, capture_output=True)

        return {
            "account_id": account_id,
            "username": account["username"],
            "ssh_access": status,
            "port": runtime["sftp_port"],
            "user": account["username"],
        }


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
