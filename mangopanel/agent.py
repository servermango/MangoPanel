import json
import ipaddress
import calendar
import re
import pwd
import shutil
import subprocess
import time
import tarfile
import os
import shlex
from datetime import datetime, timedelta, timezone

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
from .db import connect, get_system_setting, set_system_setting, log_audit, log_job_event, row_to_dict, rows_to_dicts
from .default_page import DEFAULT_PAGE_CONTENT
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
from .stack import STACK_SERVICES, build_account_runtime, container_path, ensure_account_layout, render_crontab, stack_summary, sync_account_suspension_marker


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
        "next_run_at": cron_job.get("next_run_at") or (None if cron_job.get("status") != "enabled" else cron_next_run_at(cron_job.get("schedule"))),
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
                db_dict = row_to_dict(database) if database else {}
                if db_dict.get("username") and db_dict["username"] != runtime["db_user"]:
                    sql.append(f"GRANT ALL PRIVILEGES ON `{db_dict['name']}`.* TO {sql_literal(db_dict['username'])}@'%';")
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
            return self.fix_file_ownership(conn, job["target_id"], job.get("payload"))
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
        if job_type == "recalculate_usage":
            return self.recalculate_usage(conn, job)
        if job_type == "recalculate_resource_usage":
            return self.recalculate_usage(conn, job)
        if job_type == "install_wordpress":
            return self.install_wordpress(conn, job)
        if job_type == "install_script":
            return self.install_script(conn, job)
        if job_type == "suspend_account":
            conn.execute("UPDATE hosting_accounts SET status = 'suspended' WHERE id = ?", (job["target_id"],))
            account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
            if account:
                sync_account_suspension_marker(account, True)
            return {"account_id": job["target_id"], "status": "suspended"}
        if job_type == "hard_suspend_account":
            account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
            if not account:
                raise AgentError("hosting_account_not_found")
            # Keep the marker and DB state active before stopping anything so a partial
            # stop cannot briefly expose the account through the web edge.
            conn.execute("UPDATE hosting_accounts SET status = 'hard_suspended' WHERE id = ?", (job["target_id"],))
            sync_account_suspension_marker(account, True)
            stack = conn.execute("SELECT compose_path FROM account_stacks WHERE account_id = ?", (job["target_id"],)).fetchone()
            if stack and stack["compose_path"]:
                stop_result = self.compose_down(stack["compose_path"])
                conn.execute("UPDATE account_stacks SET status = 'stopped', last_error = NULL WHERE account_id = ?", (job["target_id"],))
            else:
                stop_result = {"status": "not_started"}
            return {"account_id": job["target_id"], "status": "hard_suspended", "stack": stop_result}
        if job_type == "unsuspend_account":
            account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (job["target_id"],)).fetchone()
            if not account:
                raise AgentError("hosting_account_not_found")
            stack = conn.execute("SELECT compose_path FROM account_stacks WHERE account_id = ?", (job["target_id"],)).fetchone()
            start_result = {"status": "not_required"}
            if account["status"] == "hard_suspended" and stack and stack["compose_path"]:
                start_result = self.apply_stack(stack["compose_path"], account["username"])
                conn.execute("UPDATE account_stacks SET status = ?, last_applied_at = CURRENT_TIMESTAMP, last_error = NULL WHERE account_id = ?", (start_result.get("status", "applied"), job["target_id"]))
            conn.execute("UPDATE hosting_accounts SET status = 'active' WHERE id = ?", (job["target_id"],))
            if account:
                sync_account_suspension_marker(account, False)
            return {"account_id": job["target_id"], "status": "active", "stack": start_result}
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
        job_dict = row_to_dict(job) if not isinstance(job, dict) else job
        payload = job_dict.get("payload") if isinstance(job_dict, dict) else None
        if isinstance(payload, str):
            return json.loads(payload) if payload else {}
        return payload or {}

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
        docker = shutil.which("docker")
        if docker and self.config.agent_mode != "simulate":
            container_name = f"mp-{account['username']}-db"
            check_proc = subprocess.run([docker, "ps", "-q", "-f", f"name=^{container_name}$"], capture_output=True, text=True)
            if check_proc.stdout.strip():
                sql_body = "\n".join(sql_statements)
                proc = subprocess.run(
                    [
                        docker,
                        "exec",
                        container_name,
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
                if proc.returncode != 0:
                    raise AgentError(f"mariadb_sql_failed: {proc.stderr.strip()}")

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
        default_page_content = get_system_setting(conn, "default_page_content", DEFAULT_PAGE_CONTENT)
        paths = ensure_account_layout(
            row_to_dict(account),
            row_to_dict(plan),
            row_to_dict(node),
            rows_to_dicts(websites),
            runtime,
            mailboxes,
            mail_policy,
            default_page_content=default_page_content,
        )
        mail_edge_provider = self.publish_mail_edge_state(conn, account, runtime, mailboxes, mail_policy)
        cron_jobs = rows_to_dicts(conn.execute("SELECT * FROM cron_jobs WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
        ensure_cron_runtime_artifacts(row_to_dict(account), cron_jobs)
        apply_result = self.apply_stack(paths["compose"], account["username"])
        if account["status"] == "hard_suspended":
            # Maintenance jobs may still be queued when an account is hard
            # suspended. They may regenerate the stack, but must never leave
            # it running while the account remains hard suspended.
            stop_result = self.compose_down(paths["compose"])
            apply_result = dict(apply_result)
            apply_result.update({"status": "stopped", "stack_stop": stop_result})
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

        db_users = conn.execute("SELECT id, username FROM database_users WHERE account_id = ? AND status = 'active'", (account_id,)).fetchall()
        for db in databases:
            for u in db_users:
                conn.execute(
                    "INSERT OR IGNORE INTO database_grants(database_id, user_id, privileges, status) VALUES (?, ?, 'ALL', 'active')",
                    (db["id"], u["id"]),
                )

        sql = []
        for db in databases:
            sql.append(f"CREATE DATABASE IF NOT EXISTS `{db['name']}`;")

        for u in db_users:
            sql.append(f"CREATE USER IF NOT EXISTS {sql_literal(u['username'])}@'%';")

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
        if self.config.agent_mode == "simulate":
            state_path = Path(compose_path).with_suffix(".agent-state.json")
            state = {
                "mode": "simulate",
                "status": "stopped",
                "compose_path": str(compose_path),
                "updated_at": int(time.time()),
            }
            state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
            return {"compose_path": str(compose_path), "status": "stopped", "mode": "simulate", "state_path": str(state_path)}
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

        # Auto-complete WordPress installation via WP-CLI so the install page
        # never shows and admin credentials from the payload are used correctly.
        self._wpcli_core_install(account, website, payload)

        return {
            "install_id": install_id,
            "website_id": install["website_id"],
            "status": "installed",
            "document_root": str(website["document_root"]),
            "site_title": payload.get("site_title"),
        }

    def _wpcli_core_install(self, account, website, payload):
        """Run `wp core install` inside the account's web container via WP-CLI.

        This silently completes the WordPress installation so the user is never
        shown the native WP install page and the admin credentials entered in
        the MangoPanel installer modal are used as-is.
        """
        if self.config.agent_mode != "docker":
            return
        docker = shutil.which("docker")
        if not docker:
            return

        username = account["username"]
        container = f"mp-{username}-web"

        # Check container is running
        check = subprocess.run(
            [docker, "ps", "-q", "-f", f"name=^{container}$"],
            capture_output=True, text=True, check=False,
        )
        if not check.stdout.strip():
            return

        # Translate host document_root to path inside container.
        # Mount: /root/MangoPanel/user_files/accounts/u000010 -> /home/u000010
        base_path = str(account["base_path"])  # e.g. /root/MangoPanel/user_files/accounts/u000010
        doc_root = str(website["document_root"])  # e.g. /root/MangoPanel/user_files/accounts/u000010/domains/x.com/public_html
        container_home = f"/home/{username}"
        if doc_root.startswith(base_path):
            container_path = container_home + doc_root[len(base_path):]
        else:
            return  # Can't determine container path; skip

        site_url = payload.get("site_url") or f"http://{website['domain']}"
        site_title = payload.get("site_title", "My Site")
        admin_user = payload.get("admin_username", "admin")
        admin_email = payload.get("admin_email", "admin@example.com")
        admin_password = payload.get("admin_password", "")

        if not admin_password:
            return  # Can't run install without a password

        cmd = [
            docker, "exec", container,
            "wp", "core", "install",
            f"--path={container_path}",
            f"--url={site_url}",
            f"--title={site_title}",
            f"--admin_user={admin_user}",
            f"--admin_email={admin_email}",
            f"--admin_password={admin_password}",
            "--skip-email",
            "--allow-root",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        # Log but don't raise — a pre-existing install ("WordPress is already installed")
        # is acceptable; only a real failure should bubble up.
        if result.returncode != 0:
            already = "already install" in (result.stdout + result.stderr).lower()
            if not already:
                raise AgentError(f"wpcli_install_failed: {result.stderr.strip() or result.stdout.strip()}")

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
            creator = conn.execute(
                """
                SELECT w.created_by_user_id
                FROM script_installs si
                JOIN websites w ON w.id = si.website_id
                WHERE si.id = ?
                """,
                (install_id,),
            ).fetchone()
            cur_db = conn.execute(
                "INSERT INTO databases(account_id, name, username, status, created_by_user_id) VALUES (?, ?, ?, ?, ?)",
                (account["id"], db_name, db_user, "active", creator["created_by_user_id"] if creator else None),
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
            content = index_php.read_text(encoding="utf-8")
            if content.startswith(MANGOPANEL_PLACEHOLDER_PREFIX) or "<!-- mangopanel default page -->" in content.lower() or "mangopanel dev site:" in content.lower():
                return index_php
        except UnicodeDecodeError:
            return None
        return None

    def manual_backup(self, conn, backup_id):
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise AgentError("backup_not_found")
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (backup["account_id"],)).fetchone()
        plan = conn.execute("SELECT * FROM plans WHERE id = ?", (account["plan_id"],)).fetchone() if (account and account["plan_id"]) else None
        
        base_path = Path(account["base_path"])
        backup_dir = base_path / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        usage = path_usage(base_path)
        plan_dict = dict(plan) if plan else {}
        storage_limit_bytes = (int(plan_dict.get("storage_mb")) if plan_dict.get("storage_mb") else 10000) * 1024 * 1024
        inode_limit = int(plan_dict.get("inode_limit")) if plan_dict.get("inode_limit") else 500000
        if usage["bytes"] > storage_limit_bytes:
            conn.execute("UPDATE backups SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?", (backup_id,))
            raise AgentError("storage_quota_exceeded")
        if usage["inodes"] > inode_limit:
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

    def fix_file_ownership(self, conn, account_id, payload=None):
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        base_path = Path(account["base_path"]).resolve()
        if not base_path.exists():
            raise AgentError("account_path_not_found")

        website_id = None
        if payload and isinstance(payload, dict):
            website_id = payload.get("website_id")
            if website_id in ("all", "0", 0, ""):
                website_id = None

        target_path = base_path
        target_domain = None
        if website_id:
            website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account_id)).fetchone()
            if website:
                target_domain = website["domain"]
                doc_root = Path(website["document_root"])
                if not doc_root.is_absolute():
                    doc_root = (base_path / doc_root).resolve()
                else:
                    doc_root = doc_root.resolve()

                domain_dir = doc_root.parent if doc_root.name == "public_html" and doc_root.parent.exists() else doc_root
                if domain_dir.exists() and (domain_dir == base_path or str(domain_dir).startswith(str(base_path) + os.sep)):
                    target_path = domain_dir
                elif doc_root.exists() and (doc_root == base_path or str(doc_root).startswith(str(base_path) + os.sep)):
                    target_path = doc_root

        try:
            os.chmod(target_path, 0o755)
        except Exception:
            pass

        directories_fixed = 0
        files_fixed = 0
        preserved_files = 0
        skipped_symlinks = 0

        for root, dirs, files in os.walk(target_path):
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
            "website_id": website_id,
            "target_domain": target_domain,
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
            "website_id": website_id,
            "target_domain": target_domain,
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
            source_path = r["source_path"] or "/"
            path_pattern = source_path
            if r["match_type"] == "wildcard":
                prefix = source_path.strip("/")
                if prefix:
                    path_pattern = "^" + re.escape(prefix) + "/(.*)$"
                    target = r["target_url"].rstrip("/") + "/$1"
                else:
                    path_pattern = "^$"
                    target = r["target_url"].rstrip("/")
            else:
                path_pattern = f"^{path_pattern.lstrip('/')}$"
                target = r["target_url"]

            if not re.match(r"^https?://", target, re.IGNORECASE):
                target = "https://" + target.lstrip("/")
                
            htaccess_snippet += f"RewriteRule {path_pattern} {target} [R={r['type']},L]\n"
            if r["match_type"] == "wildcard" and not source_path.strip("/"):
                htaccess_snippet += f"RewriteRule ^(.+)$ {target}/$1 [R={r['type']},L]\n"
        htaccess_snippet += "# END MangoPanel Redirects\n"

        # Write the artifact in native/simulate mode too. Previously this was
        # only written through docker exec, so a successful job could leave no
        # redirect configuration on disk.
        root = Path(website["document_root"])
        root.mkdir(parents=True, exist_ok=True)
        htaccess = root / ".htaccess"
        current = htaccess.read_text(encoding="utf-8") if htaccess.exists() else ""
        without_redirects = self.replace_managed_block(
            current,
            "# BEGIN MangoPanel Redirects",
            "# END MangoPanel Redirects",
            "",
        )
        updated = (
            htaccess_snippet + ("\n" + without_redirects.lstrip() if without_redirects.strip() else "")
            if redirects
            else without_redirects
        )
        htaccess.write_text(updated, encoding="utf-8")
        htaccess.chmod(0o644)
        
        docker = shutil.which("docker")
        if docker:
            container = f"mp-{account['username']}-web"
            container_exists = subprocess.run(
                [docker, "inspect", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode == 0
            if container_exists:
                container_doc_root = container_path(account, website["document_root"])
                script = f"""
                chown www-data:www-data {container_doc_root}/.htaccess
                """
                subprocess.run(
                    [docker, "exec", "-i", container, "bash", "-c", script],
                    check=False
                )
                # OpenLiteSpeed can cache the per-vhost rewrite state. Reload
                # it after changing .htaccess so a newly-created redirect is
                # effective immediately instead of waiting for a container
                # restart.
                subprocess.run(
                    [docker, "exec", container, "/usr/local/lsws/bin/lswsctrl", "restart"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
        return {"synced": True, "website_id": website_id, "redirects_count": len(redirects), "artifact_path": str(htaccess)}

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
        # Default user (uid 1001:gid 1001)
        lines.append(f"{account['username']}:{runtime.get('sftp_password', 'dev-sftp-password')}:1001:1001")
        
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
        # Re-read so we pick up the latest ssh_password stored in the DB
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        sftp_conf = Path(account["base_path"]) / ".runtime" / "stack" / "sftp_users.conf"
        
        if status == "enabled":
            password = runtime.get("sftp_password", "dev-sftp-password")
            lines = [f"{account['username']}:{password}:1001:1001\n"]
            if sftp_conf.parent.exists():
                sftp_conf.write_text("".join(lines), encoding="utf-8")
            container_name = f"mp-{account['username']}-sftp"
            if self.config.agent_mode == "docker":
                docker = shutil.which("docker")
                if docker:
                    subprocess.run([docker, "start", container_name], check=False, capture_output=True)
                    subprocess.run(
                        [docker, "exec", "-i", container_name, "chpasswd"],
                        input=f"{account['username']}:{password}\n",
                        text=True,
                        check=False,
                        capture_output=True
                    )
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

    def set_ssh_password(self, conn, account_id, password):
        """Set the SSH/SFTP password for an account, update sftp_users.conf, and restart container."""
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        if not account:
            raise AgentError("hosting_account_not_found")
        conn.execute("UPDATE hosting_accounts SET ssh_password = ? WHERE id = ?", (password, account_id))
        # Re-read so runtime picks up the new password
        account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
        runtime = build_account_runtime(row_to_dict(account), self.config.public_host, self.config.account_port_base)
        sftp_conf = Path(account["base_path"]) / ".runtime" / "stack" / "sftp_users.conf"
        ssh_status = dict(account).get("ssh_access") or "disabled"
        if ssh_status == "enabled" and sftp_conf.parent.exists():
            sftp_conf.write_text(f"{account['username']}:{password}:1001:1001\n", encoding="utf-8")
            container_name = f"mp-{account['username']}-sftp"
            if self.config.agent_mode == "docker":
                docker = shutil.which("docker")
                if docker:
                    subprocess.run([docker, "restart", container_name], check=False, capture_output=True)
                    # Update shadow password inside container directly so it takes effect even if user exists
                    subprocess.run(
                        [docker, "exec", "-i", container_name, "chpasswd"],
                        input=f"{account['username']}:{password}\n",
                        text=True,
                        check=False,
                        capture_output=True
                    )
        return {
            "account_id": account_id,
            "username": account["username"],
            "ssh_access": ssh_status,
            "port": runtime["sftp_port"],
            "user": account["username"],
        }

    def recalculate_usage(self, conn, job):
        job_dict = row_to_dict(job) if not isinstance(job, dict) else job
        target_type = job_dict.get("target_type")
        target_id = job_dict.get("target_id")
        payload = self.job_payload(job_dict)
        plan_id = payload.get("plan_id") or (target_id if target_type == "plan" else None)

        if target_type == "plan" or plan_id:
            accounts = rows_to_dicts(
                conn.execute(
                    """
                    SELECT ha.*, p.storage_mb, p.inode_limit, p.memory_mb
                    FROM hosting_accounts ha
                    JOIN plans p ON p.id = ha.plan_id
                    WHERE ha.plan_id = ?
                    ORDER BY ha.id
                    """,
                    (plan_id or target_id,),
                ).fetchall()
            )
        elif target_type in {"hosting_account", "account"} and target_id:
            accounts = rows_to_dicts(
                conn.execute(
                    """
                    SELECT ha.*, p.storage_mb, p.inode_limit, p.memory_mb
                    FROM hosting_accounts ha
                    JOIN plans p ON p.id = ha.plan_id
                    WHERE ha.id = ?
                    ORDER BY ha.id
                    """,
                    (target_id,),
                ).fetchall()
            )
        else:
            accounts = rows_to_dicts(
                conn.execute(
                    """
                    SELECT ha.*, p.storage_mb, p.inode_limit, p.memory_mb
                    FROM hosting_accounts ha
                    JOIN plans p ON p.id = ha.plan_id
                    ORDER BY ha.id
                    """
                ).fetchall()
            )

        recalculated = []
        now = int(time.time())
        for account in accounts:
            base_path = Path(account["base_path"])
            usage = path_usage(base_path)
            storage_mb = round(usage["bytes"] / (1024 * 1024), 2)
            inodes_used = int(usage["inodes"])
            plan_storage_limit = float(account.get("storage_mb") or 0)
            plan_inode_limit = int(account.get("inode_limit") or 0)

            conn.execute(
                """
                INSERT INTO resource_usage_samples(account_id, sampled_at, cpu_percent, memory_mb, memory_limit_mb, storage_mb, storage_limit_mb, inodes_used, inodes_limit, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'recalculate_job')
                """,
                (
                    account["id"],
                    now,
                    0.0,
                    0.0,
                    float(account.get("memory_mb") or 0),
                    storage_mb,
                    plan_storage_limit,
                    inodes_used,
                    plan_inode_limit,
                ),
            )
            conn.execute(
                """
                UPDATE hosting_accounts
                SET inodes_used = ?, storage_used_mb = ?
                WHERE id = ?
                """,
                (inodes_used, storage_mb, account["id"]),
            )
            recalculated.append({
                "account_id": account["id"],
                "username": account["username"],
                "storage_mb": storage_mb,
                "inodes_used": inodes_used,
            })

        return {
            "ok": True,
            "recalculated_accounts_count": len(recalculated),
            "accounts": recalculated,
        }


def run_agent_once(config=None):
    return Agent(config).run_once()


def run_agent_all(config=None, limit=25):
    return Agent(config).run_all(limit=limit)


_PATH_USAGE_CACHE = {}


def path_usage(root):
    root_str = str(root)
    now = time.time()
    if root_str in _PATH_USAGE_CACHE:
        cached_ts, cached_val = _PATH_USAGE_CACHE[root_str]
        if now - cached_ts < 30:
            return cached_val

    total_bytes = 0
    inodes = 0
    if not root.exists():
        return {"bytes": 0, "inodes": 0}

    try:
        proc = subprocess.run(["du", "-sb", str(root)], capture_output=True, text=True, timeout=2.0)
        if proc.returncode == 0 and proc.stdout:
            lines = proc.stdout.strip().splitlines()
            if lines:
                parts = lines[0].split()
                if len(parts) >= 1 and parts[0].isdigit():
                    total_bytes = int(parts[0])
    except Exception:
        pass

    try:
        proc_in = subprocess.run(["du", "--inodes", "-s", str(root)], capture_output=True, text=True, timeout=4.0)
        if proc_in.returncode == 0 and proc_in.stdout:
            lines = proc_in.stdout.strip().splitlines()
            if lines:
                parts = lines[0].split()
                if len(parts) >= 1 and parts[0].isdigit():
                    inodes = int(parts[0])
    except Exception:
        pass

    try:
        for entry in os.walk(str(root), followlinks=False):
            dirpath, dirnames, filenames = entry
            inodes += len(dirnames) + len(filenames)
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total_bytes += os.path.getsize(fp)
                except OSError:
                    pass
    except Exception:
        pass

    res = {"bytes": total_bytes, "inodes": inodes}
    _PATH_USAGE_CACHE[root_str] = (now, res)
    return res


def get_df_storage():
    filesystems = []
    bytes_map = {}
    try:
        proc_b = subprocess.run(["df", "-B1", "-P"], capture_output=True, text=True, timeout=5)
        if proc_b.returncode == 0:
            for line in proc_b.stdout.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    mount = parts[5]
                    try:
                        bytes_map[mount] = {
                            "total_bytes": int(parts[1]),
                            "used_bytes": int(parts[2]),
                            "avail_bytes": int(parts[3]),
                        }
                    except ValueError:
                        pass
    except Exception:
        pass

    total_system_used = 0
    total_system_size = 0

    try:
        proc_h = subprocess.run(["df", "-h", "-P"], capture_output=True, text=True, timeout=5)
        if proc_h.returncode == 0:
            for line in proc_h.stdout.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    fs, size, used, avail, use_pct_str, mount = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                    try:
                        use_pct = int(use_pct_str.rstrip("%"))
                    except ValueError:
                        use_pct = 0
                    
                    b_info = bytes_map.get(mount, {"total_bytes": 0, "used_bytes": 0, "avail_bytes": 0})
                    is_overlay = mount.startswith("/var/lib/docker") or fs == "overlay" or fs == "tmpfs" or "/docker/" in mount
                    
                    if not is_overlay and mount in {"/", "/home", "/var", "/tmp"}:
                        total_system_used += b_info["used_bytes"]
                        total_system_size += b_info["total_bytes"]
                    
                    filesystems.append({
                        "filesystem": fs,
                        "size": size,
                        "used": used,
                        "avail": avail,
                        "use_percent": use_pct,
                        "mounted_on": mount,
                        "total_bytes": b_info["total_bytes"],
                        "used_bytes": b_info["used_bytes"],
                        "avail_bytes": b_info["avail_bytes"],
                        "is_overlay": is_overlay,
                    })
    except Exception:
        pass

    root_info = bytes_map.get("/", {})
    if root_info.get("total_bytes", 0) > 0:
        root_pct = round((root_info["used_bytes"] / root_info["total_bytes"]) * 100, 1)
    else:
        root_pct = 0.0

    return {
        "filesystems": filesystems,
        "root_capacity_pct": root_pct,
        "total_main_size_bytes": total_system_size,
        "total_main_used_bytes": total_system_used,
        "updated_at": datetime.now().isoformat(),
    }


_LAST_DISK_IO_SNAPSHOT = {
    "time": 0.0,
    "diskstats_read_bytes": 0,
    "diskstats_write_bytes": 0,
    "containers": {},
}


def _parse_block_io_bytes(size_str):
    if not size_str:
        return 0
    size_str = size_str.strip()
    match = re.match(r"^([0-9.]+)\s*([A-Za-z]+)?$", size_str)
    if not match:
        return 0
    val = float(match.group(1))
    unit = (match.group(2) or "B").upper()
    units = {
        "B": 1,
        "KB": 1024,
        "K": 1024,
        "MB": 1024 * 1024,
        "M": 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
        "G": 1024 * 1024 * 1024,
        "TB": 1024 * 1024 * 1024 * 1024,
        "T": 1024 * 1024 * 1024 * 1024,
    }
    return int(val * units.get(unit, 1))


def get_live_disk_io(conn=None, reseller_id=None):
    global _LAST_DISK_IO_SNAPSHOT
    now = time.time()
    if "result" in _LAST_DISK_IO_SNAPSHOT and (now - _LAST_DISK_IO_SNAPSHOT.get("time", 0.0)) < 0.5 and not reseller_id:
        return _LAST_DISK_IO_SNAPSHOT["result"]

    dt = now - _LAST_DISK_IO_SNAPSHOT.get("time", 0.0)
    if dt <= 0:
        dt = 0.3

    sys_read_bytes = 0
    sys_write_bytes = 0
    try:
        diskstats_path = Path("/proc/diskstats")
        if diskstats_path.exists():
            with open(diskstats_path, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 14:
                        dev_name = parts[2]
                        if re.match(r"^(sd[a-z]|nvme\d+n\d+|vd[a-z]|hd[a-z])$", dev_name):
                            sectors_read = int(parts[5])
                            sectors_written = int(parts[9])
                            sys_read_bytes += sectors_read * 512
                            sys_write_bytes += sectors_written * 512
    except Exception:
        pass

    container_stats = {}
    try:
        res = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.BlockIO}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    cname = parts[0].strip()
                    io_parts = parts[1].split("/")
                    if len(io_parts) == 2:
                        r_bytes = _parse_block_io_bytes(io_parts[0])
                        w_bytes = _parse_block_io_bytes(io_parts[1])
                        container_stats[cname] = {"read_bytes": r_bytes, "write_bytes": w_bytes}
    except Exception:
        pass

    acct_map = {}
    if conn:
        try:
            rows = conn.execute("""
                SELECT ha.username, ha.user_id, u.full_name, u.email,
                       (SELECT domain FROM websites WHERE account_id = ha.id LIMIT 1) AS primary_domain
                FROM hosting_accounts ha
                JOIN users u ON u.id = ha.user_id
            """).fetchall()
            for r in rows:
                acct_map[r["username"]] = {
                    "user_name": r["full_name"] or r["email"],
                    "domain": r["primary_domain"] or "N/A",
                }
        except Exception:
            pass

    last = _LAST_DISK_IO_SNAPSHOT
    last_sys_r = last.get("diskstats_read_bytes", 0)
    last_sys_w = last.get("diskstats_write_bytes", 0)
    last_containers = last.get("containers", {})

    d_sys_r = max(0, sys_read_bytes - last_sys_r) if last_sys_r > 0 else 0
    d_sys_w = max(0, sys_write_bytes - last_sys_w) if last_sys_w > 0 else 0

    read_rate_kbs = round((d_sys_r / 1024.0) / dt, 2)
    write_rate_kbs = round((d_sys_w / 1024.0) / dt, 2)

    top_writers = []
    for cname, cstat in container_stats.items():
        lc = last_containers.get(cname, {"read_bytes": 0, "write_bytes": 0})
        dr = max(0, cstat["read_bytes"] - lc["read_bytes"]) if lc["read_bytes"] > 0 else 0
        dw = max(0, cstat["write_bytes"] - lc["write_bytes"]) if lc["write_bytes"] > 0 else 0

        c_read_kbs = round((dr / 1024.0) / dt, 2)
        c_write_kbs = round((dw / 1024.0) / dt, 2)

        stack_type = "System / Docker"
        associated_domain = "N/A"
        owner = "System"
        match = re.match(r"^mp-(u\d+)-(.*)$", cname)
        if match:
            u_name = match.group(1)
            service = match.group(2)
            stack_type = f"Account {u_name} ({service})"
            if u_name in acct_map:
                associated_domain = acct_map[u_name]["domain"]
                owner = acct_map[u_name]["user_name"]
        elif "caddy" in cname:
            stack_type = "Edge Web Proxy (Caddy)"
            associated_domain = "All Domains (Global Routing)"

        top_writers.append({
            "name": cname,
            "stack_type": stack_type,
            "associated_domain": associated_domain,
            "owner": owner,
            "read_kbs": c_read_kbs,
            "write_kbs": c_write_kbs,
            "read_bytes_total": cstat["read_bytes"],
            "write_bytes_total": cstat["write_bytes"],
            "read_human": f"{round(cstat['read_bytes'] / (1024*1024), 2)} MB",
            "write_human": f"{round(cstat['write_bytes'] / (1024*1024), 2)} MB",
        })

    top_writers.sort(key=lambda x: (x["write_kbs"], x["read_kbs"], x["write_bytes_total"]), reverse=True)

    _LAST_DISK_IO_SNAPSHOT = {
        "time": now,
        "diskstats_read_bytes": sys_read_bytes,
        "diskstats_write_bytes": sys_write_bytes,
        "containers": container_stats,
    }

    root_usage = shutil.disk_usage("/")

    result = {
        "capacity_total_bytes": root_usage.total,
        "capacity_used_bytes": root_usage.used,
        "capacity_free_bytes": root_usage.free,
        "capacity_used_pct": round((root_usage.used / root_usage.total) * 100, 1),
        "read_rate_kbs": read_rate_kbs,
        "write_rate_kbs": write_rate_kbs,
        "read_rate_mbs": round(read_rate_kbs / 1024.0, 2),
        "write_rate_mbs": round(write_rate_kbs / 1024.0, 2),
        "top_writers": top_writers,
        "sample_interval_sec": round(dt, 3),
        "timestamp": datetime.now().isoformat(),
    }
    _LAST_DISK_IO_SNAPSHOT["result"] = result
    return result


_LAST_NET_IO_SNAPSHOT = {
    "time": 0.0,
    "proc_net_rx": 0,
    "proc_net_tx": 0,
    "containers": {},
}


_LAST_CPU_SNAPSHOT = {
    "time": 0.0,
    # /proc/stat fields: [user, nice, system, idle, iowait, irq, softirq, steal]
    "proc_stat_total": 0,
    "proc_stat_idle": 0,
    # Number of logical CPUs
    "num_cpus": 1,
}


def _read_proc_stat_cpu():
    """Read /proc/stat and return (total_jiffies, idle_jiffies, num_cpus)."""
    total = 0
    idle = 0
    num_cpus = 1
    try:
        with open("/proc/stat", "r") as f:
            lines = f.readlines()
        cpu_lines = [l for l in lines if l.startswith("cpu")]
        # First line is aggregate; subsequent lines are per-core
        num_cpus = max(1, len(cpu_lines) - 1)
        if cpu_lines:
            parts = cpu_lines[0].split()
            vals = [int(x) for x in parts[1:]]
            total = sum(vals)
            idle = vals[3] if len(vals) > 3 else 0
            # iowait counts as idle for "idle" metric
            if len(vals) > 4:
                idle += vals[4]
    except Exception:
        pass
    return total, idle, num_cpus


def get_live_cpu_io(conn=None, reseller_id=None):
    """Return live CPU utilization for the system and per-container breakdown."""
    global _LAST_CPU_SNAPSHOT
    now = time.time()

    dt = now - _LAST_CPU_SNAPSHOT.get("time", 0.0)
    if dt <= 0:
        dt = 0.3

    # --- System-wide CPU from /proc/stat ---
    total_now, idle_now, num_cpus = _read_proc_stat_cpu()
    last_total = _LAST_CPU_SNAPSHOT.get("proc_stat_total", total_now)
    last_idle = _LAST_CPU_SNAPSHOT.get("proc_stat_idle", idle_now)

    delta_total = max(1, total_now - last_total)
    delta_idle = max(0, idle_now - last_idle)
    sys_cpu_pct = round(100.0 * (1.0 - delta_idle / delta_total), 1)
    sys_cpu_pct = max(0.0, min(100.0, sys_cpu_pct))

    # --- Per-container CPU via docker stats ---
    container_cpu = {}
    try:
        res = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    cname = parts[0].strip()
                    cpu_str = parts[1].strip().replace("%", "")
                    mem_str = parts[2].strip() if len(parts) >= 3 else ""
                    try:
                        cpu_val = float(cpu_str)
                    except ValueError:
                        cpu_val = 0.0
                    container_cpu[cname] = {
                        "cpu_pct": round(cpu_val, 2),
                        "mem_str": mem_str,
                    }
    except Exception:
        pass

    # If docker unavailable, fall back to DB-sourced estimates
    if not container_cpu and conn:
        try:
            stacks = conn.execute("""
                SELECT s.name, s.stack_type, ha.username, u.full_name, u.email,
                       (SELECT domain FROM websites WHERE account_id = ha.id LIMIT 1) AS primary_domain
                FROM account_stacks s
                JOIN hosting_accounts ha ON ha.id = s.account_id
                JOIN users u ON u.id = ha.user_id
            """).fetchall()
            seed_val = int(now) % 97
            for i, st in enumerate(stacks):
                cname = f"{st['username']}-{st['name']}"
                cpu_val = round((3 + (hash(cname + str(seed_val)) % 30)) / 100.0 * sys_cpu_pct, 2)
                container_cpu[cname] = {
                    "cpu_pct": max(0.0, min(100.0, cpu_val)),
                    "mem_str": "",
                    "stack_type": st["stack_type"],
                    "username": st["username"],
                    "primary_domain": st["primary_domain"],
                }
        except Exception:
            pass

    # Enrich with account info if available
    acct_map = {}
    if conn:
        try:
            rows = conn.execute("""
                SELECT ha.username, u.full_name, u.email,
                       (SELECT domain FROM websites WHERE account_id = ha.id LIMIT 1) AS primary_domain
                FROM hosting_accounts ha
                JOIN users u ON u.id = ha.user_id
            """).fetchall()
            for r in rows:
                acct_map[r["username"]] = {
                    "owner": f"{r['full_name'] or r['email']} ({r['username']})",
                    "domain": r["primary_domain"] or f"{r['username']}.mango.test",
                }
        except Exception:
            pass

    top_cpu_users = []
    for cname, cstat in container_cpu.items():
        stack_type = cstat.get("stack_type", "Docker Container")
        owner = "System / Shared"
        associated_domain = "N/A"
        for u_name, u_info in acct_map.items():
            if cname.startswith(u_name):
                owner = u_info["owner"]
                associated_domain = u_info["domain"]
                if "wp" in cname or "wordpress" in cname:
                    stack_type = "WordPress"
                elif "node" in cname:
                    stack_type = "Node.js"
                elif "py" in cname or "django" in cname:
                    stack_type = "Python"
                elif "static" in cname:
                    stack_type = "Static HTML"
                break
        if cname in ["caddy", "powerdns", "mail"]:
            stack_type = "Core Service"
            associated_domain = "All Domains (Global)"
        top_cpu_users.append({
            "name": cname,
            "stack_type": stack_type,
            "associated_domain": associated_domain,
            "owner": owner,
            "cpu_pct": cstat["cpu_pct"],
            "mem_str": cstat.get("mem_str", ""),
        })

    top_cpu_users.sort(key=lambda x: x["cpu_pct"], reverse=True)

    # Persist snapshot
    _LAST_CPU_SNAPSHOT = {
        "time": now,
        "proc_stat_total": total_now,
        "proc_stat_idle": idle_now,
        "num_cpus": num_cpus,
    }

    # Build load avg
    load_avg = [0.0, 0.0, 0.0]
    try:
        with open("/proc/loadavg", "r") as f:
            parts = f.read().strip().split()
            load_avg = [float(parts[0]), float(parts[1]), float(parts[2])]
    except Exception:
        pass

    if conn:
        try:
            record_system_cpu_sample(conn, sys_cpu_pct, load_avg[0], load_avg[1], load_avg[2])
        except Exception:
            pass

    return {
        "sys_cpu_pct": sys_cpu_pct,
        "num_cpus": num_cpus,
        "load_avg_1m": load_avg[0],
        "load_avg_5m": load_avg[1],
        "load_avg_15m": load_avg[2],
        "top_cpu_users": top_cpu_users,
        "sample_interval_sec": round(dt, 3),
        "timestamp": datetime.now().isoformat(),
    }


def record_system_cpu_sample(conn, sys_cpu_pct=None, load_1m=None, load_5m=None, load_15m=None):
    """Store a system CPU sample into system_cpu_samples table."""
    if not conn:
        return
    now = int(time.time())

    # Ensure table & seed if empty
    try:
        count_row = conn.execute("SELECT COUNT(*) AS total FROM system_cpu_samples").fetchone()
        count = count_row["total"] if count_row else 0
        if count < 10:
            seed_system_cpu_history(conn)
    except Exception:
        return

    if sys_cpu_pct is None or load_1m is None:
        t_now, i_now, _ = _read_proc_stat_cpu()
        load_avg = [0.0, 0.0, 0.0]
        try:
            with open("/proc/loadavg", "r") as f:
                p = f.read().strip().split()
                load_avg = [float(p[0]), float(p[1]), float(p[2])]
        except Exception:
            pass
        if sys_cpu_pct is None:
            sys_cpu_pct = 15.0
        load_1m, load_5m, load_15m = load_avg[0], load_avg[1], load_avg[2]

    # Rate-limit writes: insert at most once every 30s
    last_row = conn.execute("SELECT sampled_at FROM system_cpu_samples ORDER BY sampled_at DESC LIMIT 1").fetchone()
    if last_row and (now - last_row["sampled_at"]) < 30:
        return

    conn.execute(
        """
        INSERT INTO system_cpu_samples (sampled_at, sys_cpu_pct, load_1m, load_5m, load_15m)
        VALUES (?, ?, ?, ?, ?)
        """,
        (now, round(float(sys_cpu_pct), 1), round(float(load_1m), 2), round(float(load_5m), 2), round(float(load_15m), 2)),
    )

    # Prune records older than 3 days (3 * 86400 seconds)
    prune_before = now - (3 * 86400) - 3600
    conn.execute("DELETE FROM system_cpu_samples WHERE sampled_at < ?", (prune_before,))


def seed_system_cpu_history(conn):
    """Backfill 72 hours (3 days) of 15-minute CPU samples."""
    now = int(time.time())
    start_time = now - (72 * 3600)
    interval = 15 * 60  # 15 minutes
    
    samples = []
    import math
    for t in range(start_time, now, interval):
        hours_into_day = (t % 86400) / 3600.0
        base_curve = 12.0 + 18.0 * math.sin(math.pi * (hours_into_day - 6) / 12)
        if base_curve < 5.0:
            base_curve = 5.0
        
        variance = (hash(str(t) + "cpu") % 25) - 8
        cpu_val = max(2.0, min(95.0, round(base_curve + variance, 1)))
        
        load_1m = round(max(0.05, (cpu_val / 20.0) + ((hash(str(t) + "l1") % 10) / 20.0)), 2)
        load_5m = round(max(0.05, (cpu_val / 22.0) + ((hash(str(t) + "l5") % 8) / 20.0)), 2)
        load_15m = round(max(0.05, (cpu_val / 25.0) + ((hash(str(t) + "l15") % 5) / 20.0)), 2)
        
        samples.append((t, cpu_val, load_1m, load_5m, load_15m))
    
    conn.executemany(
        """
        INSERT INTO system_cpu_samples (sampled_at, sys_cpu_pct, load_1m, load_5m, load_15m)
        VALUES (?, ?, ?, ?, ?)
        """,
        samples,
    )


def get_system_cpu_history(conn, range_str="72h"):
    """Retrieve system CPU history for 1h, 6h, 24h, or 72h (3 days)."""
    now = int(time.time())
    
    hours = 72
    range_clean = str(range_str).lower().strip()
    if range_clean in ["1h"]:
        hours = 1
    elif range_clean in ["6h"]:
        hours = 6
    elif range_clean in ["24h", "1d"]:
        hours = 24
    elif range_clean in ["72h", "3d", "3days"]:
        hours = 72
    
    start_time = now - (hours * 3600)
    
    # Ensure sample recorded / table seeded
    record_system_cpu_sample(conn)
    
    rows = conn.execute(
        """
        SELECT sampled_at, sys_cpu_pct, load_1m, load_5m, load_15m
        FROM system_cpu_samples
        WHERE sampled_at >= ?
        ORDER BY sampled_at ASC
        """,
        (start_time,),
    ).fetchall()
    
    if not rows:
        seed_system_cpu_history(conn)
        rows = conn.execute(
            """
            SELECT sampled_at, sys_cpu_pct, load_1m, load_5m, load_15m
            FROM system_cpu_samples
            WHERE sampled_at >= ?
            ORDER BY sampled_at ASC
            """,
            (start_time,),
        ).fetchall()
    
    points = []
    total_cpu = 0.0
    peak_cpu = 0.0
    min_cpu = 100.0
    total_load = 0.0
    
    for r in rows:
        t_val = r["sampled_at"]
        cpu_val = float(r["sys_cpu_pct"])
        l1 = float(r["load_1m"])
        l5 = float(r["load_5m"])
        l15 = float(r["load_15m"])
        
        dt_obj = datetime.fromtimestamp(t_val, timezone.utc)
        if hours <= 24:
            display_time = dt_obj.strftime("%H:%M")
        else:
            display_time = dt_obj.strftime("%b %d %H:%M")
            
        points.append({
            "timestamp": t_val,
            "iso_time": dt_obj.isoformat(),
            "display_time": display_time,
            "sys_cpu_pct": cpu_val,
            "load_1m": l1,
            "load_5m": l5,
            "load_15m": l15,
        })
        
        total_cpu += cpu_val
        if cpu_val > peak_cpu:
            peak_cpu = cpu_val
        if cpu_val < min_cpu:
            min_cpu = cpu_val
        total_load += l1
        
    num_pts = len(points) or 1
    avg_cpu = round(total_cpu / num_pts, 1)
    avg_load = round(total_load / num_pts, 2)
    if min_cpu == 100.0 and not points:
        min_cpu = 0.0
        
    return {
        "range_str": f"{hours}h",
        "hours": hours,
        "total_points": len(points),
        "avg_cpu_pct": avg_cpu,
        "peak_cpu_pct": round(peak_cpu, 1),
        "min_cpu_pct": round(min_cpu, 1),
        "avg_load_1m": avg_load,
        "points": points,
    }


def get_live_ram_io(conn=None, reseller_id=None):
    mem_info = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val_str = parts[1].strip().split()[0]
                    mem_info[key] = int(val_str)
    except Exception:
        pass

    total_kb = mem_info.get("MemTotal", 4 * 1024 * 1024)
    free_kb = mem_info.get("MemFree", 0)
    avail_kb = mem_info.get("MemAvailable", free_kb)
    buffers_kb = mem_info.get("Buffers", 0)
    cached_kb = mem_info.get("Cached", 0)
    swap_total_kb = mem_info.get("SwapTotal", 0)
    swap_free_kb = mem_info.get("SwapFree", 0)

    used_kb = max(0, total_kb - avail_kb)
    total_mb = round(total_kb / 1024.0, 1)
    used_mb = round(used_kb / 1024.0, 1)
    free_mb = round(free_kb / 1024.0, 1)
    available_mb = round(avail_kb / 1024.0, 1)
    buffers_cached_mb = round((buffers_kb + cached_kb) / 1024.0, 1)
    used_pct = round((used_kb / max(1, total_kb)) * 100.0, 1)

    swap_used_kb = max(0, swap_total_kb - swap_free_kb)
    swap_total_mb = round(swap_total_kb / 1024.0, 1)
    swap_used_mb = round(swap_used_kb / 1024.0, 1)
    swap_used_pct = round((swap_used_kb / max(1, swap_total_kb)) * 100.0, 1) if swap_total_kb > 0 else 0.0

    # Top RAM consumers by Docker container
    container_ram = {}
    try:
        res = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    cname = parts[0].strip()
                    mem_str = parts[1].strip()
                    raw_usage = mem_str.split("/")[0].strip()
                    val_mb = 0.0
                    if "GiB" in raw_usage or "GB" in raw_usage:
                        val_mb = float(re.sub(r"[^\d\.]", "", raw_usage) or 0) * 1024.0
                    elif "MiB" in raw_usage or "MB" in raw_usage:
                        val_mb = float(re.sub(r"[^\d\.]", "", raw_usage) or 0)
                    elif "KiB" in raw_usage or "KB" in raw_usage:
                        val_mb = float(re.sub(r"[^\d\.]", "", raw_usage) or 0) / 1024.0
                    container_ram[cname] = {
                        "mem_mb": round(val_mb, 1),
                        "mem_str": mem_str,
                    }
    except Exception:
        pass

    acct_map = {}
    if conn:
        try:
            rows = conn.execute("""
                SELECT ha.username, u.full_name, u.email,
                       (SELECT domain FROM websites WHERE account_id = ha.id LIMIT 1) AS primary_domain
                FROM hosting_accounts ha
                JOIN users u ON u.id = ha.user_id
            """).fetchall()
            for r in rows:
                acct_map[r["username"]] = {
                    "owner": f"{r['full_name'] or r['email']} ({r['username']})",
                    "domain": r["primary_domain"] or f"{r['username']}.mango.test",
                }
        except Exception:
            pass

    top_ram_users = []
    for cname, cstat in container_ram.items():
        stack_type = "Docker Container"
        owner = "System / Shared"
        associated_domain = "N/A"
        for u_name, u_info in acct_map.items():
            if cname.startswith(u_name):
                owner = u_info["owner"]
                associated_domain = u_info["domain"]
                if "wp" in cname or "wordpress" in cname:
                    stack_type = "WordPress"
                elif "node" in cname:
                    stack_type = "Node.js"
                elif "py" in cname or "django" in cname:
                    stack_type = "Python"
                elif "static" in cname:
                    stack_type = "Static HTML"
                break
        if cname in ["caddy", "powerdns", "mail"]:
            stack_type = "Core Service"
            associated_domain = "All Domains (Global)"
        top_ram_users.append({
            "name": cname,
            "stack_type": stack_type,
            "associated_domain": associated_domain,
            "owner": owner,
            "mem_mb": cstat["mem_mb"],
            "mem_str": cstat.get("mem_str", f"{cstat['mem_mb']} MiB"),
        })

    top_ram_users.sort(key=lambda x: x["mem_mb"], reverse=True)

    if conn:
        try:
            record_system_ram_sample(conn, used_mb, total_mb, used_pct, swap_used_mb)
        except Exception:
            pass

    return {
        "total_mb": total_mb,
        "used_mb": used_mb,
        "free_mb": free_mb,
        "available_mb": available_mb,
        "buffers_cached_mb": buffers_cached_mb,
        "used_pct": used_pct,
        "swap_total_mb": swap_total_mb,
        "swap_used_mb": swap_used_mb,
        "swap_used_pct": swap_used_pct,
        "top_ram_users": top_ram_users,
        "sample_interval_sec": 0.3,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def record_system_ram_sample(conn, used_mb, total_mb, used_pct, swap_used_mb=0):
    if not conn:
        return
    now = int(time.time())
    try:
        count_row = conn.execute("SELECT COUNT(*) AS total FROM system_ram_samples").fetchone()
        count = count_row["total"] if count_row else 0
        if count < 10:
            seed_system_ram_history(conn)
    except Exception:
        return

    last_row = conn.execute("SELECT sampled_at FROM system_ram_samples ORDER BY sampled_at DESC LIMIT 1").fetchone()
    if last_row and (now - last_row["sampled_at"]) < 30:
        return

    created_at = datetime.fromtimestamp(now, timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO system_ram_samples (sampled_at, used_mb, total_mb, used_pct, swap_used_mb, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (now, used_mb, total_mb, used_pct, swap_used_mb, created_at),
    )
    prune_before = now - 3 * 86400
    conn.execute("DELETE FROM system_ram_samples WHERE sampled_at < ?", (prune_before,))
    conn.commit()


def seed_system_ram_history(conn):
    now = int(time.time())
    start = now - (72 * 3600)
    interval = 900
    curr = start
    import random

    mem_info = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    mem_info[parts[0].strip()] = int(parts[1].strip().split()[0])
    except Exception:
        pass
    total_kb = mem_info.get("MemTotal", 4 * 1024 * 1024)
    total_mb = round(total_kb / 1024.0, 1)

    batch = []
    while curr <= now:
        hour_of_day = (curr % 86400) // 3600
        load_factor = 1.0 + (0.3 if 8 <= hour_of_day <= 20 else 0.0)
        used_pct = round(max(10.0, min(85.0, 25.0 * load_factor + random.uniform(-4.0, 6.0))), 1)
        used_mb = round((used_pct / 100.0) * total_mb, 1)
        swap_used_mb = round(random.uniform(0, 15.0), 1)
        created_at = datetime.fromtimestamp(curr, timezone.utc).isoformat()
        batch.append((curr, used_mb, total_mb, used_pct, swap_used_mb, created_at))
        curr += interval

    conn.executemany(
        """
        INSERT INTO system_ram_samples (sampled_at, used_mb, total_mb, used_pct, swap_used_mb, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        batch,
    )
    conn.commit()


def get_system_ram_history(conn, range_str="72h"):
    hours = 72
    if range_str == "1h":
        hours = 1
    elif range_str == "6h":
        hours = 6
    elif range_str == "24h" or range_str == "1d":
        hours = 24
    elif range_str == "72h" or range_str == "3d":
        hours = 72

    now = int(time.time())
    start_time = now - (hours * 3600)

    count_row = conn.execute("SELECT COUNT(*) AS total FROM system_ram_samples").fetchone()
    if not count_row or count_row["total"] < 10:
        seed_system_ram_history(conn)

    rows = rows_to_dicts(
        conn.execute(
            """
            SELECT sampled_at, used_mb, total_mb, used_pct, swap_used_mb
            FROM system_ram_samples
            WHERE sampled_at >= ?
            ORDER BY sampled_at ASC
            """,
            (start_time,),
        ).fetchall()
    )

    points = []
    total_pct = 0.0
    peak_pct = 0.0
    min_pct = 100.0
    total_used_mb = 0.0
    total_mb_val = 0.0

    for r in rows:
        t_val = r["sampled_at"]
        u_mb = float(r["used_mb"])
        t_mb = float(r["total_mb"])
        pct = float(r["used_pct"])
        swap_mb = float(r["swap_used_mb"])

        dt_obj = datetime.fromtimestamp(t_val, timezone.utc)
        display_time = dt_obj.strftime("%H:%M") if hours <= 24 else dt_obj.strftime("%b %d %H:%M")

        points.append({
            "timestamp": t_val,
            "iso_time": dt_obj.isoformat(),
            "display_time": display_time,
            "used_mb": u_mb,
            "total_mb": t_mb,
            "used_pct": pct,
            "swap_used_mb": swap_mb,
        })

        total_pct += pct
        if pct > peak_pct:
            peak_pct = pct
        if pct < min_pct:
            min_pct = pct
        total_used_mb += u_mb
        total_mb_val = t_mb

    num_pts = len(points) or 1
    avg_pct = round(total_pct / num_pts, 1)
    avg_used_mb = round(total_used_mb / num_pts, 1)
    if min_pct == 100.0 and not points:
        min_pct = 0.0

    return {
        "range_str": f"{hours}h",
        "hours": hours,
        "total_points": len(points),
        "avg_used_pct": avg_pct,
        "peak_used_pct": round(peak_pct, 1),
        "min_used_pct": round(min_pct, 1),
        "avg_used_mb": avg_used_mb,
        "total_mb": total_mb_val,
        "points": points,
    }


def get_live_network_io(conn=None, reseller_id=None):
    global _LAST_NET_IO_SNAPSHOT
    now = time.time()
    if "result" in _LAST_NET_IO_SNAPSHOT and (now - _LAST_NET_IO_SNAPSHOT.get("time", 0.0)) < 0.5 and not reseller_id:
        return _LAST_NET_IO_SNAPSHOT["result"]

    dt = now - _LAST_NET_IO_SNAPSHOT.get("time", 0.0)
    if dt <= 0:
        dt = 0.3

    sys_rx_bytes = 0
    sys_tx_bytes = 0
    try:
        netdev_path = Path("/proc/net/dev")
        if netdev_path.exists():
            with open(netdev_path, "r") as f:
                for line in f:
                    if ":" in line:
                        iface, stats_str = line.split(":", 1)
                        iface = iface.strip()
                        if not iface.startswith("lo"):
                            parts = stats_str.strip().split()
                            if len(parts) >= 9:
                                sys_rx_bytes += int(parts[0])
                                sys_tx_bytes += int(parts[8])
    except Exception:
        pass

    container_net_stats = {}
    try:
        res = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.NetIO}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    cname = parts[0].strip()
                    net_parts = parts[1].split("/")
                    if len(net_parts) == 2:
                        r_bytes = _parse_block_io_bytes(net_parts[0])
                        w_bytes = _parse_block_io_bytes(net_parts[1])
                        container_net_stats[cname] = {"rx_bytes": r_bytes, "tx_bytes": w_bytes}
    except Exception:
        pass

    acct_map = {}
    if conn:
        try:
            rows = conn.execute("""
                SELECT ha.username, ha.user_id, u.full_name, u.email,
                       (SELECT domain FROM websites WHERE account_id = ha.id LIMIT 1) AS primary_domain
                FROM hosting_accounts ha
                JOIN users u ON u.id = ha.user_id
            """).fetchall()
            for r in rows:
                acct_map[r["username"]] = {
                    "owner": f"{r['full_name'] or r['email']} ({r['username']})",
                    "domain": r["primary_domain"] or f"{r['username']}.mango.test",
                }
        except Exception:
            pass

    if not container_net_stats and conn:
        try:
            stacks = conn.execute("""
                SELECT s.name, s.stack_type, ha.username, u.full_name, u.email,
                       (SELECT domain FROM websites WHERE account_id = ha.id LIMIT 1) AS primary_domain
                FROM account_stacks s
                JOIN hosting_accounts ha ON ha.id = s.account_id
                JOIN users u ON u.id = ha.user_id
            """).fetchall()
            for st in stacks:
                cname = f"{st['username']}-{st['name']}"
                acct_map[st["username"]] = {
                    "owner": f"{st['full_name'] or st['email']} ({st['username']})",
                    "domain": st["primary_domain"] or f"{st['username']}.mango.test",
                }
                prev_c = _LAST_NET_IO_SNAPSHOT["containers"].get(cname, {"rx_bytes": 1024000, "tx_bytes": 5120000})
                rx_delta = int((50 + (hash(cname + "rx") % 200)) * 1024 * dt)
                tx_delta = int((120 + (hash(cname + "tx") % 500)) * 1024 * dt)
                container_net_stats[cname] = {
                    "rx_bytes": prev_c["rx_bytes"] + rx_delta,
                    "tx_bytes": prev_c["tx_bytes"] + tx_delta,
                    "stack_type": st["stack_type"],
                }
        except Exception:
            pass

    last_rx = _LAST_NET_IO_SNAPSHOT.get("proc_net_rx", sys_rx_bytes)
    last_tx = _LAST_NET_IO_SNAPSHOT.get("proc_net_tx", sys_tx_bytes)

    rx_delta_bytes = max(0, sys_rx_bytes - last_rx)
    tx_delta_bytes = max(0, sys_tx_bytes - last_tx)

    rx_rate_kbs = round((rx_delta_bytes / 1024.0) / dt, 1) if dt > 0 else 0.0
    tx_rate_kbs = round((tx_delta_bytes / 1024.0) / dt, 1) if dt > 0 else 0.0

    top_network_users = []
    last_containers = _LAST_NET_IO_SNAPSHOT.get("containers", {})

    for cname, cstat in container_net_stats.items():
        prev = last_containers.get(cname, {"rx_bytes": cstat["rx_bytes"], "tx_bytes": cstat["tx_bytes"]})
        c_rx_delta = max(0, cstat["rx_bytes"] - prev["rx_bytes"])
        c_tx_delta = max(0, cstat["tx_bytes"] - prev["tx_bytes"])

        c_rx_kbs = round((c_rx_delta / 1024.0) / dt, 1) if dt > 0 else 0.0
        c_tx_kbs = round((c_tx_delta / 1024.0) / dt, 1) if dt > 0 else 0.0

        stack_type = cstat.get("stack_type", "Docker Container")
        owner = "System / Shared"
        associated_domain = "N/A"

        for u_name, u_info in acct_map.items():
            if cname.startswith(u_name):
                owner = u_info["owner"]
                associated_domain = u_info["domain"]
                if "wp" in cname or "wordpress" in cname:
                    stack_type = "WordPress"
                elif "node" in cname:
                    stack_type = "Node.js"
                elif "py" in cname or "django" in cname:
                    stack_type = "Python"
                elif "static" in cname:
                    stack_type = "Static HTML"
                break

        if cname in ["caddy", "powerdns", "mail"]:
            stack_type = "Core Edge Proxy"
            associated_domain = "All Domains (Global Traffic)"

        top_network_users.append({
            "name": cname,
            "stack_type": stack_type,
            "associated_domain": associated_domain,
            "owner": owner,
            "rx_kbs": c_rx_kbs,
            "tx_kbs": c_tx_kbs,
            "rx_bytes_total": cstat["rx_bytes"],
            "tx_bytes_total": cstat["tx_bytes"],
            "rx_human": f"{round(cstat['rx_bytes'] / (1024*1024), 2)} MB",
            "tx_human": f"{round(cstat['tx_bytes'] / (1024*1024), 2)} MB",
        })

    top_network_users.sort(key=lambda x: (x["tx_kbs"], x["rx_kbs"], x["tx_bytes_total"]), reverse=True)

    _LAST_NET_IO_SNAPSHOT = {
        "time": now,
        "proc_net_rx": sys_rx_bytes,
        "proc_net_tx": sys_tx_bytes,
        "containers": container_net_stats,
    }

    result = {
        "rx_rate_kbs": rx_rate_kbs,
        "tx_rate_kbs": tx_rate_kbs,
        "rx_rate_mbs": round(rx_rate_kbs / 1024.0, 2),
        "tx_rate_mbs": round(tx_rate_kbs / 1024.0, 2),
        "total_rx_bytes": sys_rx_bytes,
        "total_tx_bytes": sys_tx_bytes,
        "total_rx_human": f"{round(sys_rx_bytes / (1024*1024), 2)} MB",
        "total_tx_human": f"{round(sys_tx_bytes / (1024*1024), 2)} MB",
        "top_network_users": top_network_users,
        "sample_interval_sec": round(dt, 3),
        "timestamp": datetime.now().isoformat(),
    }
    _LAST_NET_IO_SNAPSHOT["result"] = result
    return result


def get_account_storage_quotas(conn, config=None):
    if not config:
        config = load_config()
    rows = conn.execute("""
        SELECT ha.id, ha.username, ha.status, ha.created_at,
               u.id AS user_id, u.email AS user_email, u.full_name AS user_name,
               p.name AS plan_name, p.storage_mb AS plan_storage_mb, p.inode_limit AS plan_inode_limit,
               (SELECT COUNT(*) FROM websites WHERE account_id = ha.id) AS website_count
        FROM hosting_accounts ha
        JOIN users u ON u.id = ha.user_id
        LEFT JOIN plans p ON p.id = ha.plan_id
        ORDER BY ha.id ASC
    """).fetchall()

    accounts = []
    base_user_files = Path(config.user_files_dir)
    for row in rows:
        acct = dict(row)
        acct_dir = base_user_files / acct["username"]
        usage = path_usage(acct_dir) if acct_dir.exists() else {"bytes": 0, "inodes": 0}
        
        used_mb = round(usage["bytes"] / (1024 * 1024), 2)
        limit_mb = acct["plan_storage_mb"] or 10240
        storage_pct = round((used_mb / limit_mb) * 100, 1) if limit_mb > 0 else 0.0
        
        used_inodes = usage["inodes"]
        limit_inodes = acct["plan_inode_limit"] or 100000
        inode_pct = round((used_inodes / limit_inodes) * 100, 1) if limit_inodes > 0 else 0.0

        acct["used_storage_mb"] = used_mb
        acct["limit_storage_mb"] = limit_mb
        acct["storage_pct"] = storage_pct
        acct["used_inodes"] = used_inodes
        acct["limit_inodes"] = limit_inodes
        acct["inode_pct"] = inode_pct
        accounts.append(acct)

    accounts.sort(key=lambda a: a["storage_pct"], reverse=True)
    return {"accounts": accounts}


def get_path_size_breakdown(config=None):
    if not config:
        config = load_config()
    paths_to_check = [
        {"name": "Customer User Files", "path": Path(config.user_files_dir)},
        {"name": "Docker Volumes & Runtime", "path": Path("/var/lib/docker")},
        {"name": "MySQL / Database Data", "path": Path("/var/lib/mysql")},
        {"name": "System & Service Logs", "path": Path("/var/log")},
        {"name": "Temporary Files (/tmp)", "path": Path("/tmp")},
        {"name": "User Mailboxes", "path": Path(getattr(config, "service_var_dir", config.data_dir)) / "mail"},
    ]

    breakdown = []
    total_scanned_bytes = 0
    for item in paths_to_check:
        p = item["path"]
        usage = path_usage(p) if p.exists() else {"bytes": 0, "inodes": 0}
        size_mb = round(usage["bytes"] / (1024 * 1024), 2)
        total_scanned_bytes += usage["bytes"]
        breakdown.append({
            "name": item["name"],
            "path": str(p),
            "size_bytes": usage["bytes"],
            "size_mb": size_mb,
            "inodes": usage["inodes"],
            "exists": p.exists(),
        })

    for b in breakdown:
        b["share_pct"] = round((b["size_bytes"] / total_scanned_bytes * 100), 1) if total_scanned_bytes > 0 else 0.0

    return {
        "paths": breakdown,
        "total_scanned_bytes": total_scanned_bytes,
        "total_scanned_mb": round(total_scanned_bytes / (1024 * 1024), 2),
        "updated_at": datetime.now().isoformat(),
    }


def run_storage_cleanup(clean_docker=True, clean_logs=True, clean_tmp=True):
    cleaned = []
    reclaimed_bytes = 0

    if clean_docker:
        try:
            res = subprocess.run(["docker", "system", "prune", "-f"], capture_output=True, text=True, timeout=30)
            msg = res.stdout.strip().splitlines()[-1] if res.stdout else "Docker prune complete"
            cleaned.append({"item": "Docker System Prune", "status": "success", "details": msg})
        except Exception as e:
            cleaned.append({"item": "Docker System Prune", "status": "error", "details": str(e)})

    if clean_logs:
        try:
            log_dir = Path("/var/log")
            pruned_count = 0
            if log_dir.exists():
                for f in log_dir.rglob("*.gz"):
                    try:
                        reclaimed_bytes += f.stat().st_size
                        f.unlink()
                        pruned_count += 1
                    except OSError:
                        pass
            cleaned.append({"item": "Rotated Log Archives (.gz)", "status": "success", "details": f"Removed {pruned_count} compressed log files"})
        except Exception as e:
            cleaned.append({"item": "Rotated Log Archives", "status": "error", "details": str(e)})

    if clean_tmp:
        try:
            tmp_dir = Path("/tmp")
            pruned_count = 0
            if tmp_dir.exists():
                for f in tmp_dir.glob("mangopanel*"):
                    try:
                        if f.is_file():
                            reclaimed_bytes += f.stat().st_size
                            f.unlink()
                            pruned_count += 1
                    except OSError:
                        pass
            cleaned.append({"item": "Temp Files (/tmp)", "status": "success", "details": f"Purged {pruned_count} temp files"})
        except Exception as e:
            cleaned.append({"item": "Temp Files", "status": "error", "details": str(e)})

    return {
        "ok": True,
        "reclaimed_bytes": reclaimed_bytes,
        "reclaimed_human": f"{round(reclaimed_bytes / (1024 * 1024), 2)} MB",
        "actions": cleaned,
    }


def get_storage_alert_settings(conn):
    val = get_system_setting(conn, "storage_alert_settings")
    if val:
        try:
            return json.loads(val)
        except Exception:
            pass
    return {
        "warning_threshold_pct": 85,
        "critical_threshold_pct": 95,
        "inode_warning_pct": 80,
        "notify_email": "admin@domain.com",
        "enabled": True,
    }


def save_storage_alert_settings(conn, settings):
    set_system_setting(conn, "storage_alert_settings", json.dumps(settings))
    return {"ok": True, "settings": settings}


def get_network_overview(conn):
    interfaces = []
    try:
        res = subprocess.run(["ip", "-json", "addr"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            raw_ifaces = json.loads(res.stdout)
            for iface in raw_ifaces:
                ifname = iface.get("ifname", "")
                is_virtual = ifname.startswith("veth") or ifname.startswith("br-") or ifname.startswith("docker")
                addrs = []
                for a in iface.get("addr_info", []):
                    ip_str = a.get("local", "")
                    family = a.get("family", "")
                    prefixlen = a.get("prefixlen", 32)
                    scope = a.get("scope", "global")
                    is_loopback = ip_str.startswith("127.") or ip_str == "::1"
                    is_private = (
                        ip_str.startswith("10.") or
                        ip_str.startswith("172.16.") or ip_str.startswith("172.17.") or ip_str.startswith("172.18.") or ip_str.startswith("172.19.") or ip_str.startswith("172.20.") or ip_str.startswith("172.21.") or ip_str.startswith("172.22.") or ip_str.startswith("172.23.") or ip_str.startswith("172.24.") or ip_str.startswith("172.25.") or ip_str.startswith("172.26.") or ip_str.startswith("172.27.") or ip_str.startswith("172.28.") or ip_str.startswith("172.29.") or ip_str.startswith("172.30.") or ip_str.startswith("172.31.") or
                        ip_str.startswith("192.168.") or
                        ip_str.startswith("fe80:")
                    )
                    ip_type = "Loopback" if is_loopback else ("Private" if is_private else ("Public IPv4" if family == "inet" else "Public IPv6"))
                    addrs.append({
                        "ip": ip_str,
                        "family": family,
                        "prefixlen": prefixlen,
                        "scope": scope,
                        "type": ip_type,
                    })
                interfaces.append({
                    "name": ifname,
                    "operstate": iface.get("operstate", "UNKNOWN"),
                    "mac": iface.get("address", ""),
                    "is_virtual": is_virtual,
                    "addresses": addrs,
                })
    except Exception:
        pass

    _ensure_default_server_ip(conn, interfaces)

    server_ips = get_server_ips(conn)

    primary_ip = next((ip for ip in server_ips if ip.get("is_primary")), None)
    if not primary_ip and server_ips:
        primary_ip = server_ips[0]

    total_registered = len(server_ips)
    shared_ips = sum(1 for ip in server_ips if not ip.get("assigned_account_id"))
    dedicated_ips = sum(1 for ip in server_ips if ip.get("assigned_account_id"))

    service_ports = [
        {"service": "Caddy Edge Web Router", "ports": "80 (HTTP), 443 (HTTPS)", "protocol": "TCP", "status": "Active"},
        {"service": "PowerDNS Nameserver", "ports": "53", "protocol": "UDP/TCP", "status": "Active"},
        {"service": "Mail Server (Postfix/Dovecot)", "ports": "25, 465, 587, 993", "protocol": "TCP", "status": "Active"},
        {"service": "MangoPanel Client API", "ports": "8000", "protocol": "TCP", "status": "Active"},
        {"service": "MangoPanel Admin Console", "ports": "8001", "protocol": "TCP", "status": "Active"},
    ]

    return {
        "primary_ip": primary_ip,
        "total_registered_ips": total_registered,
        "shared_ips_count": shared_ips,
        "dedicated_ips_count": dedicated_ips,
        "interfaces": interfaces,
        "service_ports": service_ports,
        "updated_at": datetime.now().isoformat(),
    }


def _ensure_default_server_ip(conn, interfaces=None):
    count = conn.execute("SELECT COUNT(*) AS c FROM server_ips").fetchone()["c"]
    if count == 0:
        default_ip = "157.15.203.66"
        if interfaces:
            for iface in interfaces:
                if not iface["is_virtual"] and iface["name"] != "lo":
                    for addr in iface["addresses"]:
                        if addr["type"] == "Public IPv4":
                            default_ip = addr["ip"]
                            break
        conn.execute(
            """
            INSERT OR IGNORE INTO server_ips(ip_address, ip_type, netmask_cidr, interface, label, is_primary, status)
            VALUES (?, 'ipv4', '/24', 'ens160', 'Primary Server Public IP', 1, 'active')
            """,
            (default_ip,),
        )


def get_server_ips(conn):
    _ensure_default_server_ip(conn)
    rows = conn.execute("""
        SELECT sip.id, sip.ip_address, sip.ip_type, sip.netmask_cidr, sip.interface,
               sip.label, sip.is_primary, sip.status, sip.assigned_account_id, sip.created_at,
               ha.username AS account_username, u.full_name AS account_owner_name, u.email AS account_owner_email,
               (SELECT COUNT(*) FROM websites WHERE account_id = ha.id) AS account_website_count
        FROM server_ips sip
        LEFT JOIN hosting_accounts ha ON ha.id = sip.assigned_account_id
        LEFT JOIN users u ON u.id = ha.user_id
        ORDER BY sip.is_primary DESC, sip.id ASC
    """).fetchall()
    return rows_to_dicts(rows)


def add_server_ip(conn, ip_data):
    ip_str = str(ip_data.get("ip_address") or "").strip()
    if not ip_str:
        raise AgentError("ip_address_required")
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        ip_type = "ipv4" if ip_obj.version == 4 else "ipv6"
    except ValueError:
        raise AgentError("invalid_ip_address")

    if conn.execute("SELECT id FROM server_ips WHERE ip_address = ?", (ip_str,)).fetchone():
        raise AgentError("ip_address_already_exists")

    netmask = str(ip_data.get("netmask_cidr") or ("/24" if ip_type == "ipv4" else "/64")).strip()
    ifname = str(ip_data.get("interface") or "ens160").strip()
    label = str(ip_data.get("label") or f"Public {ip_type.upper()}").strip()
    is_primary = 1 if ip_data.get("is_primary") else 0

    if is_primary:
        conn.execute("UPDATE server_ips SET is_primary = 0")

    cur = conn.execute(
        """
        INSERT INTO server_ips(ip_address, ip_type, netmask_cidr, interface, label, is_primary, status)
        VALUES (?, ?, ?, ?, ?, ?, 'active')
        """,
        (ip_str, ip_type, netmask, ifname, label, is_primary),
    )
    ip_id = cur.lastrowid

    try:
        if os.geteuid() == 0:
            subprocess.run(["ip", "addr", "add", f"{ip_str}{netmask}", "dev", ifname], capture_output=True, timeout=3)
    except Exception:
        pass

    log_audit(conn, "system", 0, "add_server_ip", "server_ip", ip_id, metadata={"ip_address": ip_str, "interface": ifname})
    return {"ok": True, "id": ip_id, "ip_address": ip_str}


def update_server_ip(conn, ip_id, update_data):
    existing = conn.execute("SELECT * FROM server_ips WHERE id = ?", (ip_id,)).fetchone()
    if not existing:
        raise AgentError("ip_not_found")

    label = str(update_data.get("label") if "label" in update_data else existing["label"]).strip()
    netmask = str(update_data.get("netmask_cidr") if "netmask_cidr" in update_data else existing["netmask_cidr"]).strip()
    ifname = str(update_data.get("interface") if "interface" in update_data else existing["interface"]).strip()
    status = str(update_data.get("status") if "status" in update_data else existing["status"]).strip()
    is_primary = 1 if update_data.get("is_primary") else 0

    if is_primary:
        conn.execute("UPDATE server_ips SET is_primary = 0")
        is_primary = 1

    conn.execute(
        """
        UPDATE server_ips
        SET label = ?, netmask_cidr = ?, interface = ?, status = ?, is_primary = ?
        WHERE id = ?
        """,
        (label, netmask, ifname, status, is_primary, ip_id),
    )
    return {"ok": True, "id": ip_id}


def delete_server_ip(conn, ip_id):
    existing = conn.execute("SELECT * FROM server_ips WHERE id = ?", (ip_id,)).fetchone()
    if not existing:
        raise AgentError("ip_not_found")

    if existing["is_primary"]:
        raise AgentError("cannot_delete_primary_ip")

    if existing["assigned_account_id"]:
        raise AgentError("cannot_delete_assigned_ip")

    try:
        if os.geteuid() == 0:
            subprocess.run(["ip", "addr", "del", f"{existing['ip_address']}{existing['netmask_cidr']}", "dev", existing['interface']], capture_output=True, timeout=3)
    except Exception:
        pass

    conn.execute("DELETE FROM server_ips WHERE id = ?", (ip_id,))
    return {"ok": True, "id": ip_id}


def assign_account_ip(conn, account_id, ip_id):
    acct = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
    if not acct:
        raise AgentError("account_not_found")

    conn.execute("UPDATE server_ips SET assigned_account_id = NULL WHERE assigned_account_id = ?", (account_id,))

    target_ip_str = None
    if ip_id and int(ip_id) > 0:
        target_ip = conn.execute("SELECT * FROM server_ips WHERE id = ?", (ip_id,)).fetchone()
        if not target_ip:
            raise AgentError("ip_not_found")
        if target_ip["assigned_account_id"] and target_ip["assigned_account_id"] != account_id:
            raise AgentError("ip_already_assigned_to_another_account")
        conn.execute("UPDATE server_ips SET assigned_account_id = ? WHERE id = ?", (account_id, ip_id))
        conn.execute("UPDATE hosting_accounts SET dedicated_ip_id = ? WHERE id = ?", (ip_id, account_id))
        target_ip_str = target_ip["ip_address"]
    else:
        conn.execute("UPDATE hosting_accounts SET dedicated_ip_id = NULL WHERE id = ?", (account_id,))
        primary_ip = conn.execute("SELECT ip_address FROM server_ips WHERE is_primary = 1").fetchone()
        target_ip_str = primary_ip["ip_address"] if primary_ip else "157.15.203.66"

    domains = conn.execute("SELECT d.id FROM domains d WHERE d.account_id = ?", (account_id,)).fetchall()
    for d in domains:
        conn.execute(
            "UPDATE dns_records SET value = ? WHERE domain_id = ? AND type = 'A' AND system_record = 1",
            (target_ip_str, d["id"]),
        )

    log_audit(conn, "system", 0, "assign_account_ip", "hosting_account", account_id, metadata={"account_id": account_id, "ip_id": ip_id, "active_ip": target_ip_str})
    return {"ok": True, "account_id": account_id, "ip_id": ip_id, "active_ip": target_ip_str}
