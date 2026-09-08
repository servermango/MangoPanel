import os
import sys
import time
import sqlite3
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from mangopanel.config import CONFIG
from mangopanel.db import connect, get_system_setting

BASE_DIR = Path(__file__).resolve().parent.parent


def run_cmd(cmd, cwd=BASE_DIR, timeout=120):
    res = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return res.returncode, res.stdout.strip(), res.stderr.strip()


def get_current_commit():
    code, out, _ = run_cmd("git rev-parse HEAD")
    return out if code == 0 else ""


def perform_health_check(max_retries=8, delay=2):
    url = "http://127.0.0.1:8000/api/public/auth-verify"
    for _ in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={"Host": "localhost"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status in {200, 400, 401}:
                    return True
        except (urllib.error.HTTPError, urllib.error.URLError, Exception):
            pass
        time.sleep(delay)
    return False


def send_update_email(conn, subject, body):
    notify = get_system_setting(conn, "update_email_notify", "1")
    if str(notify) not in {"1", "true", "True"}:
        return
    recipient = (get_system_setting(conn, "admin_email", "") or "").strip()
    if not recipient or "@" not in recipient:
        return

    message = f"From: MangoPanel System <noreply@localhost>\nTo: {recipient}\nSubject: {subject}\n\n{body}"
    try:
        sendmail_bin = "/usr/sbin/sendmail" if Path("/usr/sbin/sendmail").exists() else ("/usr/bin/sendmail" if Path("/usr/bin/sendmail").exists() else None)
        if sendmail_bin:
            proc = subprocess.Popen([sendmail_bin, "-t"], stdin=subprocess.PIPE)
            proc.communicate(input=message.encode("utf-8"))
        else:
            import smtplib
            with smtplib.SMTP("127.0.0.1", 25, timeout=5) as s:
                s.sendmail("noreply@localhost", [recipient], message.encode("utf-8"))
    except Exception as e:
        print(f"[AutoUpdate] Failed to send notification email to {recipient}: {e}", file=sys.stderr)


def sync_auto_update_cron(conn=None):
    close_conn = False
    if conn is None:
        conn = connect(CONFIG.db_path)
        close_conn = True

    try:
        enabled = get_system_setting(conn, "auto_updates_enabled", "1")
        freq = get_system_setting(conn, "auto_update_frequency", "daily")
        time_str = get_system_setting(conn, "auto_update_time", "04:00")
        dow = get_system_setting(conn, "auto_update_day_of_week", "1")
        dom = get_system_setting(conn, "auto_update_day_of_month", "1")

        cron_file = Path("/etc/cron.d/mangopanel-auto-update")

        if str(enabled) not in {"1", "true", "True"} or freq == "never":
            if cron_file.exists():
                try:
                    cron_file.unlink()
                except OSError:
                    pass
            return

        try:
            hour, minute = time_str.split(":", 1)
            hour = int(hour)
            minute = int(minute)
        except Exception:
            hour, minute = 4, 0

        if freq == "daily":
            cron_expr = f"{minute} {hour} * * *"
        elif freq == "weekly":
            try:
                w_day = int(dow) % 7
            except Exception:
                w_day = 1
            cron_expr = f"{minute} {hour} * * {w_day}"
        elif freq == "monthly":
            try:
                m_day = int(dom)
            except Exception:
                m_day = 1
            cron_expr = f"{minute} {hour} {m_day} * *"
        else:
            cron_expr = f"{minute} {hour} * * *"

        python_bin = BASE_DIR / ".venv" / "bin" / "python"
        if not python_bin.exists():
            python_bin = sys.executable

        cron_content = (
            f"SHELL=/bin/bash\n"
            f"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            f"{cron_expr} root {python_bin} -m mangopanel.auto_update >> /var/log/mangopanel-auto-update.log 2>&1\n"
        )

        try:
            cron_file.write_text(cron_content, encoding="utf-8")
            os.chmod(cron_file, 0o644)
        except Exception as e:
            print(f"[AutoUpdate] Failed to write cron file {cron_file}: {e}", file=sys.stderr)
    finally:
        if close_conn:
            conn.close()


def _rollback_update(conn, prev_commit, failed_commit, reason):
    print(f"[AutoUpdate ROLLBACK] Reverting to commit {prev_commit} due to: {reason}", file=sys.stderr)
    if prev_commit:
        run_cmd(f"git reset --hard {prev_commit}")

    run_cmd("systemctl restart mangopanel")
    healthy = perform_health_check(max_retries=8, delay=2)

    subject = f"[MangoPanel ALERT] System Update Failed - Rolled Back to {prev_commit[:7] if prev_commit else 'Initial'}"
    body = (
        f"AN AUTOMATED UPDATE FAILED AND HAS BEEN ROLLED BACK.\n\n"
        f"Failed Commit:  {failed_commit[:7] if failed_commit else 'Unknown'}\n"
        f"Restored To:    {prev_commit[:7] if prev_commit else 'Unknown'}\n"
        f"Failure Reason: {reason}\n"
        f"Current Status: {'Healthy' if healthy else 'Degraded (Requires Attention)'}\n"
        f"Timestamp:      {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    send_update_email(conn, subject, body)

    return {
        "status": "rolled_back",
        "prev_commit": prev_commit,
        "failed_commit": failed_commit,
        "reason": reason,
        "healthy": healthy,
        "message": f"Update failed ({reason}). Rolled back to {prev_commit[:7] if prev_commit else 'previous commit'}."
    }


def execute_auto_update(force=False):
    with connect(CONFIG.db_path) as conn:
        enabled = get_system_setting(conn, "auto_updates_enabled", "1")
        if not force and str(enabled) not in {"1", "true", "True"}:
            print("[AutoUpdate] Automatic updates disabled in settings.")
            return {"status": "disabled", "message": "Automatic updates disabled."}

        prev_commit = get_current_commit()
        print(f"[AutoUpdate] Starting update check. Current commit: {prev_commit}")

        code, _, pull_err = run_cmd("git fetch origin main && git pull origin main")
        if code != 0:
            print(f"[AutoUpdate] Git pull failed: {pull_err}", file=sys.stderr)
            return {"status": "error", "message": f"Git pull failed: {pull_err}"}

        new_commit = get_current_commit()
        if prev_commit and prev_commit == new_commit:
            print("[AutoUpdate] Already up to date.")
            return {"status": "already_up_to_date", "commit": prev_commit, "message": "System is already up to date."}

        print(f"[AutoUpdate] Updated to commit: {new_commit}. Restarting mangopanel service...")

        restart_code, _, restart_err = run_cmd("systemctl restart mangopanel")
        if restart_code != 0:
            return _rollback_update(conn, prev_commit, new_commit, f"systemctl restart failed: {restart_err}")

        healthy = perform_health_check(max_retries=8, delay=2)
        if healthy:
            print(f"[AutoUpdate] Update successful! MangoPanel is healthy on commit {new_commit[:7]}.")
            subject = f"[MangoPanel] System Updated Successfully ({new_commit[:7]})"
            body = (
                f"MangoPanel has been automatically updated.\n\n"
                f"Previous Commit: {prev_commit[:7] if prev_commit else 'Unknown'}\n"
                f"New Commit:      {new_commit[:7] if new_commit else 'Unknown'}\n"
                f"Timestamp:       {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Status:          Healthy (200 OK)\n"
            )
            send_update_email(conn, subject, body)
            return {"status": "updated", "prev_commit": prev_commit, "new_commit": new_commit, "message": f"Updated to {new_commit[:7]} successfully."}
        else:
            return _rollback_update(conn, prev_commit, new_commit, "Health check verification failed post-update")


if __name__ == "__main__":
    execute_auto_update(force=False)
