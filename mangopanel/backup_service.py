"""Control-plane backup creation and S3-compatible transport.

The service deliberately uses the standard library so installations do not
need a cloud SDK. Archives are plain tar.gz files and are independently
created for the control-plane database, each user, and each website.
"""
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import tarfile

from .security import decrypt_secret


def _setting(conn, key, default=""):
    row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def backup_config(conn, config):
    secret = _setting(conn, "backup_s3_secret_encrypted", "")
    return {
        "local_enabled": _setting(conn, "backup_local_enabled", "1") == "1",
        "local_remove_enabled": _setting(conn, "backup_local_remove_enabled", "1") == "1",
        "remote_remove_enabled": _setting(conn, "backup_remote_remove_enabled", "0") == "1",
        "db_enabled": _setting(conn, "backup_db_enabled", "1") == "1",
        "files_enabled": _setting(conn, "backup_files_enabled", "1") == "1",
        "db_frequency": _setting(conn, "backup_db_frequency", "daily"),
        "files_frequency": _setting(conn, "backup_files_frequency", "daily"),
        "db_time": _setting(conn, "backup_db_time", "02:00"),
        "files_time": _setting(conn, "backup_files_time", "03:00"),
        "local_path": _setting(conn, "backup_local_path", str(config.data_dir / "system-backups")),
        "remote_enabled": _setting(conn, "backup_remote_enabled", "0") == "1",
        "remote_endpoint": _setting(conn, "backup_s3_endpoint", ""),
        "remote_bucket": _setting(conn, "backup_s3_bucket", ""),
        "remote_region": _setting(conn, "backup_s3_region", "us-east-1"),
        "remote_access_key": _setting(conn, "backup_s3_access_key", ""),
        "remote_secret": decrypt_secret(secret, config.jwt_secret) if secret else "",
        "remote_prefix": _setting(conn, "backup_s3_prefix", "mangopanel"),
        "retention_days": int(_setting(conn, "backup_retention_days", "30") or 30),
    }


def _archive(path, entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz", compresslevel=1) as tar:
        for source, arcname in entries:
            source = Path(source)
            if source.exists():
                tar.add(source, arcname=arcname, recursive=True)


def _copy_sqlite(source, destination):
    source_conn = sqlite3.connect(str(source), timeout=60)
    destination_conn = sqlite3.connect(str(destination))
    try:
        source_conn.backup(destination_conn)
        destination_conn.commit()
    finally:
        destination_conn.close()
        source_conn.close()


def _s3_signature(method, url, headers, payload, access_key, secret_key, region):
    parsed = urllib.parse.urlsplit(url)
    service = "s3"
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()
    headers = {str(k).lower(): str(v).strip() for k, v in headers.items()}
    headers["host"] = parsed.netloc
    headers["x-amz-content-sha256"] = payload_hash
    headers["x-amz-date"] = amz_date
    signed = ";".join(sorted(headers))
    canonical_headers = "".join(f"{key}:{headers[key]}\n" for key in sorted(headers))
    canonical = "\n".join([method, parsed.path or "/", parsed.query, canonical_headers, signed, payload_hash])
    scope = f"{day}/{region}/{service}/aws4_request"
    string_to_sign = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()
    def sign(key, value):
        return hmac.new(key, value.encode(), hashlib.sha256).digest()
    key = sign(sign(sign(sign(("AWS4" + secret_key).encode(), day), region), service), "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
    return headers


def put_s3(cfg, key, path):
    endpoint = cfg["remote_endpoint"].rstrip("/")
    bucket = urllib.parse.quote(cfg["remote_bucket"].strip("/"), safe="")
    object_key = urllib.parse.quote(key.lstrip("/"), safe="/-_.~")
    # Path-style URLs work with AWS, DigitalOcean Spaces, MinIO, and most S3 clones.
    url = f"{endpoint}/{bucket}/{object_key}"
    payload = Path(path).read_bytes()
    raw_headers = {"content-type": "application/gzip", "content-length": str(len(payload))}
    headers = _s3_signature("PUT", url, raw_headers, payload, cfg["remote_access_key"], cfg["remote_secret"], cfg["remote_region"])
    request_headers = {k: v for k, v in headers.items() if k != "host"}
    request = urllib.request.Request(url, data=payload, method="PUT", headers=request_headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status not in (200, 201, 204):
            raise RuntimeError(f"remote_backup_upload_failed:{response.status}")


def delete_s3(cfg, key):
    endpoint = cfg["remote_endpoint"].rstrip("/")
    url = f"{endpoint}/{urllib.parse.quote(cfg['remote_bucket'].strip('/'), safe='')}/{urllib.parse.quote(key.lstrip('/'), safe='/-_.~')}"
    payload = b""
    headers = _s3_signature("DELETE", url, {}, payload, cfg["remote_access_key"], cfg["remote_secret"], cfg["remote_region"])
    request = urllib.request.Request(url, method="DELETE", headers={k: v for k, v in headers.items() if k != "host"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status not in (200, 204):
            raise RuntimeError(f"remote_backup_delete_failed:{response.status}")


def test_remote(cfg):
    if not all([cfg["remote_endpoint"], cfg["remote_bucket"], cfg["remote_access_key"], cfg["remote_secret"]]):
        raise ValueError("incomplete_remote_storage_credentials")
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as handle:
        handle.write(b"MangoPanel backup credential test\n")
        test_path = handle.name
    try:
        key = f"{cfg['remote_prefix'].strip('/')}/.credential-test-{os.getpid()}.txt"
        put_s3(cfg, key, test_path)
        return {"ok": True, "key": key}
    finally:
        Path(test_path).unlink(missing_ok=True)


def create_system_backup(conn, config, run_id, kinds=("database", "files")):
    cfg = backup_config(conn, config)
    root = Path(cfg["local_path"]) / datetime.now(timezone.utc).strftime("%Y/%m/%d")
    temp = Path(tempfile.mkdtemp(prefix="mp-backup-"))
    artifacts = []
    try:
        # Retention is deliberately controlled independently for local and
        # remote stores. A failed remote cleanup never deletes a local copy.
        if cfg["local_remove_enabled"]:
            cutoff = datetime.now(timezone.utc).timestamp() - (cfg["retention_days"] * 86400)
            for old in Path(cfg["local_path"]).rglob("*.tar.gz") if Path(cfg["local_path"]).exists() else []:
                if old.stat().st_mtime < cutoff:
                    old.unlink(missing_ok=True)
        if cfg["remote_enabled"] and cfg["remote_remove_enabled"]:
            old_rows = conn.execute("SELECT id, remote_key FROM system_backup_artifacts WHERE remote_key IS NOT NULL AND created_at < datetime('now', ?)", (f"-{cfg['retention_days']} days",)).fetchall()
            for old in old_rows:
                try:
                    delete_s3(cfg, old["remote_key"])
                    conn.execute("UPDATE system_backup_artifacts SET status = 'expired', remote_key = NULL WHERE id = ?", (old["id"],))
                except Exception:
                    pass
        if "database" in kinds:
            db_copy = temp / "mangopanel.sqlite3"
            _copy_sqlite(config.db_path, db_copy)
            artifact = root / f"system-db-{run_id}.tar.gz"
            _archive(artifact, [(db_copy, "mangopanel.sqlite3")])
            artifacts.append(("system_database", None, None, None, artifact))

        if "files" in kinds:
            accounts = conn.execute("SELECT ha.*, u.id AS owner_id FROM hosting_accounts ha JOIN users u ON u.id = ha.user_id WHERE ha.status != 'deleted' ORDER BY ha.id").fetchall()
            for account in accounts:
                user_key = f"u{int(account['owner_id']):06d}"
                account_root = Path(account["base_path"])
                user_archive = root / user_key / f"user-{user_key}-{run_id}.tar.gz"
                _archive(user_archive, [(account_root / "account.json", "account.json"), (account_root / "domains", "domains"), (account_root / "databases", "databases"), (account_root / "pg_databases", "pg_databases"), (account_root / "mail", "mail"), (account_root / "git", "git"), (account_root / "ssl", "ssl")])
                artifacts.append(("user", account["owner_id"], account["id"], None, user_archive))
                websites = conn.execute("SELECT id, domain, document_root FROM websites WHERE account_id = ? ORDER BY id", (account["id"],)).fetchall()
                for website in websites:
                    site_archive = root / user_key / "websites" / f"website-{website['id']}-{website['domain']}-{run_id}.tar.gz"
                    _archive(site_archive, [(Path(website["document_root"]), "website"), (account_root / "databases", "databases"), (account_root / "pg_databases", "pg_databases")])
                    artifacts.append(("website", account["owner_id"], account["id"], website["id"], site_archive))

        for kind, user_id, account_id, website_id, artifact in artifacts:
            remote_key = f"{cfg['remote_prefix'].strip('/')}/{artifact.relative_to(Path(cfg['local_path']))}"
            remote_key = str(remote_key).replace(os.sep, "/")
            status = "created"
            if cfg["remote_enabled"]:
                put_s3(cfg, remote_key, artifact)
                status = "uploaded"
            conn.execute("INSERT INTO system_backup_artifacts(run_id, artifact_kind, user_id, account_id, website_id, local_path, remote_key, size_bytes, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (run_id, kind, user_id, account_id, website_id, str(artifact) if cfg["local_enabled"] else None, remote_key if cfg["remote_enabled"] else None, artifact.stat().st_size, status))
            if not cfg["local_enabled"]:
                artifact.unlink(missing_ok=True)
        conn.execute("UPDATE system_backup_runs SET status = 'completed', local_path = ?, remote_prefix = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?", (str(root) if cfg["local_enabled"] else None, cfg["remote_prefix"], run_id))
        return {"run_id": run_id, "artifacts": len(artifacts), "local_enabled": cfg["local_enabled"], "remote_enabled": cfg["remote_enabled"]}
    except Exception as exc:
        conn.execute("UPDATE system_backup_runs SET status = 'failed', error = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?", (str(exc), run_id))
        raise
    finally:
        import shutil
        shutil.rmtree(temp, ignore_errors=True)
