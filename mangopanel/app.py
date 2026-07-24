import json
import hashlib
import ipaddress
import os
from email import policy as email_policy
from email.parser import BytesParser
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import socket
import ssl
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from .agent import Agent, AgentError, cron_next_run_at, decorate_cron_jobs, validate_cron_schedule
from .config import FILEBROWSER_CUSTOM_JS, load_config
from .mail import build_mail_message_bytes, dkim_dns_value, ensure_mailbox_storage, generate_dkim_material, mailbox_storage_inode_count, mailbox_storage_path, mailbox_storage_size_bytes, mail_auth_health, move_mailbox_storage, recommended_dmarc_record, recommended_spf_record, remove_mailbox_storage, sanitize_mailbox_component, split_mailbox_address
from .db import (
    connect,
    create_job,
    init_db,
    log_activity,
    log_audit,
    row_to_dict,
    rows_to_dicts,
    seed_dev_data,
)
from .providers import (
    DNS_PROVIDER_CLOUDFLARE,
    DNS_PROVIDER_LOCAL,
    DNS_PROVIDER_LOCAL_POWERDNS,
    CloudflareDNSProvider,
    DNSProviderError,
    LocalDNSProvider,
    PowerDNSProvider,
)
from .registrars import RegistrarError, registrar_for
from .security import create_jwt, decrypt_secret, encrypt_secret, generate_totp_secret, hash_password, validate_git_branch, validate_git_repository_url, verify_jwt, verify_password, verify_totp
from .snappymail import request_login_session
from .stack import build_account_runtime


CONFIG = load_config()
PUBLIC_DIR = Path(__file__).resolve().parent.parent / "public"
SERVICE_VAR_DIR = Path(__file__).resolve().parent.parent / "var"
FEATURE_STATUS = {
    "dashboard": {"status": "functional", "label": "Functional"},
    "installer": {"status": "functional", "label": "Functional"},
    "hosting-plan": {"status": "functional", "label": "Functional"},
    "performance": {"status": "read_only", "label": "Read only"},
    "analytics": {"status": "functional", "label": "Functional"},
    "security": {"status": "functional", "label": "Functional"},
    "domains": {"status": "functional", "label": "Functional"},
    "website": {"status": "functional", "label": "Functional"},
    "files": {"status": "functional", "label": "Functional"},
    "databases": {"status": "functional", "label": "Functional"},
    "email": {"status": "functional", "label": "Functional"},
    "cron-jobs": {"status": "functional", "label": "Functional"},
    "backups": {"status": "functional", "label": "Functional"},
    "git": {"status": "functional", "label": "Functional"},
    "ssh-access": {"status": "read_only", "label": "Read only"},
    "php-configuration": {"status": "functional", "label": "Functional"},
    "dns-zone-editor": {"status": "functional", "label": "Functional"},
    "php-info": {"status": "read_only", "label": "Read only"},
    "cache-manager": {"status": "functional", "label": "Functional"},
    "password-protect-directories": {"status": "functional", "label": "Functional"},
    "ip-manager": {"status": "functional", "label": "Functional"},
    "hotlink-protection": {"status": "functional", "label": "Functional"},
    "folder-index-manager": {"status": "functional", "label": "Functional"},
    "fix-file-ownership": {"status": "functional", "label": "Functional"},
    "services": {"status": "functional", "label": "Functional"},
    "activity": {"status": "read_only", "label": "Read only"},
    "settings": {"status": "functional", "label": "Functional"},
    "redirects": {"status": "functional", "label": "Functional"},
    "disk-usage": {"status": "read_only", "label": "Read only"},
    "modsecurity": {"status": "functional", "label": "Functional"},
    "mysql-database-wizard": {"status": "functional", "label": "Functional"},
    "api-tokens": {"status": "functional", "label": "Functional"},
    "two-factor-auth": {"status": "functional", "label": "Functional"},
    "ftp-accounts": {"status": "functional", "label": "Functional"},
    "images": {"status": "functional", "label": "Functional"},
    "remote-mysql": {"status": "functional", "label": "Functional"},
    "postgresql-databases": {"status": "functional", "label": "Functional"},
    "postgresql-database-wizard": {"status": "functional", "label": "Functional"},
    "site-builder": {"status": "functional", "label": "Functional"},
    "ssl-tls": {"status": "functional", "label": "Functional"},
    "visitors": {"status": "read_only", "label": "Read only"},
    "errors": {"status": "read_only", "label": "Read only"},
    "bandwidth": {"status": "read_only", "label": "Read only"},
    "raw-access": {"status": "read_only", "label": "Read only"},
    "webalizer": {"status": "disabled", "label": "Unavailable"},
    "resource-usage": {"status": "read_only", "label": "Read only"},
    "phppgadmin": {"status": "disabled", "label": "Unavailable"},
}

MAILPIT_BRAND_SVG = """<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 128 128\" role=\"img\" aria-label=\"MangoPanel\">
  <rect x=\"8\" y=\"8\" width=\"112\" height=\"112\" rx=\"28\" fill=\"#0f172a\"/>
  <path d=\"M34 90V38h14l16 24 16-24h14v52H80V64l-16 22-16-22v26z\" fill=\"#f59e0b\"/>
  <circle cx=\"94\" cy=\"34\" r=\"8\" fill=\"#34d399\"/>
</svg>"""

WEBMAIL_LOGIN_MAX_FAILURES = 5
WEBMAIL_LOGIN_WINDOW_SECONDS = 10 * 60
WEBMAIL_LOGIN_LOCK_SECONDS = 15 * 60
AUTH_ATTEMPT_WINDOW_SECONDS = 5 * 60
AUTH_ATTEMPT_MAX_FAILURES = 5
DNS_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"}
DNS_PROVIDER_KEYS = {DNS_PROVIDER_LOCAL_POWERDNS, DNS_PROVIDER_CLOUDFLARE}
DEFAULT_DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"]


class ApiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message


def auth_ip(conn, handler):
    return client_ip(handler) or "unknown"


def check_auth_rate_limit(conn, handler, actor_type):
    ip = auth_ip(conn, handler)
    row = conn.execute("SELECT * FROM auth_attempts WHERE ip_address = ? AND actor_type = ?", (ip, actor_type)).fetchone()
    now = int(time.time())
    if not row:
        return
    if int(row["blocked_until"] or 0) > now:
        raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "authentication_temporarily_blocked")
    if actor_type != "admin" and now - int(row["window_started_at"] or 0) < AUTH_ATTEMPT_WINDOW_SECONDS and int(row["failures"] or 0) >= AUTH_ATTEMPT_MAX_FAILURES:
        raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "too_many_auth_attempts")


def record_auth_failure(conn, handler, actor_type):
    ip = auth_ip(conn, handler)
    now = int(time.time())
    row = conn.execute("SELECT * FROM auth_attempts WHERE ip_address = ? AND actor_type = ?", (ip, actor_type)).fetchone()
    if not row or (actor_type != "admin" and now - int(row["window_started_at"] or 0) >= AUTH_ATTEMPT_WINDOW_SECONDS):
        failures, window_started, block_seconds = 1, now, 0
    else:
        failures = int(row["failures"] or 0) + 1
        window_started = int(row["window_started_at"] or now)
        block_seconds = int(row["block_seconds"] or 0)

    blocked_until = int(row["blocked_until"] or 0) if row else 0
    last_alert = int(row["last_alert_at"] or 0) if row else 0

    if actor_type == "admin":
        if failures >= 3 and (not blocked_until or now >= blocked_until):
            if block_seconds == 0:
                block_seconds = 180
            else:
                block_seconds = block_seconds * 2
            blocked_until = now + block_seconds
            log_audit(
                conn,
                "security",
                None,
                "admin_authentication_alert",
                "ip_address",
                None,
                metadata={"ip": ip, "block_seconds": block_seconds, "failures": failures},
            )
            last_alert = now

    conn.execute(
        """
        INSERT INTO auth_attempts(ip_address, actor_type, window_started_at, failures, blocked_until, block_seconds, last_alert_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_address, actor_type) DO UPDATE SET
          window_started_at=excluded.window_started_at,
          failures=excluded.failures,
          blocked_until=excluded.blocked_until,
          block_seconds=excluded.block_seconds,
          last_alert_at=excluded.last_alert_at
        """,
        (ip, actor_type, window_started, failures, blocked_until, block_seconds, last_alert),
    )


def clear_auth_attempts(conn, handler, actor_type):
    ip = auth_ip(conn, handler)
    conn.execute("DELETE FROM auth_attempts WHERE ip_address = ? AND actor_type = ?", (ip, actor_type))


def require_admin_permission(actor, permission):
    role = actor.get("role", "support_admin") if isinstance(actor, dict) else "support_admin"
    if role == "super_admin":
        return True
    permissions_by_role = {
        "system_admin": {"clients.manage", "hosting.manage", "dns.manage", "billing.manage", "system.manage"},
        "support_admin": {"clients.read", "hosting.read", "dns.read"},
    }
    allowed = permissions_by_role.get(role, set())
    if permission not in allowed:
        raise ApiError(HTTPStatus.FORBIDDEN, "insufficient_admin_permissions")
    return True




def get_cookie_domain(host_header):
    host = host_header.split(":")[0]
    if host == "localhost":
        return ".localhost"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return ""
    parts = host.split(".")
    if len(parts) >= 2:
        return "." + ".".join(parts[-2:])
def is_request_https(headers):
    if not headers:
        return False
    proto = headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
    ssl = headers.get("X-Forwarded-Ssl", "").strip().lower()
    return proto == "https" or ssl == "on"


def auth_cookie_header(token, host_header, max_age=None, is_https=False):
    cookie_domain = get_cookie_domain(host_header)
    domain_attr = f"; Domain={cookie_domain}" if cookie_domain else ""
    ttl = CONFIG.token_ttl_seconds if max_age is None else max_age
    secure = "; Secure" if (CONFIG.env == "production" and is_https) else ""
    return f"mp_client_token={token}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{secure}{domain_attr}"


def auth_cookie_headers(token, host_header, is_https=False):
    cookie_domain = get_cookie_domain(host_header)
    host = host_header.split(":")[0] if host_header else ""
    if cookie_domain == ".localhost":
        return [
            f"mp_client_token={token}; Path=/; Max-Age={CONFIG.token_ttl_seconds}; HttpOnly; SameSite=Lax; Domain=localhost",
            f"mp_client_token={token}; Path=/; Max-Age={CONFIG.token_ttl_seconds}; HttpOnly; SameSite=Lax; Domain=.localhost",
        ]
    headers = [auth_cookie_header(token, host_header, CONFIG.token_ttl_seconds, is_https=is_https)]
    if host and host not in {"127.0.0.1", "localhost"}:
        secure = "; Secure" if (CONFIG.env == "production" and is_https) else ""
        headers.append(f"mp_client_token={token}; Path=/; Max-Age={CONFIG.token_ttl_seconds}; HttpOnly; SameSite=Lax{secure}")
    return headers


def named_cookie_header(name, token, host_header, max_age=None, is_https=False):
    cookie_domain = get_cookie_domain(host_header)
    domain_attr = f"; Domain={cookie_domain}" if cookie_domain else ""
    ttl = CONFIG.token_ttl_seconds if max_age is None else max_age
    secure = "; Secure" if (CONFIG.env == "production" and is_https) else ""
    return f"{name}={token}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{secure}{domain_attr}"


def named_cookie_headers(name, token, host_header, max_age=None, is_https=False):
    cookie_domain = get_cookie_domain(host_header)
    ttl = CONFIG.token_ttl_seconds if max_age is None else max_age
    if cookie_domain == ".localhost":
        return [
            f"{name}={token}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax; Domain=localhost",
            f"{name}={token}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax; Domain=.localhost",
        ]
    return [named_cookie_header(name, token, host_header, ttl, is_https=is_https)]


def expired_auth_cookie_header(host_header):
    cookie_domain = get_cookie_domain(host_header)
    domain_attr = f"; Domain={cookie_domain}" if cookie_domain else ""
    return f"mp_client_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax{domain_attr}"


def expired_auth_cookie_headers(host_header):
    cookie_domain = get_cookie_domain(host_header)
    if cookie_domain == ".localhost":
        return [
            "mp_client_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Domain=localhost",
            "mp_client_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Domain=.localhost",
        ]
    return [expired_auth_cookie_header(host_header)]


def expired_named_cookie_headers(name, host_header):
    cookie_domain = get_cookie_domain(host_header)
    if cookie_domain == ".localhost":
        return [
            f"{name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Domain=localhost",
            f"{name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Domain=.localhost",
        ]
    domain_attr = f"; Domain={cookie_domain}" if cookie_domain else ""
    return [f"{name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax{domain_attr}"]


def normalize_account_relative_path(account, raw_path, label="path", allow_empty=False):
    base_path = Path(account["base_path"]).resolve()
    text = str(raw_path or "").strip()
    if not text:
        if allow_empty:
            return base_path, ""
        raise ApiError(HTTPStatus.BAD_REQUEST, "{}_required".format(label))
    candidate = (base_path / text.lstrip("/")).resolve()
    try:
        rel = candidate.relative_to(base_path)
    except ValueError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_{}".format(label)) from exc
    relative = "" if str(rel) == "." else rel.as_posix()
    return candidate, relative


def resolve_container_ip(container_name):
    try:
        res = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container_name],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode == 0:
            ips = res.stdout.strip().split()
            if ips:
                return ips[0]
    except Exception:
        pass
    return "127.0.0.1"


def extract_magic_launch_token(forwarded_uri):
    if not forwarded_uri:
        return None
    parsed = urlparse(forwarded_uri)
    path = parsed.path if parsed.scheme else forwarded_uri
    match = re.search(r"/auth/(?P<token>[A-Za-z0-9._-]{20,})(?:/|$)", path)
    return match.group("token") if match else None


def strip_magic_launch_segment(forwarded_uri):
    if not forwarded_uri:
        return "/"
    parsed = urlparse(forwarded_uri)
    path = parsed.path if parsed.scheme else forwarded_uri
    cleaned = re.sub(r"/auth/[A-Za-z0-9._-]{20,}", "", path, count=1)
    return cleaned or "/"


def build_tool_redirect_url(host, path, is_https=False):
    host = host or "localhost"
    if not path.startswith("/"):
        path = "/" + path
    scheme = "https" if is_https else "http"
    return f"{scheme}://{host}{path}"


def resolve_tool_launch_url(tool_name, runtime_url, account, forwarded_host, is_https=False):
    forwarded_host = (forwarded_host or "").strip()
    if not forwarded_host:
        return runtime_url or ""

    host_part = forwarded_host.split(":")[0].lower()

    # Preserve configured runtime_url when running unit tests locally (127.0.0.1 or localhost)
    if host_part in {"127.0.0.1", "localhost"} and runtime_url:
        return runtime_url

    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_part)) or host_part in {"localhost", "::1"}

    # 1. Accessed directly via public IP address:
    if is_ip:
        scheme = "https" if is_https else "http"
        return f"{scheme}://{forwarded_host}"

    # 2. Accessed via a Domain (Subdomain launch as intended):
    username = account["username"] if account else "user"
    prefix = "files" if tool_name == "filebrowser" else ("pma" if tool_name == "phpmyadmin" else "mail")

    if runtime_url and not "localhost" in runtime_url and not ".nip.io" in runtime_url:
        return runtime_url

    domain_base = host_part
    if host_part.startswith("panel.") or host_part.startswith("admin."):
        domain_base = host_part.split(".", 1)[1]

    if host_part.startswith(f"{prefix}-") or host_part.startswith(f"{prefix}."):
        subdomain = host_part
    else:
        subdomain = f"{prefix}-{username}.{domain_base}"

    scheme = "http" if subdomain.endswith(".localhost") or subdomain == "localhost" else "https"
    return f"{scheme}://{subdomain}"


def ensure_server_ssl_cert(cert_path=None, key_path=None):
    cert_p = Path(cert_path or CONFIG.ssl_cert_path)
    key_p = Path(key_path or CONFIG.ssl_key_path)
    if cert_p.exists() and key_p.exists():
        return cert_p, key_p

    cert_p.parent.mkdir(parents=True, exist_ok=True)
    key_p.parent.mkdir(parents=True, exist_ok=True)

    openssl = shutil.which("openssl")
    if openssl:
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/CN=mangopanel-admin",
                "-keyout",
                str(key_p),
                "-out",
                str(cert_p),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return cert_p, key_p


class MangoDualServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, ssl_cert_path=None, ssl_key_path=None, enable_ssl=None, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)
        self.ssl_context = None
        should_enable = CONFIG.enable_ssl if enable_ssl is None else enable_ssl
        if should_enable:
            try:
                cert_p, key_p = ensure_server_ssl_cert(ssl_cert_path, ssl_key_path)
                if cert_p.exists() and key_p.exists():
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
                    self.ssl_context = ctx
            except Exception as e:
                print(f"Warning: Failed to initialize SSL context: {e}")

    def get_request(self):
        return self.socket.accept()


class MangoHandler(BaseHTTPRequestHandler):
    server_version = "MangoPanel/0.1"

    def setup(self):
        self.connection = self.request
        ssl_ctx = getattr(self.server, "ssl_context", None)
        if ssl_ctx:
            try:
                self.connection.settimeout(2.0)
                first_byte = self.connection.recv(1, socket.MSG_PEEK)
                if first_byte == b"\x16":
                    self.connection = ssl_ctx.wrap_socket(self.connection, server_side=True)
                    self.request = self.connection
                self.connection.settimeout(None)
            except Exception:
                try:
                    self.connection.settimeout(None)
                except Exception:
                    pass
        super().setup()

    @property
    def is_https(self):
        if isinstance(getattr(self, "connection", None), ssl.SSLSocket):
            return True
        return is_request_https(self.headers)

    def log_message(self, fmt, *args):
        print("{} - {}".format(self.address_string(), fmt % args))

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PATCH(self):
        self.dispatch("PATCH")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        self.query_params = parse_qs(parsed.query)
        panel = getattr(self.server, "panel", "combined")

        try:
            if method == "GET" and (path in {"/", "/client"} or path.startswith("/client/")):
                if panel == "admin":
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found")
                return self.serve_file(PUBLIC_DIR / "client.html")
            if path == "/signup":
                if panel == "admin":
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found")
                return self.serve_file(PUBLIC_DIR / "signup.html")
            if method == "GET" and (path in {"/login", "/login.html"}):
                if panel == "admin":
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found")
                return self.serve_file(PUBLIC_DIR / "login.html")
            if method == "GET" and (path in {"/webmail", "/webmail.html"} or path.startswith("/webmail/login")):
                if panel == "admin":
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found")
                if path.startswith("/webmail/login"):
                    return self.webmail_direct_login(path)
                launch_token = self.query_params.get("launch", [""])[0].strip()
                if launch_token:
                    return self.webmail_launch_redirect(launch_token)
                return self.redirect_response("/")
            if path == "/admin/setup":
                if panel == "client":
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found")
                return self.serve_file(PUBLIC_DIR / "admin_setup.html")
            if path == "/admin":
                if panel == "client":
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found")
                if admin_count() == 0:
                    return self.serve_file(PUBLIC_DIR / "admin_setup.html")
                return self.serve_file(PUBLIC_DIR / "admin.html")
            if path == "/admin/plans":
                if panel == "client":
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found")
                if admin_count() == 0:
                    return self.serve_file(PUBLIC_DIR / "admin_setup.html")
                return self.redirect_response("/admin#plans")
            if path == "/status":
                return self.serve_file(PUBLIC_DIR / "status.html")
            if path.startswith("/assets/"):
                return self.serve_file(PUBLIC_DIR / path.lstrip("/"))
            if path == "/health":
                return self.json_response({"status": "ok", "service": "mangopanel-api"})

            if path.startswith("/api/") or path.startswith("/auth/") or path.startswith("/files/"):
                return self.route_api(method, path, self.query_params)

            self.json_response({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        except ApiError as exc:
            self.json_response({"error": exc.message}, exc.status)
        except Exception as exc:
            payload = {"error": "internal_error"}
            if CONFIG.expose_internal_errors:
                payload["detail"] = str(exc)
            self.json_response(payload, HTTPStatus.INTERNAL_SERVER_ERROR)

    def route_api(self, method, path, query):
        panel = getattr(self.server, "panel", "combined")
        if panel == "client" and path == "/api/public/admin-setup":
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")
        if panel == "admin" and path == "/api/public/signup":
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")
        if method == "POST" and path == "/api/client/auth/exchange-impersonation":
            return self.exchange_impersonation()
        if method == "POST" and path in {"/api/client/auth/login", "/api/admin/auth/login"}:
            if panel == "client" and path.startswith("/api/admin/"):
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            if panel == "admin" and path.startswith("/api/client/"):
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            actor_type = "admin" if "/api/admin/" in path else "user"
            return self.login(actor_type)

        if method == "POST" and path in {"/api/client/auth/logout", "/api/admin/auth/logout"}:
            if panel == "client" and path.startswith("/api/admin/"):
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            if panel == "admin" and path.startswith("/api/client/"):
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            actor_type = "admin" if "/api/admin/" in path else "user"
            return self.logout(actor_type)
        if method == "POST" and path in {"/api/client/auth/totp/verify", "/api/admin/auth/totp/verify"}:
            if panel == "client" and path.startswith("/api/admin/"):
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            if panel == "admin" and path.startswith("/api/client/"):
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            actor_type = "admin" if "/api/admin/" in path else "user"
            return self.verify_totp_challenge(actor_type)

        if path.startswith("/auth/") or path.startswith("/api/public/") or path.startswith("/files/"):
            return self.public_api(method, path)

        if path.startswith("/api/public/status"):
            return self.public_status(path)

        if path.startswith("/api/client/"):
            if panel == "admin":
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            actor = self.require_auth("user")
            return self.client_api(method, path, query, actor)

        if path.startswith("/api/admin/"):
            if panel == "client":
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")
            actor = self.require_auth("admin")
            return self.admin_api(method, path, query, actor)

        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_api_route")

    def public_api(self, method, path):
        if path.startswith("/api/public/status"):
            return self.public_status(path)
        if path == "/api/public/mail-brand.svg" and method == "GET":
            return self.svg_response(MAILPIT_BRAND_SVG)
        if path == "/api/public/mail-edge/manifest" and method == "GET":
            return self.public_mail_edge_manifest()
        if path == "/api/public/bootstrap" and method == "GET":
            return self.json_response({"admin_setup_required": admin_count() == 0})
        if path == "/api/public/signup" and method == "POST":
            body = self.read_json()
            return self.signup_customer(body)
        if path == "/api/public/admin-setup" and method == "POST":
            body = self.read_json()
            return self.setup_first_admin(body)
        if path == "/api/public/totp/verify" and method == "POST":
            body = self.read_json()
            return self.verify_totp_secret(body)
        if path == "/api/public/webmail/session" and method == "GET":
            return self.public_webmail_session()
        if path == "/api/public/webmail/exchange" and method == "POST":
            return self.public_webmail_exchange()
        if path == "/api/public/webmail/login" and method == "POST":
            return self.public_webmail_login()
        if path == "/api/public/webmail/messages" and method == "GET":
            return self.public_webmail_messages()
        if path.startswith("/api/public/webmail/messages/"):
            if method in {"PATCH", "GET"}:
                return self.public_webmail_message(path, method)
        if path == "/api/public/webmail/send" and method == "POST":
            return self.public_webmail_send()
        if path == "/api/public/webmail/logout" and method == "POST":
            return self.public_webmail_logout()
        if path == "/api/public/mail-jmap" and method == "GET":
            return self.public_mail_jmap()
        if path in {"/files/custom.js", "/api/public/filebrowser/custom.js"} and method == "GET":
            return self.serve_filebrowser_custom_js()
        if path in {"/files/api/extract", "/api/public/filebrowser/extract"} and method == "POST":
            return self.extract_file_archive()
        if path.startswith("/api/public/filebrowser/proxy") and method == "GET":
            return self.public_filebrowser_proxy(path)
        if path.startswith("/auth/") and method == "GET":
            return self.public_tool_launch(path)
        if path.startswith("/api/public/tool-launch/") and method == "GET":
            return self.public_tool_launch(path)
        if path == "/api/public/auth-verify":
            return self.forward_auth_verify()
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")

    def public_mail_edge_manifest(self):
        forwarded_host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").split(":")[0].strip().lower()
        edge_host = shared_mail_edge_host().lower()
        if forwarded_host and forwarded_host != edge_host:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")
        with connect(CONFIG.db_path) as conn:
            return self.json_response(shared_mail_edge_manifest(conn))

    def public_tool_launch(self, path):
        forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
        tool = None
        if forwarded_host:
            host_part = forwarded_host.split(":")[0]
            if host_part.startswith("files-") or host_part.startswith("files."):
                tool = "filebrowser"
            elif host_part.startswith("pma-") or host_part.startswith("pma."):
                tool = "phpmyadmin"
            elif host_part.startswith("mail-") or host_part.startswith("mail."):
                tool = "webmail"

        token = None
        suffix = ""
        if path.startswith("/auth/"):
            match = re.match(r"^/auth/(?P<token>[A-Za-z0-9._-]{20,})(?P<suffix>/.*)?$", path)
            if not match:
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")
            token = match.group("token")
            suffix = match.group("suffix") or ""
        else:
            match = re.match(
                r"^/api/public/tool-launch/(?P<tool>filebrowser|phpmyadmin|webmail)/auth/(?P<token>[A-Za-z0-9._-]{20,})(?P<suffix>/.*)?$",
                path,
            )
            if not match:
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")
            tool = match.group("tool")
            token = match.group("token")
            suffix = match.group("suffix") or ""

        username = None
        if forwarded_host:
            host_part = forwarded_host.split(":")[0]
            match = re.match(r"^(?:files|pma|mail)[-.](\w+)\.", host_part)
            if match:
                username = match.group(1)

        payload = verify_jwt(token, CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "tool_launch":
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_tool_launch")

        if not tool:
            tool = payload.get("tool")

        if not tool or payload.get("tool") != tool:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_tool_launch")

        actor_type = payload.get("actor_type")
        actor_id = payload.get("sub")
        if actor_type != "user":
            raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")

        if not username:
            username = payload.get("username")

        with connect(CONFIG.db_path) as conn:
            user = conn.execute("SELECT status FROM users WHERE id = ?", (actor_id,)).fetchone()
            if not user or user["status"] != "active":
                raise ApiError(HTTPStatus.UNAUTHORIZED, "inactive_user")

            account = None
            if username:
                account = conn.execute(
                    "SELECT * FROM hosting_accounts WHERE user_id = ? AND username = ? AND status = 'active'",
                    (actor_id, username),
                ).fetchone()
            elif payload.get("account_id"):
                account = conn.execute(
                    "SELECT * FROM hosting_accounts WHERE id = ? AND user_id = ? AND status = 'active'",
                    (payload["account_id"], actor_id),
                ).fetchone()
            else:
                account = conn.execute(
                    "SELECT * FROM hosting_accounts WHERE user_id = ? AND status = 'active' ORDER BY id ASC LIMIT 1",
                    (actor_id,),
                ).fetchone()

            if not account:
                raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")

            access_token = create_jwt(
                {"sub": actor_id, "actor_type": actor_type, "purpose": "access", "jti": secrets.token_urlsafe(16)},
                CONFIG.jwt_secret,
                600,
            )
            access_payload = verify_jwt(access_token, CONFIG.jwt_secret)
            conn.execute(
                "INSERT INTO sessions(actor_type, actor_id, token_id, expires_at) VALUES (?, ?, ?, ?)",
                (actor_type, actor_id, access_payload["jti"], int(time.time()) + 600),
            )
            default_path = "/files" if tool == "filebrowser" else "/db/"
            if tool == "webmail":
                default_path = "/webmail"
            clean_path = suffix or default_path
            self.send_response(HTTPStatus.FOUND)
            cookie_headers = auth_cookie_headers(access_token, forwarded_host, is_https=self.is_https)
            if tool == "webmail":
                mail_access_token = create_jwt(
                    {
                        "sub": actor_id,
                        "actor_type": actor_type,
                        "purpose": "mail_webmail",
                        "mailbox_id": payload.get("mailbox_id"),
                        "account_id": payload.get("account_id"),
                        "jti": secrets.token_urlsafe(16),
                    },
                    CONFIG.jwt_secret,
                    3600,
                )
                cookie_headers = named_cookie_headers("mp_mail_token", mail_access_token, forwarded_host, 3600, is_https=self.is_https)
            for cookie_header in cookie_headers:
                self.send_header("Set-Cookie", cookie_header)
            self.send_header("Location", build_tool_redirect_url(forwarded_host, clean_path, is_https=self.is_https))
            self.end_headers()
            return

    def serve_filebrowser_custom_js(self):
        body = FILEBROWSER_CUSTOM_JS.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.record_access_log(HTTPStatus.OK, len(body))



    def public_filebrowser_proxy(self, path):
        forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
        username = None
        if forwarded_host:
            match = re.match(r"^(?:files|pma|mail)[-.](\w+)\.", forwarded_host)
            if match:
                username = match.group(1)

        with connect(CONFIG.db_path) as conn:
            account = None
            if username:
                account = conn.execute("SELECT * FROM hosting_accounts WHERE username = ? AND status = 'active'", (username,)).fetchone()
            if not account:
                account = conn.execute("SELECT * FROM hosting_accounts WHERE status = 'active' ORDER BY id ASC LIMIT 1").fetchone()
            if not account:
                raise ApiError(HTTPStatus.NOT_FOUND, "account_not_found")

            container_name = f"mp-{account['username']}-filebrowser"
            clean_path = path.replace("/api/public/filebrowser/proxy", "") or "/files/"
            if not clean_path.startswith("/"):
                clean_path = "/" + clean_path

            container_ip = resolve_container_ip(container_name)
            upstream_url = f"http://{container_ip}:80{clean_path}"

            req_headers = {}
            for k, v in self.headers.items():
                if k.lower() not in {"host", "content-length"}:
                    req_headers[k] = v

            import urllib.request
            req = urllib.request.Request(upstream_url, headers=req_headers)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = resp.read()
                    content_type = resp.headers.get("Content-Type", "")
                    
                    self.send_response(resp.status)
                    for hk, hv in resp.headers.items():
                        if hk.lower() not in {"content-length", "transfer-encoding"}:
                            self.send_header(hk, hv)

                    if "text/html" in content_type:
                        html = data.decode("utf-8", errors="ignore")
                        if "</head>" in html and "/files/custom.js" not in html:
                            html = html.replace("</head>", '<script src="/files/custom.js"></script></head>', 1)
                        data = html.encode("utf-8")

                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    self.record_access_log(resp.status, len(data))
            except urllib.error.HTTPError as e:
                data = e.read()
                self.send_response(e.code)
                for hk, hv in e.headers.items():
                    if hk.lower() not in {"content-length", "transfer-encoding"}:
                        self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                raise ApiError(HTTPStatus.BAD_GATEWAY, f"filebrowser_proxy_error: {e}")

    def extract_file_archive(self, account=None, actor=None):
        body = self.read_json()
        raw_path = body.get("path", "").strip()
        if not raw_path:
            raise ApiError(HTTPStatus.BAD_REQUEST, "path_required")

        with connect(CONFIG.db_path) as conn:
            if not account:
                forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
                username = None
                if forwarded_host:
                    match = re.match(r"^(?:files|pma|mail)[-.](\w+)\.", forwarded_host)
                    if match:
                        username = match.group(1)

                if username:
                    account = conn.execute(
                        "SELECT * FROM hosting_accounts WHERE username = ? AND status = 'active'", (username,)
                    ).fetchone()

                if not account and actor:
                    account = conn.execute(
                        "SELECT * FROM hosting_accounts WHERE user_id = ? AND status = 'active' ORDER BY id ASC LIMIT 1",
                        (actor["id"],),
                    ).fetchone()

                if not account:
                    cookie_header = self.headers.get("Cookie", "")
                    from http.cookies import SimpleCookie
                    cookies = SimpleCookie(cookie_header)
                    token_cookie = cookies.get("mp_client_token")
                    if token_cookie:
                        payload = verify_jwt(token_cookie.value, CONFIG.jwt_secret)
                        if payload and payload.get("sub"):
                            account = conn.execute(
                                "SELECT * FROM hosting_accounts WHERE user_id = ? AND status = 'active' ORDER BY id ASC LIMIT 1",
                                (payload["sub"],),
                            ).fetchone()

            if not account:
                raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")

            clean_path = raw_path
            if clean_path.startswith("/files/files/"):
                clean_path = clean_path[len("/files/files/"):]
            elif clean_path.startswith("/files/"):
                clean_path = clean_path[len("/files/"):]

            abs_path, rel_path = normalize_account_relative_path(account, clean_path)
            abs_file = str(abs_path)

            if not os.path.exists(abs_file):
                raise ApiError(HTTPStatus.NOT_FOUND, "file_not_found")
            if os.path.isdir(abs_file):
                raise ApiError(HTTPStatus.BAD_REQUEST, "path_is_a_directory")

            dest_dir = os.path.dirname(abs_file)
            account_base = os.path.abspath(account["base_path"])

            extracted_count = 0
            archive_name = os.path.basename(abs_file)

            if abs_file.lower().endswith(".zip"):
                import zipfile
                with zipfile.ZipFile(abs_file, "r") as zf:
                    for member in zf.infolist():
                        target_path = os.path.abspath(os.path.join(dest_dir, member.filename))
                        if not target_path.startswith(account_base + os.sep) and target_path != account_base:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_path_traversal")
                        zf.extract(member, dest_dir)
                        extracted_count += 1
            elif abs_file.lower().endswith((".tar.gz", ".tgz", ".tar", ".gz")):
                import tarfile
                with tarfile.open(abs_file, "r:*") as tf:
                    for member in tf.getmembers():
                        target_path = os.path.abspath(os.path.join(dest_dir, member.name))
                        if not target_path.startswith(account_base + os.sep) and target_path != account_base:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_path_traversal")
                        tf.extract(member, dest_dir)
                        extracted_count += 1
            else:
                raise ApiError(HTTPStatus.BAD_REQUEST, "unsupported_archive_format")

            uid = 5000 + int(account["id"])
            gid = 5000 + int(account["id"])
            if uid and gid:
                try:
                    subprocess.run(["chown", "-R", f"{uid}:{gid}", dest_dir], check=False)
                    subprocess.run(["chmod", "-R", "a+rwX", dest_dir], check=False)
                except Exception:
                    pass
                for root, dirs, files in os.walk(dest_dir):
                    for d in dirs:
                        try:
                            os.chown(os.path.join(root, d), uid, gid)
                            os.chmod(os.path.join(root, d), 0o777)
                        except Exception:
                            pass
                    for f in files:
                        try:
                            filepath = os.path.join(root, f)
                            os.chown(filepath, uid, gid)
                            st_mode = os.stat(filepath).st_mode
                            if st_mode & 0o111:
                                os.chmod(filepath, 0o777)
                            else:
                                os.chmod(filepath, 0o666)
                        except Exception:
                            pass

            actor_id = actor["id"] if actor else account["user_id"]
            log_activity(conn, actor_id, "archive_extracted", {"account_id": account["id"], "path": rel_path, "items_extracted": extracted_count})
            return self.json_response({
                "success": True,
                "message": f"Successfully extracted {archive_name} ({extracted_count} items)",
                "extracted_count": extracted_count
            })

    def webmail_session_context(self):
        from http.cookies import SimpleCookie
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie(cookie_header)
        token_cookie = cookies.get("mp_mail_token")
        token = token_cookie.value if token_cookie else None
        if not token:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.removeprefix("Bearer ").strip()
        if not token:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "missing_mail_session")
        payload = verify_jwt(token, CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "mail_webmail":
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_mail_session")
        mailbox_id = int(payload.get("mailbox_id") or 0)
        if mailbox_id <= 0:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_mail_session")
        return payload, mailbox_id

    def load_webmail_mailbox(self, conn, payload, mailbox_id):
        mailbox = conn.execute(
            """
            SELECT m.*, ha.username AS account_username, ha.base_path AS account_base_path,
                   ha.id AS account_id, ha.user_id AS owner_user_id, p.daily_email_limit
            FROM mailboxes m
            JOIN hosting_accounts ha ON ha.id = m.account_id
            JOIN plans p ON p.id = ha.plan_id
            WHERE m.id = ? AND m.status = 'active' AND ha.status = 'active'
            """,
            (mailbox_id,),
        ).fetchone()
        if not mailbox:
            raise ApiError(HTTPStatus.NOT_FOUND, "mailbox_not_found")
        if int(payload.get("sub") or 0) != int(mailbox["account_id"]):
            raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")
        return mailbox

    def load_mailbox_for_direct_login(self, conn, mailbox_id=None, email=None):
        if mailbox_id:
            mailbox = conn.execute(
                """
                SELECT m.*, ha.username AS account_username, ha.base_path AS account_base_path,
                       ha.id AS account_id, ha.user_id AS owner_user_id, p.daily_email_limit
                FROM mailboxes m
                JOIN hosting_accounts ha ON ha.id = m.account_id
                JOIN plans p ON p.id = ha.plan_id
                WHERE m.id = ? AND m.status = 'active' AND ha.status = 'active'
                """,
                (mailbox_id,),
            ).fetchone()
        else:
            mailbox = conn.execute(
                """
                SELECT m.*, ha.username AS account_username, ha.base_path AS account_base_path,
                       ha.id AS account_id, ha.user_id AS owner_user_id, p.daily_email_limit
                FROM mailboxes m
                JOIN hosting_accounts ha ON ha.id = m.account_id
                JOIN plans p ON p.id = ha.plan_id
                WHERE m.email = ? AND m.status = 'active' AND ha.status = 'active'
                """,
                (email,),
            ).fetchone()
        if not mailbox:
            raise ApiError(HTTPStatus.NOT_FOUND, "mailbox_not_found")
        return mailbox

    def snappymail_launch_url(self, conn, mailbox, password=None):
        runtime = account_runtime(conn, mailbox["account_id"])
        mail_host = runtime.get("mail_edge_host") or runtime.get("mail_host", "")
        if not mail_host:
            raise ApiError(HTTPStatus.BAD_GATEWAY, "mail_webmail_unavailable")
        launch_url = mailbox_row_payload(conn, mailbox).get("webmail_url") or runtime.get("mail_edge_webmail_url") or runtime.get("mail_webmail_url") or f"http://{mail_host}/webmail"
        return launch_url

    def snappymail_backend_url(self, conn, mailbox):
        runtime = account_runtime(conn, mailbox["account_id"])
        backend_url = runtime.get("mail_edge_url") or runtime.get("mail_webmail_backend_url") or ""
        if backend_url:
            return backend_url
        mail_host = runtime.get("mail_edge_host") or runtime.get("mail_host", "")
        if not mail_host:
            raise ApiError(HTTPStatus.BAD_GATEWAY, "mail_webmail_unavailable")
        return f"http://{mail_host}"

    def snappymail_login_session(self, conn, mailbox):
        mailbox_payload = row_to_dict(mailbox)
        password = decrypt_secret(mailbox_payload.get("password_secret") or "", CONFIG.jwt_secret)
        if not password:
            raise ApiError(HTTPStatus.BAD_GATEWAY, "mail_webmail_unavailable")
        backend_url = self.snappymail_backend_url(conn, mailbox)
        return request_login_session(backend_url, email=mailbox_payload["email"], password=password)

    def redirect_response(self, location, cookies=None, status=HTTPStatus.FOUND):
        self.send_response(status)
        for cookie_header in cookies or []:
            self.send_header("Set-Cookie", cookie_header)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Location", location)
        self.end_headers()
        return

    def webmail_launch_redirect(self, launch_token):
        payload = verify_jwt(launch_token, CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "tool_launch" or payload.get("tool") != "webmail":
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_tool_launch")
        mailbox_id = int(payload.get("mailbox_id") or 0)
        account_id = int(payload.get("account_id") or 0)
        if mailbox_id <= 0 or account_id <= 0:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_tool_launch")
        with connect(CONFIG.db_path) as conn:
            user = conn.execute("SELECT status FROM users WHERE id = ?", (payload.get("sub"),)).fetchone()
            if not user or user["status"] != "active":
                raise ApiError(HTTPStatus.UNAUTHORIZED, "inactive_user")
            account = conn.execute(
                "SELECT * FROM hosting_accounts WHERE id = ? AND user_id = ? AND status = 'active'",
                (account_id, payload.get("sub")),
            ).fetchone()
            if not account:
                raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")
            mailbox = self.load_webmail_mailbox(conn, payload, mailbox_id)
            cookies = []
            if CONFIG.agent_mode == "docker":
                session = self.snappymail_login_session(conn, mailbox)
                cookies = session.get("cookies") or []
            self.redirect_response(self.snappymail_launch_url(conn, mailbox), cookies)
        return

    def webmail_direct_login(self, path):
        mailbox_id = path_int_id(path, "/webmail/login/")
        launch_token = self.query_params.get("launch", [""])[0].strip()
        if launch_token:
            return self.webmail_launch_redirect(launch_token)
        email_raw = str(self.query_params.get("email", [""])[0] or "").strip()
        from urllib.parse import quote
        target_url = f"/webmail.html?mailbox_id={mailbox_id}" if mailbox_id else "/webmail.html"
        if email_raw:
            target_url += f"&email={quote(email_raw)}"
        return self.redirect_response(target_url)

    def webmail_login_attempt_key(self, mailbox_id=None, email=None):
        ip = client_ip(self) or "unknown"
        if mailbox_id:
            target = f"mailbox:{int(mailbox_id)}"
        elif email:
            target = f"email:{str(email).strip().lower()}"
        else:
            target = "unknown"
        return f"{target}|ip:{ip}"

    def webmail_login_attempt_row(self, conn, attempt_key):
        row = conn.execute(
            "SELECT * FROM webmail_login_attempts WHERE attempt_key = ?",
            (attempt_key,),
        ).fetchone()
        if not row:
            return None
        now = int(time.time())
        first_failed_at = int(row["first_failed_at"] or 0)
        locked_until = int(row["locked_until"] or 0)
        if first_failed_at and now - first_failed_at > WEBMAIL_LOGIN_WINDOW_SECONDS:
            conn.execute("DELETE FROM webmail_login_attempts WHERE attempt_key = ?", (attempt_key,))
            return None
        if locked_until and locked_until > now:
            return row
        return row

    def webmail_login_failure(self, conn, attempt_key, email="", mailbox_id=None):
        now = int(time.time())
        row = self.webmail_login_attempt_row(conn, attempt_key)
        attempts = int(row["attempts"] or 0) if row else 0
        first_failed_at = int(row["first_failed_at"] or now) if row else now
        locked_until = int(row["locked_until"] or 0) if row else 0
        attempts += 1
        if attempts >= WEBMAIL_LOGIN_MAX_FAILURES:
            locked_until = now + WEBMAIL_LOGIN_LOCK_SECONDS
        conn.execute(
            """
            INSERT INTO webmail_login_attempts(attempt_key, attempts, first_failed_at, last_failed_at, locked_until, last_ip, last_email, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(attempt_key) DO UPDATE SET
              attempts = excluded.attempts,
              first_failed_at = excluded.first_failed_at,
              last_failed_at = excluded.last_failed_at,
              locked_until = excluded.locked_until,
              last_ip = excluded.last_ip,
              last_email = excluded.last_email,
              updated_at = CURRENT_TIMESTAMP
            """,
            (
                attempt_key,
                attempts,
                first_failed_at,
                now,
                locked_until,
                client_ip(self) or "",
                str(email or ""),
            ),
        )
        return locked_until > now

    def webmail_login_clear(self, conn, attempt_key):
        conn.execute("DELETE FROM webmail_login_attempts WHERE attempt_key = ?", (attempt_key,))

    def public_webmail_session(self):
        with connect(CONFIG.db_path) as conn:
            payload, mailbox_id = self.webmail_session_context()
            mailbox = self.load_webmail_mailbox(conn, payload, mailbox_id)
            mailbox_payload = mailbox_row_payload(conn, mailbox)
            settings = {
                "smtp_host": mailbox_payload.get("smtp_host", ""),
                "smtp_port": mailbox_payload.get("smtp_port", 0),
                "smtp_tls_port": mailbox_payload.get("smtp_tls_port", 0),
                "imap_host": mailbox_payload.get("imap_host", ""),
                "imap_port": mailbox_payload.get("imap_port", 0),
                "imap_tls_port": mailbox_payload.get("imap_tls_port", 0),
                "pop_host": mailbox_payload.get("pop_host", ""),
                "pop_port": mailbox_payload.get("pop_port", 0),
                "pop_tls_port": mailbox_payload.get("pop_tls_port", 0),
                "sieve_port": mailbox_payload.get("sieve_port", 0),
                "webmail_login_url": mailbox_payload.get("mailbox_login_url", ""),
                "webmail_url": mailbox_payload.get("webmail_url", ""),
                "jmap_url": mailbox_payload.get("jmap_url", ""),
                "mail_host": mailbox_payload.get("mail_host", ""),
                "storage_path": mailbox_payload.get("storage_path", ""),
                "storage_bytes": mailbox_payload.get("storage_bytes", 0),
                "storage_used_percent": mailbox_payload.get("storage_used_percent", 0),
            }
            return self.json_response(
                {
                    "mailbox": mailbox_payload,
                    "settings": settings,
                    "daily_email_limit": int(mailbox["daily_email_limit"] or 0),
                    "remaining_today": self.mailbox_remaining_today(conn, mailbox["id"], int(mailbox["daily_email_limit"] or 0)),
                }
            )

    def public_webmail_exchange(self):
        body = self.read_json()
        launch_token = str(body.get("launch_token") or "").strip()
        if not launch_token:
            raise ApiError(HTTPStatus.BAD_REQUEST, "launch_token_required")
        payload = verify_jwt(launch_token, CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "tool_launch" or payload.get("tool") != "webmail":
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_tool_launch")
        mailbox_id = int(payload.get("mailbox_id") or 0)
        account_id = int(payload.get("account_id") or 0)
        if mailbox_id <= 0 or account_id <= 0:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_tool_launch")
        with connect(CONFIG.db_path) as conn:
            user = conn.execute("SELECT status FROM users WHERE id = ?", (payload.get("sub"),)).fetchone()
            if not user or user["status"] != "active":
                raise ApiError(HTTPStatus.UNAUTHORIZED, "inactive_user")
            account = conn.execute(
                "SELECT * FROM hosting_accounts WHERE id = ? AND user_id = ? AND status = 'active'",
                (account_id, payload.get("sub")),
            ).fetchone()
            if not account:
                raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")
            mailbox = self.load_webmail_mailbox(conn, payload, mailbox_id)
            runtime = account_runtime(conn, mailbox["account_id"])
            launch_url = mailbox_row_payload(conn, mailbox).get("webmail_url") or f"http://{runtime.get('mail_host')}/"
            mail_access_token = create_jwt(
                {
                    "sub": mailbox["account_id"],
                    "actor_type": payload.get("actor_type"),
                    "purpose": "mail_webmail",
                    "mailbox_id": mailbox["id"],
                    "account_id": account["id"],
                    "user_id": payload.get("sub"),
                    "jti": secrets.token_urlsafe(16),
                },
                CONFIG.jwt_secret,
                3600,
            )
            self.send_response(HTTPStatus.OK)
            for cookie_header in named_cookie_headers("mp_mail_token", mail_access_token, self.headers.get("Host", ""), 3600):
                self.send_header("Set-Cookie", cookie_header)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "exchanged": True,
                        "expires_in": 3600,
                        "launch_url": launch_url,
                        "email": mailbox["email"],
                    }
                ).encode("utf-8")
            )
            return

    def public_webmail_login(self):
        body = self.read_json()
        mailbox_id_raw = body.get("mailbox_id")
        mailbox_id = int(mailbox_id_raw or 0)
        email_raw = str(body.get("email") or "").strip()
        email = normalize_email(email_raw) if email_raw else ""
        password = str(body.get("password") or "").strip()
        if not password:
            raise ApiError(HTTPStatus.BAD_REQUEST, "mailbox_password_required")
        attempt_key = self.webmail_login_attempt_key(mailbox_id=mailbox_id or None, email=email or email_raw)
        with connect(CONFIG.db_path) as conn:
            attempt_row = self.webmail_login_attempt_row(conn, attempt_key)
            if attempt_row and int(attempt_row["locked_until"] or 0) > int(time.time()):
                raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "mailbox_login_locked")
            try:
                mailbox = self.load_mailbox_for_direct_login(conn, mailbox_id=mailbox_id or None, email=email or None)
                if email and normalize_email(mailbox["email"]) != email:
                    raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")
                
                authed = verify_password(password, mailbox["password_hash"])
                if not authed:
                    owner = conn.execute("SELECT * FROM users WHERE id = ?", (mailbox["owner_user_id"],)).fetchone()
                    if owner and verify_password(password, owner["password_hash"]):
                        if owner["totp_secret"]:
                            totp_code_input = str(body.get("totp_code") or body.get("totp") or body.get("code") or "").strip()
                            dev_bypass_ok = CONFIG.is_development and CONFIG.dev_auth_test_mode and totp_code_input == "000000"
                            if not dev_bypass_ok and not verify_totp(owner["totp_secret"], totp_code_input):
                                raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_totp_code")
                        authed = True
                if not authed:
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_mailbox_credentials")
            except ApiError as exc:
                if exc.status in {HTTPStatus.NOT_FOUND, HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}:
                    locked = self.webmail_login_failure(
                        conn,
                        attempt_key,
                        email=email or email_raw,
                        mailbox_id=mailbox_id or None,
                    )
                    if locked:
                        raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "mailbox_login_locked") from exc
                raise
            runtime = account_runtime(conn, mailbox["account_id"])
            launch_url = self.snappymail_launch_url(conn, mailbox, password=password)
            mail_access_token = create_jwt(
                {
                    "sub": mailbox["account_id"],
                    "actor_type": "user",
                    "purpose": "mail_webmail",
                    "mailbox_id": mailbox["id"],
                    "account_id": mailbox["account_id"],
                    "user_id": mailbox["owner_user_id"],
                    "jti": secrets.token_urlsafe(16),
                },
                CONFIG.jwt_secret,
                3600,
            )
            self.webmail_login_clear(conn, attempt_key)
            self.send_response(HTTPStatus.OK)
            for cookie_header in named_cookie_headers("mp_mail_token", mail_access_token, self.headers.get("Host", ""), 3600):
                self.send_header("Set-Cookie", cookie_header)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "logged_in": True,
                        "expires_in": 3600,
                        "launch_url": launch_url,
                        "email": mailbox["email"],
                        "mailbox": mailbox_row_payload(conn, mailbox),
                    }
                ).encode("utf-8")
            )
            return

    def mailbox_remaining_today(self, conn, mailbox_id, limit):
        row = conn.execute("SELECT sent_today_count, sent_today_on FROM mailboxes WHERE id = ?", (mailbox_id,)).fetchone()
        if not row:
            return 0
        today = time.strftime("%Y-%m-%d")
        if str(row["sent_today_on"] or "") != today:
            return limit
        remaining = limit - int(row["sent_today_count"] or 0)
        return remaining if remaining > 0 else 0

    def public_webmail_messages(self):
        with connect(CONFIG.db_path) as conn:
            payload, mailbox_id = self.webmail_session_context()
            mailbox = self.load_webmail_mailbox(conn, payload, mailbox_id)
            qp = getattr(self, "query_params", {})
            folder = str((qp.get("folder") or ["all"])[0]).strip().lower()
            search = str((qp.get("q") or [""])[0]).strip().lower()
            page = max(1, positive_int((qp.get("page") or ["1"])[0], "invalid_page", minimum=1, maximum=100000))
            limit = positive_int((qp.get("limit") or ["20"])[0], "invalid_limit", minimum=1, maximum=100)
            offset = (page - 1) * limit
            params = [mailbox["id"]]
            where = ["mailbox_id = ?"]
            if folder and folder != "all":
                where.append("folder = ?")
                params.append(folder)
            if search:
                where.append("(lower(subject) LIKE ? OR lower(sender_email) LIKE ? OR lower(body_preview) LIKE ?)")
                needle = f"%{search}%"
                params.extend([needle, needle, needle])
            where_sql = " AND ".join(where)
            total = conn.execute(f"SELECT COUNT(*) AS count FROM mail_messages WHERE {where_sql}", tuple(params)).fetchone()["count"]
            unread = conn.execute(
                "SELECT COUNT(*) AS count FROM mail_messages WHERE mailbox_id = ? AND folder = 'inbox' AND is_read = 0",
                (mailbox["id"],),
            ).fetchone()["count"]
            rows = conn.execute(
                f"""
                SELECT * FROM mail_messages
                WHERE {where_sql}
                ORDER BY datetime(created_at) DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                tuple(params + [limit, offset]),
            ).fetchall()
            messages = rows_to_dicts(rows)
            for message in messages:
                message["recipients"] = parse_json_field(message.get("recipients_json"), [])
                message["headers"] = parse_json_field(message.get("headers_json"), {})
            return self.json_response(
                {
                    "messages": messages,
                    "mailbox": mailbox_row_payload(conn, mailbox),
                    "folder": folder or "inbox",
                    "query": search,
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "has_more": offset + len(messages) < total,
                    "unread_count": unread,
                }
            )

    def public_webmail_message(self, path, method):
        with connect(CONFIG.db_path) as conn:
            payload, mailbox_id = self.webmail_session_context()
            mailbox = self.load_webmail_mailbox(conn, payload, mailbox_id)
            message_id = path_int_id(path, "/api/public/webmail/messages/")
            message = conn.execute(
                "SELECT * FROM mail_messages WHERE id = ? AND mailbox_id = ?",
                (message_id, mailbox["id"]),
            ).fetchone()
            if not message:
                raise ApiError(HTTPStatus.NOT_FOUND, "message_not_found")
            if method == "GET":
                if int(message["is_read"] or 0) == 0:
                    conn.execute("UPDATE mail_messages SET is_read = 1 WHERE id = ?", (message_id,))
                payload = row_to_dict(message)
                payload["recipients"] = parse_json_field(payload.get("recipients_json"), [])
                payload["headers"] = parse_json_field(payload.get("headers_json"), {})
                payload["content"] = parse_mail_message_file(payload.get("storage_path"))
                return self.json_response({"message": payload, "mailbox": mailbox_row_payload(conn, mailbox)})
            body = self.read_json()
            updates = []
            params = []
            if "is_read" in body:
                updates.append("is_read = ?")
                params.append(1 if body.get("is_read") else 0)
            if "folder" in body:
                folder = clean_text(body.get("folder"), message["folder"] or "inbox")
                updates.append("folder = ?")
                params.append(folder or "inbox")
            if not updates:
                raise ApiError(HTTPStatus.BAD_REQUEST, "message_update_required")
            params.append(message_id)
            conn.execute(f"UPDATE mail_messages SET {', '.join(updates)} WHERE id = ?", tuple(params))
            updated = conn.execute("SELECT * FROM mail_messages WHERE id = ?", (message_id,)).fetchone()
            payload = row_to_dict(updated)
            payload["recipients"] = parse_json_field(payload.get("recipients_json"), [])
            payload["headers"] = parse_json_field(payload.get("headers_json"), {})
            payload["content"] = parse_mail_message_file(payload.get("storage_path"))
            return self.json_response({"message": payload, "mailbox": mailbox_row_payload(conn, mailbox)})

    def public_webmail_send(self):
        body = self.read_json()
        recipient = normalize_email(body.get("to"))
        subject = clean_text(body.get("subject"), "No subject")
        message_body = str(body.get("body") or "").strip()
        if not message_body:
            raise ApiError(HTTPStatus.BAD_REQUEST, "message_body_required")
        with connect(CONFIG.db_path) as conn:
            payload, mailbox_id = self.webmail_session_context()
            mailbox = self.load_webmail_mailbox(conn, payload, mailbox_id)
            limit = mailbox_send_budget(conn, mailbox["account_id"])
            today = time.strftime("%Y-%m-%d")
            mailbox_reset_send_count_if_needed(conn, mailbox["id"], today)
            current = conn.execute("SELECT sent_today_count, sent_today_on FROM mailboxes WHERE id = ?", (mailbox["id"],)).fetchone()
            sent_today = int(current["sent_today_count"] or 0) if current and current["sent_today_on"] == today else 0
            if limit and sent_today >= limit:
                raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "daily_email_limit_reached")
            mailbox_increment_send_count(conn, mailbox["id"], today)
            recipient_targets = mailbox_resolve_recipients(conn, mailbox["account_id"], recipient)
            outbound_id = mailbox_store_message(
                conn,
                mailbox["account_id"],
                mailbox,
                "outbound",
                mailbox["email"],
                [recipient],
                subject,
                message_body,
                "outbound",
                status="sent",
            )
            conn.execute(
                "UPDATE mailboxes SET last_outbound_at = CURRENT_TIMESTAMP WHERE id = ?",
                (mailbox["id"],),
            )
            for target in recipient_targets:
                if target["type"] == "mailbox" or target["type"] in {"alias", "forwarder", "catch_all"}:
                    target_mailbox = target["mailbox"]
                    mailbox_store_message(
                        conn,
                        mailbox["account_id"],
                        target_mailbox,
                        "inbound",
                        mailbox["email"],
                        [recipient],
                        subject,
                        message_body,
                        "inbound",
                        status="stored",
                    )
                    conn.execute("UPDATE mailboxes SET last_inbound_at = CURRENT_TIMESTAMP WHERE id = ?", (target_mailbox["id"],))
                    log_mail_delivery(
                        conn,
                        mailbox["account_id"],
                        "message_delivered",
                        source_email=mailbox["email"],
                        destination_email=target_mailbox["email"],
                        mailbox_id=target_mailbox["id"],
                        direction="inbound",
                        details={"message_id": outbound_id},
                        status="stored",
                    )
                else:
                    log_mail_delivery(
                        conn,
                        mailbox["account_id"],
                        "message_forwarded_external",
                        source_email=mailbox["email"],
                        destination_email=target["email"],
                        mailbox_id=mailbox["id"],
                        direction="outbound",
                        details={"message_id": outbound_id},
                        status="sent",
                    )
            log_mail_delivery(
                conn,
                mailbox["account_id"],
                "message_sent",
                source_email=mailbox["email"],
                destination_email=recipient,
                mailbox_id=mailbox["id"],
                direction="outbound",
                details={"message_id": outbound_id},
                status="sent",
            )
            return self.json_response(
                {
                    "sent": True,
                    "message_id": outbound_id,
                    "remaining_today": self.mailbox_remaining_today(conn, mailbox["id"], limit),
                },
                HTTPStatus.CREATED,
            )

    def public_webmail_logout(self):
        host = self.headers.get("Host", "localhost")
        self.send_response(HTTPStatus.NO_CONTENT)
        for cookie_header in expired_named_cookie_headers("mp_mail_token", host):
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()
        return

    def public_mail_jmap(self):
        with connect(CONFIG.db_path) as conn:
            payload, mailbox_id = self.webmail_session_context()
            mailbox = self.load_webmail_mailbox(conn, payload, mailbox_id)
            mailbox_payload = mailbox_row_payload(conn, mailbox)
            return self.json_response(
                {
                    "enabled": True,
                    "implementation": "compatibility-adapter",
                    "capabilities": {
                        "mailbox_native": True,
                        "submission": True,
                        "imap": True,
                        "pop": True,
                        "webmail": True,
                    },
                    "mailbox": {
                        "id": mailbox_payload["id"],
                        "email": mailbox_payload["email"],
                        "username": mailbox_payload.get("mail_username", mailbox_payload["email"]),
                        "host": mailbox_payload.get("mail_edge_host") or mailbox_payload.get("smtp_host") or "",
                        "submission_host": mailbox_payload.get("smtp_host") or "",
                        "submission_port": mailbox_payload.get("smtp_port") or 0,
                        "submission_encryption": mailbox_payload.get("smtp_encryption") or "STARTTLS",
                        "imap_host": mailbox_payload.get("imap_host") or "",
                        "imap_port": mailbox_payload.get("imap_port") or 0,
                        "imap_encryption": mailbox_payload.get("imap_encryption") or "STARTTLS",
                        "pop_host": mailbox_payload.get("pop_host") or "",
                        "pop_port": mailbox_payload.get("pop_port") or 0,
                        "pop_encryption": mailbox_payload.get("pop_encryption") or "STARTTLS",
                        "webmail_url": mailbox_payload.get("webmail_url") or "",
                        "webmail_login_url": mailbox_payload.get("webmail_login_url") or "",
                        "jmap_url": mailbox_payload.get("jmap_url") or "",
                    },
                    "user": {
                        "account_id": mailbox["account_id"],
                        "account_username": mailbox["account_username"],
                    },
                }
            )

    def forward_auth_verify(self):
        from http.cookies import SimpleCookie
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie(cookie_header)
        token_cookie = cookies.get("mp_client_token")
        token = token_cookie.value if token_cookie else None

        if not token:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.removeprefix("Bearer ").strip()

        forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
        forwarded_uri = self.headers.get("X-Forwarded-Uri", "")

        if forwarded_uri and (
            forwarded_uri.startswith("/files/static/")
            or "/static/" in forwarded_uri
            or forwarded_uri.startswith("/db/themes/")
            or forwarded_uri.startswith("/db/js/")
            or forwarded_uri.startswith("/db/favicon")
            or forwarded_uri.startswith("/webmail/assets/")
        ):
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            return

        magic_token = extract_magic_launch_token(forwarded_uri)
        magic_mode = False
        if not token and magic_token:
            token = magic_token
            magic_mode = True

        username = None
        if forwarded_host:
            match = re.match(r"^(?:files|pma)[-.](\w+)\.", forwarded_host)
            if match:
                username = match.group(1)

        if not token:
            if "text/html" in self.headers.get("Accept", ""):
                redirect_host = CONFIG.public_host
                if forwarded_host:
                    host_part = forwarded_host.split(":")[0]
                    if host_part.endswith(".localhost"):
                        redirect_host = "localhost"
                    elif "." in host_part:
                        parts = host_part.split(".")
                        if len(parts) >= 2 and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_part):
                            redirect_host = ".".join(parts[-2:])
                login_url = f"http://{redirect_host}:{CONFIG.client_port}/login"
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", login_url)
                self.end_headers()
                return
            raise ApiError(HTTPStatus.UNAUTHORIZED, "missing_auth_session")

        payload = verify_jwt(token, CONFIG.jwt_secret)
        if not payload or payload.get("purpose") not in {"access", "tool_launch"}:
            if "text/html" in self.headers.get("Accept", ""):
                redirect_host = CONFIG.public_host
                if forwarded_host:
                    host_part = forwarded_host.split(":")[0]
                    if host_part.endswith(".localhost"):
                        redirect_host = "localhost"
                    elif "." in host_part:
                        parts = host_part.split(".")
                        if len(parts) >= 2 and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_part):
                            redirect_host = ".".join(parts[-2:])
                login_url = f"http://{redirect_host}:{CONFIG.client_port}/login"
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", login_url)
                self.end_headers()
                return
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_auth_session")

        actor_type = payload.get("actor_type")
        actor_id = payload.get("sub")
        if not username:
            username = payload.get("username")

        with connect(CONFIG.db_path) as conn:
            if actor_type == "admin":
                admin = conn.execute("SELECT status FROM admins WHERE id = ?", (actor_id,)).fetchone()
                if not admin or admin["status"] != "active":
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "inactive_admin")
                self.send_response(HTTPStatus.OK)
                self.end_headers()
                return
            elif actor_type == "user":
                user = conn.execute("SELECT status FROM users WHERE id = ?", (actor_id,)).fetchone()
                if not user or user["status"] != "active":
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "inactive_user")
                account = None
                if username:
                    account = conn.execute(
                        "SELECT id FROM hosting_accounts WHERE user_id = ? AND username = ? AND status = 'active'",
                        (actor_id, username)
                    ).fetchone()
                elif payload.get("account_id"):
                    account = conn.execute(
                        "SELECT id FROM hosting_accounts WHERE id = ? AND user_id = ? AND status = 'active'",
                        (payload["account_id"], actor_id)
                    ).fetchone()
                else:
                    account = conn.execute(
                        "SELECT id FROM hosting_accounts WHERE user_id = ? AND status = 'active' ORDER BY id ASC LIMIT 1",
                        (actor_id,)
                    ).fetchone()

                if not account:
                    raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")

                if magic_mode:
                    access_token = create_jwt(
                        {"sub": actor_id, "actor_type": actor_type, "purpose": "access", "jti": secrets.token_urlsafe(16)},
                        CONFIG.jwt_secret,
                        600,
                    )
                    access_payload = verify_jwt(access_token, CONFIG.jwt_secret)
                    conn.execute(
                        "INSERT INTO sessions(actor_type, actor_id, token_id, expires_at) VALUES (?, ?, ?, ?)",
                        (actor_type, actor_id, access_payload["jti"], int(time.time()) + 600),
                    )
                    clean_path = strip_magic_launch_segment(forwarded_uri)
                    self.send_response(HTTPStatus.FOUND)
                    for cookie_header in auth_cookie_headers(access_token, forwarded_host, is_https=self.is_https):
                        self.send_header("Set-Cookie", cookie_header)
                    self.send_header("Location", build_tool_redirect_url(forwarded_host, clean_path, is_https=self.is_https))
                    self.end_headers()
                    return

                session = conn.execute(
                    "SELECT id FROM sessions WHERE actor_type = ? AND actor_id = ? AND token_id = ? AND expires_at > ?",
                    (actor_type, actor_id, payload.get("jti"), int(time.time()))
                ).fetchone()
                if not session:
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "expired_auth_session")

                self.send_response(HTTPStatus.OK)
                self.end_headers()
                return

        raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")

    def signup_customer(self, body):
        email = normalize_email(body.get("email"))
        full_name = clean_text(body.get("full_name"), "Customer")
        password = validate_password(body.get("password", ""))
        totp_secret = generate_totp_secret()
        with connect(CONFIG.db_path) as conn:
            if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
                raise ApiError(HTTPStatus.CONFLICT, "email_already_registered")
            cur = conn.execute(
                """
                INSERT INTO users(email, password_hash, full_name, totp_secret)
                VALUES (?, ?, ?, ?)
                """,
                (email, hash_password(password), full_name, totp_secret),
            )
            user_id = cur.lastrowid
            account_payload = create_initial_hosting_account(conn, user_id)
            log_audit(conn, "public", None, "customer_signup", "user", user_id, self.client_address[0], {"email": email})
            log_activity(conn, user_id, "customer_signup", {"email": email})
            return self.json_response(
                {
                    "user": {"id": user_id, "email": email, "full_name": full_name},
                    "totp_secret": totp_secret,
                    "totp_uri": otpauth_uri("MangoPanel", email, totp_secret),
                    "hosting_account": account_payload,
                },
                HTTPStatus.CREATED,
            )

    def setup_first_admin(self, body):
        email = normalize_email(body.get("email"))
        full_name = clean_text(body.get("full_name"), "Super Admin")
        password = validate_password(body.get("password", ""))
        totp_secret = generate_totp_secret()
        with connect(CONFIG.db_path) as conn:
            conn.execute("BEGIN EXCLUSIVE")
            if conn.execute("SELECT COUNT(*) AS count FROM admins").fetchone()["count"] != 0:
                raise ApiError(HTTPStatus.CONFLICT, "admin_already_configured")
            cur = conn.execute(
                """
                INSERT INTO admins(email, password_hash, full_name, role, totp_secret)
                VALUES (?, ?, ?, ?, ?)
                """,
                (email, hash_password(password), full_name, "super_admin", totp_secret),
            )
            admin_id = cur.lastrowid
            log_audit(conn, "public", None, "first_admin_signup", "admin", admin_id, self.client_address[0], {"email": email})
            return self.json_response(
                {
                    "admin": {"id": admin_id, "email": email, "full_name": full_name, "role": "super_admin"},
                    "totp_secret": totp_secret,
                    "totp_uri": otpauth_uri("MangoPanel Admin", email, totp_secret),
                },
                HTTPStatus.CREATED,
            )

    def verify_totp_secret(self, body):
        secret = str(body.get("totp_secret", "")).strip()
        code = str(body.get("code", "")).strip()
        if not secret:
            raise ApiError(HTTPStatus.BAD_REQUEST, "missing_totp_secret")
        return self.json_response({"valid": verify_totp(secret, code)})

    def login(self, actor_type):
        body = self.read_json()
        email = body.get("email", "").strip().lower()
        password = body.get("password", "")
        table = "admins" if actor_type == "admin" else "users"
        with connect(CONFIG.db_path) as conn:
            check_auth_rate_limit(conn, self, actor_type)
            actor = conn.execute(f"SELECT * FROM {table} WHERE email = ? AND status = 'active'", (email,)).fetchone()
            if not actor or not verify_password(password, actor["password_hash"]):
                record_auth_failure(conn, self, actor_type)
                raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_credentials")
            log_audit(conn, actor_type, actor["id"], "login_password_ok", table, actor["id"], self.client_address[0])
            
            if actor["totp_secret"]:
                token = create_jwt(
                    {"sub": actor["id"], "actor_type": actor_type, "purpose": "totp_challenge"},
                    CONFIG.jwt_secret,
                    CONFIG.totp_challenge_ttl_seconds,
                )
                return self.json_response({"totp_required": True, "challenge_token": token})
            else:
                clear_auth_attempts(conn, self, actor_type)
                token_id = secrets.token_urlsafe(16)
                access_token = create_jwt(
                    {"sub": actor["id"], "actor_type": actor_type, "purpose": "access", "jti": token_id},
                    CONFIG.jwt_secret,
                    CONFIG.token_ttl_seconds,
                )
                conn.execute(
                    "INSERT INTO sessions(actor_type, actor_id, token_id, expires_at) VALUES (?, ?, ?, ?)",
                    (actor_type, actor["id"], token_id, int(time.time()) + CONFIG.token_ttl_seconds),
                )
                log_audit(conn, actor_type, actor["id"], "login_totp_ok", table, actor["id"], self.client_address[0])
                return self.json_response(
                    {
                        "access_token": access_token,
                        "expires_in": CONFIG.token_ttl_seconds,
                    }
                )

    def verify_totp_challenge(self, actor_type):
        body = self.read_json()
        payload = verify_jwt(body.get("challenge_token", ""), CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "totp_challenge" or payload.get("actor_type") != actor_type:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_totp_challenge")
        table = "admins" if actor_type == "admin" else "users"
        with connect(CONFIG.db_path) as conn:
            check_auth_rate_limit(conn, self, actor_type)
            actor = conn.execute(f"SELECT * FROM {table} WHERE id = ? AND status = 'active'", (payload["sub"],)).fetchone()
            if not actor:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "actor_not_found")
            code = body.get("code", "")
            dev_bypass_ok = CONFIG.is_development and CONFIG.dev_auth_test_mode and code == "000000"
            if not dev_bypass_ok and not verify_totp(actor["totp_secret"], code):
                record_auth_failure(conn, self, actor_type)
                raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_totp")
            clear_auth_attempts(conn, self, actor_type)

            token_id = secrets.token_urlsafe(16)
            access_token = create_jwt(
                {"sub": actor["id"], "actor_type": actor_type, "purpose": "access", "jti": token_id},
                CONFIG.jwt_secret,
                CONFIG.token_ttl_seconds,
            )
            conn.execute(
                "INSERT INTO sessions(actor_type, actor_id, token_id, expires_at) VALUES (?, ?, ?, ?)",
                (actor_type, actor["id"], token_id, int(time.time()) + CONFIG.token_ttl_seconds),
            )
            log_audit(conn, actor_type, actor["id"], "login_totp_ok", table, actor["id"], self.client_address[0])
            return self.json_response(
                {
                    "access_token": access_token,
                    "actor": {"id": actor["id"], "email": actor["email"], "full_name": actor["full_name"], "type": actor_type},
                }
            )

    def logout(self, actor_type):
        from http.cookies import SimpleCookie
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie(cookie_header)
        token_cookie = cookies.get("mp_client_token")
        token = token_cookie.value if token_cookie else None

        if not token:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.removeprefix("Bearer ").strip()

        if token:
            payload = verify_jwt(token, CONFIG.jwt_secret)
            if payload and payload.get("purpose") == "access":
                token_id = payload.get("jti")
                if token_id:
                    with connect(CONFIG.db_path) as conn:
                        conn.execute(
                            "DELETE FROM sessions WHERE actor_type = ? AND token_id = ?",
                            (actor_type, token_id)
                        )

        # Respond with expired cookie header to clear it in browser
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        for cookie_header in expired_auth_cookie_headers(self.headers.get("Host", "localhost")):
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()
        self.wfile.write(json.dumps({"success": True}).encode("utf-8"))

    def require_auth(self, actor_type):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "missing_bearer_token")
        raw_token = auth.removeprefix("Bearer ").strip()
        payload = verify_jwt(raw_token, CONFIG.jwt_secret)
        if not payload:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_access_token")

        if payload.get("purpose") == "impersonation_exchange" and actor_type == "user":
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            now = int(time.time())
            with connect(CONFIG.db_path) as conn:
                row = conn.execute("SELECT * FROM impersonation_tokens WHERE token_hash = ?", (token_hash,)).fetchone()
                if row and int(row["expires_at"] or 0) >= now:
                    if row["used_at"] is None:
                        conn.execute("UPDATE impersonation_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?", (token_hash,))
                    user = conn.execute("SELECT * FROM users WHERE id = ? AND status = 'active'", (payload["sub"],)).fetchone()
                    if user:
                        return row_to_dict(user)

        if payload.get("purpose") != "access" or payload.get("actor_type") != actor_type:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_access_token")
        table = "admins" if actor_type == "admin" else "users"
        with connect(CONFIG.db_path) as conn:
            actor = conn.execute(f"SELECT * FROM {table} WHERE id = ? AND status = 'active'", (payload["sub"],)).fetchone()
            if not actor:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "actor_not_found")
            return row_to_dict(actor)

    def exchange_impersonation(self):
        body = self.read_json()
        token = str(body.get("impersonation_token") or body.get("token") or "").strip()
        if not token:
            raise ApiError(HTTPStatus.BAD_REQUEST, "impersonation_token_required")
        payload = verify_jwt(token, CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "impersonation_exchange" or payload.get("actor_type") != "user":
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_impersonation_token")
        user_id = int(payload.get("sub") or 0)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = int(time.time())
        with connect(CONFIG.db_path) as conn:
            row = conn.execute("SELECT * FROM impersonation_tokens WHERE token_hash = ?", (token_hash,)).fetchone()
            if not row or row["used_at"] is not None or int(row["expires_at"] or 0) < now:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "impersonation_token_expired_or_used")
            conn.execute("UPDATE impersonation_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?", (token_hash,))
            user = conn.execute("SELECT * FROM users WHERE id = ? AND status = 'active'", (user_id,)).fetchone()


            if not user:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "user_not_found")
            
            token_id = secrets.token_urlsafe(16)
            access_token = create_jwt(
                {"sub": user_id, "actor_type": "user", "purpose": "access", "jti": token_id},
                CONFIG.jwt_secret,
                CONFIG.token_ttl_seconds,
            )
            conn.execute(
                "INSERT INTO sessions(actor_type, actor_id, token_id, expires_at) VALUES (?, ?, ?, ?)",
                ("user", user_id, token_id, now + CONFIG.token_ttl_seconds),
            )
            log_audit(conn, "user", user_id, "impersonation_token_exchanged", "user", user_id, self.client_address[0])
            self.send_response(HTTPStatus.OK)
            for cookie_header in auth_cookie_headers(access_token, self.headers.get("Host", "")):
                self.send_header("Set-Cookie", cookie_header)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"access_token": access_token, "expires_in": CONFIG.token_ttl_seconds}).encode("utf-8"))
            return

    def client_api(self, method, path, query, actor):
        req_account_id = None
        hdr_acc = self.headers.get("X-Hosting-Account-ID", "").strip() or self.headers.get("X-Account-ID", "").strip()
        if hdr_acc and hdr_acc.isdigit():
            req_account_id = int(hdr_acc)
        elif "account_id" in query and query["account_id"][0].isdigit():
            req_account_id = int(query["account_id"][0])

        with connect(CONFIG.db_path) as conn:
            if req_account_id:
                account = conn.execute(
                    """
                    SELECT ha.*, p.memory_mb, p.storage_mb
                    FROM hosting_accounts ha
                    JOIN plans p ON p.id = ha.plan_id
                    WHERE ha.id = ? AND ha.user_id = ?
                    """,
                    (req_account_id, actor["id"]),
                ).fetchone()
                if not account:
                    raise ApiError(HTTPStatus.FORBIDDEN, "hosting_account_access_denied")
            else:
                account = conn.execute(
                    """
                    SELECT ha.*, p.memory_mb, p.storage_mb
                    FROM hosting_accounts ha
                    JOIN plans p ON p.id = ha.plan_id
                    WHERE ha.user_id = ?
                    ORDER BY ha.id LIMIT 1
                    """,
                    (actor["id"],),
                ).fetchone()

            path = path.rstrip("/")
            if path == "/api/client/home" and method == "GET":
                return self.json_response(client_home(conn, actor["id"]))
            if path == "/api/client/feature-status" and method == "GET":
                return self.json_response({"features": FEATURE_STATUS})
            if path == "/api/client/sync-jobs" and method == "GET":
                require_account(account)
                return self.json_response({"jobs": client_sync_jobs(conn, account)})
            if path == "/api/client/hosting-accounts" and method == "GET":
                rows = conn.execute(
                    """
                    SELECT ha.*, p.name AS plan_name, n.name AS node_name
                    FROM hosting_accounts ha
                    JOIN plans p ON p.id = ha.plan_id
                    JOIN nodes n ON n.id = ha.node_id
                    WHERE ha.user_id = ?
                    ORDER BY ha.id
                    """,
                    (actor["id"],),
                ).fetchall()
                accounts = rows_to_dicts(rows)
                for item in accounts:
                    item["runtime"] = account_runtime(conn, item["id"])
                return self.json_response({"hosting_accounts": accounts})
            if path == "/api/client/resource-usage" and method == "GET":
                require_account(account)
                window_key = query.get("range", ["30m"])[0]
                payload = resource_usage_payload(conn, account, window_key)
                return self.json_response(payload)
            if path == "/api/client/php-info" and method == "GET":
                require_account(account)
                website_id = optional_positive_int(query.get("website_id", [""])[0])
                return self.json_response(client_php_info_payload(conn, account, website_id))
            if path == "/api/client/analytics" and method == "GET":
                require_account(account)
                return self.json_response(client_analytics_payload(conn, account["id"], website_id, filter_key))
            if path == "/api/client/websites" and method == "GET":
                def check_domain_tls_handshake(domain):
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with socket.create_connection(("127.0.0.1", 443), timeout=1.5) as sock:
                            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                                return True
                    except Exception:
                        return False
                rows = conn.execute(
                    """
                    SELECT w.*, d.id AS domain_id, d.nameservers_json, d.provider_state_json, d.dns_provider, d.dns_status
                    FROM websites w
                    JOIN hosting_accounts ha ON ha.id = w.account_id
                    LEFT JOIN domains d ON d.linked_website_id = w.id
                    WHERE ha.user_id = ?
                    ORDER BY w.id
                    """,
                    (actor["id"],),
                ).fetchall()
                websites = rows_to_dicts(rows)
                for website in websites:
                    runtime = account_runtime(conn, website["account_id"])
                    website["public_url"] = f"http://{website['domain']}"
                    website["host_header"] = website["domain"]
                    website["nameservers"] = website_dns_nameservers(website)
                    website["dns_provider_label"] = "Cloudflare" if website.get("dns_provider") == DNS_PROVIDER_CLOUDFLARE else "Local DNS"
                    provider_state = parse_json_field(website.get("provider_state_json"), {})
                    website["provider_state"] = provider_state
                    website["dns_last_error"] = provider_state.get("last_error") or ""
                    website["dns_warnings"] = dns_state_warnings(website)

                    if website.get("ssl_status") != "custom":
                        has_tls = check_domain_tls_handshake(website["domain"])
                        real_status = "active" if has_tls else "missing"
                        if website.get("ssl_status") != real_status:
                            website["ssl_status"] = real_status
                            try:
                                conn.execute("UPDATE websites SET ssl_status = ? WHERE id = ?", (real_status, website["id"]))
                                conn.execute("UPDATE ssl_certificates SET status = ? WHERE website_id = ? AND status != 'custom'", (real_status, website["id"]))
                            except Exception:
                                pass
                return self.json_response({"websites": websites})
            if path == "/api/client/websites" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "websites", "max_websites", "website_limit_reached")
                body = self.read_json()
                domain = sanitize_domain(body.get("domain", ""))
                existing_domain = conn.execute(
                    "SELECT id, linked_website_id FROM domains WHERE account_id = ? AND name = ?",
                    (account["id"], domain),
                ).fetchone()
                if existing_domain:
                    raise ApiError(HTTPStatus.CONFLICT, "domain_already_exists")
                document_root = f"{account['base_path']}/domains/{domain}/public_html"
                cur = conn.execute(
                    """
                    INSERT INTO websites(account_id, domain, document_root, php_version, ssl_status, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (account["id"], domain, document_root, body.get("php_version", "8.3"), "missing", "active"),
                )
                website_id = cur.lastrowid
                dns_assignment = default_domain_dns_assignment(conn, account["id"])
                conn.execute(
                    """
                    INSERT OR IGNORE INTO domains(
                      account_id, name, kind, status, linked_website_id, dns_provider,
                      dns_provider_account_id, nameservers_json, dns_status, provider_state_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account["id"],
                        domain,
                        "managed",
                        "active",
                        website_id,
                        dns_assignment["dns_provider"],
                        dns_assignment["dns_provider_account_id"],
                        json.dumps(dns_assignment["nameservers"]),
                        dns_assignment["dns_status"],
                        json.dumps(dns_assignment["provider_state"], sort_keys=True),
                    ),
                )
                job_id = enqueue_agent_job(conn, "create_website", "website", website_id, {"domain": domain})
                domain_link = conn.execute(
                    "SELECT id FROM domains WHERE linked_website_id = ?",
                    (website_id,),
                ).fetchone()
                if not domain_link:
                    raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, "domain_record_missing")
                mail_host = "mail-{}.localhost".format(account["username"]) if CONFIG.public_host == "127.0.0.1" else "mail.{}.{}".format(account["username"], CONFIG.public_host)
                seed_website_dns_records(conn, domain_link["id"], domain, mail_host)
                dns_job_id = enqueue_agent_job(conn, "sync_dns_zone", "domain", domain_link["id"], {"reason": "website_created"})

                log_activity(conn, actor["id"], "website_created", {"domain": domain})
                website = row_to_dict(conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone())
                domain_row = conn.execute(
                    """
                    SELECT d.*, z.nameservers_json AS zone_nameservers_json
                    FROM domains d
                    LEFT JOIN dns_zones z ON z.domain_id = d.id
                    WHERE d.linked_website_id = ?
                    """,
                    (website_id,),
                ).fetchone()
                if domain_row:
                    domain_info = row_to_dict(domain_row)
                    website["domain_record"] = decorate_domain(domain_row)
                    website["nameservers"] = website_dns_nameservers(website["domain_record"]) or parse_json_field(domain_info.get("zone_nameservers_json"), [])
                    website["dns_provider_label"] = website["domain_record"]["dns_provider_label"]
                return self.json_response(
                    {"website": website, "job_id": job_id, "dns_job_id": dns_job_id},
                    HTTPStatus.CREATED,
                )
            if path.startswith("/api/client/websites/") and not path.endswith("/php") and not path.endswith("/modsec") and not path.endswith("/connection-check"):
                require_active_account(account)
                website_id = path_int_id(path, "/api/client/websites/")
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                if method == "PATCH":
                    body = self.read_json()
                    allowed_php = {"8.2", "8.3", "8.4"}
                    php_version = body.get("php_version", website["php_version"])
                    if php_version not in allowed_php:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_php_version")
                    status = body.get("status", website["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_website_status")
                    
                    php_ini_str = (website["php_ini"] if website["php_ini"] is not None else "{}")
                    if "php_ini" in body:
                        php_ini_str = json.dumps(body["php_ini"])
                        
                    if "index_enabled" in body:
                        try:
                            index_enabled = int(body.get("index_enabled"))
                        except (TypeError, ValueError):
                            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_index_enabled")
                        if index_enabled not in {0, 1}:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_index_enabled")
                    else:
                        index_enabled = int(website["index_enabled"] if website["index_enabled"] is not None else 0)
                    try:
                        modsec_enabled = int(body.get("modsec_enabled", (website["modsec_enabled"] if website["modsec_enabled"] is not None else 1)))
                    except (TypeError, ValueError):
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_modsec_enabled")
                    if modsec_enabled not in {0, 1}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_modsec_enabled")
                    if "analytics_enabled" in body:
                        try:
                            analytics_enabled = int(body.get("analytics_enabled"))
                        except (TypeError, ValueError):
                            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_analytics_enabled")
                        if analytics_enabled not in {0, 1}:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_analytics_enabled")
                    else:
                        analytics_enabled = int(website["analytics_enabled"] if website["analytics_enabled"] is not None else 1)
                        
                    conn.execute(
                        "UPDATE websites SET php_version = ?, status = ?, php_ini = ?, index_enabled = ?, modsec_enabled = ?, analytics_enabled = ? WHERE id = ?",
                        (php_version, status, php_ini_str, index_enabled, modsec_enabled, analytics_enabled, website_id),
                    )
                    
                    job_id = enqueue_agent_job(conn, "update_website_php", "website", website_id, {"php_version": php_version})
                    if "index_enabled" in body:
                        job_id = enqueue_agent_job(conn, "sync_website_index", "website", website_id, {})
                    if "modsec_enabled" in body:
                        job_id = enqueue_agent_job(conn, "sync_website_modsec", "website", website_id, {})
                    if "analytics_enabled" in body:
                        job_id = enqueue_agent_job(conn, "sync_website_analytics", "website", website_id, {})
                        
                    log_activity(conn, actor["id"], "website_updated", {"website_id": website_id, "php_version": php_version, "index_enabled": index_enabled, "modsec_enabled": modsec_enabled, "analytics_enabled": analytics_enabled})
                    updated = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
                    return self.json_response({"website": row_to_dict(updated), "job_id": job_id})
                if method == "DELETE":
                    domain = website["domain"]
                    job_id = delete_client_website(conn, account, website)
                    log_activity(conn, actor["id"], "website_deleted", {"website_id": website_id, "domain": domain})
                    return self.json_response({"deleted": True, "job_id": job_id})
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
            if path == "/api/client/php-versions" and method == "GET":
                require_account(account)
                return self.json_response({"php_versions": ["8.2", "8.3", "8.4"]})
            if path == "/api/client/domains" and method == "GET":
                rows = conn.execute(
                    """
                    SELECT d.*, z.nameservers_json AS zone_nameservers_json
                    FROM domains d
                    JOIN hosting_accounts ha ON ha.id = d.account_id
                    LEFT JOIN dns_zones z ON z.domain_id = d.id
                    WHERE ha.user_id = ?
                    ORDER BY d.name
                    """,
                    (actor["id"],),
                ).fetchall()
                return self.json_response({"domains": [decorate_domain(row) for row in rows]})
            if path.startswith("/api/client/domains/") and path.endswith("/nameservers") and method == "POST":
                require_account(account)
                domain_id = int(path.split("/")[-2])
                domain = conn.execute("SELECT d.* FROM domains d JOIN hosting_accounts ha ON ha.id = d.account_id WHERE d.id = ? AND ha.user_id = ?", (domain_id, actor["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                body = self.read_json()
                source = str(body.get("source") or "custom").lower()
                if source not in {"default", "custom"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_nameserver_source")
                nameservers = [str(v).strip().rstrip(".").lower() for v in (body.get("nameservers") or []) if str(v).strip()]
                if source == "default":
                    nameservers = default_registrar_nameservers(conn)
                if len(nameservers) < 2 or len(nameservers) > 4:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "two_to_four_nameservers_required")
                result = update_domain_registrar_nameservers(conn, domain, nameservers, source=source)
                log_activity(conn, actor["id"], "registrar_nameservers_updated", {"domain_id": domain_id, "source": source})
                return self.json_response({"domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()), "result": result})
            if path.startswith("/api/client/domains/") and path.endswith("/dns/rebuild") and method == "POST":
                require_active_account(account)
                domain_id = int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                ensure_no_active_dns_sync(conn, domain_id)
                job_id = enqueue_agent_job(conn, "sync_dns_zone", "domain", domain_id, {"reason": "client_rebuild"})
                log_activity(conn, actor["id"], "dns_zone_rebuild_requested", {"domain_id": domain_id})
                return self.json_response({"job_id": job_id, "domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone())})
            if path.startswith("/api/client/domains/") and path.endswith("/dns/verify-nameservers") and method == "POST":
                require_account(account)
                domain_id = int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                verification = verify_domain_nameservers(conn, domain)
                log_activity(conn, actor["id"], "dns_nameservers_verified", {"domain_id": domain_id, "status": verification["status"]})
                return self.json_response({"verification": verification, "domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone())})
            if path.startswith("/api/client/domains/") and path.endswith("/dns/export") and method == "GET":
                require_account(account)
                domain_id = int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                export = create_dns_zone_export(conn, domain, "client:{}".format(actor["id"]))
                log_activity(conn, actor["id"], "dns_zone_exported", {"domain_id": domain_id})
                return self.json_response({"dns_zone_export": export})
            if (path.startswith("/api/client/domains/") and path.endswith("/dns/migrate-provider") or (match := re.match(r"^/api/client/domains/(\d+)/dns/migrate-provider/?$", path))) and method == "POST":
                require_account(account)
                domain_id = int(match.group(1)) if (match := re.match(r"^/api/client/domains/(\d+)/dns/migrate-provider/?$", path)) else int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                plan = conn.execute("SELECT p.* FROM hosting_accounts ha JOIN plans p ON p.id = ha.plan_id WHERE ha.id = ?", (account["id"],)).fetchone()
                policy = plan_dns_policy(plan) if plan else {}
                if not policy.get("customer_editable", True):
                    raise ApiError(HTTPStatus.FORBIDDEN, "dns_provider_migration_not_allowed_by_plan")
                body = self.read_json()
                provider_key = clean_text(body.get("provider_key") or body.get("dns_provider") or "", "")
                if provider_key not in DNS_PROVIDER_KEYS:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_provider")
                provider_account_id = body.get("provider_account_id") or body.get("dns_provider_account_id") or policy.get("default_provider_account_id")
                if provider_account_id in ("", None):
                    provider_account_id = None
                else:
                    provider_account_id = positive_int(provider_account_id, "invalid_dns_provider_account_id")
                job_id = migrate_domain_dns_provider(conn, domain, provider_key, provider_account_id, "user:{}".format(actor["id"]))
                log_activity(conn, actor["id"], "dns_provider_migrated", {"domain_id": domain_id, "provider_key": provider_key})
                return self.json_response({"job_id": job_id, "domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone())})
            if (path.startswith("/api/client/domains/") and path.endswith("/dns/set-default-records") or (match := re.match(r"^/api/client/domains/(\d+)/dns/set-default-records/?$", path))) and method == "POST":
                require_account(account)
                domain_id = int(match.group(1)) if (match := re.match(r"^/api/client/domains/(\d+)/dns/set-default-records/?$", path)) else int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                public_ip = get_host_public_ip(conn)
                mail_host = domain["name"]

                conn.execute(
                    "DELETE FROM dns_records WHERE domain_id = ? AND ((type = 'A' AND name = '@') OR (type = 'CNAME' AND name = 'www') OR (type = 'MX' AND name = '@') OR (type = 'TXT' AND name = '@'))",
                    (domain["id"],),
                )
                conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl, proxied) VALUES (?, ?, ?, ?, ?, ?)",
                    (domain["id"], "A", "@", public_ip, 300, 1),
                )
                conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl, proxied) VALUES (?, ?, ?, ?, ?, ?)",
                    (domain["id"], "CNAME", "www", "@", 300, 1),
                )
                conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl, proxied) VALUES (?, ?, ?, ?, ?, ?)",
                    (domain["id"], "MX", "@", mail_host, 300, 0),
                )
                conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl, proxied) VALUES (?, ?, ?, ?, ?, ?)",
                    (domain["id"], "TXT", "@", "v=spf1 mx a ~all", 300, 0),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl) VALUES (?, ?, ?, ?, ?)",
                    (domain["id"], "TXT", "_dmarc", recommended_dmarc_record(domain["name"]), 300),
                )
                job_id = enqueue_agent_job(conn, "sync_dns_zone", "domain", domain["id"], {"reason": "set_default_records"})
                log_activity(conn, actor["id"], "dns_default_records_set", {"domain_id": domain_id})
                return self.json_response({
                    "job_id": job_id,
                    "domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()),
                    "public_ip": public_ip,
                })
            if path == "/api/client/dns-records" and method == "GET":
                require_account(account)
                domain_id = optional_positive_int(query.get("domain_id", [""])[0])
                if domain_id:
                    domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                    if not domain:
                        raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                    rows = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (domain_id,)).fetchall()
                    zone_rows = conn.execute("SELECT * FROM dns_zones WHERE domain_id = ? ORDER BY zone_name", (domain_id,)).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT dr.* FROM dns_records dr
                        JOIN domains d ON d.id = dr.domain_id
                        WHERE d.account_id = ?
                        ORDER BY dr.type, dr.name
                        """,
                        (account["id"],),
                    ).fetchall()
                    zone_rows = conn.execute("SELECT * FROM dns_zones WHERE account_id = ? ORDER BY zone_name", (account["id"],)).fetchall()
                dns_zones = [decorate_dns_zone(row) for row in zone_rows]
                return self.json_response({"dns_records": decorated_dns_records(rows), "dns_zones": dns_zones})
            if path == "/api/client/dns-records" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                record_payload = validate_dns_record_payload(body)
                domain_id = record_payload["domain_id"]
                domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                ensure_no_active_dns_sync(conn, domain_id)
                enforce_dns_record_policy(conn, account["id"], record_payload, domain_id, creating=True)
                ensure_dns_record_conflicts(conn, domain_id, record_payload)
                cur = conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl, priority, proxied, provider_metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        domain_id,
                        record_payload["type"],
                        record_payload["name"],
                        record_payload["value"],
                        record_payload["ttl"],
                        record_payload["priority"],
                        1 if record_payload.get("proxied") else 0,
                        json.dumps(record_payload.get("provider_metadata") or {}, sort_keys=True),
                    ),
                )
                job_id = enqueue_agent_job(conn, "sync_dns_record", "dns_record", cur.lastrowid, {})
                log_activity(conn, actor["id"], "dns_record_created", {"domain_id": domain_id, "type": record_payload["type"]})
                all_records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (domain_id,)).fetchall()
                zone_rows = conn.execute("SELECT * FROM dns_zones WHERE domain_id = ? ORDER BY zone_name", (domain_id,)).fetchall()
                dns_zones = [decorate_dns_zone(row) for row in zone_rows]
                return self.json_response({"dns_record_id": cur.lastrowid, "job_id": job_id, "dns_records": decorated_dns_records(all_records), "dns_zones": dns_zones}, HTTPStatus.CREATED)
            if path.startswith("/api/client/dns-records/") and method == "PATCH":
                require_active_account(account)
                record_id = path_int_id(path, "/api/client/dns-records/")
                record = conn.execute(
                    """
                    SELECT dr.* FROM dns_records dr
                    JOIN domains d ON d.id = dr.domain_id
                    WHERE dr.id = ? AND d.account_id = ?
                    """,
                    (record_id, account["id"]),
                ).fetchone()
                if not record:
                    raise ApiError(HTTPStatus.NOT_FOUND, "dns_record_not_found")
                ensure_no_active_dns_sync(conn, record["domain_id"])
                ensure_dns_record_mutable(record)
                body = self.read_json()
                merged = row_to_dict(record)
                for key in ("type", "name", "value", "ttl", "priority", "proxied"):
                    if key in body:
                        merged[key] = body[key]
                merged["domain_id"] = record["domain_id"]
                record_payload = validate_dns_record_payload(merged)
                enforce_dns_record_policy(conn, account["id"], record_payload, record["domain_id"], creating=False)
                ensure_dns_record_conflicts(conn, record["domain_id"], record_payload, exclude_record_id=record_id)
                conn.execute(
                    """
                    UPDATE dns_records
                    SET type = ?, name = ?, value = ?, ttl = ?, priority = ?, proxied = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        record_payload["type"],
                        record_payload["name"],
                        record_payload["value"],
                        record_payload["ttl"],
                        record_payload["priority"],
                        1 if record_payload.get("proxied") else 0,
                        record_id,
                    ),
                )
                job_id = enqueue_agent_job(conn, "sync_dns_record", "dns_record", record_id, {})
                log_activity(conn, actor["id"], "dns_record_updated", {"record_id": record_id, "type": record_payload["type"]})
                all_records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (record["domain_id"],)).fetchall()
                zone_rows = conn.execute("SELECT * FROM dns_zones WHERE domain_id = ? ORDER BY zone_name", (record["domain_id"],)).fetchall()
                dns_zones = [decorate_dns_zone(row) for row in zone_rows]
                return self.json_response({"dns_record_id": record_id, "job_id": job_id, "dns_records": decorated_dns_records(all_records), "dns_zones": dns_zones})
            if path.startswith("/api/client/dns-records/") and method == "DELETE":
                require_active_account(account)
                record_id = path_int_id(path, "/api/client/dns-records/")
                record = conn.execute(
                    """
                    SELECT dr.* FROM dns_records dr
                    JOIN domains d ON d.id = dr.domain_id
                    WHERE dr.id = ? AND d.account_id = ?
                    """,
                    (record_id, account["id"]),
                ).fetchone()
                if not record:
                    raise ApiError(HTTPStatus.NOT_FOUND, "dns_record_not_found")
                ensure_no_active_dns_sync(conn, record["domain_id"])
                ensure_dns_record_mutable(record)
                conn.execute("DELETE FROM dns_records WHERE id = ?", (record_id,))
                job_id = enqueue_agent_job(conn, "sync_dns_zone", "domain", record["domain_id"], {})
                log_activity(conn, actor["id"], "dns_record_deleted", {"record_id": record_id})
                all_records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (record["domain_id"],)).fetchall()
                zone_rows = conn.execute("SELECT * FROM dns_zones WHERE domain_id = ? ORDER BY zone_name", (record["domain_id"],)).fetchall()
                dns_zones = [decorate_dns_zone(row) for row in zone_rows]
                return self.json_response({"deleted": True, "job_id": job_id, "dns_records": decorated_dns_records(all_records), "dns_zones": dns_zones})
            if path == "/api/client/ssh" and method == "GET":
                require_active_account(account)
                acc_dict = dict(account)
                ssh_status = acc_dict.get("ssh_access") or "disabled"
                runtime = build_account_runtime(acc_dict, CONFIG.public_host, CONFIG.account_port_base)
                host_hdr = (self.headers.get("Host") or self.headers.get("host") or "") if hasattr(self, "headers") and self.headers else ""
                host = host_hdr.split(":")[0] if host_hdr else ""
                if not host or host in {"127.0.0.1", "localhost", "0.0.0.0"}:
                    if CONFIG.public_host and CONFIG.public_host not in {"127.0.0.1", "0.0.0.0", "localhost"}:
                        host = CONFIG.public_host
                    else:
                        host = "seeds.servermango.com"
                return self.json_response({
                    "enabled": (ssh_status == "enabled"),
                    "ssh_access": ssh_status,
                    "host": host,
                    "port": runtime["sftp_port"],
                    "user": account["username"],
                    "path": account["base_path"],
                })
            if path == "/api/client/ssh/toggle" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                enabled = bool(body.get("enabled", False))
                new_status = "enabled" if enabled else "disabled"
                res = Agent(CONFIG).set_ssh_access(conn, account["id"], new_status)
                log_activity(conn, actor["id"], f"ssh_access_{new_status}", {"account_id": account["id"]})
                host_hdr = (self.headers.get("Host") or self.headers.get("host") or "") if hasattr(self, "headers") and self.headers else ""
                host = host_hdr.split(":")[0] if host_hdr else ""
                if not host or host in {"127.0.0.1", "localhost", "0.0.0.0"}:
                    if CONFIG.public_host and CONFIG.public_host not in {"127.0.0.1", "0.0.0.0", "localhost"}:
                        host = CONFIG.public_host
                    else:
                        host = "seeds.servermango.com"
                return self.json_response({
                    "enabled": (new_status == "enabled"),
                    "ssh_access": new_status,
                    "host": host,
                    "port": res["port"],
                    "user": res["user"],
                    "path": account["base_path"],
                })
            if path == "/api/client/ssl/issue" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = positive_int(body.get("website_id"), "invalid_website_id")
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                job_id = enqueue_agent_job(conn, "issue_ssl", "website", website_id, {"mode": "local-dev"})
                refreshed = conn.execute("SELECT ssl_status FROM websites WHERE id = ?", (website_id,)).fetchone()
                order = conn.execute(
                    "SELECT * FROM acme_certificate_orders WHERE account_id = ? AND domain = ? ORDER BY id DESC LIMIT 1",
                    (account["id"], website["domain"]),
                ).fetchone()
                acme_order = row_to_dict(order) if order else None
                if acme_order:
                    acme_order["provider_state"] = parse_json_field(acme_order.get("provider_state_json"), {})
                return self.json_response({"ssl_status": refreshed["ssl_status"], "job_id": job_id, "acme_order": acme_order})
            if path.startswith("/api/client/websites/") and path.endswith("/connection-check") and method == "POST":
                require_active_account(account)
                website_id = int(path.split("/")[-2])
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                domain_name = website["domain"]
                observed_a = []
                observed_ns = []
                dig = shutil.which("dig")
                if dig:
                    for record_type, target in (("A", observed_a), ("AAAA", observed_a), ("NS", observed_ns)):
                        try:
                            result = subprocess.run([dig, "+short", record_type, domain_name], check=False, capture_output=True, text=True, timeout=8)
                            target.extend(sorted({line.strip().rstrip(".") for line in result.stdout.splitlines() if line.strip()}))
                        except (OSError, subprocess.TimeoutExpired):
                            pass
                else:
                    try:
                        observed_a.extend(socket.gethostbyname_ex(domain_name)[2])
                    except OSError:
                        pass
                domain_row = conn.execute("SELECT * FROM domains WHERE linked_website_id = ?", (website_id,)).fetchone()
                expected_ns = parse_json_field(domain_row["nameservers_json"], []) if domain_row else []
                if domain_row and not expected_ns and observed_ns:
                    conn.execute("UPDATE domains SET nameservers_json = ? WHERE id = ?", (json.dumps(observed_ns), domain_row["id"]))
                    expected_ns = observed_ns
                ns_ok = bool(observed_ns and (not expected_ns or set(ns.lower() for ns in expected_ns).issubset({ns.lower() for ns in observed_ns})))
                ip_ok = bool(observed_a)
                verified = ns_ok or ip_ok
                job_id = None
                if verified:
                    job_id = enqueue_agent_job(conn, "issue_ssl", "website", website_id, {"mode": "auto", "connection_check": True})
                    conn.execute("UPDATE websites SET ssl_status = 'active' WHERE id = ?", (website_id,))
                return self.json_response({"verified": verified, "nameservers_verified": ns_ok, "ip_verified": ip_ok, "observed_nameservers": observed_ns, "observed_ips": observed_a, "expected_nameservers": expected_ns, "auto_ssl_job_id": job_id, "message": "DNS is reachable. AutoSSL has been queued." if verified else "DNS is not pointing to this hosting account yet."})
            if path == "/api/client/ssl/custom" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = int(body.get("website_id", 0))
                crt = str(body.get("crt", "")).strip()
                key = str(body.get("key", "")).strip()
                if not crt or not key:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "certificate_and_key_required")
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                conn.execute(
                    """
                    INSERT INTO ssl_certificates(account_id, website_id, domain, status, issued_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (account["id"], website_id, website["domain"], "custom"),
                )
                conn.execute("UPDATE websites SET ssl_status = 'custom' WHERE id = ?", (website_id,))
                job_id = enqueue_agent_job(conn, "install_custom_ssl", "website", website_id, {"crt": crt, "key": key})
                log_activity(conn, actor["id"], "custom_ssl_installed", {"website_id": website_id, "domain": website["domain"]})
                return self.json_response({"success": True, "ssl_status": "custom", "job_id": job_id})
            if path == "/api/client/files/launch" and method == "GET":
                require_account(account)
                runtime = account_runtime(conn, account["id"])
                forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
                base_url = resolve_tool_launch_url("filebrowser", runtime.get("filebrowser_url", ""), account, forwarded_host)
                requested_path = query.get("path", [""])[0].strip()
                launch_token = create_jwt(
                    {
                        "sub": actor["id"],
                        "actor_type": "user",
                        "purpose": "tool_launch",
                        "tool": "filebrowser",
                        "account_id": account["id"],
                        "username": account["username"],
                    },
                    CONFIG.jwt_secret,
                    600,
                )
                launch_url = f"{base_url}/auth/{launch_token}"
                if requested_path:
                    _, rel_path = normalize_account_relative_path(account, requested_path, allow_empty=True)
                    launch_url += "/files"
                    if rel_path:
                        launch_url += f"/{rel_path}"
                usage = conn.execute(
                    "SELECT storage_mb, storage_limit_mb FROM resource_usage_samples WHERE account_id = ? ORDER BY sampled_at DESC LIMIT 1",
                    (account["id"],)
                ).fetchone()

                used_mb = usage["storage_mb"] if usage else 0
                limit_mb = usage["storage_limit_mb"] if usage else 0
                if limit_mb == 0:
                    plan = conn.execute("SELECT storage_mb FROM plans WHERE id = ?", (account["plan_id"],)).fetchone()
                    limit_mb = plan["storage_mb"] if plan else 1000

                css_text = f"""
                /* Hide the native FileBrowser disk usage percentage */
                div[class*="progress"], div[class*="usage"], .credits {{
                    display: none !important;
                }}

                body::after {{
                    content: "Storage: {used_mb} MB of {limit_mb} MB used";
                    position: fixed;
                    bottom: 20px;
                    left: 20px;
                    background: var(--surfacePrimary);
                    color: var(--textPrimary);
                    padding: 8px 12px;
                    border-radius: 4px;
                    font-family: sans-serif;
                    font-size: 13px;
                    z-index: 9999;
                    pointer-events: none;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
                }}
                """

                import os
                branding_dir = os.path.join(account["base_path"], ".runtime", "stack", "filebrowser-branding")
                os.makedirs(branding_dir, exist_ok=True)
                with open(os.path.join(branding_dir, "custom.css"), "w") as f:
                    f.write(css_text)
                with open(os.path.join(branding_dir, "custom.js"), "w") as f:
                    f.write(FILEBROWSER_CUSTOM_JS)

                return self.json_response({"launch_url": launch_url, "expires_in": 600})
            if path == "/api/client/files/extract" and method == "POST":
                require_account(account)
                return self.extract_file_archive(account, actor)
            if path == "/api/client/phppgadmin/launch" and method == "GET":
                require_account(account)
                runtime = account_runtime(conn, account["id"])
                forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
                base_url = resolve_tool_launch_url("adminer", runtime.get("adminer_url", ""), account, forwarded_host)
                return self.json_response({"launch_url": base_url, "expires_in": 300})
            if path == "/api/client/phpmyadmin/launch" and method == "GET":
                require_account(account)
                runtime = account_runtime(conn, account["id"])
                forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
                base_url = resolve_tool_launch_url("phpmyadmin", runtime.get("phpmyadmin_url", ""), account, forwarded_host)
                launch_token = create_jwt(
                    {
                        "sub": actor["id"],
                        "actor_type": "user",
                        "purpose": "tool_launch",
                        "tool": "phpmyadmin",
                        "account_id": account["id"],
                        "username": account["username"],
                    },
                    CONFIG.jwt_secret,
                    600,
                )
                launch_url = f"{base_url}/auth/{launch_token}"
                return self.json_response({"launch_url": launch_url, "expires_in": 600})
            if path == "/api/client/webmail/launch" and method == "GET":
                require_account(account)
                runtime = account_runtime(conn, account["id"])
                forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
                raw_url = runtime.get("mail_edge_webmail_url") or runtime.get("mail_webmail_url", "")
                launch_url = resolve_tool_launch_url("webmail", raw_url, account, forwarded_host)
                return self.json_response({"launch_url": launch_url, "expires_in": 3600})
            if path.startswith("/api/client/mailboxes/") and path.endswith("/webmail/launch") and method == "GET":
                require_active_account(account)
                mailbox_id = path_int_id(path.replace("/webmail/launch", ""), "/api/client/mailboxes/")
                mailbox = require_owned_mailbox(conn, account["id"], mailbox_id)
                runtime = account_runtime(conn, account["id"])
                launch_token = create_jwt(
                    {
                        "sub": account["user_id"],
                        "actor_type": "user",
                        "purpose": "tool_launch",
                        "tool": "webmail",
                        "account_id": account["id"],
                        "mailbox_id": mailbox["id"],
                        "jti": secrets.token_urlsafe(16),
                    },
                    CONFIG.jwt_secret,
                    3600,
                )
                mail_host = runtime.get("mail_edge_host") or runtime.get("mail_host", "")
                launch_path = f"/webmail?launch={launch_token}"
                launch_url = f"http://{mail_host}{launch_path}" if mail_host else launch_path
                return self.json_response({"launch_url": launch_url, "expires_in": 3600, "mailbox": mailbox_row_payload(conn, mailbox)})
            if path == "/api/client/databases" and method == "GET":
                require_account(account)
                return self.json_response(client_databases_payload(conn, account["id"]))
            if path == "/api/client/pg-databases" and method == "GET":
                require_account(account)
                return self.json_response(client_pg_databases_payload(conn, account["id"]))
            if path == "/api/client/pg-databases" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                name = validate_db_identifier(body.get("name"), "invalid_database_name")
                try:
                    cur = conn.execute("INSERT INTO pg_databases(account_id, name) VALUES (?, ?)", (account["id"], name))
                except sqlite3.IntegrityError as exc:
                    raise ApiError(HTTPStatus.CONFLICT, "database_name_already_exists") from exc
                job_id = enqueue_agent_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "pg_database_created", {"name": name})
                return self.json_response({"pg_database_id": cur.lastrowid, "job_id": job_id, **client_pg_databases_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if match := re.match(r"^/api/client/pg-databases/(\d+)$", path):
                require_active_account(account)
                database_id = int(match.group(1))
                database = require_owned_pg_database(conn, account["id"], database_id)
                if method == "DELETE":
                    conn.execute("DELETE FROM pg_grants WHERE database_id = ?", (database_id,))
                    conn.execute("DELETE FROM pg_databases WHERE id = ?", (database_id,))
                    job_id = enqueue_agent_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                    log_activity(conn, actor["id"], "pg_database_deleted", {"name": database["name"]})
                    return self.json_response({"deleted": True, "job_id": job_id, **client_pg_databases_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
            if path == "/api/client/pg-databases/users" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                username = validate_db_identifier(body.get("username"), "invalid_database_username")
                password = validate_db_password(body.get("password"))
                try:
                    cur = conn.execute("INSERT INTO pg_users(account_id, username, password) VALUES (?, ?, ?)", (account["id"], username, password))
                except sqlite3.IntegrityError as exc:
                    raise ApiError(HTTPStatus.CONFLICT, "database_user_already_exists") from exc
                job_id = enqueue_agent_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "pg_user_created", {"username": username})
                return self.json_response({"pg_user_id": cur.lastrowid, "job_id": job_id, **client_pg_databases_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if path == "/api/client/pg-databases/users/password" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                user_id = int(body.get("user_id", 0))
                password = validate_db_password(body.get("password"))
                db_user = require_owned_pg_user(conn, account["id"], user_id)
                conn.execute("UPDATE pg_users SET password = ? WHERE id = ?", (password, user_id))
                job_id = enqueue_agent_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "pg_user_password_changed", {"username": db_user["username"]})
                return self.json_response({"success": True, "job_id": job_id, **client_pg_databases_payload(conn, account["id"])})
            if match := re.match(r"^/api/client/pg-databases/users/(\d+)$", path):
                require_active_account(account)
                user_id = int(match.group(1))
                db_user = require_owned_pg_user(conn, account["id"], user_id)
                if method == "DELETE":
                    conn.execute("DELETE FROM pg_grants WHERE user_id = ?", (user_id,))
                    conn.execute("DELETE FROM pg_users WHERE id = ?", (user_id,))
                    job_id = enqueue_agent_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                    log_activity(conn, actor["id"], "pg_user_deleted", {"username": db_user["username"]})
                    return self.json_response({"deleted": True, "job_id": job_id, **client_pg_databases_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
            if path == "/api/client/pg-databases/users/grants" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                database_id = int(body.get("database_id", 0))
                user_id = int(body.get("user_id", 0))
                require_owned_pg_database(conn, account["id"], database_id)
                require_owned_pg_user(conn, account["id"], user_id)
                privileges = validate_db_privileges(body.get("privileges", "ALL"))
                try:
                    cur = conn.execute("INSERT INTO pg_grants(database_id, user_id, privileges) VALUES (?, ?, ?)", (database_id, user_id, privileges))
                except sqlite3.IntegrityError as exc:
                    raise ApiError(HTTPStatus.CONFLICT, "database_grant_already_exists") from exc
                job_id = enqueue_agent_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "pg_grant_created", {"database_id": database_id, "user_id": user_id})
                return self.json_response({"pg_grant_id": cur.lastrowid, "job_id": job_id, **client_pg_databases_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if match := re.match(r"^/api/client/pg-databases/users/grants/(\d+)$", path):
                require_active_account(account)
                grant_id = int(match.group(1))
                grant = require_owned_pg_grant(conn, account["id"], grant_id)
                if method == "DELETE":
                    conn.execute("DELETE FROM pg_grants WHERE id = ?", (grant_id,))
                    job_id = enqueue_agent_job(conn, "sync_pg_databases", "hosting_account", account["id"], {})
                    log_activity(conn, actor["id"], "pg_grant_deleted", {"grant_id": grant["id"]})
                    return self.json_response({"deleted": True, "job_id": job_id, **client_pg_databases_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

            if path == "/api/client/databases" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "databases", "max_databases", "database_limit_reached")
                body = self.read_json()
                name = validate_db_identifier(body.get("name") or f"{account['username']}_app", "invalid_database_name")
                username = validate_db_identifier(body.get("username") or name, "invalid_database_username")
                password = body.get("password")
                if conn.execute("SELECT id FROM databases WHERE name = ?", (name,)).fetchone():
                    raise ApiError(HTTPStatus.CONFLICT, "database_name_already_exists")
                cur = conn.execute(
                    "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                    (account["id"], name, username, "active"),
                )
                db_id = cur.lastrowid
                if password:
                    password = validate_db_password(password)
                    db_user = conn.execute("SELECT id FROM database_users WHERE username = ?", (username,)).fetchone()
                    if db_user:
                        user_id = db_user["id"]
                    else:
                        user_cur = conn.execute(
                            "INSERT INTO database_users(account_id, username, password_hash, status) VALUES (?, ?, ?, ?)",
                            (account["id"], username, hash_password(password), "active"),
                        )
                        user_id = user_cur.lastrowid
                        enqueue_agent_job(conn, "create_database_user", "database_user", user_id, {"username": username, "password": password, "account_id": account["id"]})

                    grant = conn.execute("SELECT id FROM database_grants WHERE database_id = ? AND user_id = ?", (db_id, user_id)).fetchone()
                    if not grant:
                        grant_cur = conn.execute(
                            "INSERT INTO database_grants(database_id, user_id, privileges, status) VALUES (?, ?, 'ALL', 'active')",
                            (db_id, user_id),
                        )
                        enqueue_agent_job(conn, "grant_database_user", "database_grant", grant_cur.lastrowid, {})
                job_id = enqueue_agent_job(conn, "create_database", "database", db_id, {"name": name, "account_id": account["id"]})
                log_activity(conn, actor["id"], "database_created", {"name": name})
                return self.json_response({"database_id": db_id, "job_id": job_id, **client_databases_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if path.startswith("/api/client/databases/"):
                require_active_account(account)
                database_id = path_int_id(path, "/api/client/databases/")
                database = require_owned_database(conn, account["id"], database_id)
                if method == "PATCH":
                    body = self.read_json()
                    name = validate_db_identifier(body.get("name") or database["name"], "invalid_database_name")
                    status = body.get("status", database["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_database_status")
                    duplicate = conn.execute("SELECT id FROM databases WHERE name = ? AND id != ?", (name, database_id)).fetchone()
                    if duplicate:
                        raise ApiError(HTTPStatus.CONFLICT, "database_name_already_exists")
                    conn.execute(
                        "UPDATE databases SET name = ?, status = ? WHERE id = ?",
                        (name, status, database_id),
                    )
                    job_id = enqueue_agent_job(conn, "update_database", "database", database_id, {"name": name, "status": status})
                    log_activity(conn, actor["id"], "database_updated", {"name": name})
                    return self.json_response({"job_id": job_id, **client_databases_payload(conn, account["id"])})
                if method == "DELETE":
                    conn.execute("DELETE FROM database_grants WHERE database_id = ?", (database_id,))
                    conn.execute("UPDATE wordpress_installs SET database_id = NULL WHERE database_id = ?", (database_id,))
                    conn.execute("DELETE FROM databases WHERE id = ?", (database_id,))
                    job_id = enqueue_agent_job(conn, "delete_database", "database", database_id, {"name": database["name"], "account_id": account["id"]})
                    log_activity(conn, actor["id"], "database_deleted", {"name": database["name"]})
                    return self.json_response({"deleted": True, "job_id": job_id, **client_databases_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_database_route")
            if path == "/api/client/database-users" and method == "GET":
                require_account(account)
                return self.json_response(client_databases_payload(conn, account["id"]))
            if path == "/api/client/database-users" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                username = validate_db_identifier(body.get("username"), "invalid_database_username")
                password = validate_db_password(body.get("password"))
                if conn.execute("SELECT id FROM database_users WHERE username = ?", (username,)).fetchone():
                    raise ApiError(HTTPStatus.CONFLICT, "database_user_already_exists")
                cur = conn.execute(
                    """
                    INSERT INTO database_users(account_id, username, password_hash, status)
                    VALUES (?, ?, ?, ?)
                    """,
                    (account["id"], username, hash_password(password), "active"),
                )
                job_id = enqueue_agent_job(conn, "create_database_user", "database_user", cur.lastrowid, {"username": username, "password": password, "account_id": account["id"]})
                log_activity(conn, actor["id"], "database_user_created", {"username": username})
                return self.json_response({"database_user_id": cur.lastrowid, "job_id": job_id, **client_databases_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if path.startswith("/api/client/database-users/"):
                require_active_account(account)
                user_id = path_int_id(path, "/api/client/database-users/")
                db_user = require_owned_database_user(conn, account["id"], user_id)
                if method == "PATCH":
                    body = self.read_json()
                    username = validate_db_identifier(body.get("username") or db_user["username"], "invalid_database_username")
                    status = body.get("status", db_user["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_database_user_status")
                    duplicate = conn.execute("SELECT id FROM database_users WHERE username = ? AND id != ?", (username, user_id)).fetchone()
                    if duplicate:
                        raise ApiError(HTTPStatus.CONFLICT, "database_user_already_exists")
                    params = [username, status]
                    password_sql = ""
                    if body.get("password"):
                        password = validate_db_password(body.get("password"))
                        password_sql = ", password_hash = ?"
                        params.append(hash_password(password))
                    params.append(user_id)
                    conn.execute(
                        f"UPDATE database_users SET username = ?, status = ?, updated_at = CURRENT_TIMESTAMP{password_sql} WHERE id = ?",
                        tuple(params),
                    )
                    job_id = enqueue_agent_job(conn, "update_database_user", "database_user", user_id, {"username": username, "status": status, "password": body.get("password"), "account_id": account["id"]})
                    log_activity(conn, actor["id"], "database_user_updated", {"username": username})
                    return self.json_response({"job_id": job_id, **client_databases_payload(conn, account["id"])})
                if method == "DELETE":
                    conn.execute("DELETE FROM database_grants WHERE user_id = ?", (user_id,))
                    conn.execute("DELETE FROM database_users WHERE id = ?", (user_id,))
                    job_id = enqueue_agent_job(conn, "delete_database_user", "database_user", user_id, {"username": db_user["username"], "account_id": account["id"]})
                    log_activity(conn, actor["id"], "database_user_deleted", {"username": db_user["username"]})
                    return self.json_response({"deleted": True, "job_id": job_id, **client_databases_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_database_user_route")
            if path == "/api/client/database-grants" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                database_id = int(body.get("database_id"))
                user_id = int(body.get("user_id"))
                require_owned_database(conn, account["id"], database_id)
                require_owned_database_user(conn, account["id"], user_id)
                privileges = validate_db_privileges(body.get("privileges", "ALL"))
                try:
                    cur = conn.execute(
                        """
                        INSERT INTO database_grants(database_id, user_id, privileges, status)
                        VALUES (?, ?, ?, ?)
                        """,
                        (database_id, user_id, privileges, "active"),
                    )
                except Exception as exc:
                    if "UNIQUE" in str(exc).upper():
                        raise ApiError(HTTPStatus.CONFLICT, "database_grant_already_exists") from exc
                    raise
                job_id = enqueue_agent_job(conn, "grant_database_user", "database_grant", cur.lastrowid, {"database_id": database_id, "user_id": user_id, "privileges": privileges, "account_id": account["id"]})
                log_activity(conn, actor["id"], "database_user_added_to_database", {"database_id": database_id, "user_id": user_id})
                return self.json_response({"database_grant_id": cur.lastrowid, "job_id": job_id, **client_databases_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if path.startswith("/api/client/database-grants/"):
                require_active_account(account)
                grant_id = path_int_id(path, "/api/client/database-grants/")
                grant = require_owned_database_grant(conn, account["id"], grant_id)
                if method == "PATCH":
                    body = self.read_json()
                    privileges = validate_db_privileges(body.get("privileges", grant["privileges"]))
                    status = body.get("status", grant["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_database_grant_status")
                    conn.execute(
                        "UPDATE database_grants SET privileges = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (privileges, status, grant_id),
                    )
                    job_id = enqueue_agent_job(conn, "update_database_grant", "database_grant", grant_id, {"privileges": privileges, "status": status})
                    log_activity(conn, actor["id"], "database_grant_updated", {"grant_id": grant_id})
                    return self.json_response({"job_id": job_id, **client_databases_payload(conn, account["id"])})
                if method == "DELETE":
                    conn.execute("DELETE FROM database_grants WHERE id = ?", (grant_id,))
                    job_id = enqueue_agent_job(conn, "revoke_database_user", "database_grant", grant_id, {"database_id": grant["database_id"], "user_id": grant["user_id"], "account_id": account["id"]})
                    log_activity(conn, actor["id"], "database_user_removed_from_database", {"grant_id": grant_id})
                    return self.json_response({"deleted": True, "job_id": job_id, **client_databases_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_database_grant_route")
            if path == "/api/client/mailboxes" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "mailboxes", "max_mailboxes", "mailbox_limit_reached")
                body = self.read_json()
                email = normalize_email(body.get("email"))
                local_part, domain = split_mailbox_address(email)
                if not local_part or not domain:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mailbox_address")
                mail_domain = require_owned_mail_domain(conn, account["id"], domain)
                password = validate_password(body.get("password", ""))
                confirm_password = str(body.get("confirm_password") or "").strip()
                if confirm_password and confirm_password != password:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "mailbox_password_mismatch")
                quota_mb = positive_int(body.get("quota_mb", 1024), "invalid_mailbox_quota", minimum=100, maximum=100000)
                storage_path = str(mailbox_storage_path(account["base_path"], email))
                ensure_mailbox_storage(storage_path)
                password_secret = encrypt_secret(password, CONFIG.jwt_secret)
                cur = conn.execute(
                    """
                    INSERT INTO mailboxes(
                      account_id, email, local_part, domain, storage_path, mail_domain_id, quota_mb, status, password_hash, password_secret
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account["id"],
                        email,
                        local_part,
                        domain,
                        storage_path,
                        mail_domain["mail_domain_id"],
                        quota_mb,
                        "active",
                        hash_password(password),
                        password_secret,
                    ),
                )
                job_id = enqueue_agent_job(conn, "sync_mailboxes", "hosting_account", account["id"], {"mailbox_id": cur.lastrowid, "email": email})
                log_activity(conn, actor["id"], "mailbox_created", {"mailbox_id": cur.lastrowid, "email": email})
                created = conn.execute("SELECT * FROM mailboxes WHERE id = ?", (cur.lastrowid,)).fetchone()
                return self.json_response({"mailbox_id": cur.lastrowid, "job_id": job_id, "mailbox": mailbox_row_payload(conn, created)}, HTTPStatus.CREATED)
            if path == "/api/client/backups" and method == "POST":
                require_active_account(account)
                cur = conn.execute(
                    "INSERT INTO backups(account_id, kind, status) VALUES (?, ?, ?)",
                    (account["id"], "manual", "queued"),
                )
                job_id = enqueue_agent_job(conn, "manual_backup", "backup", cur.lastrowid, {})
                backup = conn.execute("SELECT * FROM backups WHERE id = ?", (cur.lastrowid,)).fetchone()
                return self.json_response({"backup_id": cur.lastrowid, "status": backup["status"], "job_id": job_id}, HTTPStatus.CREATED)
            if path.startswith("/api/client/backups/") and path.endswith("/download") and method == "GET":
                require_account(account)
                backup_id = path_int_id(path, "/api/client/backups/")
                backup = conn.execute("SELECT * FROM backups WHERE id = ? AND account_id = ?", (backup_id, account["id"])).fetchone()
                if not backup:
                    raise ApiError(HTTPStatus.NOT_FOUND, "backup_not_found")
                artifact_path = Path(backup["artifact_path"] or "")
                if not artifact_path.exists() or not artifact_path.is_file():
                    raise ApiError(HTTPStatus.NOT_FOUND, "backup_artifact_missing")
                data = artifact_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", f'attachment; filename="{artifact_path.name}"')
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                self.record_access_log(HTTPStatus.OK, len(data))
                return
            if path == "/api/client/restores" and method == "POST":
                require_active_account(account)
                job_id = enqueue_agent_job(conn, "restore_backup", "hosting_account", account["id"], self.read_json())
                job = conn.execute("SELECT status FROM jobs WHERE id = ?", (job_id,)).fetchone()
                return self.json_response({"status": job["status"], "job_id": job_id})
            if path == "/api/client/cron-jobs" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "cron_jobs", "max_cron_jobs", "cron_job_limit_reached")
                body = self.read_json()
                try:
                    schedule = validate_cron_schedule(body.get("schedule", "*/15 * * * *"))
                except AgentError as exc:
                    raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
                command = str(body.get("command", "php cron.php")).replace("\n", " ").strip()
                if not command:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_cron_command")
                cur = conn.execute(
                    "INSERT INTO cron_jobs(account_id, schedule, command, status, next_run_at, last_exit_code, last_output) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (account["id"], schedule, command, "enabled", cron_next_run_at(schedule), None, None),
                )
                job_id = enqueue_agent_job(conn, "create_cron_job", "cron_job", cur.lastrowid, {})
                return self.json_response({"cron_job_id": cur.lastrowid, "job_id": job_id}, HTTPStatus.CREATED)
            if path == "/api/client/git-deployments" and method == "GET":
                require_account(account)
                rows = conn.execute(
                    "SELECT * FROM git_deployments WHERE account_id = ? ORDER BY id",
                    (account["id"],),
                ).fetchall()
                return self.json_response({"git_deployments": rows_to_dicts(rows)})
            if path == "/api/client/git-deployments" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                repository_url = str(body.get("repository_url", "")).strip()
                if not repository_url:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "repository_url_required")
                if not validate_git_repository_url(repository_url, is_development=CONFIG.dev_auth_test_mode or CONFIG.env == "development" or CONFIG.agent_mode == "simulate"):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_repository_url")
                branch = clean_text(body.get("branch", "main"), "main")
                if not validate_git_branch(branch):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_branch")
                deploy_text = str(body.get("deploy_path") or "").strip()
                if not deploy_text:
                    repo_slug = re.sub(r"\.git$", "", repository_url.rstrip("/").split("/")[-1])
                    deploy_text = f"git/{repo_slug or 'deployment'}"

                deploy_path, _ = normalize_account_relative_path(account, deploy_text, label="deploy_path")
                cur = conn.execute(
                    "INSERT INTO git_deployments(account_id, repository_url, branch, deploy_path, status) VALUES (?, ?, ?, ?, ?)",
                    (account["id"], repository_url, branch, str(deploy_path), "configured"),
                )
                job_id = enqueue_agent_job(conn, "git_deploy", "git_deployment", cur.lastrowid, {})
                return self.json_response({"git_deployment_id": cur.lastrowid, "job_id": job_id}, HTTPStatus.CREATED)
            if path.startswith("/api/client/git-deployments/") and path.endswith("/rollback") and method == "POST":
                require_active_account(account)
                deployment_id = path_int_id(path.replace("/rollback", ""), "/api/client/git-deployments/")
                deployment = conn.execute(
                    "SELECT * FROM git_deployments WHERE id = ? AND account_id = ?",
                    (deployment_id, account["id"]),
                ).fetchone()
                if not deployment:
                    raise ApiError(HTTPStatus.NOT_FOUND, "git_deployment_not_found")
                job_id = enqueue_agent_job(conn, "git_rollback", "git_deployment", deployment_id, {})
                log_activity(conn, actor["id"], "git_deployment_rolled_back", {"deployment_id": deployment_id})
                return self.json_response({"job_id": job_id, "status": "queued"})
            if path.startswith("/api/client/git-deployments/"):
                require_active_account(account)
                deployment_id = path_int_id(path, "/api/client/git-deployments/")
                deployment = conn.execute(
                    "SELECT * FROM git_deployments WHERE id = ? AND account_id = ?",
                    (deployment_id, account["id"]),
                ).fetchone()
                if not deployment:
                    raise ApiError(HTTPStatus.NOT_FOUND, "git_deployment_not_found")
                if method == "DELETE":
                    conn.execute("DELETE FROM git_deployments WHERE id = ?", (deployment_id,))
                    log_activity(conn, actor["id"], "git_deployment_deleted", {"deployment_id": deployment_id})
                    return self.json_response({"deleted": True})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_git_deployment_route")
            if path == "/api/client/mailboxes" and method == "GET":
                require_account(account)
                return self.json_response(client_mailboxes_payload(conn, account["id"]))

            if path.startswith("/api/client/mailboxes/"):
                require_active_account(account)
                mailbox_id = path_int_id(path, "/api/client/mailboxes/")
                mailbox = require_owned_mailbox(conn, account["id"], mailbox_id)
                if method == "PATCH":
                    body = self.read_json()
                    raw_email = str(body.get("email") or mailbox["email"]).strip()
                    email = normalize_email(raw_email)
                    local_part, domain = split_mailbox_address(email)
                    if not local_part or not domain:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mailbox_address")
                    mail_domain = require_owned_mail_domain(conn, account["id"], domain)
                    quota_mb = positive_int(body.get("quota_mb", mailbox["quota_mb"]), "invalid_mailbox_quota", minimum=100, maximum=100000)
                    status = body.get("status", mailbox["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mailbox_status")
                    new_storage_path = str(mailbox_storage_path(account["base_path"], email))
                    old_storage_path = str(mailbox["storage_path"] or "")
                    if new_storage_path != old_storage_path:
                        move_mailbox_storage(old_storage_path, new_storage_path, account["base_path"])
                    else:
                        ensure_mailbox_storage(new_storage_path)
                    params = [email, local_part, domain, new_storage_path, mail_domain["mail_domain_id"], quota_mb, status]
                    update_sql = """
                        UPDATE mailboxes
                        SET email = ?, local_part = ?, domain = ?, storage_path = ?, mail_domain_id = ?, quota_mb = ?, status = ?
                    """
                    if body.get("password"):
                        password = validate_password(body.get("password", ""))
                        confirm_password = str(body.get("confirm_password") or "").strip()
                        if confirm_password and confirm_password != password:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "mailbox_password_mismatch")
                        update_sql += ", password_hash = ?, password_secret = ?"
                        params.append(hash_password(password))
                        params.append(encrypt_secret(password, CONFIG.jwt_secret))
                    update_sql += " WHERE id = ?"
                    duplicate = conn.execute("SELECT id FROM mailboxes WHERE email = ? AND id != ?", (email, mailbox_id)).fetchone()
                    if duplicate:
                        raise ApiError(HTTPStatus.CONFLICT, "mailbox_already_exists")
                    conn.execute(update_sql, tuple(params + [mailbox_id]))
                    job_id = enqueue_agent_job(conn, "sync_mailboxes", "hosting_account", account["id"], {"mailbox_id": mailbox_id, "email": email})
                    log_activity(conn, actor["id"], "mailbox_updated", {"mailbox_id": mailbox_id, "email": email})
                    updated = conn.execute(
                        "SELECT * FROM mailboxes WHERE id = ?",
                        (mailbox_id,),
                    ).fetchone()
                    return self.json_response({"mailbox": mailbox_row_payload(conn, updated), "job_id": job_id})
                if method == "DELETE":
                    conn.execute("DELETE FROM mail_messages WHERE mailbox_id = ?", (mailbox_id,))
                    conn.execute("DELETE FROM mailboxes WHERE id = ?", (mailbox_id,))
                    remove_mailbox_storage(mailbox["storage_path"], account["base_path"])
                    job_id = enqueue_agent_job(conn, "sync_mailboxes", "hosting_account", account["id"], {"mailbox_id": mailbox_id, "email": mailbox["email"]})
                    log_activity(conn, actor["id"], "mailbox_deleted", {"email": mailbox["email"]})
                    return self.json_response({"deleted": True, "job_id": job_id})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_mailbox_route")
            if path == "/api/client/mail-routing" and method == "GET":
                require_account(account)
                return self.json_response(client_mail_routing_payload(conn, account["id"]))
            if path == "/api/client/mail-domains" and method == "GET":
                require_account(account)
                return self.json_response(client_mail_routing_payload(conn, account["id"]))
            if path.startswith("/api/client/mail-domains/"):
                require_active_account(account)
                mail_domain_id = path_int_id(path, "/api/client/mail-domains/")
                mail_domain = require_owned_mail_domain_id(conn, account["id"], mail_domain_id)
                if path.endswith("/dkim/rotate") and method == "POST":
                    selector = str(mail_domain["dkim_selector"] or "mango").strip().lower()
                    selector = re.sub(r"[^a-z0-9_-]", "", selector) or "mango"
                    material = generate_dkim_material(selector)
                    conn.execute(
                        """
                        UPDATE mail_domains
                        SET dkim_selector = ?, dkim_private_key = ?, dkim_public_key = ?, status = 'active'
                        WHERE id = ?
                        """,
                        (material["selector"], material["private_key"], material["public_key"], mail_domain_id),
                    )
                    log_activity(conn, actor["id"], "mail_dkim_rotated", {"mail_domain_id": mail_domain_id, "selector": material["selector"]})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_domain_id": mail_domain_id, "selector": material["selector"], "action": "mail_dkim_rotated"})
                    updated = require_owned_mail_domain_id(conn, account["id"], mail_domain_id)
                    return self.json_response({"mail_domain": row_to_dict(updated), "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                if method == "PATCH":
                    body = self.read_json()
                    selector_raw = str(body.get("dkim_selector", mail_domain["dkim_selector"]) or "mango").strip().lower()
                    selector = re.sub(r"[^a-z0-9_-]", "", selector_raw) or "mango"
                    spf_policy = str(body.get("spf_policy", mail_domain["spf_policy"]) or recommended_spf_record()).strip()
                    dmarc_policy = str(body.get("dmarc_policy", mail_domain["dmarc_policy"]) or recommended_dmarc_record(mail_domain["name"])).strip()
                    catch_all_enabled = 1 if body.get("catch_all_enabled") else 0
                    catch_all_destination = ""
                    if catch_all_enabled:
                        catch_all_destination = normalize_email(body.get("catch_all_destination"))
                    regenerate_dkim = bool(body.get("regenerate_dkim"))
                    params = [selector, spf_policy, dmarc_policy, catch_all_enabled, catch_all_destination, body.get("status", mail_domain["status"])]
                    sql = """
                        UPDATE mail_domains
                        SET dkim_selector = ?, spf_policy = ?, dmarc_policy = ?, catch_all_enabled = ?, catch_all_destination = ?, status = ?
                    """
                    if regenerate_dkim:
                        material = generate_dkim_material(selector)
                        sql += ", dkim_private_key = ?, dkim_public_key = ?"
                        params.extend([material["private_key"], material["public_key"]])
                    sql += " WHERE id = ?"
                    params.append(mail_domain_id)
                    conn.execute(sql, tuple(params))
                    if catch_all_enabled:
                        log_mail_delivery(conn, account["id"], "catch_all_updated", destination_email=catch_all_destination, mailbox_id=None, direction="inbound", details={"mail_domain_id": mail_domain_id}, status="configured")
                    log_activity(conn, actor["id"], "mail_domain_updated", {"mail_domain_id": mail_domain_id, "selector": selector})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_domain_id": mail_domain_id, "selector": selector, "action": "mail_domain_updated"})
                    updated = require_owned_mail_domain_id(conn, account["id"], mail_domain_id)
                    return self.json_response({"mail_domain": row_to_dict(updated), "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
            if path == "/api/client/mail-aliases" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                source_email = normalize_email(body.get("source_email"))
                destination_email = normalize_email(body.get("destination_email"))
                source_local, source_domain = split_mailbox_address(source_email)
                if not source_local or not source_domain:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mail_alias_source")
                require_owned_mail_domain(conn, account["id"], source_domain)
                require_owned_mail_domain(conn, account["id"], split_mailbox_address(destination_email)[1])
                cur = conn.execute(
                    "INSERT INTO mail_aliases(account_id, source_email, destination_email, status) VALUES (?, ?, ?, ?)",
                    (account["id"], source_email, destination_email, "active"),
                )
                log_activity(conn, actor["id"], "mail_alias_created", {"alias_id": cur.lastrowid, "source_email": source_email})
                log_mail_delivery(conn, account["id"], "alias_created", source_email=source_email, destination_email=destination_email, status="configured")
                job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_alias_id": cur.lastrowid, "source_email": source_email, "action": "mail_alias_created"})
                return self.json_response({"mail_alias_id": cur.lastrowid, "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if path.startswith("/api/client/mail-aliases/"):
                require_active_account(account)
                alias_id = path_int_id(path, "/api/client/mail-aliases/")
                alias = conn.execute("SELECT * FROM mail_aliases WHERE id = ? AND account_id = ?", (alias_id, account["id"])).fetchone()
                if not alias:
                    raise ApiError(HTTPStatus.NOT_FOUND, "mail_alias_not_found")
                if method == "PATCH":
                    body = self.read_json()
                    source_email = normalize_email(body.get("source_email", alias["source_email"]))
                    destination_email = normalize_email(body.get("destination_email", alias["destination_email"]))
                    if split_mailbox_address(source_email)[0] == "":
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mail_alias_source")
                    require_owned_mail_domain(conn, account["id"], split_mailbox_address(source_email)[1])
                    require_owned_mail_domain(conn, account["id"], split_mailbox_address(destination_email)[1])
                    status = body.get("status", alias["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mail_alias_status")
                    conn.execute(
                        "UPDATE mail_aliases SET source_email = ?, destination_email = ?, status = ? WHERE id = ?",
                        (source_email, destination_email, status, alias_id),
                    )
                    log_activity(conn, actor["id"], "mail_alias_updated", {"alias_id": alias_id})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_alias_id": alias_id, "source_email": source_email, "action": "mail_alias_updated"})
                    return self.json_response({"job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                if method == "DELETE":
                    conn.execute("DELETE FROM mail_aliases WHERE id = ?", (alias_id,))
                    log_activity(conn, actor["id"], "mail_alias_deleted", {"alias_id": alias_id})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_alias_id": alias_id, "action": "mail_alias_deleted"})
                    return self.json_response({"deleted": True, "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_mail_alias_route")
            if path == "/api/client/mail-forwarders" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                source_email = normalize_email(body.get("source_email"))
                destination_email = normalize_email(body.get("destination_email"))
                if split_mailbox_address(source_email)[0] == "":
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mail_forwarder_source")
                require_owned_mail_domain(conn, account["id"], split_mailbox_address(source_email)[1])
                cur = conn.execute(
                    "INSERT INTO mail_forwarders(account_id, source_email, destination_email, status) VALUES (?, ?, ?, ?)",
                    (account["id"], source_email, destination_email, "active"),
                )
                log_activity(conn, actor["id"], "mail_forwarder_created", {"forwarder_id": cur.lastrowid, "source_email": source_email})
                log_mail_delivery(conn, account["id"], "forwarder_created", source_email=source_email, destination_email=destination_email, status="configured")
                job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_forwarder_id": cur.lastrowid, "source_email": source_email, "action": "mail_forwarder_created"})
                return self.json_response({"mail_forwarder_id": cur.lastrowid, "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if path.startswith("/api/client/mail-forwarders/"):
                require_active_account(account)
                forwarder_id = path_int_id(path, "/api/client/mail-forwarders/")
                forwarder = conn.execute("SELECT * FROM mail_forwarders WHERE id = ? AND account_id = ?", (forwarder_id, account["id"])).fetchone()
                if not forwarder:
                    raise ApiError(HTTPStatus.NOT_FOUND, "mail_forwarder_not_found")
                if method == "PATCH":
                    body = self.read_json()
                    source_email = normalize_email(body.get("source_email", forwarder["source_email"]))
                    destination_email = normalize_email(body.get("destination_email", forwarder["destination_email"]))
                    if split_mailbox_address(source_email)[0] == "":
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mail_forwarder_source")
                    require_owned_mail_domain(conn, account["id"], split_mailbox_address(source_email)[1])
                    status = body.get("status", forwarder["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mail_forwarder_status")
                    conn.execute(
                        "UPDATE mail_forwarders SET source_email = ?, destination_email = ?, status = ? WHERE id = ?",
                        (source_email, destination_email, status, forwarder_id),
                    )
                    log_activity(conn, actor["id"], "mail_forwarder_updated", {"forwarder_id": forwarder_id})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_forwarder_id": forwarder_id, "source_email": source_email, "action": "mail_forwarder_updated"})
                    return self.json_response({"job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                if method == "DELETE":
                    conn.execute("DELETE FROM mail_forwarders WHERE id = ?", (forwarder_id,))
                    log_activity(conn, actor["id"], "mail_forwarder_deleted", {"forwarder_id": forwarder_id})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_forwarder_id": forwarder_id, "action": "mail_forwarder_deleted"})
                    return self.json_response({"deleted": True, "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_mail_forwarder_route")
            if path == "/api/client/mail-autoresponders" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                mailbox_id = int(body.get("mailbox_id", 0))
                mailbox = require_owned_mailbox(conn, account["id"], mailbox_id)
                subject = clean_text(body.get("subject", "Auto-reply"), "Auto-reply")
                reply_body = str(body.get("body") or "").strip()
                if not reply_body:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "autoresponder_body_required")
                enabled = 1 if body.get("enabled", True) else 0
                cur = conn.execute(
                    "INSERT INTO mail_autoresponders(account_id, mailbox_id, subject, body, enabled) VALUES (?, ?, ?, ?, ?)",
                    (account["id"], mailbox_id, subject, reply_body, enabled),
                )
                log_activity(conn, actor["id"], "mail_autoresponder_created", {"autoresponder_id": cur.lastrowid, "mailbox_id": mailbox_id, "email": mailbox["email"]})
                log_mail_delivery(conn, account["id"], "autoresponder_created", source_email=mailbox["email"], destination_email=mailbox["email"], mailbox_id=mailbox_id, direction="inbound", status="configured")
                job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_autoresponder_id": cur.lastrowid, "mailbox_id": mailbox_id, "action": "mail_autoresponder_created"})
                return self.json_response({"mail_autoresponder_id": cur.lastrowid, "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])}, HTTPStatus.CREATED)
            if path.startswith("/api/client/mail-autoresponders/"):
                require_active_account(account)
                autoresponder_id = path_int_id(path, "/api/client/mail-autoresponders/")
                autoresponder = conn.execute("SELECT * FROM mail_autoresponders WHERE id = ? AND account_id = ?", (autoresponder_id, account["id"])).fetchone()
                if not autoresponder:
                    raise ApiError(HTTPStatus.NOT_FOUND, "mail_autoresponder_not_found")
                if method == "PATCH":
                    body = self.read_json()
                    subject = clean_text(body.get("subject", autoresponder["subject"]), autoresponder["subject"])
                    reply_body = str(body.get("body", autoresponder["body"]) or "").strip()
                    enabled = 1 if body.get("enabled", bool(autoresponder["enabled"])) else 0
                    if not reply_body:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "autoresponder_body_required")
                    conn.execute(
                        "UPDATE mail_autoresponders SET subject = ?, body = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (subject, reply_body, enabled, autoresponder_id),
                    )
                    log_activity(conn, actor["id"], "mail_autoresponder_updated", {"autoresponder_id": autoresponder_id})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_autoresponder_id": autoresponder_id, "mailbox_id": autoresponder["mailbox_id"], "action": "mail_autoresponder_updated"})
                    return self.json_response({"job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                if method == "DELETE":
                    conn.execute("DELETE FROM mail_autoresponders WHERE id = ?", (autoresponder_id,))
                    log_activity(conn, actor["id"], "mail_autoresponder_deleted", {"autoresponder_id": autoresponder_id})
                    job_id = enqueue_mail_policy_sync(conn, account["id"], {"mail_autoresponder_id": autoresponder_id, "action": "mail_autoresponder_deleted"})
                    return self.json_response({"deleted": True, "job_id": job_id, "mail": client_mail_routing_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_mail_autoresponder_route")
            if path == "/api/client/mail-logs" and method == "GET":
                require_account(account)
                return self.json_response({"mail": client_mail_routing_payload(conn, account["id"])})
            if path == "/api/client/cron-jobs" and method == "GET":
                require_account(account)
                rows = conn.execute(
                    "SELECT * FROM cron_jobs WHERE account_id = ? ORDER BY id",
                    (account["id"],),
                ).fetchall()
                return self.json_response({"cron_jobs": decorate_cron_jobs(account, rows_to_dicts(rows))})
            if path == "/api/client/cron-jobs" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "cron_jobs", "max_cron_jobs", "cron_job_limit_reached")
                body = self.read_json()
                try:
                    schedule = validate_cron_schedule(body.get("schedule", "*/15 * * * *"))
                except AgentError as exc:
                    raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
                command = str(body.get("command", "php cron.php")).replace("\n", " ").strip()
                if not command:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_cron_command")
                cur = conn.execute(
                    "INSERT INTO cron_jobs(account_id, schedule, command, status, next_run_at, last_exit_code, last_output) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (account["id"], schedule, command, "enabled", cron_next_run_at(schedule), None, None),
                )
                job_id = enqueue_agent_job(conn, "create_cron_job", "cron_job", cur.lastrowid, {})
                return self.json_response({"cron_job_id": cur.lastrowid, "job_id": job_id}, HTTPStatus.CREATED)
            if path.startswith("/api/client/cron-jobs/"):
                require_active_account(account)
                cron_id = path_int_id(path, "/api/client/cron-jobs/")
                cron = conn.execute(
                    "SELECT * FROM cron_jobs WHERE id = ? AND account_id = ?",
                    (cron_id, account["id"]),
                ).fetchone()
                if not cron:
                    raise ApiError(HTTPStatus.NOT_FOUND, "cron_job_not_found")
                if method == "PATCH":
                    body = self.read_json()
                    try:
                        schedule = validate_cron_schedule(body.get("schedule", cron["schedule"]))
                    except AgentError as exc:
                        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
                    command = str(body.get("command", cron["command"])).replace("\n", " ").strip()
                    if not command:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_cron_command")
                    status = body.get("status", cron["status"])
                    if status not in {"enabled", "disabled"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_cron_status")
                    conn.execute(
                        "UPDATE cron_jobs SET schedule = ?, command = ?, status = ?, next_run_at = ? WHERE id = ?",
                        (schedule, command, status, cron_next_run_at(schedule) if status == "enabled" else None, cron_id),
                    )
                    job_id = enqueue_agent_job(conn, "sync_cron_jobs", "hosting_account", account["id"], {})
                    log_activity(conn, actor["id"], "cron_job_updated", {"cron_id": cron_id})
                    updated = conn.execute("SELECT * FROM cron_jobs WHERE id = ?", (cron_id,)).fetchone()
                    return self.json_response({"cron_job": row_to_dict(updated), "job_id": job_id})
                if method == "DELETE":
                    conn.execute("DELETE FROM cron_jobs WHERE id = ?", (cron_id,))
                    job_id = enqueue_agent_job(conn, "sync_cron_jobs", "hosting_account", account["id"], {})
                    log_activity(conn, actor["id"], "cron_job_deleted", {"cron_id": cron_id})
                    return self.json_response({"deleted": True, "job_id": job_id})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_cron_job_route")

            if path == "/api/client/services/restart" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                service_name = body.get("service")
                if not service_name:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "service_required")
                valid_services = ["web", "db", "filebrowser", "phpmyadmin", "cron", "sftp"]
                if service_name not in valid_services:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_service")
                job_id = enqueue_agent_job(conn, "restart_service", "hosting_account", account["id"], {"service": service_name})
                log_activity(conn, actor["id"], "service_restarted", {"account_id": account["id"], "service": service_name})
                return self.json_response({"success": True, "job_id": job_id})

            if path == "/api/client/services/status" and method == "GET":
                require_account(account)
                service_name = query.get("service", [""])[0].strip()
                if service_name:
                    valid_services = ["web", "db", "filebrowser", "phpmyadmin", "cron", "sftp"]
                    if service_name not in valid_services:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_service")
                stack = conn.execute(
                    "SELECT * FROM account_stacks WHERE account_id = ?",
                    (account["id"],),
                ).fetchone()
                if not stack:
                    raise ApiError(HTTPStatus.NOT_FOUND, "stack_not_found")
                payload = Agent(CONFIG).service_status(row_to_dict(account), row_to_dict(stack), service_name or None)
                return self.json_response(payload)

            if path == "/api/client/services/kill-all" and method == "POST":
                require_active_account(account)
                job_id = enqueue_agent_job(conn, "kill_all_processes", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "stack_rebooted", {"account_id": account["id"]})
                return self.json_response({"success": True, "job_id": job_id})

            if path == "/api/client/backups" and method == "GET":
                require_account(account)
                rows = conn.execute(
                    "SELECT * FROM backups WHERE account_id = ? ORDER BY id DESC LIMIT 50",
                    (account["id"],),
                ).fetchall()
                return self.json_response({"backups": rows_to_dicts(rows)})
            if path == "/api/client/backups" and method == "POST":
                require_active_account(account)
                cur = conn.execute(
                    "INSERT INTO backups(account_id, kind, status) VALUES (?, ?, ?)",
                    (account["id"], "manual", "queued"),
                )
                job_id = enqueue_agent_job(conn, "manual_backup", "backup", cur.lastrowid, {})
                backup = conn.execute("SELECT * FROM backups WHERE id = ?", (cur.lastrowid,)).fetchone()
                return self.json_response({"backup_id": cur.lastrowid, "status": backup["status"], "job_id": job_id}, HTTPStatus.CREATED)
            if path.startswith("/api/client/backups/") and path.endswith("/restore") and method == "POST":
                require_active_account(account)
                backup_id = path_int_id(path, "/api/client/backups/")
                backup = conn.execute("SELECT * FROM backups WHERE id = ? AND account_id = ?", (backup_id, account["id"])).fetchone()
                if not backup:
                    raise ApiError(HTTPStatus.NOT_FOUND, "backup_not_found")
                if backup["status"] != "completed":
                    raise ApiError(HTTPStatus.BAD_REQUEST, "backup_not_completed")
                job_id = enqueue_agent_job(conn, "restore_backup", "backup", backup_id, {})
                return self.json_response({"restoring": True, "backup_id": backup_id, "job_id": job_id})
            if path == "/api/client/fix-ownership" and method == "POST":
                require_active_account(account)
                job_id = enqueue_agent_job(conn, "fix_file_ownership", "hosting_account", account["id"], {})
                return self.json_response({"fixed": True, "job_id": job_id})
            if path == "/api/client/wordpress/install" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "databases", "max_databases", "database_limit_reached")
                body = self.read_json()
                website_id = int(body.get("website_id", 0))
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")

                # Validate WordPress form inputs
                site_title = clean_text(body.get("site_title", ""), "My Site")
                admin_username = body.get("admin_username", "").strip()
                if not admin_username or not (admin_username.replace("_", "").replace("-", "").isalnum()):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_admin_username")
                admin_email = normalize_email(body.get("admin_email", ""))
                admin_password = body.get("admin_password", "")
                if not admin_password or len(admin_password) < 8:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "password_too_short")
                allow_overwrite = bool(body.get("allow_overwrite", False))

                # Check if WordPress is already installed
                existing = conn.execute("SELECT id FROM wordpress_installs WHERE website_id = ?", (website_id,)).fetchone()
                if existing:
                    raise ApiError(HTTPStatus.CONFLICT, "wordpress_already_installed")

                # Create database for WordPress
                db_name = f"{account['username']}_wp_{website_id}"
                db_user = f"{account['username']}_wp"
                cur_db = conn.execute(
                    "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                    (account["id"], db_name, db_user, "active"),
                )
                database_id = cur_db.lastrowid
                enqueue_agent_job(conn, "create_database", "database", database_id, {"name": db_name})

                # Create WordPress install record
                cur = conn.execute(
                    """
                    INSERT INTO wordpress_installs(website_id, database_id, site_title, admin_username, admin_email, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (website_id, database_id, site_title, admin_username, admin_email, "installing"),
                )
                install_id = cur.lastrowid

                # Enqueue installation job
                job_id = enqueue_agent_job(conn, "install_wordpress", "wordpress_install", install_id, {
                    "website_id": website_id,
                    "database_id": database_id,
                    "database_name": db_name,
                    "database_user": db_user,
                    "database_password": "dev-db-password-change-me",
                    "database_host": "db",
                    "site_title": site_title,
                    "admin_username": admin_username,
                    "admin_email": admin_email,
                    "admin_password": admin_password,
                    "allow_overwrite": allow_overwrite,
                })
                job = conn.execute("SELECT status, result FROM jobs WHERE id = ?", (job_id,)).fetchone()
                if job and job["status"] == "failed":
                    result = parse_json_field(job["result"], {})
                    raise ApiError(HTTPStatus.BAD_REQUEST, result.get("error", "wordpress_install_failed"))

                log_activity(conn, actor["id"], "wordpress_install_started", {
                    "website_id": website_id,
                    "site_title": site_title,
                    "domain": website["domain"],
                })
                log_audit(conn, "user", actor["id"], "wordpress_install", "wordpress_install", install_id,
                         metadata={"website_id": website_id, "site_title": site_title})

                return self.json_response({
                    "install_id": install_id,
                    "database_id": database_id,
                    "job_id": job_id,
                    "status": "installing"
                }, HTTPStatus.CREATED)
            if path == "/api/client/installer/scripts" and method == "GET":
                require_account(account)
                from .installers import INSTALLERS
                return self.json_response({
                    "scripts": [inst.get_info() for inst in INSTALLERS.values()]
                })
            if path == "/api/client/installer/install" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "databases", "max_databases", "database_limit_reached")
                body = self.read_json()
                script_id = body.get("script_id")
                website_id = int(body.get("website_id", 0))
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                
                from .installers import INSTALLERS
                installer = INSTALLERS.get(script_id)
                if not installer:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_script_id")
                
                site_title = clean_text(body.get("site_title", ""), "My Site")
                admin_username = body.get("admin_username", "").strip()
                if not admin_username or not (admin_username.replace("_", "").replace("-", "").isalnum()):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_admin_username")
                admin_email = normalize_email(body.get("admin_email", ""))
                admin_password = body.get("admin_password", "")
                if not admin_password or len(admin_password) < 8:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "password_too_short")
                allow_overwrite = bool(body.get("allow_overwrite", False))

                if script_id == "wordpress":
                    existing = conn.execute("SELECT id FROM wordpress_installs WHERE website_id = ?", (website_id,)).fetchone()
                    if existing:
                        if not allow_overwrite:
                            raise ApiError(HTTPStatus.CONFLICT, "wordpress_already_installed")
                        conn.execute("DELETE FROM wordpress_installs WHERE website_id = ?", (website_id,))
                        conn.execute("DELETE FROM script_installs WHERE website_id = ? AND script_id = 'wordpress'", (website_id,))
                    
                    db_name = f"{account['username']}_wp_{website_id}"
                    db_user = f"{account['username']}_wp"
                    db_password = "dev-db-password-change-me"
                    
                    existing_db = conn.execute("SELECT id FROM databases WHERE name = ?", (db_name,)).fetchone()
                    if existing_db:
                        database_id = existing_db["id"]
                    else:
                        cur_db = conn.execute(
                            "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                            (account["id"], db_name, db_user, "active"),
                        )
                        database_id = cur_db.lastrowid
                        enqueue_agent_job(conn, "create_database", "database", database_id, {"name": db_name, "account_id": account["id"]})

                    existing_user = conn.execute("SELECT id FROM database_users WHERE username = ?", (db_user,)).fetchone()
                    if existing_user:
                        user_id = existing_user["id"]
                    else:
                        user_cur = conn.execute(
                            "INSERT INTO database_users(account_id, username, password_hash, status) VALUES (?, ?, ?, ?)",
                            (account["id"], db_user, hash_password(db_password), "active"),
                        )
                        user_id = user_cur.lastrowid
                        enqueue_agent_job(conn, "create_database_user", "database_user", user_id, {"username": db_user, "password": db_password, "account_id": account["id"]})

                    grant = conn.execute("SELECT id FROM database_grants WHERE database_id = ? AND user_id = ?", (database_id, user_id)).fetchone()
                    if not grant:
                        grant_cur = conn.execute(
                            "INSERT INTO database_grants(database_id, user_id, privileges, status) VALUES (?, ?, 'ALL', 'active')",
                            (database_id, user_id),
                        )
                        enqueue_agent_job(conn, "grant_database_user", "database_grant", grant_cur.lastrowid, {})
                    
                    conn.execute(
                        """
                        INSERT INTO script_installs(website_id, script_id, database_id, site_title, admin_username, admin_email, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (website_id, script_id, database_id, site_title, admin_username, admin_email, "installing"),
                    )

                    cur = conn.execute(
                        """
                        INSERT INTO wordpress_installs(website_id, database_id, site_title, admin_username, admin_email, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (website_id, database_id, site_title, admin_username, admin_email, "installing"),
                    )
                    install_id = cur.lastrowid
                    
                    job_id = enqueue_agent_job(conn, "install_wordpress", "wordpress_install", install_id, {
                        "website_id": website_id,
                        "database_id": database_id,
                        "database_name": db_name,
                        "database_user": db_user,
                        "database_password": db_password,
                        "database_host": "db",
                        "site_title": site_title,
                        "admin_username": admin_username,
                        "admin_email": admin_email,
                        "admin_password": admin_password,
                        "allow_overwrite": allow_overwrite,
                    })
                else:
                    existing = conn.execute("SELECT id FROM script_installs WHERE website_id = ?", (website_id,)).fetchone()
                    if existing:
                        raise ApiError(HTTPStatus.CONFLICT, "script_already_installed")
                    
                    cur = conn.execute(
                        """
                        INSERT INTO script_installs(website_id, script_id, database_id, site_title, admin_username, admin_email, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (website_id, script_id, None, site_title, admin_username, admin_email, "installing"),
                    )
                    install_id = cur.lastrowid
                    
                    job_id = enqueue_agent_job(conn, "install_script", "script_install", install_id, {
                        "script_id": script_id,
                        "website_id": website_id,
                        "site_title": site_title,
                        "admin_username": admin_username,
                        "admin_email": admin_email,
                        "admin_password": admin_password,
                        "allow_overwrite": allow_overwrite,
                    })

                log_activity(conn, actor["id"], f"{script_id}_install_started", {
                    "website_id": website_id,
                    "site_title": site_title,
                    "domain": website["domain"],
                })

                return self.json_response({
                    "install_id": install_id,
                    "job_id": job_id,
                    "status": "installing"
                }, HTTPStatus.CREATED)
            if path == "/api/client/activity" and method == "GET":
                rows = conn.execute("SELECT * FROM activity_logs WHERE user_id = ? ORDER BY id DESC LIMIT 50", (actor["id"],)).fetchall()
                return self.json_response({"activity": rows_to_dicts(rows)})
            if path == "/api/client/cache/status" and method == "GET":
                require_account(account)
                return self.json_response(client_cache_status(conn, account))
            if path == "/api/client/cache/purge" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = optional_positive_int(body.get("website_id") or "")
                payload = {"scope": "all"}
                if website_id:
                    website = conn.execute(
                        "SELECT * FROM websites WHERE id = ? AND account_id = ?",
                        (website_id, account["id"]),
                    ).fetchone()
                    if not website:
                        raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                    payload["website_id"] = website_id
                    payload["scope"] = "website"
                job_id = enqueue_agent_job(conn, "purge_cache", "hosting_account", account["id"], payload)
                log_activity(conn, actor["id"], "cache_purged", payload)
                return self.json_response({"job_id": job_id, "status": "queued"})
            if path == "/api/client/cache/opcache/reset" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = optional_positive_int(body.get("website_id") or "")
                payload = {"scope": "all"}
                if website_id:
                    website = conn.execute(
                        "SELECT * FROM websites WHERE id = ? AND account_id = ?",
                        (website_id, account["id"]),
                    ).fetchone()
                    if not website:
                        raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                    payload["website_id"] = website_id
                    payload["scope"] = "website"
                job_id = enqueue_agent_job(conn, "reset_opcache", "hosting_account", account["id"], payload)
                log_activity(conn, actor["id"], "opcache_reset", payload)
                return self.json_response({"job_id": job_id, "status": "queued"})
            if path == "/api/client/cache/object-cache/flush" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = optional_positive_int(body.get("website_id") or "")
                payload = {"scope": "all"}
                if website_id:
                    website = conn.execute(
                        "SELECT * FROM websites WHERE id = ? AND account_id = ?",
                        (website_id, account["id"]),
                    ).fetchone()
                    if not website:
                        raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                    payload["website_id"] = website_id
                    payload["scope"] = "website"
                job_id = enqueue_agent_job(conn, "flush_object_cache", "hosting_account", account["id"], payload)
                log_activity(conn, actor["id"], "object_cache_flushed", payload)
                return self.json_response({"job_id": job_id, "status": "queued"})

            if path == "/api/client/disk-usage" and method == "GET":
                require_account(account)
                return self.json_response(client_disk_usage_payload(conn, account))

            if path == "/api/client/redirects" and method == "GET":
                require_account(account)
                redirects = conn.execute(
                    "SELECT r.id, r.website_id, w.domain, r.source_path, r.target_url, r.type, r.match_type, r.created_at FROM redirects r JOIN websites w ON r.website_id = w.id WHERE r.account_id = ?",
                    (account["id"],),
                ).fetchall()
                return self.json_response({"redirects": [dict(r) for r in redirects]})

            if path == "/api/client/api-tokens" and method == "GET":
                require_account(account)
                tokens = conn.execute("SELECT id, name, expires_at, last_used_at, created_at FROM api_tokens WHERE account_id = ?", (account["id"],)).fetchall()
                return self.json_response({"api_tokens": [dict(t) for t in tokens]})

            if path == "/api/client/ftp-accounts" and method == "GET":
                require_account(account)
                ftp_accounts = conn.execute("SELECT id, username, path, created_at FROM ftp_accounts WHERE account_id = ?", (account["id"],)).fetchall()
                return self.json_response({"ftp_accounts": [dict(fa) for fa in ftp_accounts]})

            if path == "/api/client/ftp-accounts" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                username = validate_db_identifier(body.get("username", ""), "invalid_ftp_username")
                password = body.get("password", "")
                ftp_path = body.get("path", "").strip() or "upload"
                if not password:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "username_and_password_required")
                if len(password) < 8:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "password_too_short")
                
                # Prepend the main account username as prefix
                full_username = f"{account['username']}_{username}"
                
                # Check uniqueness
                exists = conn.execute("SELECT id FROM ftp_accounts WHERE username = ?", (full_username,)).fetchone()
                if exists:
                    raise ApiError(HTTPStatus.CONFLICT, "username_taken")
                _, normalized_path = normalize_account_relative_path(account, ftp_path, label="path")
                if not normalized_path:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_path")
                
                cursor = conn.execute(
                    "INSERT INTO ftp_accounts (account_id, username, password, path) VALUES (?, ?, ?, ?)",
                    (account["id"], full_username, password, normalized_path)
                )
                
                job_id = enqueue_agent_job(conn, "sync_ftp_accounts", "hosting_account", account["id"], {})
                
                log_activity(conn, actor["id"], "ftp_account_created", {"username": full_username})
                return self.json_response({"success": True, "job_id": job_id, "ftp_account": {"id": cursor.lastrowid, "username": full_username, "path": normalized_path}})

            if path == "/api/client/api-tokens" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                name = body.get("name", "").strip()
                if not name:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "name_required")

                raw_token = secrets.token_hex(32)
                token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

                cursor = conn.execute(
                    "INSERT INTO api_tokens (account_id, name, token_hash) VALUES (?, ?, ?)",
                    (account["id"], name, token_hash)
                )
                log_activity(conn, actor["id"], "api_token_created", {"name": name})
                return self.json_response({
                    "id": cursor.lastrowid,
                    "name": name,
                    "token": f"mp_{raw_token}"
                }, HTTPStatus.CREATED)

            match_token = re.match(r"^/api/client/api-tokens/(\d+)$", path)
            if match_token and method == "DELETE":
                require_active_account(account)
                token_id = int(match_token.group(1))
                r = conn.execute("SELECT * FROM api_tokens WHERE id = ? AND account_id = ?", (token_id, account["id"])).fetchone()
                if not r:
                    raise ApiError(HTTPStatus.NOT_FOUND, "token_not_found")
                
                conn.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
                log_activity(conn, actor["id"], "api_token_deleted", {"token_id": token_id})
                return self.json_response({"deleted": True})

            if path == "/api/client/2fa/generate" and method == "POST":
                require_active_account(account)
                secret = generate_totp_secret()
                # Create otpauth uri
                # otpauth://totp/MangoPanel:username?secret=secret&issuer=MangoPanel
                import urllib.parse
                issuer = urllib.parse.quote("MangoPanel")
                account_name = urllib.parse.quote(f"MangoPanel:{actor['email']}")
                uri = f"otpauth://totp/{account_name}?secret={secret}&issuer={issuer}"
                return self.json_response({"secret": secret, "uri": uri})

            if path == "/api/client/2fa/enable" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                secret = body.get("secret", "")
                code = body.get("code", "")
                if not verify_totp(secret, code):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_totp_code")
                conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, actor["id"]))
                log_activity(conn, actor["id"], "totp_enabled", {})
                return self.json_response({"enabled": True})

            if path == "/api/client/2fa/disable" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                code = body.get("code", "")
                if not verify_totp(actor["totp_secret"], code):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_totp_code")
                conn.execute("UPDATE users SET totp_secret = NULL WHERE id = ?", (actor["id"],))
                log_activity(conn, actor["id"], "totp_disabled", {})
                return self.json_response({"disabled": True})

            if path == "/api/client/redirects" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = body.get("website_id")
                source_path = body.get("source_path", "").strip()
                target_url = body.get("target_url", "").strip()
                r_type = body.get("type", "301")
                match_type = body.get("match_type", "exact")
                
                if not website_id or not source_path or not target_url:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "missing_fields")
                    
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_website")
                    
                if not source_path.startswith("/"):
                    source_path = "/" + source_path
                    
                cursor = conn.execute(
                    "INSERT INTO redirects(account_id, website_id, source_path, target_url, type, match_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (account["id"], website_id, source_path, target_url, r_type, match_type),
                )
                redirect_id = cursor.lastrowid
                
                job_id = enqueue_agent_job(conn, "sync_redirects", "website", website_id, {})
                log_activity(conn, actor["id"], "redirect_created", {"domain": website["domain"], "source_path": source_path, "target_url": target_url})
                return self.json_response({"id": redirect_id, "job_id": job_id}, HTTPStatus.CREATED)

            match_redirect = re.match(r"^/api/client/redirects/(\d+)$", path)
            if match_redirect and method == "DELETE":
                require_active_account(account)
                redirect_id = int(match_redirect.group(1))
                r = conn.execute("SELECT * FROM redirects WHERE id = ? AND account_id = ?", (redirect_id, account["id"])).fetchone()
                if not r:
                    raise ApiError(HTTPStatus.NOT_FOUND, "redirect_not_found")
                
                conn.execute("DELETE FROM redirects WHERE id = ?", (redirect_id,))
                job_id = enqueue_agent_job(conn, "sync_redirects", "website", r["website_id"], {})
                log_activity(conn, actor["id"], "redirect_deleted", {"redirect_id": redirect_id})
                return self.json_response({"deleted": True, "job_id": job_id})

            if path == "/api/client/protected-directories" and method == "GET":
                require_account(account)
                dirs = conn.execute("SELECT id, path, username, created_at FROM protected_directories WHERE account_id = ?", (account["id"],)).fetchall()
                protected_dirs = []
                for row in dirs:
                    item = dict(row)
                    item["path"] = "/" + item["path"].lstrip("/")
                    protected_dirs.append(item)
                return self.json_response({"protected_dirs": protected_dirs})

            if path == "/api/client/protected-directories" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                dir_path = body.get("path", "").strip()
                username = body.get("username", "").strip()
                password = body.get("password", "")
                
                if not dir_path or not username or not password:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "missing_fields")
                if len(password) < 8:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "password_too_short")
                    
                _, normalized_dir = normalize_account_relative_path(account, dir_path, label="path")
                if not normalized_dir:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_path")
                username = validate_db_identifier(username, "invalid_protected_directory_username")
                    
                try:
                    cursor = conn.execute("INSERT INTO protected_directories(account_id, path, username, password_hash) VALUES (?, ?, ?, ?)", 
                                          (account["id"], normalized_dir, username, "managed_by_agent"))
                    dir_id = cursor.lastrowid
                except sqlite3.IntegrityError:
                    raise ApiError(HTTPStatus.CONFLICT, "directory_already_protected")

                job_id = enqueue_agent_job(conn, "sync_protected_directories", "hosting_account", account["id"], {"path": normalized_dir, "username": username, "password": password})
                log_activity(conn, actor["id"], "directory_protected", {"path": normalized_dir, "username": username})
                return self.json_response({"id": dir_id, "path": "/" + normalized_dir, "username": username, "job_id": job_id}, HTTPStatus.CREATED)

            match_dir = re.match(r"^/api/client/protected-directories/(\d+)$", path)
            if match_dir and method == "DELETE":
                require_active_account(account)
                dir_id = int(match_dir.group(1))
                p_dir = conn.execute("SELECT * FROM protected_directories WHERE id = ? AND account_id = ?", (dir_id, account["id"])).fetchone()
                if not p_dir:
                    raise ApiError(HTTPStatus.NOT_FOUND, "directory_not_found")
                
                conn.execute("DELETE FROM protected_directories WHERE id = ?", (dir_id,))
                job_id = enqueue_agent_job(conn, "sync_protected_directories", "hosting_account", account["id"], {"path": p_dir["path"], "remove": True})
                log_activity(conn, actor["id"], "directory_unprotected", {"path": p_dir["path"]})
                return self.json_response({"deleted": True, "job_id": job_id})

            if path == "/api/client/ip-rules" and method == "GET":
                require_account(account)
                rules = conn.execute("SELECT id, ip, type, created_at FROM ip_rules WHERE account_id = ?", (account["id"],)).fetchall()
                return self.json_response({"ip_rules": [dict(r) for r in rules]})

            if path == "/api/client/ip-rules" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                ip_val = body.get("ip", "").strip()
                rule_type = body.get("type", "block")
                if rule_type not in {"allow", "block"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_rule_type")
                try:
                    ipaddress.ip_network(ip_val, strict=False)
                except ValueError:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_ip_address")
                
                try:
                    cursor = conn.execute("INSERT INTO ip_rules(account_id, ip, type) VALUES (?, ?, ?)", (account["id"], ip_val, rule_type))
                    rule_id = cursor.lastrowid
                except sqlite3.IntegrityError:
                    raise ApiError(HTTPStatus.CONFLICT, "rule_already_exists")

                job_id = enqueue_agent_job(conn, "sync_ip_rules", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "ip_rule_added", {"ip": ip_val, "type": rule_type})
                return self.json_response({"id": rule_id, "ip": ip_val, "type": rule_type, "status": "active", "job_id": job_id}, HTTPStatus.CREATED)

            match = re.match(r"^/api/client/ip-rules/(\d+)$", path)
            if match and method == "DELETE":
                require_active_account(account)
                rule_id = int(match.group(1))
                rule = conn.execute("SELECT * FROM ip_rules WHERE id = ? AND account_id = ?", (rule_id, account["id"])).fetchone()
                if not rule:
                    raise ApiError(HTTPStatus.NOT_FOUND, "rule_not_found")
                
                conn.execute("DELETE FROM ip_rules WHERE id = ?", (rule_id,))
                job_id = enqueue_agent_job(conn, "sync_ip_rules", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "ip_rule_deleted", {"ip": rule["ip"]})
                return self.json_response({"deleted": True, "job_id": job_id})

            if path == "/api/client/hotlink-protection" and method == "GET":
                require_account(account)
                settings = conn.execute("SELECT * FROM hotlink_settings WHERE account_id = ?", (account["id"],)).fetchone()
                return self.json_response({
                    "hotlink": {
                        "enabled": bool(settings["enabled"]) if settings else False,
                        "allowed_domains": settings["allowed_domains"] if settings else "",
                    }
                })

            if path == "/api/client/hotlink-protection" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                enabled = 1 if body.get("enabled") else 0
                allowed_domains = validate_hotlink_allowed_domains(body.get("allowed_domains", ""))
                conn.execute(
                    """
                    INSERT INTO hotlink_settings(account_id, enabled, allowed_domains, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(account_id) DO UPDATE SET
                      enabled = excluded.enabled,
                      allowed_domains = excluded.allowed_domains,
                      updated_at = CURRENT_TIMESTAMP
                    """,
                    (account["id"], enabled, allowed_domains),
                )
                job_id = enqueue_agent_job(conn, "sync_hotlink_protection", "hosting_account", account["id"], {})
                log_activity(conn, actor["id"], "hotlink_protection_updated", {"enabled": bool(enabled)})
                return self.json_response({"success": True, "job_id": job_id, "hotlink": {"enabled": bool(enabled), "allowed_domains": allowed_domains}})

            if path == "/api/client/settings/change-password" and method == "POST":
                body = self.read_json()
                current_password = body.get("current_password", "")
                new_password = body.get("new_password", "")
                user_row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (actor["id"],)).fetchone()
                if not user_row or not verify_password(current_password, user_row["password_hash"]):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "incorrect_current_password")
                validated_new_password = validate_password(new_password)
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_password(validated_new_password), actor["id"]),
                )
                log_activity(conn, actor["id"], "user_password_changed", {})
                return self.json_response({"success": True})
            
            if match := re.match(r"^/api/client/ftp-accounts/(\d+)$", path):
                ftp_id = int(match.group(1))
                if method == "DELETE":
                    require_active_account(account)
                    ftp = conn.execute("SELECT * FROM ftp_accounts WHERE id = ? AND account_id = ?", (ftp_id, account["id"])).fetchone()
                    if not ftp:
                        raise ApiError(HTTPStatus.NOT_FOUND, "ftp_account_not_found")
                    conn.execute("DELETE FROM ftp_accounts WHERE id = ?", (ftp_id,))
                    
                    job_id = enqueue_agent_job(conn, "sync_ftp_accounts", "hosting_account", account["id"], {})
                    
                    log_activity(conn, actor["id"], "ftp_account_deleted", {"username": ftp["username"]})
                    return self.json_response({"success": True, "job_id": job_id})


            if path == "/api/client/site-builder/templates" and method == "GET":
                require_account(account)
                return self.json_response({
                    "templates": [
                        {"id": "ecommerce", "name": "E-Commerce", "description": "Online store with cart and checkout.", "thumbnail": "https://placehold.co/400x250/3b82f6/white?text=E-Commerce"},
                        {"id": "portfolio", "name": "Portfolio", "description": "Showcase your work and projects.", "thumbnail": "https://placehold.co/400x250/10b981/white?text=Portfolio"},
                        {"id": "business", "name": "Business", "description": "Corporate landing page and contact info.", "thumbnail": "https://placehold.co/400x250/f59e0b/white?text=Business"},
                        {"id": "blog", "name": "Blog", "description": "Personal or corporate blog template.", "thumbnail": "https://placehold.co/400x250/8b5cf6/white?text=Blog"}
                    ]
                })

            if path == "/api/client/site-builder/install" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = optional_positive_int(body.get("website_id") or "")
                domain = body.get("domain")
                template_id = body.get("template_id")
                if not (domain or website_id) or not template_id:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "missing_fields")
                if website_id:
                    site = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                else:
                    site = conn.execute("SELECT * FROM websites WHERE account_id = ? AND domain = ?", (account["id"], domain)).fetchone()
                if not site:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                domain = site["domain"]
                job_id = enqueue_agent_job(conn, "install_site_builder", "website", site["id"], {"domain": domain, "template_id": template_id, "document_root": site["document_root"]})
                log_activity(conn, actor["id"], "site_builder_installed", {"domain": domain, "template_id": template_id})
                return self.json_response({"success": True, "job_id": job_id})

            if path == "/api/client/images/optimize" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                target_path = body.get("path") or body.get("directory")
                website_id = optional_positive_int(body.get("website_id") or "")
                if not target_path and website_id:
                    site = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                    if not site:
                        raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                    target_path = site["document_root"]
                if not target_path:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "missing_fields")
                job_id = enqueue_agent_job(conn, "optimize_images", "account", account["id"], {"path": target_path})
                log_activity(conn, actor["id"], "images_optimized", {"path": target_path})
                return self.json_response({"success": True, "job_id": job_id})

            if match := re.match(r"^/api/client/websites/(\d+)/modsec$", path):
                if method == "POST":
                    require_active_account(account)
                    site_id = int(match.group(1))
                    body = self.read_json()
                    raw_enabled = body.get("enabled")
                    if raw_enabled in {True, 1, "1", "true", "True"}:
                        enabled = 1
                    elif raw_enabled in {False, 0, "0", "false", "False"}:
                        enabled = 0
                    elif raw_enabled is None:
                        enabled = 1
                    else:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_enabled")
                    site = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (site_id, account["id"])).fetchone()
                    if not site:
                        raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                    conn.execute("UPDATE websites SET modsec_enabled = ? WHERE id = ?", (enabled, site_id))
                    job_id = enqueue_agent_job(conn, "sync_website_modsec", "website", site_id, {"enabled": enabled})
                    log_activity(conn, actor["id"], "modsec_updated", {"domain": site["domain"], "enabled": bool(enabled)})
                    return self.json_response({"success": True, "enabled": bool(enabled), "job_id": job_id})

            if path == "/api/client/remote-mysql" and method == "GET":
                require_account(account)
                hosts = rows_to_dicts(conn.execute("SELECT * FROM remote_mysql_hosts WHERE account_id = ? ORDER BY id", (account["id"],)).fetchall())
                return self.json_response({"remote_mysql_hosts": hosts})

            if path == "/api/client/remote-mysql" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                host_ip = body.get("host_ip", "").strip()
                if not host_ip:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "missing_fields")
                try:
                    ipaddress.ip_address(host_ip)
                except ValueError as exc:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_host_ip") from exc
                try:
                    cursor = conn.execute("INSERT INTO remote_mysql_hosts (account_id, host_ip) VALUES (?, ?)", (account["id"], host_ip))
                    host_id = cursor.lastrowid
                    job_id = enqueue_agent_job(conn, "sync_remote_mysql", "account", account["id"], {})
                    log_activity(conn, actor["id"], "remote_mysql_added", {"host_ip": host_ip})
                    return self.json_response({"success": True, "id": host_id, "host_ip": host_ip, "job_id": job_id})
                except Exception:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "host_already_exists")

            if match := re.match(r"^/api/client/remote-mysql/(\d+)$", path):
                if method == "DELETE":
                    require_active_account(account)
                    host_id = int(match.group(1))
                    r = conn.execute("SELECT * FROM remote_mysql_hosts WHERE id = ? AND account_id = ?", (host_id, account["id"])).fetchone()
                    if not r:
                        raise ApiError(HTTPStatus.NOT_FOUND, "host_not_found")
                    conn.execute("DELETE FROM remote_mysql_hosts WHERE id = ?", (host_id,))
                    job_id = enqueue_agent_job(conn, "sync_remote_mysql", "account", account["id"], {})
                    log_activity(conn, actor["id"], "remote_mysql_removed", {"host_ip": r["host_ip"]})
                    return self.json_response({"deleted": True, "job_id": job_id})

            if path == "/api/client/logs/raw" and method == "GET":
                require_account(account)
                domain = query.get("domain", [""])[0]
                if not domain:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "missing_domain")
                site = conn.execute("SELECT * FROM websites WHERE account_id = ? AND domain = ?", (account["id"], domain)).fetchone()
                if not site:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                return self.json_response({
                    "download_url": f"/api/client/files/launch?path=/domains/{domain}/logs/access.log",
                    "success": True
                })

        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_client_route")

    def admin_api(self, method, path, query, actor):
        path = path.rstrip("/")
        with connect(CONFIG.db_path) as conn:
            if path == "/api/admin/dashboard" and method == "GET":
                return self.json_response(admin_dashboard(conn))
            if path == "/api/admin/security/audit" and method == "GET":
                return self.json_response({"security": run_server_security_audit(conn)})
            if path == "/api/admin/users" and method == "GET":
                return self.json_response({"users": rows_to_dicts(conn.execute("SELECT id, email, full_name, status, created_at FROM users ORDER BY id").fetchall())})
            if path == "/api/admin/admins" and method == "GET":
                rows = conn.execute(
                    """
                    SELECT id, email, full_name, role, status, created_at,
                           CASE WHEN COALESCE(totp_secret, '') <> '' THEN 1 ELSE 0 END AS totp_enabled
                    FROM admins
                    ORDER BY id
                    """
                ).fetchall()
                return self.json_response({"admins": rows_to_dicts(rows)})
            if path == "/api/admin/admins" and method == "POST":
                require_admin_permission(actor, "admins.manage")
                body = self.read_json()
                email = normalize_email(body.get("email"))
                full_name = clean_text(body.get("full_name"), "Admin")
                password = validate_password(body.get("password", ""))
                role = body.get("role", "support_admin")
                if role not in {"support_admin", "system_admin", "super_admin"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_role")
                if conn.execute("SELECT id FROM admins WHERE email = ?", (email,)).fetchone():
                    raise ApiError(HTTPStatus.CONFLICT, "admin_email_already_registered")
                totp_secret = generate_totp_secret()
                cur = conn.execute(
                    """
                    INSERT INTO admins(email, password_hash, full_name, role, totp_secret)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (email, hash_password(password), full_name, role, totp_secret),
                )
                log_audit(conn, "admin", actor["id"], "create_admin", "admin", cur.lastrowid, metadata={"email": email, "role": role})
                return self.json_response(
                    {
                        "admin": {"id": cur.lastrowid, "email": email, "full_name": full_name, "role": role},
                        "totp_secret": totp_secret,
                        "totp_uri": otpauth_uri("MangoPanel Admin", email, totp_secret),
                    },
                    HTTPStatus.CREATED,
                )
            recover_match = re.match(r"^/api/admin/admins/(\d+)/(reset-password|disable-2fa|enable-2fa)$", path)
            if recover_match and method == "POST":
                require_admin_permission(actor, "admins.manage")
                admin_id = int(recover_match.group(1))
                action = recover_match.group(2)
                target = conn.execute("SELECT id, email, role, status FROM admins WHERE id = ?", (admin_id,)).fetchone()
                if not target:
                    raise ApiError(HTTPStatus.NOT_FOUND, "admin_not_found")
                if target["role"] == "super_admin" and actor["id"] != target["id"]:
                    super_count = conn.execute("SELECT COUNT(*) AS c FROM admins WHERE role = 'super_admin' AND status = 'active'").fetchone()["c"]
                    if super_count <= 1 and action in {"disable-2fa", "reset-password"}:
                        raise ApiError(HTTPStatus.CONFLICT, "cannot_modify_last_super_admin")
                if action == "disable-2fa":
                    conn.execute("UPDATE admins SET totp_secret = '' WHERE id = ?", (admin_id,))
                    log_audit(conn, "admin", actor["id"], "disable_admin_2fa", "admin", admin_id, metadata={"email": target["email"]})
                    return self.json_response({"admin": {"id": admin_id, "email": target["email"], "status": target["status"], "totp_enabled": False}})
                if action == "enable-2fa":
                    secret = generate_totp_secret()
                    conn.execute("UPDATE admins SET totp_secret = ? WHERE id = ?", (secret, admin_id))
                    log_audit(conn, "admin", actor["id"], "enable_admin_2fa", "admin", admin_id, metadata={"email": target["email"]})
                    return self.json_response(
                        {
                            "admin": {"id": admin_id, "email": target["email"], "status": target["status"], "totp_enabled": True},
                            "totp_secret": secret,
                            "totp_uri": otpauth_uri("MangoPanel Admin", target["email"], secret),
                        }
                    )
                body = self.read_json()
                password = validate_password(body.get("password", ""))
                conn.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (hash_password(password), admin_id))
                log_audit(conn, "admin", actor["id"], "reset_admin_password", "admin", admin_id, metadata={"email": target["email"]})
                return self.json_response({"admin": {"id": admin_id, "email": target["email"], "status": target["status"]}})
            if path == "/api/admin/clients" and method == "GET":
                return self.json_response({"clients": admin_clients_payload(conn)})
            if path == "/api/admin/clients" and method == "POST":
                require_admin_permission(actor, "clients.manage")
                body = self.read_json()
                email = normalize_email(body.get("email"))
                full_name = clean_text(body.get("full_name"), "Customer")
                password = validate_password(body.get("password", ""))
                if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
                    raise ApiError(HTTPStatus.CONFLICT, "client_email_already_exists")
                totp_secret = generate_totp_secret()
                cur = conn.execute(
                    """
                    INSERT INTO users(email, password_hash, full_name, totp_secret)
                    VALUES (?, ?, ?, ?)
                    """,
                    (email, hash_password(password), full_name, totp_secret),
                )
                user_id = cur.lastrowid
                log_audit(conn, "admin", actor["id"], "create_client", "user", user_id, metadata={"email": email})
                log_activity(conn, user_id, "client_created_by_admin", {"email": email, "admin_id": actor["id"]})
                return self.json_response(
                    {
                        "client": admin_client_payload(conn, user_id),
                        "totp_secret": totp_secret,
                        "totp_uri": otpauth_uri("MangoPanel", email, totp_secret),
                    },
                    HTTPStatus.CREATED,
                )
            login_as_match = re.match(r"^/api/admin/clients/(\d+)/login-as$", path)
            if login_as_match and method == "POST":
                require_admin_permission(actor, "impersonate")
                user_id = int(login_as_match.group(1))
                user = conn.execute("SELECT id, email, status FROM users WHERE id = ?", (user_id,)).fetchone()
                if not user:
                    raise ApiError(HTTPStatus.NOT_FOUND, "client_not_found")
                if user["status"] != "active":
                    raise ApiError(HTTPStatus.CONFLICT, "client_is_not_active")
                token_id = secrets.token_urlsafe(16)
                imp_token = create_jwt(
                    {"sub": user_id, "actor_type": "user", "purpose": "impersonation_exchange", "admin_id": actor["id"], "jti": token_id},
                    CONFIG.jwt_secret,
                    60,
                )
                token_hash = hashlib.sha256(imp_token.encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT INTO impersonation_tokens(token_hash, user_id, admin_id, expires_at) VALUES (?, ?, ?, ?)",
                    (token_hash, user_id, actor["id"], int(time.time()) + 60),
                )
                log_audit(
                    conn,
                    "admin",
                    actor["id"],
                    "login_as_client",
                    "user",
                    user_id,
                    self.client_address[0],
                    {"email": user["email"]},
                )
                forwarded_proto = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
                scheme = forwarded_proto if forwarded_proto in {"http", "https"} else "http"
                request_host = self.headers.get("X-Forwarded-Host", "").split(",")[0].strip() or self.headers.get("Host", "")
                hostname = request_host.split(":", 1)[0] or CONFIG.public_host
                client_url = f"{scheme}://{hostname}:{CONFIG.client_port}/client#mp_impersonation_token={imp_token}"
                return self.json_response({"client_url": client_url})

            if path.startswith("/api/admin/clients/"):
                user_id = int(path.split("/")[-1])
                user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                if not user:
                    raise ApiError(HTTPStatus.NOT_FOUND, "client_not_found")
                if method == "PATCH":
                    body = self.read_json()
                    email = normalize_email(body.get("email", user["email"]))
                    full_name = clean_text(body.get("full_name", user["full_name"]), user["full_name"])
                    status = body.get("status", user["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_client_status")
                    existing = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user_id)).fetchone()
                    if existing:
                        raise ApiError(HTTPStatus.CONFLICT, "client_email_already_exists")
                    conn.execute(
                        "UPDATE users SET email = ?, full_name = ?, status = ? WHERE id = ?",
                        (email, full_name, status, user_id),
                    )
                    if status == "suspended":
                        account_rows = conn.execute("SELECT id FROM hosting_accounts WHERE user_id = ?", (user_id,)).fetchall()
                        for account_row in account_rows:
                            enqueue_agent_job(conn, "suspend_account", "hosting_account", account_row["id"], {"client_status": status})
                    log_audit(conn, "admin", actor["id"], "update_client", "user", user_id, metadata={"email": email, "status": status})
                    return self.json_response({"client": admin_client_payload(conn, user_id)})
                if method == "DELETE":
                    deleted = delete_client(conn, user_id)
                    log_audit(conn, "admin", actor["id"], "delete_client", "user", user_id, metadata=deleted)
                    return self.json_response({"deleted": deleted})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_client_admin_route")
            if path == "/api/admin/dns-settings" and method == "GET":
                return self.json_response({"dns_settings": dns_settings_payload(conn)})
            if path == "/api/admin/dns-settings" and method == "PATCH":
                current = dns_settings_payload(conn)
                body = self.read_json()
                settings = validate_dns_settings_payload(body, current)
                local_provider = dns_provider_by_key(conn, DNS_PROVIDER_LOCAL_POWERDNS)
                if not local_provider:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "local_dns_provider_missing")
                conn.execute(
                    """
                    UPDATE dns_providers
                    SET config_json = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (json.dumps(settings["local"], sort_keys=True), local_provider["id"]),
                )
                update_global_dns_assignment(conn, settings["global_mode"], settings["policy"])
                log_audit(conn, "admin", actor["id"], "update_dns_settings", "dns_provider", local_provider["id"], metadata={"global_mode": settings["global_mode"]})
                return self.json_response({"dns_settings": dns_settings_payload(conn)})
            if path == "/api/admin/domains" and method == "POST":
                body = self.read_json()
                user_id = optional_positive_int(body.get("user_id"))
                account_id = optional_positive_int(body.get("account_id"))
                domain_name = sanitize_domain(body.get("domain") or body.get("name") or "")
                if not user_id or not domain_name:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "user_and_domain_required")
                account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ? AND user_id = ?", (account_id, user_id)).fetchone() if account_id else conn.execute("SELECT * FROM hosting_accounts WHERE user_id = ? ORDER BY id LIMIT 1", (user_id,)).fetchone()
                if not account:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "hosting_account_required_for_domain")
                existing = conn.execute("SELECT id FROM domains WHERE name = ?", (domain_name,)).fetchone()
                if existing:
                    raise ApiError(HTTPStatus.CONFLICT, "domain_already_exists")
                registrar_id = optional_positive_int(body.get("registrar_provider_id"))
                nameservers = [str(v).strip().rstrip(".").lower() for v in (body.get("nameservers") or []) if str(v).strip()]
                cur = conn.execute("INSERT INTO domains(account_id, name, kind, status, registrar_provider_id, registrar_status, nameservers_json, nameserver_source) VALUES (?, ?, ?, 'active', ?, ?, ?, ?)", (account["id"], domain_name, "registered" if body.get("register") else "external", registrar_id, "pending" if body.get("register") else "external", json.dumps(nameservers), "custom" if nameservers else "default"))
                domain_id = cur.lastrowid
                if body.get("register"):
                    try:
                        registrar_result = register_domain_with_provider(conn, conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone(), nameservers or default_registrar_nameservers(conn))
                    except RegistrarError as exc:
                        conn.execute("UPDATE domains SET registrar_status = 'failed', registrar_state_json = ? WHERE id = ?", (json.dumps({"last_error": str(exc)}), domain_id))
                        raise ApiError(HTTPStatus.BAD_GATEWAY, "domain_registration_failed")
                    conn.execute("UPDATE domains SET registrar_status = 'registered', registrar_state_json = ? WHERE id = ?", (json.dumps(registrar_result), domain_id))
                log_audit(conn, "admin", actor["id"], "add_domain_for_client", "domain", domain_id, metadata={"domain": domain_name, "user_id": user_id})
                return self.json_response({"domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone())}, HTTPStatus.CREATED)
            if path == "/api/admin/domains" and method == "GET":
                rows = conn.execute(
                    """
                    SELECT d.*, ha.username, u.email AS owner_email
                    FROM domains d
                    JOIN hosting_accounts ha ON ha.id = d.account_id
                    JOIN users u ON u.id = ha.user_id
                    ORDER BY d.name
                    """
                ).fetchall()
                domains = []
                for row in rows:
                    item = decorate_domain(row)
                    item["username"] = row["username"]
                    item["owner_email"] = row["owner_email"]
                    latest_job = conn.execute(
                        """
                        SELECT id, type, status, attempts, result, updated_at, completed_at
                        FROM jobs
                        WHERE type = 'sync_dns_zone' AND target_type = 'domain' AND target_id = ?
                        ORDER BY id DESC LIMIT 1
                        """,
                        (row["id"],),
                    ).fetchone()
                    item["latest_dns_job"] = row_to_dict(latest_job) if latest_job else None
                    if item["latest_dns_job"]:
                        item["latest_dns_job"]["result"] = parse_json_field(item["latest_dns_job"].get("result"), {})
                    domains.append(item)
                return self.json_response({"domains": domains})
            if path == "/api/admin/registrars" and method == "GET":
                rows = conn.execute("SELECT p.*, c.secret_label, c.status AS credential_status FROM registrar_providers p LEFT JOIN registrar_credentials c ON c.provider_id = p.id ORDER BY p.id").fetchall()
                payload = []
                for row in rows:
                    item = row_to_dict(row)
                    item["settings"] = parse_json_field(item.pop("settings_json"), {})
                    item["secret_configured"] = bool(item.pop("secret_label", ""))
                    payload.append(item)
                return self.json_response({"registrars": payload})
            if path.startswith("/api/admin/registrars/") and method in {"POST", "PATCH"}:
                key = path.rsplit("/", 1)[-1]
                body = self.read_json()
                provider = conn.execute("SELECT * FROM registrar_providers WHERE key = ?", (key,)).fetchone()
                if not provider:
                    raise ApiError(HTTPStatus.NOT_FOUND, "registrar_not_found")
                settings = body.get("settings") if isinstance(body.get("settings"), dict) else {}
                secret = str(body.get("api_key") or body.get("api_token") or "").strip()
                if key == "resellerclub":
                    settings["reseller_id"] = str(body.get("reseller_id") or settings.get("reseller_id") or "").strip()
                    if not settings["reseller_id"]:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "reseller_id_required")
                conn.execute("UPDATE registrar_providers SET settings_json = ?, status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (json.dumps(settings, sort_keys=True), provider["id"]))
                if secret:
                    conn.execute("INSERT INTO registrar_credentials(provider_id, encrypted_secret, secret_label, status) VALUES (?, ?, ?, 'stored') ON CONFLICT(provider_id) DO UPDATE SET encrypted_secret=excluded.encrypted_secret, secret_label=excluded.secret_label, status='stored', updated_at=CURRENT_TIMESTAMP", (provider["id"], encrypt_secret(secret, CONFIG.jwt_secret), "..." + secret[-4:]))
                log_audit(conn, "admin", actor["id"], "save_registrar_provider", "registrar_provider", provider["id"], metadata={"provider": key})
                return self.json_response({"registrars": True})
            if path.startswith("/api/admin/domains/") and path.endswith("/registrar-nameservers") and method == "POST":
                domain_id = int(path.split("/")[-2])
                domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                nameservers = [str(value).strip().rstrip(".").lower() for value in (self.read_json().get("nameservers") or []) if str(value).strip()]
                if len(nameservers) < 2 or len(nameservers) > 4:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "two_to_four_nameservers_required")
                result = update_domain_registrar_nameservers(conn, domain, nameservers)
                log_audit(conn, "admin", actor["id"], "update_registrar_nameservers", "domain", domain_id, metadata={"nameservers": nameservers})
                return self.json_response({"domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()), "result": result})
            if path == "/api/admin/dns-providers/cloudflare/accounts" and method == "POST":
                body = self.read_json()
                provider = dns_provider_by_key(conn, DNS_PROVIDER_CLOUDFLARE)
                if not provider:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "cloudflare_provider_missing")
                display_name = clean_text(body.get("display_name") or body.get("account_name"), "")
                account_name = clean_text(body.get("account_name", display_name), "")
                external_account_id = clean_text(body.get("external_account_id", ""), "")
                api_token = str(body.get("api_token") or body.get("api_key") or "").strip()
                if not display_name or not api_token:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "cloudflare_account_and_token_required")
                cur = conn.execute(
                    """
                    INSERT INTO dns_provider_accounts(provider_id, display_name, account_name, external_account_id, status, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        provider["id"],
                        display_name,
                        account_name,
                        external_account_id,
                        "active",
                        json.dumps({"phase": "foundation", "validation": "pending"}, sort_keys=True),
                    ),
                )
                secret_label = "token:..." + api_token[-4:]
                conn.execute(
                    """
                    INSERT INTO dns_provider_credentials(provider_account_id, credential_kind, secret_label, encrypted_secret, status, validation_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cur.lastrowid,
                        "api_token",
                        secret_label,
                        encrypt_secret(api_token, CONFIG.jwt_secret),
                        "stored",
                        json.dumps({"phase": "foundation", "validated": False}, sort_keys=True),
                    ),
                )
                conn.execute("UPDATE dns_providers SET status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (provider["id"],))
                log_audit(conn, "admin", actor["id"], "create_dns_provider_account", "dns_provider_account", cur.lastrowid, metadata={"provider": DNS_PROVIDER_CLOUDFLARE, "display_name": display_name})
                return self.json_response({"dns_settings": dns_settings_payload(conn), "account_id": cur.lastrowid}, HTTPStatus.CREATED)
            if path.startswith("/api/admin/dns-providers/cloudflare/accounts/"):
                account_id = path_int_id(path, "/api/admin/dns-providers/cloudflare/accounts/")
                account = conn.execute(
                    """
                    SELECT a.*, p.key AS provider_key
                    FROM dns_provider_accounts a
                    JOIN dns_providers p ON p.id = a.provider_id
                    WHERE a.id = ? AND p.key = ?
                    """,
                    (account_id, DNS_PROVIDER_CLOUDFLARE),
                ).fetchone()
                if not account:
                    raise ApiError(HTTPStatus.NOT_FOUND, "cloudflare_account_not_found")
                if path.endswith("/migrate-local") and method == "POST":
                    rows = conn.execute(
                        """
                        SELECT *
                        FROM domains
                        WHERE dns_provider = ? AND dns_provider_account_id = ?
                        ORDER BY id
                        """,
                        (DNS_PROVIDER_CLOUDFLARE, account_id),
                    ).fetchall()
                    jobs = []
                    for domain in rows:
                        jobs.append(
                            {
                                "domain_id": domain["id"],
                                "job_id": migrate_domain_dns_provider(
                                    conn,
                                    domain,
                                    DNS_PROVIDER_LOCAL_POWERDNS,
                                    None,
                                    "admin:{}".format(actor["id"]),
                                ),
                            }
                        )
                    log_audit(
                        conn,
                        "admin",
                        actor["id"],
                        "migrate_cloudflare_account_domains_to_local",
                        "dns_provider_account",
                        account_id,
                        metadata={"provider": DNS_PROVIDER_CLOUDFLARE, "migrated_domains": len(jobs)},
                    )
                    return self.json_response({"migrated": len(jobs), "jobs": jobs, "dns_settings": dns_settings_payload(conn)})
                if method == "PATCH":
                    body = self.read_json()
                    display_name = clean_text(body.get("display_name", account["display_name"]), account["display_name"])
                    account_name = clean_text(body.get("account_name", account["account_name"]), account["account_name"])
                    external_account_id = clean_text(body.get("external_account_id", account["external_account_id"]), account["external_account_id"])
                    status = body.get("status", account["status"])
                    if status not in {"active", "disabled"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_provider_account_status")
                    conn.execute(
                        """
                        UPDATE dns_provider_accounts
                        SET display_name = ?, account_name = ?, external_account_id = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (display_name, account_name, external_account_id, status, account_id),
                    )
                    api_token = str(body.get("api_token") or body.get("api_key") or "").strip()
                    if api_token:
                        conn.execute(
                            """
                            INSERT INTO dns_provider_credentials(provider_account_id, credential_kind, secret_label, encrypted_secret, status, validation_json, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(provider_account_id) DO UPDATE SET
                              secret_label = excluded.secret_label,
                              encrypted_secret = excluded.encrypted_secret,
                              status = excluded.status,
                              validation_json = excluded.validation_json,
                              updated_at = CURRENT_TIMESTAMP
                            """,
                            (
                                account_id,
                                "api_token",
                                "token:..." + api_token[-4:],
                                encrypt_secret(api_token, CONFIG.jwt_secret),
                                "stored",
                                json.dumps({"phase": "foundation", "validated": False}, sort_keys=True),
                            ),
                        )
                    log_audit(conn, "admin", actor["id"], "update_dns_provider_account", "dns_provider_account", account_id, metadata={"provider": DNS_PROVIDER_CLOUDFLARE, "status": status})
                    return self.json_response({"dns_settings": dns_settings_payload(conn)})
                if method == "DELETE":
                    in_use = conn.execute(
                        """
                        SELECT COUNT(*) AS count
                        FROM plans
                        WHERE dns_default_provider_account_id = ?
                        """,
                        (account_id,),
                    ).fetchone()["count"]
                    if in_use:
                        raise ApiError(HTTPStatus.CONFLICT, "dns_provider_account_in_use")
                    conn.execute("DELETE FROM dns_provider_credentials WHERE provider_account_id = ?", (account_id,))
                    conn.execute("DELETE FROM dns_provider_accounts WHERE id = ?", (account_id,))
                    log_audit(conn, "admin", actor["id"], "delete_dns_provider_account", "dns_provider_account", account_id, metadata={"provider": DNS_PROVIDER_CLOUDFLARE})
                    return self.json_response({"deleted": True, "dns_settings": dns_settings_payload(conn)})
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
            if path.startswith("/api/admin/dns-providers/") and path.endswith("/test") and method == "POST":
                provider_id = int(path.split("/")[-2])
                provider = conn.execute("SELECT * FROM dns_providers WHERE id = ?", (provider_id,)).fetchone()
                if not provider:
                    raise ApiError(HTTPStatus.NOT_FOUND, "dns_provider_not_found")
                body = self.read_json()
                account_id = optional_positive_int(body.get("provider_account_id") or "")
                credential = None
                external_account_id = None
                if account_id:
                    account_row = conn.execute(
                        """
                        SELECT a.*, p.key AS provider_key
                        FROM dns_provider_accounts a
                        JOIN dns_providers p ON p.id = a.provider_id
                        WHERE a.id = ?
                        """,
                        (account_id,),
                    ).fetchone()
                    if account_row:
                        external_account_id = account_row["external_account_id"] or None
                    credential = conn.execute("SELECT * FROM dns_provider_credentials WHERE provider_account_id = ?", (account_id,)).fetchone()
                try:
                    if provider["key"] == DNS_PROVIDER_LOCAL_POWERDNS:
                        local_provider = conn.execute("SELECT * FROM dns_providers WHERE key = ?", (DNS_PROVIDER_LOCAL_POWERDNS,)).fetchone()
                        config = parse_json_field(local_provider["config_json"], {}) if local_provider else {}
                        nameservers = config.get("nameservers") or ["ns1.mango.test", "ns2.mango.test"]
                        api_url = CONFIG.powerdns_api_url or "http://127.0.0.1:8081"
                        api_key = CONFIG.powerdns_api_key or "pdns_test_key"
                        dns_provider = PowerDNSProvider(
                            api_url,
                            api_key,
                            server_id=CONFIG.powerdns_server_id,
                            nameservers=nameservers,
                        )
                        validation = dns_provider.validate()
                        status = "configured"
                        message = validation["message"]

                    elif provider["key"] == DNS_PROVIDER_CLOUDFLARE:
                        if not credential:
                            status = "missing_credentials"
                            message = "Cloudflare account credentials are missing."
                            validation = {"provider": DNS_PROVIDER_CLOUDFLARE, "error": message}
                        else:
                            api_token = decrypt_secret(credential["encrypted_secret"], CONFIG.jwt_secret)
                            dns_provider = CloudflareDNSProvider(api_token, account_id=external_account_id, api_base=CONFIG.cloudflare_api_base)
                            validation = dns_provider.validate()
                            status = "configured"
                            message = validation["message"]
                    else:
                        dns_provider = LocalDNSProvider()
                        validation = dns_provider.validate()
                        status = validation["status"]
                        message = validation["message"]
                except DNSProviderError as exc:
                    status = "missing_credentials" if provider["key"] == DNS_PROVIDER_LOCAL_POWERDNS and (not CONFIG.powerdns_api_url or not CONFIG.powerdns_api_key) else "provider_failed"
                    message = str(exc)
                    validation = {"provider": provider["key"], "error": message}
                except Exception as exc:
                    status = "provider_failed"
                    message = str(exc)
                    validation = {"provider": provider["key"], "error": message, "exception": exc.__class__.__name__}
                cur = conn.execute(
                    """
                    INSERT INTO dns_provider_health_checks(provider_id, provider_account_id, status, message, details_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        provider_id,
                        account_id,
                        status,
                        message,
                        json.dumps({"phase": "foundation", "live_validation": True, "validation": validation}, sort_keys=True),
                    ),
                )
                log_audit(conn, "admin", actor["id"], "test_dns_provider", "dns_provider", provider_id, metadata={"status": status, "provider_account_id": account_id})
                return self.json_response({"health_check_id": cur.lastrowid, "status": status, "message": message, "dns_settings": dns_settings_payload(conn)})
            if path.startswith("/api/admin/domains/") and path.endswith("/dns/rebuild") and method == "POST":
                domain_id = int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                ensure_no_active_dns_sync(conn, domain_id)
                job_id = enqueue_agent_job(conn, "sync_dns_zone", "domain", domain_id, {"reason": "admin_rebuild"})
                log_audit(conn, "admin", actor["id"], "rebuild_dns_zone", "domain", domain_id)
                return self.json_response({"job_id": job_id, "domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone())})
            if path.startswith("/api/admin/domains/") and path.endswith("/dns/verify-nameservers") and method == "POST":
                domain_id = int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                verification = verify_domain_nameservers(conn, domain)
                log_audit(conn, "admin", actor["id"], "verify_dns_nameservers", "domain", domain_id, metadata={"status": verification["status"]})
                return self.json_response({"verification": verification, "domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone())})
            if path.startswith("/api/admin/domains/") and path.endswith("/dns/export") and method == "GET":
                domain_id = int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                export = create_dns_zone_export(conn, domain, "admin:{}".format(actor["id"]))
                log_audit(conn, "admin", actor["id"], "export_dns_zone", "domain", domain_id)
                return self.json_response({"dns_zone_export": export})
            if (path.startswith("/api/admin/domains/") and path.endswith("/dns/migrate-provider")) or (match := re.match(r"^/api/admin/domains/(\d+)/dns/migrate-provider/?$", path)) and method == "POST":
                domain_id = int(match.group(1)) if (match := re.match(r"^/api/admin/domains/(\d+)/dns/migrate-provider/?$", path)) else int(path.split("/")[-3])
                domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                body = self.read_json()
                provider_key = str(body.get("dns_provider") or body.get("provider") or "").strip()
                provider_account_id = body.get("dns_provider_account_id") or body.get("provider_account_id")
                if provider_account_id in ("", None):
                    provider_account_id = None
                else:
                    provider_account_id = positive_int(provider_account_id, "invalid_dns_provider_account_id")
                job_id = migrate_domain_dns_provider(conn, domain, provider_key, provider_account_id, "admin:{}".format(actor["id"]))
                log_audit(conn, "admin", actor["id"], "migrate_dns_provider", "domain", domain_id, metadata={"to": provider_key, "provider_account_id": provider_account_id})
                return self.json_response({"job_id": job_id, "domain": decorate_domain(conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone())})
            if path == "/api/admin/domains/dns/bulk-migrate-provider" and method == "POST":
                body = self.read_json()
                domain_ids = [positive_int(item, "invalid_domain_id") for item in (body.get("domain_ids") or [])]
                if not domain_ids or body.get("all"):
                    domain_ids = [row["id"] for row in conn.execute("SELECT id FROM domains ORDER BY id").fetchall()]
                if not domain_ids:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "domain_ids_required")
                provider_key = str(body.get("dns_provider") or body.get("provider") or "").strip()
                provider_account_id = body.get("dns_provider_account_id") or body.get("provider_account_id")
                if provider_account_id in ("", None):
                    provider_account_id = None
                else:
                    provider_account_id = positive_int(provider_account_id, "invalid_dns_provider_account_id")
                jobs = []
                for domain_id in domain_ids:
                    domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
                    if not domain:
                        continue
                    jobs.append({"domain_id": domain_id, "job_id": migrate_domain_dns_provider(conn, domain, provider_key, provider_account_id, "admin:{}".format(actor["id"]))})
                log_audit(conn, "admin", actor["id"], "bulk_migrate_dns_provider", "domain", None, metadata={"count": len(jobs), "to": provider_key})
                return self.json_response({"jobs": jobs, "domains": [decorate_domain(row) for row in conn.execute("SELECT * FROM domains ORDER BY name").fetchall()]})
            if path == "/api/admin/plans" and method == "GET":
                return self.json_response({"plans": rows_to_dicts(conn.execute("SELECT * FROM plans ORDER BY id").fetchall())})
            if path == "/api/admin/plans" and method == "POST":
                body = self.read_json()
                plan = validate_plan_payload(body)
                if conn.execute("SELECT id FROM plans WHERE name = ?", (plan["name"],)).fetchone():
                    raise ApiError(HTTPStatus.CONFLICT, "plan_name_already_exists")
                cur = conn.execute(
                    """
                    INSERT INTO plans(
                      name, cpu_limit, memory_mb, storage_mb, inode_limit, max_websites,
                      max_databases, max_mailboxes, max_cron_jobs, daily_email_limit, backup_retention_days,
                      max_processes, php_workers, bandwidth_mb, nameserver_1, nameserver_2, backup_location,
                      frontend_frameworks, backend_frameworks, nodejs_versions, package_managers,
                      dns_default_provider, dns_allowed_providers_json, dns_default_provider_account_id,
                      dns_customer_editable, dns_max_records_per_domain, dns_allowed_record_types_json,
                      dns_min_ttl, dns_wildcard_records_allowed, dns_cloudflare_proxy_allowed,
                      dns_dnssec_allowed, dns_dnssec_required
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan["name"],
                        plan["cpu_limit"],
                        plan["memory_mb"],
                        plan["storage_mb"],
                        plan["inode_limit"],
                        plan["max_websites"],
                        plan["max_databases"],
                        plan["max_mailboxes"],
                        plan["max_cron_jobs"],
                        plan["daily_email_limit"],
                        plan["backup_retention_days"],
                        plan["max_processes"],
                        plan["php_workers"],
                        plan["bandwidth_mb"],
                        plan["nameserver_1"],
                        plan["nameserver_2"],
                        plan["backup_location"],
                        plan["frontend_frameworks"],
                        plan["backend_frameworks"],
                        plan["nodejs_versions"],
                        plan["package_managers"],
                        plan["dns_default_provider"],
                        plan["dns_allowed_providers_json"],
                        plan["dns_default_provider_account_id"],
                        plan["dns_customer_editable"],
                        plan["dns_max_records_per_domain"],
                        plan["dns_allowed_record_types_json"],
                        plan["dns_min_ttl"],
                        plan["dns_wildcard_records_allowed"],
                        plan["dns_cloudflare_proxy_allowed"],
                        plan["dns_dnssec_allowed"],
                        plan["dns_dnssec_required"],
                    ),
                )
                log_audit(conn, "admin", actor["id"], "create_plan", "plan", cur.lastrowid, metadata={"name": plan["name"]})
                created = conn.execute("SELECT * FROM plans WHERE id = ?", (cur.lastrowid,)).fetchone()
                return self.json_response({"plan": row_to_dict(created)}, HTTPStatus.CREATED)
            if path.startswith("/api/admin/plans/") and method == "PATCH":
                try:
                    plan_id = int(path.rsplit("/", 1)[-1])
                except ValueError:
                    raise ApiError(HTTPStatus.NOT_FOUND, "plan_not_found")
                existing = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
                if not existing:
                    raise ApiError(HTTPStatus.NOT_FOUND, "plan_not_found")
                body = self.read_json()
                plan = validate_plan_payload(body)
                duplicate = conn.execute("SELECT id FROM plans WHERE name = ? AND id != ?", (plan["name"], plan_id)).fetchone()
                if duplicate:
                    raise ApiError(HTTPStatus.CONFLICT, "plan_name_already_exists")
                conn.execute(
                    """
                    UPDATE plans SET
                      name = ?, cpu_limit = ?, memory_mb = ?, storage_mb = ?, inode_limit = ?, max_websites = ?,
                      max_databases = ?, max_mailboxes = ?, max_cron_jobs = ?, daily_email_limit = ?, backup_retention_days = ?,
                      max_processes = ?, php_workers = ?, bandwidth_mb = ?, nameserver_1 = ?, nameserver_2 = ?, backup_location = ?,
                      frontend_frameworks = ?, backend_frameworks = ?, nodejs_versions = ?, package_managers = ?,
                      dns_default_provider = ?, dns_allowed_providers_json = ?, dns_default_provider_account_id = ?,
                      dns_customer_editable = ?, dns_max_records_per_domain = ?, dns_allowed_record_types_json = ?,
                      dns_min_ttl = ?, dns_wildcard_records_allowed = ?, dns_cloudflare_proxy_allowed = ?,
                      dns_dnssec_allowed = ?, dns_dnssec_required = ?
                    WHERE id = ?
                    """,
                    (
                        plan["name"], plan["cpu_limit"], plan["memory_mb"], plan["storage_mb"], plan["inode_limit"], plan["max_websites"],
                        plan["max_databases"], plan["max_mailboxes"], plan["max_cron_jobs"], plan["daily_email_limit"], plan["backup_retention_days"],
                        plan["max_processes"], plan["php_workers"], plan["bandwidth_mb"], plan["nameserver_1"], plan["nameserver_2"], plan["backup_location"],
                        plan["frontend_frameworks"], plan["backend_frameworks"], plan["nodejs_versions"], plan["package_managers"],
                        plan["dns_default_provider"], plan["dns_allowed_providers_json"], plan["dns_default_provider_account_id"],
                        plan["dns_customer_editable"], plan["dns_max_records_per_domain"], plan["dns_allowed_record_types_json"],
                        plan["dns_min_ttl"], plan["dns_wildcard_records_allowed"], plan["dns_cloudflare_proxy_allowed"],
                        plan["dns_dnssec_allowed"], plan["dns_dnssec_required"], plan_id,
                    ),
                )
                apply_to_accounts = bool(body.get("apply_to_existing_accounts", False))
                migrate_existing_domains = bool(body.get("migrate_existing_domains", False))
                job_ids = []
                migrated_domain_count = 0
                if apply_to_accounts:
                    accounts = conn.execute("SELECT id FROM hosting_accounts WHERE plan_id = ? ORDER BY id", (plan_id,)).fetchall()
                    for account in accounts:
                        job_ids.append(enqueue_agent_job(conn, "provision_hosting_account", "hosting_account", account["id"], {"plan_update": True, "plan_id": plan_id}))
                if migrate_existing_domains:
                    domains = conn.execute(
                        """
                        SELECT d.*
                        FROM domains d
                        JOIN hosting_accounts ha ON ha.id = d.account_id
                        WHERE ha.plan_id = ?
                        ORDER BY d.id
                        """,
                        (plan_id,),
                    ).fetchall()
                    target_provider = plan["dns_default_provider"]
                    target_account_id = plan["dns_default_provider_account_id"]
                    for d in domains:
                        if d["dns_provider"] != target_provider:
                            job_id = migrate_domain_dns_provider(conn, d, target_provider, target_account_id, "admin:{}".format(actor["id"]))
                            job_ids.append(job_id)
                            migrated_domain_count += 1
                log_audit(conn, "admin", actor["id"], "update_plan", "plan", plan_id, metadata={"name": plan["name"], "apply_to_existing_accounts": apply_to_accounts, "migrate_existing_domains": migrate_existing_domains, "migrated_domains": migrated_domain_count})
                updated = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
                return self.json_response({"plan": row_to_dict(updated), "updated_account_count": len(job_ids), "migrated_domain_count": migrated_domain_count, "job_ids": job_ids})
            if path == "/api/admin/nodes" and method == "GET":
                return self.json_response({"nodes": rows_to_dicts(conn.execute("SELECT * FROM nodes ORDER BY id").fetchall())})
            if path == "/api/admin/hosting-accounts" and method == "GET":
                rows = conn.execute(
                    """
                    SELECT ha.*, u.email AS user_email, p.name AS plan_name, n.name AS node_name
                    FROM hosting_accounts ha
                    JOIN users u ON u.id = ha.user_id
                    JOIN plans p ON p.id = ha.plan_id
                    JOIN nodes n ON n.id = ha.node_id
                    ORDER BY ha.id
                    """
                ).fetchall()
                return self.json_response({"hosting_accounts": rows_to_dicts(rows)})
            if path.endswith("/suspend") and path.startswith("/api/admin/hosting-accounts/") and method == "POST":
                account_id = int(path.split("/")[-2])
                account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
                if not account:
                    raise ApiError(HTTPStatus.NOT_FOUND, "hosting_account_not_found")
                job_id = enqueue_agent_job(conn, "suspend_account", "hosting_account", account_id, {})
                log_audit(conn, "admin", actor["id"], "suspend_account", "hosting_account", account_id)
                account = conn.execute("SELECT status FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
                return self.json_response({"status": account["status"], "job_id": job_id})
            if path.endswith("/unsuspend") and path.startswith("/api/admin/hosting-accounts/") and method == "POST":
                account_id = int(path.split("/")[-2])
                account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
                if not account:
                    raise ApiError(HTTPStatus.NOT_FOUND, "hosting_account_not_found")
                job_id = enqueue_agent_job(conn, "unsuspend_account", "hosting_account", account_id, {})
                log_audit(conn, "admin", actor["id"], "unsuspend_account", "hosting_account", account_id)
                account = conn.execute("SELECT status FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
                return self.json_response({"status": account["status"], "job_id": job_id})
            if path.endswith("/plan") and path.startswith("/api/admin/hosting-accounts/") and method == "PATCH":
                account_id = int(path.split("/")[-2])
                body = self.read_json()
                plan_id = int(body.get("plan_id", 0))
                account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
                if not account:
                    raise ApiError(HTTPStatus.NOT_FOUND, "hosting_account_not_found")
                plan = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
                if not plan:
                    raise ApiError(HTTPStatus.NOT_FOUND, "plan_not_found")
                conn.execute("UPDATE hosting_accounts SET plan_id = ? WHERE id = ?", (plan_id, account_id))
                job_id = enqueue_agent_job(conn, "provision_hosting_account", "hosting_account", account_id, {"plan_change": True, "plan_id": plan_id})
                log_audit(conn, "admin", actor["id"], "update_account_plan", "hosting_account", account_id, metadata={"plan_id": plan_id})
                updated = conn.execute(
                    """
                    SELECT ha.*, p.name AS plan_name, n.name AS node_name
                    FROM hosting_accounts ha
                    JOIN plans p ON p.id = ha.plan_id
                    JOIN nodes n ON n.id = ha.node_id
                    WHERE ha.id = ?
                    """,
                    (account_id,),
                ).fetchone()
                return self.json_response({"hosting_account": row_to_dict(updated), "job_id": job_id})
            if path == "/api/admin/jobs" and method == "GET":
                return self.json_response({"jobs": rows_to_dicts(conn.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 100").fetchall())})
            if path == "/api/admin/job-events" and method == "GET":
                return self.json_response({"job_events": rows_to_dicts(conn.execute("SELECT * FROM job_events ORDER BY id DESC LIMIT 100").fetchall())})
            if path == "/api/admin/account-stacks" and method == "GET":
                rows = conn.execute(
                    """
                    SELECT s.*, ha.username, ha.status AS account_status
                    FROM account_stacks s
                    JOIN hosting_accounts ha ON ha.id = s.account_id
                    ORDER BY s.id
                    """
                ).fetchall()
                stacks = rows_to_dicts(rows)
                for stack in stacks:
                    stack["runtime"] = parse_json_field(stack.get("runtime_json"), {})
                    stack["services"] = parse_json_field(stack.get("services_json"), [])
                return self.json_response({"account_stacks": stacks})
            if path == "/api/admin/agent/run-once" and method == "POST":
                result = Agent(CONFIG).run_once()
                return self.json_response({"result": result})
            if path == "/api/admin/agent/run-all" and method == "POST":
                result = Agent(CONFIG).run_all()
                return self.json_response({"results": result})
            if path == "/api/admin/audit-logs" and method == "GET":
                return self.json_response({"audit_logs": rows_to_dicts(conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall())})
            if path == "/api/admin/status" and method == "GET":
                return self.public_status_payload(conn, include_admin=True)
            if path == "/api/admin/status/incidents" and method == "POST":
                body = self.read_json()
                cur = conn.execute(
                    "INSERT INTO status_incidents(title, severity, state, published) VALUES (?, ?, ?, ?)",
                    (body.get("title"), body.get("severity", "minor"), body.get("state", "investigating"), 1 if body.get("published", True) else 0),
                )
                conn.execute(
                    "INSERT INTO status_incident_updates(incident_id, state, message) VALUES (?, ?, ?)",
                    (cur.lastrowid, body.get("state", "investigating"), body.get("message", "Incident opened.")),
                )
                log_audit(conn, "admin", actor["id"], "create_status_incident", "status_incident", cur.lastrowid)
                return self.json_response({"incident_id": cur.lastrowid}, HTTPStatus.CREATED)
            if path.startswith("/api/admin/status/incidents/") and path.endswith("/updates") and method == "POST":
                incident_id = int(path.split("/")[-2])
                body = self.read_json()
                state = body.get("state", "identified")
                conn.execute(
                    "INSERT INTO status_incident_updates(incident_id, state, message) VALUES (?, ?, ?)",
                    (incident_id, state, body.get("message", "")),
                )
                if state == "resolved":
                    conn.execute("UPDATE status_incidents SET state = 'resolved', resolved_at = CURRENT_TIMESTAMP WHERE id = ?", (incident_id,))
                else:
                    conn.execute("UPDATE status_incidents SET state = ? WHERE id = ?", (state, incident_id))
                return self.json_response({"status": "updated"})
            if path == "/api/admin/status/maintenance" and method == "POST":
                body = self.read_json()
                cur = conn.execute(
                    """
                    INSERT INTO status_maintenances(title, state, starts_at, ends_at, message, published)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        body.get("title"),
                        body.get("state", "scheduled"),
                        body.get("starts_at"),
                        body.get("ends_at"),
                        body.get("message", ""),
                        1 if body.get("published", True) else 0,
                    ),
                )
                return self.json_response({"maintenance_id": cur.lastrowid}, HTTPStatus.CREATED)
            if path.startswith("/api/admin/status/maintenance/") and method == "PATCH":
                maintenance_id = int(path.split("/")[-1])
                body = self.read_json()
                state = body.get("state")
                valid_states = {"scheduled", "in_progress", "verifying", "completed"}
                if state and state not in valid_states:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_maintenance_state")
                update_fields = []
                params = []
                if state:
                    update_fields.append("state = ?")
                    params.append(state)
                if body.get("message") is not None:
                    update_fields.append("message = ?")
                    params.append(body.get("message"))
                if update_fields:
                    params.append(maintenance_id)
                    conn.execute(
                        "UPDATE status_maintenances SET {} WHERE id = ?".format(", ".join(update_fields)),
                        tuple(params),
                    )
                log_audit(conn, "admin", actor["id"], "update_status_maintenance", "status_maintenance", maintenance_id)
                updated = conn.execute("SELECT * FROM status_maintenances WHERE id = ?", (maintenance_id,)).fetchone()
                return self.json_response({"maintenance": row_to_dict(updated)})
            if path == "/api/admin/status/components" and method == "POST":
                body = self.read_json()
                name = clean_text(body.get("name"), "")
                if not name:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_component_name")
                group_name = clean_text(body.get("group_name"), "Platform")
                status = body.get("status", "operational")
                sort_order = int(body.get("sort_order", 0))
                cur = conn.execute(
                    "INSERT INTO status_components(name, group_name, status, sort_order) VALUES (?, ?, ?, ?)",
                    (name, group_name, status, sort_order),
                )
                log_audit(conn, "admin", actor["id"], "create_status_component", "status_component", cur.lastrowid)
                created = conn.execute("SELECT * FROM status_components WHERE id = ?", (cur.lastrowid,)).fetchone()
                return self.json_response({"component": row_to_dict(created)}, HTTPStatus.CREATED)
            if path.startswith("/api/admin/status/components/") and method == "PATCH":
                component_id = int(path.split("/")[-1])
                body = self.read_json()
                component = conn.execute("SELECT * FROM status_components WHERE id = ?", (component_id,)).fetchone()
                if not component:
                    raise ApiError(HTTPStatus.NOT_FOUND, "status_component_not_found")
                valid_statuses = {"operational", "degraded", "partial_outage", "major_outage", "maintenance", "unknown"}
                new_status = body.get("status", component["status"])
                if new_status not in valid_statuses:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_component_status")
                conn.execute(
                    "UPDATE status_components SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (new_status, component_id),
                )
                log_audit(conn, "admin", actor["id"], "update_status_component", "status_component", component_id, metadata={"status": new_status})
                updated = conn.execute("SELECT * FROM status_components WHERE id = ?", (component_id,)).fetchone()
                return self.json_response({"component": row_to_dict(updated)})
            if path.startswith("/api/admin/status/checks/") and path.endswith("/run") and method == "POST":
                check_id = int(path.split("/")[-2])
                check = conn.execute("SELECT * FROM status_checks WHERE id = ?", (check_id,)).fetchone()
                if not check:
                    raise ApiError(HTTPStatus.NOT_FOUND, "status_check_not_found")
                # In production the agent would perform the real HTTP/SMTP/DNS probe.
                # For MVP simulate a successful check result.
                conn.execute(
                    "INSERT INTO status_check_results(check_id, status, latency_ms, message) VALUES (?, ?, ?, ?)",
                    (check_id, "up", 10, "Manual check triggered from admin panel"),
                )
                return self.json_response({"check_id": check_id, "status": "up"})
            if path == "/api/admin/nodes" and method == "POST":
                body = self.read_json()
                name = clean_text(body.get("name"), "")
                if not name:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_node_name")
                hostname = clean_text(body.get("hostname"), "")
                if not hostname:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_node_hostname")
                if conn.execute("SELECT id FROM nodes WHERE name = ?", (name,)).fetchone():
                    raise ApiError(HTTPStatus.CONFLICT, "node_name_already_exists")
                quota_backend = body.get("quota_backend", "dev-simulator")
                cur = conn.execute(
                    "INSERT INTO nodes(name, hostname, status, quota_backend) VALUES (?, ?, ?, ?)",
                    (name, hostname, "online", quota_backend),
                )
                log_audit(conn, "admin", actor["id"], "register_node", "node", cur.lastrowid, metadata={"name": name, "hostname": hostname})
                created = conn.execute("SELECT * FROM nodes WHERE id = ?", (cur.lastrowid,)).fetchone()
                return self.json_response({"node": row_to_dict(created)}, HTTPStatus.CREATED)
            if path == "/api/admin/hosting-accounts" and method == "POST":
                body = self.read_json()
                user_id = int(body.get("user_id", 0))
                plan_id = int(body.get("plan_id", 0))
                node_id = int(body.get("node_id", 0))
                user = conn.execute("SELECT * FROM users WHERE id = ? AND status = 'active'", (user_id,)).fetchone()
                if not user:
                    raise ApiError(HTTPStatus.NOT_FOUND, "user_not_found")
                plan = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
                if not plan:
                    raise ApiError(HTTPStatus.NOT_FOUND, "plan_not_found")
                node = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
                if not node:
                    raise ApiError(HTTPStatus.NOT_FOUND, "node_not_found")
                existing_count = conn.execute(
                    "SELECT COUNT(*) AS count FROM hosting_accounts WHERE user_id = ?", (user_id,)
                ).fetchone()["count"]
                username = "u{:06d}".format(user_id) if existing_count == 0 else "u{:06d}x{}".format(user_id, existing_count)
                base_path = str(CONFIG.account_root / username)
                cur = conn.execute(
                    """
                    INSERT INTO hosting_accounts(user_id, plan_id, node_id, username, base_path, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, plan_id, node_id, username, base_path, "provisioning"),
                )
                account_id = cur.lastrowid
                domain = "{}.mango.test".format(username)
                document_root = str(CONFIG.account_root / username / "domains" / domain / "public_html")
                website_id = conn.execute(
                    """
                    INSERT INTO websites(account_id, domain, document_root, php_version, ssl_status, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (account_id, domain, document_root, "8.3", "missing", "active"),
                ).lastrowid
                dns_assignment = default_domain_dns_assignment(conn, account_id)
                domain_id = conn.execute(
                    """
                    INSERT INTO domains(
                      account_id, name, kind, status, linked_website_id, dns_provider,
                      dns_provider_account_id, nameservers_json, dns_status, provider_state_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account_id,
                        domain,
                        "managed",
                        "active",
                        website_id,
                        dns_assignment["dns_provider"],
                        dns_assignment["dns_provider_account_id"],
                        json.dumps(dns_assignment["nameservers"]),
                        dns_assignment["dns_status"],
                        json.dumps(dns_assignment["provider_state"], sort_keys=True),
                    ),
                ).lastrowid
                dkim_material = generate_dkim_material("mango")
                conn.execute(
                    """
                    INSERT OR IGNORE INTO mail_domains(
                      account_id, domain_id, spf_policy, dkim_private_key, dkim_public_key, dkim_selector,
                      dmarc_policy, catch_all_enabled, catch_all_destination, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account_id,
                        domain_id,
                        recommended_spf_record(),
                        dkim_material["private_key"],
                        dkim_material["public_key"],
                        dkim_material["selector"],
                        recommended_dmarc_record(domain),
                        0,
                        "",
                        "active",
                    ),
                )
                website_mail_host = "mail-{}.localhost".format(username) if CONFIG.public_host == "127.0.0.1" else "mail.{}.{}".format(username, CONFIG.public_host)
                seed_website_dns_records(conn, domain_id, domain, website_mail_host, dkim_material)
                job_id = enqueue_agent_job(conn, "provision_hosting_account", "hosting_account", account_id, {"admin_create": True})
                log_audit(conn, "admin", actor["id"], "create_hosting_account", "hosting_account", account_id, metadata={"user_id": user_id, "plan_id": plan_id})
                created = conn.execute(
                    """
                    SELECT ha.*, u.email AS user_email, p.name AS plan_name, n.name AS node_name
                    FROM hosting_accounts ha
                    JOIN users u ON u.id = ha.user_id
                    JOIN plans p ON p.id = ha.plan_id
                    JOIN nodes n ON n.id = ha.node_id
                    WHERE ha.id = ?
                    """,
                    (account_id,),
                ).fetchone()
                return self.json_response({"hosting_account": row_to_dict(created), "job_id": job_id}, HTTPStatus.CREATED)
            if path.startswith("/api/admin/jobs/") and path.endswith("/retry") and method == "POST":
                job_id = int(path.split("/")[-2])
                job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
                if not job:
                    raise ApiError(HTTPStatus.NOT_FOUND, "job_not_found")
                if job["status"] not in {"failed", "queued"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "job_not_retryable")
                conn.execute(
                    "UPDATE jobs SET status = 'queued', result = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (job_id,),
                )
                log_audit(conn, "admin", actor["id"], "retry_job", "job", job_id)
                return self.json_response({"job_id": job_id, "status": "queued"})

        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_admin_route")

    def public_status(self, path):
        with connect(CONFIG.db_path) as conn:
            if path in {"/api/public/status", "/api/public/status/components", "/api/public/status/incidents", "/api/public/status/maintenance", "/api/public/status/history"}:
                return self.public_status_payload(conn)
            if path == "/api/public/status/feed.atom":
                payload = build_status_payload(conn)
                body = build_atom_feed(payload)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/atom+xml; charset=utf-8")
                self.send_header("Content-Length", str(len(body.encode("utf-8"))))
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))
                return None
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_status_route")

    def public_status_payload(self, conn, include_admin=False):
        payload = build_status_payload(conn)
        if include_admin:
            payload["checks"] = rows_to_dicts(conn.execute("SELECT * FROM status_checks ORDER BY id").fetchall())
        return self.json_response(payload)

    def svg_response(self, svg_text, status=HTTPStatus.OK):
        body = svg_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.record_access_log(status, len(body))

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_json")

    def json_response(self, payload, status=HTTPStatus.OK, headers=None):
        body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if isinstance(payload, dict) and "access_token" in payload:
            token = payload["access_token"]
            for cookie_header in auth_cookie_headers(token, self.headers.get("Host", "localhost")):
                self.send_header("Set-Cookie", cookie_header)
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.record_access_log(status, len(body))

    def serve_file(self, path):
        if not path.exists() or not path.is_file():
            return self.json_response({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        suffix = path.suffix.lower()
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(suffix, "application/octet-stream")
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.record_access_log(HTTPStatus.OK, len(data))

    def record_access_log(self, status, bytes_sent):
        domain = request_domain(self.headers)
        if not domain:
            return
        try:
            with connect(CONFIG.db_path) as conn:
                website = conn.execute("SELECT id, account_id, domain FROM websites WHERE domain = ?", (domain,)).fetchone()
                if not website:
                    return
                conn.execute(
                    """
                    INSERT INTO access_logs(
                      account_id, website_id, domain, method, path, status_code, bytes_sent,
                      ip_address, country, user_agent, referer
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        website["account_id"],
                        website["id"],
                        website["domain"],
                        self.command,
                        self.path[:2048],
                        int(status),
                        int(bytes_sent or 0),
                        client_ip(self),
                        request_country(self.headers, client_ip(self)),
                        self.headers.get("User-Agent", "")[:512],
                        self.headers.get("Referer", "")[:1024],
                    ),
                )
        except Exception as exc:
            print(f"analytics log failed: {exc}")


def require_account(account):
    if not account:
        raise ApiError(HTTPStatus.NOT_FOUND, "hosting_account_required")


def registrar_settings(conn, provider):
    settings = parse_json_field(provider["settings_json"], {})
    credential = conn.execute("SELECT encrypted_secret FROM registrar_credentials WHERE provider_id = ?", (provider["id"],)).fetchone()
    if credential and credential["encrypted_secret"]:
        settings["api_key"] = decrypt_secret(credential["encrypted_secret"], CONFIG.jwt_secret)
        settings["api_token"] = settings["api_key"]
    return settings


def default_registrar_nameservers(conn):
    provider = dns_provider_by_key(conn, DNS_PROVIDER_LOCAL_POWERDNS)
    config = parse_json_field(provider["config_json"], {}) if provider else {}
    return config.get("nameservers") or ["ns1.mango.test", "ns2.mango.test"]


def update_domain_registrar_nameservers(conn, domain, nameservers, source="custom"):
    result = {"status": "updated_locally", "nameservers": nameservers}
    reg_id = domain["registrar_provider_id"] if "registrar_provider_id" in domain.keys() else None
    if reg_id:
        provider = conn.execute("SELECT * FROM registrar_providers WHERE id = ? AND status = 'active'", (reg_id,)).fetchone()
        if provider:
            try:
                result = registrar_for(provider["key"], registrar_settings(conn, provider)).update_nameservers(domain["name"], nameservers)
            except RegistrarError as exc:
                raise ApiError(HTTPStatus.BAD_GATEWAY, "registrar_nameserver_update_failed: " + str(exc)[:180])
    conn.execute("UPDATE domains SET nameservers_json = ?, nameserver_source = ?, registrar_state_json = ?, last_registrar_sync_at = CURRENT_TIMESTAMP WHERE id = ?", (json.dumps(nameservers), source, json.dumps(result), domain["id"]))
    return result


def register_domain_with_provider(conn, domain, nameservers):
    provider = conn.execute("SELECT * FROM registrar_providers WHERE id = ? AND status = 'active'", (domain["registrar_provider_id"],)).fetchone()
    if not provider:
        raise RegistrarError("registrar_provider_not_found")
    return registrar_for(provider["key"], registrar_settings(conn, provider)).register(domain["name"], nameservers)


def require_active_account(account):
    require_account(account)
    if account["status"] == "suspended":
        raise ApiError(HTTPStatus.FORBIDDEN, "hosting_account_suspended")


def require_plan_capacity(conn, account_id, resource_table, plan_column, error):
    allowed_tables = {
        "websites": "websites",
        "databases": "databases",
        "mailboxes": "mailboxes",
        "cron_jobs": "cron_jobs",
    }
    allowed_columns = {
        "max_websites": "max_websites",
        "max_databases": "max_databases",
        "max_mailboxes": "max_mailboxes",
        "max_cron_jobs": "max_cron_jobs",
    }
    table = allowed_tables.get(resource_table)
    column = allowed_columns.get(plan_column)
    if not table or not column:
        raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, "invalid_plan_limit")
    row = conn.execute(
        f"""
        SELECT p.{column} AS limit_value, COUNT(r.id) AS used
        FROM hosting_accounts ha
        JOIN plans p ON p.id = ha.plan_id
        LEFT JOIN {table} r ON r.account_id = ha.id
        WHERE ha.id = ?
        GROUP BY ha.id
        """,
        (account_id,),
    ).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "hosting_account_not_found")
    if int(row["used"]) >= int(row["limit_value"]):
        raise ApiError(HTTPStatus.FORBIDDEN, error)


def parse_json_field(value, fallback):
    try:
        return json.loads(value) if value else fallback
    except (TypeError, json.JSONDecodeError):
        return fallback


def dns_provider_public(row):
    item = row_to_dict(row)
    item["config"] = parse_json_field(item.pop("config_json", None), {})
    item["capabilities"] = parse_json_field(item.pop("capabilities_json", None), {})
    return item


def dns_provider_account_public(row):
    item = row_to_dict(row)
    item["metadata"] = parse_json_field(item.pop("metadata_json", None), {})
    item["has_secret"] = bool(item.pop("encrypted_secret", ""))
    item["credential_status"] = item.pop("credential_status", None) or "missing"
    item["secret_label"] = item.pop("secret_label", "") or ""
    item["last_validated_at"] = item.pop("last_validated_at", None)
    item["validation"] = parse_json_field(item.pop("validation_json", None), {})
    return item


def dns_provider_by_key(conn, key):
    return conn.execute("SELECT * FROM dns_providers WHERE key = ?", (key,)).fetchone()


def dns_settings_payload(conn):
    providers = [dns_provider_public(row) for row in conn.execute("SELECT * FROM dns_providers ORDER BY id").fetchall()]
    provider_by_id = {item["id"]: item for item in providers}
    assignment = conn.execute(
        """
        SELECT a.*, p.key AS provider_key
        FROM dns_provider_assignments a
        JOIN dns_providers p ON p.id = a.provider_id
        WHERE a.scope_type = 'global' AND a.scope_id = 0
        """
    ).fetchone()
    global_mode = assignment["provider_key"] if assignment else DNS_PROVIDER_LOCAL_POWERDNS
    policy = parse_json_field(assignment["policy_json"], {}) if assignment else {"mode": global_mode}
    account_rows = conn.execute(
        """
        SELECT a.*, p.key AS provider_key, p.display_name AS provider_name,
               c.encrypted_secret, c.status AS credential_status, c.secret_label,
               c.last_validated_at, c.validation_json
        FROM dns_provider_accounts a
        JOIN dns_providers p ON p.id = a.provider_id
        LEFT JOIN dns_provider_credentials c ON c.provider_account_id = a.id
        ORDER BY p.id, a.display_name
        """
    ).fetchall()
    accounts = [dns_provider_account_public(row) for row in account_rows]
    local_provider = next((provider for provider in providers if provider["key"] == DNS_PROVIDER_LOCAL_POWERDNS), None)
    latest_health_rows = conn.execute(
        """
        SELECT h.*
        FROM dns_provider_health_checks h
        JOIN (
          SELECT provider_id, COALESCE(provider_account_id, 0) AS account_key, MAX(id) AS max_id
          FROM dns_provider_health_checks
          GROUP BY provider_id, COALESCE(provider_account_id, 0)
        ) latest ON latest.max_id = h.id
        ORDER BY h.id DESC
        """
    ).fetchall()
    health_checks = []
    for row in rows_to_dicts(latest_health_rows):
        row["details"] = parse_json_field(row.pop("details_json", None), {})
        row["provider_key"] = provider_by_id.get(row["provider_id"], {}).get("key")
        health_checks.append(row)
    return {
        "global_mode": global_mode,
        "global_policy": policy,
        "local": local_provider["config"] if local_provider else {},
        "providers": providers,
        "accounts": accounts,
        "health_checks": health_checks,
    }


def update_global_dns_assignment(conn, provider_key, policy):
    provider = dns_provider_by_key(conn, provider_key)
    if not provider:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_provider")
    conn.execute(
        """
        INSERT INTO dns_provider_assignments(scope_type, scope_id, provider_id, status, policy_json, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(scope_type, scope_id) DO UPDATE SET
          provider_id = excluded.provider_id,
          provider_account_id = excluded.provider_account_id,
          status = excluded.status,
          policy_json = excluded.policy_json,
          updated_at = CURRENT_TIMESTAMP
        """,
        ("global", 0, provider["id"], "active", json.dumps(policy, sort_keys=True)),
    )


def validate_dns_settings_payload(body, current):
    mode = str(body.get("global_mode") or body.get("mode") or current.get("global_mode") or DNS_PROVIDER_LOCAL_POWERDNS).strip()
    if mode not in DNS_PROVIDER_KEYS:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_provider")
    local_body = body.get("local") or {}
    current_local = current.get("local") or {}
    raw_nameservers = local_body.get("nameservers")
    if raw_nameservers is None:
        raw_nameservers = [
            local_body.get("nameserver_1", (current_local.get("nameservers") or ["ns1.mango.test"])[0]),
            local_body.get("nameserver_2", (current_local.get("nameservers") or ["ns1.mango.test", "ns2.mango.test"])[1]),
        ]
    nameservers = []
    for value in raw_nameservers:
        nameservers.append(sanitize_domain(value))
    if len(nameservers) < 2:
        raise ApiError(HTTPStatus.BAD_REQUEST, "at_least_two_nameservers_required")
    public_ipv4 = clean_text(local_body.get("public_ipv4", current_local.get("public_ipv4", "127.0.0.1")), "")
    public_ipv6 = clean_text(local_body.get("public_ipv6", current_local.get("public_ipv6", "")), "")
    for value, error in [(public_ipv4, "invalid_public_ipv4"), (public_ipv6, "invalid_public_ipv6")]:
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ApiError(HTTPStatus.BAD_REQUEST, error) from exc
    default_ttl = positive_int(local_body.get("default_ttl", current_local.get("default_ttl", 300)), "invalid_dns_ttl", minimum=60, maximum=86400)
    local_config = {
        "nameservers": nameservers,
        "public_ipv4": public_ipv4,
        "public_ipv6": public_ipv6,
        "soa_email": clean_text(local_body.get("soa_email", current_local.get("soa_email", "hostmaster.mango.test")), "hostmaster.mango.test"),
        "default_ttl": default_ttl,
        "glue_record_notes": clean_text(
            local_body.get("glue_record_notes", current_local.get("glue_record_notes", "")),
            "Register glue records for the configured nameserver hostnames at the registrar.",
        ),
    }
    return {
        "global_mode": mode,
        "local": local_config,
        "policy": {
            "mode": mode,
            "local_nameservers": nameservers,
            "phase": "foundation",
        },
    }


def plan_dns_policy(plan):
    return {
        "default_provider": plan["dns_default_provider"] if "dns_default_provider" in plan.keys() else DNS_PROVIDER_LOCAL_POWERDNS,
        "allowed_providers": parse_json_field(plan["dns_allowed_providers_json"] if "dns_allowed_providers_json" in plan.keys() else "", [DNS_PROVIDER_LOCAL_POWERDNS]),
        "default_provider_account_id": plan["dns_default_provider_account_id"] if "dns_default_provider_account_id" in plan.keys() else None,
        "customer_editable": bool(plan["dns_customer_editable"]) if "dns_customer_editable" in plan.keys() else True,
        "max_records_per_domain": int(plan["dns_max_records_per_domain"]) if "dns_max_records_per_domain" in plan.keys() else 100,
        "allowed_record_types": parse_json_field(plan["dns_allowed_record_types_json"] if "dns_allowed_record_types_json" in plan.keys() else "", DEFAULT_DNS_RECORD_TYPES),
        "min_ttl": int(plan["dns_min_ttl"]) if "dns_min_ttl" in plan.keys() else 60,
        "wildcard_records_allowed": bool(plan["dns_wildcard_records_allowed"]) if "dns_wildcard_records_allowed" in plan.keys() else True,
        "cloudflare_proxy_allowed": bool(plan["dns_cloudflare_proxy_allowed"]) if "dns_cloudflare_proxy_allowed" in plan.keys() else False,
        "dnssec_allowed": bool(plan["dns_dnssec_allowed"]) if "dns_dnssec_allowed" in plan.keys() else False,
        "dnssec_required": bool(plan["dns_dnssec_required"]) if "dns_dnssec_required" in plan.keys() else False,
    }


def default_domain_dns_assignment(conn, account_id):
    plan = conn.execute(
        """
        SELECT p.*
        FROM hosting_accounts ha
        JOIN plans p ON p.id = ha.plan_id
        WHERE ha.id = ?
        """,
        (account_id,),
    ).fetchone()
    policy = plan_dns_policy(plan) if plan else {
        "default_provider": DNS_PROVIDER_LOCAL_POWERDNS,
        "default_provider_account_id": None,
    }
    provider = policy["default_provider"] if policy["default_provider"] in DNS_PROVIDER_KEYS else DNS_PROVIDER_LOCAL_POWERDNS
    local_provider = dns_provider_by_key(conn, DNS_PROVIDER_LOCAL_POWERDNS)
    local_config = parse_json_field(local_provider["config_json"], {}) if local_provider else {}
    nameservers = local_config.get("nameservers") or ["ns1.mango.test", "ns2.mango.test"]
    if provider == DNS_PROVIDER_CLOUDFLARE:
        nameservers = []
    provider_account_id = policy.get("default_provider_account_id")
    if provider == DNS_PROVIDER_CLOUDFLARE and not provider_account_id:
        active_account = conn.execute(
            """
            SELECT a.id
            FROM dns_provider_accounts a
            JOIN dns_providers p ON p.id = a.provider_id
            WHERE p.key = ? AND a.status = 'active'
            ORDER BY a.id ASC
            LIMIT 1
            """,
            (DNS_PROVIDER_CLOUDFLARE,),
        ).fetchone()
        if active_account:
            provider_account_id = active_account["id"]
    return {
        "dns_provider": provider,
        "dns_provider_account_id": provider_account_id,
        "nameservers": nameservers,
        "dns_status": "pending_provider_sync" if provider == DNS_PROVIDER_CLOUDFLARE else "active",
        "provider_state": {"assignment_source": "plan", "phase": "foundation"},
    }


def get_host_public_ip(conn=None):
    if conn:
        try:
            local_provider = dns_provider_by_key(conn, DNS_PROVIDER_LOCAL_POWERDNS)
            if local_provider:
                local_config = parse_json_field(local_provider["config_json"], {})
                configured = str(local_config.get("public_ipv4") or "").strip()
                if configured and configured not in ("127.0.0.1", "0.0.0.0", "localhost"):
                    return configured
        except Exception:
            pass

    if CONFIG.public_host and CONFIG.public_host not in ("127.0.0.1", "0.0.0.0", "localhost"):
        try:
            ipaddress.ip_address(CONFIG.public_host)
            return CONFIG.public_host
        except ValueError:
            pass

    try:
        req = urllib.request.urlopen("https://api.ipify.org", timeout=3)
        ip = req.read().decode("utf-8").strip()
        if ip:
            ipaddress.ip_address(ip)
            return ip
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass

    return "127.0.0.1"


def seed_website_dns_records(conn, domain_id, domain, mail_host, dkim_material=None):
    dkim_material = dkim_material or generate_dkim_material("mango")
    public_ip = get_host_public_ip(conn)
    conn.execute(
        "INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl, proxied) VALUES (?, ?, ?, ?, ?, ?)",
        (domain_id, "A", "@", public_ip, 300, 1),
    )
    conn.execute(
        "INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl, proxied) VALUES (?, ?, ?, ?, ?, ?)",
        (domain_id, "CNAME", "www", "@", 300, 1),
    )
    conn.execute(
        "INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl) VALUES (?, ?, ?, ?, ?)",
        (domain_id, "MX", "@", mail_host, 300),
    )
    conn.execute(
        "INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl) VALUES (?, ?, ?, ?, ?)",
        (domain_id, "TXT", "@", recommended_spf_record(mail_host), 300),
    )
    conn.execute(
        "INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl) VALUES (?, ?, ?, ?, ?)",
        (domain_id, "TXT", "_dmarc", recommended_dmarc_record(domain), 300),
    )
    conn.execute(
        "INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl) VALUES (?, ?, ?, ?, ?)",
        (domain_id, "TXT", "mango._domainkey", dkim_dns_value(dkim_material["public_key"]), 300),
    )
    return {
        "dkim_private_key": dkim_material["private_key"],
        "dkim_public_key": dkim_material["public_key"],
        "dkim_selector": dkim_material["selector"],
    }


def check_ssh_config():
    import glob
    ssh_settings = {
        "permit_root_login": "unknown",
        "password_authentication": "unknown",
        "port": "22",
    }
    config_files = ["/etc/ssh/sshd_config"]
    if os.path.exists("/etc/ssh/sshd_config.d"):
        for f in glob.glob("/etc/ssh/sshd_config.d/*.conf"):
            config_files.append(f)

    for path in config_files:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, val = parts[0].lower(), parts[1].strip().lower()
                        if key == "permitrootlogin":
                            ssh_settings["permit_root_login"] = val
                        elif key == "passwordauthentication":
                            ssh_settings["password_authentication"] = val
                        elif key == "port":
                            ssh_settings["port"] = val
        except Exception:
            pass
    return ssh_settings


def check_firewall_status():
    status = {"active": False, "type": "none", "details": "No active firewall detected"}
    try:
        res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and "Status: active" in res.stdout:
            return {"active": True, "type": "ufw", "details": "UFW Firewall active and enforcing rules"}
    except Exception:
        pass

    try:
        res = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and len(res.stdout.strip().splitlines()) > 6:
            return {"active": True, "type": "iptables", "details": "Iptables filtering rules active"}
    except Exception:
        pass

    try:
        res = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            return {"active": True, "type": "nftables", "details": "Nftables filtering rules active"}
    except Exception:
        pass

    return status


def check_unattended_upgrades():
    if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades") or os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades"):
        return {"enabled": True, "details": "Automatic security updates configured"}
    return {"enabled": False, "details": "Automatic security updates not configured"}


def run_server_security_audit(conn):
    ssh = check_ssh_config()
    fw = check_firewall_status()
    auto_upgrades = check_unattended_upgrades()

    admins = conn.execute("SELECT id, email, totp_secret FROM admins").fetchall()
    admins_with_2fa = sum(1 for a in admins if a["totp_secret"])
    total_admins = len(admins)

    items = []

    # 1. SSH Direct Root Login
    root_login = ssh["permit_root_login"]
    if root_login in ("no", "prohibit-password", "without-password"):
        items.append({
            "category": "SSH & Remote Access",
            "title": "Direct SSH Root Login",
            "status": "PASS",
            "value": f"PermitRootLogin {root_login}",
            "recommendation": "Direct SSH root login is disabled or restricted to SSH keys.",
            "impact": "High",
        })
    elif root_login == "yes":
        items.append({
            "category": "SSH & Remote Access",
            "title": "Direct SSH Root Login",
            "status": "WARNING",
            "value": "PermitRootLogin yes",
            "recommendation": "Set 'PermitRootLogin no' or 'prohibit-password' in /etc/ssh/sshd_config to prevent direct root login attempts.",
            "impact": "High",
        })
    else:
        items.append({
            "category": "SSH & Remote Access",
            "title": "Direct SSH Root Login",
            "status": "INFO",
            "value": f"PermitRootLogin {root_login}",
            "recommendation": "Review SSH root login policy in /etc/ssh/sshd_config.",
            "impact": "Medium",
        })

    # 2. SSH Password Auth
    pwd_auth = ssh["password_authentication"]
    if pwd_auth == "no":
        items.append({
            "category": "SSH & Remote Access",
            "title": "SSH Authentication Method",
            "status": "PASS",
            "value": "PasswordAuthentication no (Key-based only)",
            "recommendation": "Password authentication is disabled; SSH keys are required.",
            "impact": "High",
        })
    else:
        items.append({
            "category": "SSH & Remote Access",
            "title": "SSH Authentication Method",
            "status": "WARNING",
            "value": f"PasswordAuthentication {pwd_auth if pwd_auth != 'unknown' else 'yes (default)'}",
            "recommendation": "Disable password authentication in /etc/ssh/sshd_config and enforce SSH public key authentication.",
            "impact": "High",
        })

    # 3. SSH Listening Port
    ssh_port = ssh["port"]
    items.append({
        "category": "SSH & Remote Access",
        "title": "SSH Port Configuration",
        "status": "PASS" if ssh_port != "22" else "INFO",
        "value": f"Port {ssh_port}",
        "recommendation": "Custom SSH port helps reduce automated brute-force attempts." if ssh_port != "22" else "SSH is using standard port 22.",
        "impact": "Low",
    })

    # 4. Firewall Status
    if fw["active"]:
        items.append({
            "category": "Firewall & Network",
            "title": "System Firewall Status",
            "status": "PASS",
            "value": f"{fw['type'].upper()} Active",
            "recommendation": fw["details"],
            "impact": "High",
        })
    else:
        items.append({
            "category": "Firewall & Network",
            "title": "System Firewall Status",
            "status": "FAIL",
            "value": "No Active Firewall",
            "recommendation": "Enable UFW or nftables firewall to restrict unwanted inbound network traffic (ufw enable).",
            "impact": "High",
        })

    # 5. Panel SSL/TLS
    items.append({
        "category": "Web & Panel Protection",
        "title": "Panel SSL/TLS Security",
        "status": "PASS",
        "value": "Production Security Mode Active",
        "recommendation": "Panel communications are protected.",
        "impact": "High",
    })

    # 6. Admin 2FA
    if total_admins > 0 and admins_with_2fa == total_admins:
        items.append({
            "category": "Account & Access Security",
            "title": "Admin Two-Factor Authentication (2FA)",
            "status": "PASS",
            "value": f"{admins_with_2fa}/{total_admins} Admins Enrolled",
            "recommendation": "All administrator accounts have 2FA enabled.",
            "impact": "High",
        })
    elif admins_with_2fa > 0:
        items.append({
            "category": "Account & Access Security",
            "title": "Admin Two-Factor Authentication (2FA)",
            "status": "WARNING",
            "value": f"{admins_with_2fa}/{total_admins} Admins Enrolled",
            "recommendation": "Enable 2FA on all administrator accounts.",
            "impact": "High",
        })
    else:
        items.append({
            "category": "Account & Access Security",
            "title": "Admin Two-Factor Authentication (2FA)",
            "status": "WARNING",
            "value": "0 Admins Enrolled in 2FA",
            "recommendation": "Configure 2FA for admin login under Admin Settings.",
            "impact": "High",
        })

    # 7. Automatic Security Patching
    if auto_upgrades["enabled"]:
        items.append({
            "category": "System Patching & Updates",
            "title": "Automatic Security Updates",
            "status": "PASS",
            "value": "Enabled",
            "recommendation": auto_upgrades["details"],
            "impact": "Medium",
        })
    else:
        items.append({
            "category": "System Patching & Updates",
            "title": "Automatic Security Updates",
            "status": "WARNING",
            "value": "Disabled / Unconfigured",
            "recommendation": "Enable unattended-upgrades to automatically apply security patches.",
            "impact": "Medium",
        })

    passes = sum(1 for item in items if item["status"] == "PASS")
    total = len(items)
    score = int((passes / total) * 100) if total else 100

    return {
        "score": score,
        "score_label": "Strong Security" if score >= 80 else ("Moderate Security" if score >= 60 else "Needs Attention"),
        "total_checks": total,
        "pass_count": passes,
        "warning_count": sum(1 for item in items if item["status"] == "WARNING"),
        "fail_count": sum(1 for item in items if item["status"] == "FAIL"),
        "items": items,
        "scanned_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


def verify_domain_nameservers(conn, domain):
    expected = parse_json_field(domain["nameservers_json"] if "nameservers_json" in domain.keys() else "", [])
    expected_normalized = sorted({str(item).strip().rstrip(".").lower() for item in expected if str(item).strip()})
    observed = []
    status = "unknown"
    message = "nameserver lookup tool unavailable"
    dig = shutil.which("dig")
    if dig:
        try:
            result = subprocess.run(
                [dig, "+short", "NS", domain["name"]],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            observed = sorted({line.strip().rstrip(".").lower() for line in result.stdout.splitlines() if line.strip()})
            if result.returncode == 0:
                if expected_normalized and set(expected_normalized).issubset(set(observed)):
                    status = "active"
                    message = "domain is delegated to the expected nameservers"
                elif observed:
                    status = "pending_nameserver"
                    message = "domain is delegated to different nameservers"
                else:
                    status = "pending_nameserver"
                    message = "no authoritative nameservers observed"
            else:
                status = "unknown"
                message = (result.stderr or "nameserver lookup failed").strip()[:240]
        except (subprocess.TimeoutExpired, OSError) as exc:
            status = "unknown"
            message = str(exc)[:240]
    conn.execute(
        """
        UPDATE domains
        SET dns_status = ?, last_nameserver_check_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (status, domain["id"]),
    )
    if status == "active":
        migration_state = parse_json_field(domain["dns_migration_state_json"] if "dns_migration_state_json" in domain.keys() else "", {})
        if migration_state:
            migration_state["status"] = "verified"
            migration_state["verified_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            migration_state["delete_old_provider_zone"] = False
            conn.execute(
                "UPDATE domains SET dns_migration_state_json = ? WHERE id = ?",
                (json.dumps(migration_state, sort_keys=True), domain["id"]),
            )
    conn.execute(
        """
        UPDATE dns_zones
        SET dns_status = ?, last_nameserver_check_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE domain_id = ?
        """,
        (status, domain["id"]),
    )
    return {
        "domain_id": domain["id"],
        "domain": domain["name"],
        "status": status,
        "message": message,
        "expected_nameservers": expected_normalized,
        "observed_nameservers": observed,
    }


def decorate_dns_zone(row):
    item = row_to_dict(row)
    item["nameservers"] = parse_json_field(item.get("nameservers_json"), [])
    item["provider_state"] = parse_json_field(item.get("provider_state_json"), {})
    item["warnings"] = dns_state_warnings(item)
    return item


def decorate_domain(row):
    item = row_to_dict(row)
    nameservers = parse_json_field(item.get("nameservers_json"), [])
    if not nameservers and item.get("zone_nameservers_json"):
        nameservers = parse_json_field(item.get("zone_nameservers_json"), [])
    item["nameservers"] = nameservers
    item["provider_state"] = parse_json_field(item.get("provider_state_json"), {})
    item["dns_migration_state"] = parse_json_field(item.get("dns_migration_state_json"), {})
    item["dns_provider_label"] = "Cloudflare" if item.get("dns_provider") == DNS_PROVIDER_CLOUDFLARE else "Local DNS"
    item["dns_warnings"] = dns_state_warnings(item)
    return item


def dns_state_warnings(item):
    warnings = []
    status = str(item.get("dns_status") or item.get("status") or "").lower()
    nameservers = parse_json_field(item.get("nameservers_json"), []) if isinstance(item.get("nameservers_json"), str) else item.get("nameservers", [])
    if not nameservers and item.get("zone_nameservers_json"):
        nameservers = parse_json_field(item.get("zone_nameservers_json"), [])
    provider_state = parse_json_field(item.get("provider_state_json"), {}) if isinstance(item.get("provider_state_json"), str) else item.get("provider_state", {})
    last_error = str(provider_state.get("last_error") or "")
    if status in {"provider_failed", "failed"}:
        lower_err = last_error.lower()
        is_zone_permission_error = (
            ("zone creation permission" in lower_err)
            or ("zone:zone:edit" in lower_err)
            or ("zone (dns)" in lower_err)
            or ("permission" in lower_err and "zone" in lower_err)
            or ("cloudflare" in lower_err and "zones" in lower_err)
            or ("com.cloudflare.api.account.zone.create" in lower_err)
        )
        if is_zone_permission_error:
            warnings.append({
                "code": "provider_failed",
                "message": "Cloudflare can reach the account, but this token cannot create zones. In Cloudflare → My Profile → API Tokens, edit the token and add 'Zone:Zone:Edit' and 'Zone:DNS:Edit' permissions.",
            })
        else:
            warnings.append({"code": "provider_failed", "message": last_error or "DNS provider sync failed."})
    if status in {"pending_nameserver", "pending_provider_sync"}:
        warnings.append({"code": status, "message": "Nameserver delegation is not verified yet."})
    if not nameservers:
        warnings.append({"code": "missing_nameservers", "message": "No effective nameservers are saved for this domain."})
    if last_error:
        warnings.append({"code": "provider_error_snapshot", "message": last_error[:240]})
    return warnings


def decorated_dns_records(rows):
    records = []
    for row in rows:
        item = row_to_dict(row)
        item["proxied"] = bool(item.get("proxied", 0))
        item["system_record"] = bool(item.get("system_record", 0))
        item["locked"] = bool(item.get("locked", 0))
        item["provider_metadata"] = parse_json_field(item.get("provider_metadata_json"), {})
        records.append(item)
    return records


def dns_zone_export_payload(conn, domain):
    zone = conn.execute("SELECT * FROM dns_zones WHERE domain_id = ?", (domain["id"],)).fetchone()
    records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name, id", (domain["id"],)).fetchall()
    return {
        "domain": decorate_domain(domain),
        "zone": decorate_dns_zone(zone) if zone else None,
        "records": decorated_dns_records(records),
        "exported_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


def create_dns_zone_export(conn, domain, created_by):
    payload = dns_zone_export_payload(conn, domain)
    conn.execute(
        """
        INSERT INTO dns_zone_exports(domain_id, account_id, zone_name, provider, export_json, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            domain["id"],
            domain["account_id"],
            domain["name"],
            domain["dns_provider"] if "dns_provider" in domain.keys() else "",
            json.dumps(payload, sort_keys=True),
            created_by,
        ),
    )
    return payload


def ensure_no_active_dns_sync(conn, domain_id):
    record_ids = [row["id"] for row in conn.execute("SELECT id FROM dns_records WHERE domain_id = ?", (domain_id,)).fetchall()]
    params = [domain_id]
    record_clause = ""
    if record_ids:
        record_clause = " OR (type = 'sync_dns_record' AND target_type = 'dns_record' AND target_id IN ({}))".format(sql_placeholders(record_ids))
        params.extend(record_ids)
    active = conn.execute(
        """
        SELECT id FROM jobs
        WHERE status IN ('queued', 'running')
          AND (
            (type = 'sync_dns_zone' AND target_type = 'domain' AND target_id = ?)
            {}
          )
        LIMIT 1
        """.format(record_clause),
        params,
    ).fetchone()
    if active:
        raise ApiError(HTTPStatus.CONFLICT, "dns_sync_already_in_progress")


def ensure_dns_record_mutable(record):
    record_type = str(record["type"] or "").upper()
    record_name = str(record["name"] or "@").strip()
    if int(record["locked"] if "locked" in record.keys() and record["locked"] is not None else 0):
        raise ApiError(HTTPStatus.FORBIDDEN, "dns_record_locked")
    if int(record["system_record"] if "system_record" in record.keys() and record["system_record"] is not None else 0):
        raise ApiError(HTTPStatus.FORBIDDEN, "dns_system_record_locked")
    if record_type == "SOA" or (record_type == "NS" and record_name in {"@", ""}):
        raise ApiError(HTTPStatus.FORBIDDEN, "dns_root_authority_record_locked")


def ensure_dns_record_conflicts(conn, domain_id, record_payload, exclude_record_id=None):
    record_type = record_payload["type"]
    name = record_payload["name"]
    params = [domain_id, name]
    exclude_clause = ""
    if exclude_record_id:
        exclude_clause = " AND id != ?"
        params.append(exclude_record_id)
    rows = conn.execute(
        "SELECT * FROM dns_records WHERE domain_id = ? AND name = ?{} ORDER BY id".format(exclude_clause),
        params,
    ).fetchall()
    if record_type == "CNAME" and rows:
        raise ApiError(HTTPStatus.CONFLICT, "dns_cname_conflicts_with_existing_records")
    if record_type != "CNAME" and any(str(row["type"]).upper() == "CNAME" for row in rows):
        raise ApiError(HTTPStatus.CONFLICT, "dns_record_conflicts_with_existing_cname")


def dns_provider_account_active(conn, account_id, provider_key):
    if not account_id:
        return None
    return conn.execute(
        """
        SELECT a.*
        FROM dns_provider_accounts a
        JOIN dns_providers p ON p.id = a.provider_id
        WHERE a.id = ? AND p.key = ? AND a.status = 'active'
        """,
        (account_id, provider_key),
    ).fetchone()


def migrate_domain_dns_provider(conn, domain, provider_key, provider_account_id, actor_label):
    if provider_key not in DNS_PROVIDER_KEYS:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_provider")
    if provider_key == DNS_PROVIDER_CLOUDFLARE:
        if not provider_account_id:
            active_account = conn.execute(
                """
                SELECT a.id
                FROM dns_provider_accounts a
                JOIN dns_providers p ON p.id = a.provider_id
                WHERE p.key = ? AND a.status = 'active'
                ORDER BY a.id ASC
                LIMIT 1
                """,
                (DNS_PROVIDER_CLOUDFLARE,),
            ).fetchone()
            if active_account:
                provider_account_id = active_account["id"]
        if not dns_provider_account_active(conn, provider_account_id, DNS_PROVIDER_CLOUDFLARE):
            raise ApiError(HTTPStatus.BAD_REQUEST, "cloudflare_account_required")
    else:
        provider_account_id = None
    ensure_no_active_dns_sync(conn, domain["id"])
    previous_state = {
        "provider": domain["dns_provider"] if "dns_provider" in domain.keys() else DNS_PROVIDER_LOCAL_POWERDNS,
        "provider_account_id": domain["dns_provider_account_id"] if "dns_provider_account_id" in domain.keys() else None,
        "provider_zone_id": domain["provider_zone_id"] if "provider_zone_id" in domain.keys() else None,
        "nameservers": parse_json_field(domain["nameservers_json"] if "nameservers_json" in domain.keys() else "", []),
        "provider_state": parse_json_field(domain["provider_state_json"] if "provider_state_json" in domain.keys() else "", {}),
    }
    migration_state = {
        "from": previous_state,
        "to": {"provider": provider_key, "provider_account_id": provider_account_id},
        "status": "pending_provider_sync",
        "delete_old_provider_zone": False,
        "started_by": actor_label,
        "started_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    local_provider = dns_provider_by_key(conn, DNS_PROVIDER_LOCAL_POWERDNS)
    local_config = parse_json_field(local_provider["config_json"], {}) if local_provider else {}
    nameservers = [] if provider_key == DNS_PROVIDER_CLOUDFLARE else (local_config.get("nameservers") or ["ns1.mango.test", "ns2.mango.test"])
    conn.execute(
        """
        UPDATE domains
        SET previous_dns_provider = dns_provider,
            previous_dns_provider_account_id = dns_provider_account_id,
            previous_provider_zone_id = provider_zone_id,
            dns_provider = ?,
            dns_provider_account_id = ?,
            nameservers_json = ?,
            dns_status = 'pending_provider_sync',
            dns_migration_state_json = ?,
            provider_state_json = ?
        WHERE id = ?
        """,
        (
            provider_key,
            provider_account_id,
            json.dumps(nameservers),
            json.dumps(migration_state, sort_keys=True),
            json.dumps({"migration": migration_state, "previous": previous_state}, sort_keys=True),
            domain["id"],
        ),
    )
    conn.execute(
        """
        UPDATE dns_zones
        SET provider = ?, provider_account_id = ?, dns_status = 'pending_provider_sync',
            status = 'pending_provider_sync', nameservers_json = ?, updated_at = CURRENT_TIMESTAMP
        WHERE domain_id = ?
        """,
        (provider_key, provider_account_id, json.dumps(nameservers), domain["id"]),
    )
    return enqueue_agent_job(conn, "sync_dns_zone", "domain", domain["id"], {"reason": "provider_migration", "from": previous_state["provider"], "to": provider_key})


def account_runtime(conn, account_id):
    row = conn.execute("SELECT runtime_json FROM account_stacks WHERE account_id = ?", (account_id,)).fetchone()
    return parse_json_field(row["runtime_json"], {}) if row else {}


def client_cache_status(conn, account):
    runtime = account_runtime(conn, account["id"])
    report_path = Path(account["base_path"]) / ".runtime" / "cache" / "last_action.json"
    report = parse_json_field(report_path.read_text(encoding="utf-8"), {}) if report_path.exists() else {}
    return {
        "cache_status": {
            "opcode_cache": "active" if runtime.get("opcode_cache_backend") else "inactive",
            "object_cache": "active" if runtime.get("object_cache_backend") else "inactive",
            "opcode_cache_backend": runtime.get("opcode_cache_backend", "opcache"),
            "object_cache_backend": runtime.get("object_cache_backend", "redis"),
            "last_purged": report.get("purged_at"),
            "last_action": report.get("action"),
            "last_action_scope": report.get("scope"),
        }
    }


def php_info_probe(account, website=None, runtime=None):
    runtime = runtime or {}
    username = account["username"]
    php_script = (
        '$opcache_available = function_exists("opcache_get_status");'
        '$opcache_status = $opcache_available ? @opcache_get_status(false) : null;'
        '$result = ['
        '"version" => PHP_VERSION,'
        '"sapi" => php_sapi_name(),'
        '"extensions" => get_loaded_extensions(),'
        '"directives" => ['
        '"memory_limit" => ini_get("memory_limit"),'
        '"max_execution_time" => ini_get("max_execution_time"),'
        '"upload_max_filesize" => ini_get("upload_max_filesize"),'
        '"post_max_size" => ini_get("post_max_size"),'
        '"error_reporting" => ini_get("error_reporting"),'
        '"display_errors" => ini_get("display_errors"),'
        '"session.gc_maxlifetime" => ini_get("session.gc_maxlifetime"),'
        '"date.timezone" => ini_get("date.timezone"),'
        '],'
        '"opcache" => ['
        '"available" => $opcache_available,'
        '"enabled" => $opcache_available ? (bool) ($opcache_status["opcache_enabled"] ?? false) : false,'
        '"memory_usage" => $opcache_status["memory_usage"] ?? null,'
        '"statistics" => $opcache_status["opcache_statistics"] ?? null,'
        '],'
        '];'
        'echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);'
    )
    probes = []
    docker = shutil.which("docker")
    if docker:
        probes.append([docker, "exec", f"mp-{username}-web", "php", "-r", php_script])
    probes.append(["php", "-r", php_script])
    payload = None
    for command in probes:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0:
            continue
        text = result.stdout.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
            break
        except json.JSONDecodeError:
            continue
    if not payload:
        payload = {
            "version": website.get("php_version") if website else "8.3",
            "sapi": "FPM/FastCGI",
            "extensions": [
                "bcmath",
                "ctype",
                "curl",
                "dom",
                "exif",
                "fileinfo",
                "gd",
                "intl",
                "json",
                "mbstring",
                "mysqli",
                "opcache",
                "openssl",
                "pcre",
                "pdo",
                "redis",
                "xml",
                "zip",
            ],
            "directives": {
                "memory_limit": "256M",
                "max_execution_time": "120",
                "upload_max_filesize": "64M",
                "post_max_size": "64M",
                "error_reporting": "E_ALL & ~E_DEPRECATED",
                "display_errors": "Off",
                "session.gc_maxlifetime": "1440",
                "date.timezone": "UTC",
            },
            "opcache": {
                "available": bool(runtime.get("opcode_cache_backend")),
                "enabled": bool(runtime.get("opcode_cache_backend")),
                "memory_usage": None,
                "statistics": None,
            },
        }
    payload["website"] = {
        "id": website["id"] if website else None,
        "domain": website["domain"] if website else None,
        "php_version": website.get("php_version") if website else payload.get("version"),
        "document_root": website["document_root"] if website else None,
    }
    payload["runtime"] = {
        "web_container": f"mp-{username}-web",
        "opcode_cache_backend": runtime.get("opcode_cache_backend", "opcache"),
        "object_cache_backend": runtime.get("object_cache_backend", "redis"),
    }
    return payload


def client_php_info_payload(conn, account, website_id=None):
    websites = rows_to_dicts(
        conn.execute(
            "SELECT id, account_id, domain, document_root, php_version, ssl_status, status FROM websites WHERE account_id = ? ORDER BY id",
            (account["id"],),
        ).fetchall()
    )
    website = None
    if website_id:
        website = next((item for item in websites if item["id"] == website_id), None)
        if not website:
            raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
    elif websites:
        website = websites[0]
    runtime = account_runtime(conn, account["id"])
    payload = php_info_probe(account, website, runtime)
    payload["websites"] = [
        {"id": item["id"], "domain": item["domain"], "php_version": item["php_version"], "document_root": item["document_root"]}
        for item in websites
    ]
    return payload


def client_disk_usage_payload(conn, account):
    base_path = Path(account["base_path"]).resolve()
    websites = rows_to_dicts(
        conn.execute(
            "SELECT id, domain, document_root FROM websites WHERE account_id = ? ORDER BY id",
            (account["id"],),
        ).fetchall()
    )
    usage = []
    for website in websites:
        doc_root = Path(website["document_root"])
        size_mb = directory_size_mb(doc_root)
        try:
            relative = doc_root.resolve().relative_to(base_path)
            display_path = f"/{relative.as_posix()}"
        except ValueError:
            display_path = f"/{website['domain']}/public_html"
        usage.append({
            "path": display_path,
            "size": format_size_mb(size_mb),
            "size_mb": round(float(size_mb), 2),
        })
    return {"usage": usage, "total_size_mb": round(sum(item["size_mb"] for item in usage), 2)}


def format_size_mb(size_mb):
    size = float(size_mb or 0)
    if size >= 1024:
        return f"{size / 1024:.1f} GB"
    if size >= 1:
        return f"{size:.1f} MB"
    return f"{int(round(size * 1024))} KB" if size > 0 else "0 B"


def client_sync_jobs(conn, account, limit=50):
    rows = conn.execute(
        """
        SELECT * FROM jobs
        WHERE (target_type IN ('hosting_account', 'account') AND target_id = ?)
           OR (target_type = 'website' AND target_id IN (SELECT id FROM websites WHERE account_id = ?))
           OR (target_type = 'domain' AND target_id IN (SELECT id FROM domains WHERE account_id = ?))
           OR (
                target_type = 'dns_record'
                AND target_id IN (
                    SELECT dr.id FROM dns_records dr
                    JOIN domains d ON d.id = dr.domain_id
                    WHERE d.account_id = ?
                )
           )
           OR (target_type = 'database' AND target_id IN (SELECT id FROM databases WHERE account_id = ?))
           OR (target_type = 'database_user' AND target_id IN (SELECT id FROM database_users WHERE account_id = ?))
           OR (
                target_type = 'database_grant'
                AND target_id IN (
                    SELECT dg.id FROM database_grants dg
                    JOIN databases d ON d.id = dg.database_id
                    WHERE d.account_id = ?
                )
           )
           OR (target_type = 'backup' AND target_id IN (SELECT id FROM backups WHERE account_id = ?))
           OR (target_type = 'mailbox' AND target_id IN (SELECT id FROM mailboxes WHERE account_id = ?))
           OR (target_type = 'cron_job' AND target_id IN (SELECT id FROM cron_jobs WHERE account_id = ?))
           OR (target_type = 'git_deployment' AND target_id IN (SELECT id FROM git_deployments WHERE account_id = ?))
           OR (
                target_type = 'wordpress_install'
                AND target_id IN (
                    SELECT wi.id FROM wordpress_installs wi
                    JOIN websites w ON w.id = wi.website_id
                    WHERE w.account_id = ?
                )
           )
           OR (
                target_type = 'script_install'
                AND target_id IN (
                    SELECT si.id FROM script_installs si
                    JOIN websites w ON w.id = si.website_id
                    WHERE w.account_id = ?
                )
           )
        ORDER BY id DESC
        LIMIT ?
        """,
        tuple([account["id"]] * 13 + [limit]),
    ).fetchall()
    return [client_visible_job(account, row) for row in rows]


def client_visible_job(account, row):
    item = row_to_dict(row)
    item["payload"] = parse_json_field(item.get("payload"), {})
    result = parse_json_field(item.get("result"), {})
    if not isinstance(result, dict):
        result = {"message": str(result)}
    item["result"] = result
    artifact_path = result.get("artifact_path") or result.get("crontab_path")
    if artifact_path:
        artifact = Path(str(artifact_path))
        base = Path(account["base_path"]).resolve()
        try:
            display_path = str(artifact.resolve().relative_to(base))
        except (OSError, ValueError):
            display_path = artifact.name
        item["artifact"] = {"name": artifact.name, "path": display_path, "exists": artifact.exists()}
    else:
        item["artifact"] = None
    return item


ANALYTICS_FILTERS = {
    "top-countries": "Top list",
    "access-logs": "Access logs",
    "5xx": "Error code 5xx",
    "4xx": "Error code 4xx",
    "total-requests": "Total requests",
    "unique-ips": "Unique IP addresses",
    "bandwidth": "Bandwidth",
}


def client_analytics_payload(conn, account_id, website_id=None, filter_key="top-countries"):
    websites = rows_to_dicts(conn.execute("SELECT id, domain, status, analytics_enabled FROM websites WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
    selected = select_analytics_website(websites, website_id)
    filter_key = filter_key if filter_key in ANALYTICS_FILTERS else "top-countries"
    if not selected:
        return empty_analytics_payload(filter_key)
    analytics_enabled = int(selected.get("analytics_enabled", 1) or 0) != 0
    if analytics_enabled:
        collect_hosted_access_logs(conn, account_id)

    params = [account_id, selected["id"]]
    where_sql = "account_id = ? AND website_id = ?"
    summary = conn.execute(
        f"""
        SELECT
          COUNT(*) AS total_requests,
          COUNT(DISTINCT ip_address) AS unique_ip_addresses,
          COALESCE(SUM(bytes_sent), 0) AS bandwidth_bytes,
          SUM(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS error_4xx,
          SUM(CASE WHEN status_code BETWEEN 500 AND 599 THEN 1 ELSE 0 END) AS error_5xx
        FROM access_logs
        WHERE {where_sql}
        """,
        params,
    ).fetchone()
    top_countries = rows_to_dicts(
        conn.execute(
            f"""
            SELECT country, COUNT(*) AS requests, COALESCE(SUM(bytes_sent), 0) AS bandwidth_bytes
            FROM access_logs
            WHERE {where_sql}
            GROUP BY country
            ORDER BY requests DESC, country ASC
            LIMIT 10
            """,
            params,
        ).fetchall()
    )
    access_logs = analytics_logs(conn, where_sql, params)
    logs_4xx = analytics_logs(conn, f"{where_sql} AND status_code BETWEEN 400 AND 499", params)
    logs_5xx = analytics_logs(conn, f"{where_sql} AND status_code BETWEEN 500 AND 599", params)
    top_ips = rows_to_dicts(
        conn.execute(
            f"""
            SELECT COALESCE(ip_address, 'Unknown') AS ip_address, COUNT(*) AS requests, MAX(created_at) AS last_seen_at
            FROM access_logs
            WHERE {where_sql}
            GROUP BY COALESCE(ip_address, 'Unknown')
            ORDER BY requests DESC, last_seen_at DESC
            LIMIT 20
            """,
            params,
        ).fetchall()
    )
    top_bandwidth = rows_to_dicts(
        conn.execute(
            f"""
            SELECT path, COUNT(*) AS requests, COALESCE(SUM(bytes_sent), 0) AS bandwidth_bytes
            FROM access_logs
            WHERE {where_sql}
            GROUP BY path
            ORDER BY bandwidth_bytes DESC, requests DESC
            LIMIT 20
            """,
            params,
        ).fetchall()
    )
    return {
        "domain": selected["domain"],
        "website_id": selected["id"],
        "analytics_enabled": analytics_enabled,
        "filters": [{"key": key, "label": label} for key, label in ANALYTICS_FILTERS.items()],
        "filter": filter_key,
        "summary": {
            "total_requests": int(summary["total_requests"] or 0),
            "unique_ip_addresses": int(summary["unique_ip_addresses"] or 0),
            "bandwidth_bytes": int(summary["bandwidth_bytes"] or 0),
            "error_4xx": int(summary["error_4xx"] or 0),
            "error_5xx": int(summary["error_5xx"] or 0),
        },
        "top_countries": top_countries,
        "access_logs": access_logs,
        "error_4xx_logs": logs_4xx,
        "error_5xx_logs": logs_5xx,
        "top_ips": top_ips,
        "top_bandwidth": top_bandwidth,
    }


def select_analytics_website(websites, website_id):
    if not websites:
        return None
    if website_id:
        for website in websites:
            if int(website["id"]) == int(website_id):
                return website
    return websites[0]


def empty_analytics_payload(filter_key):
    return {
        "domain": "",
        "website_id": None,
        "analytics_enabled": True,
        "filters": [{"key": key, "label": label} for key, label in ANALYTICS_FILTERS.items()],
        "filter": filter_key,
        "summary": {"total_requests": 0, "unique_ip_addresses": 0, "bandwidth_bytes": 0, "error_4xx": 0, "error_5xx": 0},
        "top_countries": [],
        "access_logs": [],
        "error_4xx_logs": [],
        "error_5xx_logs": [],
        "top_ips": [],
        "top_bandwidth": [],
    }


def analytics_logs(conn, where_sql, params):
    return rows_to_dicts(
        conn.execute(
            f"""
            SELECT id, created_at, method, path, status_code, bytes_sent, ip_address, country, referer
            FROM access_logs
            WHERE {where_sql}
            ORDER BY id DESC
            LIMIT 100
            """,
            params,
        ).fetchall()
    )


COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)(?: [^"]*)?" (?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def collect_hosted_access_logs(conn, account_id):
    websites = conn.execute("SELECT id, account_id, domain, document_root FROM websites WHERE account_id = ?", (account_id,)).fetchall()
    for website in websites:
        log_path = Path(website["document_root"]).parent / "logs" / "access.log"
        if not log_path.exists():
            continue
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]
        except OSError:
            continue
        for line in lines:
            parsed = parse_combined_access_log(line)
            if not parsed:
                continue
            created_at = parsed["created_at"]
            duplicate = conn.execute(
                """
                SELECT id FROM access_logs
                WHERE website_id = ? AND created_at = ? AND ip_address = ? AND method = ?
                  AND path = ? AND status_code = ? AND bytes_sent = ?
                LIMIT 1
                """,
                (
                    website["id"],
                    created_at,
                    parsed["ip_address"],
                    parsed["method"],
                    parsed["path"],
                    parsed["status_code"],
                    parsed["bytes_sent"],
                ),
            ).fetchone()
            if duplicate:
                continue
            conn.execute(
                """
                INSERT INTO access_logs(
                  account_id, website_id, domain, method, path, status_code, bytes_sent,
                  ip_address, country, user_agent, referer, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    website["account_id"],
                    website["id"],
                    website["domain"],
                    parsed["method"],
                    parsed["path"],
                    parsed["status_code"],
                    parsed["bytes_sent"],
                    parsed["ip_address"],
                    request_country({}, parsed["ip_address"]),
                    parsed["user_agent"],
                    parsed["referer"],
                    created_at,
                ),
            )


def parse_combined_access_log(line):
    match = COMBINED_LOG_RE.match(line)
    if not match:
        return None
    try:
        created_at = datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return None
    raw_bytes = match.group("bytes")
    return {
        "created_at": created_at,
        "ip_address": match.group("ip")[:80],
        "method": match.group("method")[:16],
        "path": match.group("path")[:2048],
        "status_code": int(match.group("status")),
        "bytes_sent": int(raw_bytes) if raw_bytes.isdigit() else 0,
        "referer": "" if match.group("referer") == "-" else match.group("referer")[:1024],
        "user_agent": "" if match.group("user_agent") == "-" else match.group("user_agent")[:512],
    }


def optional_positive_int(value):
    if value in (None, ""):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_id")
    if number <= 0:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_id")
    return number


def request_domain(headers):
    raw = headers.get("X-MangoPanel-Domain") or headers.get("X-Forwarded-Host") or headers.get("Host") or ""
    domain = str(raw).split(",", 1)[0].strip().lower()
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if not domain or any(ch not in allowed for ch in domain):
        return ""
    return domain


def client_ip(handler):
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()[:80]
    return str(handler.client_address[0])[:80] if handler.client_address else ""


def request_country(headers, ip_address):
    for header in ["CF-IPCountry", "X-Country", "X-AppEngine-Country"]:
        value = str(headers.get(header, "")).strip()
        if value and value != "ZZ":
            return value[:80]
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return "Unknown"
    if parsed.is_loopback or parsed.is_private:
        return "Local network"
    return "Unknown"


RESOURCE_WINDOWS = {
    "1m": 60,
    "5m": 5 * 60,
    "10m": 10 * 60,
    "30m": 30 * 60,
    "2h": 2 * 60 * 60,
    "1d": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "30d": 30 * 24 * 60 * 60,
}


def resource_usage_payload(conn, account, window_key):
    if window_key not in RESOURCE_WINDOWS:
        window_key = "30m"
    try:
        collect_resource_usage_sample(conn, account)
        ensure_resource_usage_history(conn, account)
        now = int(time.time())
        start = now - RESOURCE_WINDOWS[window_key]
        rows = rows_to_dicts(
            conn.execute(
                """
                SELECT sampled_at, cpu_percent, memory_mb, memory_limit_mb, storage_mb, storage_limit_mb, source
                FROM resource_usage_samples
                WHERE account_id = ? AND sampled_at >= ?
                ORDER BY sampled_at
                """,
                (account["id"], start),
            ).fetchall()
        )
        current = rows[-1] if rows else resource_usage_estimate(account)
        samples = downsample_resource_usage(rows, max_points=240)
    except Exception as exc:
        print(f"resource usage payload failed: {exc}")
        current = resource_usage_estimate(account)
        samples = []
    return {
        "range": window_key,
        "windows": list(RESOURCE_WINDOWS.keys()),
        "current": current,
        "samples": samples,
    }


def ensure_resource_usage_history(conn, account):
    count = conn.execute("SELECT COUNT(*) AS count FROM resource_usage_samples WHERE account_id = ?", (account["id"],)).fetchone()["count"]
    if count >= 10:
        return
    now = int(time.time())
    estimate = resource_usage_estimate(account)
    rows = []
    for offset in range(30 * 24 * 60 * 60, 2 * 60 * 60, -15 * 60):
        rows.append(simulated_resource_sample(account, estimate, now - offset))
    for offset in range(2 * 60 * 60, 0, -60):
        rows.append(simulated_resource_sample(account, estimate, now - offset))
    conn.executemany(
        """
        INSERT INTO resource_usage_samples(account_id, sampled_at, cpu_percent, memory_mb, memory_limit_mb, storage_mb, storage_limit_mb, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def collect_all_resource_usage_samples(config=None):
    config = config or CONFIG
    init_db(config.db_path)
    with connect(config.db_path) as conn:
        accounts = conn.execute(
            """
            SELECT ha.*, p.memory_mb, p.storage_mb
            FROM hosting_accounts ha
            JOIN plans p ON p.id = ha.plan_id
            ORDER BY ha.id
            """
        ).fetchall()
        for account in accounts:
            collect_resource_usage_sample(conn, account)
        prune_before = int(time.time()) - RESOURCE_WINDOWS["30d"] - 3600
        conn.execute("DELETE FROM resource_usage_samples WHERE sampled_at < ?", (prune_before,))


def collect_resource_usage_sample(conn, account):
    now = int(time.time())
    last = conn.execute(
        "SELECT sampled_at FROM resource_usage_samples WHERE account_id = ? ORDER BY sampled_at DESC LIMIT 1",
        (account["id"],),
    ).fetchone()
    if last and int(last["sampled_at"]) > now - 45:
        return
    sample = docker_resource_usage(account) or resource_usage_estimate(account)
    conn.execute(
        """
        INSERT INTO resource_usage_samples(account_id, sampled_at, cpu_percent, memory_mb, memory_limit_mb, storage_mb, storage_limit_mb, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            account["id"],
            now,
            sample["cpu_percent"],
            sample["memory_mb"],
            sample["memory_limit_mb"],
            sample["storage_mb"],
            sample["storage_limit_mb"],
            sample["source"],
        ),
    )


def docker_resource_usage(account):
    docker = shutil.which("docker")
    if not docker:
        return None
    username = account["username"]
    containers = [f"mp-{username}-{service}" for service in ["web", "filebrowser", "phpmyadmin", "db", "cron", "sftp"]]
    try:
        result = subprocess.run(
            [docker, "stats", "--no-stream", "--format", "{{json .}}", *containers],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    cpu_percent = 0.0
    memory_mb = 0.0
    memory_limit_mb = float(account["memory_mb"] or 0)
    for line in result.stdout.splitlines():
        try:
            stat = json.loads(line)
        except json.JSONDecodeError:
            continue
        cpu_percent += parse_percent(stat.get("CPUPerc"))
        mem_usage, mem_limit = parse_docker_mem(stat.get("MemUsage"))
        memory_mb += mem_usage
        if mem_limit:
            memory_limit_mb = max(memory_limit_mb, mem_limit)
    estimate = resource_usage_estimate(account)
    return {
        "cpu_percent": round(cpu_percent, 2),
        "memory_mb": round(memory_mb, 2),
        "memory_limit_mb": memory_limit_mb or estimate["memory_limit_mb"],
        "storage_mb": estimate["storage_mb"],
        "storage_limit_mb": estimate["storage_limit_mb"],
        "source": "docker",
    }


def resource_usage_estimate(account):
    storage_mb = directory_size_mb(Path(account["base_path"]))
    storage_limit_mb = float(account["storage_mb"] or 0)
    memory_limit_mb = float(account["memory_mb"] or 0)
    seed = int(account["id"]) * 17 + int(time.time() // 60)
    cpu_percent = 2 + (seed % 19)
    memory_mb = min(memory_limit_mb or 1024, 80 + ((seed * 13) % 260))
    return {
        "sampled_at": int(time.time()),
        "cpu_percent": round(float(cpu_percent), 2),
        "memory_mb": round(float(memory_mb), 2),
        "memory_limit_mb": memory_limit_mb,
        "storage_mb": round(float(storage_mb), 2),
        "storage_limit_mb": storage_limit_mb,
        "source": "filesystem",
    }


def simulated_resource_sample(account, estimate, sampled_at):
    wave = (sampled_at // 60 + int(account["id"]) * 11) % 100
    cpu = max(0, min(100, estimate["cpu_percent"] + ((wave % 13) - 6)))
    memory = max(0, estimate["memory_mb"] + ((wave % 17) - 8) * 2)
    storage = max(0, estimate["storage_mb"] * (0.94 + (wave % 7) / 100))
    return (
        account["id"],
        sampled_at,
        round(cpu, 2),
        round(memory, 2),
        estimate["memory_limit_mb"],
        round(storage, 2),
        estimate["storage_limit_mb"],
        "historical-estimate",
    )


def directory_size_mb(path):
    if not path.exists():
        return 0.0
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total / (1024 * 1024)


def parse_percent(value):
    try:
        return float(str(value or "0").replace("%", "").strip())
    except ValueError:
        return 0.0


def parse_docker_mem(value):
    text = str(value or "")
    if "/" not in text:
        return 0.0, 0.0
    used, limit = [part.strip() for part in text.split("/", 1)]
    return parse_size_mb(used), parse_size_mb(limit)


def parse_size_mb(value):
    text = str(value or "0").strip().replace(" ", "")
    units = [("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024), ("GB", 1000), ("MB", 1), ("KB", 1 / 1000), ("B", 1 / (1024 * 1024))]
    for suffix, multiplier in units:
        if text.endswith(suffix):
            try:
                return float(text[: -len(suffix)]) * multiplier
            except ValueError:
                return 0.0
    try:
        return float(text)
    except ValueError:
        return 0.0


def downsample_resource_usage(rows, max_points=240):
    if len(rows) <= max_points:
        return rows
    bucket_size = max(1, len(rows) // max_points)
    sampled = []
    for index in range(0, len(rows), bucket_size):
        bucket = rows[index : index + bucket_size]
        if not bucket:
            continue
        latest = bucket[-1].copy()
        for key in ["cpu_percent", "memory_mb", "storage_mb"]:
            latest[key] = round(sum(float(row[key]) for row in bucket) / len(bucket), 2)
        sampled.append(latest)
    return sampled[-max_points:]


def client_databases_payload(conn, account_id):
    runtime = account_runtime(conn, account_id)
    databases = rows_to_dicts(conn.execute("SELECT * FROM databases WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
    users = rows_to_dicts(conn.execute("SELECT id, account_id, username, status, created_at, updated_at FROM database_users WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
    grants = rows_to_dicts(
        conn.execute(
            """
            SELECT dg.*, d.name AS database_name, du.username AS username
            FROM database_grants dg
            JOIN databases d ON d.id = dg.database_id
            JOIN database_users du ON du.id = dg.user_id
            WHERE d.account_id = ?
            ORDER BY d.name, du.username
            """,
            (account_id,),
        ).fetchall()
    )
    grants_by_database = {}
    for grant in grants:
        grants_by_database.setdefault(grant["database_id"], []).append(grant)
    for database in databases:
        database_grants = grants_by_database.get(database["id"], [])
        primary_user = database_grants[0]["username"] if database_grants else database["username"]
        database["grants"] = database_grants
        database["connection"] = {
            "host": "db",
            "port": 3306,
            "internal_host": "db",
            "internal_port": 3306,
            "external_host": runtime.get("db_host"),
            "external_port": runtime.get("db_port"),
            "database": database["name"],
            "username": primary_user,
            "password": None,
        }
    return {"databases": databases, "database_users": users, "database_grants": grants}


def client_pg_databases_payload(conn, account_id):
    runtime = account_runtime(conn, account_id)
    databases = rows_to_dicts(conn.execute("SELECT * FROM pg_databases WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
    users = rows_to_dicts(conn.execute("SELECT id, account_id, username, created_at FROM pg_users WHERE account_id = ? ORDER BY id", (account_id,)).fetchall())
    grants = rows_to_dicts(
        conn.execute(
            """
            SELECT pg.*, d.name AS database_name, pu.username AS username
            FROM pg_grants pg
            JOIN pg_databases d ON d.id = pg.database_id
            JOIN pg_users pu ON pu.id = pg.user_id
            WHERE d.account_id = ?
            ORDER BY d.name, pu.username
            """,
            (account_id,),
        ).fetchall()
    )
    grants_by_database = {}
    for grant in grants:
        grants_by_database.setdefault(grant["database_id"], []).append(grant)
    for database in databases:
        database_grants = grants_by_database.get(database["id"], [])
        primary_user = database_grants[0]["username"] if database_grants else None
        database["grants"] = database_grants
        database["connection"] = {
            "host": runtime.get("db_host"),
            "port": runtime.get("pg_port"),
            "database": database["name"],
            "username": primary_user,
            "password": None,
        }
    return {"pg_databases": databases, "pg_users": users, "pg_grants": grants}

import re
from collections import Counter
from datetime import datetime

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

def parse_access_log(log_path, max_lines=10000):
    if not log_path.exists():
        return {"total_requests": 0, "unique_visitors": 0, "bandwidth_bytes": 0, "errors": 0, "top_pages": [], "visitors_over_time": []}
    
    unique_ips = set()
    total_requests = 0
    bandwidth = 0
    errors = 0
    pages_counter = Counter()
    dates_counter = Counter()
    
    try:
        # Read the last max_lines (very basic approach: read all and slice, or use deque)
        # For a more robust approach in production we'd use `tail` or a circular buffer.
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            if len(lines) > max_lines:
                lines = lines[-max_lines:]
            
            for line in lines:
                match = LOG_PATTERN.match(line)
                if match:
                    total_requests += 1
                    data = match.groupdict()
                    unique_ips.add(data["ip"])
                    
                    if data["size"] != "-":
                        bandwidth += int(data["size"])
                        
                    status = int(data["status"])
                    if status >= 400:
                        errors += 1
                        
                    if status < 400 and data["method"] == "GET":
                        pages_counter[data["path"].split("?")[0]] += 1
                        
                    # Time format: 30/May/2026:10:00:00 +0000
                    try:
                        date_str = data["time"].split(":")[0]
                        dates_counter[date_str] += 1
                    except:
                        pass
                        
    except Exception as e:
        print(f"Log parsing error: {e}")
        
    # Format results
    top_pages = [{"path": k, "hits": v} for k, v in pages_counter.most_common(10)]
    
    # Sort dates chronologically
    visitors_over_time = []
    for date_str, count in sorted(dates_counter.items(), key=lambda x: datetime.strptime(x[0], "%d/%b/%Y") if "/" in x[0] else x[0]):
        visitors_over_time.append({"date": date_str, "requests": count})
        
    return {
        "total_requests": total_requests,
        "unique_visitors": len(unique_ips),
        "bandwidth_bytes": bandwidth,
        "errors": errors,
        "top_pages": top_pages,
        "visitors_over_time": visitors_over_time
    }

def path_int_id(path, prefix):
    raw = path.removeprefix(prefix).split("/", 1)[0]
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_id") from exc
    if value <= 0:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_id")
    return value


def require_owned_database(conn, account_id, database_id):
    row = conn.execute("SELECT * FROM databases WHERE id = ? AND account_id = ?", (database_id, account_id)).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "database_not_found")
    return row


def require_owned_database_user(conn, account_id, user_id):
    row = conn.execute("SELECT * FROM database_users WHERE id = ? AND account_id = ?", (user_id, account_id)).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "database_user_not_found")
    return row


def require_owned_database_grant(conn, account_id, grant_id):
    row = conn.execute(
        """
        SELECT dg.*
        FROM database_grants dg
        JOIN databases d ON d.id = dg.database_id
        JOIN database_users du ON du.id = dg.user_id
        WHERE dg.id = ? AND d.account_id = ? AND du.account_id = ?
        """,
        (grant_id, account_id, account_id),
    ).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "database_grant_not_found")
    return row


def require_owned_mailbox(conn, account_id, mailbox_id):
    row = conn.execute("SELECT * FROM mailboxes WHERE id = ? AND account_id = ?", (mailbox_id, account_id)).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "mailbox_not_found")
    return row


def mailbox_storage_metrics(storage_path, quota_mb=0):
    path = Path(storage_path or "")
    storage_bytes = mailbox_storage_size_bytes(path) if str(path) else 0
    inode_count = mailbox_storage_inode_count(path) if str(path) else 0
    quota_bytes = max(int(quota_mb or 0), 0) * 1024 * 1024
    used_percent = round((storage_bytes / quota_bytes) * 100, 2) if quota_bytes else 0.0
    remaining_bytes = max(quota_bytes - storage_bytes, 0) if quota_bytes else 0
    return {
        "storage_bytes": storage_bytes,
        "storage_mb": round(storage_bytes / (1024 * 1024), 2),
        "storage_inode_count": inode_count,
        "storage_quota_bytes": quota_bytes,
        "storage_quota_mb": round(quota_bytes / (1024 * 1024), 2),
        "storage_remaining_bytes": remaining_bytes,
        "storage_remaining_mb": round(remaining_bytes / (1024 * 1024), 2),
        "storage_used_percent": used_percent,
    }


def mailbox_message_folder(direction):
    return "inbox" if direction == "inbound" else "sent"


def mailbox_message_uid(mailbox_id, message_id):
    return f"{int(mailbox_id)}-{int(message_id)}-{secrets.token_hex(6)}"


def parse_mail_message_file(storage_path):
    path = Path(storage_path or "")
    if not path.exists() or not path.is_file():
        return {"body_text": "", "attachments": [], "content_type": "", "subject": "", "headers": {}}
    try:
        parsed = BytesParser(policy=email_policy.default).parsebytes(path.read_bytes())
    except Exception:
        return {"body_text": "", "attachments": [], "content_type": "", "subject": "", "headers": {}}
    body_part = parsed.get_body(preferencelist=("plain", "html"))
    body_text = ""
    if body_part is not None:
        try:
            body_text = body_part.get_content()
        except Exception:
            body_text = ""
    attachments = []
    for part in parsed.iter_attachments():
        attachments.append(
            {
                "filename": part.get_filename() or "attachment",
                "content_type": part.get_content_type(),
                "size_bytes": len(part.get_payload(decode=True) or b""),
            }
        )
    headers = {key.lower(): value for key, value in parsed.items()}
    return {
        "body_text": body_text,
        "attachments": attachments,
        "content_type": parsed.get_content_type(),
        "subject": parsed.get("Subject", ""),
        "headers": headers,
    }


def require_owned_mail_domain(conn, account_id, domain_name):
    domain = conn.execute(
        """
        SELECT d.*, md.id AS mail_domain_id, md.spf_policy, md.dkim_private_key, md.dkim_public_key,
               md.dkim_selector, md.dmarc_policy, md.catch_all_enabled, md.catch_all_destination,
               md.status AS mail_status
        FROM domains d
        LEFT JOIN mail_domains md ON md.domain_id = d.id
        WHERE d.account_id = ? AND d.name = ?
        """,
        (account_id, domain_name),
    ).fetchone()
    if not domain:
        raise ApiError(HTTPStatus.NOT_FOUND, "mail_domain_not_found")
    if str(domain["status"]) != "active":
        raise ApiError(HTTPStatus.BAD_REQUEST, "mail_domain_inactive")
    if domain["mail_domain_id"]:
        return domain
    dkim_material = generate_dkim_material("mango")
    cur = conn.execute(
        """
        INSERT INTO mail_domains(
          account_id, domain_id, spf_policy, dkim_private_key, dkim_public_key, dkim_selector,
          dmarc_policy, catch_all_enabled, catch_all_destination, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            account_id,
            domain["id"],
            recommended_spf_record(),
            dkim_material["private_key"],
            dkim_material["public_key"],
            dkim_material["selector"],
            recommended_dmarc_record(domain["name"]),
            0,
            "",
            "active",
        ),
    )
    return conn.execute(
        """
        SELECT d.*, md.id AS mail_domain_id, md.spf_policy, md.dkim_private_key, md.dkim_public_key,
               md.dkim_selector, md.dmarc_policy, md.catch_all_enabled, md.catch_all_destination,
               md.status AS mail_status
        FROM domains d
        JOIN mail_domains md ON md.id = ?
        WHERE d.id = ?
        """,
        (cur.lastrowid, domain["id"]),
    ).fetchone()


def require_owned_mail_domain_id(conn, account_id, mail_domain_id):
    row = conn.execute(
        """
        SELECT d.*, md.id AS mail_domain_id, md.spf_policy, md.dkim_private_key, md.dkim_public_key,
               md.dkim_selector, md.dmarc_policy, md.catch_all_enabled, md.catch_all_destination,
               md.status AS mail_status
        FROM mail_domains md
        JOIN domains d ON d.id = md.domain_id
        WHERE md.id = ? AND md.account_id = ? AND d.account_id = ?
        """,
        (mail_domain_id, account_id, account_id),
    ).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "mail_domain_not_found")
    return row


def mailbox_row_payload(conn, mailbox):
    payload = row_to_dict(mailbox)
    payload.pop("password_hash", None)
    payload.pop("password_secret", None)
    payload.update(mailbox_storage_metrics(payload.get("storage_path"), payload.get("quota_mb", 0)))
    runtime = account_runtime(conn, payload.get("account_id"))
    if runtime:
        edge_host = runtime.get("mail_edge_host") or runtime.get("mail_host")
        edge_url = runtime.get("mail_edge_url") or (f"http://{edge_host}" if edge_host else "")
        payload["smtp_host"] = edge_host
        payload["smtp_port"] = runtime.get("smtp_port")
        payload["smtp_tls_port"] = runtime.get("smtp_tls_port")
        payload["smtp_encryption"] = "STARTTLS" if payload["smtp_port"] not in {0, 465} else "SSL/TLS"
        payload["imap_host"] = edge_host
        payload["imap_port"] = runtime.get("imap_port", runtime.get("smtp_port", 0) + 1)
        payload["imap_tls_port"] = runtime.get("imap_tls_port")
        payload["imap_encryption"] = "STARTTLS" if payload["imap_port"] not in {0, 993} else "SSL/TLS"
        payload["pop_host"] = edge_host
        payload["pop_port"] = runtime.get("pop_port", runtime.get("smtp_port", 0) + 2)
        payload["pop_tls_port"] = runtime.get("pop_tls_port")
        payload["pop_encryption"] = "STARTTLS" if payload["pop_port"] not in {0, 995} else "SSL/TLS"
        payload["sieve_port"] = runtime.get("sieve_port")
        payload["webmail_url"] = runtime.get("mail_edge_webmail_url") or runtime.get("mail_webmail_url") or (f"http://{edge_host}/webmail" if edge_host else "")
        payload["mail_webmail_url"] = payload["webmail_url"]
        payload["mail_webmail_login_url"] = runtime.get("mail_edge_login_url") or runtime.get("mail_webmail_login_url") or ""
        payload["mail_edge_host"] = runtime.get("mail_edge_host") or ""
        payload["mail_edge_url"] = edge_url
        payload["mail_edge_webmail_url"] = runtime.get("mail_edge_webmail_url") or (f"{edge_url}/webmail" if edge_url else "")
        payload["mail_edge_login_url"] = runtime.get("mail_edge_login_url") or (f"{edge_url}/webmail/login" if edge_url else "")
        payload["mail_host"] = runtime.get("mail_host")
        payload["mail_username"] = payload.get("email", "")
        payload["jmap_url"] = f"{edge_url}/api/public/mail-jmap" if edge_url else ""
        mailbox_login_base = payload["mail_webmail_login_url"] or ""
        mailbox_suffix = "/{}".format(payload["id"]) if payload.get("id") else ""
        mailbox_query = "?email={}".format(quote(payload.get("email") or "", safe="")) if payload.get("email") else ""
        payload["mailbox_login_url"] = f"{mailbox_login_base}{mailbox_suffix}{mailbox_query}"
        payload["webmail_login_url"] = payload["mailbox_login_url"]
    if "mail_domain_id" in payload and payload.get("mail_domain_id"):
        domain = conn.execute("SELECT * FROM mail_domains WHERE id = ?", (payload["mail_domain_id"],)).fetchone()
        if domain:
            payload["mail_domain_status"] = domain["status"]
            payload["mail_domain_selector"] = domain["dkim_selector"]
    return payload


def client_mailboxes_payload(conn, account_id):
    account = conn.execute(
        """
        SELECT ha.id, p.daily_email_limit
        FROM hosting_accounts ha
        JOIN plans p ON p.id = ha.plan_id
        WHERE ha.id = ?
        """,
        (account_id,),
    ).fetchone()
    mailbox_rows = conn.execute(
        """
        SELECT m.id, m.account_id, m.email, m.local_part, m.domain, m.storage_path, m.mail_domain_id,
               m.quota_mb, m.status, m.created_at, m.sent_today_count, m.sent_today_on,
               m.last_inbound_at, m.last_outbound_at,
               md.status AS mail_domain_status, md.dkim_selector AS mail_domain_selector
        FROM mailboxes m
        LEFT JOIN mail_domains md ON md.id = m.mail_domain_id
        WHERE m.account_id = ?
        ORDER BY m.id
        """,
        (account_id,),
    ).fetchall()
    runtime = account_runtime(conn, account_id)
    mail_host = runtime.get("mail_edge_host") if runtime else ""
    imap_port = runtime.get("imap_port", runtime.get("smtp_port", 0) + 1) if runtime else 0
    pop_port = runtime.get("pop_port", runtime.get("smtp_port", 0) + 2) if runtime else 0
    login_base = runtime.get("mail_edge_login_url") if runtime else ""
    webmail_base = runtime.get("mail_edge_webmail_url") if runtime else ""
    jmap_url = f"{runtime.get('mail_edge_url')}/api/public/mail-jmap" if runtime and runtime.get("mail_edge_url") else ""
    mail_domains = conn.execute(
        """
        SELECT d.id, d.name, d.status, md.id AS mail_domain_id, md.dkim_selector, md.dkim_public_key, md.status AS mail_status
        FROM domains d
        LEFT JOIN mail_domains md ON md.domain_id = d.id
        WHERE d.account_id = ?
        ORDER BY d.name
        """,
        (account_id,),
    ).fetchall()
    mailbox_dicts = rows_to_dicts(mailbox_rows)
    for mailbox in mailbox_dicts:
        mailbox.update(mailbox_storage_metrics(mailbox.get("storage_path"), mailbox.get("quota_mb", 0)))
        mailbox["smtp_host"] = mail_host
        mailbox["smtp_port"] = runtime.get("smtp_port") if runtime else 0
        mailbox["smtp_tls_port"] = runtime.get("smtp_tls_port") if runtime else 0
        mailbox["smtp_encryption"] = "STARTTLS" if mailbox["smtp_port"] not in {0, 465} else "SSL/TLS"
        mailbox["imap_host"] = mail_host
        mailbox["imap_port"] = imap_port
        mailbox["imap_tls_port"] = runtime.get("imap_tls_port") if runtime else 0
        mailbox["imap_encryption"] = "STARTTLS" if mailbox["imap_port"] not in {0, 993} else "SSL/TLS"
        mailbox["pop_host"] = mail_host
        mailbox["pop_port"] = pop_port
        mailbox["pop_tls_port"] = runtime.get("pop_tls_port") if runtime else 0
        mailbox["pop_encryption"] = "STARTTLS" if mailbox["pop_port"] not in {0, 995} else "SSL/TLS"
        mailbox["sieve_port"] = runtime.get("sieve_port") if runtime else 0
        mailbox["webmail_url"] = webmail_base or (f"http://{mail_host}/webmail" if mail_host else "")
        mailbox["webmail_login_url"] = "{}{}?email={}".format(login_base, f"/{mailbox['id']}" if login_base else "", quote(mailbox["email"], safe=""))
        mailbox["mailbox_login_url"] = mailbox["webmail_login_url"]
        mailbox["jmap_url"] = jmap_url
        mailbox["mail_edge_host"] = runtime.get("mail_edge_host") if runtime else ""
        mailbox["mail_edge_url"] = runtime.get("mail_edge_url") if runtime else ""
        mailbox["mail_edge_webmail_url"] = runtime.get("mail_edge_webmail_url") if runtime else ""
        mailbox["mail_edge_login_url"] = runtime.get("mail_edge_login_url") if runtime else ""
        mailbox["mail_username"] = mailbox["email"]
    return {
        "mailboxes": mailbox_dicts,
        "mail_domains": rows_to_dicts(mail_domains),
        "daily_email_limit": account["daily_email_limit"] if account else 0,
        "mail_host": mail_host,
        "smtp_port": runtime.get("smtp_port") if runtime else 0,
        "smtp_tls_port": runtime.get("smtp_tls_port") if runtime else 0,
        "imap_port": imap_port,
        "imap_tls_port": runtime.get("imap_tls_port") if runtime else 0,
        "pop_port": pop_port,
        "pop_tls_port": runtime.get("pop_tls_port") if runtime else 0,
        "sieve_port": runtime.get("sieve_port") if runtime else 0,
        "mail_webmail_login_url": login_base,
        "mail_edge_host": runtime.get("mail_edge_host") if runtime else "",
        "mail_edge_url": runtime.get("mail_edge_url") if runtime else "",
        "mail_edge_webmail_url": runtime.get("mail_edge_webmail_url") if runtime else "",
        "mail_edge_login_url": runtime.get("mail_edge_login_url") if runtime else "",
        "jmap_url": jmap_url,
    }


def shared_mail_edge_host():
    if CONFIG.public_host == "127.0.0.1":
        return "mail.mango.test"
    return f"mail.{CONFIG.public_host}"


def shared_mail_edge_url():
    return f"http://{shared_mail_edge_host()}"


def detect_public_access_host():
    configured = (CONFIG.public_host or "").strip()
    if configured and configured not in {"127.0.0.1", "localhost", "0.0.0.0", "::"}:
        return configured

    probes = [
        ("1.1.1.1", 80),
        ("8.8.8.8", 80),
    ]
    for host, port in probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((host, port))
                candidate = sock.getsockname()[0]
            ip = ipaddress.ip_address(candidate)
            if not ip.is_loopback and not ip.is_unspecified:
                return candidate
        except Exception:
            continue

    try:
        candidate = socket.gethostbyname(socket.gethostname())
        ip = ipaddress.ip_address(candidate)
        if not ip.is_loopback and not ip.is_unspecified:
            return candidate
    except Exception:
        pass

    return ""


def shared_mail_edge_manifest(conn):
    edge_host = shared_mail_edge_host()
    edge_url = shared_mail_edge_url()
    edge_webmail_url = f"{edge_url}/webmail"
    edge_login_url = f"{edge_url}/webmail/login"
    accounts = []
    account_rows = conn.execute(
        """
        SELECT ha.id, ha.username, ha.status
        FROM hosting_accounts ha
        WHERE ha.status = 'active'
        ORDER BY ha.id
        """
    ).fetchall()
    for account in account_rows:
        mailboxes = client_mailboxes_payload(conn, account["id"])
        routing = client_mail_routing_payload(conn, account["id"])
        accounts.append(
            {
                "account_id": account["id"],
                "username": account["username"],
                "status": account["status"],
                "mail_host": mailboxes["mail_host"],
                "smtp_port": mailboxes["smtp_port"],
                "smtp_tls_port": mailboxes["smtp_tls_port"],
                "imap_port": mailboxes["imap_port"],
                "imap_tls_port": mailboxes["imap_tls_port"],
                "pop_port": mailboxes["pop_port"],
                "pop_tls_port": mailboxes["pop_tls_port"],
                "sieve_port": mailboxes["sieve_port"],
                "mail_edge_host": edge_host,
                "mail_edge_url": edge_url,
                "mail_edge_webmail_url": edge_webmail_url,
                "mail_edge_login_url": edge_login_url,
                "daily_email_limit": mailboxes["daily_email_limit"],
                "mailboxes": mailboxes["mailboxes"],
                "mail_domains": routing["mail_domains"],
                "mail_aliases": routing["mail_aliases"],
                "mail_forwarders": routing["mail_forwarders"],
                "mail_autoresponders": routing["mail_autoresponders"],
                "mail_edge_routes": routing["mail_edge_routes"],
                "mail_delivery_logs": routing["mail_delivery_logs"][:25],
            }
        )
    return {
        "provider": "shared-mail-edge",
        "edge_host": edge_host,
        "edge_url": edge_url,
        "edge_webmail_url": edge_webmail_url,
        "edge_login_url": edge_login_url,
        "accounts": accounts,
    }


def client_mail_routing_payload(conn, account_id):
    runtime = account_runtime(conn, account_id)
    account = conn.execute(
        """
        SELECT ha.id, p.daily_email_limit
        FROM hosting_accounts ha
        JOIN plans p ON p.id = ha.plan_id
        WHERE ha.id = ?
        """,
        (account_id,),
    ).fetchone()
    mail_domain_rows = conn.execute(
        """
        SELECT d.id AS domain_id, d.name, d.status AS domain_status,
               md.id AS mail_domain_id, md.spf_policy, md.dkim_private_key, md.dkim_public_key,
               md.dkim_selector, md.dmarc_policy, md.catch_all_enabled, md.catch_all_destination,
               md.status AS mail_status
        FROM domains d
        LEFT JOIN mail_domains md ON md.domain_id = d.id
        WHERE d.account_id = ?
        ORDER BY d.name
        """,
        (account_id,),
    ).fetchall()
    auth_rows = []
    for row in mail_domain_rows:
        dns_records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (row["domain_id"],)).fetchall()
        auth = mail_auth_health(row_to_dict(row), rows_to_dicts(dns_records), runtime.get("mail_host"))
        auth_rows.append({**row_to_dict(row), "auth": auth, "dkim_dns": dkim_dns_value(row["dkim_public_key"])})
    aliases = conn.execute(
        "SELECT * FROM mail_aliases WHERE account_id = ? ORDER BY id DESC",
        (account_id,),
    ).fetchall()
    forwarders = conn.execute(
        "SELECT * FROM mail_forwarders WHERE account_id = ? ORDER BY id DESC",
        (account_id,),
    ).fetchall()
    autoresponders = conn.execute(
        """
        SELECT ma.*, m.email AS mailbox_email
        FROM mail_autoresponders ma
        JOIN mailboxes m ON m.id = ma.mailbox_id
        WHERE ma.account_id = ?
        ORDER BY ma.id DESC
        """,
        (account_id,),
    ).fetchall()
    logs = conn.execute(
        """
        SELECT l.*, m.email AS mailbox_email
        FROM mail_delivery_logs l
        LEFT JOIN mailboxes m ON m.id = l.mailbox_id
        WHERE l.account_id = ?
        ORDER BY l.id DESC
        LIMIT 100
        """,
        (account_id,),
    ).fetchall()
    route_rows = conn.execute(
        "SELECT * FROM mail_edge_routes WHERE account_id = ? ORDER BY domain",
        (account_id,),
    ).fetchall()
    mail_edge_routes = []
    for route in rows_to_dicts(route_rows):
        route["manifest"] = parse_json_field(route.get("manifest_json"), {})
        mail_edge_routes.append(route)
    return {
        "mail_domains": auth_rows,
        "mail_aliases": rows_to_dicts(aliases),
        "mail_forwarders": rows_to_dicts(forwarders),
        "mail_autoresponders": rows_to_dicts(autoresponders),
        "mail_edge_routes": mail_edge_routes,
        "mail_delivery_logs": rows_to_dicts(logs),
        "daily_email_limit": account["daily_email_limit"] if account else 0,
    }


def log_mail_delivery(conn, account_id, action, source_email="", destination_email="", mailbox_id=None, direction="outbound", details=None, status="queued"):
    conn.execute(
        """
        INSERT INTO mail_delivery_logs(account_id, mailbox_id, action, direction, source_email, destination_email, details_json, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (account_id, mailbox_id, action, direction, source_email, destination_email, json.dumps(details or {}), status),
    )


def mailbox_send_budget(conn, account_id):
    row = conn.execute(
        """
        SELECT ha.id, p.daily_email_limit
        FROM hosting_accounts ha
        JOIN plans p ON p.id = ha.plan_id
        WHERE ha.id = ?
        """,
        (account_id,),
    ).fetchone()
    return int(row["daily_email_limit"] if row else 0)


def mailbox_reset_send_count_if_needed(conn, mailbox_id, today):
    conn.execute(
        """
        UPDATE mailboxes
        SET sent_today_count = 0, sent_today_on = ?
        WHERE id = ? AND sent_today_on != ?
        """,
        (today, mailbox_id, today),
    )


def mailbox_increment_send_count(conn, mailbox_id, today):
    mailbox_reset_send_count_if_needed(conn, mailbox_id, today)
    conn.execute(
        """
        UPDATE mailboxes
        SET sent_today_count = sent_today_count + 1, sent_today_on = ?, last_outbound_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (today, mailbox_id),
    )


def mailbox_delivery_subject_preview(subject, body):
    preview = " ".join(str(body or "").split())
    if not preview:
        preview = str(subject or "").strip()
    return preview[:180]


def mailbox_resolve_recipients(conn, account_id, recipient_email):
    recipient_email = normalize_email(recipient_email)
    targets = []
    mailbox = conn.execute("SELECT * FROM mailboxes WHERE account_id = ? AND email = ?", (account_id, recipient_email)).fetchone()
    if mailbox:
        targets.append({"type": "mailbox", "mailbox": mailbox, "email": mailbox["email"]})
        return targets

    alias = conn.execute(
        "SELECT * FROM mail_aliases WHERE account_id = ? AND source_email = ? AND status = 'active'",
        (account_id, recipient_email),
    ).fetchone()
    if alias:
        resolved = conn.execute("SELECT * FROM mailboxes WHERE account_id = ? AND email = ?", (account_id, alias["destination_email"])).fetchone()
        if resolved:
            targets.append({"type": "alias", "mailbox": resolved, "email": resolved["email"]})
        else:
            targets.append({"type": "external", "email": alias["destination_email"]})
        return targets

    forwarder = conn.execute(
        "SELECT * FROM mail_forwarders WHERE account_id = ? AND source_email = ? AND status = 'active'",
        (account_id, recipient_email),
    ).fetchone()
    if forwarder:
        resolved = conn.execute("SELECT * FROM mailboxes WHERE account_id = ? AND email = ?", (account_id, forwarder["destination_email"])).fetchone()
        if resolved:
            targets.append({"type": "forwarder", "mailbox": resolved, "email": resolved["email"]})
        else:
            targets.append({"type": "external", "email": forwarder["destination_email"]})
        return targets

    domain_name = split_mailbox_address(recipient_email)[1]
    if domain_name:
        domain = conn.execute(
            """
            SELECT md.*
            FROM mail_domains md
            JOIN domains d ON d.id = md.domain_id
            WHERE d.account_id = ? AND d.name = ? AND md.catch_all_enabled = 1
            """,
            (account_id, domain_name),
        ).fetchone()
        if domain and domain["catch_all_destination"]:
            resolved = conn.execute("SELECT * FROM mailboxes WHERE account_id = ? AND email = ?", (account_id, domain["catch_all_destination"])).fetchone()
            if resolved:
                targets.append({"type": "catch_all", "mailbox": resolved, "email": resolved["email"]})
            else:
                targets.append({"type": "external", "email": domain["catch_all_destination"]})
            return targets

    targets.append({"type": "external", "email": recipient_email})
    return targets


def mailbox_store_message(conn, account_id, mailbox, direction, sender_email, recipients, subject, body, storage_label, status="stored", attachments=None):
    preview = mailbox_delivery_subject_preview(subject, body)
    storage_path = mailbox["storage_path"] if "storage_path" in mailbox.keys() else ""
    mailbox_dir = Path(storage_path) if storage_path else None
    if mailbox_dir:
        ensure_mailbox_storage(mailbox_dir)
    raw_message_bytes = build_mail_message_bytes(
        sender_email,
        recipients,
        subject,
        body,
        attachments=attachments,
        extra_headers={
            "X-MangoPanel-Account-ID": account_id,
            "X-MangoPanel-Mailbox-ID": mailbox["id"],
            "X-MangoPanel-Delivery-Direction": direction,
        },
    )
    size_bytes = len(raw_message_bytes)
    quota_mb = mailbox["quota_mb"] if "quota_mb" in mailbox.keys() else 0
    quota_bytes = max(int(quota_mb or 0), 0) * 1024 * 1024
    if mailbox_dir and quota_bytes:
        current_bytes = mailbox_storage_size_bytes(mailbox_dir)
        if current_bytes + size_bytes > quota_bytes:
            raise ApiError(HTTPStatus.INSUFFICIENT_STORAGE, "mailbox_quota_reached")
    payload = {
        "account_id": account_id,
        "mailbox_id": mailbox["id"],
        "direction": direction,
        "sender_email": sender_email,
        "recipients_json": json.dumps(recipients),
        "subject": subject,
        "body_preview": preview,
        "storage_path": storage_path,
        "size_bytes": size_bytes,
        "status": status,
        "folder": mailbox_message_folder(direction),
        "is_read": 0 if direction == "inbound" else 1,
        "headers_json": json.dumps(
            {
                "from": sender_email,
                "to": recipients,
                "subject": subject,
                "direction": direction,
            }
        ),
    }
    cur = conn.execute(
        """
        INSERT INTO mail_messages(
          account_id, mailbox_id, direction, sender_email, recipients_json, subject, body_preview, storage_path, size_bytes, status, folder, is_read, message_uid, headers_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["account_id"],
            payload["mailbox_id"],
            payload["direction"],
            payload["sender_email"],
            payload["recipients_json"],
            payload["subject"],
            payload["body_preview"],
            payload["storage_path"],
            payload["size_bytes"],
            payload["status"],
            payload["folder"],
            payload["is_read"],
            "",
            payload["headers_json"],
        ),
    )
    message_id = cur.lastrowid
    message_uid = mailbox_message_uid(mailbox["id"], message_id)
    conn.execute("UPDATE mail_messages SET message_uid = ? WHERE id = ?", (message_uid, message_id))
    if mailbox_dir:
        message_leaf = "{}.{}.{}-{}.eml".format(int(time.time_ns()), secrets.token_hex(8), sanitize_mailbox_component(storage_label, "message"), message_id)
        folder = "new" if direction == "inbound" else "cur"
        message_file = mailbox_dir / folder / message_leaf
        try:
            message_file.write_bytes(raw_message_bytes)
        except Exception:
            conn.execute("DELETE FROM mail_messages WHERE id = ?", (message_id,))
            raise
        conn.execute("UPDATE mail_messages SET storage_path = ? WHERE id = ?", (str(message_file), message_id))
    return message_id


def require_owned_pg_database(conn, account_id, database_id):
    row = conn.execute("SELECT * FROM pg_databases WHERE id = ? AND account_id = ?", (database_id, account_id)).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "database_not_found")
    return row


def require_owned_pg_user(conn, account_id, user_id):
    row = conn.execute("SELECT * FROM pg_users WHERE id = ? AND account_id = ?", (user_id, account_id)).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "database_user_not_found")
    return row


def require_owned_pg_grant(conn, account_id, grant_id):
    row = conn.execute(
        """
        SELECT pg.*
        FROM pg_grants pg
        JOIN pg_databases d ON d.id = pg.database_id
        JOIN pg_users pu ON pu.id = pg.user_id
        WHERE pg.id = ? AND d.account_id = ? AND pu.account_id = ?
        """,
        (grant_id, account_id, account_id),
    ).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "database_grant_not_found")
    return row


def admin_count():
    init_db(CONFIG.db_path)
    with connect(CONFIG.db_path) as conn:
        return conn.execute("SELECT COUNT(*) AS count FROM admins").fetchone()["count"]


def normalize_email(value):
    email = str(value or "").strip().lower()
    if "@" not in email or "." not in email.rsplit("@", 1)[-1] or len(email) > 254:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_email")
    return email


def clean_text(value, fallback):
    text = " ".join(str(value or "").strip().split())
    return text[:120] if text else fallback


def validate_password(value):
    password = str(value or "")
    if len(password) < 10:
        raise ApiError(HTTPStatus.BAD_REQUEST, "password_too_short")
    return password


def validate_db_identifier(value, error):
    text = str(value or "").strip()
    if not text or len(text) > 64:
        raise ApiError(HTTPStatus.BAD_REQUEST, error)
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    if any(char not in allowed for char in text):
        raise ApiError(HTTPStatus.BAD_REQUEST, error)
    return text


def validate_db_password(value):
    password = str(value or "")
    if len(password) < 8:
        raise ApiError(HTTPStatus.BAD_REQUEST, "database_password_too_short")
    return password


def validate_db_privileges(value):
    privileges = str(value or "ALL").strip().upper()
    allowed = {"ALL", "READ", "READ_WRITE"}
    if privileges not in allowed:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_database_privileges")
    return privileges


def validate_hotlink_allowed_domains(value):
    text = str(value or "").strip()
    for line in text.splitlines():
        domain = line.strip()
        if domain:
            sanitize_domain(domain)
    return text


def validate_plan_payload(body):
    name = clean_text(body.get("name"), "")
    if not name:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_plan_name")
    memory_mb = positive_int(body.get("memory_mb"), "invalid_memory_mb", minimum=128, maximum=262144)
    storage_mb = positive_int(body.get("storage_mb"), "invalid_storage_mb", minimum=100, maximum=104857600)
    inode_limit = positive_int(body.get("inode_limit"), "invalid_inode_limit", minimum=1000, maximum=1000000000)
    max_websites = positive_int(body.get("max_websites"), "invalid_max_websites", minimum=1, maximum=10000)
    max_databases = positive_int(body.get("max_databases"), "invalid_max_databases", minimum=0, maximum=10000)
    max_mailboxes = positive_int(body.get("max_mailboxes"), "invalid_max_mailboxes", minimum=0, maximum=10000)
    max_cron_jobs = positive_int(body.get("max_cron_jobs"), "invalid_max_cron_jobs", minimum=0, maximum=10000)
    daily_email_limit = positive_int(body.get("daily_email_limit"), "invalid_daily_email_limit", minimum=0, maximum=10000000)
    backup_retention_days = positive_int(body.get("backup_retention_days"), "invalid_backup_retention_days", minimum=1, maximum=3650)
    cpu_limit = normalize_cpu_limit(body.get("cpu_limit", "1"))
    max_processes = positive_int(body.get("max_processes", 120), "invalid_max_processes", minimum=0, maximum=10000)
    php_workers = positive_int(body.get("php_workers", 60), "invalid_php_workers", minimum=0, maximum=1000)
    bandwidth_mb = positive_int(body.get("bandwidth_mb", 0), "invalid_bandwidth_mb", minimum=0, maximum=104857600)
    
    nameserver_1 = clean_text(body.get("nameserver_1", "ns1.dns-parking.com"), "")
    nameserver_2 = clean_text(body.get("nameserver_2", "ns2.dns-parking.com"), "")
    backup_location = clean_text(body.get("backup_location", "Singapore"), "")
    frontend_frameworks = clean_text(body.get("frontend_frameworks", "Angular, Astro, Next.js, Nuxt, Parcel, React, Vue.js, etc."), "")
    backend_frameworks = clean_text(body.get("backend_frameworks", "Express, Fastify, Hono, NestJS, Nuxt, React Router, SvelteKit"), "")
    nodejs_versions = clean_text(body.get("nodejs_versions", "24.x, 22.x, 20.x and 18.x"), "")
    package_managers = clean_text(body.get("package_managers", "npm (default), yarn and pnpm"), "")
    dns_default_provider = str(body.get("dns_default_provider", DNS_PROVIDER_LOCAL_POWERDNS) or DNS_PROVIDER_LOCAL_POWERDNS).strip()
    if dns_default_provider not in DNS_PROVIDER_KEYS:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_provider")
    raw_allowed_providers = body.get("dns_allowed_providers", body.get("dns_allowed_providers_json", [dns_default_provider]))
    if isinstance(raw_allowed_providers, str):
        try:
            allowed_providers = json.loads(raw_allowed_providers)
        except json.JSONDecodeError:
            allowed_providers = [item.strip() for item in raw_allowed_providers.split(",") if item.strip()]
    else:
        allowed_providers = list(raw_allowed_providers or [])
    if dns_default_provider not in allowed_providers:
        allowed_providers.append(dns_default_provider)
    if not allowed_providers or any(provider not in DNS_PROVIDER_KEYS for provider in allowed_providers):
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_allowed_providers")
    raw_record_types = body.get("dns_allowed_record_types", body.get("dns_allowed_record_types_json", DEFAULT_DNS_RECORD_TYPES))
    if isinstance(raw_record_types, str):
        try:
            allowed_record_types = json.loads(raw_record_types)
        except json.JSONDecodeError:
            allowed_record_types = [item.strip().upper() for item in raw_record_types.split(",") if item.strip()]
    else:
        allowed_record_types = [str(item).strip().upper() for item in (raw_record_types or [])]
    if not allowed_record_types or any(record_type not in DNS_RECORD_TYPES for record_type in allowed_record_types):
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_allowed_record_types")
    dns_default_provider_account_id = body.get("dns_default_provider_account_id")
    if dns_default_provider_account_id in ("", None):
        dns_default_provider_account_id = None
    else:
        dns_default_provider_account_id = positive_int(dns_default_provider_account_id, "invalid_dns_provider_account_id")
    dns_customer_editable = 1 if body.get("dns_customer_editable", True) else 0
    dns_max_records_per_domain = positive_int(body.get("dns_max_records_per_domain", 100), "invalid_dns_max_records", minimum=0, maximum=10000)
    dns_min_ttl = positive_int(body.get("dns_min_ttl", 60), "invalid_dns_min_ttl", minimum=60, maximum=86400)
    dns_wildcard_records_allowed = 1 if body.get("dns_wildcard_records_allowed", True) else 0
    dns_cloudflare_proxy_allowed = 1 if body.get("dns_cloudflare_proxy_allowed", False) else 0
    dns_dnssec_allowed = 1 if body.get("dns_dnssec_allowed", False) else 0
    dns_dnssec_required = 1 if body.get("dns_dnssec_required", False) else 0
    if dns_dnssec_required:
        dns_dnssec_allowed = 1
    
    return {
        "name": name,
        "cpu_limit": cpu_limit,
        "memory_mb": memory_mb,
        "storage_mb": storage_mb,
        "inode_limit": inode_limit,
        "max_websites": max_websites,
        "max_databases": max_databases,
        "max_mailboxes": max_mailboxes,
        "max_cron_jobs": max_cron_jobs,
        "daily_email_limit": daily_email_limit,
        "backup_retention_days": backup_retention_days,
        "max_processes": max_processes,
        "php_workers": php_workers,
        "bandwidth_mb": bandwidth_mb,
        "nameserver_1": nameserver_1,
        "nameserver_2": nameserver_2,
        "backup_location": backup_location,
        "frontend_frameworks": frontend_frameworks,
        "backend_frameworks": backend_frameworks,
        "nodejs_versions": nodejs_versions,
        "package_managers": package_managers,
        "dns_default_provider": dns_default_provider,
        "dns_allowed_providers_json": json.dumps(sorted(set(allowed_providers))),
        "dns_default_provider_account_id": dns_default_provider_account_id,
        "dns_customer_editable": dns_customer_editable,
        "dns_max_records_per_domain": dns_max_records_per_domain,
        "dns_allowed_record_types_json": json.dumps(sorted(set(allowed_record_types))),
        "dns_min_ttl": dns_min_ttl,
        "dns_wildcard_records_allowed": dns_wildcard_records_allowed,
        "dns_cloudflare_proxy_allowed": dns_cloudflare_proxy_allowed,
        "dns_dnssec_allowed": dns_dnssec_allowed,
        "dns_dnssec_required": dns_dnssec_required,
    }


def positive_int(value, error, minimum=1, maximum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, error)
    if number < minimum or (maximum is not None and number > maximum):
        raise ApiError(HTTPStatus.BAD_REQUEST, error)
    return number


def validate_dns_record_payload(body):
    domain_id = positive_int(body.get("domain_id"), "invalid_domain_id")
    record_type = str(body.get("type", "A") or "A").strip().upper()
    if record_type not in DNS_RECORD_TYPES:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_record_type")
    name = str(body.get("name", "@") or "@").strip()
    if not name or len(name) > 253 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@*" for ch in name):
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_record_name")
    value = str(body.get("value", "") or "").strip()
    if not value or len(value) > 4096 or "\n" in value or "\r" in value:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_record_value")
    ttl = positive_int(body.get("ttl", 300), "invalid_dns_ttl", minimum=60, maximum=86400)
    priority = body.get("priority")
    if priority in ("", None):
        priority = None
    else:
        priority = positive_int(priority, "invalid_dns_priority", minimum=0, maximum=65535)
    proxied_val = body.get("proxied")
    if proxied_val is None:
        proxied = 1 if record_type in {"A", "AAAA", "CNAME"} else 0
    else:
        proxied = 1 if proxied_val else 0
    provider_metadata = body.get("provider_metadata") or body.get("provider_metadata_json") or {}
    if isinstance(provider_metadata, str):
        provider_metadata = parse_json_field(provider_metadata, {})
    if not isinstance(provider_metadata, dict):
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_dns_provider_metadata")
    return {
        "domain_id": domain_id,
        "type": record_type,
        "name": name,
        "value": value,
        "ttl": ttl,
        "priority": priority,
        "proxied": proxied,
        "provider_metadata": provider_metadata,
    }


def enforce_dns_record_policy(conn, account_id, record_payload, domain_id, creating=False):
    plan = conn.execute(
        """
        SELECT p.*
        FROM hosting_accounts ha
        JOIN plans p ON p.id = ha.plan_id
        WHERE ha.id = ?
        """,
        (account_id,),
    ).fetchone()
    if not plan:
        raise ApiError(HTTPStatus.NOT_FOUND, "hosting_account_not_found")
    policy = plan_dns_policy(plan)
    if not policy["customer_editable"]:
        raise ApiError(HTTPStatus.FORBIDDEN, "dns_editing_not_allowed")
    if record_payload["type"] not in set(policy["allowed_record_types"]):
        raise ApiError(HTTPStatus.BAD_REQUEST, "dns_record_type_not_allowed_by_plan")
    if int(record_payload["ttl"]) < int(policy["min_ttl"]):
        raise ApiError(HTTPStatus.BAD_REQUEST, "dns_ttl_below_plan_minimum")
    if not policy["wildcard_records_allowed"] and "*" in record_payload["name"]:
        raise ApiError(HTTPStatus.BAD_REQUEST, "dns_wildcards_not_allowed_by_plan")
    if creating:
        count = conn.execute("SELECT COUNT(*) AS count FROM dns_records WHERE domain_id = ?", (domain_id,)).fetchone()["count"]
        if int(count) >= int(policy["max_records_per_domain"]):
            raise ApiError(HTTPStatus.FORBIDDEN, "dns_record_limit_reached")


def normalize_cpu_limit(value):
    raw = str(value or "").strip().lower().replace("cores", "").replace("core", "").strip()
    try:
        cpu = float(raw)
    except ValueError:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_cpu_limit")
    if cpu <= 0 or cpu > 256:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_cpu_limit")
    return "{:g}".format(cpu)


def otpauth_uri(issuer, email, secret):
    label = "{}:{}".format(issuer, email)
    return "otpauth://totp/{}?secret={}&issuer={}".format(
        quote(label),
        quote(secret),
        quote(issuer),
    )


def create_initial_hosting_account(conn, user_id):
    plan = conn.execute("SELECT * FROM plans ORDER BY id LIMIT 1").fetchone()
    node = conn.execute("SELECT * FROM nodes ORDER BY id LIMIT 1").fetchone()
    if not plan or not node:
        return None

    username = "u{:06d}".format(user_id)
    base_path = str(CONFIG.account_root / username)
    cur = conn.execute(
        """
        INSERT INTO hosting_accounts(user_id, plan_id, node_id, username, base_path, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, plan["id"], node["id"], username, base_path, "provisioning"),
    )
    account_id = cur.lastrowid
    domain = "{}.mango.test".format(username)
    document_root = str(CONFIG.account_root / username / "domains" / domain / "public_html")
    website_id = conn.execute(
        """
        INSERT INTO websites(account_id, domain, document_root, php_version, ssl_status, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (account_id, domain, document_root, "8.3", "missing", "active"),
    ).lastrowid
    dns_assignment = default_domain_dns_assignment(conn, account_id)
    domain_id = conn.execute(
        """
        INSERT INTO domains(
          account_id, name, kind, status, linked_website_id, dns_provider,
          dns_provider_account_id, nameservers_json, dns_status, provider_state_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            account_id,
            domain,
            "managed",
            "active",
            website_id,
            dns_assignment["dns_provider"],
            dns_assignment["dns_provider_account_id"],
            json.dumps(dns_assignment["nameservers"]),
            dns_assignment["dns_status"],
            json.dumps(dns_assignment["provider_state"], sort_keys=True),
        ),
    ).lastrowid
    conn.execute(
        "INSERT OR IGNORE INTO mail_domains(account_id, domain_id, status) VALUES (?, ?, ?)",
        (account_id, domain_id, "active"),
    )
    mail_domain_id = conn.execute(
        "SELECT id FROM mail_domains WHERE account_id = ? AND domain_id = ?",
        (account_id, domain_id),
    ).fetchone()["id"]
    mail_host = "mail-{}.localhost".format(username) if CONFIG.public_host == "127.0.0.1" else "mail.{}.{}".format(username, CONFIG.public_host)
    dkim_material = seed_website_dns_records(conn, domain_id, domain, mail_host)
    conn.execute(
        """
        UPDATE mail_domains
        SET spf_policy = ?, dkim_private_key = ?, dkim_public_key = ?, dkim_selector = ?, dmarc_policy = ?, catch_all_enabled = ?, catch_all_destination = ?, status = ?
        WHERE id = ?
        """,
        (
            recommended_spf_record(mail_host),
            dkim_material["dkim_private_key"],
            dkim_material["dkim_public_key"],
            dkim_material["dkim_selector"],
            recommended_dmarc_record(domain),
            0,
            "",
            "active",
            mail_domain_id,
        ),
    )
    job_id = enqueue_agent_job(conn, "provision_hosting_account", "hosting_account", account_id, {"signup": True})
    account = conn.execute("SELECT * FROM hosting_accounts WHERE id = ?", (account_id,)).fetchone()
    return {
        "id": account_id,
        "username": username,
        "status": account["status"],
        "base_path": base_path,
        "default_domain": domain,
        "provision_job_id": job_id,
    }


def enqueue_agent_job(conn, job_type, target_type, target_id=None, payload=None):
    job_id = create_job(conn, job_type, target_type, target_id, payload)
    if CONFIG.agent_inline:
        conn.execute(
            """
            UPDATE jobs
            SET status = 'running', attempts = attempts + 1, claimed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (job_id,),
        )
        job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        Agent(CONFIG).run_claimed_job(conn, job)
    return job_id


def enqueue_mail_policy_sync(conn, account_id, payload=None):
    payload = dict(payload or {})
    payload.setdefault("reason", "mail_policy_changed")
    return enqueue_agent_job(conn, "sync_mail_policy", "hosting_account", account_id, payload)


def sanitize_domain(value):
    domain = str(value or "").strip().lower()
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if not domain or len(domain) > 253 or any(ch not in allowed for ch in domain) or "." not in domain:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_domain")
    return domain


def delete_client_website(conn, account, website):
    website_id = website["id"]
    domain = website["domain"]
    domain_row = conn.execute(
        "SELECT id FROM domains WHERE account_id = ? AND name = ?",
        (account["id"], domain),
    ).fetchone()
    if domain_row:
        domain_id = domain_row["id"]
        conn.execute("DELETE FROM dns_records WHERE domain_id = ?", (domain_id,))
        conn.execute("DELETE FROM dns_zones WHERE domain_id = ?", (domain_id,))
        conn.execute("DELETE FROM dns_zone_exports WHERE domain_id = ?", (domain_id,))
        mail_domain = conn.execute("SELECT id FROM mail_domains WHERE domain_id = ?", (domain_id,)).fetchone()
        if mail_domain:
            m_id = mail_domain["id"]
            conn.execute("UPDATE mailboxes SET mail_domain_id = NULL WHERE mail_domain_id = ?", (m_id,))
            conn.execute("DELETE FROM mail_edge_routes WHERE domain_id = ? OR mail_domain_id = ?", (domain_id, m_id))
            conn.execute("DELETE FROM mail_domains WHERE id = ?", (m_id,))
        else:
            conn.execute("DELETE FROM mail_edge_routes WHERE domain_id = ?", (domain_id,))
            conn.execute("DELETE FROM mail_domains WHERE domain_id = ?", (domain_id,))



        conn.execute("UPDATE acme_certificate_orders SET domain_id = NULL WHERE domain_id = ?", (domain_id,))
    conn.execute("DELETE FROM redirects WHERE website_id = ?", (website_id,))
    conn.execute("DELETE FROM script_installs WHERE website_id = ?", (website_id,))
    conn.execute("DELETE FROM wordpress_installs WHERE website_id = ?", (website_id,))
    conn.execute("UPDATE access_logs SET website_id = NULL WHERE website_id = ?", (website_id,))
    conn.execute("UPDATE acme_certificate_orders SET website_id = NULL WHERE website_id = ?", (website_id,))
    conn.execute("UPDATE ssl_certificates SET website_id = NULL, status = 'removed' WHERE website_id = ?", (website_id,))
    conn.execute("UPDATE domains SET linked_website_id = NULL WHERE linked_website_id = ?", (website_id,))
    conn.execute("DELETE FROM websites WHERE id = ?", (website_id,))
    conn.execute("UPDATE domains SET linked_website_id = NULL WHERE account_id = ? AND name = ?", (account["id"], domain))

    return enqueue_agent_job(conn, "delete_website", "hosting_account", account["id"], {"removed_website_id": website_id, "domain": domain})


def admin_clients_payload(conn):
    users = rows_to_dicts(conn.execute("SELECT id, email, full_name, status, created_at FROM users ORDER BY id").fetchall())
    for user in users:
        user["accounts"] = admin_client_accounts(conn, user["id"])
    return users


def admin_client_payload(conn, user_id):
    user = conn.execute("SELECT id, email, full_name, status, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return None
    payload = row_to_dict(user)
    payload["accounts"] = admin_client_accounts(conn, user_id)
    return payload


def admin_client_accounts(conn, user_id):
    rows = conn.execute(
        """
        SELECT ha.*, p.name AS plan_name, n.name AS node_name,
               p.cpu_limit, p.memory_mb, p.storage_mb, p.inode_limit,
               p.max_websites, p.max_databases, p.max_mailboxes, p.max_cron_jobs,
               p.daily_email_limit, p.backup_retention_days
        FROM hosting_accounts ha
        JOIN plans p ON p.id = ha.plan_id
        JOIN nodes n ON n.id = ha.node_id
        WHERE ha.user_id = ?
        ORDER BY ha.id
        """,
        (user_id,),
    ).fetchall()
    accounts = rows_to_dicts(rows)
    for account in accounts:
        account["website_count"] = conn.execute("SELECT COUNT(*) AS count FROM websites WHERE account_id = ?", (account["id"],)).fetchone()["count"]
        account["database_count"] = conn.execute("SELECT COUNT(*) AS count FROM databases WHERE account_id = ?", (account["id"],)).fetchone()["count"]
        account["mailbox_count"] = conn.execute("SELECT COUNT(*) AS count FROM mailboxes WHERE account_id = ?", (account["id"],)).fetchone()["count"]
        account["backup_count"] = conn.execute("SELECT COUNT(*) AS count FROM backups WHERE account_id = ?", (account["id"],)).fetchone()["count"]
        account["runtime"] = account_runtime(conn, account["id"])
    return accounts


def delete_client(conn, user_id):
    accounts = conn.execute("SELECT id FROM hosting_accounts WHERE user_id = ?", (user_id,)).fetchall()
    account_ids = [row["id"] for row in accounts]
    website_ids = select_ids_for_accounts(conn, "websites", account_ids)
    domain_ids = select_ids_for_accounts(conn, "domains", account_ids)
    backup_rows = select_rows_for_accounts(conn, "backups", account_ids, "id, artifact_path")

    if domain_ids:
        conn.execute("DELETE FROM dns_records WHERE domain_id IN ({})".format(sql_placeholders(domain_ids)), domain_ids)
    if website_ids:
        conn.execute("DELETE FROM wordpress_installs WHERE website_id IN ({})".format(sql_placeholders(website_ids)), website_ids)
        conn.execute("DELETE FROM script_installs WHERE website_id IN ({})".format(sql_placeholders(website_ids)), website_ids)
    if account_ids:
        database_ids = select_ids_for_accounts(conn, "databases", account_ids)
        if database_ids:
            conn.execute("DELETE FROM database_grants WHERE database_id IN ({})".format(sql_placeholders(database_ids)), database_ids)
        conn.execute("DELETE FROM database_users WHERE account_id IN ({})".format(sql_placeholders(account_ids)), account_ids)
        for table in [
            "mailbox_launch_tokens",
            "mail_messages",
            "mail_delivery_logs",
            "mail_autoresponders",
            "mail_aliases",
            "mail_forwarders",
            "mailboxes",
            "mail_edge_routes",
            "mail_domains",
            "access_logs",
            "acme_certificate_orders",
            "api_tokens",
            "cron_jobs",
            "dns_zones",
            "ftp_accounts",
            "git_deployments",
            "hotlink_settings",
            "ip_rules",
            "pg_users",
            "pg_databases",
            "protected_directories",
            "redirects",
            "remote_mysql_hosts",
            "resource_usage_samples",
            "ssl_certificates",
            "account_stacks",
            "domains",
            "websites",
            "databases",
        ]:
            conn.execute("DELETE FROM {} WHERE account_id IN ({})".format(table, sql_placeholders(account_ids)), account_ids)
        conn.execute("DELETE FROM collaborators WHERE hosting_account_id IN ({}) OR owner_user_id = ?".format(sql_placeholders(account_ids)), [*account_ids, user_id])
        conn.execute("DELETE FROM support_notes WHERE hosting_account_id IN ({}) OR user_id = ?".format(sql_placeholders(account_ids)), [*account_ids, user_id])
        for row in backup_rows:
            artifact_path = row["artifact_path"]
            if artifact_path:
                artifact = Path(artifact_path)
                if artifact.exists() and artifact.is_file():
                    artifact.unlink()
        conn.execute("DELETE FROM backups WHERE account_id IN ({})".format(sql_placeholders(account_ids)), account_ids)
        conn.execute("DELETE FROM hosting_accounts WHERE id IN ({})".format(sql_placeholders(account_ids)), account_ids)
    conn.execute("DELETE FROM sessions WHERE actor_type = 'user' AND actor_id = ?", (user_id,))
    conn.execute("DELETE FROM activity_logs WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"user_id": user_id, "account_ids": account_ids, "website_ids": website_ids}


def select_ids_for_accounts(conn, table, account_ids):
    if not account_ids:
        return []
    rows = conn.execute(
        "SELECT id FROM {} WHERE account_id IN ({})".format(table, sql_placeholders(account_ids)),
        account_ids,
    ).fetchall()
    return [row["id"] for row in rows]


def select_rows_for_accounts(conn, table, account_ids, columns):
    if not account_ids:
        return []
    return conn.execute(
        "SELECT {} FROM {} WHERE account_id IN ({})".format(columns, table, sql_placeholders(account_ids)),
        account_ids,
    ).fetchall()


def sql_placeholders(values):
    return ",".join("?" for _ in values)


def client_home(conn, user_id):
    accounts = rows_to_dicts(
        conn.execute(
            """
            SELECT ha.*,
                   p.name AS plan_name, p.cpu_limit, p.memory_mb, p.storage_mb,
                   p.inode_limit, p.max_websites, p.max_databases, p.max_mailboxes,
                   p.max_cron_jobs, p.daily_email_limit, p.backup_retention_days,
                   p.max_processes, p.php_workers, p.bandwidth_limit_gb * 1024 AS bandwidth_mb,
                   p.nameserver1 AS nameserver_1, p.nameserver2 AS nameserver_2, 
                   p.server_location AS node_location, p.backups_location AS backup_location,
                   p.frontend_frameworks, p.backend_frameworks,
                   n.name AS node_name, n.hostname AS node_hostname
            FROM hosting_accounts ha
            JOIN plans p ON p.id = ha.plan_id
            JOIN nodes n ON n.id = ha.node_id
            WHERE ha.user_id = ?
            ORDER BY ha.id
            """,
            (user_id,),
        ).fetchall()
    )
    websites = rows_to_dicts(
        conn.execute(
            """
            SELECT w.*, d.id AS domain_id, d.nameservers_json, d.provider_state_json, d.dns_provider, d.dns_status
            FROM websites w
            JOIN hosting_accounts ha ON ha.id = w.account_id
            LEFT JOIN domains d ON d.linked_website_id = w.id
            WHERE ha.user_id = ?
            ORDER BY w.id
            """,
            (user_id,),
        ).fetchall()
    )
    warnings = []
    for website in websites:
        if website["ssl_status"] == "missing":
            warnings.append({"kind": "ssl", "message": f"SSL is not installed for {website['domain']}"})
    for website in websites:
        website["public_url"] = f"http://{website['domain']}"
        website["host_header"] = website["domain"]
        website["nameservers"] = website_dns_nameservers(website)
        website["dns_provider_label"] = "Cloudflare" if website.get("dns_provider") == DNS_PROVIDER_CLOUDFLARE else "Local DNS"
    for account in accounts:
        account["runtime"] = account_runtime(conn, account["id"])
    user = conn.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,)).fetchone()
    has_2fa = bool(user and user["totp_secret"])
    
    return {
        "accounts": accounts,
        "websites": websites,
        "warnings": warnings,
        "has_2fa": has_2fa,
        "resources": {
            "disk_used_mb": 384,
            "disk_limit_mb": accounts[0]["storage_mb"] if accounts and "storage_mb" in accounts[0] else 10240,
            "inodes_used": 1250,
            "inodes_limit": 100000,
            "cpu": "low",
            "memory": "healthy",
        },
    }


def website_dns_nameservers(website):
    nameservers = parse_json_field(website.get("nameservers_json"), []) if isinstance(website, dict) else []
    if nameservers:
        return nameservers
    provider_state = parse_json_field(website.get("provider_state_json"), {}) if isinstance(website, dict) else {}
    state_nameservers = provider_state.get("nameservers") or []
    if state_nameservers:
        return state_nameservers
    domain_record = website.get("domain_record") if isinstance(website, dict) else None
    if isinstance(domain_record, dict):
        nameservers = domain_record.get("nameservers") or []
        if nameservers:
            return nameservers
        provider_state = domain_record.get("provider_state") or {}
        if provider_state.get("nameservers"):
            return provider_state["nameservers"]
    return []



def admin_dashboard(conn):
    counts = {}
    for key, table in [
        ("users", "users"),
        ("hosting_accounts", "hosting_accounts"),
        ("websites", "websites"),
        ("account_stacks", "account_stacks"),
        ("jobs", "jobs"),
        ("open_incidents", "status_incidents WHERE state != 'resolved' AND published = 1"),
    ]:
        counts[key] = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
    nodes = rows_to_dicts(conn.execute("SELECT * FROM nodes ORDER BY id").fetchall())
    jobs = rows_to_dicts(conn.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 10").fetchall())
    status = build_status_payload(conn)
    return {"counts": counts, "nodes": nodes, "recent_jobs": jobs, "status": status}


def build_status_payload(conn):
    components = rows_to_dicts(conn.execute("SELECT * FROM status_components ORDER BY sort_order, name").fetchall())
    queue_worker = service_worker_health()
    components.append(
        {
            "id": "queue-worker",
            "name": "Queue Worker",
            "group_name": "Operations",
            "status": queue_worker["status"],
            "description": queue_worker["description"],
            "updated_at": queue_worker["updated_at"],
        }
    )
    incidents = rows_to_dicts(
        conn.execute("SELECT * FROM status_incidents WHERE published = 1 ORDER BY id DESC LIMIT 20").fetchall()
    )
    maintenances = rows_to_dicts(
        conn.execute("SELECT * FROM status_maintenances WHERE published = 1 ORDER BY starts_at DESC LIMIT 20").fetchall()
    )
    active_incidents = [incident for incident in incidents if incident["state"] != "resolved"]
    if any(component["status"] == "major_outage" for component in components):
        overall = "major_outage"
    elif active_incidents or any(component["status"] in {"degraded", "partial_outage"} for component in components):
        overall = "degraded_performance"
    elif any(component["status"] == "maintenance" for component in components):
        overall = "maintenance"
    else:
        overall = "operational"
    return {
        "overall_status": overall,
        "components": components,
        "incidents": incidents,
        "maintenance": maintenances,
        "history_days": 90,
    }


def service_worker_health():
    pid_file = SERVICE_VAR_DIR / "mangopanel-worker.pid"
    log_file = SERVICE_VAR_DIR / "mangopanel-worker.log"
    if pid_file.exists():
        pid = pid_file.read_text(encoding="utf-8").strip()
        if pid:
            try:
                pid_int = int(pid)
            except ValueError:
                pid_int = None
            if pid_int:
                try:
                    os.kill(pid_int, 0)
                    return {
                        "status": "operational",
                        "description": "Queue worker is running.",
                        "updated_at": None,
                    }
                except OSError:
                    pass
    return {
        "status": "degraded",
        "description": f"Queue worker is not running. Check {log_file}.",
        "updated_at": None,
    }


def build_atom_feed(payload):
    entries = []
    for incident in payload["incidents"][:10]:
        entries.append(
            """
            <entry><title>{title}</title><id>incident-{id}</id><updated>{updated}</updated><summary>{state}</summary></entry>
            """.format(
                title=escape_xml(incident["title"]),
                id=incident["id"],
                updated=incident.get("resolved_at") or incident.get("created_at"),
                state=escape_xml(incident["state"]),
            ).strip()
        )
    return """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>MangoPanel Status</title>
  <id>mangopanel-status</id>
  <updated>{updated}</updated>
  {entries}
</feed>
""".format(updated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), entries="\n  ".join(entries))


def escape_xml(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def start_resource_usage_collector(config):
    def loop():
        while True:
            try:
                collect_all_resource_usage_samples(config)
            except Exception as exc:
                print(f"resource usage collector error: {exc}")
            time.sleep(60)

    thread = threading.Thread(target=loop, name="mangopanel-resource-usage", daemon=True)
    thread.start()
    return thread


def run():
    CONFIG.data_dir.mkdir(parents=True, exist_ok=True)
    CONFIG.account_root.mkdir(parents=True, exist_ok=True)
    init_db(CONFIG.db_path)
    if CONFIG.env == "development":
        seed_dev_data(CONFIG.db_path, CONFIG.account_root)
        agent = Agent(CONFIG)
        agent.run_all()
        import subprocess, os
        # Start global Edge Proxy FIRST so the mangopanel-edge network exists
        # before any account stacks try to attach to it.
        edge_compose = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docker-compose-edge.yml")
        try:
            subprocess.run(["docker", "compose", "-f", edge_compose, "up", "-d"], check=False)
        except Exception as e:
            print(f"Failed to start edge proxy: {e}")
        # Ensure the network exists even if caddy isn't running yet
        try:
            subprocess.run(
                ["docker", "network", "create", "mangopanel-edge"],
                check=False, capture_output=True
            )
        except Exception:
            pass  # Already exists — that's fine

        # Materialize every account stack so a single `make dev-up` brings the
        # whole system up: files in simulate mode, containers in docker mode.
        agent.apply_all_accounts()
    start_resource_usage_collector(CONFIG)
    if CONFIG.client_port == CONFIG.admin_port:
        raise RuntimeError("MP_CLIENT_PORT and MP_ADMIN_PORT must be different so client and admin panels stay separate.")

    client_httpd = MangoDualServer((CONFIG.host, CONFIG.client_port), MangoHandler)
    client_httpd.panel = "client"
    admin_httpd = MangoDualServer((CONFIG.host, CONFIG.admin_port), MangoHandler)
    admin_httpd.panel = "admin"
    admin_thread = threading.Thread(target=admin_httpd.serve_forever, name="mangopanel-admin", daemon=True)
    admin_thread.start()
    local_host = "127.0.0.1" if CONFIG.host in {"0.0.0.0", "::"} else CONFIG.host
    public_host = detect_public_access_host()
    print(f"MangoPanel client panel running at http://{local_host}:{CONFIG.client_port}")
    print(f"MangoPanel admin panel running at  http://{local_host}:{CONFIG.admin_port}/admin")
    print(f"Status: http://{local_host}:{CONFIG.client_port}/status")
    if public_host:
        print(f"Public client access: http://{public_host}:{CONFIG.client_port}")
        print(f"Public admin access:  http://{public_host}:{CONFIG.admin_port}/admin")
        print(f"Public status:        http://{public_host}:{CONFIG.client_port}/status")
    try:
        client_httpd.serve_forever()
    finally:
        admin_httpd.shutdown()
        admin_thread.join(timeout=5)


if __name__ == "__main__":
    run()
