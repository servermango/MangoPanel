import json
import ipaddress
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from .agent import Agent, AgentError, cron_next_run_at, decorate_cron_jobs, validate_cron_schedule
from .config import load_config
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
from .security import create_jwt, generate_totp_secret, hash_mailpit_password, hash_password, verify_jwt, verify_password, verify_totp


CONFIG = load_config()
PUBLIC_DIR = Path(__file__).resolve().parent.parent / "public"
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


class ApiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message


def get_cookie_domain(host_header):
    host = host_header.split(":")[0]
    if host == "localhost":
        return ".localhost"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return ""
    parts = host.split(".")
    if len(parts) >= 2:
        return "." + ".".join(parts[-2:])
    return ""


def auth_cookie_header(token, host_header, max_age=None):
    cookie_domain = get_cookie_domain(host_header)
    domain_attr = f"; Domain={cookie_domain}" if cookie_domain else ""
    ttl = CONFIG.token_ttl_seconds if max_age is None else max_age
    return f"mp_client_token={token}; Path=/; Max-Age={ttl}; SameSite=Lax{domain_attr}"


def auth_cookie_headers(token, host_header):
    cookie_domain = get_cookie_domain(host_header)
    if cookie_domain == ".localhost":
        return [
            f"mp_client_token={token}; Path=/; Max-Age={CONFIG.token_ttl_seconds}; SameSite=Lax; Domain=localhost",
            f"mp_client_token={token}; Path=/; Max-Age={CONFIG.token_ttl_seconds}; SameSite=Lax; Domain=.localhost",
        ]
    return [auth_cookie_header(token, host_header, CONFIG.token_ttl_seconds)]


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


def build_tool_redirect_url(host, path):
    host = host or "localhost"
    if not path.startswith("/"):
        path = "/" + path
    return f"http://{host}{path}"


class MangoHandler(BaseHTTPRequestHandler):
    server_version = "MangoPanel/0.1"

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
        query = parse_qs(parsed.query)
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
                return self.serve_file(PUBLIC_DIR / "admin_plans.html")
            if path == "/status":
                return self.serve_file(PUBLIC_DIR / "status.html")
            if path.startswith("/assets/"):
                return self.serve_file(PUBLIC_DIR / path.lstrip("/"))
            if path == "/health":
                return self.json_response({"status": "ok", "service": "mangopanel-api"})

            if path.startswith("/api/") or path.startswith("/auth/"):
                return self.route_api(method, path, query)

            self.json_response({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        except ApiError as exc:
            self.json_response({"error": exc.message}, exc.status)
        except Exception as exc:
            self.json_response({"error": "internal_error", "detail": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def route_api(self, method, path, query):
        panel = getattr(self.server, "panel", "combined")
        if panel == "client" and path == "/api/public/admin-setup":
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")
        if panel == "admin" and path == "/api/public/signup":
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")
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

        if path.startswith("/auth/") or path.startswith("/api/public/"):
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
        if path == "/api/public/mailpit-brand.svg" and method == "GET":
            return self.svg_response(MAILPIT_BRAND_SVG)
        if path == "/api/public/bootstrap" and method == "GET":
            return self.json_response({"admin_setup_required": admin_count() == 0})
        if path == "/api/public/signup" and method == "POST":
            body = self.read_json()
            return self.signup_customer(body)
        if path == "/api/public/admin-setup" and method == "POST":
            body = self.read_json()
            return self.setup_first_admin(body)
        if path.startswith("/auth/") and method == "GET":
            return self.public_tool_launch(path)
        if path.startswith("/api/public/tool-launch/") and method == "GET":
            return self.public_tool_launch(path)
        if path == "/api/public/auth-verify":
            return self.forward_auth_verify()
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_public_route")

    def public_tool_launch(self, path):
        forwarded_host = self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
        tool = None
        if forwarded_host:
            host_part = forwarded_host.split(":")[0]
            if host_part.startswith("files-") or host_part.startswith("files."):
                tool = "filebrowser"
            elif host_part.startswith("pma-") or host_part.startswith("pma."):
                tool = "phpmyadmin"

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
                r"^/api/public/tool-launch/(?P<tool>filebrowser|phpmyadmin)/auth/(?P<token>[A-Za-z0-9._-]{20,})(?P<suffix>/.*)?$",
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
            match = re.match(r"^(?:files|pma)[-.](\w+)\.", host_part)
            if match:
                username = match.group(1)

        if not tool:
            raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")

        payload = verify_jwt(token, CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "tool_launch" or payload.get("tool") != tool:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_tool_launch")

        actor_type = payload.get("actor_type")
        actor_id = payload.get("sub")
        if actor_type != "user" or not username:
            raise ApiError(HTTPStatus.FORBIDDEN, "access_denied")

        with connect(CONFIG.db_path) as conn:
            user = conn.execute("SELECT status FROM users WHERE id = ?", (actor_id,)).fetchone()
            if not user or user["status"] != "active":
                raise ApiError(HTTPStatus.UNAUTHORIZED, "inactive_user")
            account = conn.execute(
                "SELECT * FROM hosting_accounts WHERE user_id = ? AND username = ? AND status = 'active'",
                (actor_id, username),
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
            clean_path = suffix or default_path
            self.send_response(HTTPStatus.FOUND)
            for cookie_header in auth_cookie_headers(access_token, forwarded_host):
                self.send_header("Set-Cookie", cookie_header)
            self.send_header("Location", build_tool_redirect_url(forwarded_host, clean_path))
            self.end_headers()
            return

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

        if not token or not username:
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
                account = conn.execute(
                    "SELECT id FROM hosting_accounts WHERE user_id = ? AND username = ? AND status = 'active'",
                    (actor_id, username)
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
                    for cookie_header in auth_cookie_headers(access_token, forwarded_host):
                        self.send_header("Set-Cookie", cookie_header)
                    self.send_header("Location", build_tool_redirect_url(forwarded_host, clean_path))
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

    def login(self, actor_type):
        body = self.read_json()
        email = body.get("email", "").strip().lower()
        password = body.get("password", "")
        table = "admins" if actor_type == "admin" else "users"
        with connect(CONFIG.db_path) as conn:
            actor = conn.execute(f"SELECT * FROM {table} WHERE email = ? AND status = 'active'", (email,)).fetchone()
            if not actor or not verify_password(password, actor["password_hash"]):
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
            actor = conn.execute(f"SELECT * FROM {table} WHERE id = ? AND status = 'active'", (payload["sub"],)).fetchone()
            if not actor:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "actor_not_found")
            code = body.get("code", "")
            dev_bypass_ok = CONFIG.is_development and CONFIG.dev_auth_test_mode and code == "000000"
            if not dev_bypass_ok and not verify_totp(actor["totp_secret"], code):
                raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_totp")
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
        payload = verify_jwt(auth.removeprefix("Bearer ").strip(), CONFIG.jwt_secret)
        if not payload or payload.get("purpose") != "access" or payload.get("actor_type") != actor_type:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "invalid_access_token")
        table = "admins" if actor_type == "admin" else "users"
        with connect(CONFIG.db_path) as conn:
            actor = conn.execute(f"SELECT * FROM {table} WHERE id = ? AND status = 'active'", (payload["sub"],)).fetchone()
            if not actor:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "actor_not_found")
            return row_to_dict(actor)

    def client_api(self, method, path, query, actor):
        with connect(CONFIG.db_path) as conn:
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
                website_id = optional_positive_int(query.get("website_id", [""])[0])
                filter_key = query.get("filter", ["top-countries"])[0]
                return self.json_response(client_analytics_payload(conn, account["id"], website_id, filter_key))
            if path == "/api/client/websites" and method == "GET":
                rows = conn.execute(
                    """
                    SELECT w.* FROM websites w
                    JOIN hosting_accounts ha ON ha.id = w.account_id
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
                return self.json_response({"websites": websites})
            if path == "/api/client/websites" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "websites", "max_websites", "website_limit_reached")
                body = self.read_json()
                domain = sanitize_domain(body.get("domain", ""))
                document_root = f"{account['base_path']}/domains/{domain}/public_html"
                cur = conn.execute(
                    """
                    INSERT INTO websites(account_id, domain, document_root, php_version, ssl_status, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (account["id"], domain, document_root, body.get("php_version", "8.3"), "missing", "active"),
                )
                website_id = cur.lastrowid
                conn.execute(
                    "INSERT OR IGNORE INTO domains(account_id, name, kind, status, linked_website_id) VALUES (?, ?, ?, ?, ?)",
                    (account["id"], domain, "managed", "active", website_id),
                )
                job_id = enqueue_agent_job(conn, "create_website", "website", website_id, {"domain": domain})
                log_activity(conn, actor["id"], "website_created", {"domain": domain})
                return self.json_response(
                    {"website": row_to_dict(conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()), "job_id": job_id},
                    HTTPStatus.CREATED,
                )
            if path.startswith("/api/client/websites/") and not path.endswith("/php") and not path.endswith("/modsec"):
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
                    SELECT d.* FROM domains d
                    JOIN hosting_accounts ha ON ha.id = d.account_id
                    WHERE ha.user_id = ?
                    ORDER BY d.name
                    """,
                    (actor["id"],),
                ).fetchall()
                return self.json_response({"domains": rows_to_dicts(rows)})
            if path == "/api/client/dns-records" and method == "GET":
                require_account(account)
                domain_id = optional_positive_int(query.get("domain_id", [""])[0])
                if domain_id:
                    domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                    if not domain:
                        raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                    rows = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (domain_id,)).fetchall()
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
                return self.json_response({"dns_records": rows_to_dicts(rows)})
            if path == "/api/client/dns-records" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                domain_id = int(body.get("domain_id"))
                domain = conn.execute("SELECT * FROM domains WHERE id = ? AND account_id = ?", (domain_id, account["id"])).fetchone()
                if not domain:
                    raise ApiError(HTTPStatus.NOT_FOUND, "domain_not_found")
                cur = conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl, priority) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        domain_id,
                        body.get("type", "A").upper(),
                        body.get("name", "@"),
                        body.get("value", ""),
                        int(body.get("ttl", 300)),
                        body.get("priority"),
                    ),
                )
                job_id = enqueue_agent_job(conn, "sync_dns_record", "dns_record", cur.lastrowid, {})
                log_activity(conn, actor["id"], "dns_record_created", {"domain_id": domain_id, "type": body.get("type", "A")})
                all_records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (domain_id,)).fetchall()
                return self.json_response({"dns_record_id": cur.lastrowid, "job_id": job_id, "dns_records": rows_to_dicts(all_records)}, HTTPStatus.CREATED)
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
                conn.execute("DELETE FROM dns_records WHERE id = ?", (record_id,))
                job_id = enqueue_agent_job(conn, "sync_dns_zone", "domain", record["domain_id"], {})
                log_activity(conn, actor["id"], "dns_record_deleted", {"record_id": record_id})
                all_records = conn.execute("SELECT * FROM dns_records WHERE domain_id = ? ORDER BY type, name", (record["domain_id"],)).fetchall()
                return self.json_response({"deleted": True, "job_id": job_id, "dns_records": rows_to_dicts(all_records)})
            if path == "/api/client/ssl/issue" and method == "POST":
                require_active_account(account)
                body = self.read_json()
                website_id = int(body.get("website_id"))
                website = conn.execute("SELECT * FROM websites WHERE id = ? AND account_id = ?", (website_id, account["id"])).fetchone()
                if not website:
                    raise ApiError(HTTPStatus.NOT_FOUND, "website_not_found")
                job_id = enqueue_agent_job(conn, "issue_ssl", "website", website_id, {"mode": "local-dev"})
                refreshed = conn.execute("SELECT ssl_status FROM websites WHERE id = ?", (website_id,)).fetchone()
                return self.json_response({"ssl_status": refreshed["ssl_status"], "job_id": job_id})
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
                base_url = runtime.get("filebrowser_url", "")
                requested_path = query.get("path", [""])[0].strip()
                launch_token = create_jwt(
                    {"sub": actor["id"], "actor_type": "user", "purpose": "tool_launch", "tool": "filebrowser"},
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

                return self.json_response({"launch_url": launch_url, "expires_in": 600})
            if path == "/api/client/phppgadmin/launch" and method == "GET":
                require_account(account)
                runtime = account_runtime(conn, account["id"])
                return self.json_response({"launch_url": runtime.get("adminer_url"), "expires_in": 300})
            if path == "/api/client/phpmyadmin/launch" and method == "GET":
                require_account(account)
                runtime = account_runtime(conn, account["id"])
                base_url = runtime.get("phpmyadmin_url", "")
                launch_token = create_jwt(
                    {"sub": actor["id"], "actor_type": "user", "purpose": "tool_launch", "tool": "phpmyadmin"},
                    CONFIG.jwt_secret,
                    600,
                )
                launch_url = f"{base_url}/auth/{launch_token}"
                return self.json_response({"launch_url": launch_url, "expires_in": 600})
            if path == "/api/client/webmail/launch" and method == "GET":
                require_account(account)
                runtime = account_runtime(conn, account["id"])
                return self.json_response({"launch_url": runtime.get("mailpit_url"), "expires_in": 300})
            if path.startswith("/api/client/mailboxes/") and path.endswith("/webmail/launch") and method == "GET":
                require_account(account)
                mailbox_id = path_int_id(path, "/api/client/mailboxes/")
                mailbox = require_owned_mailbox(conn, account["id"], mailbox_id)
                runtime = account_runtime(conn, account["id"])
                mailbox_query = quote(f'addressed:"{mailbox["email"]}"', safe="")
                launch_url = f"{runtime.get('mailpit_url', '').rstrip('/')}/search?q={mailbox_query}"
                return self.json_response({"launch_url": launch_url, "mailbox": {"id": mailbox_id, "email": mailbox["email"]}, "expires_in": 300})
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
                if conn.execute("SELECT id FROM databases WHERE name = ?", (name,)).fetchone():
                    raise ApiError(HTTPStatus.CONFLICT, "database_name_already_exists")
                cur = conn.execute(
                    "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                    (account["id"], name, username, "active"),
                )
                job_id = enqueue_agent_job(conn, "create_database", "database", cur.lastrowid, {"name": name})
                log_activity(conn, actor["id"], "database_created", {"name": name})
                return self.json_response({"database_id": cur.lastrowid, "job_id": job_id, **client_databases_payload(conn, account["id"])}, HTTPStatus.CREATED)
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
                    job_id = enqueue_agent_job(conn, "delete_database", "database", database_id, {"name": database["name"]})
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
                job_id = enqueue_agent_job(conn, "create_database_user", "database_user", cur.lastrowid, {"username": username})
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
                    job_id = enqueue_agent_job(conn, "update_database_user", "database_user", user_id, {"username": username, "status": status, "password_changed": bool(body.get("password"))})
                    log_activity(conn, actor["id"], "database_user_updated", {"username": username})
                    return self.json_response({"job_id": job_id, **client_databases_payload(conn, account["id"])})
                if method == "DELETE":
                    conn.execute("DELETE FROM database_grants WHERE user_id = ?", (user_id,))
                    conn.execute("DELETE FROM database_users WHERE id = ?", (user_id,))
                    job_id = enqueue_agent_job(conn, "delete_database_user", "database_user", user_id, {"username": db_user["username"]})
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
                job_id = enqueue_agent_job(conn, "grant_database_user", "database_grant", cur.lastrowid, {"database_id": database_id, "user_id": user_id, "privileges": privileges})
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
                    job_id = enqueue_agent_job(conn, "revoke_database_user", "database_grant", grant_id, {"database_id": grant["database_id"], "user_id": grant["user_id"]})
                    log_activity(conn, actor["id"], "database_user_removed_from_database", {"grant_id": grant_id})
                    return self.json_response({"deleted": True, "job_id": job_id, **client_databases_payload(conn, account["id"])})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_database_grant_route")
            if path == "/api/client/mailboxes" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "mailboxes", "max_mailboxes", "mailbox_limit_reached")
                body = self.read_json()
                email = normalize_email(body.get("email"))
                password = validate_password(body.get("password", ""))
                confirm_password = str(body.get("confirm_password") or "").strip()
                if confirm_password and confirm_password != password:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "mailbox_password_mismatch")
                quota_mb = positive_int(body.get("quota_mb", 1024), "invalid_mailbox_quota", minimum=100, maximum=100000)
                cur = conn.execute(
                    "INSERT INTO mailboxes(account_id, email, quota_mb, status, password_hash, mailpit_auth_hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (account["id"], email, quota_mb, "active", hash_password(password), hash_mailpit_password(password)),
                )
                job_id = enqueue_agent_job(conn, "create_mailbox", "mailbox", cur.lastrowid, {"email": email})
                return self.json_response({"mailbox_id": cur.lastrowid, "job_id": job_id}, HTTPStatus.CREATED)
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
                branch = clean_text(body.get("branch", "main"), "main")
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
                rows = conn.execute(
                    "SELECT id, account_id, email, quota_mb, status, created_at FROM mailboxes WHERE account_id = ? ORDER BY id",
                    (account["id"],),
                ).fetchall()
                return self.json_response({"mailboxes": rows_to_dicts(rows)})
            if path == "/api/client/mailboxes" and method == "POST":
                require_active_account(account)
                require_plan_capacity(conn, account["id"], "mailboxes", "max_mailboxes", "mailbox_limit_reached")
                body = self.read_json()
                email = normalize_email(body.get("email"))
                password = validate_password(body.get("password", ""))
                confirm_password = str(body.get("confirm_password") or "").strip()
                if confirm_password and confirm_password != password:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "mailbox_password_mismatch")
                quota_mb = positive_int(body.get("quota_mb", 1024), "invalid_mailbox_quota", minimum=100, maximum=100000)
                cur = conn.execute(
                    "INSERT INTO mailboxes(account_id, email, quota_mb, status, password_hash, mailpit_auth_hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (account["id"], email, quota_mb, "active", hash_password(password), hash_mailpit_password(password)),
                )
                job_id = enqueue_agent_job(conn, "create_mailbox", "mailbox", cur.lastrowid, {"email": email})
                return self.json_response({"mailbox_id": cur.lastrowid, "job_id": job_id}, HTTPStatus.CREATED)
            if path.startswith("/api/client/mailboxes/"):
                require_active_account(account)
                mailbox_id = path_int_id(path, "/api/client/mailboxes/")
                mailbox = require_owned_mailbox(conn, account["id"], mailbox_id)
                if method == "PATCH":
                    body = self.read_json()
                    quota_mb = positive_int(body.get("quota_mb", mailbox["quota_mb"]), "invalid_mailbox_quota", minimum=100, maximum=100000)
                    status = body.get("status", mailbox["status"])
                    if status not in {"active", "suspended"}:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_mailbox_status")
                    password_sql = ""
                    params = [quota_mb, status]
                    if body.get("password"):
                        password = validate_password(body.get("password", ""))
                        confirm_password = str(body.get("confirm_password") or "").strip()
                        if confirm_password and confirm_password != password:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "mailbox_password_mismatch")
                        password_sql = ", password_hash = ?, mailpit_auth_hash = ?"
                        params.extend([hash_password(password), hash_mailpit_password(password)])
                    conn.execute(
                        f"UPDATE mailboxes SET quota_mb = ?, status = ?{password_sql} WHERE id = ?",
                        tuple(params + [mailbox_id]),
                    )
                    job_id = enqueue_agent_job(conn, "sync_mailboxes", "hosting_account", account["id"], {"mailbox_id": mailbox_id})
                    log_activity(conn, actor["id"], "mailbox_updated", {"mailbox_id": mailbox_id})
                    updated = conn.execute(
                        "SELECT id, account_id, email, quota_mb, status, created_at FROM mailboxes WHERE id = ?",
                        (mailbox_id,),
                    ).fetchone()
                    return self.json_response({"mailbox": row_to_dict(updated), "job_id": job_id})
                if method == "DELETE":
                    conn.execute("DELETE FROM mailboxes WHERE id = ?", (mailbox_id,))
                    job_id = enqueue_agent_job(conn, "sync_mailboxes", "hosting_account", account["id"], {"mailbox_id": mailbox_id, "email": mailbox["email"]})
                    log_activity(conn, actor["id"], "mailbox_deleted", {"email": mailbox["email"]})
                    return self.json_response({"deleted": True, "job_id": job_id})
                raise ApiError(HTTPStatus.NOT_FOUND, "unknown_mailbox_route")
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
                valid_services = ["web", "db", "filebrowser", "phpmyadmin", "cron", "sftp", "smtp-relay"]
                if service_name not in valid_services:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_service")
                job_id = enqueue_agent_job(conn, "restart_service", "hosting_account", account["id"], {"service": service_name})
                log_activity(conn, actor["id"], "service_restarted", {"account_id": account["id"], "service": service_name})
                return self.json_response({"success": True, "job_id": job_id})

            if path == "/api/client/services/status" and method == "GET":
                require_account(account)
                service_name = query.get("service", [""])[0].strip()
                if service_name:
                    valid_services = ["web", "db", "filebrowser", "phpmyadmin", "cron", "sftp", "smtp-relay"]
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
                        raise ApiError(HTTPStatus.CONFLICT, "wordpress_already_installed")
                    
                    db_name = f"{account['username']}_wp_{website_id}"
                    db_user = f"{account['username']}_wp"
                    cur_db = conn.execute(
                        "INSERT INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
                        (account["id"], db_name, db_user, "active"),
                    )
                    database_id = cur_db.lastrowid
                    enqueue_agent_job(conn, "create_database", "database", database_id, {"name": db_name})
                    
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
                        "database_password": "dev-db-password-change-me",
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
                
                import secrets
                import hashlib
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
        with connect(CONFIG.db_path) as conn:
            if path == "/api/admin/dashboard" and method == "GET":
                return self.json_response(admin_dashboard(conn))
            if path == "/api/admin/users" and method == "GET":
                return self.json_response({"users": rows_to_dicts(conn.execute("SELECT id, email, full_name, status, created_at FROM users ORDER BY id").fetchall())})
            if path == "/api/admin/admins" and method == "GET":
                rows = conn.execute("SELECT id, email, full_name, role, status, created_at FROM admins ORDER BY id").fetchall()
                return self.json_response({"admins": rows_to_dicts(rows)})
            if path == "/api/admin/admins" and method == "POST":
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
            if path == "/api/admin/clients" and method == "GET":
                return self.json_response({"clients": admin_clients_payload(conn)})
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
                      frontend_frameworks, backend_frameworks, nodejs_versions, package_managers
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    ),
                )
                log_audit(conn, "admin", actor["id"], "create_plan", "plan", cur.lastrowid, metadata={"name": plan["name"]})
                created = conn.execute("SELECT * FROM plans WHERE id = ?", (cur.lastrowid,)).fetchone()
                return self.json_response({"plan": row_to_dict(created)}, HTTPStatus.CREATED)
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
                domain_id = conn.execute(
                    "INSERT INTO domains(account_id, name, kind, status, linked_website_id) VALUES (?, ?, ?, ?, ?)",
                    (account_id, domain, "managed", "active", website_id),
                ).lastrowid
                conn.execute(
                    "INSERT INTO dns_records(domain_id, type, name, value, ttl) VALUES (?, ?, ?, ?, ?)",
                    (domain_id, "A", "@", "127.0.0.1", 300),
                )
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
    containers = [f"mp-{username}-{service}" for service in ["web", "filebrowser", "phpmyadmin", "db", "cron", "sftp", "smtp-relay"]]
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
            "host": runtime.get("db_host"),
            "port": runtime.get("db_port"),
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
    }


def positive_int(value, error, minimum=1, maximum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, error)
    if number < minimum or (maximum is not None and number > maximum):
        raise ApiError(HTTPStatus.BAD_REQUEST, error)
    return number


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
    domain_id = conn.execute(
        """
        INSERT INTO domains(account_id, name, kind, status, linked_website_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (account_id, domain, "managed", "active", website_id),
    ).lastrowid
    conn.execute(
        "INSERT INTO dns_records(domain_id, type, name, value, ttl) VALUES (?, ?, ?, ?, ?)",
        (domain_id, "A", "@", "127.0.0.1", 300),
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


def sanitize_domain(value):
    domain = str(value or "").strip().lower()
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if not domain or len(domain) > 253 or any(ch not in allowed for ch in domain) or "." not in domain:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_domain")
    return domain


def delete_client_website(conn, account, website):
    website_id = website["id"]
    domain = website["domain"]
    conn.execute("DELETE FROM redirects WHERE website_id = ?", (website_id,))
    conn.execute("DELETE FROM script_installs WHERE website_id = ?", (website_id,))
    conn.execute("DELETE FROM wordpress_installs WHERE website_id = ?", (website_id,))
    conn.execute("UPDATE access_logs SET website_id = NULL WHERE website_id = ?", (website_id,))
    conn.execute("UPDATE ssl_certificates SET website_id = NULL, status = 'removed' WHERE website_id = ?", (website_id,))
    conn.execute("UPDATE domains SET linked_website_id = NULL WHERE linked_website_id = ?", (website_id,))
    conn.execute("DELETE FROM websites WHERE id = ?", (website_id,))
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
    if account_ids:
        database_ids = select_ids_for_accounts(conn, "databases", account_ids)
        if database_ids:
            conn.execute("DELETE FROM database_grants WHERE database_id IN ({})".format(sql_placeholders(database_ids)), database_ids)
        conn.execute("DELETE FROM database_users WHERE account_id IN ({})".format(sql_placeholders(account_ids)), account_ids)
        for table in ["domains", "websites", "databases", "mailboxes", "cron_jobs", "git_deployments", "account_stacks"]:
            conn.execute("DELETE FROM {} WHERE account_id IN ({})".format(table, sql_placeholders(account_ids)), account_ids)
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
            SELECT w.* FROM websites w
            JOIN hosting_accounts ha ON ha.id = w.account_id
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
    if CONFIG.is_development:
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

    client_httpd = ThreadingHTTPServer((CONFIG.host, CONFIG.client_port), MangoHandler)
    client_httpd.panel = "client"
    admin_httpd = ThreadingHTTPServer((CONFIG.host, CONFIG.admin_port), MangoHandler)
    admin_httpd.panel = "admin"
    admin_thread = threading.Thread(target=admin_httpd.serve_forever, name="mangopanel-admin", daemon=True)
    admin_thread.start()
    print(f"MangoPanel client panel running at http://{CONFIG.host}:{CONFIG.client_port}")
    print(f"MangoPanel admin panel running at  http://{CONFIG.host}:{CONFIG.admin_port}/admin")
    print(f"Status: http://{CONFIG.host}:{CONFIG.client_port}/status")
    try:
        client_httpd.serve_forever()
    finally:
        admin_httpd.shutdown()
        admin_thread.join(timeout=5)


if __name__ == "__main__":
    run()
