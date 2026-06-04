import json
import secrets
import shutil
import time
import urllib.parse
import urllib.request
from pathlib import Path


SNAPPYMAIL_DEFAULT_SSO_PLUGIN = "login-external-sso"
SNAPPYMAIL_APP_VERSION = "2.38.2"
SNAPPYMAIL_IMAGE = "djmaze/snappymail:latest@sha256:5e3d990438809a8a49f8ac5758db03e858e6e9fc0e369e1f9e474f7664079905"
SNAPPYMAIL_THEME_NAME = "MangoPanel"
SNAPPYMAIL_THEME_SOURCE = Path(__file__).resolve().parent.parent / "templates" / "snappymail-theme" / SNAPPYMAIL_THEME_NAME


def _default_domain_config(mail_host, runtime=None):
    runtime = runtime or {}
    imap_tls_port = int(runtime.get("mail_backend_imap_port") or 993)
    smtp_tls_port = int(runtime.get("mail_backend_smtp_port") or 465)
    sieve_port = int(runtime.get("mail_backend_sieve_port") or 4190)
    return {
        "IMAP": {
            "host": str(mail_host or ""),
            "port": imap_tls_port,
            "type": 1,
            "timeout": 300,
            "shortLogin": False,
            "lowerLogin": True,
            "sasl": [
                "SCRAM-SHA3-512",
                "SCRAM-SHA-512",
                "SCRAM-SHA-256",
                "SCRAM-SHA-1",
                "PLAIN",
                "LOGIN",
            ],
            "ssl": {
                "verify_peer": False,
                "verify_peer_name": False,
                "allow_self_signed": True,
                "SNI_enabled": True,
                "disable_compression": True,
                "security_level": 1,
            },
            "disabled_capabilities": ["METADATA", "OBJECTID", "PREVIEW", "STATUS=SIZE"],
            "use_expunge_all_on_delete": False,
            "fast_simple_search": True,
            "force_select": False,
            "message_all_headers": False,
            "message_list_limit": 10000,
            "search_filter": "",
        },
        "SMTP": {
            "host": str(mail_host or ""),
            "port": smtp_tls_port,
            "type": 1,
            "timeout": 60,
            "shortLogin": False,
            "lowerLogin": True,
            "sasl": [
                "SCRAM-SHA3-512",
                "SCRAM-SHA-512",
                "SCRAM-SHA-256",
                "SCRAM-SHA-1",
                "PLAIN",
                "LOGIN",
            ],
            "ssl": {
                "verify_peer": False,
                "verify_peer_name": False,
                "allow_self_signed": True,
                "SNI_enabled": True,
                "disable_compression": True,
                "security_level": 1,
            },
            "useAuth": True,
            "setSender": False,
            "usePhpMail": False,
        },
        "Sieve": {
            "host": str(mail_host or ""),
            "port": sieve_port,
            "type": 1,
            "timeout": 10,
            "shortLogin": False,
            "lowerLogin": True,
            "sasl": [
                "SCRAM-SHA3-512",
                "SCRAM-SHA-512",
                "SCRAM-SHA-256",
                "SCRAM-SHA-1",
                "PLAIN",
                "LOGIN",
            ],
            "ssl": {
                "verify_peer": False,
                "verify_peer_name": False,
                "allow_self_signed": True,
                "SNI_enabled": True,
                "disable_compression": True,
                "security_level": 1,
            },
            "enabled": True,
        },
        "whiteList": "",
    }


def _render_application_ini(mail_host):
    theme_icon_url = f"/snappymail/v/{SNAPPYMAIL_APP_VERSION}/themes/{SNAPPYMAIL_THEME_NAME}/images/wind.png"
    return (
        "; SnappyMail configuration file\n"
        "; Managed by MangoPanel\n\n"
        "[webmail]\n"
        "title = \"Server Mango Windz Webmail\"\n"
        "loading_description = \"Server Mango Windz\"\n"
        f"favicon_url = \"{theme_icon_url}\"\n"
        "app_path = \"\"\n"
        f"theme = \"{SNAPPYMAIL_THEME_NAME}\"\n"
        "allow_themes = On\n"
        "allow_user_background = Off\n"
        "language = \"en\"\n"
        "allow_languages_on_settings = On\n"
        "allow_additional_accounts = On\n"
        "allow_additional_identities = On\n"
        "popup_identity = On\n"
        "messages_per_page = 20\n"
        "message_read_delay = 5\n"
        "min_refresh_interval = 5\n"
        "attachment_size_limit = 25\n"
        "compress_output = Off\n\n"
        "[interface]\n"
        "show_attachment_thumbnail = On\n\n"
        "[security]\n"
        "custom_server_signature = \"SnappyMail\"\n"
        "x_xss_protection_header = \"1; mode=block\"\n"
        "gnupg = On\n"
        "openpgp = On\n"
        "auto_verify_signatures = Off\n"
        "allow_admin_panel = Off\n"
        "admin_password = \"\"\n"
        "admin_totp = \"\"\n"
        "insecure_cryptkey = Off\n"
        "force_https = Off\n"
        "hide_x_mailer_header = On\n"
        "max_sys_getloadavg = 0\n"
        "content_security_policy = \"\"\n"
        "csp_report = Off\n"
        "encrypt_cipher = \"aes-256-cbc-hmac-sha1\"\n"
        "cookie_samesite = \"Lax\"\n"
        "secfetch_allow = \"mode=navigate,dest=document,site=cross-site,user=true;mode=navigate,dest=document,site=same-site,user=true\"\n\n"
        "[admin_panel]\n"
        "host = \"\"\n"
        "key = \"admin\"\n"
        "allow_update = Off\n"
        "language = \"en\"\n\n"
        "[ssl]\n"
        "verify_certificate = Off\n"
        "allow_self_signed = On\n"
        "security_level = 1\n"
        "cafile = \"\"\n"
        "capath = \"\"\n"
        "local_cert = \"\"\n"
        "disable_compression = On\n\n"
        "[capa]\n"
        "dangerous_actions = On\n"
        "attachments_actions = On\n\n"
        "[login]\n"
        "default_domain = \"\"\n"
        "allow_languages_on_login = On\n"
        "determine_user_language = On\n"
        "determine_user_domain = Off\n"
        "sign_me_auto = \"DefaultOff\"\n"
        "fault_delay = 5\n\n"
        "[plugins]\n"
        "enable = On\n"
        f"enabled_list = \"{SNAPPYMAIL_DEFAULT_SSO_PLUGIN}\"\n\n"
        "[defaults]\n"
        "view_editor_type = \"Html\"\n"
        "view_layout = 1\n"
        "view_use_checkboxes = On\n"
        "view_show_next_message = On\n"
        "autologout = 30\n"
        "view_html = On\n"
        "show_images = Off\n"
        "view_images = \"ask\"\n"
        "contacts_autosave = On\n"
        "mail_list_grouped = Off\n"
        "mail_use_threads = Off\n"
        "allow_draft_autosave = On\n"
        "mail_reply_same_folder = Off\n"
        "msg_default_action = 1\n"
        "collapse_blockquotes = On\n"
        "allow_spellcheck = Off\n\n"
        "[logs]\n"
        "enable = Off\n"
        "path = \"\"\n"
        "level = 4\n"
        "hide_passwords = On\n"
        "time_zone = \"UTC\"\n"
        "filename = \"log-{date:Y-m-d}.txt\"\n"
        "auth_logging = Off\n"
        "auth_logging_filename = \"fail2ban/auth-{date:Y-m-d}.txt\"\n"
        "auth_logging_format = \"[{date:Y-m-d H:i:s}] Auth failed: ip={request:ip} user={imap:login} host={imap:host} port={imap:port}\"\n"
        "auth_syslog = Off\n"
        "json_response_write_limit = 300\n\n"
        "[debug]\n"
        "enable = Off\n"
        "javascript = Off\n"
        "css = Off\n\n"
        "[cache]\n"
        "enable = On\n"
        "path = \"\"\n"
        "index = \"v1\"\n"
        "fast_cache_index = \"v1\"\n"
        "http = On\n"
        "http_expires = 3600\n"
        "server_uids = On\n"
        "system_data = On\n\n"
        "[imap]\n"
        "use_force_selection = Off\n"
        "use_expunge_all_on_delete = Off\n"
        "message_list_fast_simple_search = On\n"
        "message_list_permanent_filter = \"\"\n"
        "message_all_headers = Off\n"
        "show_login_alert = On\n"
        "fetch_new_messages = On\n\n"
        "[labs]\n"
        "allow_message_append = Off\n"
        "smtp_show_server_errors = Off\n"
        "mail_func_clear_headers = On\n"
        "mail_func_additional_parameters = Off\n"
        "folders_spec_limit = 50\n"
        "curl_proxy = \"\"\n"
        "curl_proxy_auth = \"\"\n"
        "custom_login_link = \"\"\n"
        "custom_logout_link = \"\"\n"
        "http_client_ip_check_proxy = Off\n"
        "use_local_proxy_for_external_images = On\n"
        "image_exif_auto_rotate = Off\n"
        "cookie_default_path = \"\"\n"
        "cookie_default_secure = Off\n"
        "replace_env_in_configuration = \"\"\n"
        "boundary_prefix = \"\"\n"
        "dev_email = \"\"\n"
        "dev_password = \"\"\n\n"
        "[version]\n"
        "current = \"0.0.0\"\n"
        "saved = \"\"\n"
    )


def render_snappymail_domain_json(domain_name, runtime=None):
    runtime = runtime or {}
    config = _default_domain_config(runtime.get("mail_backend_host") or "mailserver", runtime)
    return json.dumps(config, indent=2) + "\n"


def ensure_snappymail_layout(base_path, runtime, domain_names, *, sso_key=None):
    base = Path(base_path)
    data_root = base / "_data_" / "_default_"
    configs_dir = data_root / "configs"
    domains_dir = data_root / "domains"
    plugins_dir = data_root / "plugins"
    theme_dir = base / "themes" / SNAPPYMAIL_THEME_NAME
    for path in (configs_dir, domains_dir, plugins_dir):
        path.mkdir(parents=True, exist_ok=True)
    theme_dir.mkdir(parents=True, exist_ok=True)
    (data_root / "storage").mkdir(parents=True, exist_ok=True)
    (data_root / "cache").mkdir(parents=True, exist_ok=True)
    (domains_dir / "disabled").write_text("", encoding="utf-8")

    sso_key = sso_key or secrets.token_urlsafe(32)
    state = {
        "provider": "snappymail",
        "backend_url": runtime.get("mail_edge_url") or runtime.get("mail_webmail_backend_url", ""),
        "sso_key": sso_key,
        "mail_host": runtime.get("mail_edge_host") or runtime.get("mail_host", ""),
        "mail_backend_host": runtime.get("mail_backend_host") or "mailserver",
        "mail_webmail_url": runtime.get("mail_edge_webmail_url") or runtime.get("mail_webmail_url", ""),
        "mail_webmail_login_url": runtime.get("mail_edge_login_url") or runtime.get("mail_webmail_login_url", ""),
    }
    (base / "snappymail.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    (configs_dir / "application.ini").write_text(_render_application_ini(runtime.get("mail_edge_host") or runtime.get("mail_host", "")), encoding="utf-8")
    (configs_dir / f"plugin-{SNAPPYMAIL_DEFAULT_SSO_PLUGIN}.json").write_text(
        json.dumps({"plugin": {"key": sso_key}}, indent=2) + "\n",
        encoding="utf-8",
    )

    theme_source = SNAPPYMAIL_THEME_SOURCE
    theme_styles_source = theme_source / "styles.css"
    theme_styles_target = theme_dir / "styles.css"
    if theme_styles_source.exists():
        shutil.copy2(theme_styles_source, theme_styles_target)
    elif not theme_styles_target.exists():
        theme_styles_target.write_text(
            ":root{color-scheme:dark;--main-color:#f7f7f9;--main-bg-color:#101416;--main-bg-image:linear-gradient(135deg,#101416 0%,#151d30 50%,#1e1b4b 100%);}\n",
            encoding="utf-8",
        )
    for asset_dir_name in ("images", "fonts"):
        asset_source = theme_source / asset_dir_name
        if asset_source.exists():
            shutil.copytree(asset_source, theme_dir / asset_dir_name, dirs_exist_ok=True)

    default_domain = _default_domain_config(runtime.get("mail_backend_host") or "mailserver", runtime)
    (domains_dir / "default.json").write_text(json.dumps(default_domain, indent=2) + "\n", encoding="utf-8")
    for domain_name in sorted({str(name).lower() for name in domain_names if name}):
        (domains_dir / f"{domain_name}.json").write_text(json.dumps(default_domain, indent=2) + "\n", encoding="utf-8")
    return state


def load_snappymail_state(base_path):
    path = Path(base_path) / "snappymail.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _extract_cookie_value(headers, cookie_name):
    cookie_name = str(cookie_name or "").strip()
    if not cookie_name:
        return ""
    for header in headers or []:
        value = str(header or "").strip()
        if value.startswith(f"{cookie_name}="):
            return value.split(";", 1)[0]
    return ""


def request_login_session(backend_url, *, email, password, timeout=20, retries=3):
    if not backend_url:
        raise RuntimeError("snappymail_backend_missing")
    base_url = str(backend_url).rstrip("/")
    last_error = None
    for attempt in range(max(1, int(retries or 1))):
        try:
            appdata_request = urllib.request.Request(
                f"{base_url}/?/AppData/0/{secrets.token_urlsafe(12)}/",
                headers={"Accept": "application/json"},
                method="GET",
            )
            with urllib.request.urlopen(appdata_request, timeout=timeout) as response:
                appdata_payload = response.read().decode("utf-8")
                appdata_cookies = response.headers.get_all("Set-Cookie") or []
            try:
                appdata = json.loads(appdata_payload)
            except json.JSONDecodeError as exc:
                raise RuntimeError("snappymail_boot_invalid_response") from exc
            csrf_token = ((appdata.get("System") or {}).get("token") or "").strip()
            if not csrf_token:
                raise RuntimeError("snappymail_csrf_missing")

            connection_cookie = _extract_cookie_value(appdata_cookies, "smtoken")
            if not connection_cookie:
                raise RuntimeError("snappymail_cookie_missing")

            body = urllib.parse.urlencode(
                {
                    "Action": "Login",
                    "Email": email or "",
                    "Password": password or "",
                    "language": "",
                    "signMe": "1",
                    "XToken": csrf_token,
                }
            ).encode("utf-8")
            login_request = urllib.request.Request(
                f"{base_url}/?/Json/-/0/",
                data=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Cookie": connection_cookie,
                    "X-SM-Token": csrf_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(login_request, timeout=timeout) as response:
                payload = response.read().decode("utf-8")
                login_cookies = response.headers.get_all("Set-Cookie") or []
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise RuntimeError("snappymail_login_invalid_response") from exc
            if not parsed.get("Result"):
                raise RuntimeError(parsed.get("messageAdditional") or parsed.get("message") or "snappymail_login_failed")
            return {
                "result": parsed.get("Result"),
                "csrf_token": csrf_token,
                "cookies": appdata_cookies + login_cookies,
            }
        except Exception as exc:
            last_error = exc
            if attempt + 1 < max(1, int(retries or 1)):
                time.sleep(0.4 * (attempt + 1))
                continue
            raise
    if last_error:
        raise last_error
    raise RuntimeError("snappymail_login_failed")
