import json
import os
import time
import urllib.error
import urllib.request


CLIENT_BASE_URL = os.getenv("MP_CLIENT_BASE_URL", os.getenv("MP_BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
ADMIN_BASE_URL = os.getenv("MP_ADMIN_BASE_URL", "http://127.0.0.1:8001").rstrip("/")
PASSWORD = "ChangeMe-DevOnly-123!"
TOTP = "000000"


def request(base_url, method, path, body=None, token=None):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {path} failed: {exc.code} {exc.read().decode('utf-8')}") from exc


def request_raw(base_url, method, path, body=None, token=None, host=None, extra_headers=None):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if host:
        headers["Host"] = host
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.HTTPHandler, NoRedirectHandler)
    try:
        with opener.open(req, timeout=10) as response:
            return response.status, dict(response.headers), response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8")


def login(base_url, prefix, email):
    challenge = request(base_url, "POST", f"/api/{prefix}/auth/login", {"email": email, "password": PASSWORD})
    auth = request(
        base_url,
        "POST",
        f"/api/{prefix}/auth/totp/verify",
        {"challenge_token": challenge["challenge_token"], "code": TOTP},
    )
    return auth["access_token"]


def main():
    health = request(CLIENT_BASE_URL, "GET", "/health")
    assert health["status"] == "ok"
    admin_health = request(ADMIN_BASE_URL, "GET", "/health")
    assert admin_health["status"] == "ok"
    bootstrap = request(CLIENT_BASE_URL, "GET", "/api/public/bootstrap")
    assert bootstrap["admin_setup_required"] is False

    admin_token = login(ADMIN_BASE_URL, "admin", "admin@mango.test")
    client_token = login(CLIENT_BASE_URL, "client", "owner@example.mango.test")

    suffix = int(time.time())
    signup = request(
        CLIENT_BASE_URL,
        "POST",
        "/api/public/signup",
        {
            "full_name": "Smoke Signup",
            "email": f"smoke-{suffix}@example.mango.test",
            "password": PASSWORD,
        },
    )
    assert signup["totp_secret"], "expected TOTP secret for new customer"
    assert signup["hosting_account"]["username"].startswith("u")
    new_client_token = login(CLIENT_BASE_URL, "client", f"smoke-{suffix}@example.mango.test")
    new_home = request(CLIENT_BASE_URL, "GET", "/api/client/home", token=new_client_token)
    assert new_home["accounts"], "expected signup-created hosting account"

    home = request(CLIENT_BASE_URL, "GET", "/api/client/home", token=client_token)
    assert home["accounts"], "expected seeded account"
    assert home["websites"], "expected seeded website"
    website = home["websites"][0]

    feature_status = request(CLIENT_BASE_URL, "GET", "/api/client/feature-status", token=client_token)
    assert feature_status["features"]["dns-zone-editor"]["status"] == "functional"
    assert feature_status["features"]["ssl-tls"]["status"] == "functional"
    assert feature_status["features"]["email"]["status"] == "functional"

    domains = request(CLIENT_BASE_URL, "GET", "/api/client/domains", token=client_token)["domains"]
    dns_record = request(
        CLIENT_BASE_URL,
        "POST",
        "/api/client/dns-records",
        {"domain_id": domains[0]["id"], "type": "TXT", "name": f"_smoke_{suffix}", "value": "ok", "ttl": 300},
        token=client_token,
    )
    assert dns_record["job_id"], "expected DNS sync job"
    assert dns_record["dns_zones"], "expected DNS provider state"
    assert dns_record["dns_zones"][0]["provider"] == "local-dev-dns"
    assert dns_record["dns_zones"][0]["status"] == "published"

    issued_ssl = request(CLIENT_BASE_URL, "POST", "/api/client/ssl/issue", {"website_id": website["id"]}, token=client_token)
    assert issued_ssl["acme_order"]["provider"] == "local-dev-acme"
    assert issued_ssl["acme_order"]["status"] == "issued"
    request(
        CLIENT_BASE_URL,
        "POST",
        "/api/client/ssl/custom",
        {"website_id": website["id"], "crt": "-----BEGIN CERTIFICATE-----\nsmoke\n-----END CERTIFICATE-----", "key": "-----BEGIN PRIVATE KEY-----\nsmoke\n-----END PRIVATE KEY-----"},
        token=client_token,
    )
    request(CLIENT_BASE_URL, "GET", "/api/client/files/launch", token=client_token)
    pma_launch = request(CLIENT_BASE_URL, "GET", "/api/client/phpmyadmin/launch", token=client_token)
    pma_path = pma_launch["launch_url"].replace("http://pma-u000001.localhost", "")
    status, headers, _ = request_raw(
        CLIENT_BASE_URL,
        "GET",
        f"/api/public/tool-launch/phpmyadmin/auth/{pma_path.split('/auth/', 1)[1].strip('/')}",
        host="pma-u000001.localhost",
        extra_headers={"X-Forwarded-Host": "pma-u000001.localhost"},
    )
    assert status == 302
    assert "Set-Cookie" in headers
    mailbox = request(
        CLIENT_BASE_URL,
        "POST",
        "/api/client/mailboxes",
        {"email": f"smoke-mail-{suffix}@example.mango.test", "quota_mb": 1024, "password": PASSWORD, "confirm_password": PASSWORD},
        token=client_token,
    )
    mailbox_launch = request(CLIENT_BASE_URL, "GET", f"/api/client/mailboxes/{mailbox['mailbox_id']}/webmail/launch", token=client_token)
    assert "/webmail?launch=" in mailbox_launch["launch_url"]
    direct_login = mailbox["mailbox"]["webmail_login_url"]
    assert direct_login.endswith(f"/webmail/login/{mailbox['mailbox_id']}?email=smoke-mail-{suffix}%40example.mango.test")
    mail_routing = request(CLIENT_BASE_URL, "GET", "/api/client/mail-routing", token=client_token)
    assert mail_routing["mail_edge_routes"], "expected shared mail-edge routes"
    assert mail_routing["mail_edge_routes"][0]["provider"] == "shared-mail-edge"
    edge_status, _, edge_body = request_raw(CLIENT_BASE_URL, "GET", "/api/public/mail-edge/manifest", host="mail.mango.test")
    assert edge_status == 200, edge_body
    edge_manifest = json.loads(edge_body)
    assert edge_manifest["provider"] == "shared-mail-edge"
    bad_edge_status, _, _ = request_raw(CLIENT_BASE_URL, "GET", "/api/public/mail-edge/manifest", host="files-u000001.localhost")
    assert bad_edge_status == 404, "mail-edge manifest must be host-gated"
    request(CLIENT_BASE_URL, "POST", "/api/client/backups", {}, token=client_token)
    request(CLIENT_BASE_URL, "POST", "/api/client/restores", {"kind": "latest"}, token=client_token)
    pg_db = request(CLIENT_BASE_URL, "POST", "/api/client/pg-databases", {"name": f"u000001_smoke_{suffix}"}, token=client_token)
    pg_user = request(CLIENT_BASE_URL, "POST", "/api/client/pg-databases/users", {"username": f"u000001_smokeu_{suffix}", "password": PASSWORD}, token=client_token)
    request(
        CLIENT_BASE_URL,
        "POST",
        "/api/client/pg-databases/users/grants",
        {"database_id": pg_db["pg_database_id"], "user_id": pg_user["pg_user_id"], "privileges": "READ_WRITE"},
        token=client_token,
    )
    request(CLIENT_BASE_URL, "POST", "/api/client/hotlink-protection", {"enabled": True, "allowed_domains": "example.mango.test"}, token=client_token)
    templates = request(CLIENT_BASE_URL, "GET", "/api/client/site-builder/templates", token=client_token)
    assert templates["templates"], "expected site builder templates"
    request(CLIENT_BASE_URL, "POST", "/api/client/site-builder/install", {"website_id": website["id"], "template_id": "portfolio"}, token=client_token)
    request(CLIENT_BASE_URL, "POST", "/api/client/images/optimize", {"website_id": website["id"]}, token=client_token)
    host_octet = 10 + (suffix % 200)
    remote_host = request(CLIENT_BASE_URL, "POST", "/api/client/remote-mysql", {"host_ip": f"203.0.113.{host_octet}"}, token=client_token)
    assert remote_host["job_id"], "expected remote MySQL sync job"
    sync_jobs = request(CLIENT_BASE_URL, "GET", "/api/client/sync-jobs", token=client_token)
    assert any(job["type"] == "sync_dns_record" for job in sync_jobs["jobs"]), "expected DNS job in client sync history"
    assert any(job["type"] == "sync_pg_databases" for job in sync_jobs["jobs"]), "expected PostgreSQL job in client sync history"

    dashboard = request(ADMIN_BASE_URL, "GET", "/api/admin/dashboard", token=admin_token)
    assert dashboard["counts"]["hosting_accounts"] >= 1
    assert dashboard["counts"]["account_stacks"] >= 1
    assert dashboard["status"]["overall_status"] in {"operational", "degraded_performance", "maintenance", "major_outage"}
    stacks = request(ADMIN_BASE_URL, "GET", "/api/admin/account-stacks", token=admin_token)
    assert stacks["account_stacks"], "expected generated account stack"
    assert stacks["account_stacks"][0]["compose_path"].endswith("docker-compose.yml")
    events = request(ADMIN_BASE_URL, "GET", "/api/admin/job-events", token=admin_token)
    assert events["job_events"], "expected agent job events"
    admin_create = request(
        ADMIN_BASE_URL,
        "POST",
        "/api/admin/admins",
        {
            "full_name": "Smoke Admin",
            "email": f"admin-smoke-{suffix}@mango.test",
            "role": "support_admin",
            "password": PASSWORD,
        },
        token=admin_token,
    )
    assert admin_create["totp_secret"], "expected TOTP secret for created admin"

    incident = request(
        ADMIN_BASE_URL,
        "POST",
        "/api/admin/status/incidents",
        {"title": "Smoke test incident", "severity": "minor", "state": "investigating", "message": "Created by dev smoke."},
        token=admin_token,
    )
    request(
        ADMIN_BASE_URL,
        "POST",
        f"/api/admin/status/incidents/{incident['incident_id']}/updates",
        {"state": "resolved", "message": "Smoke test incident resolved."},
        token=admin_token,
    )

    status = request(CLIENT_BASE_URL, "GET", "/api/public/status")
    assert status["components"], "expected status components"
    print("dev-smoke passed")


if __name__ == "__main__":
    main()
