import json
import os
import subprocess
import time
import urllib.error
import urllib.request


CLIENT_BASE_URL = os.getenv("MP_CLIENT_BASE_URL", os.getenv("MP_BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
PASSWORD = "ChangeMe-DevOnly-123!"
TOTP = "000000"


def request(method, path, body=None, token=None):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(CLIENT_BASE_URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def login(prefix, email):
    challenge = request("POST", f"/api/{prefix}/auth/login", {"email": email, "password": PASSWORD})
    auth = request(
        "POST",
        f"/api/{prefix}/auth/totp/verify",
        {"challenge_token": challenge["challenge_token"], "code": TOTP},
    )
    return auth["access_token"]


def wait_http(url, contains=None, timeout=180):
    last_error = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                body = response.read()
            if contains is None or contains in body:
                return body
            last_error = f"{url} did not contain {contains!r}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(3)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def docker_exec(args):
    result = subprocess.run(["docker", "exec", *args], capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def main():
    client_token = login("client", "owner@example.mango.test")
    home = request("GET", "/api/client/home", token=client_token)
    account = home["accounts"][0]
    runtime = account["runtime"]
    assert runtime["web_url"], "account stack has no web URL"

    wait_http(runtime["web_url"], b"MangoPanel dev site")
    wait_http(runtime["filebrowser_url"], b"File Browser")
    wait_http(runtime["phpmyadmin_url"], b"phpMyAdmin")
    wait_http(runtime["mailpit_url"], b"Mailpit")

    ping = docker_exec(
        [
            f"mp-{account['username']}-db",
            "mariadb-admin",
            "ping",
            "-h",
            "127.0.0.1",
            "-u",
            "root",
            f"-p{runtime['db_root_password']}",
        ]
    )
    assert "mysqld is alive" in ping

    print("dev-hosting-smoke passed")
    print(f"Website: {runtime['web_url']}")
    print(f"File manager: {runtime['filebrowser_url']}")
    print(f"phpMyAdmin: {runtime['phpmyadmin_url']}")
    print(f"Mailpit: {runtime['mailpit_url']}")
    print(f"Database: {runtime['db_host']}:{runtime['db_port']}")
    print(f"SFTP: {runtime['sftp_host']}:{runtime['sftp_port']}")


if __name__ == "__main__":
    main()
