"""Scoped, conditional changes to Caddy's configuration.

The Docker proxy owns listeners, TLS and website routing. IP-rule updates may
only replace an existing routes array, using Caddy's ETag to reject stale reads.
"""

import ipaddress
import json
import re
import subprocess
from urllib.parse import quote


class CaddyConfigError(Exception):
    pass


def _request(method, path, body=None, etag=None):
    if method != "GET" and (
        method != "PATCH" or not re.fullmatch(r"/config/apps/http/servers/[^/]+/routes", path)
        or not etag or not isinstance(body, list) or not body
    ):
        raise CaddyConfigError("unsafe_caddy_config_request")
    command = [
        "docker", "exec", "-i", "mangopanel-caddy", "curl",
        "--silent", "--show-error", "--max-time", "15", "--include",
        "--http1.1", "--header", "Expect:", "--request", method,
    ]
    if etag:
        command.extend(["--header", f"If-Match: {etag}"])
    if body is not None:
        command.extend(["--header", "Content-Type: application/json", "--data-binary", "@-"])
    command.append(f"http://127.0.0.1:2019{path}")
    result = subprocess.run(
        command, input=json.dumps(body).encode() if body is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=20,
    )
    headers, separator, payload = result.stdout.partition(b"\r\n\r\n")
    if not separator:
        raise CaddyConfigError("invalid_caddy_config_response")
    try:
        status = int(headers.splitlines()[0].split()[1])
    except (IndexError, ValueError) as exc:
        raise CaddyConfigError("invalid_caddy_config_response") from exc
    response_etag = next((
        line.split(b":", 1)[1].strip().decode()
        for line in headers.splitlines()[1:] if line.lower().startswith(b"etag:")
    ), None)
    return status, response_etag, payload


def _updated_routes(routes, account_id, domains, ranges, exact_ips, cloudflare_ranges, server_name):
    prefix = f"mangopanel-ip-block-{int(account_id)}-"
    updated = [route for route in routes if not str(route.get("@id", "")).startswith(prefix)]
    # Preserve unrelated account rules and every website route, in order.
    insert_at = next((
        index for index, route in enumerate(updated)
        if any(host in domains for matcher in route.get("match", []) for host in matcher.get("host", []))
    ), len(updated))
    handlers = [{"handler": "static_response", "status_code": 403, "body": "Forbidden\n"}]
    new_rules = []
    if ranges:
        new_rules.append({
            "@id": f"{prefix}{server_name}-direct",
            "match": [{"host": domains, "remote_ip": {"ranges": ranges}}],
            "handle": handlers, "terminal": True,
        })
    if exact_ips:
        new_rules.append({
            "@id": f"{prefix}{server_name}-cloudflare",
            "match": [{"host": domains, "remote_ip": {"ranges": cloudflare_ranges},
                       "header": {"CF-Connecting-IP": exact_ips}}],
            "handle": handlers, "terminal": True,
        })
    updated[insert_at:insert_at] = new_rules
    return updated


def sync_account_ip_rules(account_id, domains, blocked_ips, cloudflare_ranges):
    ranges, exact_ips = [], []
    for value in blocked_ips:
        try:
            ranges.append(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            continue
        try:
            exact_ips.append(str(ipaddress.ip_address(value)))
        except ValueError:
            pass

    # Each retry rereads all servers. A concurrent label reload or another IP
    # sync must never be overwritten by a stale whole-configuration snapshot.
    for attempt in range(3):
        try:
            status, _, payload = _request("GET", "/config/apps/http/servers")
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt == 0:
                # Development installations may not have a Caddy container.
                return
            raise CaddyConfigError("caddy_ip_rule_sync_deferred: proxy unavailable")
        if status == 404:
            continue
        if status != 200:
            raise CaddyConfigError(f"caddy_ip_rule_sync_failed: read HTTP {status}")
        try:
            servers = json.loads(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CaddyConfigError("invalid_caddy_config_response") from exc
        if not isinstance(servers, dict) or not servers or not any(
            isinstance(server, dict) and server.get("listen") and server.get("routes")
            for server in servers.values()
        ):
            continue

        retry = False
        for name, server in servers.items():
            if not isinstance(server, dict) or not server.get("listen") or not server.get("routes"):
                continue
            path = f"/config/apps/http/servers/{quote(name, safe='')}/routes"
            try:
                status, etag, payload = _request("GET", path)
                if status == 404:
                    retry = True
                    break
                if status != 200 or not etag:
                    raise CaddyConfigError("caddy_ip_rule_sync_deferred: routes or ETag unavailable")
                routes = json.loads(payload)
                if not isinstance(routes, list) or not routes or not all(isinstance(route, dict) for route in routes):
                    raise CaddyConfigError("caddy_ip_rule_sync_deferred: invalid routes")
                updated = _updated_routes(routes, account_id, domains, ranges, exact_ips, cloudflare_ranges, name)
                if updated == routes:
                    continue
                status, _, _ = _request("PATCH", path, updated, etag)
                if status in (404, 412):
                    retry = True
                    break
                if status != 200:
                    raise CaddyConfigError(f"caddy_ip_rule_sync_failed: update HTTP {status}")
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as exc:
                raise CaddyConfigError("caddy_ip_rule_sync_failed: route update failed") from exc
        if not retry:
            return
    raise CaddyConfigError("caddy_ip_rule_sync_deferred: proxy starting or configuration changed")
