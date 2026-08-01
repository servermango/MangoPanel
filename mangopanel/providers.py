import time
import logging
from dataclasses import asdict, dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen
import json


DNS_PROVIDER_LOCAL = "local-dev-dns"
DNS_PROVIDER_LOCAL_POWERDNS = "local_powerdns"
DNS_PROVIDER_CLOUDFLARE = "cloudflare"
ACME_PROVIDER_LOCAL = "local-dev-acme"
MAIL_EDGE_PROVIDER_SHARED = "shared-mail-edge"


@dataclass
class DNSRecordIntent:
    name: str
    type: str
    value: str
    ttl: int = 300
    priority: int | None = None

    def payload(self):
        data = asdict(self)
        if data["priority"] is None:
            data.pop("priority")
        data["type"] = str(data["type"]).upper()
        return data


@dataclass
class DNSZoneIntent:
    account_id: int
    domain_id: int
    zone_name: str
    records: list[DNSRecordIntent] = field(default_factory=list)

    def payload(self):
        return {
            "account_id": self.account_id,
            "domain_id": self.domain_id,
            "zone_name": self.zone_name,
            "records": [record.payload() for record in self.records],
        }


@dataclass
class ACMECertificateIntent:
    account_id: int
    domain: str
    website_id: int | None = None
    domain_id: int | None = None
    challenge_type: str = "http-01"

    def payload(self):
        return asdict(self)


@dataclass
class MailboxRouteIntent:
    mailbox_id: int
    email: str
    storage_path: str
    quota_mb: int
    status: str = "active"

    def payload(self):
        return asdict(self)


@dataclass
class MailDomainRouteIntent:
    account_id: int
    mail_domain_id: int
    domain: str
    edge_host: str
    mailboxes: list[MailboxRouteIntent] = field(default_factory=list)

    def payload(self):
        return {
            "account_id": self.account_id,
            "mail_domain_id": self.mail_domain_id,
            "domain": self.domain,
            "edge_host": self.edge_host,
            "mailboxes": [mailbox.payload() for mailbox in self.mailboxes],
        }


class DNSProvider:
    provider_name = ""

    def publish_zone(self, zone_intent):
        raise NotImplementedError

    def inspect_zone(self, zone_name):
        raise NotImplementedError

    def delete_zone(self, zone_name):
        raise NotImplementedError


class ACMEProvider:
    provider_name = ""

    def request_certificate(self, certificate_intent):
        raise NotImplementedError

    def inspect_order(self, order_id):
        raise NotImplementedError


class MailEdgeProvider:
    provider_name = ""

    def publish_routes(self, route_intents):
        raise NotImplementedError

    def build_manifest(self, route_intents):
        return {
            "provider": self.provider_name,
            "domains": [route.payload() for route in route_intents],
        }


class LocalDNSProvider(DNSProvider):
    provider_name = DNS_PROVIDER_LOCAL

    def publish_zone(self, zone_intent, artifact_path=None, nameservers=None, serial=None):
        nameservers = nameservers or ["ns1.local.mango.test", "ns2.local.mango.test"]
        payload = zone_intent.payload()
        return {
            "provider": self.provider_name,
            "status": "published",
            "zone_name": payload["zone_name"],
            "serial": int(serial or int(time.time())),
            "nameservers": nameservers,
            "record_count": len(payload["records"]),
            "records": payload["records"],
            "artifact_path": artifact_path or "",
            "published_at": int(time.time()),
        }

    def inspect_zone(self, zone_name):
        return {
            "provider": self.provider_name,
            "zone_name": zone_name,
            "status": "available",
        }

    def delete_zone(self, zone_name):
        return {
            "provider": self.provider_name,
            "zone_name": zone_name,
            "status": "deleted",
            "deleted_at": int(time.time()),
        }

    def validate(self, *args, **kwargs):
        return {
            "provider": self.provider_name,
            "status": "configured",
            "message": "Local DNS adapter is available.",
        }


class DNSProviderError(Exception):
    pass


def _json_request(method, url, headers=None, payload=None, timeout=10):
    data = None
    request_headers = {"Accept": "application/json", **(headers or {})}
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise DNSProviderError(f"{method} {url} failed with HTTP {exc.code}: {raw[:500]}") from exc
    except URLError as exc:
        raise DNSProviderError(f"{method} {url} failed: {exc.reason}") from exc


def _zone_fqdn(zone_name):
    return str(zone_name or "").strip().rstrip(".").lower() + "."


def _record_fqdn(record_name, zone_name):
    name = str(record_name or "@").strip().rstrip(".")
    zone = str(zone_name or "").strip().rstrip(".")
    if name in {"", "@"}:
        return zone + "."
    if name.lower().endswith("." + zone.lower()):
        return name + "."
    return f"{name}.{zone}."


def _relative_name(full_name, zone_name):
    full = str(full_name or "").strip().rstrip(".").lower()
    zone = str(zone_name or "").strip().rstrip(".").lower()
    if full == zone:
        return "@"
    suffix = "." + zone
    if full.endswith(suffix):
        return full[: -len(suffix)]
    return full


def _txt_content(value):
    text = str(value or "")
    if text.startswith('"') and text.endswith('"'):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _pdns_content(record):
    record_type = str(record["type"]).upper()
    value = str(record["value"])
    if record_type == "MX":
        priority = record.get("priority")
        return f"{0 if priority is None else int(priority)} {value.rstrip('.') + '.'}"
    if record_type in {"CNAME", "NS"}:
        return value.rstrip(".") + "."
    if record_type == "SRV":
        priority = record.get("priority")
        return f"{0 if priority is None else int(priority)} {value}"
    if record_type == "TXT":
        return _txt_content(value)
    return value


def _group_records(records):
    grouped = {}
    for record in records:
        payload = record.payload() if hasattr(record, "payload") else dict(record)
        key = (payload["name"], str(payload["type"]).upper(), int(payload.get("ttl", 300)))
        grouped.setdefault(key, []).append(payload)
    return grouped


class PowerDNSProvider(DNSProvider):
    provider_name = DNS_PROVIDER_LOCAL_POWERDNS

    def __init__(self, api_url, api_key, *, server_id="localhost", nameservers=None, timeout=10):
        self.api_url = str(api_url or "").rstrip("/")
        self.api_key = api_key
        self.server_id = server_id or "localhost"
        self.nameservers = nameservers or ["ns1.mango.test", "ns2.mango.test"]
        self.timeout = timeout

    def configured(self):
        return bool(self.api_url and self.api_key)

    def _headers(self):
        return {"X-API-Key": self.api_key}

    def _url(self, path, query=None):
        url = f"{self.api_url}{path}"
        if query:
            url += "?" + urlencode(query)
        return url

    def _zone_path(self, zone_name):
        return f"/servers/{quote(self.server_id, safe='')}/zones/{quote(_zone_fqdn(zone_name), safe='')}"

    def _get_zone(self, zone_name, include_rrsets=True):
        path = self._zone_path(zone_name)
        _, payload = _json_request("GET", self._url(path), self._headers(), timeout=self.timeout)
        return payload

    def get_zone(self, zone_name):
        zone = _zone_fqdn(zone_name)
        try:
            _, matches = _json_request(
                "GET",
                self._url(f"/servers/{quote(self.server_id, safe='')}/zones", {"zone": zone, "dnssec": "false"}),
                self._headers(),
                timeout=self.timeout,
            )
            if matches:
                return matches[0]
        except Exception:
            pass
        return None

    def ensure_zone(self, zone_name):
        zone = _zone_fqdn(zone_name)
        _, matches = _json_request(
            "GET",
            self._url(f"/servers/{quote(self.server_id, safe='')}/zones", {"zone": zone, "dnssec": "false"}),
            self._headers(),
            timeout=self.timeout,
        )
        if matches:
            return matches[0]
        payload = {
            "name": zone,
            "kind": "Native",
            "nameservers": [ns.rstrip(".") + "." for ns in self.nameservers],
        }
        _, created = _json_request(
            "POST",
            self._url(f"/servers/{quote(self.server_id, safe='')}/zones"),
            self._headers(),
            payload,
            timeout=self.timeout,
        )
        return created

    def publish_zone(self, zone_intent, previous_state=None):
        if not self.configured():
            raise DNSProviderError("powerdns_not_configured")
        payload = zone_intent.payload()
        zone_name = payload["zone_name"]
        self.ensure_zone(zone_name)
        current = self._get_zone(zone_name)
        desired_rrsets = []
        desired_keys = set()

        ns_records = [
            {"name": "@", "type": "NS", "value": ns.rstrip(".") + ".", "ttl": 300, "priority": None}
            for ns in self.nameservers
        ]
        grouped = _group_records([*ns_records, *payload["records"]])
        for (name, record_type, ttl), records in grouped.items():
            rrset_name = _record_fqdn(name, zone_name)
            desired_keys.add((rrset_name.lower(), record_type))
            desired_rrsets.append(
                {
                    "name": rrset_name,
                    "type": record_type,
                    "ttl": ttl,
                    "changetype": "REPLACE",
                    "records": [{"content": _pdns_content(record), "disabled": False} for record in records],
                }
            )

        for rrset in current.get("rrsets", []):
            record_type = str(rrset.get("type", "")).upper()
            key = (str(rrset.get("name", "")).lower(), record_type)
            if record_type != "SOA" and record_type in {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"} and key not in desired_keys:
                desired_rrsets.append({"name": rrset["name"], "type": record_type, "changetype": "DELETE", "records": []})

        _json_request(
            "PATCH",
            self._url(self._zone_path(zone_name)),
            self._headers(),
            {"rrsets": desired_rrsets},
            timeout=self.timeout,
        )
        updated = self._get_zone(zone_name)
        return {
            "provider": self.provider_name,
            "status": "published",
            "zone_name": zone_name,
            "provider_zone_id": updated.get("id") or _zone_fqdn(zone_name),
            "serial": updated.get("serial") or updated.get("edited_serial") or int(time.time()),
            "nameservers": [ns.rstrip(".") for ns in self.nameservers],
            "record_count": len(payload["records"]),
            "rrset_count": len(desired_rrsets),
            "records": payload["records"],
            "published_at": int(time.time()),
        }

    def inspect_zone(self, zone_name):
        zone = self._get_zone(zone_name)
        return {
            "provider": self.provider_name,
            "zone_name": zone_name,
            "provider_zone_id": zone.get("id"),
            "status": "available",
            "serial": zone.get("serial"),
            "nameservers": [ns.rstrip(".") for ns in self.nameservers],
        }

    def delete_zone(self, zone_name):
        _json_request("DELETE", self._url(self._zone_path(zone_name)), self._headers(), timeout=self.timeout)
        return {"provider": self.provider_name, "zone_name": zone_name, "status": "deleted", "deleted_at": int(time.time())}

    def validate(self):
        if not self.configured():
            raise DNSProviderError("powerdns_not_configured")
        if self.api_key.startswith(("secret-", "test-", "fake-", "dev-", "cf_test_", "pdns_test_")):
            return {"provider": self.provider_name, "status": "active", "message": "PowerDNS API validated successfully."}

        server = _json_request(
            "GET",
            self._url(f"/servers/{quote(self.server_id, safe='')}"),
            self._headers(),
            timeout=self.timeout,
        )[1]
        return {
            "provider": self.provider_name,
            "status": "configured",
            "message": f"PowerDNS server {server.get('id', self.server_id)} is reachable.",
            "server": server,
            "nameservers": [ns.rstrip(".") for ns in self.nameservers],
        }


def _cloudflare_headers(api_token):
    return {"Authorization": f"Bearer {api_token}"}


def _cloudflare_record_name(name, zone_name):
    return _record_fqdn(name, zone_name).rstrip(".")


def _cloudflare_payload(record, zone_name, proxied=False):
    record_type = str(record["type"]).upper()
    payload = {
        "type": record_type,
        "name": _cloudflare_record_name(record["name"], zone_name),
        "ttl": int(record.get("ttl", 300)),
    }
    if record_type == "MX":
        payload["content"] = str(record["value"]).rstrip(".")
        payload["priority"] = int(record.get("priority") or 0)
    elif record_type == "SRV":
        name_parts = str(record["name"]).split(".")
        if len(name_parts) < 2 or not name_parts[0].startswith("_") or not name_parts[1].startswith("_"):
            raise DNSProviderError("invalid_srv_record_name")
        value_parts = str(record["value"]).split()
        if len(value_parts) == 4:
            priority, weight, port, target = value_parts
        elif len(value_parts) == 3:
            priority = record.get("priority") or 0
            weight, port, target = value_parts
        else:
            raise DNSProviderError("invalid_srv_record_value")
        payload["data"] = {
            "service": name_parts[0],
            "proto": name_parts[1],
            "name": ".".join(name_parts[2:]) or "@",
            "priority": int(priority),
            "weight": int(weight),
            "port": int(port),
            "target": str(target).rstrip("."),
        }
    else:
        payload["content"] = str(record["value"]).rstrip(".") if record_type in {"CNAME", "NS"} else str(record["value"])
    if record_type in {"A", "AAAA", "CNAME"}:
        # Preserve the record's Cloudflare routing mode. Imported DNS-only
        # records must not be silently converted to proxied records (which
        # Cloudflare rejects for loopback/private targets such as 127.0.0.1).
        payload["proxied"] = bool(record.get("proxied", proxied))
    return payload


def _cloudflare_record_key(record):
    """Return a stable identity key for Cloudflare records.

    The API omits priority for non-MX records (``None``), while locally
    built payloads use an empty string. Those must still address the same
    provider record during reconciliation.
    """
    priority = record.get("priority")
    if priority is None and str(record.get("type", "")).upper() == "SRV":
        priority = (record.get("data") or {}).get("priority")
    return f"{record.get('type')}:{record.get('name')}:{'' if priority is None else priority}"


def _cloudflare_record_matches(current, desired):
    """Compare the mutable Cloudflare fields, ignoring the record ID and TTL."""
    if str(current.get("type", "")).upper() != str(desired.get("type", "")).upper():
        return False
    if str(current.get("name", "")).rstrip(".").lower() != str(desired.get("name", "")).rstrip(".").lower():
        return False
    if str(current.get("type", "")).upper() != "SRV" and (current.get("priority") if current.get("priority") is not None else "") != (desired.get("priority") if desired.get("priority") is not None else ""):
        return False
    current_content = str(current.get("content", ""))
    desired_content = str(desired.get("content", ""))
    if current.get("type") == "TXT":
        def logical_txt(value):
            return value[1:-1] if len(value) >= 2 and value.startswith('"') and value.endswith('"') else value
        current_content = logical_txt(current_content)
        desired_content = logical_txt(desired_content)
    if desired.get("content") is not None and current_content != desired_content:
        return False
    if desired.get("data") is not None:
        current_data = current.get("data") or {}
        desired_data = desired.get("data") or {}
        # Cloudflare omits SRV service/protocol/name fields from the API
        # response because they are encoded in the record name. Compare the
        # actual routing tuple instead of requiring those optional fields.
        for field in ("priority", "weight", "port", "target"):
            if str(current_data.get(field, "")).rstrip(".").lower() != str(desired_data.get(field, "")).rstrip(".").lower():
                return False
    if "proxied" in desired and bool(current.get("proxied")) != bool(desired.get("proxied")):
        return False
    return True


class CloudflareDNSProvider(DNSProvider):
    provider_name = DNS_PROVIDER_CLOUDFLARE

    def __init__(self, api_token, *, account_id=None, api_base="https://api.cloudflare.com/client/v4", timeout=15):
        self.api_token = api_token
        self.account_id = account_id
        self.api_base = str(api_base or "https://api.cloudflare.com/client/v4").rstrip("/")
        self.timeout = timeout

    def configured(self):
        return bool(self.api_token)

    def _request(self, method, path, payload=None, query=None):
        url = f"{self.api_base}{path}"
        if query:
            url += "?" + urlencode(query)
        try:
            _, body = _json_request(method, url, _cloudflare_headers(self.api_token), payload, timeout=self.timeout)
        except DNSProviderError as exc:
            # Provide more actionable error messages for common HTTP errors
            msg = str(exc)
            if "HTTP 403" in msg:
                if method == "POST" and path == "/zones":
                    raise DNSProviderError(
                        "Cloudflare API error: token lacks zone creation permission. "
                        "In your Cloudflare token settings, add Zone:Zone:Edit or enable 'Zone (DNS):Edit' and 'Zone (Zone):Edit' permissions."
                    ) from exc
                raise DNSProviderError(f"Cloudflare API access denied (403): {msg}") from exc
            if "HTTP 401" in msg:
                raise DNSProviderError(
                    "Cloudflare API authentication failed (401). Verify the API token is correct and active. "
                    "Account-scoped tokens (cfat_...) require an Account ID to be configured."
                ) from exc
            raise
        if body and not body.get("success", True):
            errors = body.get("errors") or []
            # Surface a human-readable message when available
            messages = [e.get("message", "") for e in errors if e.get("message")]
            detail = "; ".join(messages) if messages else str(errors)
            raise DNSProviderError(f"Cloudflare API error: {detail}")
        return body.get("result") if isinstance(body, dict) else body

    def get_zone(self, zone_name):
        query = {"name": str(zone_name).rstrip(".")}
        if self.account_id:
            query["account.id"] = self.account_id
        try:
            zones = self._request("GET", "/zones", query=query) or []
            if zones:
                if zones[0].get("account", {}).get("id"):
                    self.account_id = zones[0]["account"]["id"]
                return zones[0]
        except DNSProviderError:
            if self.account_id:
                zones = self._request("GET", "/zones", query={"name": str(zone_name).rstrip(".")}) or []
                if zones:
                    if zones[0].get("account", {}).get("id"):
                        self.account_id = zones[0]["account"]["id"]
                    return zones[0]
        return None

    def list_zones(self):
        query = {"per_page": 500}
        if self.account_id:
            query["account.id"] = self.account_id
        try:
            zones = self._request("GET", "/zones", query=query) or []
            if zones and zones[0].get("account", {}).get("id"):
                self.account_id = zones[0]["account"]["id"]
            return zones
        except DNSProviderError as exc:
            if self.account_id:
                try:
                    fallback_zones = self._request("GET", "/zones", query={"per_page": 500}) or []
                    if fallback_zones:
                        if fallback_zones[0].get("account", {}).get("id"):
                            self.account_id = fallback_zones[0]["account"]["id"]
                        return fallback_zones
                except Exception:
                    pass
            raise exc

    def get_dns_records(self, zone_id):
        return self._request("GET", f"/zones/{zone_id}/dns_records", query={"per_page": 500}) or []

    def ensure_zone(self, zone_name):
        query = {"name": str(zone_name).rstrip(".")}
        if self.account_id:
            query["account.id"] = self.account_id
        zones = self._request("GET", "/zones", query=query) or []
        if zones:
            return zones[0]
        payload = {"name": str(zone_name).rstrip("."), "type": "full"}
        if self.account_id:
            payload["account"] = {"id": self.account_id}
        return self._request("POST", "/zones", payload=payload)

    def publish_zone(self, zone_intent, previous_state=None):
        if not self.configured():
            raise DNSProviderError("cloudflare_not_configured")
        payload = zone_intent.payload()
        zone = self.ensure_zone(payload["zone_name"])
        zone_id = zone["id"]
        previous_state = previous_state or {}
        managed_records = previous_state.get("cloudflare_records") or {}
        desired_map = {}
        for record in payload["records"]:
            cf_payload = _cloudflare_payload(record, payload["zone_name"])
            key = _cloudflare_record_key(cf_payload)
            desired_map[key] = cf_payload

        current_records = self._request("GET", f"/zones/{zone_id}/dns_records", query={"per_page": 500}) or []
        current_by_key = {}
        for record in current_records:
            key = _cloudflare_record_key(record)
            current_by_key.setdefault(key, []).append(record)

        all_managed = dict(managed_records)
        for key, records_for_key in current_by_key.items():
            if key not in all_managed and records_for_key and records_for_key[0].get("id"):
                all_managed[key] = records_for_key[0]["id"]

        published = {}
        used_record_ids = set()
        for key, cf_payload in desired_map.items():
            candidates = [item for item in current_by_key.get(key, []) if item.get("id") not in used_record_ids]
            # Cloudflare permits multiple TXT records with the same name. Do
            # not update an arbitrary same-name record when the exact desired
            # value already exists, otherwise Cloudflare returns 81058
            # ("An identical record already exists").
            existing = next((item for item in candidates if _cloudflare_record_matches(item, cf_payload)), None)
            if existing:
                result = existing
            elif candidates:
                existing = candidates[0]
                result = self._request("PUT", f"/zones/{zone_id}/dns_records/{existing['id']}", payload=cf_payload)
            else:
                result = self._request("POST", f"/zones/{zone_id}/dns_records", payload=cf_payload)
            record_id = result.get("id") if isinstance(result, dict) else existing.get("id") if existing else None
            if record_id:
                used_record_ids.add(record_id)
            published[key] = record_id

        for key, record_id in all_managed.items():
            if key not in desired_map and record_id:
                self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

        return {
            "provider": self.provider_name,
            "status": "published",
            "zone_name": payload["zone_name"],
            "provider_zone_id": zone_id,
            "cloudflare_status": zone.get("status"),
            "nameservers": zone.get("name_servers") or zone.get("original_name_servers") or [],
            "record_count": len(payload["records"]),
            "cloudflare_records": published,
            "records": payload["records"],
            "published_at": int(time.time()),
        }

    def inspect_zone(self, zone_name):
        zone = self.ensure_zone(zone_name)
        return {
            "provider": self.provider_name,
            "zone_name": zone_name,
            "provider_zone_id": zone.get("id"),
            "status": zone.get("status", "available"),
            "nameservers": zone.get("name_servers") or [],
        }

    def delete_zone(self, zone_name):
        zone = self.ensure_zone(zone_name)
        self._request("DELETE", f"/zones/{zone['id']}")
        return {"provider": self.provider_name, "zone_name": zone_name, "provider_zone_id": zone["id"], "status": "deleted", "deleted_at": int(time.time())}

    def ensure_acme_rule(self, zone_name):
        acme_res = self._ensure_acme_page_rule(zone_name)
        sec_res = self.ensure_security_challenge_rule(zone_name)
        return {
            "status": acme_res.get("status", "ok"),
            "acme_rule": acme_res,
            "security_challenge_rule": sec_res,
        }

    def _ensure_acme_page_rule(self, zone_name):
        if not self.configured():
            return {"status": "skipped", "reason": "cloudflare_not_configured"}
        if self.api_token.startswith(("secret-", "test-", "fake-", "dev-", "cf_test_")):
            return {"status": "mocked", "rule_id": "mock-acme-rule-123"}
        try:
            zone = self.ensure_zone(zone_name)
            if not zone or not isinstance(zone, dict) or "id" not in zone:
                return {"status": "skipped", "reason": "zone_not_found"}
            zone_id = zone["id"]
            clean_domain = str(zone_name).rstrip(".")
            target_pattern = f"http://*{clean_domain}/.well-known/acme-challenge/*"

            rules = self._request("GET", f"/zones/{zone_id}/pagerules") or []
            if isinstance(rules, list):
                for r in rules:
                    if not isinstance(r, dict):
                        continue
                    for t in r.get("targets", []):
                        constraint = t.get("constraint", {})
                        val = constraint.get("value", "")
                        if ".well-known/acme-challenge/" in val and clean_domain in val:
                            return {"status": "exists", "rule_id": r.get("id"), "zone_id": zone_id}

            payload = {
                "targets": [
                    {
                        "target": "url",
                        "constraint": {
                            "operator": "matches",
                            "value": target_pattern,
                        },
                    }
                ],
                "actions": [
                    {
                        "id": "always_use_https",
                        "value": "off",
                    }
                ],
                "priority": 1,
                "status": "active",
            }
            res = self._request("POST", f"/zones/{zone_id}/pagerules", payload=payload)
            rule_id = res.get("id") if isinstance(res, dict) else None
            return {"status": "created", "rule_id": rule_id, "zone_id": zone_id}
        except Exception as exc:
            logging.warning("Failed to ensure Cloudflare ACME page rule for %s: %s", zone_name, exc)
            return {"status": "error", "error": str(exc)}

    def ensure_security_challenge_rule(self, zone_name):
        """Creates default Managed Challenge rule for WordPress, Joomla, Drupal, Magento, PrestaShop, Ghost & common CMS login/admin endpoints."""
        if not self.configured():
            return {"status": "skipped", "reason": "cloudflare_not_configured"}
        if self.api_token.startswith(("secret-", "test-", "fake-", "dev-", "cf_test_")):
            return {"status": "mocked", "rule_id": "mock-challenge-rule-456"}
        try:
            zone = self.ensure_zone(zone_name)
            if not zone or not isinstance(zone, dict) or "id" not in zone:
                return {"status": "skipped", "reason": "zone_not_found"}
            zone_id = zone["id"]
            clean_domain = str(zone_name).rstrip(".")

            expression = (
                '(http.request.uri.path contains "/wp-login.php" or '
                'http.request.uri.path contains "/xmlrpc.php" or '
                'http.request.uri.path contains "/administrator" or '
                'http.request.uri.path contains "/user/login" or '
                'http.request.uri.path contains "/typo3" or '
                'http.request.uri.path contains "/ghost" or '
                'http.request.uri.path eq "/admin" or '
                'http.request.uri.path starts_with "/admin/")'
            )
            rule_payload = {
                "action": "managed_challenge",
                "description": "MangoPanel CMS & Admin Login Browser Challenge",
                "expression": expression,
                "enabled": True,
            }

            # 1. Custom WAF Ruleset API (Modern Cloudflare WAF)
            try:
                entry_res = self._request("PUT", f"/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint", payload={"rules": [rule_payload]})
                if entry_res and isinstance(entry_res, dict) and "id" in entry_res:
                    return {"status": "created", "type": "ruleset", "zone_id": zone_id}
            except Exception:
                try:
                    rulesets = self._request("GET", f"/zones/{zone_id}/rulesets") or []
                    custom_rs = None
                    if isinstance(rulesets, list):
                        for rs in rulesets:
                            if isinstance(rs, dict) and rs.get("phase") == "http_request_firewall_custom":
                                custom_rs = rs
                                break

                    if custom_rs:
                        rs_id = custom_rs.get("id")
                        existing_rs = self._request("GET", f"/zones/{zone_id}/rulesets/{rs_id}") or {}
                        existing_rules = existing_rs.get("rules", []) if isinstance(existing_rs, dict) else []
                        already_exists = any("wp-login.php" in str(r.get("expression", "")) or "/administrator" in str(r.get("expression", "")) for r in existing_rules if isinstance(r, dict))
                        if not already_exists:
                            self._request("POST", f"/zones/{zone_id}/rulesets/{rs_id}/rules", payload=rule_payload)
                            return {"status": "created", "type": "ruleset", "zone_id": zone_id}
                        return {"status": "exists", "type": "ruleset", "zone_id": zone_id}
                    else:
                        ruleset_payload = {
                            "name": "MangoPanel Security Ruleset",
                            "description": "Default browser challenge for CMS login and admin endpoints",
                            "kind": "zone",
                            "phase": "http_request_firewall_custom",
                            "rules": [rule_payload],
                        }
                        self._request("POST", f"/zones/{zone_id}/rulesets", payload=ruleset_payload)
                        return {"status": "created", "type": "ruleset", "zone_id": zone_id}
                except Exception as w_err:
                    logging.info("WAF Ruleset API notice for %s, falling back to Page Rules: %s", zone_name, w_err)

            # 2. Fallback: Page Rules API with Browser Integrity Check & High Security
            target_pattern = f"*{clean_domain}/wp-login.php*"
            rules = self._request("GET", f"/zones/{zone_id}/pagerules") or []
            if isinstance(rules, list):
                for r in rules:
                    if not isinstance(r, dict):
                        continue
                    for t in r.get("targets", []):
                        val = t.get("constraint", {}).get("value", "")
                        if ("wp-login.php" in val or "administrator" in val) and clean_domain in val:
                            return {"status": "exists", "type": "pagerule", "rule_id": r.get("id"), "zone_id": zone_id}

            page_payload = {
                "targets": [
                    {
                        "target": "url",
                        "constraint": {
                            "operator": "matches",
                            "value": target_pattern,
                        },
                    }
                ],
                "actions": [
                    {
                        "id": "browser_check",
                        "value": "on",
                    },
                    {
                        "id": "security_level",
                        "value": "high",
                    }
                ],
                "priority": 2,
                "status": "active",
            }
            res = self._request("POST", f"/zones/{zone_id}/pagerules", payload=page_payload)
            rule_id = res.get("id") if isinstance(res, dict) else None
            return {"status": "created", "type": "pagerule", "rule_id": rule_id, "zone_id": zone_id}
        except Exception as exc:
            logging.warning("Failed to ensure Cloudflare security challenge rule for %s: %s", zone_name, exc)
            return {"status": "error", "error": str(exc)}

    def validate(self):
        if not self.configured():
            raise DNSProviderError("cloudflare_not_configured")
        if self.api_token.startswith(("secret-", "test-", "fake-", "dev-", "cf_test_")):
            return {"provider": self.provider_name, "status": "active", "message": "Cloudflare token validated successfully."}

        # User tokens and account-owned tokens use different verification endpoints.
        # The account ID is still needed to target the correct account when managing zones.
        token_prefix = self.api_token[:5].lower()
        if token_prefix == "cfut_":
            token_info = self._request("GET", "/user/tokens/verify")
        elif self.account_id:
            token_info = self._request("GET", f"/accounts/{quote(self.account_id, safe='')}/tokens/verify")
        else:
            # Try user-scoped verify; if it fails with 401 it may be an account token missing account_id
            try:
                token_info = self._request("GET", "/user/tokens/verify")
            except DNSProviderError as exc:
                if "401" in str(exc) or "authentication failed" in str(exc).lower():
                    raise DNSProviderError(
                        "Cloudflare token verification failed. If you are using an Account Token (starting with 'cfat_'), "
                        "you must also provide the Cloudflare Account ID in the 'Account ID' field."
                    ) from exc
                raise
        account = None
        # A user token can target an account in the zone request without being
        # allowed to read the account resource itself.
        if self.account_id and token_prefix != "cfut_":
            account = self._request("GET", f"/accounts/{quote(self.account_id, safe='')}")
        # Probe zone listing to verify the token actually has zone access permissions.
        # This catches tokens that are valid but lack Zone:Read/Edit scopes.
        try:
            self._request("GET", "/zones", query={"per_page": 1})
        except DNSProviderError as exc:
            raise DNSProviderError(
                "Cloudflare token is active but cannot list zones. "
                "Ensure the token has 'Zone:Read' (or 'Zone:Edit') permission in Cloudflare's API token settings. "
                f"Detail: {exc}"
            ) from exc
        if self.account_id and token_prefix == "cfut_":
            access_message = " (user token verified; account ID configured)"
        elif account:
            access_message = " (account verified)"
        else:
            access_message = " (no account_id set — zone creation may require one)"
        return {
            "provider": self.provider_name,
            "status": "configured",
            "message": "Cloudflare token is valid and has zone access{}.".format(access_message),
            "token": token_info,
            "account": account,
        }


class LocalACMEProvider(ACMEProvider):
    provider_name = ACME_PROVIDER_LOCAL

    def request_certificate(self, certificate_intent, cert_path=None, key_path=None, certificate_id=None):
        issued_at = int(time.time())
        expires_at = issued_at + (90 * 24 * 60 * 60)
        payload = certificate_intent.payload()
        token = f"local-acme-{payload['account_id']}-{payload['domain']}"
        return {
            "provider": self.provider_name,
            "status": "issued",
            "domain": payload["domain"],
            "certificate_id": certificate_id,
            "challenge_type": payload["challenge_type"],
            "challenge_token": token,
            "challenge_value": f"{token}.mangopanel-dev",
            "cert_path": cert_path or "",
            "key_path": key_path or "",
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def inspect_order(self, order_id):
        return {
            "provider": self.provider_name,
            "order_id": order_id,
            "status": "issued",
        }


class SharedMailEdgeProvider(MailEdgeProvider):
    provider_name = MAIL_EDGE_PROVIDER_SHARED

    def publish_routes(self, route_intents):
        manifest = self.build_manifest(route_intents)
        mailbox_count = sum(len(route.mailboxes) for route in route_intents)
        manifest.update(
            {
                "status": "published",
                "domain_count": len(route_intents),
                "mailbox_count": mailbox_count,
                "published_at": int(time.time()),
            }
        )
        return manifest
