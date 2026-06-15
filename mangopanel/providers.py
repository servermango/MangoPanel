import time
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
        payload["proxied"] = bool(record.get("proxied", proxied))
    return payload


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
        _, body = _json_request(method, url, _cloudflare_headers(self.api_token), payload, timeout=self.timeout)
        if body and not body.get("success", True):
            errors = body.get("errors") or []
            raise DNSProviderError(f"cloudflare_api_error: {errors}")
        return body.get("result") if isinstance(body, dict) else body

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
            key = f"{cf_payload['type']}:{cf_payload['name']}:{cf_payload.get('priority', '')}"
            desired_map[key] = cf_payload

        current_records = self._request("GET", f"/zones/{zone_id}/dns_records", query={"per_page": 500}) or []
        current_by_key = {}
        for record in current_records:
            key = f"{record.get('type')}:{record.get('name')}:{record.get('priority', '')}"
            current_by_key[key] = record

        published = {}
        for key, cf_payload in desired_map.items():
            existing = current_by_key.get(key)
            if existing:
                result = self._request("PUT", f"/zones/{zone_id}/dns_records/{existing['id']}", payload=cf_payload)
            else:
                result = self._request("POST", f"/zones/{zone_id}/dns_records", payload=cf_payload)
            published[key] = result.get("id") if isinstance(result, dict) else None

        for key, record_id in managed_records.items():
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
