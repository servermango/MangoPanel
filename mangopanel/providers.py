import time
from dataclasses import asdict, dataclass, field


DNS_PROVIDER_LOCAL = "local-dev-dns"
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
