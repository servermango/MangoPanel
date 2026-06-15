import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from mangopanel.providers import (
    ACMEProvider,
    ACMECertificateIntent,
    CloudflareDNSProvider,
    DNSProvider,
    DNSRecordIntent,
    DNSZoneIntent,
    LocalACMEProvider,
    LocalDNSProvider,
    MAIL_EDGE_PROVIDER_SHARED,
    MailDomainRouteIntent,
    MailEdgeProvider,
    MailboxRouteIntent,
    PowerDNSProvider,
    SharedMailEdgeProvider,
)


class FakeHTTPServer:
    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.base_url = "http://127.0.0.1:{}".format(self.httpd.server_address[1])
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class FakePowerDNSHandler(BaseHTTPRequestHandler):
    patched_rrsets = []

    def log_message(self, fmt, *args):
        return

    def json_response(self, payload, status=200):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/api/v1/servers/localhost/zones":
            if query.get("zone", [""])[0] == "example.mango.test.":
                return self.json_response([])
        if parsed.path == "/api/v1/servers/localhost/zones/example.mango.test.":
            return self.json_response(
                {
                    "id": "example.mango.test.",
                    "serial": 2026060601,
                    "rrsets": [
                        {"name": "example.mango.test.", "type": "SOA", "ttl": 300, "records": []},
                        {"name": "old.example.mango.test.", "type": "A", "ttl": 300, "records": [{"content": "192.0.2.10", "disabled": False}]},
                    ],
                }
            )
        return self.json_response({"error": "not_found"}, 404)

    def do_POST(self):
        if self.path == "/api/v1/servers/localhost/zones":
            return self.json_response({"id": "example.mango.test.", "name": "example.mango.test.", "serial": 1})
        return self.json_response({"error": "not_found"}, 404)

    def do_PATCH(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
        FakePowerDNSHandler.patched_rrsets.append(json.loads(raw))
        self.send_response(204)
        self.end_headers()


class FakeCloudflareHandler(BaseHTTPRequestHandler):
    created_zone = None
    created_records = []

    def log_message(self, fmt, *args):
        return

    def json_response(self, payload, status=200):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/client/v4/zones":
            return self.json_response({"success": True, "result": []})
        if parsed.path == "/client/v4/zones/cf-zone-1/dns_records":
            return self.json_response({"success": True, "result": []})
        return self.json_response({"success": False, "errors": [{"message": "not_found"}]}, 404)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
        payload = json.loads(raw) if raw else {}
        if self.path == "/client/v4/zones":
            FakeCloudflareHandler.created_zone = payload
            return self.json_response(
                {
                    "success": True,
                    "result": {
                        "id": "cf-zone-1",
                        "name": payload["name"],
                        "status": "pending",
                        "name_servers": ["abby.ns.cloudflare.com", "bob.ns.cloudflare.com"],
                    },
                }
            )
        if self.path == "/client/v4/zones/cf-zone-1/dns_records":
            FakeCloudflareHandler.created_records.append(payload)
            return self.json_response({"success": True, "result": {"id": "record-{}".format(len(FakeCloudflareHandler.created_records)), **payload}})
        return self.json_response({"success": False, "errors": [{"message": "not_found"}]}, 404)


class ProviderContractTests(unittest.TestCase):
    def test_dns_zone_intent_serializes_records(self):
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[DNSRecordIntent(name="@", type="mx", value="mail.mango.test", priority=10)],
        )

        payload = intent.payload()

        self.assertEqual(payload["zone_name"], "example.mango.test")
        self.assertEqual(payload["records"][0]["type"], "MX")
        self.assertEqual(payload["records"][0]["priority"], 10)

    def test_acme_certificate_intent_uses_standard_challenge(self):
        intent = ACMECertificateIntent(account_id=1, domain_id=2, website_id=3, domain="example.mango.test")

        self.assertEqual(intent.payload()["challenge_type"], "http-01")

    def test_mail_edge_manifest_contract(self):
        provider = MailEdgeProvider()
        provider.provider_name = MAIL_EDGE_PROVIDER_SHARED
        route = MailDomainRouteIntent(
            account_id=1,
            mail_domain_id=2,
            domain="example.mango.test",
            edge_host="mail.mango.test",
            mailboxes=[
                MailboxRouteIntent(
                    mailbox_id=3,
                    email="hello@example.mango.test",
                    storage_path="/srv/accounts/u000001/mail/example.mango.test/hello",
                    quota_mb=1024,
                )
            ],
        )

        manifest = provider.build_manifest([route])

        self.assertEqual(manifest["provider"], MAIL_EDGE_PROVIDER_SHARED)
        self.assertEqual(manifest["domains"][0]["mailboxes"][0]["email"], "hello@example.mango.test")

    def test_local_dns_provider_publishes_zone_state(self):
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[DNSRecordIntent(name="@", type="A", value="127.0.0.1")],
        )

        state = LocalDNSProvider().publish_zone(intent, artifact_path="/tmp/example.zone", serial=7)

        self.assertEqual(state["provider"], "local-dev-dns")
        self.assertEqual(state["status"], "published")
        self.assertEqual(state["serial"], 7)
        self.assertEqual(state["records"][0]["type"], "A")

    def test_local_acme_provider_issues_dev_certificate_state(self):
        intent = ACMECertificateIntent(account_id=1, domain_id=2, website_id=3, domain="example.mango.test")

        state = LocalACMEProvider().request_certificate(intent, cert_path="/tmp/cert.pem", key_path="/tmp/key.pem", certificate_id=4)

        self.assertEqual(state["provider"], "local-dev-acme")
        self.assertEqual(state["status"], "issued")
        self.assertEqual(state["certificate_id"], 4)
        self.assertIn("local-acme-1-example.mango.test", state["challenge_token"])

    def test_shared_mail_edge_provider_publishes_route_manifest(self):
        route = MailDomainRouteIntent(
            account_id=1,
            mail_domain_id=2,
            domain="example.mango.test",
            edge_host="mail.mango.test",
            mailboxes=[MailboxRouteIntent(mailbox_id=3, email="hello@example.mango.test", storage_path="/mail/hello", quota_mb=1024)],
        )

        manifest = SharedMailEdgeProvider().publish_routes([route])

        self.assertEqual(manifest["provider"], MAIL_EDGE_PROVIDER_SHARED)
        self.assertEqual(manifest["status"], "published")
        self.assertEqual(manifest["domain_count"], 1)
        self.assertEqual(manifest["mailbox_count"], 1)

    def test_powerdns_provider_publishes_rrsets(self):
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[
                DNSRecordIntent(name="@", type="A", value="127.0.0.1", ttl=300),
                DNSRecordIntent(name="@", type="MX", value="mail.example.mango.test", ttl=300, priority=10),
            ],
        )
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = PowerDNSProvider(server.base_url + "/api/v1", "secret", nameservers=["ns1.mango.test", "ns2.mango.test"])
            state = provider.publish_zone(intent)

        self.assertEqual(state["provider"], "local_powerdns")
        rrsets = FakePowerDNSHandler.patched_rrsets[0]["rrsets"]
        self.assertTrue(any(item["type"] == "A" and item["changetype"] == "REPLACE" for item in rrsets))
        self.assertTrue(any(item["name"] == "old.example.mango.test." and item["changetype"] == "DELETE" for item in rrsets))

    def test_cloudflare_provider_creates_zone_records_and_nameservers(self):
        FakeCloudflareHandler.created_zone = None
        FakeCloudflareHandler.created_records = []
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[DNSRecordIntent(name="@", type="A", value="127.0.0.1", ttl=300)],
        )
        with FakeHTTPServer(FakeCloudflareHandler) as server:
            provider = CloudflareDNSProvider("token", account_id="account-1", api_base=server.base_url + "/client/v4")
            state = provider.publish_zone(intent)

        self.assertEqual(FakeCloudflareHandler.created_zone["account"]["id"], "account-1")
        self.assertEqual(FakeCloudflareHandler.created_records[0]["name"], "example.mango.test")
        self.assertEqual(state["provider"], "cloudflare")
        self.assertEqual(state["nameservers"], ["abby.ns.cloudflare.com", "bob.ns.cloudflare.com"])

    def test_base_providers_require_implementation(self):
        with self.assertRaises(NotImplementedError):
            DNSProvider().publish_zone(None)
        with self.assertRaises(NotImplementedError):
            DNSProvider().delete_zone("example.mango.test")
        with self.assertRaises(NotImplementedError):
            ACMEProvider().request_certificate(None)


if __name__ == "__main__":
    unittest.main()
