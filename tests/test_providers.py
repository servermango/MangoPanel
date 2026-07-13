import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from mangopanel.providers import (
    ACMEProvider,
    ACMECertificateIntent,
    CloudflareDNSProvider,
    DNS_PROVIDER_LOCAL_POWERDNS,
    DNSProvider,
    DNSProviderError,
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
    _zone_fqdn,
    _record_fqdn,
    _relative_name,
    _txt_content,
    _pdns_content,
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
    deleted_zones = []
    # Controls whether the zone list returns an existing zone (True) or empty (False)
    zone_exists = False

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
            zone = query.get("zone", [""])[0]
            if zone == "example.mango.test.":
                if FakePowerDNSHandler.zone_exists:
                    return self.json_response([{"id": "example.mango.test.", "name": "example.mango.test."}])
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

    def do_DELETE(self):
        FakePowerDNSHandler.deleted_zones.append(self.path)
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


class PowerDNSProviderTests(unittest.TestCase):
    """Comprehensive unit tests for the local_powerdns (PowerDNSProvider) DNS provider."""

    def _make_provider(self, server):
        return PowerDNSProvider(
            server.base_url + "/api/v1",
            "test-api-key",
            server_id="localhost",
            nameservers=["ns1.mango.test", "ns2.mango.test"],
        )

    def setUp(self):
        FakePowerDNSHandler.patched_rrsets = []
        FakePowerDNSHandler.deleted_zones = []
        FakePowerDNSHandler.zone_exists = False

    # ------------------------------------------------------------------
    # Provider identity and configuration
    # ------------------------------------------------------------------

    def test_provider_name_is_local_powerdns(self):
        provider = PowerDNSProvider("http://localhost:8053/api/v1", "key")
        self.assertEqual(provider.provider_name, DNS_PROVIDER_LOCAL_POWERDNS)
        self.assertEqual(provider.provider_name, "local_powerdns")

    def test_configured_returns_true_when_url_and_key_present(self):
        provider = PowerDNSProvider("http://localhost:8053/api/v1", "mykey")
        self.assertTrue(provider.configured())

    def test_configured_returns_false_when_url_missing(self):
        self.assertFalse(PowerDNSProvider("", "mykey").configured())

    def test_configured_returns_false_when_key_missing(self):
        self.assertFalse(PowerDNSProvider("http://localhost:8053", "").configured())

    def test_publish_zone_raises_when_not_configured(self):
        provider = PowerDNSProvider("", "")
        intent = DNSZoneIntent(account_id=1, domain_id=2, zone_name="example.mango.test")
        with self.assertRaises(DNSProviderError) as ctx:
            provider.publish_zone(intent)
        self.assertIn("powerdns_not_configured", str(ctx.exception))

    # ------------------------------------------------------------------
    # Zone creation — new zone (ensure_zone creates)
    # ------------------------------------------------------------------

    def test_publish_zone_creates_new_zone_when_not_existing(self):
        """When the zone list returns empty, ensure_zone POSTs to create the zone."""
        FakePowerDNSHandler.zone_exists = False
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[DNSRecordIntent(name="@", type="A", value="127.0.0.1", ttl=300)],
        )
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            state = provider.publish_zone(intent)

        self.assertEqual(state["provider"], "local_powerdns")
        self.assertEqual(state["status"], "published")
        self.assertEqual(state["zone_name"], "example.mango.test")
        self.assertIn("ns1.mango.test", state["nameservers"])
        self.assertEqual(state["record_count"], 1)

    # ------------------------------------------------------------------
    # Zone creation — existing zone (ensure_zone reuses)
    # ------------------------------------------------------------------

    def test_publish_zone_reuses_existing_zone(self):
        """When the zone list returns a match, ensure_zone does NOT POST to create."""
        FakePowerDNSHandler.zone_exists = True
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[DNSRecordIntent(name="@", type="A", value="10.0.0.1", ttl=300)],
        )
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            state = provider.publish_zone(intent)

        # Zone was reused, not re-created; publish still succeeds
        self.assertEqual(state["provider"], "local_powerdns")
        self.assertEqual(state["status"], "published")

    # ------------------------------------------------------------------
    # publish_zone — NS records are always injected
    # ------------------------------------------------------------------

    def test_publish_zone_injects_ns_rrset(self):
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[DNSRecordIntent(name="@", type="A", value="1.2.3.4", ttl=300)],
        )
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            provider.publish_zone(intent)

        rrsets = FakePowerDNSHandler.patched_rrsets[0]["rrsets"]
        ns_rrset = next((r for r in rrsets if r["type"] == "NS"), None)
        self.assertIsNotNone(ns_rrset, "NS rrset should be injected automatically")
        ns_contents = [rec["content"] for rec in ns_rrset["records"]]
        self.assertIn("ns1.mango.test.", ns_contents)
        self.assertIn("ns2.mango.test.", ns_contents)

    # ------------------------------------------------------------------
    # publish_zone — stale records deleted
    # ------------------------------------------------------------------

    def test_publish_zone_deletes_stale_records(self):
        """Records present in the current zone but absent from the intent get a DELETE rrset."""
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            # Does NOT include the 'old' A record the fake server returns
            records=[DNSRecordIntent(name="www", type="A", value="5.5.5.5", ttl=300)],
        )
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            provider.publish_zone(intent)

        rrsets = FakePowerDNSHandler.patched_rrsets[0]["rrsets"]
        deleted = [r for r in rrsets if r.get("changetype") == "DELETE"]
        self.assertTrue(
            any("old.example.mango.test." in d["name"] for d in deleted),
            "Stale 'old' A record should be queued for deletion",
        )

    # ------------------------------------------------------------------
    # publish_zone — SOA records are never deleted
    # ------------------------------------------------------------------

    def test_publish_zone_never_deletes_soa_record(self):
        """SOA records must not appear in the DELETE list."""
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(account_id=1, domain_id=2, zone_name="example.mango.test", records=[])
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            provider.publish_zone(intent)

        rrsets = FakePowerDNSHandler.patched_rrsets[0]["rrsets"]
        deleted_types = {r["type"] for r in rrsets if r.get("changetype") == "DELETE"}
        self.assertNotIn("SOA", deleted_types)

    # ------------------------------------------------------------------
    # publish_zone — result fields
    # ------------------------------------------------------------------

    def test_publish_zone_returns_serial_and_zone_id(self):
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(account_id=1, domain_id=2, zone_name="example.mango.test", records=[])
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            state = provider.publish_zone(intent)

        self.assertIn("serial", state)
        # The fake GET returns serial 2026060601
        self.assertEqual(state["serial"], 2026060601)
        self.assertIn("provider_zone_id", state)
        self.assertIn("published_at", state)

    # ------------------------------------------------------------------
    # inspect_zone
    # ------------------------------------------------------------------

    def test_inspect_zone_returns_zone_info(self):
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            info = provider.inspect_zone("example.mango.test")

        self.assertEqual(info["provider"], "local_powerdns")
        self.assertEqual(info["zone_name"], "example.mango.test")
        self.assertEqual(info["status"], "available")
        self.assertIn("ns1.mango.test", info["nameservers"])
        self.assertEqual(info["serial"], 2026060601)
        self.assertIn("provider_zone_id", info)

    # ------------------------------------------------------------------
    # delete_zone
    # ------------------------------------------------------------------

    def test_delete_zone_calls_delete_and_returns_status(self):
        FakePowerDNSHandler.deleted_zones = []
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            result = provider.delete_zone("example.mango.test")

        self.assertEqual(result["provider"], "local_powerdns")
        self.assertEqual(result["zone_name"], "example.mango.test")
        self.assertEqual(result["status"], "deleted")
        self.assertIn("deleted_at", result)
        # Verify the DELETE HTTP request was made
        self.assertTrue(
            any("example.mango.test" in path for path in FakePowerDNSHandler.deleted_zones),
            "DELETE request should have been sent to the PowerDNS API",
        )

    # ------------------------------------------------------------------
    # X-API-Key header is always sent
    # ------------------------------------------------------------------

    def test_publish_zone_sends_api_key_header(self):
        """Verify the provider sends the X-API-Key authentication header."""
        received_headers = []

        class HeaderCapturingHandler(FakePowerDNSHandler):
            def do_GET(self):
                received_headers.append(dict(self.headers))
                return super().do_GET()

            def do_POST(self):
                received_headers.append(dict(self.headers))
                return super().do_POST()

            def do_PATCH(self):
                received_headers.append(dict(self.headers))
                return super().do_PATCH()

        HeaderCapturingHandler.patched_rrsets = []
        HeaderCapturingHandler.deleted_zones = []
        HeaderCapturingHandler.zone_exists = False
        intent = DNSZoneIntent(account_id=1, domain_id=2, zone_name="example.mango.test", records=[])
        with FakeHTTPServer(HeaderCapturingHandler) as server:
            provider = PowerDNSProvider(
                server.base_url + "/api/v1", "my-secret-key", nameservers=["ns1.mango.test"]
            )
            provider.publish_zone(intent)

        api_key_values = {
            h.get("X-Api-Key") or h.get("x-api-key")
            for h in received_headers
        } - {None}
        self.assertTrue(api_key_values, "X-API-Key header should be present in requests")
        self.assertIn("my-secret-key", api_key_values)

    # ------------------------------------------------------------------
    # Error handling — network failures
    # ------------------------------------------------------------------

    def test_publish_zone_raises_dns_provider_error_on_network_failure(self):
        """Connecting to a port that refuses connections raises DNSProviderError."""
        provider = PowerDNSProvider(
            "http://127.0.0.1:1",  # port 1 is never open
            "key",
            nameservers=["ns1.mango.test"],
        )
        intent = DNSZoneIntent(account_id=1, domain_id=2, zone_name="example.mango.test", records=[])
        with self.assertRaises(DNSProviderError):
            provider.publish_zone(intent)

    # ------------------------------------------------------------------
    # _pdns_content helper — record-type formatting
    # ------------------------------------------------------------------

    def test_pdns_content_a_record_returned_verbatim(self):
        self.assertEqual(_pdns_content({"type": "A", "value": "192.0.2.1"}), "192.0.2.1")

    def test_pdns_content_aaaa_record_returned_verbatim(self):
        self.assertEqual(_pdns_content({"type": "AAAA", "value": "::1"}), "::1")

    def test_pdns_content_mx_with_priority_formats_correctly(self):
        content = _pdns_content({"type": "MX", "value": "mail.example.com", "priority": 10})
        self.assertEqual(content, "10 mail.example.com.")

    def test_pdns_content_mx_without_priority_defaults_to_zero(self):
        content = _pdns_content({"type": "MX", "value": "mail.example.com", "priority": None})
        self.assertEqual(content, "0 mail.example.com.")

    def test_pdns_content_mx_strips_trailing_dot_before_appending(self):
        content = _pdns_content({"type": "MX", "value": "mail.example.com.", "priority": 20})
        self.assertEqual(content, "20 mail.example.com.")

    def test_pdns_content_cname_appends_trailing_dot(self):
        self.assertEqual(_pdns_content({"type": "CNAME", "value": "target.example.com"}), "target.example.com.")

    def test_pdns_content_cname_does_not_double_dot(self):
        self.assertEqual(_pdns_content({"type": "CNAME", "value": "target.example.com."}), "target.example.com.")

    def test_pdns_content_ns_appends_trailing_dot(self):
        self.assertEqual(_pdns_content({"type": "NS", "value": "ns1.example.com"}), "ns1.example.com.")

    def test_pdns_content_txt_wraps_value_in_quotes(self):
        content = _pdns_content({"type": "TXT", "value": "v=spf1 include:example.com ~all"})
        self.assertEqual(content, '"v=spf1 include:example.com ~all"')

    def test_pdns_content_txt_already_quoted_stays_unchanged(self):
        content = _pdns_content({"type": "TXT", "value": '"already-quoted"'})
        self.assertEqual(content, '"already-quoted"')

    def test_pdns_content_txt_escapes_inner_quotes(self):
        content = _pdns_content({"type": "TXT", "value": 'say "hello"'})
        self.assertIn('\\"', content)

    def test_pdns_content_srv_with_priority(self):
        content = _pdns_content({"type": "SRV", "value": "10 80 sip.example.com", "priority": 5})
        self.assertTrue(content.startswith("5 "))

    def test_pdns_content_srv_without_priority_defaults_zero(self):
        content = _pdns_content({"type": "SRV", "value": "10 80 sip.example.com", "priority": None})
        self.assertTrue(content.startswith("0 "))

    def test_pdns_content_caa_returned_verbatim(self):
        value = '0 issue "letsencrypt.org"'
        self.assertEqual(_pdns_content({"type": "CAA", "value": value}), value)

    # ------------------------------------------------------------------
    # Helper function unit tests
    # ------------------------------------------------------------------

    def test_zone_fqdn_appends_trailing_dot(self):
        self.assertEqual(_zone_fqdn("example.mango.test"), "example.mango.test.")

    def test_zone_fqdn_does_not_double_trailing_dot(self):
        self.assertEqual(_zone_fqdn("example.mango.test."), "example.mango.test.")

    def test_zone_fqdn_lowercases(self):
        self.assertEqual(_zone_fqdn("EXAMPLE.MANGO.TEST"), "example.mango.test.")

    def test_record_fqdn_apex_returns_zone_with_dot(self):
        self.assertEqual(_record_fqdn("@", "example.mango.test"), "example.mango.test.")

    def test_record_fqdn_empty_returns_zone_with_dot(self):
        self.assertEqual(_record_fqdn("", "example.mango.test"), "example.mango.test.")

    def test_record_fqdn_relative_combines_with_zone(self):
        self.assertEqual(_record_fqdn("www", "example.mango.test"), "www.example.mango.test.")

    def test_record_fqdn_already_fqdn_does_not_double(self):
        result = _record_fqdn("www.example.mango.test", "example.mango.test")
        self.assertEqual(result, "www.example.mango.test.")

    def test_relative_name_apex_returns_at_symbol(self):
        self.assertEqual(_relative_name("example.mango.test", "example.mango.test"), "@")

    def test_relative_name_strips_zone_suffix(self):
        self.assertEqual(_relative_name("www.example.mango.test", "example.mango.test"), "www")

    def test_relative_name_no_suffix_match_returns_full(self):
        self.assertEqual(_relative_name("other.domain.test", "example.mango.test"), "other.domain.test")

    def test_txt_content_wraps_plain_value(self):
        self.assertEqual(_txt_content("hello"), '"hello"')

    def test_txt_content_already_quoted_unchanged(self):
        self.assertEqual(_txt_content('"hello"'), '"hello"')

    def test_txt_content_escapes_backslash(self):
        self.assertIn("\\\\", _txt_content("back\\slash"))

    # ------------------------------------------------------------------
    # Group records — multi-value rrsets
    # ------------------------------------------------------------------

    def test_publish_zone_groups_multiple_a_records_into_one_rrset(self):
        """Two A records for the same name+TTL should produce a single rrset."""
        FakePowerDNSHandler.patched_rrsets = []
        intent = DNSZoneIntent(
            account_id=1,
            domain_id=2,
            zone_name="example.mango.test",
            records=[
                DNSRecordIntent(name="@", type="A", value="1.1.1.1", ttl=300),
                DNSRecordIntent(name="@", type="A", value="2.2.2.2", ttl=300),
            ],
        )
        with FakeHTTPServer(FakePowerDNSHandler) as server:
            provider = self._make_provider(server)
            provider.publish_zone(intent)

        rrsets = FakePowerDNSHandler.patched_rrsets[0]["rrsets"]
        a_rrsets = [r for r in rrsets if r["type"] == "A" and r.get("changetype") == "REPLACE"]
        self.assertEqual(len(a_rrsets), 1, "Two A records for the same name should merge into a single rrset")
        a_records = a_rrsets[0]["records"]
        self.assertEqual(len(a_records), 2)
        contents = {rec["content"] for rec in a_records}
        self.assertIn("1.1.1.1", contents)
        self.assertIn("2.2.2.2", contents)

    # ------------------------------------------------------------------
    # Default nameservers
    # ------------------------------------------------------------------

    def test_default_nameservers_used_when_not_specified(self):
        provider = PowerDNSProvider("http://localhost", "key")
        self.assertIn("ns1.mango.test", provider.nameservers)
        self.assertIn("ns2.mango.test", provider.nameservers)

    def test_custom_nameservers_override_defaults(self):
        provider = PowerDNSProvider("http://localhost", "key", nameservers=["ns1.custom.test"])
        self.assertEqual(provider.nameservers, ["ns1.custom.test"])


if __name__ == "__main__":
    unittest.main()
