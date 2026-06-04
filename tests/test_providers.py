import unittest

from mangopanel.providers import (
    ACMEProvider,
    ACMECertificateIntent,
    DNSProvider,
    DNSRecordIntent,
    DNSZoneIntent,
    LocalACMEProvider,
    LocalDNSProvider,
    MAIL_EDGE_PROVIDER_SHARED,
    MailDomainRouteIntent,
    MailEdgeProvider,
    MailboxRouteIntent,
    SharedMailEdgeProvider,
)


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

    def test_base_providers_require_implementation(self):
        with self.assertRaises(NotImplementedError):
            DNSProvider().publish_zone(None)
        with self.assertRaises(NotImplementedError):
            ACMEProvider().request_certificate(None)


if __name__ == "__main__":
    unittest.main()
