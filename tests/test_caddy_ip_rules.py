import copy
import json
import subprocess
import unittest
from unittest.mock import patch

from mangopanel.caddy import CaddyConfigError, _request, sync_account_ip_rules


class Proxy:
    def __init__(self):
        self.servers = {
            "https": {"listen": [":443"], "tls_connection_policies": [{}], "routes": [
                {"match": [{"host": ["example.com", "www.example.com"]}],
                 "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "web:80"}]}]},
                {"match": [{"host": ["other.example"]}], "handle": [{"handler": "file_server"}]},
            ]},
            "http": {"listen": [":80"], "routes": [
                {"match": [{"host": ["example.com"]}], "handle": [{"handler": "file_server"}]},
            ]},
        }
        self.calls = []
        self.race = None

    def request(self, method, path, body=None, etag=None):
        self.calls.append((method, path, copy.deepcopy(body), etag))
        if path == "/config/apps/http/servers":
            return (200, '"servers"', json.dumps(self.servers).encode()) if self.servers else (404, None, b'')
        name = path.split("/")[-2]
        if method == "GET":
            return 200, '"' + json.dumps(self.servers[name]["routes"]) + '"', json.dumps(self.servers[name]["routes"]).encode()
        if self.race:
            race, self.race = self.race, None
            race(self)
            return 412, None, b''
        if name not in self.servers:
            return 404, None, b''
        current_etag = '"' + json.dumps(self.servers[name]["routes"]) + '"'
        if etag != current_etag:
            return 412, None, b''
        self.servers[name]["routes"] = copy.deepcopy(body)
        return 200, None, b''


class CaddyIPRuleTests(unittest.TestCase):
    def sync(self, proxy, account=1, ips=None):
        with patch("mangopanel.caddy._request", side_effect=proxy.request):
            sync_account_ip_rules(account, ["example.com", "www.example.com"],
                                  ["192.0.2.10"] if ips is None else ips, ["173.245.48.0/20"])

    def test_startup_config_never_causes_a_write(self):
        for servers in ({}, {"http": {"listen": [":80"], "routes": []}}):
            proxy = Proxy()
            proxy.servers = servers
            with self.assertRaisesRegex(CaddyConfigError, "deferred"):
                self.sync(proxy, ips=[])
            self.assertTrue(all(call[0] == "GET" for call in proxy.calls))

    def test_add_remove_preserves_listeners_tls_and_other_sites(self):
        proxy = Proxy()
        original = copy.deepcopy(proxy.servers)
        self.sync(proxy)
        for name, server in proxy.servers.items():
            self.assertEqual(server["listen"], original[name]["listen"])
            self.assertEqual(server.get("tls_connection_policies"), original[name].get("tls_connection_policies"))
            self.assertEqual(server["routes"][2:], original[name]["routes"])
            self.assertEqual(server["routes"][0]["match"][0]["remote_ip"]["ranges"], ["192.0.2.10/32"])
            self.assertEqual(server["routes"][1]["match"][0]["header"], {"CF-Connecting-IP": ["192.0.2.10"]})
        self.sync(proxy, ips=[])
        self.assertEqual(proxy.servers, original)
        for method, path, _, etag in proxy.calls:
            if method != "GET":
                self.assertEqual(method, "PATCH")
                self.assertTrue(path.endswith("/routes"))
                self.assertIsNotNone(etag)

    def test_no_rules_and_repeated_sync_do_not_reload(self):
        proxy = Proxy()
        self.sync(proxy, ips=[])
        self.assertFalse(any(call[0] == "PATCH" for call in proxy.calls))
        self.sync(proxy)
        proxy.calls.clear()
        self.sync(proxy)
        self.assertFalse(any(call[0] == "PATCH" for call in proxy.calls))

    def test_concurrent_site_and_other_account_changes_are_preserved(self):
        proxy = Proxy()
        other_rule = {"@id": "mangopanel-ip-block-2-https-direct", "handle": [{"handler": "static_response", "status_code": 403}]}
        new_site = {"match": [{"host": ["new.example"]}], "handle": [{"handler": "file_server"}]}
        def reload(p):
            p.servers["https"]["routes"].extend([other_rule, new_site])
        proxy.race = reload
        self.sync(proxy)
        self.assertIn(other_rule, proxy.servers["https"]["routes"])
        self.assertIn(new_site, proxy.servers["https"]["routes"])

    def test_server_removed_during_reload_is_not_recreated(self):
        proxy = Proxy()
        proxy.race = lambda p: p.servers.pop("https")
        self.sync(proxy)
        self.assertNotIn("https", proxy.servers)
        self.assertEqual(proxy.servers["http"]["listen"], [":80"])

    def test_continuous_contention_is_bounded_without_unsafe_fallback(self):
        proxy = Proxy()
        def request(method, path, body=None, etag=None):
            if method == "PATCH":
                proxy.calls.append((method, path, body, etag))
                return 412, None, b''
            return proxy.request(method, path, body, etag)
        with patch("mangopanel.caddy._request", side_effect=request):
            with self.assertRaisesRegex(CaddyConfigError, "deferred"):
                sync_account_ip_rules(1, ["example.com"], ["192.0.2.10"], [])
        self.assertEqual(sum(call[0] == "PATCH" for call in proxy.calls), 3)
        self.assertFalse(any("/load" in call[1] for call in proxy.calls))

    def test_missing_etag_refuses_update(self):
        proxy = Proxy()
        def request(method, path, body=None, etag=None):
            status, _, payload = proxy.request(method, path, body, etag)
            return status, None, payload
        with patch("mangopanel.caddy._request", side_effect=request):
            with self.assertRaisesRegex(CaddyConfigError, "ETag"):
                sync_account_ip_rules(1, ["example.com"], ["192.0.2.10"], [])
        self.assertFalse(any(call[0] == "PATCH" for call in proxy.calls))

    def test_transport_sends_conditional_patch_over_stdin(self):
        result = subprocess.CompletedProcess([], 0, b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', b'')
        with patch("mangopanel.caddy.subprocess.run", return_value=result) as run:
            self.assertEqual(_request("PATCH", "/config/apps/http/servers/https/routes", [{"a": 1}], '"tag"')[0], 200)
        command = run.call_args.args[0]
        self.assertIn("If-Match: \"tag\"", command)
        self.assertIn("PATCH", command)
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), [{"a": 1}])

    def test_transport_rejects_full_config_or_unconditional_writes(self):
        for path, etag in (("/load", '"tag"'), ("/config/", '"tag"'), ("/config/apps/http/servers/https/routes", None)):
            with patch("mangopanel.caddy.subprocess.run") as run:
                with self.assertRaises(CaddyConfigError):
                    _request("PATCH", path, [], etag)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
