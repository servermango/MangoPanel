"""Registrar adapters used by the admin domain-management API."""
import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class RegistrarError(Exception):
    pass


def _request(method, url, headers=None, data=None, timeout=20):
    payload = None
    request_headers = {"Accept": "application/json", **(headers or {})}
    if data is not None:
        payload = urlencode(data).encode("utf-8")
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        request = Request(url, data=payload, headers=request_headers, method=method)
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except Exception as exc:
        raise RegistrarError(str(exc)) from exc


class Registrar:
    key = ""

    def __init__(self, settings):
        self.settings = settings or {}

    def update_nameservers(self, domain, nameservers):
        raise NotImplementedError

    def register(self, domain, nameservers, years=1, contacts=None):
        raise NotImplementedError


class ResellerClubRegistrar(Registrar):
    key = "resellerclub"

    def _call(self, path, params):
        base = (self.settings.get("api_base") or "https://httpapi.com/api").rstrip("/")
        params = {"auth-userid": self.settings.get("reseller_id", ""), "api-key": self.settings.get("api_key", ""), **params}
        return _request("POST", f"{base}/{path}.json", data=params)

    def update_nameservers(self, domain, nameservers):
        result = self._call("domains/modify-ns", {"domain-name": domain, "name-server1": nameservers[0], "name-server2": nameservers[1]})
        if isinstance(result, dict) and result.get("status") == "Failed":
            raise RegistrarError(str(result))
        return {"provider": self.key, "response": result}

    def register(self, domain, nameservers, years=1, contacts=None):
        params = {"domain-name": domain, "years": years, "ns1": nameservers[0], "ns2": nameservers[1]}
        if contacts:
            params.update(contacts)
        result = self._call("domains/register", params)
        if isinstance(result, dict) and result.get("status") == "Failed":
            raise RegistrarError(str(result))
        return {"provider": self.key, "response": result}


class DomainNameAPIRegistrar(Registrar):
    key = "domainnameapi"

    def _call(self, path, payload):
        base = (self.settings.get("api_base") or "https://api.domainnameapi.com/api").rstrip("/")
        headers = {"Authorization": f"Bearer {self.settings.get('api_token', '')}"}
        return _request("POST", f"{base}/{path.lstrip('/')}", headers=headers, data=payload)

    def update_nameservers(self, domain, nameservers):
        result = self._call("domains/nameservers", {"domain": domain, "nameServers": ",".join(nameservers)})
        return {"provider": self.key, "response": result}

    def register(self, domain, nameservers, years=1, contacts=None):
        payload = {"domain": domain, "years": years, "nameServers": ",".join(nameservers)}
        if contacts:
            payload.update(contacts)
        return {"provider": self.key, "response": self._call("domains/register", payload)}


class CloudflareRegistrar(Registrar):
    key = "cloudflare"

    def update_nameservers(self, domain, nameservers):
        raise RegistrarError("Cloudflare assigns nameservers; use the DNS provider zone operation instead")


def registrar_for(key, settings):
    adapters = {"resellerclub": ResellerClubRegistrar, "domainnameapi": DomainNameAPIRegistrar, "cloudflare": CloudflareRegistrar}
    adapter = adapters.get(str(key or "").lower())
    if not adapter:
        raise RegistrarError("unsupported_registrar")
    return adapter(settings)
