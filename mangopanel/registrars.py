"""Registrar adapters used by the admin domain-management API."""
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlencode
from urllib.error import HTTPError
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


def _json_request(method, url, headers=None, params=None, data=None, timeout=20):
    """Make a JSON API request and surface provider errors consistently."""
    request_headers = {
        "Accept": "application/json",
        # DomainNameAPI's API gateway sits behind a WAF that rejects
        # urllib's default `Python-urllib/...` signature as a browser bot.
        "User-Agent": "MangoPanel-Registrar/1.0",
        **(headers or {}),
    }
    request_url = url
    payload = None
    if method in {"GET", "DELETE"} and params:
        request_url = f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"
    elif data is not None:
        payload = json.dumps(data).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    try:
        request = Request(request_url, data=payload, headers=request_headers, method=method)
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)
        raise RegistrarError(f"HTTP {exc.code}: {detail[:400]}") from exc
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

    def list_domains(self):
        raise RegistrarError("domain_inventory_not_supported")

    def renew(self, domain, years=1):
        raise RegistrarError("renewal_not_supported")

    def get_details(self, domain):
        raise RegistrarError("whois_refresh_not_supported")


class ResellerClubRegistrar(Registrar):
    key = "resellerclub"

    def _call(self, path, params, method="POST"):
        base = (self.settings.get("api_base") or "https://httpapi.com/api").rstrip("/")
        params = {"auth-userid": self.settings.get("reseller_id", ""), "api-key": self.settings.get("api_key", ""), **params}
        url = f"{base}/{path}.json"
        if method == "GET":
            url = f"{url}?{urlencode(params)}"
            return _request("GET", url)
        return _request(method, url, data=params)

    @staticmethod
    def _date(value):
        """Normalize the date formats returned by ResellerClub."""
        if value in (None, ""):
            return None
        try:
            # Some ResellerClub endpoints return Unix timestamps.
            number = float(value)
            if number > 100000000:
                from datetime import datetime, timezone
                return datetime.fromtimestamp(number, timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
        return str(value).strip()

    def list_domains(self):
        """Return all domains managed by this reseller account.

        Unlike the write APIs, ResellerClub's inventory endpoint is a GET
        endpoint and returns order records in a dictionary keyed by order id.
        The response also contains pagination metadata, so do not treat those
        metadata entries as domains.
        """
        domains = []
        page_size = 500
        page = 1
        while True:
            response = self._call(
                "domains/search",
                {"no-of-records": page_size, "page-no": page},
                method="GET",
            )
            if not isinstance(response, dict):
                raise RegistrarError(f"invalid_domain_inventory_response: {str(response)[:300]}")
            if str(response.get("status", "")).lower() in {"failed", "error"}:
                raise RegistrarError(str(response))

            items = []
            for value in response.values():
                if not isinstance(value, dict):
                    continue
                name = value.get("entity.description") or value.get("entity.entityid") or value.get("entityid") or value.get("domainname") or value.get("domain-name") or value.get("domain")
                if name:
                    items.append(value)

            for item in items:
                def field(*keys):
                    return next((item.get(key) for key in keys if item.get(key) not in (None, "")), None)

                name = str(field("entity.description", "entity.entityid", "entityid", "domainname", "domain-name", "domain")).strip().lower()
                if not name:
                    continue
                nameservers = field("nameservers", "name-servers", "nameServers") or []
                if isinstance(nameservers, str):
                    nameservers = [nameservers]
                domains.append({
                    "id": field("orders.orderid", "orderid", "order-id", "id") or "",
                    "domain": name,
                    "status": str(field("entity.currentstatus", "status") or "active").lower(),
                    "expiry_at": self._date(field("orders.endtime", "endtime", "expirationdate", "expirydate")),
                    "registered_at": self._date(field("orders.creationtime", "creationtime", "creationdate")),
                    "auto_renew": str(field("orders.autorenew", "orders.auto_renew", "auto_renew", "auto-renew", "autoRenew") or "").lower() in {"1", "true", "yes"},
                    "transfer_lock": str(field("orders.transferlock", "transferlock", "transfer-lock", "transferLock") or "").lower() in {"1", "true", "yes"},
                    "auth_code_available": bool(field("authcode", "auth-code", "authCode")),
                    "nameservers": nameservers,
                    "whois": {},
                    "metadata": {"provider_record": item},
                })

            if len(items) < page_size:
                break
            page += 1
        result = {"domains": domains}
        try:
            balance = self._call(
                "billing/reseller-balance",
                {"reseller-id": self.settings.get("reseller_id", "")},
                method="GET",
            )
            if isinstance(balance, dict):
                amount = balance.get("sellingcurrencybalance")
                currency = balance.get("sellingcurrencysymbol") or ""
                if amount not in (None, ""):
                    result["balance"] = float(amount)
                    result["currency"] = str(currency)
                    result["balances"] = [{"balance": float(amount), "currency": str(currency)}]
        except (RegistrarError, TypeError, ValueError):
            # Inventory remains useful when billing permission is unavailable.
            pass
        return result

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

    def renew(self, domain, years=1):
        result = self._call("domains/renew", {"domain-name": domain, "years": years})
        if isinstance(result, dict) and result.get("status") == "Failed":
            raise RegistrarError(str(result))
        return {"provider": self.key, "response": result}


class DomainNameAPIRegistrar(Registrar):
    key = "domainnameapi"

    def _call(self, method, path, params=None, payload=None):
        base = (self.settings.get("api_base") or "https://api.domainresellerapi.com/api/v1").rstrip("/")
        reseller_id = self.settings.get("reseller_id") or self.settings.get("account_identifier") or ""
        api_key = self.settings.get("api_token") or self.settings.get("api_key") or ""
        headers = {"X-API-KEY": api_key, "__reseller": reseller_id}
        return _json_request(method, f"{base}/{path.lstrip('/')}", headers=headers, params=params, data=payload)

    @staticmethod
    def _date(value):
        return str(value).replace(" T", "T").strip() if value else None

    def list_domains(self):
        domains = []
        page_size = 200
        skip = 0
        while True:
            response = self._call("GET", "domains", params={"MaxResultCount": page_size, "SkipCount": skip})
            items = response.get("items") if isinstance(response, dict) else None
            if not isinstance(items, list):
                raise RegistrarError(f"invalid_domain_inventory_response: {str(response)[:300]}")
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("domainName") or "").strip().lower()
                if not name:
                    continue
                domains.append({
                    "id": item.get("id", ""),
                    "domain": name,
                    "status": str(item.get("statusCode") or item.get("statusText") or item.get("status") or "active").lower(),
                    "expiry_at": self._date(item.get("expirationDate")),
                    "registered_at": self._date(item.get("startDate")),
                    "auto_renew": bool(item.get("autoRenew") or item.get("autoRenewal")),
                    "transfer_lock": bool(item.get("lockStatus")),
                    "auth_code_available": bool(item.get("authCode")),
                    "nameservers": item.get("nameServers") or [],
                    "whois": {"privacy": bool(item.get("privacyProtectionStatus"))},
                    "metadata": {"provider_record": item},
                })
            if len(items) < page_size:
                break
            skip += len(items)

        result = {"domains": domains}
        try:
            balance = self._call("GET", "deposit/accounts/me")
            if isinstance(balance, dict):
                result["balance"] = balance.get("usdBalance")
                result["currency"] = "USD"
                result["balances"] = [
                    {"balance": balance.get("usdBalance"), "currency": "USD"},
                    {"balance": balance.get("tryBalance"), "currency": "TRY"},
                ]
        except RegistrarError:
            # Inventory is still useful when the optional balance endpoint is
            # unavailable or the reseller has no balance permission.
            pass
        return result

    def update_nameservers(self, domain, nameservers):
        result = self._call("PUT", "domains/dns/name-server", payload={"domainName": domain, "nameServers": nameservers})
        return {"provider": self.key, "response": result}

    def register(self, domain, nameservers, years=1, contacts=None):
        payload = {"domainName": domain, "period": years, "nameServers": nameservers}
        if contacts:
            payload.update(contacts)
        return {"provider": self.key, "response": self._call("POST", "domains/register-with-contacts", payload=payload)}

    def renew(self, domain, years=1):
        return {"provider": self.key, "response": self._call("POST", "domains/renew", payload={"domainName": domain, "period": years})}

    def get_details(self, domain):
        response = self._call("GET", "domains/info", params={"DomainName": domain})
        item = response.get("data") if isinstance(response, dict) and isinstance(response.get("data"), dict) else response
        raw_contacts = item.get("contacts") or item.get("Contacts") or []
        if isinstance(raw_contacts, dict):
            raw_contacts = list(raw_contacts.values())
        whois = {}
        roles = ("registrant", "administrative", "technical", "billing")
        for index, contact in enumerate(raw_contacts if isinstance(raw_contacts, list) else []):
            if not isinstance(contact, dict):
                continue
            role = roles[index] if index < len(roles) else "registrant"
            whois[role] = {
                "name": " ".join(str(value).strip() for value in (contact.get("firstName") or contact.get("FirstName") or "", contact.get("lastName") or contact.get("LastName") or "") if str(value).strip()),
                "organization": contact.get("companyName") or contact.get("Company") or "",
                "email": contact.get("eMail") or contact.get("Email") or contact.get("EMail") or "",
                "phone": contact.get("phone") or contact.get("Phone") or "",
                "address": contact.get("address") or contact.get("AddressLine1") or "",
                "city": contact.get("city") or contact.get("City") or "",
                "state": contact.get("state") or contact.get("State") or "",
                "postal_code": contact.get("postalCode") or contact.get("ZipCode") or "",
                "country": contact.get("country") or contact.get("Country") or "",
            }
        return {"whois": whois, "nameservers": item.get("nameservers") or item.get("NameServers") or [], "metadata": item}


class CloudflareRegistrar(Registrar):
    key = "cloudflare"

    def list_domains(self):
        """Use the linked Cloudflare account's zones as the local inventory.

        Cloudflare Registrar does not expose a separate reseller inventory
        endpoint; zones are the authoritative account-level domain list for
        the DNS/registration account linked in MangoPanel.
        """
        base = (self.settings.get("api_base") or "https://api.cloudflare.com/client/v4").rstrip("/")
        account_id = self.settings.get("cloudflare_account_id") or self.settings.get("external_account_id")
        headers = {"Authorization": f"Bearer {self.settings.get('api_token') or self.settings.get('api_key', '')}"}
        registrations = {}
        if account_id:
            try:
                response = _request("GET", f"{base}/accounts/{account_id}/registrar/registrations?per_page=50", headers=headers)
                if not response.get("success", True):
                    raise RegistrarError(str(response.get("errors") or response))
                for item in response.get("result") or []:
                    name = str(item.get("domain_name") or "").strip().lower()
                    if name:
                        registrations[name] = item
                # Registrar sync must never fall back to DNS zones: zones can
                # include domains that are registered at another registrar.
                return [
                    {"id": item.get("id", ""), "domain": name, "status": str(item.get("status") or "active").lower(),
                     "expiry_at": item.get("expires_at"), "registered_at": item.get("created_at"),
                     "auto_renew": item.get("auto_renew", False), "transfer_lock": item.get("locked", False),
                     "metadata": {"registrar": item}}
                    for name, item in registrations.items()
                ]
            except RegistrarError as exc:
                raise RegistrarError("cloudflare_registrar_access_required: " + str(exc)) from exc
        raise RegistrarError("cloudflare_account_id_required_for_registrar_sync")

    def update_nameservers(self, domain, nameservers):
        raise RegistrarError("Cloudflare assigns nameservers; use the DNS provider zone operation instead")


class NamecheapRegistrar(Registrar):
    key = "namecheap"

    def _call(self, command, params=None):
        account_username = self.settings.get("api_user") or self.settings.get("username") or self.settings.get("account_identifier") or ""
        if not account_username:
            raise RegistrarError("namecheap_username_required: enter your Namecheap account username")
        client_ip = self.settings.get("client_ip") or ""
        if not client_ip:
            raise RegistrarError("namecheap_client_ip_required: enter the IPv4 address whitelisted in Namecheap API Access")
        values = {
            # Namecheap uses the normal account username for both fields; it
            # does not issue a separate API username.
            "ApiUser": account_username,
            "ApiKey": self.settings.get("api_key", ""),
            "UserName": account_username,
            "ClientIp": client_ip,
            "Command": command,
        }
        values.update(params or {})
        base = (self.settings.get("api_base") or "https://api.namecheap.com/xml.response").rstrip("?")
        try:
            with urlopen(f"{base}?{urlencode(values)}", timeout=20) as response:
                root = ET.fromstring(response.read())
        except Exception as exc:
            raise RegistrarError(str(exc)) from exc
        if root.attrib.get("Status") != "OK":
            errors = [node.text or "" for node in root.iter() if node.tag.endswith("Error")]
            raise RegistrarError("; ".join(errors) or "namecheap_request_failed")
        return root

    def list_domains(self):
        root = self._call("namecheap.domains.getList", {"PageSize": 100})
        domains = []
        for node in root.iter():
            if not node.tag.endswith("Domain") or not node.attrib.get("Name"):
                continue
            domains.append({
                "id": node.attrib.get("ID", ""), "domain": node.attrib.get("Name", "").lower(),
                "status": "expired" if node.attrib.get("IsExpired", "false").lower() == "true" else "active",
                "expiry_at": node.attrib.get("Expires"), "registered_at": node.attrib.get("Created"),
                "auto_renew": node.attrib.get("AutoRenew", "false").lower() == "true",
                "transfer_lock": node.attrib.get("IsLocked", "false").lower() == "true",
                "whois": {"privacy": node.attrib.get("WhoisGuard", "")},
            })
        result = {"domains": domains}
        try:
            balance_root = self._call("namecheap.users.getBalances")
            balance_node = next((node for node in balance_root.iter() if node.tag.endswith("UserGetBalancesResult")), None)
            if balance_node is not None and balance_node.attrib.get("AvailableBalance") is not None:
                amount = float(balance_node.attrib.get("AvailableBalance") or 0)
                currency = balance_node.attrib.get("Currency") or "USD"
                result.update({
                    "balance": amount,
                    "currency": currency,
                    "balances": [{"balance": amount, "currency": currency}],
                })
        except RegistrarError:
            # A reseller may have permission to list domains but not read
            # billing details; do not discard a successful inventory sync.
            pass
        return result

    def renew(self, domain, years=1):
        return {"provider": self.key, "response": self._call("namecheap.domains.renew", {"DomainName": domain, "Years": years})}

    def get_details(self, domain):
        root = self._call("namecheap.domains.getInfo", {"DomainName": domain})
        details = next((node for node in root.iter() if node.tag.endswith("DomainDetails")), None)
        if details is None:
            return {"whois": {}, "nameservers": [], "metadata": {}}
        whois = {"registrant": dict(details.attrib)}
        nameservers = [node.attrib.get("NameServer") or node.attrib.get("Name") for node in details.iter() if node.tag.endswith("NameServer") and (node.attrib.get("NameServer") or node.attrib.get("Name"))]
        return {"whois": whois, "nameservers": nameservers, "metadata": dict(details.attrib)}


def registrar_for(key, settings):
    adapters = {"resellerclub": ResellerClubRegistrar, "pdr": ResellerClubRegistrar, "domainnameapi": DomainNameAPIRegistrar, "namecheap": NamecheapRegistrar, "cloudflare": CloudflareRegistrar}
    adapter = adapters.get(str(key or "").lower())
    if not adapter:
        raise RegistrarError("unsupported_registrar")
    return adapter(settings)
