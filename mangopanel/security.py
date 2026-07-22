import base64
import hashlib
import hmac
import json
import os
import secrets
import time


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def hash_password(password, iterations=260000):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        _b64url_encode(salt),
        _b64url_encode(digest),
    )


def hash_mailpit_password(password):
    digest = hashlib.sha1(password.encode("utf-8")).digest()
    return "{SHA}" + base64.b64encode(digest).decode("ascii")


def _secret_key(master_secret):
    return hashlib.sha256(str(master_secret or "").encode("utf-8")).digest()


def _xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt_secret(plaintext, master_secret):
    if plaintext is None:
        return ""
    raw = str(plaintext).encode("utf-8")
    if not raw:
        return ""
    # Standard PBKDF2 derived key + HMAC-SHA256 authenticated encryption construction (v2)
    key = hashlib.pbkdf2_hmac("sha256", str(master_secret or "").encode("utf-8"), b"MangoSecretSalt", 10000)
    enc_key = key[:16]
    mac_key = key[16:]
    nonce = os.urandom(16)
    stream = bytearray()
    block = 0
    while len(stream) < len(raw):
        stream.extend(hmac.new(enc_key, nonce + block.to_bytes(4, "big"), hashlib.sha256).digest())
        block += 1
    ciphertext = _xor_bytes(raw, bytes(stream[: len(raw)]))
    mac = hmac.new(mac_key, b"v2:" + nonce + ciphertext, hashlib.sha256).digest()
    payload = b"v2:" + nonce + mac + ciphertext
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_secret(token, master_secret):
    if not token:
        return ""
    try:
        raw_payload = base64.urlsafe_b64decode(str(token).encode("ascii"))
    except (ValueError, TypeError):
        return ""
    # Handle v2 prefix
    if raw_payload.startswith(b"v2:"):
        payload = raw_payload[3:]
        if len(payload) < 48:
            return ""
        nonce = payload[:16]
        mac = payload[16:48]
        ciphertext = payload[48:]
        key = hashlib.pbkdf2_hmac("sha256", str(master_secret or "").encode("utf-8"), b"MangoSecretSalt", 10000)
        enc_key = key[:16]
        mac_key = key[16:]
        expected_mac = hmac.new(mac_key, b"v2:" + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return ""
        stream = bytearray()
        block = 0
        while len(stream) < len(ciphertext):
            stream.extend(hmac.new(enc_key, nonce + block.to_bytes(4, "big"), hashlib.sha256).digest())
            block += 1
        plaintext = _xor_bytes(ciphertext, bytes(stream[: len(ciphertext)]))
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    # Legacy v1 fallback for backward compatibility
    if len(raw_payload) < 48:
        return ""
    nonce = raw_payload[:16]
    mac = raw_payload[16:48]
    ciphertext = raw_payload[48:]
    key = _secret_key(master_secret)
    expected_mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        return ""
    stream = bytearray()
    block = 0
    while len(stream) < len(ciphertext):
        stream.extend(hmac.new(key, nonce + block.to_bytes(4, "big"), hashlib.sha256).digest())
        block += 1
    plaintext = _xor_bytes(ciphertext, bytes(stream[: len(ciphertext)]))
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def validate_git_repository_url(url, is_development=False):
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if url.startswith("-"):
        return False
    if is_development:
        if url.startswith("/") or url.startswith("file://") or url.startswith("http://") or url.startswith("https://"):
            return True
        return False
    if not url.startswith("https://"):
        return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        if hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
            return False
        import ipaddress
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass
        return True
    except Exception:
        return False



def validate_git_branch(branch):
    if not branch or not isinstance(branch, str):
        return False
    branch = branch.strip()
    if branch.startswith("-"):
        return False
    import re
    if not re.match(r"^[a-zA-Z0-9_./-]+$", branch):
        return False
    if ".." in branch or branch.endswith("/") or branch.startswith("/"):
        return False
    return True



def verify_password(password, encoded):
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            _b64url_decode(salt),
            int(iterations),
        )
        return hmac.compare_digest(_b64url_encode(digest), expected)
    except (ValueError, TypeError):
        return False


def create_jwt(payload, secret, ttl_seconds):
    now = int(time.time())
    body = dict(payload)
    body.setdefault("iat", now)
    body.setdefault("exp", now + ttl_seconds)
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = "{}.{}".format(
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8")),
    )
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return "{}.{}".format(signing_input, _b64url_encode(signature))


def verify_jwt(token, secret):
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = "{}.{}".format(header_b64, payload_b64)
        expected = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_encode(expected), signature_b64):
            return None
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") != "HS256":
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except (ValueError, json.JSONDecodeError, TypeError):
        return None


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret, for_time=None, step=30, digits=6):
    if for_time is None:
        for_time = int(time.time())
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int(for_time // step).to_bytes(8, "big")
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp(secret, code, window=1):
    if not secret:
        return False
    cleaned = str(code or "").strip().replace(" ", "")
    now = int(time.time())
    for delta in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret, now + (delta * 30)), cleaned):
            return True
    return False
