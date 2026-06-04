import base64
import json
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
import re
import time
from email.message import EmailMessage


MAIL_PATH_SAFE = re.compile(r"[^a-z0-9._+-]+")


def split_mailbox_address(email):
    text = str(email or "").strip().lower()
    if "@" not in text:
        return "", ""
    local_part, domain = text.rsplit("@", 1)
    return local_part, domain


def sanitize_mailbox_component(value, fallback="mailbox"):
    text = str(value or "").strip().lower()
    text = MAIL_PATH_SAFE.sub("_", text)
    text = text.strip("._-+")
    return text or fallback


def mailbox_storage_path(base_path, email):
    base = Path(base_path)
    local_part, domain = split_mailbox_address(email)
    if not local_part or not domain:
        return base / "mail" / "mailboxes" / "mailbox"
    return base / "mail" / sanitize_mailbox_component(domain, "domain") / sanitize_mailbox_component(local_part, "mailbox")


def mailbox_storage_components(email):
    local_part, domain = split_mailbox_address(email)
    return {
        "local_part": local_part,
        "domain": domain,
        "storage_segment": str(Path(sanitize_mailbox_component(domain, "domain")) / sanitize_mailbox_component(local_part, "mailbox")),
    }


def ensure_mailbox_storage(storage_path):
    path = Path(storage_path)
    path.mkdir(parents=True, exist_ok=True)
    for leaf in ("cur", "new", "tmp"):
        (path / leaf).mkdir(parents=True, exist_ok=True)
    return path


def mailbox_storage_size_bytes(storage_path):
    path = Path(storage_path)
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def mailbox_storage_size_mb(storage_path):
    return mailbox_storage_size_bytes(storage_path) / (1024 * 1024)


def mailbox_storage_inode_count(storage_path):
    path = Path(storage_path)
    if not path.exists():
        return 0
    count = 1
    for item in path.rglob("*"):
        try:
            count += 1
        except OSError:
            continue
    return count


def _within_base_path(path, base_path):
    if base_path is None:
        return True
    try:
        Path(path).resolve().relative_to(Path(base_path).resolve())
        return True
    except Exception:
        return False


def remove_mailbox_storage(storage_path, base_path=None):
    path = Path(storage_path)
    if not path.exists():
        return False
    if not _within_base_path(path, base_path):
        return False
    shutil.rmtree(path)
    return True


def move_mailbox_storage(source_path, target_path, base_path=None):
    source = Path(source_path)
    target = Path(target_path)
    if source.resolve() == target.resolve():
        return target
    if not source.exists():
        return ensure_mailbox_storage(target)
    if not _within_base_path(source, base_path) or not _within_base_path(target, base_path):
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(source), str(target))
    return ensure_mailbox_storage(target)


def build_mail_message_bytes(sender_email, recipients, subject, body, attachments=None, extra_headers=None):
    message = EmailMessage()
    message["From"] = str(sender_email or "")
    message["To"] = ", ".join([str(recipient or "").strip() for recipient in (recipients or []) if str(recipient or "").strip()])
    message["Subject"] = str(subject or "")
    message["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    if extra_headers:
        for key, value in extra_headers.items():
            if key and value is not None:
                message[str(key)] = str(value)
    attachments = attachments or []
    if attachments:
        message.set_content(str(body or ""))
        for attachment in attachments:
            filename = str(attachment.get("filename") or "attachment")
            content = attachment.get("content", b"")
            if isinstance(content, str):
                content = content.encode("utf-8")
            content_type = str(attachment.get("content_type") or "application/octet-stream")
            maintype, _, subtype = content_type.partition("/")
            if not maintype or not subtype:
                maintype, subtype = "application", "octet-stream"
            message.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)
    else:
        message.set_content(str(body or ""))
    return message.as_bytes()


def recommended_spf_record(mail_host=None):
    host = str(mail_host or "").strip().lower()
    if host:
        return "v=spf1 mx a:{} -all".format(host)
    return "v=spf1 mx -all"


def recommended_dmarc_record(domain, policy="quarantine"):
    domain = str(domain or "").strip().lower()
    if not domain:
        domain = "example.com"
    policy = policy if policy in {"none", "quarantine", "reject"} else "quarantine"
    return "v=DMARC1; p={}; rua=mailto:postmaster@{}".format(policy, domain)


def generate_dkim_material(selector="mango", key_bits=1024):
    selector = sanitize_mailbox_component(selector or "mango", "mango")
    private_key = ""
    public_key = ""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            private_path = Path(tmp) / "dkim-private.pem"
            public_path = Path(tmp) / "dkim-public.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:{}".format(int(key_bits)), "-out", str(private_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            private_key = private_path.read_text(encoding="utf-8")
            public_key = public_path.read_text(encoding="utf-8")
    except Exception:
        private_key = "fallback-private-{}".format(secrets.token_hex(32))
        public_key = "fallback-public-{}".format(secrets.token_hex(32))
    return {
        "selector": selector,
        "private_key": private_key,
        "public_key": public_key,
    }


def dkim_dns_value(public_key):
    text = str(public_key or "").strip()
    if not text:
        return ""
    if "BEGIN" in text:
        body = "".join(line.strip() for line in text.splitlines() if "BEGIN" not in line and "END" not in line)
        return "v=DKIM1; k=rsa; p={}".format(body)
    return "v=DKIM1; k=rsa; p={}".format(base64.b64encode(text.encode("utf-8")).decode("ascii"))


def mail_auth_health(domain_row, dns_records, mail_host=None):
    dns_records = dns_records or []
    domain = str(domain_row.get("name") or "").strip().lower()
    expected_spf = recommended_spf_record(mail_host)
    expected_dmarc = recommended_dmarc_record(domain)
    spf_ok = False
    dmarc_ok = False
    dkim_ok = False
    notes = []
    for record in dns_records:
        rtype = str(record.get("type") or "").upper()
        name = str(record.get("name") or "").strip()
        value = str(record.get("value") or "").strip()
        normalized_value = value.lower()
        if rtype == "TXT" and name in {"@", domain} and normalized_value == expected_spf.lower():
            spf_ok = True
        if rtype == "TXT" and name == "_dmarc" and normalized_value == expected_dmarc.lower():
            dmarc_ok = True
        if rtype in {"TXT", "CNAME"} and (name.startswith("mango._domainkey") or name.endswith("._domainkey")):
            dkim_ok = True
    if not spf_ok:
        notes.append("SPF missing or not aligned")
    if not dmarc_ok:
        notes.append("DMARC missing or not aligned")
    if not dkim_ok:
        notes.append("DKIM selector record missing")
    status = "ok" if not notes else "warning"
    if not domain:
        status = "missing"
        notes.append("Domain name unavailable")
    return {
        "status": status,
        "spf": {"expected": expected_spf, "configured": spf_ok},
        "dmarc": {"expected": expected_dmarc, "configured": dmarc_ok},
        "dkim": {"configured": dkim_ok},
        "notes": notes,
    }
