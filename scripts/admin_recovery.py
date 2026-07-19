#!/usr/bin/env python3
import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mangopanel.config import load_config
from mangopanel.db import connect, init_db
from mangopanel.security import generate_totp_secret, hash_password
from mangopanel.app import otpauth_uri


def require_root_or_privileged():
    if os.name != "posix":
        return
    if os.geteuid() == 0:
        return
    if os.environ.get("SUDO_USER"):
        return
    raise SystemExit("This command must be run as root or through sudo.")


def parse_args():
    parser = argparse.ArgumentParser(description="Reset an admin password or enable/disable admin 2FA.")
    parser.add_argument("--email", required=True, help="Admin email address.")
    parser.add_argument("--set-password", action="store_true", help="Set or change the admin password.")
    parser.add_argument("--enable-totp", action="store_true", help="Enable TOTP for the admin with a fresh secret.")
    parser.add_argument("--disable-totp", action="store_true", help="Disable the admin's TOTP secret.")
    parser.add_argument("--password", help="New password. If omitted, you will be prompted.")
    return parser.parse_args()


def main():
    require_root_or_privileged()
    args = parse_args()
    if not args.set_password and not args.enable_totp and not args.disable_totp:
        raise SystemExit("Choose at least one action: --set-password, --enable-totp, and/or --disable-totp.")
    if args.enable_totp and args.disable_totp:
        raise SystemExit("Choose only one TOTP action: --enable-totp or --disable-totp.")

    config = load_config()
    init_db(config.db_path)

    with connect(config.db_path) as conn:
        admin = conn.execute("SELECT id, email, full_name, role, status FROM admins WHERE email = ?", (args.email.lower(),)).fetchone()
        if not admin:
            raise SystemExit(f"No admin account found for {args.email}.")

        if args.set_password:
            password = args.password or getpass.getpass("New admin password: ")
            if not args.password:
                confirm = getpass.getpass("Confirm new admin password: ")
                if password != confirm:
                    raise SystemExit("Passwords do not match.")
            conn.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (hash_password(password), admin["id"]))
            print(f"Password reset for {admin['email']}.")

        if args.enable_totp:
            secret = generate_totp_secret()
            conn.execute("UPDATE admins SET totp_secret = ? WHERE id = ?", (secret, admin["id"]))
            print(f"TOTP enabled for {admin['email']}.")
            print(f"Secret: {secret}")
            print(f"URI: {otpauth_uri('MangoPanel Admin', admin['email'], secret)}")

        if args.disable_totp:
            conn.execute("UPDATE admins SET totp_secret = '' WHERE id = ?", (admin["id"],))
            print(f"TOTP disabled for {admin['email']}.")


if __name__ == "__main__":
    main()
