#!/usr/bin/env python3
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from mangopanel.config import CONFIG
from mangopanel.db import connect
from mangopanel.app import sync_cloudflare_acme_rules


def main():
    db_path = CONFIG.db_path
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        sys.exit(1)

    print(f"Connecting to database at {db_path}...")
    with connect(db_path) as conn:
        website_id = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else None
        if website_id:
            print(f"Syncing Cloudflare ACME rules for website ID {website_id}...")
        else:
            print("Syncing Cloudflare ACME rules for all existing websites...")

        results = sync_cloudflare_acme_rules(conn, CONFIG, website_id=website_id)
        print("\n--- Sync Results ---")
        for r in results:
            domain = r.get("domain")
            status = r.get("status") or r.get("rule_result", {}).get("status")
            rule_id = r.get("rule_result", {}).get("rule_id") or r.get("rule_result", {}).get("error") or r.get("reason")
            print(f"  Domain: {domain:<30} | Status: {status:<10} | Info: {rule_id}")

    print("\nSync completed.")


if __name__ == "__main__":
    main()
