#!/usr/bin/env python3
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from mangopanel.config import CONFIG
from mangopanel.db import connect

DEFAULT_WORDPRESS_HTACCESS = """# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"""


def is_wordpress_directory(dir_path):
    path = Path(dir_path)
    if not path.is_dir():
        return False
    indicators = [
        path / "wp-config.php",
        path / "wp-load.php",
        path / "wp-settings.php",
        path / "wp-includes",
        path / ".wordpress-install",
    ]
    return any(ind.exists() for ind in indicators)


def ensure_htaccess_for_directory(dir_path):
    path = Path(dir_path)
    if not is_wordpress_directory(path):
        return {"status": "skipped", "reason": "not_wordpress"}

    htaccess_file = path / ".htaccess"
    if htaccess_file.exists() and htaccess_file.stat().st_size > 0:
        return {"status": "exists", "path": str(htaccess_file)}

    try:
        htaccess_file.write_text(DEFAULT_WORDPRESS_HTACCESS, encoding="utf-8")
        try:
            os.chmod(htaccess_file, 0o644)
        except OSError:
            pass
        return {"status": "created", "path": str(htaccess_file)}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "path": str(htaccess_file)}


def main():
    print("Scanning for WordPress sites across MangoPanel...")
    scanned_roots = set()

    # 1. Scan DB websites
    if CONFIG.db_path.exists():
        with connect(CONFIG.db_path) as conn:
            rows = conn.execute("SELECT id, domain, document_root FROM websites WHERE status != 'deleted'").fetchall()
            for r in rows:
                doc_root = r["document_root"]
                if doc_root and Path(doc_root).is_dir():
                    scanned_roots.add(Path(doc_root).resolve())

    # 2. Scan accounts directory on disk
    accounts_dir = CONFIG.account_root
    if accounts_dir.exists():
        for wp_cfg in accounts_dir.glob("**/public_html/wp-config.php"):
            scanned_roots.add(wp_cfg.parent.resolve())

    print(f"Found {len(scanned_roots)} site directories to evaluate.\n")
    
    created_count = 0
    existing_count = 0
    skipped_count = 0
    error_count = 0

    for root_path in sorted(scanned_roots):
        res = ensure_htaccess_for_directory(root_path)
        status = res["status"]
        if status == "created":
            created_count += 1
            print(f"  [CREATED]  {root_path} -> .htaccess created")
        elif status == "exists":
            existing_count += 1
            print(f"  [EXISTS]   {root_path} -> .htaccess already exists")
        elif status == "skipped":
            skipped_count += 1
        elif status == "error":
            error_count += 1
            print(f"  [ERROR]    {root_path} -> {res.get('error')}")

    print("\n--- Summary ---")
    print(f"  Created:  {created_count}")
    print(f"  Existing: {existing_count}")
    print(f"  Skipped:  {skipped_count} (Non-WordPress sites)")
    print(f"  Errors:   {error_count}")


if __name__ == "__main__":
    main()
