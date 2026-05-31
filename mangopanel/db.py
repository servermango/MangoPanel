import json
import sqlite3
import time
from pathlib import Path

from .security import hash_password


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  totp_secret TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'super_admin',
  status TEXT NOT NULL DEFAULT 'active',
  totp_secret TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL,
  actor_id INTEGER NOT NULL,
  token_id TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  cpu_limit TEXT NOT NULL,
  memory_mb INTEGER NOT NULL,
  storage_mb INTEGER NOT NULL,
  inode_limit INTEGER NOT NULL,
  max_websites INTEGER NOT NULL,
  max_databases INTEGER NOT NULL,
  max_mailboxes INTEGER NOT NULL,
  max_cron_jobs INTEGER NOT NULL,
  daily_email_limit INTEGER NOT NULL,
  backup_retention_days INTEGER NOT NULL,
  max_processes INTEGER NOT NULL DEFAULT 120,
  php_workers INTEGER NOT NULL DEFAULT 60,
  bandwidth_limit_gb INTEGER NOT NULL DEFAULT 0,
  nameserver1 TEXT NOT NULL DEFAULT 'ns1.mangopanel.com',
  nameserver2 TEXT NOT NULL DEFAULT 'ns2.mangopanel.com',
  server_location TEXT NOT NULL DEFAULT 'Asia (India)',
  backups_location TEXT NOT NULL DEFAULT 'Singapore',
  frontend_frameworks TEXT NOT NULL DEFAULT 'Angular, Astro, Next.js, Nuxt, Parcel, React, React Router, Svelte, SvelteKit, Vite, Vue.js',
  backend_frameworks TEXT NOT NULL DEFAULT 'Astro, Express, Fastify, Hono, NestJS, Next.js, Nuxt, React Router, SvelteKit',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  hostname TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'online',
  docker_version TEXT,
  quota_backend TEXT NOT NULL DEFAULT 'dev-simulator',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS hosting_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  plan_id INTEGER NOT NULL REFERENCES plans(id),
  node_id INTEGER NOT NULL REFERENCES nodes(id),
  username TEXT NOT NULL UNIQUE,
  base_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'provisioning',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS account_stacks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL UNIQUE REFERENCES hosting_accounts(id),
  compose_path TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'simulate',
  status TEXT NOT NULL DEFAULT 'generated',
  services_json TEXT NOT NULL DEFAULT '[]',
  runtime_json TEXT NOT NULL DEFAULT '{}',
  generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_applied_at TEXT,
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS resource_usage_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  sampled_at INTEGER NOT NULL,
  cpu_percent REAL NOT NULL DEFAULT 0,
  memory_mb REAL NOT NULL DEFAULT 0,
  memory_limit_mb REAL NOT NULL DEFAULT 0,
  storage_mb REAL NOT NULL DEFAULT 0,
  storage_limit_mb REAL NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'panel',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_resource_usage_samples_account_time
ON resource_usage_samples(account_id, sampled_at);

CREATE TABLE IF NOT EXISTS access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  website_id INTEGER REFERENCES websites(id),
  domain TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  bytes_sent INTEGER NOT NULL DEFAULT 0,
  ip_address TEXT,
  country TEXT NOT NULL DEFAULT 'Unknown',
  user_agent TEXT,
  referer TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_access_logs_account_domain_time
ON access_logs(account_id, domain, created_at);

CREATE INDEX IF NOT EXISTS idx_access_logs_website_time
ON access_logs(website_id, created_at);

CREATE TABLE IF NOT EXISTS websites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  domain TEXT NOT NULL UNIQUE,
  document_root TEXT NOT NULL,
  php_version TEXT NOT NULL DEFAULT '8.3',
  ssl_status TEXT NOT NULL DEFAULT 'missing',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'managed',
  status TEXT NOT NULL DEFAULT 'active',
  linked_website_id INTEGER REFERENCES websites(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  ttl INTEGER NOT NULL DEFAULT 300,
  priority INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS databases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  name TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  size_mb INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS database_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS database_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  database_id INTEGER NOT NULL REFERENCES databases(id),
  user_id INTEGER NOT NULL REFERENCES database_users(id),
  privileges TEXT NOT NULL DEFAULT 'ALL',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(database_id, user_id)
);

CREATE TABLE IF NOT EXISTS pg_databases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(account_id, name)
);

CREATE TABLE IF NOT EXISTS pg_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(account_id, username)
);

CREATE TABLE IF NOT EXISTS pg_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  database_id INTEGER NOT NULL REFERENCES pg_databases(id),
  user_id INTEGER NOT NULL REFERENCES pg_users(id),
  privileges TEXT NOT NULL DEFAULT 'ALL',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(database_id, user_id)
);

CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  email TEXT NOT NULL UNIQUE,
  quota_mb INTEGER NOT NULL DEFAULT 1024,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cron_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  schedule TEXT NOT NULL,
  command TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'enabled',
  last_run_at TEXT,
  last_exit_code INTEGER,
  last_output TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  artifact_path TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS git_deployments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  repository_url TEXT NOT NULL,
  branch TEXT NOT NULL DEFAULT 'main',
  deploy_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'configured',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  target_type TEXT NOT NULL,
  target_id INTEGER,
  payload TEXT NOT NULL DEFAULT '{}',
  result TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  ip TEXT NOT NULL,
  type TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(account_id, ip)
);

CREATE TABLE IF NOT EXISTS protected_directories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  path TEXT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(account_id, path)
);

CREATE TABLE IF NOT EXISTS redirects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  website_id INTEGER NOT NULL REFERENCES websites(id),
  source_path TEXT NOT NULL,
  target_url TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT '301',
  match_type TEXT NOT NULL DEFAULT 'exact',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT,
  last_used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ftp_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT 'upload',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS remote_mysql_hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  host_ip TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(account_id, host_ip)
);

CREATE TABLE IF NOT EXISTS hotlink_settings (
  account_id INTEGER PRIMARY KEY REFERENCES hosting_accounts(id),
  enabled INTEGER NOT NULL DEFAULT 0,
  allowed_domains TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS job_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL REFERENCES jobs(id),
  level TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL,
  actor_id INTEGER,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id INTEGER,
  ip_address TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS status_components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  group_name TEXT NOT NULL DEFAULT 'Platform',
  status TEXT NOT NULL DEFAULT 'operational',
  sort_order INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS status_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  component_id INTEGER NOT NULL REFERENCES status_components(id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS status_check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id INTEGER NOT NULL REFERENCES status_checks(id),
  status TEXT NOT NULL,
  latency_ms INTEGER,
  message TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS status_incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'investigating',
  published INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS status_incident_updates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES status_incidents(id),
  state TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS status_maintenances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'scheduled',
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  message TEXT NOT NULL,
  published INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS wordpress_installs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  website_id INTEGER NOT NULL UNIQUE REFERENCES websites(id),
  database_id INTEGER REFERENCES databases(id),
  site_title TEXT NOT NULL,
  admin_username TEXT NOT NULL,
  admin_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'installing',
  installed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS script_installs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  website_id INTEGER NOT NULL UNIQUE REFERENCES websites(id),
  script_id TEXT NOT NULL,
  database_id INTEGER REFERENCES databases(id),
  site_title TEXT NOT NULL,
  admin_username TEXT NOT NULL,
  admin_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'installing',
  installed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ssl_certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  website_id INTEGER REFERENCES websites(id),
  domain TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'missing',
  issued_at TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mail_domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  domain_id INTEGER REFERENCES domains(id),
  dkim_public_key TEXT,
  dkim_selector TEXT NOT NULL DEFAULT 'mango',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mail_aliases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  source_email TEXT NOT NULL,
  destination_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mail_forwarders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  source_email TEXT NOT NULL,
  destination_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS collaborators (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL REFERENCES users(id),
  invited_email TEXT NOT NULL,
  hosting_account_id INTEGER REFERENCES hosting_accounts(id),
  permissions_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL REFERENCES admins(id),
  user_id INTEGER REFERENCES users(id),
  hosting_account_id INTEGER REFERENCES hosting_accounts(id),
  note TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS status_subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  token TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS status_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subscriber_id INTEGER NOT NULL REFERENCES status_subscribers(id),
  incident_id INTEGER REFERENCES status_incidents(id),
  sent_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def connect(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(db_path):
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        ensure_schema(conn)
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (1)")


def ensure_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wordpress_installs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          website_id INTEGER NOT NULL UNIQUE REFERENCES websites(id),
          database_id INTEGER REFERENCES databases(id),
          site_title TEXT NOT NULL,
          admin_username TEXT NOT NULL,
          admin_email TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'installing',
          installed_at TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS script_installs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          website_id INTEGER NOT NULL UNIQUE REFERENCES websites(id),
          script_id TEXT NOT NULL,
          database_id INTEGER REFERENCES databases(id),
          site_title TEXT NOT NULL,
          admin_username TEXT NOT NULL,
          admin_email TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'installing',
          installed_at TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS database_users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS database_grants (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          database_id INTEGER NOT NULL REFERENCES databases(id),
          user_id INTEGER NOT NULL REFERENCES database_users(id),
          privileges TEXT NOT NULL DEFAULT 'ALL',
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(database_id, user_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS resource_usage_samples (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          sampled_at INTEGER NOT NULL,
          cpu_percent REAL NOT NULL DEFAULT 0,
          memory_mb REAL NOT NULL DEFAULT 0,
          memory_limit_mb REAL NOT NULL DEFAULT 0,
          storage_mb REAL NOT NULL DEFAULT 0,
          storage_limit_mb REAL NOT NULL DEFAULT 0,
          source TEXT NOT NULL DEFAULT 'panel',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_resource_usage_samples_account_time
        ON resource_usage_samples(account_id, sampled_at)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS access_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          website_id INTEGER REFERENCES websites(id),
          domain TEXT NOT NULL,
          method TEXT NOT NULL,
          path TEXT NOT NULL,
          status_code INTEGER NOT NULL,
          bytes_sent INTEGER NOT NULL DEFAULT 0,
          ip_address TEXT,
          country TEXT NOT NULL DEFAULT 'Unknown',
          user_agent TEXT,
          referer TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_access_logs_account_domain_time
        ON access_logs(account_id, domain, created_at)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_access_logs_website_time
        ON access_logs(website_id, created_at)
        """
    )
    ensure_table_columns(
        conn,
        "jobs",
        {
            "claimed_at": "TEXT",
            "completed_at": "TEXT",
            "attempts": "INTEGER NOT NULL DEFAULT 0",
        },
    )
    ensure_table_columns(
        conn,
        "account_stacks",
        {
            "runtime_json": "TEXT NOT NULL DEFAULT '{}'",
        },
    )
    ensure_table_columns(
        conn,
        "plans",
        {
            "max_processes": "INTEGER NOT NULL DEFAULT 120",
            "php_workers": "INTEGER NOT NULL DEFAULT 60",
            "bandwidth_mb": "INTEGER NOT NULL DEFAULT 0",
            "nameserver_1": "TEXT NOT NULL DEFAULT 'ns1.dns-parking.com'",
            "nameserver_2": "TEXT NOT NULL DEFAULT 'ns2.dns-parking.com'",
            "backup_location": "TEXT NOT NULL DEFAULT 'Singapore'",
            "frontend_frameworks": "TEXT NOT NULL DEFAULT 'Angular, Astro, Next.js, Nuxt, Parcel, React, Vue.js, etc.'",
            "backend_frameworks": "TEXT NOT NULL DEFAULT 'Express, Fastify, Hono, NestJS, Nuxt, React Router, SvelteKit'",
            "nodejs_versions": "TEXT NOT NULL DEFAULT '24.x, 22.x, 20.x and 18.x'",
            "package_managers": "TEXT NOT NULL DEFAULT 'npm (default), yarn and pnpm'",
        },
    )
    ensure_table_columns(
        conn,
        "websites",
        {
            "php_ini": "TEXT NOT NULL DEFAULT '{}'",
            "index_enabled": "INTEGER NOT NULL DEFAULT 0",
            "modsec_enabled": "INTEGER NOT NULL DEFAULT 1",
        },
    )
    ensure_table_columns(conn, "users", {"totp_secret": "TEXT"})
    ensure_table_columns(conn, "admins", {"totp_secret": "TEXT"})
    ensure_table_columns(
        conn,
        "plans",
        {
            "max_processes": "INTEGER NOT NULL DEFAULT 120",
            "php_workers": "INTEGER NOT NULL DEFAULT 60",
            "bandwidth_limit_gb": "INTEGER NOT NULL DEFAULT 0",
            "nameserver1": "TEXT NOT NULL DEFAULT 'ns1.mangopanel.com'",
            "nameserver2": "TEXT NOT NULL DEFAULT 'ns2.mangopanel.com'",
            "server_location": "TEXT NOT NULL DEFAULT 'Asia (India)'",
            "backups_location": "TEXT NOT NULL DEFAULT 'Singapore'",
            "frontend_frameworks": "TEXT NOT NULL DEFAULT 'Angular, Astro, Next.js, Nuxt, Parcel, React, React Router, Svelte, SvelteKit, Vite, Vue.js'",
            "backend_frameworks": "TEXT NOT NULL DEFAULT 'Astro, Express, Fastify, Hono, NestJS, Next.js, Nuxt, React Router, SvelteKit'",
        },
    )
    # Ensure all tables from Project.md that may not exist in older DBs
    for stmt in [
        """
        CREATE TABLE IF NOT EXISTS recovery_codes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id),
          code_hash TEXT NOT NULL,
          used INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ssl_certificates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          website_id INTEGER REFERENCES websites(id),
          domain TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'missing',
          issued_at TEXT,
          expires_at TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mail_domains (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          domain_id INTEGER REFERENCES domains(id),
          dkim_public_key TEXT,
          dkim_selector TEXT NOT NULL DEFAULT 'mango',
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mail_aliases (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          source_email TEXT NOT NULL,
          destination_email TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mail_forwarders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          source_email TEXT NOT NULL,
          destination_email TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS collaborators (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          owner_user_id INTEGER NOT NULL REFERENCES users(id),
          invited_email TEXT NOT NULL,
          hosting_account_id INTEGER REFERENCES hosting_accounts(id),
          permissions_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS support_notes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          admin_id INTEGER NOT NULL REFERENCES admins(id),
          user_id INTEGER REFERENCES users(id),
          hosting_account_id INTEGER REFERENCES hosting_accounts(id),
          note TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS status_subscribers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT NOT NULL UNIQUE,
          token TEXT NOT NULL UNIQUE,
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS status_notifications (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subscriber_id INTEGER NOT NULL REFERENCES status_subscribers(id),
          incident_id INTEGER REFERENCES status_incidents(id),
          sent_at TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS remote_mysql_hosts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          host_ip TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(account_id, host_ip)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS hotlink_settings (
          account_id INTEGER PRIMARY KEY REFERENCES hosting_accounts(id),
          enabled INTEGER NOT NULL DEFAULT 0,
          allowed_domains TEXT NOT NULL DEFAULT '',
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
    ]:
        conn.execute(stmt)
    seed_legacy_database_users(conn)


def ensure_table_columns(conn, table, columns):
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def seed_legacy_database_users(conn):
    rows = conn.execute("SELECT id, account_id, username FROM databases").fetchall()
    for database in rows:
        if not database["username"]:
            continue
        user = conn.execute("SELECT id FROM database_users WHERE username = ?", (database["username"],)).fetchone()
        if user:
            user_id = user["id"]
        else:
            cur = conn.execute(
                """
                INSERT INTO database_users(account_id, username, password_hash, status)
                VALUES (?, ?, ?, ?)
                """,
                (database["account_id"], database["username"], hash_password("ChangeMe-DevOnly-123!"), "active"),
            )
            user_id = cur.lastrowid
        conn.execute(
            """
            INSERT OR IGNORE INTO database_grants(database_id, user_id, privileges, status)
            VALUES (?, ?, ?, ?)
            """,
            (database["id"], user_id, "ALL", "active"),
        )


def row_to_dict(row):
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def rows_to_dicts(rows):
    return [row_to_dict(row) for row in rows]


def log_audit(conn, actor_type, actor_id, action, target_type=None, target_id=None, ip_address=None, metadata=None):
    conn.execute(
        """
        INSERT INTO audit_logs(actor_type, actor_id, action, target_type, target_id, ip_address, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (actor_type, actor_id, action, target_type, target_id, ip_address, json.dumps(metadata or {})),
    )


def log_activity(conn, user_id, action, metadata=None):
    conn.execute(
        "INSERT INTO activity_logs(user_id, action, metadata) VALUES (?, ?, ?)",
        (user_id, action, json.dumps(metadata or {})),
    )


def create_job(conn, job_type, target_type, target_id=None, payload=None, status="queued", result=None):
    cur = conn.execute(
        """
        INSERT INTO jobs(type, status, target_type, target_id, payload, result, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (job_type, status, target_type, target_id, json.dumps(payload or {}), result),
    )
    return cur.lastrowid


def log_job_event(conn, job_id, message, level="info", metadata=None):
    conn.execute(
        "INSERT INTO job_events(job_id, level, message, metadata) VALUES (?, ?, ?, ?)",
        (job_id, level, message, json.dumps(metadata or {})),
    )


def seed_dev_data(db_path, account_root=None):
    init_db(db_path)
    with connect(db_path) as conn:
        default_account_root = Path(__file__).resolve().parent.parent / "user_files" / "accounts"
        account_base_path = str(Path(account_root or default_account_root) / "u000001")
        admin_secret = "JBSWY3DPEHPK3PXP"
        user_secret = "JBSWY3DPEHPK3PXP"
        password_hash = hash_password("ChangeMe-DevOnly-123!")

        conn.execute(
            """
            INSERT OR IGNORE INTO admins(email, password_hash, full_name, role, totp_secret)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("admin@mango.test", password_hash, "Mango Admin", "super_admin", admin_secret),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO users(email, password_hash, full_name, totp_secret)
            VALUES (?, ?, ?, ?)
            """,
            ("owner@example.mango.test", password_hash, "Example Owner", user_secret),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO plans(
              name, cpu_limit, memory_mb, storage_mb, inode_limit, max_websites,
              max_databases, max_mailboxes, max_cron_jobs, daily_email_limit, backup_retention_days
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("Dev Shared Starter", "1 core", 1024, 10240, 100000, 10, 10, 10, 10, 250, 7),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO nodes(name, hostname, status, docker_version, quota_backend, last_seen_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            ("local-m1", "localhost", "online", "dev-docker", "dev-simulator"),
        )

        user_id = conn.execute("SELECT id FROM users WHERE email = ?", ("owner@example.mango.test",)).fetchone()["id"]
        plan_id = conn.execute("SELECT id FROM plans WHERE name = ?", ("Dev Shared Starter",)).fetchone()["id"]
        node_id = conn.execute("SELECT id FROM nodes WHERE name = ?", ("local-m1",)).fetchone()["id"]

        conn.execute(
            """
            INSERT OR IGNORE INTO hosting_accounts(user_id, plan_id, node_id, username, base_path, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, plan_id, node_id, "u000001", account_base_path, "active"),
        )
        account_id = conn.execute("SELECT id FROM hosting_accounts WHERE username = ?", ("u000001",)).fetchone()["id"]

        conn.execute(
            """
            INSERT OR IGNORE INTO websites(account_id, domain, document_root, php_version, ssl_status, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                "example.mango.test",
                str(Path(account_base_path) / "domains" / "example.mango.test" / "public_html"),
                "8.3",
                "local-dev",
                "active",
            ),
        )
        website_id = conn.execute("SELECT id FROM websites WHERE domain = ?", ("example.mango.test",)).fetchone()["id"]

        conn.execute(
            """
            INSERT OR IGNORE INTO domains(account_id, name, kind, status, linked_website_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (account_id, "example.mango.test", "managed", "active", website_id),
        )
        domain_id = conn.execute("SELECT id FROM domains WHERE name = ?", ("example.mango.test",)).fetchone()["id"]

        default_records = [
            ("A", "@", "127.0.0.1", 300, None),
            ("CNAME", "www", "example.mango.test", 300, None),
            ("MX", "@", "mail.mango.test", 300, 10),
            ("TXT", "@", "v=spf1 mx -all", 300, None),
            ("TXT", "_dmarc", "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.mango.test", 300, None),
        ]
        for record in default_records:
            conn.execute(
                """
                INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl, priority)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (domain_id, *record),
            )

        conn.execute(
            "INSERT OR IGNORE INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
            (account_id, "u000001_app", "u000001_app", "active"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO mailboxes(account_id, email, quota_mb, status) VALUES (?, ?, ?, ?)",
            (account_id, "hello@example.mango.test", 1024, "active"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO cron_jobs(account_id, schedule, command, status, last_exit_code, last_output) VALUES (?, ?, ?, ?, ?, ?)",
            (account_id, "*/15 * * * *", "php /home/u000001/domains/example.mango.test/public_html/cron.php", "enabled", 0, "dev seed"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO backups(account_id, kind, status, artifact_path, completed_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (account_id, "manual", "completed", "./var/dev/backups/u000001-seed.tar.gz"),
        )

        components = [
            ("Client panel", "Panel", "operational", 10),
            ("Admin panel", "Panel", "operational", 20),
            ("API", "Platform", "operational", 30),
            ("Website hosting edge", "Hosting", "operational", 40),
            ("DNS", "Hosting", "operational", 50),
            ("Email SMTP", "Email", "operational", 60),
            ("Email IMAP/webmail", "Email", "operational", 70),
            ("Databases", "Hosting", "operational", 80),
            ("Backups", "Platform", "operational", 90),
            ("SSL certificate automation", "Platform", "operational", 100),
            ("File manager", "Hosting", "operational", 110),
        ]
        for component in components:
            conn.execute(
                """
                INSERT OR IGNORE INTO status_components(name, group_name, status, sort_order)
                VALUES (?, ?, ?, ?)
                """,
                component,
            )

        api_component_id = conn.execute("SELECT id FROM status_components WHERE name = ?", ("API",)).fetchone()["id"]
        conn.execute(
            """
            INSERT OR IGNORE INTO status_checks(component_id, name, kind, target)
            VALUES (?, ?, ?, ?)
            """,
            (api_component_id, "API /health", "http", "http://127.0.0.1:8000/health"),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO status_check_results(check_id, status, latency_ms, message)
            SELECT id, 'up', 12, 'Seeded dev check passed' FROM status_checks WHERE name = ?
            """,
            ("API /health",),
        )

        if conn.execute("SELECT COUNT(*) AS count FROM status_incidents").fetchone()["count"] == 0:
            incident_id = conn.execute(
                """
                INSERT INTO status_incidents(title, severity, state, published)
                VALUES (?, ?, ?, ?)
                """,
                ("Dev incident example", "minor", "resolved", 1),
            ).lastrowid
            conn.execute(
                """
                INSERT INTO status_incident_updates(incident_id, state, message)
                VALUES (?, ?, ?)
                """,
                (incident_id, "resolved", "Seed data incident used to verify public status history."),
            )

        stack_count = conn.execute("SELECT COUNT(*) AS count FROM account_stacks WHERE account_id = ?", (account_id,)).fetchone()["count"]
        queued_count = conn.execute(
            """
            SELECT COUNT(*) AS count FROM jobs
            WHERE type = 'provision_hosting_account'
              AND target_type = 'hosting_account'
              AND target_id = ?
              AND status IN ('queued', 'running')
            """,
            (account_id,),
        ).fetchone()["count"]
        if stack_count == 0 and queued_count == 0:
            create_job(conn, "provision_hosting_account", "hosting_account", account_id, {"dev_seed": True})
        seed_legacy_database_users(conn)
        log_audit(conn, "system", None, "dev_seed", "hosting_account", account_id, metadata={"ts": int(time.time())})
        log_activity(conn, user_id, "dev_seed_completed", {"account": "u000001"})
