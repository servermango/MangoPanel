import json
import os
import sqlite3
import time
from pathlib import Path

from .mail import dkim_dns_value, ensure_mailbox_storage, generate_dkim_material, mailbox_storage_path, recommended_dmarc_record, recommended_spf_record, split_mailbox_address
from .providers import ACME_PROVIDER_LOCAL, DNS_PROVIDER_CLOUDFLARE, DNS_PROVIDER_LOCAL, DNS_PROVIDER_LOCAL_POWERDNS, MAIL_EDGE_PROVIDER_SHARED
from .security import encrypt_secret, hash_password


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
  totp_secret TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'super_admin',
  status TEXT NOT NULL DEFAULT 'active',
  totp_secret TEXT,
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

CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  window_started_at INTEGER NOT NULL,
  failures INTEGER NOT NULL DEFAULT 0,
  blocked_until INTEGER NOT NULL DEFAULT 0,
  block_seconds INTEGER NOT NULL DEFAULT 0,
  last_alert_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(ip_address, actor_type)
);

CREATE TABLE IF NOT EXISTS impersonation_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  admin_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
  proxied INTEGER NOT NULL DEFAULT 0,
  system_record INTEGER NOT NULL DEFAULT 0,
  locked INTEGER NOT NULL DEFAULT 0,
  provider_metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_zones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  domain_id INTEGER NOT NULL UNIQUE REFERENCES domains(id),
  zone_name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'local-dev-dns',
  status TEXT NOT NULL DEFAULT 'active',
  serial INTEGER NOT NULL DEFAULT 1,
  nameservers_json TEXT NOT NULL DEFAULT '[]',
  provider_state_json TEXT NOT NULL DEFAULT '{}',
  last_synced_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  config_json TEXT NOT NULL DEFAULT '{}',
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_provider_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
  display_name TEXT NOT NULL,
  account_name TEXT NOT NULL DEFAULT '',
  external_account_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(provider_id, display_name)
);

CREATE TABLE IF NOT EXISTS dns_provider_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_account_id INTEGER NOT NULL UNIQUE REFERENCES dns_provider_accounts(id),
  credential_kind TEXT NOT NULL DEFAULT 'api_token',
  secret_label TEXT NOT NULL DEFAULT '',
  encrypted_secret TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'stored',
  last_validated_at TEXT,
  validation_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_provider_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope_type TEXT NOT NULL,
  scope_id INTEGER NOT NULL DEFAULT 0,
  provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
  provider_account_id INTEGER REFERENCES dns_provider_accounts(id),
  status TEXT NOT NULL DEFAULT 'active',
  policy_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(scope_type, scope_id)
);

CREATE TABLE IF NOT EXISTS dns_provider_health_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
  provider_account_id INTEGER REFERENCES dns_provider_accounts(id),
  status TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  details_json TEXT NOT NULL DEFAULT '{}',
  checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_zone_exports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  zone_name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  export_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL DEFAULT 'system',
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

CREATE TABLE IF NOT EXISTS mailbox_launch_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
  token_id TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL DEFAULT 'webmail',
  status TEXT NOT NULL DEFAULT 'active',
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  provider_state_json TEXT NOT NULL DEFAULT '{}',
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

CREATE TABLE IF NOT EXISTS acme_certificate_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  website_id INTEGER REFERENCES websites(id),
  domain_id INTEGER REFERENCES domains(id),
  certificate_id INTEGER REFERENCES ssl_certificates(id),
  domain TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'local-dev-acme',
  status TEXT NOT NULL DEFAULT 'pending',
  challenge_type TEXT NOT NULL DEFAULT 'http-01',
  challenge_token TEXT NOT NULL DEFAULT '',
  challenge_value TEXT NOT NULL DEFAULT '',
  requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  issued_at TEXT,
  expires_at TEXT,
  provider_state_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(account_id, domain, provider)
);

CREATE TABLE IF NOT EXISTS mail_domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  domain_id INTEGER REFERENCES domains(id),
  spf_policy TEXT NOT NULL DEFAULT 'v=spf1 mx -all',
  dkim_private_key TEXT NOT NULL DEFAULT '',
  dkim_public_key TEXT,
  dkim_selector TEXT NOT NULL DEFAULT 'mango',
  dmarc_policy TEXT NOT NULL DEFAULT 'v=DMARC1; p=quarantine',
  catch_all_enabled INTEGER NOT NULL DEFAULT 0,
  catch_all_destination TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mail_edge_routes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  mail_domain_id INTEGER NOT NULL UNIQUE REFERENCES mail_domains(id),
  domain_id INTEGER REFERENCES domains(id),
  domain TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'shared-mail-edge',
  edge_host TEXT NOT NULL DEFAULT '',
  smtp_enabled INTEGER NOT NULL DEFAULT 1,
  pop_enabled INTEGER NOT NULL DEFAULT 1,
  imap_enabled INTEGER NOT NULL DEFAULT 1,
  jmap_enabled INTEGER NOT NULL DEFAULT 1,
  webmail_enabled INTEGER NOT NULL DEFAULT 1,
  manifest_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  last_synced_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

CREATE TABLE IF NOT EXISTS mail_autoresponders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
  subject TEXT NOT NULL DEFAULT 'Auto-reply',
  body TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mail_delivery_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
  mailbox_id INTEGER REFERENCES mailboxes(id),
  action TEXT NOT NULL,
  direction TEXT NOT NULL DEFAULT 'outbound',
  source_email TEXT NOT NULL DEFAULT '',
  destination_email TEXT NOT NULL DEFAULT '',
  details_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'queued',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webmail_login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_key TEXT NOT NULL UNIQUE,
  attempts INTEGER NOT NULL DEFAULT 0,
  first_failed_at INTEGER NOT NULL DEFAULT 0,
  last_failed_at INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  last_ip TEXT NOT NULL DEFAULT '',
  last_email TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
        CREATE TABLE IF NOT EXISTS auth_attempts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip_address TEXT NOT NULL,
          actor_type TEXT NOT NULL,
          window_started_at INTEGER NOT NULL,
          failures INTEGER NOT NULL DEFAULT 0,
          blocked_until INTEGER NOT NULL DEFAULT 0,
          block_seconds INTEGER NOT NULL DEFAULT 0,
          last_alert_at INTEGER NOT NULL DEFAULT 0,
          UNIQUE(ip_address, actor_type)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS impersonation_tokens (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          admin_id INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
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
    ensure_table_columns(
        conn,
        "hosting_accounts",
        {
            "ssh_access": "TEXT NOT NULL DEFAULT 'disabled'",
            "ssh_password": "TEXT",
        },
    )
    ensure_table_columns(
        conn,
        "resource_usage_samples",
        {
            "memory_limit_mb": "REAL NOT NULL DEFAULT 0",
            "storage_limit_mb": "REAL NOT NULL DEFAULT 0",
            "source": "TEXT NOT NULL DEFAULT 'panel'",
        },
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
            "max_attempts": "INTEGER NOT NULL DEFAULT 3",
            "not_before_at": "TEXT",
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
            "dns_default_provider": "TEXT NOT NULL DEFAULT 'local_powerdns'",
            "dns_allowed_providers_json": "TEXT NOT NULL DEFAULT '[\"local_powerdns\"]'",
            "dns_default_provider_account_id": "INTEGER",
            "dns_customer_editable": "INTEGER NOT NULL DEFAULT 1",
            "dns_max_records_per_domain": "INTEGER NOT NULL DEFAULT 100",
            "dns_allowed_record_types_json": "TEXT NOT NULL DEFAULT '[\"A\",\"AAAA\",\"CNAME\",\"MX\",\"TXT\",\"NS\",\"SRV\",\"CAA\"]'",
            "dns_min_ttl": "INTEGER NOT NULL DEFAULT 60",
            "dns_wildcard_records_allowed": "INTEGER NOT NULL DEFAULT 1",
            "dns_cloudflare_proxy_allowed": "INTEGER NOT NULL DEFAULT 0",
            "dns_dnssec_allowed": "INTEGER NOT NULL DEFAULT 0",
            "dns_dnssec_required": "INTEGER NOT NULL DEFAULT 0",
        },
    )
    ensure_table_columns(
        conn,
        "websites",
        {
            "php_ini": "TEXT NOT NULL DEFAULT '{}'",
            "index_enabled": "INTEGER NOT NULL DEFAULT 0",
            "modsec_enabled": "INTEGER NOT NULL DEFAULT 1",
            "analytics_enabled": "INTEGER NOT NULL DEFAULT 1",
        },
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_zones (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          domain_id INTEGER NOT NULL UNIQUE REFERENCES domains(id),
          zone_name TEXT NOT NULL,
          provider TEXT NOT NULL DEFAULT 'local-dev-dns',
          status TEXT NOT NULL DEFAULT 'active',
          serial INTEGER NOT NULL DEFAULT 1,
          nameservers_json TEXT NOT NULL DEFAULT '[]',
          provider_state_json TEXT NOT NULL DEFAULT '{}',
          last_synced_at TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    ensure_table_columns(
        conn,
        "dns_zones",
        {
            "provider": "TEXT NOT NULL DEFAULT 'local-dev-dns'",
            "serial": "INTEGER NOT NULL DEFAULT 1",
            "nameservers_json": "TEXT NOT NULL DEFAULT '[]'",
            "provider_state_json": "TEXT NOT NULL DEFAULT '{}'",
            "provider_account_id": "INTEGER",
            "provider_zone_id": "TEXT",
            "dns_status": "TEXT NOT NULL DEFAULT 'active'",
            "last_nameserver_check_at": "TEXT",
            "dnssec_status": "TEXT NOT NULL DEFAULT 'unknown'",
            "last_synced_at": "TEXT",
            "updated_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        },
    )
    ensure_table_columns(
        conn,
        "dns_records",
        {
            "proxied": "INTEGER NOT NULL DEFAULT 0",
            "system_record": "INTEGER NOT NULL DEFAULT 0",
            "locked": "INTEGER NOT NULL DEFAULT 0",
            "provider_metadata_json": "TEXT NOT NULL DEFAULT '{}'",
            "updated_at": "TEXT",
        },
    )
    ensure_table_columns(
        conn,
        "domains",
        {
            "dns_provider": "TEXT NOT NULL DEFAULT 'local_powerdns'",
            "dns_provider_account_id": "INTEGER",
            "provider_zone_id": "TEXT",
            "nameservers_json": "TEXT NOT NULL DEFAULT '[]'",
            "dns_status": "TEXT NOT NULL DEFAULT 'active'",
            "last_dns_sync_at": "TEXT",
            "last_nameserver_check_at": "TEXT",
            "provider_state_json": "TEXT NOT NULL DEFAULT '{}'",
            "dns_locked": "INTEGER NOT NULL DEFAULT 0",
            "dns_migration_state_json": "TEXT NOT NULL DEFAULT '{}'",
            "previous_dns_provider": "TEXT",
            "previous_dns_provider_account_id": "INTEGER",
            "previous_provider_zone_id": "TEXT",
        },
    )
    ensure_registrar_schema(conn)
    ensure_dns_provider_schema(conn)
    seed_dns_provider_defaults(conn)
    ensure_table_columns(
        conn,
        "cron_jobs",
        {
            "next_run_at": "TEXT",
        },
    )
    ensure_table_columns(
        conn,
        "git_deployments",
        {
            "last_commit": "TEXT",
            "previous_commit": "TEXT",
            "last_deployed_at": "TEXT",
            "last_error": "TEXT",
        },
    )
    ensure_table_columns(conn, "users", {"totp_secret": "TEXT"})
    ensure_table_columns(conn, "admins", {"totp_secret": "TEXT"})
    ensure_table_columns(
        conn,
        "mailboxes",
        {
            "local_part": "TEXT NOT NULL DEFAULT ''",
            "domain": "TEXT NOT NULL DEFAULT ''",
            "storage_path": "TEXT NOT NULL DEFAULT ''",
            "password_hash": "TEXT NOT NULL DEFAULT ''",
            "password_secret": "TEXT NOT NULL DEFAULT ''",
            "mail_domain_id": "INTEGER REFERENCES mail_domains(id)",
            "sent_today_count": "INTEGER NOT NULL DEFAULT 0",
            "sent_today_on": "TEXT NOT NULL DEFAULT ''",
            "last_inbound_at": "TEXT",
            "last_outbound_at": "TEXT",
        },
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mailbox_launch_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
          token_id TEXT NOT NULL UNIQUE,
          purpose TEXT NOT NULL DEFAULT 'webmail',
          status TEXT NOT NULL DEFAULT 'active',
          expires_at INTEGER NOT NULL,
          consumed_at INTEGER,
          provider_state_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mail_messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
          direction TEXT NOT NULL DEFAULT 'inbound',
          sender_email TEXT NOT NULL DEFAULT '',
          recipients_json TEXT NOT NULL DEFAULT '[]',
          subject TEXT NOT NULL DEFAULT '',
          body_preview TEXT NOT NULL DEFAULT '',
          storage_path TEXT NOT NULL DEFAULT '',
          size_bytes INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'stored',
          folder TEXT NOT NULL DEFAULT 'inbox',
          is_read INTEGER NOT NULL DEFAULT 0,
          message_uid TEXT NOT NULL DEFAULT '',
          headers_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    ensure_table_columns(
        conn,
        "mail_messages",
        {
            "folder": "TEXT NOT NULL DEFAULT 'inbox'",
            "is_read": "INTEGER NOT NULL DEFAULT 0",
            "message_uid": "TEXT NOT NULL DEFAULT ''",
            "headers_json": "TEXT NOT NULL DEFAULT '{}'",
        },
    )
    ensure_table_columns(
        conn,
        "mail_domains",
        {
            "spf_policy": "TEXT NOT NULL DEFAULT 'v=spf1 mx -all'",
            "dkim_private_key": "TEXT NOT NULL DEFAULT ''",
            "dmarc_policy": "TEXT NOT NULL DEFAULT 'v=DMARC1; p=quarantine'",
            "catch_all_enabled": "INTEGER NOT NULL DEFAULT 0",
            "catch_all_destination": "TEXT NOT NULL DEFAULT ''",
        },
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS acme_certificate_orders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          website_id INTEGER REFERENCES websites(id),
          domain_id INTEGER REFERENCES domains(id),
          certificate_id INTEGER REFERENCES ssl_certificates(id),
          domain TEXT NOT NULL,
          provider TEXT NOT NULL DEFAULT 'local-dev-acme',
          status TEXT NOT NULL DEFAULT 'pending',
          challenge_type TEXT NOT NULL DEFAULT 'http-01',
          challenge_token TEXT NOT NULL DEFAULT '',
          challenge_value TEXT NOT NULL DEFAULT '',
          requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          issued_at TEXT,
          expires_at TEXT,
          provider_state_json TEXT NOT NULL DEFAULT '{}',
          UNIQUE(account_id, domain, provider)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mail_edge_routes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          mail_domain_id INTEGER NOT NULL UNIQUE REFERENCES mail_domains(id),
          domain_id INTEGER REFERENCES domains(id),
          domain TEXT NOT NULL,
          provider TEXT NOT NULL DEFAULT 'shared-mail-edge',
          edge_host TEXT NOT NULL DEFAULT '',
          smtp_enabled INTEGER NOT NULL DEFAULT 1,
          pop_enabled INTEGER NOT NULL DEFAULT 1,
          imap_enabled INTEGER NOT NULL DEFAULT 1,
          jmap_enabled INTEGER NOT NULL DEFAULT 1,
          webmail_enabled INTEGER NOT NULL DEFAULT 1,
          manifest_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'active',
          last_synced_at TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
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
        CREATE TABLE IF NOT EXISTS mail_autoresponders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
          subject TEXT NOT NULL DEFAULT 'Auto-reply',
          body TEXT NOT NULL DEFAULT '',
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mail_delivery_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          mailbox_id INTEGER REFERENCES mailboxes(id),
          action TEXT NOT NULL,
          direction TEXT NOT NULL DEFAULT 'outbound',
          source_email TEXT NOT NULL DEFAULT '',
          destination_email TEXT NOT NULL DEFAULT '',
          details_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'queued',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mail_messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
          direction TEXT NOT NULL DEFAULT 'inbound',
          sender_email TEXT NOT NULL DEFAULT '',
          recipients_json TEXT NOT NULL DEFAULT '[]',
          subject TEXT NOT NULL DEFAULT '',
          body_preview TEXT NOT NULL DEFAULT '',
          storage_path TEXT NOT NULL DEFAULT '',
          size_bytes INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'stored',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS webmail_login_attempts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          attempt_key TEXT NOT NULL UNIQUE,
          attempts INTEGER NOT NULL DEFAULT 0,
          first_failed_at INTEGER NOT NULL DEFAULT 0,
          last_failed_at INTEGER NOT NULL DEFAULT 0,
          locked_until INTEGER NOT NULL DEFAULT 0,
          last_ip TEXT NOT NULL DEFAULT '',
          last_email TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
        """
        CREATE TABLE IF NOT EXISTS dns_zone_exports (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain_id INTEGER NOT NULL REFERENCES domains(id),
          account_id INTEGER NOT NULL REFERENCES hosting_accounts(id),
          zone_name TEXT NOT NULL,
          provider TEXT NOT NULL DEFAULT '',
          export_json TEXT NOT NULL DEFAULT '{}',
          created_by TEXT NOT NULL DEFAULT 'system',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
    ]:
        conn.execute(stmt)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_zone_exports_domain ON dns_zone_exports(domain_id, created_at)")
    seed_legacy_database_users(conn)


def ensure_table_columns(conn, table, columns):
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def ensure_registrar_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS registrar_providers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          settings_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS registrar_credentials (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider_id INTEGER NOT NULL UNIQUE REFERENCES registrar_providers(id),
          encrypted_secret TEXT NOT NULL DEFAULT '',
          secret_label TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'stored',
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    for key, label in (("resellerclub", "ResellerClub / PDR"), ("domainnameapi", "DomainNameAPI"), ("cloudflare", "Cloudflare")):
        conn.execute("INSERT OR IGNORE INTO registrar_providers(key, display_name) VALUES (?, ?)", (key, label))
    ensure_table_columns(conn, "domains", {
        "registrar_provider_id": "INTEGER",
        "registrar_domain_id": "TEXT NOT NULL DEFAULT ''",
        "registrar_status": "TEXT NOT NULL DEFAULT 'external'",
        "registrar_state_json": "TEXT NOT NULL DEFAULT '{}'",
        "nameserver_source": "TEXT NOT NULL DEFAULT 'default'",
        "custom_nameservers_json": "TEXT NOT NULL DEFAULT '[]'",
        "last_registrar_sync_at": "TEXT",
    })


def ensure_dns_provider_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_providers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key TEXT NOT NULL UNIQUE,
          kind TEXT NOT NULL,
          display_name TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          config_json TEXT NOT NULL DEFAULT '{}',
          capabilities_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_provider_accounts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
          display_name TEXT NOT NULL,
          account_name TEXT NOT NULL DEFAULT '',
          external_account_id TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'active',
          metadata_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(provider_id, display_name)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_provider_credentials (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider_account_id INTEGER NOT NULL UNIQUE REFERENCES dns_provider_accounts(id),
          credential_kind TEXT NOT NULL DEFAULT 'api_token',
          secret_label TEXT NOT NULL DEFAULT '',
          encrypted_secret TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'stored',
          last_validated_at TEXT,
          validation_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_provider_assignments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scope_type TEXT NOT NULL,
          scope_id INTEGER NOT NULL DEFAULT 0,
          provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
          provider_account_id INTEGER REFERENCES dns_provider_accounts(id),
          status TEXT NOT NULL DEFAULT 'active',
          policy_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(scope_type, scope_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_provider_health_checks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
          provider_account_id INTEGER REFERENCES dns_provider_accounts(id),
          status TEXT NOT NULL,
          message TEXT NOT NULL DEFAULT '',
          details_json TEXT NOT NULL DEFAULT '{}',
          checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def seed_dns_provider_defaults(conn):
    local_config = {
        "nameservers": ["ns1.mango.test", "ns2.mango.test"],
        "public_ipv4": "127.0.0.1",
        "public_ipv6": "",
        "soa_email": "hostmaster.mango.test",
        "default_ttl": 300,
        "glue_record_notes": "Register glue records for the configured nameserver hostnames at the registrar before using local authoritative DNS in production.",
    }
    local_capabilities = {
        "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"],
        "supports_dnssec": False,
        "supports_health_checks": True,
        "phase": "foundation",
    }
    cloudflare_capabilities = {
        "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"],
        "supports_proxy": True,
        "supports_auto_ttl": True,
        "supports_dnssec": True,
        "phase": "foundation",
    }
    conn.execute(
        """
        INSERT OR IGNORE INTO dns_providers(key, kind, display_name, status, config_json, capabilities_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            DNS_PROVIDER_LOCAL_POWERDNS,
            "local",
            "Local PowerDNS",
            "active",
            json.dumps(local_config, sort_keys=True),
            json.dumps(local_capabilities, sort_keys=True),
        ),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO dns_providers(key, kind, display_name, status, config_json, capabilities_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            DNS_PROVIDER_CLOUDFLARE,
            "cloudflare",
            "Cloudflare",
            "inactive",
            json.dumps({}, sort_keys=True),
            json.dumps(cloudflare_capabilities, sort_keys=True),
        ),
    )
    local_provider = conn.execute("SELECT id FROM dns_providers WHERE key = ?", (DNS_PROVIDER_LOCAL_POWERDNS,)).fetchone()
    if local_provider:
        conn.execute(
            """
            INSERT OR IGNORE INTO dns_provider_assignments(scope_type, scope_id, provider_id, status, policy_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "global",
                0,
                local_provider["id"],
                "active",
                json.dumps({"mode": DNS_PROVIDER_LOCAL_POWERDNS, "source": "default"}, sort_keys=True),
            ),
        )


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
        mailbox_password_plain = "ChangeMe-DevOnly-123!"
        mailbox_password = hash_password(mailbox_password_plain)
        mailbox_password_secret = encrypt_secret(mailbox_password_plain, "dev-only-change-me")

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
            UPDATE plans
            SET dns_default_provider = ?, dns_allowed_providers_json = ?, dns_customer_editable = ?,
                dns_max_records_per_domain = ?, dns_min_ttl = ?, dns_wildcard_records_allowed = ?
            WHERE id = ?
            """,
            (
                DNS_PROVIDER_LOCAL_POWERDNS,
                json.dumps([DNS_PROVIDER_LOCAL_POWERDNS], sort_keys=True),
                1,
                100,
                60,
                1,
                plan_id,
            ),
        )

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
            INSERT OR IGNORE INTO websites(account_id, domain, document_root, php_version, ssl_status, analytics_enabled, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                "example.mango.test",
                str(Path(account_base_path) / "domains" / "example.mango.test" / "public_html"),
                "8.3",
                "local-dev",
                1,
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
        nameservers_json = json.dumps(["ns1.mango.test", "ns2.mango.test"])
        conn.execute(
            """
            UPDATE domains
            SET dns_provider = ?, nameservers_json = ?, dns_status = ?, provider_state_json = ?
            WHERE id = ?
            """,
            (
                DNS_PROVIDER_LOCAL_POWERDNS,
                nameservers_json,
                "active",
                json.dumps({"fixture": "dev-seed", "provider": DNS_PROVIDER_LOCAL_POWERDNS}, sort_keys=True),
                domain_id,
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO dns_zones(account_id, domain_id, zone_name, provider, status, nameservers_json, provider_state_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                domain_id,
                "example.mango.test",
                DNS_PROVIDER_LOCAL,
                "active",
                nameservers_json,
                json.dumps({"fixture": "dev-seed", "adapter": DNS_PROVIDER_LOCAL}),
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO mail_domains(account_id, domain_id, dkim_selector, status)
            VALUES (?, ?, ?, ?)
            """,
            (account_id, domain_id, "mango", "active"),
        )
        mail_domain_id = conn.execute(
            "SELECT id FROM mail_domains WHERE account_id = ? AND domain_id = ?",
            (account_id, domain_id),
        ).fetchone()["id"]
        dkim_material = generate_dkim_material("mango")
        conn.execute(
            """
            UPDATE mail_domains
            SET spf_policy = ?, dkim_private_key = ?, dkim_public_key = ?, dkim_selector = ?, dmarc_policy = ?, catch_all_enabled = ?, catch_all_destination = ?, status = ?
            WHERE id = ?
            """,
            (
                recommended_spf_record("mail-u000001.localhost"),
                dkim_material["private_key"],
                dkim_material["public_key"],
                dkim_material["selector"],
                recommended_dmarc_record("example.mango.test"),
                1,
                "hello@example.mango.test",
                "active",
                mail_domain_id,
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO dns_records(domain_id, type, name, value, ttl)
            VALUES (?, ?, ?, ?, ?)
            """,
            (domain_id, "TXT", "mango._domainkey", dkim_dns_value(dkim_material["public_key"]), 300),
        )

        default_records = [
            ("A", "@", "127.0.0.1", 300, None),
            ("CNAME", "www", "example.mango.test", 300, None),
            ("MX", "@", "mail.mango.test", 300, 10),
            ("TXT", "@", recommended_spf_record("mail-u000001.localhost"), 300, None),
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

        cert = conn.execute(
            "SELECT id FROM ssl_certificates WHERE account_id = ? AND website_id = ? AND domain = ?",
            (account_id, website_id, "example.mango.test"),
        ).fetchone()
        if cert:
            certificate_id = cert["id"]
        else:
            certificate_id = conn.execute(
                """
                INSERT INTO ssl_certificates(account_id, website_id, domain, status, issued_at, expires_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime('now', '+90 days'))
                """,
                (account_id, website_id, "example.mango.test", "local-dev"),
            ).lastrowid
        conn.execute(
            """
            INSERT OR IGNORE INTO acme_certificate_orders(
              account_id, website_id, domain_id, certificate_id, domain, provider, status, challenge_type, challenge_token, challenge_value, provider_state_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                website_id,
                domain_id,
                certificate_id,
                "example.mango.test",
                ACME_PROVIDER_LOCAL,
                "issued",
                "http-01",
                "dev-acme-token-example",
                "dev-acme-challenge-example",
                json.dumps({"fixture": "dev-seed", "adapter": ACME_PROVIDER_LOCAL}),
            ),
        )

        conn.execute(
            "INSERT OR IGNORE INTO databases(account_id, name, username, status) VALUES (?, ?, ?, ?)",
            (account_id, "u000001_app", "u000001_app", "active"),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO mailboxes(
              account_id, email, local_part, domain, storage_path, mail_domain_id, quota_mb, status, password_hash, password_secret
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                "hello@example.mango.test",
                "hello",
                "example.mango.test",
                str(mailbox_storage_path(account_base_path, "hello@example.mango.test")),
                mail_domain_id,
                1024,
                "active",
                mailbox_password,
                mailbox_password_secret,
            ),
        )
        ensure_mailbox_storage(mailbox_storage_path(account_base_path, "hello@example.mango.test"))
        conn.execute(
            """
            UPDATE mailboxes
            SET password_hash = ?, password_secret = ?
            WHERE account_id = ? AND email = ?
            """,
            (
                mailbox_password,
                mailbox_password_secret,
                account_id,
                "hello@example.mango.test",
            ),
        )
        mailbox_id = conn.execute(
            "SELECT id FROM mailboxes WHERE account_id = ? AND email = ?",
            (account_id, "hello@example.mango.test"),
        ).fetchone()["id"]
        mail_edge_host = "mail.mango.test"
        conn.execute(
            """
            INSERT OR IGNORE INTO mail_edge_routes(
              account_id, mail_domain_id, domain_id, domain, provider, edge_host, manifest_json, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                mail_domain_id,
                domain_id,
                "example.mango.test",
                MAIL_EDGE_PROVIDER_SHARED,
                mail_edge_host,
                json.dumps(
                    {
                        "fixture": "dev-seed",
                        "edge_host": mail_edge_host,
                        "domain": "example.mango.test",
                        "mailboxes": [{"id": mailbox_id, "email": "hello@example.mango.test"}],
                    }
                ),
                "active",
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO mailbox_launch_tokens(
              account_id, mailbox_id, token_id, purpose, status, expires_at, provider_state_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                mailbox_id,
                "dev-webmail-u000001-hello",
                "webmail",
                "active",
                int(time.time()) + 3600,
                json.dumps({"fixture": "dev-seed", "provider": MAIL_EDGE_PROVIDER_SHARED}),
            ),
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
