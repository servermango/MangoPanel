# MangoPanel

MangoPanel is a self-hosted shared hosting control panel inspired by the Hostinger hPanel experience. The MVP goal is to let a hosting provider run a usable shared hosting business from one server or a small group of servers: create plans, provision customer hosting accounts, let customers manage websites/domains/email/databases/files/backups, and let admins operate the infrastructure safely.

The first release focuses on shared hosting. VPS/KVM hosting is a later module and should not block the shared hosting MVP.

## Product Goals

- Provide a clean client panel for non-technical customers to manage hosting without SSH.
- Provide an admin panel for provisioning, support, abuse handling, server operations, and quota control.
- Run customer workloads in isolated Docker account stacks with hard limits for CPU, memory, storage, inodes, processes, and outbound mail.
- Support multiple websites/domains per hosting account.
- Use SQLite for the MangoPanel control plane in the MVP.
- Keep privileged host operations outside the public API by using a local node agent.
- Make every important infrastructure action auditable and recoverable.

## MVP Scope

### Included

- Client SPA served from a Docker container.
- Admin SPA served from a Docker container.
- Client API and Admin API, preferably one backend app with separate route groups and RBAC.
- SQLite control-plane database with migrations, WAL mode, scheduled backups, and integrity checks.
- Mandatory JWT-based authentication with TOTP 2FA for users and admins.
- Docker-based shared hosting account stacks.
- Website management: add domain, subdomain, temporary domain, redirects, document root, status, logs.
- DNS zone management for domains using MangoPanel nameservers.
- SSL certificate issue, install, force HTTPS, renew, revoke.
- File manager and SFTP/FTP credential management.
- MySQL-compatible database management with phpMyAdmin access.
- Email platform roadmap: shared public mail edge, mailbox-native storage, DNS/auth setup, SMTP/POP/IMAP/JMAP access, independent webmail, and plan-based mail limits.
- Backups: automatic files and database backups, manual backup, download, restore.
- Cron jobs.
- Git deployment for public/private repositories.
- Basic WordPress installer as the only one-click app in the MVP.
- Resource usage dashboards and activity logs.
- Local development and test profile that runs the complete MVP flow on an Apple Silicon Mac.
- Public and admin-managed status page for incidents, maintenance, service health, and uptime history.
- Admin plan management, user management, hosting account lifecycle, server health, job queue, suspend/unsuspend.

### Deferred

- Domain registration, transfer, WHOIS contact management, and payment gateway billing.
- VPS/KVM hosting, snapshots, VPS networking, and VPS storage automation.
- CDN, object storage product, website builder, AI builder, email marketing, reseller automation.
- Multi-region orchestration and automatic live migration.
- Full marketplace of one-click apps beyond WordPress.
- Advanced malware cleanup service. MVP only scans and reports.

### Dashboard Roadmap (To-Dos)

The following client dashboard features are configured in the frontend dashboard layout but require backend integration and UI screens:

- **Files:**
  - [ ] Images manager/gallery
  - [ ] Disk Usage details explorer
  - [ ] Additional FTP Accounts manager
- **Databases:**
  - [ ] MySQL Database Wizard (step-by-step setup)
  - [ ] Remote MySQL access hosts manager
  - [ ] PostgreSQL Databases manager
  - [ ] PostgreSQL Database Wizard
  - [ ] phpPgAdmin web interface launch
- **Email:**
  - [ ] Phase 1 mailbox creation, editing, quotas, and MX/inbound mail foundation.
  - [ ] Phase 2 SPF, DKIM, DMARC, aliases, forwarders, catch-all, and autoresponders.
  - [ ] Phase 3 SMTP, POP, IMAP, JMAP, one-click panel launch, and independent per-mailbox webmail login URLs.
  - [ ] Replace the current mail-capture flow with the shared mail edge and mailbox-native storage path.
  - [ ] Deliver a Hostinger-style mailbox experience with a one-click launch button and a separate direct webmail URL.
- **Metrics:**
  - [ ] Visitors list & details
  - [ ] Errors log explorer
  - [ ] Bandwidth usage detailed graphs
  - [ ] Raw Access logs downloader
  - [ ] Webalizer stats interface
  - [ ] Resource Usage detailed details (CPU/Memory/IO limits tracker)
- **Security:**
  - [ ] API Tokens generator (access keys)
  - [ ] SSL/TLS manager (keys, CSRs, certificates upload)
  - [ ] ModSecurity toggle per domain
  - [ ] Two-Factor Authentication (mandatory/optional configuration)
- **Domains:**
  - [ ] Site Builder integration
  - [ ] Redirects manager (301/302 redirects configuration)

## Roles

- Customer owner: owns hosting accounts, domains, mailboxes, databases, and collaborators.
- Customer collaborator: limited access granted by owner per hosting account or website.
- Support admin: can inspect metadata, view logs, trigger safe actions, and create support notes.
- System admin: can manage nodes, plans, users, infrastructure settings, suspensions, and backups.
- Super admin: can manage admin accounts, global security settings, and destructive actions.

## High-Level Architecture

### Runtime Components

- `mangopanel-web`: serves the client SPA and admin SPA.
- `mangopanel-api`: HTTP API for client and admin panels.
- `mangopanel-agent`: privileged local agent running on each hosting node. It owns Docker, filesystem, quota, firewall, DNS, mail, backup, and certificate operations.
- `mangopanel-edge`: public HTTP/HTTPS edge proxy that routes domains to the correct account container and handles ACME challenges.
- `mangopanel-dns`: authoritative DNS service for managed zones.
- `mangopanel-mail`: shared public mail edge plus mailbox-native storage and webmail handoff.
- `mangopanel-backup`: scheduled backup worker using restic or borg.
- `mangopanel-status`: public status page and status API.
- Customer account stacks: isolated Docker networks and containers per hosting account.

### Mail Architecture

- Mail storage is mailbox-native: each mailbox gets its own on-disk directory and the mailbox directory is the source of truth for messages and attachments.
- A shared public mail edge handles the standard Internet-facing mail ports and maps each authenticated session to the correct hosting account and mailbox backend.
- MangoPanel remains the control plane for users, hosting accounts, domains, mailboxes, quotas, aliases, and DNS intent.
- Mailboxes are isolated logically by account ownership, domain ownership, session scope, and quota enforcement.
- The client panel provides one-click webmail launch for a mailbox.
- The same mailbox also has a standalone login URL that can be opened directly, independent of the hosting panel session.
- The webmail portal is a separate UI layer on top of the mailbox store, so it can be branded and iterated without changing mail delivery.

### Frontend

- Client panel: Vue.js CDN-based SPA.
- Admin panel: Vue.js CDN-based SPA.
- Both SPAs are static assets served by `mangopanel-web`.
- Keep panels separate at routing and authorization level:
  - `/` or `/client`
  - `/admin`
- Use API-driven screens. No direct Docker, filesystem, or database access from frontend.

### Backend API

- One backend service is acceptable for MVP if route groups are cleanly separated:
  - `/api/client/*`
  - `/api/admin/*`
  - `/api/public/*`
- API creates desired-state records and job records in SQLite.
- API never mounts the Docker socket and never runs privileged shell commands.
- Agent polls signed jobs from SQLite or a local queue and reports status back.
- All state-changing actions write audit log entries.

### Database

SQLite is used for MangoPanel control-plane data only.

MVP requirements:

- WAL mode enabled.
- Foreign keys enabled.
- Versioned migrations.
- Daily SQLite dump plus file-level backup.
- Health check that verifies database file accessibility, migration version, and integrity.
- Customer website databases are MySQL-compatible databases, not stored in SQLite.

## Shared Hosting Model

### Core Concepts

- Plan: quota template and feature limits.
- Hosting account: a customer's isolated shared hosting subscription attached to a plan.
- Website: one domain/subdomain/temporary domain with a document root and runtime settings.
- Domain: a DNS/identity object that can be attached to websites, email, and redirects.
- Account stack: containers, network, volumes, quotas, and config for one hosting account.

### Directory Layout

Use stable numeric user IDs in paths:

```text
/home/mangopanel/u000001/
  account.json
  domains/
    example.com/
      public_html/
      logs/
      tmp/
      .runtime/
  databases/
  mail/
    example.com/
  backups/
  git/
  ssl/
```

Document roots must never point outside the account base directory.

### Account Docker Stack

Each hosting account gets an isolated Docker network and at least:

- `mp-u000001-ols`: OpenLiteSpeed with PHP runtime support.
- `mp-u000001-filebrowser`: browser file manager mounted to the account base directory.
- `mp-u000001-phpmyadmin`: phpMyAdmin, reachable only through authenticated panel launch or private network.
- `mp-u000001-db`: MySQL-compatible database service for MVP isolation, using MariaDB or MySQL.
- `mp-u000001-cron`: cron runner for customer scheduled jobs.
- `mp-u000001-sftp`: SFTP access container with chroot to account base directory.
- `mp-u000001-mail`: account-local mailbox storage and routing metadata used for inbound mail delivery and future submission services.

Notes:

- The public edge proxy routes website traffic to the OpenLiteSpeed container.
- The database container may later be replaced by a shared or clustered database service, but the MVP should expose the same database API.
- phpMyAdmin and Filebrowser must not be exposed directly to the public internet without short-lived panel-issued sessions.

### Quotas and Isolation

Plans define:

- CPU shares and optional CPU core limit.
- Memory limit.
- Process/PID limit.
- Disk storage limit.
- Inode limit.
- Maximum websites.
- Maximum databases.
- Maximum database storage.
- Maximum mailboxes.
- Maximum mailbox storage.
- Maximum FTP/SFTP accounts.
- Maximum cron jobs.
- Daily outbound email limit.
- Backup retention.

Implementation requirements:

- Docker memory, CPU, PIDs, restart policy, and health checks configured for every account container.
- Filesystem quotas enforced with XFS project quotas, ZFS datasets, Btrfs qgroups, or another real quota mechanism. Do not rely only on application-side checks.
- Inode quotas enforced at filesystem layer when supported.
- Containers run as non-root where possible.
- Drop Linux capabilities that are not required.
- Use per-account Docker networks. No cross-account network access.
- No customer container can access Docker socket, host root filesystem, panel database, or other accounts.

## Client Panel MVP

### Home

- Show active hosting accounts, websites, domains, email services, and warnings.
- Show to-dos:
  - Domain not pointing to MangoPanel nameservers.
  - SSL not installed.
  - Backup failing.
  - Storage/inode/mail quota warning.
  - Website container unhealthy.
- Show resource widgets:
  - Disk usage.
  - Inodes.
  - CPU and memory trend.
  - Database storage.
  - Mailbox storage.
  - Backup status.

### Websites

- List websites with status, domain, document root, SSL status, PHP version, disk usage, and quick actions.
- Add website wizard:
  - Use existing domain.
  - Add external domain.
  - Create subdomain.
  - Use temporary domain.
  - Choose empty PHP site or WordPress install.
- Website dashboard:
  - Open live site.
  - File Manager.
  - Databases.
  - phpMyAdmin.
  - SSL.
  - Backups.
  - Cron jobs.
  - Git deployments.
  - Logs.
  - Redirects.
  - PHP settings.
  - Cache controls.
  - Malware scan result.
- Website settings:
  - Document root.
  - PHP version from admin-enabled runtimes.
  - PHP limits: memory limit, upload size, max execution time.
  - Index file preference.
  - Force HTTPS.
  - Maintenance mode.
  - Delete website.

### Domains and DNS

- Domain list:
  - Managed domains.
  - External domains.
  - Status: active, pending nameserver, DNS misconfigured, suspended.
  - Linked website and email status.
- DNS zone editor:
  - A, AAAA, CNAME, MX, TXT, SRV, CAA, NS records.
  - Validate record names and values.
  - Show effective nameservers.
  - Warn before destructive MX/NS changes.
  - Provide reset-to-default DNS templates for website and email.
- Subdomains:
  - Create, list, delete.
  - Choose document root or redirect target.
- Redirects:
  - 301 and 302 redirects.
  - Wildcard redirect support.
- Parked domains:
  - Alias one domain to another website document root.

### Files

- Launch Filebrowser with a short-lived token.
- File operations:
  - Upload, download, create folder, create file.
  - Rename, copy, move, delete, restore from trash if supported.
  - Edit text files.
  - Extract and create `.zip` and `.tar.gz` archives.
  - View file size, modified time, permissions, and inode usage.
  - Reset common file permissions.
- SFTP/FTP:
  - Show host, port, username, root path.
  - Reset password.
  - Create additional SFTP users scoped to a directory.
  - Disable insecure FTP by default; enable only if admin allows it.

### Databases

- Create MySQL-compatible database and user.
- List databases with size, linked website, username, and created date.
- Reset database user password.
- Delete database with confirmation.
- Launch phpMyAdmin with short-lived access.
- Remote MySQL access:
  - Allow specific IPv4/IPv6 host.
  - Optional wildcard host if admin allows it.
  - Revoke access.
- Database backups:
  - Download `.sql.gz`.
  - Restore from backup date.

### Email

- Domain email setup checklist:
  - MX records.
  - SPF.
  - DKIM.
  - DMARC recommendation.
- Mailboxes:
  - Create mailbox.
  - Reset password.
  - Set mailbox quota.
  - Suspend/unsuspend mailbox.
  - Delete mailbox with recovery period if storage backend supports it.
- Webmail:
  - Launch independent per-mailbox webmail login URLs.
- Aliases and forwarders:
  - Create alias.
  - Create forwarder.
  - Create catch-all address.
  - Add autoresponder.
- Client configuration:
  - IMAP, SMTP, POP3, JMAP, ports, encryption, username.
- Logs:
  - Delivery log.
  - Login/access log.
  - Rate-limit status.

### Shared Mail Edge Checklist

This is the sequential build plan for replacing the current mail path with a shared public mail edge and mailbox-native storage where each mailbox has its own on-disk directory and quota can be measured from real storage usage.

#### Phase 1: Mailbox Storage and Identity

- [x] Add mailbox storage helpers in `mangopanel/mail.py` for `Maildir` paths, directory creation, directory size calculation, and safe recursive cleanup.
- [x] Change `mailboxes.storage_path` to point to the mailbox’s real directory under `user_files/accounts/<account>/mail/<domain>/<local_part>/Maildir`.
- [x] Add shared-edge identity metadata and a routing manifest so the control plane can resolve each mailbox to the shared mail edge.
- [x] Update `seed_dev_data()` in `mangopanel/db.py` to create the per-mailbox directory tree and seed the initial mailbox storage path.
- [x] Update mailbox create, patch, and delete handlers in `mangopanel/app.py` so the filesystem directory is created, renamed, or removed together with the database row.
- [x] Add mailbox move/rename logic so changing the mailbox address migrates the on-disk directory without duplicating content.
- [x] Store mailbox size and inode usage in the control plane for display and quota checks.
- [x] Update the account usage dashboard so mailbox disk usage comes from the real directory, not from a cached counter.
- [x] Add job-backed sync hooks in `mangopanel/agent.py` and `mangopanel/stack.py` for mailbox directory provisioning and ownership fixes.
- [x] Add tests in `tests/test_agent.py` and `tests/test_phase6_hardening.py` for mailbox directory creation, rename, delete, and quota lookup.

#### Phase 2: Shared Mail Edge, DNS, and Routing

- [x] Add SPF, DKIM, and DMARC record generators in `mangopanel/mail.py` and persist the resulting policy values in `mail_domains` rows.
- [x] Add a domain-auth health helper that reads DNS records and reports SPF/DKIM/DMARC status in the client panel.
- [x] Add alias, forwarder, catch-all, and autoresponder sync code in `mangopanel/app.py`, `mangopanel/agent.py`, and the mail-edge provider module.
- [x] Add mailbox and domain audit events for auth policy changes, routing changes, and quota changes.
- [x] Add delivery-log persistence for inbound delivery, outbound delivery, forwarding, and autoresponder actions.
- [x] Enforce quota and send-limit checks before accepting inbound delivery, submission, or forwarded delivery.
- [x] Add mailbox and domain management UI payloads for auth status, routing targets, and live delivery totals.
- [x] Surface real mailbox disk usage and quota consumption in the panel next to auth/routing status.
- [x] Expose a shared mail-edge manifest API so the edge proxy can consume a single routing map for all active accounts.
- [x] Add tests for SPF/DKIM/DMARC generation, alias routing, forward routing, catch-all delivery, autoresponder triggers, and quota-limit rejection.

#### Phase 3: Mail Access and Webmail Handoff

- [x] Add a shared SMTP submission edge and expose the submission host/ports in the client panel.
- [ ] Add shared POP and IMAP listeners with mailbox-scoped authentication and folder sync support.
- [x] Add JMAP endpoints or a JMAP-compatible adapter if the selected mail stack supports it.
- [x] Create a direct `/webmail/login/:mailbox_id` flow that issues a mailbox-scoped session token without requiring the hosting panel session.
- [x] Keep the one-click panel launch flow and the direct login URL in sync through shared launch-token code in `mangopanel/app.py`.
- [x] Make the webmail launch behave as a true handoff into SnappyMail with branded account selection and cookie/session exchange.
- [x] Expose host, ports, username, encryption, and endpoint details in the client mailbox settings screen.
- [x] Add session expiry, logout, and host-scoped token validation for mailbox sessions.
- [x] Add end-to-end coverage in `tests/test_phase6_hardening.py` and `scripts/dev_smoke.py` for login, submission, POP/IMAP/JMAP, and webmail launch.

### SSL

- Issue free SSL certificate via ACME.
- Support HTTP-01 challenge for domains routed to MangoPanel.
- Show validation failures and DNS instructions.
- Auto-renew certificates.
- Force HTTPS toggle.
- Revoke/reissue certificate.
- Show expiry date and renewal status.

### Backups

- Automatic backup schedule:
  - Files.
  - Databases.
  - Email metadata where practical.
- Manual backup once per configured cooldown.
- Backup list by date and type.
- Restore:
  - Full account restore.
  - Website files restore.
  - Database restore.
- Download:
  - Files as `.tar.gz`.
  - Databases as `.sql.gz`.
- Admin-configured retention per plan.
- Backup jobs must show progress and failure reason.

### Cron Jobs

- Create cron job with preset intervals and custom expressions.
- Command path must be inside allowed runtime paths.
- Capture last run time, exit code, and output tail.
- Enable/disable/delete job.
- Enforce plan limits and minimum intervals.

### Git Deployment

- Connect repository URL.
- Support public repositories for MVP.
- Support private repositories using deploy keys.
- Select branch and deploy path.
- Manual deploy button.
- Optional auto-deploy webhook token.
- Keep deployment logs.
- Refuse deploy paths outside the account base directory.

### WordPress Installer

- Install WordPress into a selected website document root.
- Create database automatically.
- Let user set site title, admin username, admin email, and password.
- Install over empty directory only unless user explicitly confirms overwrite.
- Store install metadata but never store WordPress admin password after provisioning.

### Account and Security

- Login with email/password and mandatory TOTP.
- TOTP setup required before entering panel.
- Recovery codes generated once and stored hashed.
- Change password.
- Active sessions list and revoke session.
- Activity log for logins and important actions.
- Collaborator access:
  - Invite by email.
  - Assign hosting account or website scope.
  - Assign permissions: view, manage files, manage DNS, manage email, manage databases, manage backups.

## Admin Panel MVP

### Dashboard

- Node health: online/offline, load, CPU, memory, disk, inode pressure.
- Docker health: running/stopped/unhealthy containers.
- Queue health: pending/running/failed jobs.
- Backup health: latest success/failure per account.
- Mail queue and outbound rate-limit warnings.
- SSL renewals due and failures.
- Public status summary, open incidents, and scheduled maintenance.
- Recent audit events.

### Users and Admins

- Create customer.
- Verify email manually if needed.
- Reset customer password.
- Require TOTP reset.
- Suspend/unsuspend customer.
- View customer activity log.
- Create admin accounts with role.
- Disable admin account.
- Admin actions require TOTP and are audited.

### Plans

- Create and edit shared hosting plans.
- Define quotas and feature flags.
- Assign plan to hosting account.
- Upgrade/downgrade account with quota reconciliation.
- Prevent downgrade if current usage exceeds target plan.

### Hosting Accounts

- Create hosting account for customer.
- Select node and plan.
- Provision account stack.
- View containers, quotas, websites, domains, databases, email, backups, and jobs.
- Suspend:
  - Stop website traffic or show suspension page.
  - Keep data intact.
  - Disable mail sending.
- Unsuspend.
- Terminate with delayed deletion window.
- Move account to another node is deferred, but admin UI should reserve the concept.

### Domains and DNS

- View all domains and zones.
- Rebuild DNS zone.
- Lock domain from customer changes.
- Add system DNS templates.
- Detect domains that do not point to MangoPanel nameservers.

### DNS Provider System Roadmap

MangoPanel must support real authoritative DNS through two production-capable provider modes:

- Local DNS: run an authoritative DNS service from the MangoPanel stack.
- Cloudflare DNS: create and manage customer zones through Cloudflare accounts configured by admins.

For the local DNS provider, use PowerDNS Authoritative Server as the MVP target. It is open source, fast enough for shared hosting, production-proven, supports an HTTP API, exposes metrics, and maps cleanly to MangoPanel's existing desired-state plus agent-job model. Knot DNS remains a future option for deployments that prioritize raw authoritative-server performance, but PowerDNS is the better first control-panel integration.

Implementation rule: MangoPanel stores DNS intent locally, queues provider sync jobs, and lets the agent publish the final state to either PowerDNS or Cloudflare. Client and admin APIs must not call DNS providers directly.

#### Phase 1: DNS provider foundation — implemented

- Add first-class provider tables:
  - `dns_providers`
  - `dns_provider_accounts`
  - `dns_provider_credentials`
  - `dns_provider_assignments`
  - `dns_provider_health_checks`
- Extend `plans` with DNS policy fields:
  - default DNS method: local, Cloudflare, or admin-selected.
  - allowed DNS methods.
  - default Cloudflare provider account.
  - whether customers can edit DNS.
  - max DNS records per domain.
  - allowed record types.
  - minimum TTL.
  - whether wildcard records are allowed.
  - whether Cloudflare proxy mode is allowed.
  - whether DNSSEC is allowed or required.
- Extend `domains` and `dns_zones` with:
  - selected DNS provider.
  - selected provider account.
  - provider zone ID.
  - effective nameservers.
  - DNS status.
  - last provider sync time.
  - last nameserver verification time.
  - provider state JSON.
- Add admin DNS settings page:
  - Global DNS mode: local, Cloudflare, or per-plan.
  - Local DNS settings: nameserver hostnames, public IPv4/IPv6 addresses, SOA email, default TTL, glue-record instructions.
  - Cloudflare settings: multiple account name plus API token pairs, encrypted token storage, resolved Cloudflare account ID, token scope validation, and connection test.
- Keep provider secrets encrypted and never return them to any frontend.
- Add DNS audit events for provider settings changes, credential changes, provider assignment changes, record edits, zone rebuilds, and nameserver verification actions.

#### Phase 2: Provider implementation and delegated sync — implemented

- Replace the current local-dev DNS placeholder with a real provider interface:
  - `ensure_zone(domain)`
  - `publish_records(domain, records)`
  - `delete_record(record)`
  - `delete_zone(domain)`
  - `inspect_zone(domain)`
  - `get_nameservers(domain)`
  - `verify_authoritative_nameservers(domain)`
  - `normalize_record(record)`
  - `diff_records(desired, provider_state)`
- Local PowerDNS provider:
  - Add `mangopanel-dns` container running PowerDNS Authoritative.
  - Bind public TCP/UDP 53 only when local DNS is enabled.
  - Keep the PowerDNS API private to the internal Docker/network side.
  - Store PowerDNS state in a dedicated PowerDNS database, not MangoPanel's control-plane SQLite.
  - Publish zones through the PowerDNS HTTP API.
  - Generate SOA and NS records automatically from admin DNS settings.
  - Increment serials on every zone publish.
  - Support A, AAAA, CNAME, TXT, MX, SRV, CAA, and NS records in the MVP.
  - Add health checks using direct authoritative lookups.
- Cloudflare provider:
  - Admin can register multiple Cloudflare account name plus API token pairs.
  - Resolve and store Cloudflare account IDs after token validation.
  - Create or find a Cloudflare zone when a domain is assigned to a Cloudflare-backed plan or package.
  - Publish MangoPanel default DNS templates to the Cloudflare zone.
  - Save returned Cloudflare nameservers into `domains` and `dns_zones`.
  - Show the returned nameservers in the user's panel per domain.
  - Support Cloudflare-specific DNS fields where allowed by plan: proxied flag, automatic TTL, comments/tags, and apex CNAME flattening awareness.
  - Handle Cloudflare API rate limits, retryable errors, permission errors, and zone ownership conflicts.
- DNS update flow:
  - User adds, edits, or deletes DNS records from the hosting control panel.
  - API validates ownership, plan limits, record type, TTL, record name, record value, and record conflicts.
  - API writes the desired state to MangoPanel tables.
  - API queues a DNS sync job.
  - Agent resolves the domain's provider and account assignment.
  - Agent publishes to local PowerDNS or Cloudflare.
  - Agent updates `dns_zones`, provider state, nameservers, status, serial, and timestamps.
  - Client panel displays job status, last sync time, provider, and effective nameservers.
- Add default DNS templates for:
  - website apex A/AAAA records.
  - `www` CNAME.
  - MX records for MangoPanel mail.
  - SPF, DKIM, and DMARC.
  - CAA records for the configured certificate authority.
  - reset-to-default website and mail records.

#### Phase 3: Hostinger-style UX, migration, verification, and operations — implemented

Implemented status:

- Added admin DNS domain operations for listing managed zones, rebuilding zones, verifying nameserver delegation, exporting zone snapshots, and migrating domains between local PowerDNS and Cloudflare.
- Added provider migration state on domains, retaining previous provider/account/zone data while publishing the new provider and marking the domain pending nameserver verification.
- Added DNS zone export storage for support/backups.
- Added per-domain DNS mutation locking against queued/running DNS jobs.
- Added provider error snapshots on domains/zones and retry scheduling for retryable DNS sync failures.
- Added safer record mutation rules for CNAME conflicts, locked/system records, root NS records, and provider metadata.
- Added client panel DNS status visibility, effective nameservers, rebuild/verify/export actions, and locked-record display.
- Added tests for provider migration, zone export, CNAME conflict prevention, locked records, Cloudflare sync, plan policy, and nameserver persistence.

- Admin UX:
  - DNS settings page.
  - Cloudflare account manager.
  - Local nameserver manager.
  - DNS provider health dashboard.
  - Per-plan DNS assignment.
  - Bulk provider reassignment for domains.
  - Rebuild zone action.
  - Provider sync logs and failed-job inspection.
  - Warnings for missing glue records, closed port 53, bad NS delegation, failed Cloudflare token, unreachable provider, or stale zone serials.
- Client UX:
  - Domains page shows DNS provider, effective nameservers, delegation status, and last checked time.
  - DNS Zone Editor shows pending, syncing, failed, and published states.
  - Cloudflare-backed zones show proxy controls only when plan policy allows them.
  - System records can be locked from customer edits while still visible.
  - Website setup wizard shows provider-aware nameserver instructions:
    - local DNS shows MangoPanel nameservers.
    - Cloudflare shows Cloudflare-assigned nameservers returned by the API.
- Domain lifecycle:
  - Domain is added.
  - DNS provider assignment is selected from plan/package policy.
  - Provider zone is created or found.
  - Default DNS records are generated.
  - DNS sync job is queued.
  - Effective nameservers are saved per domain.
  - Nameserver verification job runs periodically.
  - SSL issuance starts only when DNS points correctly, unless using DNS-01 with an authorized provider token.
- Provider migration:
  - Local to Cloudflare creates the Cloudflare zone, copies records, saves new nameservers, and marks the domain pending nameserver change.
  - Cloudflare to local publishes the local PowerDNS zone, saves local nameservers, and marks the domain pending nameserver change.
  - Keep old provider data until the new delegation is verified.
  - Do not delete the old provider zone automatically without admin confirmation.
- Reliability and safety:
  - Per-domain lock for concurrent DNS mutations.
  - Retry DNS jobs with backoff.
  - Store provider error snapshots for support.
  - Export and backup DNS zones.
  - Prevent dangerous CNAME conflicts.
  - Prevent customer edits to SOA and root NS records unless plan policy allows it.
  - Validate DNS records before enqueueing provider jobs.
- Tests:
  - Provider selection and plan-policy tests.
  - DNS record validation tests.
  - Local PowerDNS sync tests.
  - Mocked Cloudflare API tests.
  - Nameserver persistence tests.
  - User-panel add/edit/delete record tests.
  - Admin credential and provider assignment tests.
  - Agent dispatch and retry tests.

### Server and Node Management

- Register node with agent token.
- View node capabilities:
  - Docker version.
  - Filesystem quota backend.
  - Available PHP runtimes.
  - Mail services.
  - Backup repository status.
- Drain node flag to prevent new provisioning.
- Maintenance mode.
- View agent logs.

### Operations

- Job queue browser:
  - Pending, running, succeeded, failed.
  - Retry failed safe jobs.
  - Cancel pending jobs.
- Audit logs:
  - Filter by actor, target, action, status, IP.
- Abuse/security:
  - Block IP for website.
  - Suspend outgoing mail for account.
  - Run malware scan.
  - View scan findings.
- Backup administration:
  - Configure backup repository.
  - Trigger account backup.
  - Verify restore test job.

### Status Page

- Manage public components and component groups.
- Create and publish incidents.
- Add incident updates.
- Resolve incidents.
- Schedule maintenance windows.
- Override component status manually.
- Review automated status checks and failure history.
- Send status notifications to subscribers.

## Provisioning Flows

### Create Hosting Account

1. Admin selects customer, node, and plan.
2. API creates hosting account and provisioning job.
3. Agent creates account directory and assigns UID/GID/project quota.
4. Agent creates Docker network and account containers.
5. Agent writes OpenLiteSpeed base config.
6. Agent creates default temporary domain.
7. Agent starts containers and runs health checks.
8. API marks account active and writes audit event.

### Add Website

1. Customer chooses domain/subdomain/temporary domain.
2. API validates ownership, plan limits, and document root.
3. Agent creates domain directory and logs directory.
4. Agent renders OpenLiteSpeed virtual host config.
5. Edge proxy route is created or reloaded.
6. DNS defaults are created if domain is managed.
7. SSL job is queued if domain points correctly.
8. Website becomes active after health check.

### Create Database

1. Customer enters database name, username, and password.
2. API validates quota and naming.
3. Agent creates database and grants scoped privileges.
4. API stores metadata only, not plaintext password.
5. phpMyAdmin access becomes available for that database user.

### Create Mailbox

1. Phase 1: customer selects email domain and mailbox name.
2. API validates DNS/domain ownership, quota, and plan send limits.
3. Agent creates mailbox storage and records mailbox metadata.
4. Mail service reloads virtual mailbox maps and inbound routing.
5. Phase 2 adds SPF, DKIM, DMARC, aliases, forwarders, catch-all, and autoresponders.
6. Phase 3 enables SMTP, POP, IMAP, JMAP, one-click panel launch, and an independent mailbox webmail login URL.

### Backup and Restore

1. Backup worker snapshots files and dumps databases.
2. Metadata and checksum are saved.
3. Customer/admin can request restore.
4. Restore job verifies ownership, available storage, and backup integrity.
5. Agent restores to target and records completion.

## Security Requirements

- Passwords hashed with Argon2id or bcrypt with strong cost.
- JWT access tokens are short-lived.
- Refresh tokens are stored server-side hashed and are revocable.
- Prefer secure, HTTP-only cookies for browser sessions.
- TOTP is mandatory for all customer and admin accounts.
- Recovery codes are one-time use and stored hashed.
- Admin actions use RBAC and audit logging.
- Dangerous operations require confirmation and recent 2FA validation.
- API input validation for every path, domain, email, DNS record, cron command, and repository URL.
- Prevent path traversal everywhere.
- Never store plaintext hosting, SFTP, database, mailbox, or WordPress passwords.
- Secrets are encrypted at rest when they must be stored for automation.
- Agent accepts jobs only from trusted local source or signed requests.
- Rate-limit login, 2FA, password reset, and panel launch endpoints.
- Customer-facing launch tokens for Filebrowser, phpMyAdmin, and webmail are short-lived and scoped.
- Default firewall exposes only public panel ports, HTTP/HTTPS, DNS if enabled, mail ports, and SFTP/FTP if enabled.

## Local Development and Testing

MangoPanel must include a local development profile that can exercise the complete shared hosting MVP on an Apple Silicon Mac, such as M1, M2, or M3. The goal is functional confidence for product flows, provisioning, routing, DNS, SSL, email, backups, cron, Git deployment, WordPress installation, and status reporting without requiring public domains or production servers.

### Developer Commands

Provide these commands in a `Makefile` or equivalent script:

```bash
make dev-init
make dev-up
make dev-seed
make dev-smoke
make dev-e2e
make dev-reset
make dev-down
```

Expected behavior:

- `dev-init`: verifies Docker Desktop, Docker Compose, available ports, local resolver setup, and Apple Silicon image compatibility.
- `dev-up`: starts the complete local stack using `docker-compose.dev.yml`.
- `dev-seed`: creates an admin, customer, plan, node, hosting account, test domains, DNS zone, mailbox, database, and sample website.
- `dev-smoke`: runs fast checks for API health, login, TOTP test flow, provisioning, website routing, DNS, TLS, phased email checks, backup, restore, and status page.
- `dev-e2e`: runs browser/API integration tests against the local stack.
- `dev-reset`: deletes local containers, volumes, generated certificates, seed data, and test account files.
- `dev-down`: stops the stack while preserving volumes.

### Apple Silicon Requirements

- Every dev image must support `linux/arm64` or be built locally for ARM64.
- If a third-party image has no reliable ARM64 build, provide a local Dockerfile replacement for the dev profile.
- Avoid `platform: linux/amd64` by default because emulation makes hosting and database tests slow and can hide architecture issues.
- The dev profile must run on Docker Desktop for Mac with no production host changes except optional local DNS resolver setup.
- Production-grade filesystem quota behavior must be tested on Linux. On macOS, the dev profile uses a quota simulator for functional UI/API/job testing and an optional Linux VM profile for real XFS/ZFS/Btrfs quota tests.

### Local Domains and DNS

Use `.test` domains only:

```text
panel.mango.test
admin.mango.test
status.mango.test
mail.mango.test
webmail.mango.test
phpmyadmin.mango.test
files.mango.test
u000001.mango.test
example.mango.test
sub.example.mango.test
```

Local DNS method:

- Run a dev DNS container, preferably CoreDNS or PowerDNS, bound to `127.0.0.1:5353`.
- Provide a setup script for macOS `/etc/resolver/test` so `*.test` resolves through the local DNS server.
- Provide a fallback `/etc/hosts` mode for fixed domains if the resolver setup is not available.
- DNS zone APIs must write to the same provider abstraction used in production, with the dev provider backed by the local DNS service.
- Tests must verify records using `dig @127.0.0.1 -p 5353 example.mango.test`.

### Local TLS and ACME

Two TLS modes are required:

- Fast local TLS mode using `mkcert` or a generated local root CA for `*.mango.test`.
- ACME test mode using Pebble or Step CA so the SSL issue/renew/revoke job flow can be tested without Let's Encrypt.

Rules:

- Production ACME endpoints must be disabled in dev mode.
- The panel must clearly label local certificates as development certificates.
- `dev-smoke` must verify HTTPS routing and force-HTTPS behavior.

### Local Email

The dev stack must support the same three-phase email roadmap as production:

- Phase 1 local mode: mailbox CRUD, shared edge identity mapping, mailbox storage, and outbound limit configuration without external delivery.
- Phase 2 local mode: SPF, DKIM, DMARC, aliases, forwarders, catch-all, autoresponder, and delivery logging.
- Phase 3 local mode: SMTP submission plus POP/IMAP/JMAP plus a one-click launch button and an independent per-mailbox webmail login URL.

Rules:

- Outbound internet email is disabled in local development.
- Mail delivery between local `.test` mailboxes must work.
- DNS setup checklist must validate local MX, SPF, DKIM, and DMARC records.
- `dev-smoke` must exercise mailbox creation, inbound mail routing, SMTP submission, JMAP/IMAP/POP access, the one-click webmail launch, and the standalone mailbox login flow for the active phase.

### Local Hosting Stack

The dev profile provisions the same account stack as production, with dev-safe substitutions where needed:

- OpenLiteSpeed/PHP container.
- Filebrowser container.
- phpMyAdmin container.
- MariaDB or MySQL container.
- SFTP container exposed on a non-privileged host port such as `2222`.
- Cron runner.
- Local shared mail edge plus mailbox-native storage components.
- Edge proxy on `8080` and `8443` by default, with optional `80` and `443` binding if the developer enables privileged ports.

The seed account should use:

```text
/tmp/mangopanel-dev/u000001/
  domains/example.mango.test/public_html/index.php
```

### Local Feature Services

- Backups use a local restic or borg repository under `./var/dev/backups`.
- Git deployments use a local Gitea container with seeded public and private repositories.
- WordPress installer uses a cached WordPress package in `./fixtures/wordpress/` so tests can run without internet after first setup.
- Malware scanning uses a local ClamAV container or a lightweight scanner stub that returns deterministic test fixtures.
- Metrics use Prometheus-compatible local scraping or simple API-collected metrics.
- Status page consumes local health checks and incident records from the same status system used in production.

### Dev Seed Credentials

Use deterministic seed data only in dev mode:

- Admin email: `admin@mango.test`
- Customer email: `owner@example.mango.test`
- Test password: `ChangeMe-DevOnly-123!`
- TOTP mode: deterministic test secret or bypass code only when `MP_DEV_AUTH_TEST_MODE=true`.
- Test website: `https://example.mango.test:8443`
- Status page: `https://status.mango.test:8443`

The API must refuse deterministic credentials and TOTP bypass outside `MP_ENV=development`.

### Local Test Matrix

`dev-smoke` must verify:

- Admin login and mandatory TOTP.
- Customer login and mandatory TOTP.
- Plan creation.
- Hosting account provisioning.
- Website creation with PHP response.
- Local DNS record creation and lookup.
- Local TLS certificate installation.
- Force HTTPS redirect.
- Filebrowser launch token.
- SFTP upload.
- Database creation and phpMyAdmin launch token.
- Remote MySQL allow/revoke flow against local network addresses.
- Phase 1 mailbox creation and shared-edge MX/inbound routing.
- Phase 2 SPF, DKIM, DMARC, aliases, forwarder, and rate-limit behavior.
- Phase 3 SMTP submission, POP/IMAP access, and per-mailbox webmail login.
- Cron job execution and output capture.
- Git deployment from local Gitea.
- WordPress install.
- Manual backup, backup download, and restore.
- Account suspend and unsuspend.
- Public status page shows current component state.
- Admin can create an incident and scheduled maintenance.

### Linux Quota Test Profile

Because Docker Desktop for Mac does not behave like a production Linux hosting filesystem, provide an optional full quota profile:

- `make dev-linux-vm-up`
- Starts or documents an ARM64 Ubuntu VM through UTM, Lima, Colima, or another supported local VM.
- Formats a test disk with XFS, ZFS, or Btrfs.
- Enables real project quotas or dataset quotas.
- Runs the same provisioning and quota tests against the Linux node agent.

This profile is required before declaring quota enforcement production-ready.

## Status Page System

MangoPanel must include a public status page similar to hosted infrastructure status pages. It should be useful for customers during outages and useful for admins during maintenance and incident response.

### Public Status Page

Expose a public page at `/status` and optionally `status.{panel-domain}`.

Public page requirements:

- Overall status banner:
  - Operational.
  - Degraded performance.
  - Partial outage.
  - Major outage.
  - Maintenance.
- Component list:
  - Client panel.
  - Admin panel.
  - API.
  - Website hosting edge.
  - DNS.
  - Email stack.
  - Databases.
  - Backups.
  - SSL certificate automation.
  - File manager.
  - VPS later, when enabled.
- Per-component status:
  - Operational.
  - Degraded.
  - Partial outage.
  - Major outage.
  - Maintenance.
  - Unknown.
- Current incidents.
- Scheduled maintenance.
- Incident history by day.
- Uptime history for the last 90 days in the MVP.
- RSS or Atom feed.
- JSON status endpoint for automation.

The public status page must not expose private customer data, hostnames, internal IP addresses, account IDs, or stack traces.

### Admin Status Management

Admins can:

- Create an incident.
- Set severity and affected components.
- Post incident updates.
- Resolve an incident.
- Schedule maintenance.
- Start maintenance early or mark it complete.
- Override component status manually.
- Link an incident to failed health checks or jobs.
- Publish or keep drafts internal.
- Preview public status before publishing.

Incident lifecycle:

```text
investigating -> identified -> monitoring -> resolved
```

Maintenance lifecycle:

```text
scheduled -> in_progress -> verifying -> completed
```

### Automated Health Checks

The status system consumes checks from:

- API health endpoint.
- Agent heartbeats.
- Edge proxy route checks.
- DNS lookup checks.
- SMTP submission check.
- IMAP login check.
- Webmail check.
- Database provisioning check.
- Backup repository check.
- SSL renewal queue check.
- Job queue latency check.

Rules:

- A single failed check should not immediately create a public incident.
- Repeated failures can automatically mark a component degraded and notify admins.
- Public incidents remain admin-controlled in the MVP.
- Status history stores check results separately from published incident updates.

### Status Notifications

MVP notification channels:

- Email notifications to subscribed customers.
- Webhook notifications for admins.
- RSS or Atom feed for public subscribers.

Deferred notification channels:

- SMS.
- Slack.
- Discord.
- Telegram.
- PagerDuty/Opsgenie.

### Status Data Model

Additional tables:

- `status_components`
- `status_component_groups`
- `status_checks`
- `status_check_results`
- `status_incidents`
- `status_incident_updates`
- `status_maintenances`
- `status_subscribers`
- `status_notifications`

### Status API

Public API:

- `GET /api/public/status`
- `GET /api/public/status/components`
- `GET /api/public/status/incidents`
- `GET /api/public/status/maintenance`
- `GET /api/public/status/history`
- `GET /api/public/status/feed.atom`

Admin API:

- `GET /api/admin/status`
- `POST /api/admin/status/components`
- `PATCH /api/admin/status/components/{id}`
- `POST /api/admin/status/incidents`
- `PATCH /api/admin/status/incidents/{id}`
- `POST /api/admin/status/incidents/{id}/updates`
- `POST /api/admin/status/maintenance`
- `PATCH /api/admin/status/maintenance/{id}`
- `POST /api/admin/status/checks/{id}/run`

### Status Acceptance Criteria

- Public visitors can view current platform health without logging in.
- Admin can publish an incident affecting one or more components.
- Admin can post incident updates and resolve the incident.
- Admin can schedule maintenance and mark it complete.
- Component status changes are reflected on the public page.
- Automated checks store historical results.
- Repeated check failures can mark a component degraded internally and notify admins.
- The page exposes a JSON endpoint and Atom feed.
- Local dev mode includes status seed data and smoke tests.

## Observability

- Health checks for API, agent, edge proxy, DNS, mail, database, and backup worker.
- Structured logs with request ID and job ID.
- Metrics:
  - Account CPU/memory.
  - Disk and inode usage.
  - HTTP status counts.
  - Mail queue length.
  - Backup duration and failures.
  - SSL renewal failures.
  - Job queue duration and retries.
- Activity log visible to customers for their own account.
- Audit log visible to admins.
- Status component history visible publicly in summarized form.
- Incident and maintenance events visible publicly after admin publication.

## Suggested Data Model

Core tables:

- `users`
- `admins`
- `roles`
- `sessions`
- `totp_secrets`
- `recovery_codes`
- `plans`
- `nodes`
- `hosting_accounts`
- `account_quotas`
- `websites`
- `domains`
- `dns_zones`
- `dns_records`
- `dns_providers`
- `dns_provider_accounts`
- `dns_provider_credentials`
- `dns_provider_assignments`
- `dns_provider_health_checks`
- `ssl_certificates`
- `databases`
- `database_users`
- `mail_domains`
- `mailboxes`
- `mail_aliases`
- `mail_forwarders`
- `cron_jobs`
- `git_deployments`
- `backups`
- `backup_items`
- `jobs`
- `job_events`
- `audit_logs`
- `activity_logs`
- `collaborators`
- `support_notes`

Every customer-owned table must include ownership fields, timestamps, status, and soft-delete support where recovery is useful.

## Suggested API Areas

Client API:

- `POST /api/client/auth/login`
- `POST /api/client/auth/totp/verify`
- `GET /api/client/home`
- `GET /api/client/hosting-accounts`
- `GET /api/client/websites`
- `POST /api/client/websites`
- `GET /api/client/domains`
- `POST /api/client/dns-records`
- `PATCH /api/client/dns-records/:id`
- `DELETE /api/client/dns-records/:id`
- `POST /api/client/domains/:id/dns/rebuild`
- `POST /api/client/domains/:id/dns/verify-nameservers`
- `GET /api/client/domains/:id/dns/export`
- `POST /api/client/ssl/issue`
- `GET /api/client/files/launch`
- `POST /api/client/databases`
- `GET /api/client/phpmyadmin/launch`
- `POST /api/client/mailboxes`
- `PATCH /api/client/mailboxes/:id`
- `POST /api/client/backups`
- `POST /api/client/restores`
- `POST /api/client/cron-jobs`
- `POST /api/client/git-deployments`
- `GET /api/client/activity`

Admin API:

- `GET /api/admin/dashboard`
- `POST /api/admin/users`
- `POST /api/admin/admins`
- `POST /api/admin/plans`
- `POST /api/admin/nodes`
- `POST /api/admin/hosting-accounts`
- `POST /api/admin/hosting-accounts/{id}/suspend`
- `POST /api/admin/hosting-accounts/{id}/unsuspend`
- `GET /api/admin/dns-settings`
- `PATCH /api/admin/dns-settings`
- `POST /api/admin/dns-providers/cloudflare/accounts`
- `PATCH /api/admin/dns-providers/cloudflare/accounts/{id}`
- `DELETE /api/admin/dns-providers/cloudflare/accounts/{id}`
- `POST /api/admin/dns-providers/{id}/test`
- `GET /api/admin/domains`
- `POST /api/admin/domains/{id}/dns/rebuild`
- `POST /api/admin/domains/{id}/dns/verify-nameservers`
- `GET /api/admin/domains/{id}/dns/export`
- `POST /api/admin/domains/{id}/dns/migrate-provider`
- `POST /api/admin/domains/dns/bulk-migrate-provider`
- `GET /api/admin/jobs`
- `POST /api/admin/jobs/{id}/retry`
- `GET /api/admin/audit-logs`
- `POST /api/admin/backups/{id}/restore-test`

Public API:

- `GET /api/public/bootstrap`
- `POST /api/public/signup`
- `POST /api/public/admin-setup`
- `GET /api/public/status`
- `GET /api/public/status/feed.atom`

## MVP Acceptance Criteria

- An admin can create a plan, node, customer, and hosting account from the admin panel.
- The agent provisions an isolated account stack with enforced CPU, memory, storage, and inode limits.
- A customer can log in, complete mandatory TOTP, and see the hosting dashboard.
- A customer can add a domain or temporary website and upload `index.php` through Filebrowser or SFTP.
- The website serves PHP through OpenLiteSpeed behind the edge proxy.
- A customer can issue SSL, force HTTPS, and see renewal status.
- A customer can create a MySQL-compatible database and open phpMyAdmin.
- A customer can complete the phased email experience: mailbox creation, DNS/auth setup, SMTP submission, POP/IMAP/JMAP access, one-click webmail launch, and independent webmail login URLs backed by the shared mail edge.
- A customer can edit DNS records for managed domains.
- A customer can create and run a cron job and inspect its last output.
- A customer can trigger a manual backup, download it, and restore files or a database.
- A customer can install WordPress into an empty website.
- Admin can suspend and unsuspend a hosting account.
- Admin can see job status, node health, audit logs, backup failures, and quota usage.
- Failed provisioning jobs are visible with actionable errors and can be retried when safe.
- A developer on an Apple Silicon Mac can run `make dev-up`, seed a local account, and complete the MVP smoke test without public domains.
- The local dev profile can test DNS, TLS, the shared mail edge, databases, backups, cron, Git deploy, WordPress install, and status page flows.
- Public visitors can view the status page, current incidents, scheduled maintenance, and uptime history.
- Admin can publish and resolve status incidents and maintenance events.

## Implementation Milestones

1. Foundation
   - API skeleton, SQLite migrations, auth, TOTP, RBAC, audit logs.
   - Client/admin SPA shells.
   - Agent registration and job queue.
   - Local development compose stack, seed data, and smoke test harness.
2. Account provisioning
   - Plans, nodes, hosting accounts.
   - Docker network/container creation.
   - Filesystem layout and quotas.
3. Websites, edge routing, DNS, SSL
   - OpenLiteSpeed vhost rendering.
   - Edge proxy routing.
   - DNS zone management.
   - ACME certificates.
4. Files and databases
   - Filebrowser launch.
   - SFTP users.
   - MySQL-compatible database provisioning.
   - phpMyAdmin launch.
5. Email
   - Phase 1: mailbox CRUD, mailbox storage, shared-edge identity mapping, inbound routing, MX checklist, and plan send limits.
   - Phase 2: SPF, DKIM, DMARC, aliases, forwarders, catch-all, autoresponders, and delivery logs.
   - Phase 3: SMTP, POP, IMAP, and independent per-mailbox webmail login URLs.
6. Backups, cron, Git, WordPress
   - Backup worker and restore flows.
   - Cron runner.
   - Git deploy.
   - WordPress installer.
7. Admin operations hardening
   - Suspension, retries, alerts, malware scan, support tools.
   - Security review and restore drills.
8. Status page and local release validation
   - Public status page, incidents, maintenance, health checks, notifications.
   - Apple Silicon dev profile, ACME test mode, local mail mode, local DNS mode.
   - Linux quota test profile and release smoke tests.

## Native Feature Migration Todo

The dashboard should keep `simulated` only for features that still rely on placeholder data, mock job output, or non-native wrappers. Do not change a feature's status to `functional` until the backend path, agent job, and regression tests all exist and the client can exercise the real workflow end to end.

### Execution Rules

- [ ] Keep the feature intent intact. The goal is to make the function behave like cPanel, not just make a button return success.
- [ ] Every task must include success coverage, unauthorized access coverage, ownership checks, bad-input checks, and one intrusion or security-abuse test.
- [ ] Prefer additive changes. Add new route, handler, schema, or job first, then switch the UI/status once the live path is proven.
- [ ] Do not remove old response fields until the frontend no longer depends on them.
- [ ] Verify the real workflow in the browser or API before marking the task done.
- [ ] When a feature leaves `simulated`, update every layer that surfaces its state: backend `FEATURE_STATUS`, frontend labels/toasts/copy in `client.js` and `client.html`, and any tests that assert the status string.
- [ ] After any client-facing status or wording change, restart the running dev server or rebuild the asset bundle so the browser does not keep an old copy.
- [ ] Update the todo checklist only after tests pass and the function is working end to end.

### Phase 1: Filesystem and account primitives

- [x] `files`
  - Replace simulated file actions with real account-root filesystem operations.
  - Keep Filebrowser launch, deep links, upload, delete, rename, and permissions tied to the account's real document root.
  - Add success, unauthorized, ownership, and bad-input tests for each exposed file action.
- [x] `ftp-accounts`
  - Create real FTP users mapped to the account filesystem and shell policy.
  - Ensure user creation, password rotation, disable/delete, and home-directory validation are job-backed and auditable.
  - Verify launch and cleanup paths do not leak credentials or stale mounts.
- [x] `password-protect-directories`
  - Write actual auth configuration for protected paths instead of storing a simulated flag.
  - Support add, remove, and list flows for protected directories.
  - Verify the browser challenge, config reload, and ownership scope in tests.
- [x] `hotlink-protection`
  - Generate real proxy or web-server rules for allowed referrers.
  - Validate allowlist parsing, rule rendering, and per-account isolation.
  - Keep the existing response fields while the client migrates to the native config model.
- [x] `folder-index-manager`
  - Toggle real directory listing behavior in the web stack.
  - Persist the chosen state per directory and ensure it survives refresh/redeploy.
  - Test that the visible index state matches the rendered web-server config.
- [x] `fix-file-ownership`
  - Replace simulated ownership repair with actual recursive ownership and permission correction on the account tree.
  - Make the job idempotent and safe to retry.
  - Add coverage for large trees, missing paths, and unauthorized requests.
- [x] `cache-manager`
  - Connect cache purges to the real application or proxy cache path.
  - Support targeted and full-cache purge jobs with clear job results.
  - Verify that purge output reflects the actual cache backend in use.
- [x] `services`
  - Replace simulated service actions with real service state reporting and restart/reload jobs where the stack supports them.
  - Keep unsupported services explicitly read-only or unavailable rather than pretending they are actionable.
  - Add tests for service status, ownership, and unsupported-service responses.
- [x] `modsecurity`
  - Move from a simulated toggle to actual web-stack rule management.
  - Support enable/disable, rule-set selection, and account-scoped exceptions where permitted.
  - Confirm the generated config is applied by the edge or app server.

### Phase 2: Job-backed operational workflows

- [x] `backups`
  - Replace simulated backup artifacts with real archive creation, retention, download, and restore jobs.
  - Back up files, databases, and configuration in a way that is restorable and account-scoped.
  - Add tests for success, retry, restore safety, and bad input.
- [x] `cron-jobs`
  - Write actual crontab entries and validate schedule syntax before commit.
  - Track next-run, last-run, and captured output from the real runner.
  - Ensure jobs are ownership-scoped and can be deleted or disabled cleanly.
- [x] `git`
  - Switch Git deploys to a real repository checkout with actual pull, deploy, and rollback behavior.
  - Preserve commit, branch, and remote metadata from the live repo state.
  - Test deploy success, invalid refs, unauthorized access, and dirty-worktree handling.
- [x] `images`
  - Replace simulated image optimization with real resize/compress/convert jobs.
  - Record the generated derivative artifact and source file relationship.
  - Verify the output file exists, the dimensions or format changed as expected, and the job is repeatable.
- [x] `remote-mysql`
  - Write actual allowlist and connection settings for remote database access.
  - Validate IP parsing, CIDR handling, and duplicate rule behavior.
  - Test that the resulting database accepts or rejects connections according to the stored policy.
- [x] `postgresql-databases`
  - Create real PostgreSQL databases and users with actual grants and ownership.
  - Replace the simulated JSON model with a real DB-backed or service-backed source of truth.
  - Cover create, rename if supported, delete, privilege assignment, and access tests.
- [x] `postgresql-database-wizard`
  - Wire the wizard to the same native PostgreSQL provisioning path.
  - Keep the wizard thin so it validates and dispatches instead of inventing a second data model.
  - Verify it produces the same result as the direct database flow.

### Phase 3: Stack-integrated hosting features

- [x] `dns-zone-editor`
  - Move DNS edits from simulated records to real managed-zone writes.
  - Preserve record validation, ownership checks, TTL handling, and audit logs.
  - Add dispatch tests for add, update, delete, and bad record input.
- [x] `ssl-tls`
  - Issue or import actual certificates and bind them to the live web stack.
  - Keep renewals, expiry status, and force-HTTPS behavior tied to real cert state.
  - Test issuance, renewal, failure handling, and unauthorized attempts.
- [x] `site-builder`
  - Replace the simulated scaffold with a real site creation job that writes a live document root, starter assets, and bootstrap config.
  - Ensure the created site can immediately serve content through the normal web path.
  - Verify the generated site survives redeploy and ownership repair.
- [x] `installer`
  - Turn the installer into a real backend flow that creates the requested application and records the actual deployment artifacts.
  - Keep install templates, version selection, and progress reporting driven by job state.
  - Add tests for supported app installs, invalid versions, and conflicting paths.

### Phase 4: Launch, visibility, and admin polish

- [x] `ssh-access`
  - Keep this read-only unless we deliberately support managed SSH access and key provisioning.
  - If enabled later, make it real with actual key install and account policy checks.
- [x] `php-info`
  - Ensure the view reflects the live runtime and container state rather than a cached placeholder.
  - Keep it read-only, but verify the data source is the actual running environment.
- [x] `activity`
  - Keep the page read-only, but make sure it reflects real jobs, artifacts, and audit rows only.
- [x] `analytics`
  - Make analytics a real per-site tracking control with an on/off toggle.
  - Keep log collection tied to live site state and verify it with route, agent, and behavior tests.
- [x] `performance`, `disk-usage`, `visitors`, `errors`, `bandwidth`, `raw-access`, `resource-usage`
  - Keep these as read-only until the underlying statistics pipeline is native and trustworthy.
  - Promote individual panels only when the live source of truth exists and is tested.
- [x] `webalizer`
  - Keep unavailable unless a real stats pipeline is introduced and maintained.

### Promotion rules

- [ ] Every promoted feature must have:
  - one success test
  - one unauthorized test
  - one ownership test
  - one bad-input test
  - one agent dispatch test
  - one artifact or state verification test
- [ ] Keep old response fields until the frontend no longer depends on them.
- [ ] Make each migration additive: new route, new handler, new schema, then a status flip.
- [ ] Only mark a feature as `functional` after the client can use the native workflow end to end.

## VPS Hosting Later

VPS support should be a separate module after the shared hosting MVP is stable:

- KVM/libvirt provisioning.
- VPS plans and images.
- Network bridge/VLAN/firewalling.
- Block storage.
- Snapshots.
- Console access.
- Rebuild, reboot, rescue mode.
- Usage and billing hooks.
