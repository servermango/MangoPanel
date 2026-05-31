# MangoPanel

MangoPanel is an hPanel-style shared hosting control panel. This repository currently contains the first foundation build from `Project.md`: a runnable API, SQLite control-plane database, Vue CDN client/admin/status pages, dev seed data, and smoke tests.

## Current Build

- Python standard-library HTTP API.
- SQLite schema and development seed data.
- JWT-style signed access tokens.
- Mandatory TOTP flow, with development-only code `000000`.
- Public client signup page at `/signup`.
- Client panel at `/` on the client port.
- First-admin setup page at `/admin` when no admin exists, and `/admin/setup` for explicit setup checks on the admin port.
- Admin panel at `/admin` on the admin port.
- Public status page at `/status` on the client port.
- Development API coverage for hosting accounts, websites, DNS records, SSL jobs, launch tokens, databases, mailboxes, backups, cron jobs, Git deployments, jobs, audit logs, and status incidents.
- Node-agent job runner with simulated and Docker Compose execution modes.
- Account-stack generator for OpenLiteSpeed, Filebrowser, phpMyAdmin, MariaDB, cron, SFTP, and SMTP relay.

This is not the production hosting runtime yet. The agent now generates account filesystem layout and Docker Compose files, but real DNS, real mail, real ACME, and quota enforcement still need their production providers.

## Quick Start

```bash
make dev-init   # check Python, Docker, and ports
make dev-up     # start the client + admin panels (seeds dev data on first run)
```

Then open the client panel at <http://127.0.0.1:8000/> and the admin panel at <http://127.0.0.1:8001/admin>, and log in with the seed credentials below (TOTP code `000000` in dev mode). That's all you need for day-to-day work; the rest of this document explains how the pieces fit together.

## How It Works

MangoPanel is a single Python program ([`mangopanel/app.py`](mangopanel/app.py)) that serves two HTTP panels and an API, backed by one SQLite database. There is no external web framework — it uses only the standard library.

- **Two panels, two ports.** `make dev-up` starts one process that binds two ports: the client panel on `8000` and the admin panel on `8001`. Each port only serves its own routes (`/api/client/*` vs `/api/admin/*`), so the panels stay isolated. Public routes (`/api/public/*`, `/status`) are reachable from either.
- **Auth.** Login is two steps: email + password returns a short-lived challenge token, then a TOTP code exchanges it for an access token (a signed JWT). In development, `MP_DEV_AUTH_TEST_MODE=true` accepts the bypass code `000000`. All access tokens are checked on every `/api/client` and `/api/admin` request.
- **Control plane (SQLite).** Every panel action writes desired-state rows (users, hosting accounts, websites, databases, mailboxes, etc.) and an audit/activity entry. The API never touches Docker or the filesystem directly.
- **Node agent.** State-changing actions enqueue a row in the `jobs` table. The agent ([`mangopanel/agent.py`](mangopanel/agent.py)) picks up jobs and does the privileged work — creating the account directory layout and rendering Docker Compose files ([`mangopanel/stack.py`](mangopanel/stack.py)). In dev, `MP_AGENT_INLINE=true` runs jobs immediately in `simulate` mode (files written, no containers). Set `MP_AGENT_MODE=docker` to actually launch per-account containers (OpenLiteSpeed, Filebrowser, phpMyAdmin, MariaDB, cron, SFTP, SMTP relay).
- **Config.** Everything is driven by environment variables read in [`mangopanel/config.py`](mangopanel/config.py) (`MP_*`), with sensible local defaults — so the Makefile targets work with no setup.

Request flow in one line: **browser → panel API (writes SQLite + enqueues job) → agent (provisions files/containers) → status reported back to SQLite → panel shows result.**

## Data Layout

All persistent state lives in a single `user_files/` directory in the project root, so a server admin can reach customer files and the database in one place:

```text
user_files/
  accounts/                 # per-customer hosting files  (MP_ACCOUNT_ROOT)
    u000001/
      account.json
      domains/<domain>/public_html/
      databases/  mail/  backups/  ssl/  git/  .runtime/
  data/                     # control-plane database       (MP_DATA_DIR)
    mangopanel.sqlite3
```

Override the location with `MP_USER_FILES_DIR` (or the more specific `MP_ACCOUNT_ROOT` / `MP_DATA_DIR` / `MP_DB_PATH`). `user_files/` is git-ignored. `make dev-reset` deletes it for a clean slate.

## Local Development

Run the setup checks:

```bash
make dev-init
```

Start the local panel:

```bash
make dev-up
```

Open:

- Client: <http://127.0.0.1:8000/>
- Admin: <http://127.0.0.1:8001/admin>
- Status: <http://127.0.0.1:8000/status>

Seed credentials:

- Admin: `admin@mango.test`
- Customer: `owner@example.mango.test`
- Password: `ChangeMe-DevOnly-123!`
- TOTP code in dev mode: `000000`

Client signup:

- Open <http://127.0.0.1:8000/signup>
- The page calls `POST /api/public/signup`
- The API returns a TOTP secret and creates an initial hosting account when a plan and node are available

First admin setup:

- If the database has zero admins, `/admin` on the admin port shows the first-admin setup page
- The setup page calls `POST /api/public/admin-setup`
- Once an admin exists, first-admin setup is locked
- Existing admins can add more admins from the admin dashboard

Run tests:

```bash
make test
```

Run the API smoke test while the dev server is running:

```bash
make dev-smoke
```

Run queued agent jobs manually:

```bash
make dev-agent
```

The development server uses `MP_AGENT_INLINE=true` by default, so API-created jobs are processed immediately in simulated mode. Generated account stack files are written under `user_files/accounts/u000001/` unless `MP_ACCOUNT_ROOT` is changed. See [Data Layout](#data-layout) for the full directory map.

Run the full system with real local hosting containers — one command:

```bash
make dev-up-docker
```

This starts the panels and brings up the per-account Docker stack (OpenLiteSpeed, Filebrowser, phpMyAdmin, MariaDB, cron, SFTP, SMTP relay) in the same process. It requires Docker Desktop to be running. Then, in another terminal:

```bash
make dev-hosting-smoke
```

The local Docker stack exposes:

- Website: `http://127.0.0.1:18010`
- Filebrowser: `http://127.0.0.1:18011`
- phpMyAdmin: `http://127.0.0.1:18012`
- Mailpit: `http://127.0.0.1:18013`
- MariaDB: `127.0.0.1:18014`
- SFTP: `127.0.0.1:18015`

Additional accounts get their own port range.

Reset local data:

```bash
make dev-reset
```

## Docker Development

The initial compose file runs the panel container:

```bash
docker compose -f docker-compose.dev.yml up --build
```

To let the agent apply generated account stacks with Docker Compose instead of only writing files:

```bash
MP_AGENT_MODE=docker make dev-agent
```

Keep the default `simulate` mode for fast M1 development. Docker mode may pull large third-party images and should be tested separately.

## Next Implementation Steps

1. Add local DNS and local ACME providers behind the same provider interfaces that production will use.
2. Add mail capture/full mail mode with Mailpit/Postfix/Dovecot/Roundcube.
3. Add browser E2E tests for the client/admin/status pages.
4. Add the Linux quota test profile for real storage and inode enforcement.
5. Harden Docker mode with image pinning, health checks, and per-service secrets.
