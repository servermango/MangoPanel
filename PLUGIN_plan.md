# MangoPanel Plugin System Architecture Plan

Status: architecture proposal only

This document proposes an architecture for extending MangoPanel with plugins such as a Softaculous-like application catalog and installer, a SpamAssassin-based mail filtering feature, and a Sucuri-like website security, monitoring, scanning, or WAF integration.

No application, database, Docker, installer, or production-server code is changed by this document. This is a future implementation plan.

The central recommendation is:

> A MangoPanel plugin should be a versioned, signed, capability-scoped extension that communicates through stable MangoPanel contracts. Third-party plugin code must run outside the panel process and must never receive unrestricted access to the Docker socket, host filesystem, control-plane database, or customer secrets.

The model combines declarative registration, a versioned Plugin Service Interface (PSI), out-of-process workers, and durable auditable jobs/events.

## 1. Goals, non-goals, and principles

### Goals

The system should allow an administrator to:

- discover, inspect, install, configure, enable, disable, update, roll back, and uninstall plugins;
- understand the publisher, license, version, capabilities, external services, data access, resource needs, and tenant scope before activation;
- expose functionality in admin, client, and reseller panels without editing the core frontend for each plugin;
- attach behavior to accounts, plans, websites, domains, databases, mailboxes, nodes, backups, and jobs;
- run long-running or privileged work through MangoPanel’s agent/job model;
- support open-source plugins and connectors to commercial services;
- keep state and side effects tenant-scoped and auditable;
- preserve platform availability when a plugin is slow, unavailable, misconfigured, or disabled;
- support future multi-node and high-availability operation.

### Non-goals

The first version should not:

- scan a directory and import arbitrary Python files as trusted panel code;
- promise that a sandbox makes malicious code harmless;
- give plugins direct SQL access to MangoPanel’s database;
- let plugins modify arbitrary Docker Compose YAML or execute arbitrary host commands;
- support binary compatibility with internal Python classes;
- let plugins replace authentication, authorization, DNS, TLS, billing, or the scheduler without an explicit core contract;
- redistribute proprietary vendor software without the vendor’s license and approval;
- claim universal compatibility with every future MangoPanel release.

### Principles

1. The core owns authority. Plugins request actions; MangoPanel validates authorization, tenancy, policy, quotas, and lifecycle state.
2. Declarative before imperative. A plugin declares what it contributes. Code runs only behind a narrow service contract.
3. Async for side effects. Network calls, scans, installs, DNS changes, mail changes, and stack changes become durable jobs.
4. Default deny. Capabilities are explicitly granted and are not automatically inherited by every account.
5. No internal-schema coupling. Plugins use versioned APIs and resource references, never arbitrary SQL against core tables.
6. Tenant boundaries are enforced by the host, not trusted to plugin filtering.
7. Failure is a first-class state. A plugin can be unavailable while the rest of MangoPanel remains usable.
8. Every mutation is explainable. Audit records identify actor, plugin, version, capability, resource, job, external operation, and result.
9. HA is designed in. Plugin state, jobs, leases, and side effects must survive restart and not depend on one local disk.
10. Core contracts are smaller than product features. The core exposes stable primitives; a plugin owns feature-specific workflow and UI.

## 2. Current MangoPanel architecture and extension seams

MangoPanel already has useful internal seams, but they are not yet a public plugin API.

| Existing area | Current role | Plugin-system implication |
|---|---|---|
| mangopanel/app.py | HTTP panels, authentication, authorization, API routing, feature status, and job enqueueing | Add a route/page registry and host-owned authorization boundary rather than plugin branches throughout this file. |
| mangopanel/db.py | SQLite schema, migrations, settings, users, accounts, nodes, jobs, and audit-related state | Add core plugin registry, namespaced settings/data, and migration records. Plugins must not share the core schema casually. |
| mangopanel/agent.py | Privileged work, files, Docker Compose, services, backups, mail synchronization, and stacks | Route plugin work through a capability broker with resource scope, idempotency, and executor policy. |
| mangopanel/stack.py | Per-account directory layout and generated Compose configuration | Add typed stack contributions, never arbitrary YAML or host mounts. |
| mangopanel/providers.py | DNS, ACME, mail-edge, and intent/provider abstractions | Formalize these as versioned provider SPIs and adapter-plugin contracts. |
| Static Vue panels | Client/admin/reseller UI | Add plugin UI declarations and namespaced pages/actions without unsafe global script injection. |
| FEATURE_STATUS | Feature maturity/status | Plugins should publish status through a versioned health contract. |
| user_files/accounts/uXXXXXX/ | Account data, runtime, website files, mailboxes, and stack artifacts | Plugins need explicit account filesystem scopes, portable state rules, and backup participation. |
| jobs and agent polling | Asynchronous execution | Plugin jobs need namespaces, leases, retries, progress, cancellation, and audit links. |

A simple “load every plugin.py” approach would allow a plugin to read every account, retrieve encryption keys, monkey-patch authorization, collide with routes or migrations, invoke Docker, block panel startup, and survive disablement as an untracked process. It would turn every plugin update into a control-plane update, which is not an acceptable marketplace boundary.

## 3. Plugin categories and trust classes

### Categories

- Declarative UI/policy: dashboard widgets, settings, feature flags, and quota display.
- Provider/connector: DNS, registrar, ACME, backup storage, CDN/WAF, billing, and licensing.
- Account service: mail filtering, antivirus scanning, image optimization, cache, and logs/metrics.
- Application catalog/installer: Softaculous-like catalog, WordPress toolkit, framework starters, and migration tools.
- Security/compliance: monitoring, malware/integrity scanning, ModSecurity rules, and vulnerability reports.
- Core-control: scheduler, orchestrator, DNS authority, and billing entitlement engine. Initially first-party/trusted only.

### Trust classes

| Class | Runtime | Examples | Approval |
|---|---|---|---|
| T0 declarative | No executable code | UI, settings, metadata | Signature and schema validation |
| T1 connector | Isolated worker, restricted egress | DNS, registrar, CDN, licensing API | Admin approval and capability review |
| T2 account service | Isolated worker and account sidecar | Mail filter, scanner, cache | Admin approval, resource/data review |
| T3 privileged controller | Dedicated worker plus brokered host actions | Stack, backup, orchestration controller | First-party or trusted publisher |
| T4 external service | Local connector only | SaaS WAF, payment, remote security | Vendor credentials, terms, consent |

A container does not make a plugin trusted. The marketplace must display requested capabilities and data access for every executable class.

## 4. Recommended runtime model

Only first-party MangoPanel code should run in the panel process. That tier is appropriate for core provider adapters, migrations, pure transformations, and controlled compatibility shims. These are core modules, not marketplace plugins.

Third-party or independently updated executable plugins should run as separate workers:

- a local unprivileged process for development or tightly trusted deployments;
- a rootless container for ordinary connectors;
- an account-scoped sidecar for service functionality;
- a remote service accessed through a signed connector protocol.

The panel communicates through a versioned JSON-RPC or HTTP protocol over a Unix socket or mutually authenticated loopback endpoint. The worker receives a typed invocation envelope and returns a typed result. It does not receive a database connection, Python object graph, session cookie, or unrestricted host API.

### Controller-style execution

The recommended model is a controller/operator. A desired MangoPanel resource or configuration creates a durable plugin job/event. A plugin controller observes it, makes typed MangoPanel broker calls, converges the external system or account cell, and reports observed state.

The controller must be safe to invoke repeatedly: after a restart or retry it inspects current state and converges instead of blindly duplicating work.

This is informed by the [Kubernetes Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) and [Kubernetes controller pattern](https://kubernetes.io/docs/concepts/architecture/controller/).

Every request should carry a correlation ID, actor, tenant, resource reference, plugin version, API version, deadline, and idempotency key. Payloads are JSON-schema validated. Secrets are references or one-time handles. Long-running work returns a MangoPanel job reference rather than holding an HTTP request open.

## 5. Package and manifest design

### Package layout

A signed archive or OCI artifact should contain:

- plugin.json: required manifest;
- signature.json: publisher signature and digest;
- sbom.spdx.json: dependency inventory;
- README, LICENSE, and CHANGELOG;
- server worker and frontend static assets, when required;
- schemas for config, events, jobs, and UI;
- namespaced migrations;
- contract and smoke tests;
- policy declarations for resources and network.

The ID must be immutable and globally unique, for example org.example.mangopanel.softinstall. A display-name change must not create a new security identity.

### Manifest fields

The manifest should declare:

- id, name, description, publisher;
- immutable semantic version;
- supported PSI and MangoPanel platform ranges;
- license, artifact digest, publisher signature, and key identity;
- trust class and worker entrypoint/image;
- requested capabilities and scopes;
- dependencies and conflicts;
- consumed and produced events;
- namespaced jobs, schemas, retry policy, and resource requirements;
- API routes, pages, menu placement, permissions, and assets;
- global/node/plan/account/website/mailbox settings schemas;
- CPU, memory, storage, process, network, and concurrency limits;
- external egress hosts, ports, and protocols;
- typed stack contributions;
- migrations and uninstall policy;
- health checks, backup policy, privacy/data-transfer declarations;
- HA mode, state-replication requirements, and update/rollback behavior.

The host must show capabilities, data categories, external destinations, and operational effects before activation.

### Capability examples

Capabilities should be granular:

    ui.admin.read
    ui.client.read
    ui.client.action
    account.read
    account.settings.write
    website.read
    website.files.read
    website.files.write
    domain.read
    dns.records.write
    ssl.request
    mail.message.metadata.read
    mail.message.body.scan
    mail.policy.write
    stack.service.request
    stack.config.request
    job.enqueue:plugin.example.scan
    backup.read
    backup.write
    secret.use:vendor.sucuri.api
    network.egress:api.vendor.example:443
    webhook.receive:plugin.example

Capabilities are checked by the host on every broker call. A capability is not a substitute for actor permission or plan entitlement. Capabilities such as Docker socket and host root should not exist for ordinary plugins; privileged first-party controllers should use narrow broker operations instead.

## 6. Lifecycle

### States

    discovered -> verified -> staged -> approved -> active -> degraded
                                          |          |
                                          |          +-> disabled
                                          +-> rejected
    active -> update_staged -> update_approved -> active
    active -> uninstall_pending -> disabled -> removed

Downloaded and verified does not mean active. An artifact must not become active merely because it exists on disk.

### Install flow

1. Obtain a package from a trusted repository or administrator upload.
2. Validate archive, manifest, signature, digest, license, dependencies, and platform compatibility.
3. Inspect SBOM, vulnerabilities, capabilities, egress, and resource requirements.
4. Scan package/image according to repository policy.
5. Stage an immutable content-addressed artifact.
6. Register it as verified or awaiting approval.
7. Let an administrator approve the exact version and capability grant.
8. Run namespaced migrations in a recoverable phase.
9. Start the worker in isolation and run health/contract tests.
10. Activate only after readiness and dependencies pass.
11. Audit actor, digest, signature key, grant, and migration result.

Activation must be atomic from the panel’s perspective. Routes and pages are namespaced and collision-checked. Enabling globally must not silently enable a plugin for every account.

Disable stops new invocations, revokes broker tokens, stops plugin-owned workers, and marks in-flight jobs according to cancellation policy. It must not delete customer data.

Quarantine is triggered by signature mismatch, revoked keys, repeated crashes, protocol violations, critical vulnerabilities, unauthorized capability requests, resource abuse, or emergency action. The plugin manifest defines whether a security/mail feature fails open, fails closed, or retains the last known policy.

The safe uninstall default is disable and retain data. Destructive purge is a separate, strongly confirmed, backup/export-gated operation.

Updates are staged beside the active version. The host verifies the new artifact, compares capabilities, requires re-approval for expanded capabilities, runs migrations and tests, canaries selected nodes/accounts, monitors health, and retains the previous artifact. Rollback must have a real migration strategy.

## 7. Core plugin contracts

### Resource references

Plugins receive opaque typed references such as account://123, website://456, domain://789, mailbox://321, node://17, and job://abc.

The host resolves a reference only after checking actor, tenant, capability, resource status, and operation policy. Plugins receive only a typed field subset through a broker call.

### Events

Events are durable facts, delivered at least once and versioned. Initial families:

- platform.started.v1 and platform.degraded.v1;
- plugin.activated.v1, plugin.disabled.v1, and plugin.updated.v1;
- account.created.v1, account.provisioned.v1, account.suspended.v1, and account.deleted.v1;
- website.created.v1, website.provisioned.v1, website.updated.v1, and website.deleted.v1;
- domain.created.v1, domain.dns_published.v1, and domain.ssl_issued.v1;
- database.created.v1, mailbox.created.v1, and backup.completed.v1;
- node.joined.v1, node.unhealthy.v1, and node.fenced.v1;
- job.completed.v1, job.failed.v1, and job.cancelled.v1;
- user.created.v1, plan.updated.v1, and entitlement.changed.v1.

Each event contains schema version, event ID, occurrence time, actor, tenant/account scope, resource reference, correlation ID, causation ID, and redacted metadata. Plugins deduplicate event IDs and tolerate out-of-order delivery. The host provides replay from a bounded cursor.

### Actions versus filters

MangoPanel should distinguish asynchronous actions/events from synchronous filters. WordPress documents this useful distinction: actions are for side effects and filters modify a value. See the [WordPress hooks documentation](https://developer.wordpress.org/plugins/hooks/).

For MangoPanel, filters are pure, bounded, synchronous transformations and cannot perform network or filesystem access. Actions run through jobs or event delivery. Authorization decisions are never delegated to arbitrary filters, and core request latency must not depend on a vendor API.

### Jobs

Plugin job types are namespaced:

    org.example.softinstall.catalog_sync
    org.example.softinstall.install
    org.example.spamfilter.rebuild_policy
    org.example.spamfilter.scan_message
    org.example.securityscan.website_scan
    org.example.sucuri.attach_site

Every job carries plugin ID/version, actor, tenant/account scope, target resource, validated input, correlation/causation IDs, idempotency key, deadline, retry/cancellation policy, resource needs, node affinity, progress, redacted result, and safe error category.

A plugin cannot create an untracked subprocess or job. Privileged work is requested through a broker, which creates a core-owned child job or audited execution step.

## 8. Account and stack integration

### Typed stack contributions

Account-service plugins contribute an intermediate service specification containing service name, immutable image digest or approved image, allowlisted command/arguments, environment variables with secret references separated, approved account mounts, internal networks, health/readiness checks, CPU/memory/process/disk/port limits, startup dependencies, and backup/HA classification.

The core renderer validates path traversal, privileged mode, host PID/network/IPC, device mounts, Docker socket, unapproved public ports, image policy, conflicts, quotas, and node capacity. Plugin-generated Compose text must never be merged directly into the host Compose file.

Reject or explicitly resolve conflicts involving service names, ports, shared-service versions, mail/DNS ownership, exclusive provider slots, filesystem ownership, startup dependencies, and resource limits. Show a stack diff before applying a service change where practical.

Standard lifecycle hooks should include pre_account_provision, account_provisioned, pre_account_suspend, account_suspended, pre_account_resume, account_resumed, pre_account_delete, account_deleted, pre_stack_rebuild, stack_rebuilt, and post_backup_restore.

Plugins declare whether they block a lifecycle or observe asynchronously. A vendor scan should not indefinitely block account creation merely because an external API is unavailable unless the administrator selected that policy.

## 9. Data, settings, secrets, and migrations

The core should own registry records for plugin identity/publisher, installed versions/digests, signature and approval state, capability grants, worker health, settings references, applied migrations, plugin jobs, event cursors, plugin-owned resources, and quarantine incidents.

Plugin data must be namespaced. A plugin may have its own logical schema or key namespace, but not arbitrary writes to core tables.

Use explicit settings scopes: global, node, plan, account, website/domain/mailbox, and user. The host resolves effective configuration and returns only the scope the plugin may see. Settings need JSON Schema validation, types/ranges/enums, secret markers, defaults, dependencies, capability/role requirements, audit, effective-value preview, reset/export, and redacted display. This aligns with the [WordPress Settings API](https://developer.wordpress.org/plugins/settings/settings-api).

Secrets are references or short-lived operation-scoped handles, never encrypted database values. They never reach browser JavaScript, ordinary logs, traces, job payloads, or error text. A plugin cannot enumerate all secrets. Vendor credentials should be scoped to one vendor/account. Rotation revokes outstanding handles, and secret use is audited.

Plugin migrations are namespaced, deterministic, ordered, validated, time-bounded, recoverable, and included in backup/restore metadata. They do not alter core tables except through an approved host migration and must not assume SQLite behavior if MangoPanel later moves to an HA relational database.

## 10. API, UI, and permissions

Plugin APIs use namespaced paths such as:

    /api/plugins/{plugin_id}/admin/...
    /api/plugins/{plugin_id}/client/...
    /api/plugins/{plugin_id}/reseller/...

The host performs authentication, CSRF protection, rate limiting, actor-role checks, account scoping, and capability checks before forwarding to the worker. A plugin cannot register catch-all routes or replace authentication middleware.

A plugin may declare admin menus, client account tabs, reseller actions, dashboard cards, account/website/mailbox actions, schema-generated settings pages, activity panels, status badges, and external dashboard links.

The first version should prefer host-rendered or static constrained UI. If custom code is needed, use a namespaced iframe or separate sandbox with strict CSP, no panel cookies/local storage, a small bridge, host-owned navigation, and asset limits. WordPress’s [plugin security guidance](https://developer.wordpress.org/apis/security/) is relevant: extensions must validate input, use platform security APIs, and escape output.

Every request checks:

1. Actor permission: is this admin, reseller, or client allowed?
2. Plugin capability: has this plugin been granted the operation?
3. Feature entitlement: is it enabled for this plan/account/website and within quota?

The server repeats these checks even if the UI hides the action. Granular capabilities are preferable to one broad manage-plugin permission; see the [WordPress roles and capabilities model](https://developer.wordpress.org/plugins/users/roles-and-capabilities/).

## 11. Security and supply chain

Executable plugins must be treated as potentially hostile. Risks include compromised dependencies, runtime escapes, SSRF, broker bugs, credential theft, mutable image tags, update takeover, resource exhaustion, unsafe extraction, command injection, and cross-tenant data leakage.

A repository should maintain a signed index, publisher identity and key revocation, immutable artifact digests, build provenance, SBOMs, vulnerability state, supported platform/PSI versions, release notes, a takedown process, and a security reporting path.

Apache SpamAssassin provides a relevant precedent: official releases are accompanied by signatures and checksums. See [SpamAssassin downloads and integrity verification](https://spamassassin.apache.org/downloads.html).

Workers should run as dedicated non-root identities, use rootless containers where possible, apply seccomp/AppArmor-equivalent profiles, drop Linux capabilities, use read-only roots where possible, limit CPU/memory/processes/disk/open files, use explicit scratch directories, restrict egress by host/port, disallow host network/PID/IPC and Docker socket, mount only approved account paths, never receive panel session cookies, use rotating broker credentials, and be terminated on protocol/resource violations.

Webhook endpoints need signatures, timestamp/replay protection, per-plugin secrets, size/type limits, schema validation, idempotency keys, rate limiting, tenant routing, and redacted audit records.

Plugins that inspect website files or mail bodies declare data categories, external transfer, retention, encryption, consent, residency, deletion/export, and vendor access.

“Softaculous-like,” “SpamAssassin-based,” and “Sucuri-like” describe integration shapes, not permission to redistribute or impersonate products:

- Softaculous integration may require a customer/vendor license and should use supported APIs/SDKs.
- SpamAssassin is open source, but package, rule, dependency, and license obligations remain.
- Sucuri is commercial; a connector should use supported vendor APIs and must not describe a local scanner as Sucuri protection.
- Marketplace metadata states whether an integration is official, independent, or third-party.

## 12. HA and multi-node behavior

A single-server plugin can become a hidden single point of failure during account failover, so every plugin declares an HA mode:

| Mode | Meaning | Example |
|---|---|---|
| stateless | Worker can restart anywhere; state is in MangoPanel or an external service | DNS API connector |
| rebuildable | Local state can be recreated from desired state | Website scan cache |
| active-passive | Exactly one worker may act on a tenant at a time | Account installer/mail policy controller |
| distributed | Multiple workers coordinate through supported external state | Catalog mirror/metrics collector |
| external | Critical state belongs to a vendor | SaaS WAF connector |
| unsupported | Cannot safely operate during failover | Must be visible and block HA if required |

An HA-compatible plugin must store desired configuration in replicated control-plane/external state, make side effects idempotent, use leases or account generations, identify node and plugin version, tolerate replay, declare standby behavior, provide readiness before promotion, participate in backup/restore, report convergence/lag, avoid local-only license state, handle duplicate vendor requests, and define compensation for interrupted operations.

The HA controller must not promote an account if a required plugin reports unknown state, unavailable credentials, or unhealthy required service.

Plugins must not update DNS directly. They request a desired endpoint through the core DNS contract; the core/HA controller owns fencing, ordering, health validation, serials, audit, and rollback.

## 13. Example plugin architectures

### 13.1 Softaculous-like application installer

A complete installer needs a catalog, signed metadata/packages, domain/document-root selection, databases/users, credentials, progress, updates, backups/rollback, licensing, and failed-install cleanup.

Softaculous documents API operations for installing, upgrading, importing, listing, backing up, restoring, removing installations, and deleting backups. Its auto-install API describes a class-based integration that triggers installation and returns installed/error results. See [Softaculous API](https://www.softaculous.com/docs/api/api/), [Softaculous Auto Install API](https://www.softaculous.com/docs/api/auto-install-api/), and [Softaculous Remote API](https://www.softaculous.com/docs/api/remote-api/).

Use three components:

1. Catalog controller: sync signed metadata, store catalog records in the plugin namespace, verify checksums/runtime requirements, and apply licensing.
2. Install planner: validate account, quota, domain, document root, runtime, database, disk, and permissions; produce a typed plan; request core jobs; never treat names or paths as shell syntax.
3. Account-scoped runner: operate inside the account boundary, download approved/content-addressed artifacts, extract with traversal protection, write only to the approved root, report progress, support cancellation, and record application/version/checksum/fileset.

The desired-state record should say application version X is installed at website Y, allowing drift detection and rebuild. It should not be only a one-time shell command.

Safety decisions:

- Application-specific steps execute in the account runner, never on the host agent.
- Packages/scripts are sandboxed and signature/checksum-pinned.
- Database credentials are host-generated and passed as handles.
- Upgrades create a backup/snapshot where supported.
- Installed status requires health checks and database completion.
- Partial failure creates a cleanup/recovery plan.
- Passwords never appear in URLs, logs, browser history, or job errors.

### 13.2 SpamAssassin plugin

SpamAssassin is an extensible mail filter with scoring, heuristic/statistical tests, Bayesian filtering, DNS blocklists, collaborative filtering, configuration rules, and integration APIs. Official material describes integration with Postfix, Sendmail, qmail, procmail, and other mail systems, and distinguishes the scanner, spamd, and spamc. See [SpamAssassin](https://spamassassin.apache.org/), [documentation](https://spamassassin.apache.org/doc.html), and the [4.0 manual](https://spamassassin.apache.org/full/4.0.x/doc/spamassassin.html).

The plugin needs global/plan/account/domain/mailbox policy settings, a mail-edge scanning contract, a managed scanner service, rules/update jobs, score/action policy, quarantine/release/report workflows, health metrics, and privacy/resource declarations.

Deployment options are:

1. Shared mail-edge scanner: lower overhead but requires tenant-scoped policy, queue fairness, and strict isolation.
2. Account/node-local scanner: simpler isolation but higher resource cost; Bayesian state and mailbox data require HA/backup treatment.

Prefer a shared core-managed mail-edge integration if MangoPanel’s mail architecture supports it. The plugin contributes policy and scanner behavior through the mail provider contract rather than inserting arbitrary SMTP commands.

Failure policy must be explicit: accept/tag, defer, or reject when scanning is unavailable. Message IDs and idempotency prevent duplicate delivery. Message bodies must never be logged. Quarantine is tenant-scoped with retention limits. Bayesian training is scoped and backed up if considered customer state. Failover must prevent two active scanners applying divergent policy.

### 13.3 Sucuri-like security integration

Website security may mean remote monitoring, cloud WAF/CDN, DNS onboarding, server-side scanning, malware response, backup, or blacklist monitoring. These are separate features.

Sucuri’s technical whitepaper describes DNS/A-record switching for protection, API/dashboard onboarding for remote scanning, and server-scanning agents that may require SFTP/FTP/SSH. See the [Sucuri technical whitepaper](https://sucuri.net/wp-content/uploads/2022/02/sucuri_technical_whitepaper_2022.pdf).

Split the plugin into independently enabled capabilities:

1. Remote monitoring: register domains, schedule scans, import findings, store status, and use vendor credentials through handles.
2. Origin/WAF onboarding: validate origin/TLS/DNS prerequisites, request core-managed DNS changes, wait for vendor/DNS health, and verify protected traffic.
3. Local integrity scanner: account-scoped scanner container, file baseline, evidence, quarantine/reporting, no silent overwrite.
4. Incident/remediation workflow: findings, approval, before/after hashes, backups, restore, and suspension integration.

DNS remains core/HA-controller owned. The plugin cannot claim WAF protection while traffic bypasses the WAF. Malware cleanup is backup-first and approval-gated. The UI distinguishes monitoring, scan health, WAF onboarding, and traffic verification. Vendor outage degrades visibility without silently changing DNS or disabling websites.

## 14. Effects on MangoPanel subsystems

| Subsystem | Required architecture | Risk if ignored |
|---|---|---|
| HTTP/API | Namespaced plugin gateway, schemas, host auth/CSRF/rate limits | Route collision or privilege bypass |
| Admin UI | Catalog, approvals, capabilities, health, logs, rollback | Uncontrolled activation |
| Client UI | Tenant pages/actions, entitlements, progress, consent | Cross-account exposure or misleading status |
| Reseller UI | Delegated policy with reseller/account boundaries | Over-granted features |
| Authentication | Host actor context and short-lived worker tokens | Session theft or alternate login path |
| Authorization | Actor permission + plugin capability + entitlement | UI-only security |
| Database | Registry, namespaced settings/data, migration ledger | Schema collisions/unsafe updates |
| Jobs | Namespaced, idempotent, leased, retryable plugin jobs | Duplicate installs, scans, DNS, or mail work |
| Agent | Capability broker and executor policy | Host/Docker compromise |
| Docker/Compose | Typed service specs and validation | Privileged containers and host mounts |
| Account files | Explicit scopes and backup metadata | Cross-account access/lost state |
| DNS | Core provider calls, ordering, serials, audit | Unready or incorrect endpoint |
| SSL/ACME | Typed certificate intent and challenge policy | Challenge conflicts/secret leakage |
| Mail | Mail-edge SPI, policy scopes, queue/idempotency | Message loss/duplicate delivery/body leakage |
| Backups | Plugin data/config/restore hooks declared | Silent loss after restore |
| Monitoring | Worker health, queue metrics, vendor status | Invisible plugin failure |
| Logging | Correlation IDs and redaction | Secret/content leakage |
| Billing | Entitlement adapter and fail-safe policy | Incorrect paid-feature state |
| HA | Mode, replication, leases, node readiness | Duplicate active controllers/stale protection |
| Upgrades | Compatibility and migration gates | Core updates break services |
| Testing | Contract, tenant, failure, upgrade suites | Works only on developer machine |

## 15. Observability and testing

Each plugin exposes worker liveness/readiness, version/digest, last invocation, error category, queue depth, retries, external latency/rate-limit state, resource usage, affected accounts, migration/update state, credential health, and HA convergence.

Use statuses such as not_installed, installed_disabled, starting, ready, degraded, blocked_by_dependency, blocked_by_capability, quarantined, updating, and failed.

User-facing errors should be actionable and safe, such as “the installer is waiting for the account database job,” “the vendor catalog is unavailable; existing installations are unaffected,” or “monitoring is active, but WAF traffic verification is pending.” Never show stack traces, keys, SMTP credentials, message bodies, or vendor response headers.

Publish contract fixtures for manifest validation, capability/scope checks, event replay, job retry/idempotency, worker timeouts, settings schemas, resource references, stack validation, secret handles, webhook signatures, backups, and HA failover.

Tenant tests must prove that account A cannot read or affect account B’s settings, files, jobs, scans, mail, logs, events, or webhooks. Failure tests include worker crashes, duplicate events, external timeouts, updates during jobs, node loss during failover, revoked credentials, full disk/quota, malformed catalogs, invalid stack contributions, and quarantine while accounts are active.

Use explicit PSI versions. A plugin declares support for PSI v1; breaking changes require PSI v2. Provide an SDK/generated client, compatibility matrix, deprecation warnings, and migration guidance. Plugins must not import internal classes from the application, database, agent, or stack modules as their public API.

## 16. Repository and marketplace

Support:

1. MangoPanel official repository: first-party, reviewed, signed plugins.
2. Trusted publisher repository: independent publisher with a configured trust key.
3. Private/local repository: internal, customer-specific, or air-gapped plugins.

Listings show identity, verified publisher, version/digest, license, capabilities, data access, destinations, resources, supported platform/PSI versions, HA behavior, backup/restore behavior, limitations, test status, and support/security contacts.

Installing a plugin must not automatically enable it for all accounts, alter DNS, change mail, install account containers, expose client UI, send customer data, or change billing. Those are separate visible operations.

## 17. Phased roadmap

### Phase 0: contracts

Define PSI v1 resource references, manifest, capabilities, job/event envelopes, health states, and security/licensing policy. Formalize which provider intents and agent jobs are public extension points.

### Phase 1: declarative registry

Implement registry state, signed verification, approvals, capabilities, schema settings, pages, menus, and T0 plugins only.

### Phase 2: provider workers

Implement worker protocol, secret handles, egress policies, DNS/ACME/registrar/backup connectors, durable plugin jobs, events, and audit integration.

### Phase 3: account services

Implement typed stack contributions, account filesystem scopes, quotas, service health, rebuild behavior, and a tightly reviewed mail-filter/scanner pilot.

### Phase 4: application installer

Implement signed catalogs/artifacts, install plans, account runner, document-root/database orchestration, backups, updates, rollback, and drift detection. Begin with one narrow application rather than a general arbitrary-script engine.

### Phase 5: HA and security integrations

Implement plugin HA declarations, controller leases, replay-safe events, vendor onboarding, core-owned DNS requests, scan findings, WAF verification, and incidents.

### Phase 6: marketplace

Implement signed repository indexes, publisher identity/key revocation, security/compatibility scans, review policy, private registry, and offline import.

## 18. Production acceptance criteria

The platform is not production-ready until:

- executable third-party plugins cannot run in the panel process;
- every executable plugin has a signed immutable artifact and declared capabilities;
- administrators can see and approve data access, egress, resource, and HA behavior;
- every plugin API call is host-scoped to a tenant/resource;
- plugin jobs are durable, idempotent, retryable, auditable, and observable;
- workers cannot access Docker socket or arbitrary host paths;
- UI registration cannot override core routes or auth;
- settings are schema-validated and secrets protected;
- disable/quarantine revokes authority and stops new work;
- update/rollback behavior is tested;
- backup/restore includes declared state;
- provisioning, suspension, deletion, and rebuild have explicit plugin semantics;
- HA compatibility is declared and tested;
- account A cannot observe or affect account B;
- vendor outage degrades only the relevant feature unless a blocking policy was selected;
- commercial integrations respect licenses, API terms, identity, and trademarks.

## 19. Recommended decisions

1. Make out-of-process workers the default for third-party executable plugins.
2. Limit in-process extensions to trusted first-party core code.
3. Make the manifest and capability approval central to installation.
4. Formalize existing provider intents and agent jobs into versioned SPIs.
5. Use controller/event/job patterns so plugins converge desired state and survive retries.
6. Make typed stack contributions the only supported way to add account services.
7. Keep DNS, SSL, authorization, secrets, and host execution core-owned.
8. Treat application installers, mail filters, and security connectors as different classes with different isolation/data policies.
9. Make HA mode, state replication, and failover readiness mandatory manifest fields.
10. Start with an official/private registry and contract tests before opening a public marketplace.

The architectural boundary is simple: MangoPanel exposes stable, narrow capabilities and a durable control loop. Plugin authors build features on those contracts, while MangoPanel remains the authority for identity, tenant boundaries, quotas, secrets, host execution, DNS, lifecycle, and audit.

## 20. Research references

- [WordPress Plugin Handbook](https://developer.wordpress.org/plugins/)
- [WordPress hooks: actions and filters](https://developer.wordpress.org/plugins/hooks/)
- [WordPress Settings API](https://developer.wordpress.org/plugins/settings/settings-api/)
- [WordPress plugin security](https://developer.wordpress.org/apis/security/)
- [WordPress roles and capabilities](https://developer.wordpress.org/plugins/users/roles-and-capabilities/)
- [cPanel guide to plugins](https://api.docs.cpanel.net/guides/guide-to-cpanel-plugins)
- [Kubernetes Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
- [Kubernetes controller pattern](https://kubernetes.io/docs/concepts/architecture/controller/)
- [Softaculous API](https://www.softaculous.com/docs/api/api/)
- [Softaculous Auto Install API](https://www.softaculous.com/docs/api/auto-install-api/)
- [Softaculous Remote API](https://www.softaculous.com/docs/api/remote-api/)
- [Apache SpamAssassin official site](https://spamassassin.apache.org/)
- [Apache SpamAssassin documentation](https://spamassassin.apache.org/doc.html)
- [Apache SpamAssassin 4.0 manual](https://spamassassin.apache.org/full/4.0.x/doc/spamassassin.html)
- [Apache SpamAssassin downloads, signatures, and checksums](https://spamassassin.apache.org/downloads.html)
- [Sucuri technical whitepaper](https://sucuri.net/wp-content/uploads/2022/02/sucuri_technical_whitepaper_2022.pdf)

