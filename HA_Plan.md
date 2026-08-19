# MangoPanel Decentralized High-Availability Plan

Status: architecture proposal only

This document describes how MangoPanel could support an account/stack being marked **High availability** so that the account can be served by another online node after a node failure, with replicated data and DNS failover. It does not change the application, database, Docker manifests, or production infrastructure.

The central conclusion is important:

> DNS reassignment is only the final traffic switch. It is not the HA mechanism.

Before DNS is changed, the platform must establish a single authoritative failover decision, fence the failed node so it cannot continue writing, promote a sufficiently current data replica, start and validate the account stack on the replacement node, and only then update DNS. Otherwise the design can produce split-brain writes, stale websites, corrupted databases, duplicate mail delivery, or DNS pointing at an unready server.

## 1. Goals, non-goals, and terminology

### Goals

For an account whose HA policy is enabled:

- Keep a warm or hot copy of its workload on one or more other nodes.
- Detect loss of the active node using more than one failure observer.
- Elect exactly one failover controller for the account.
- Fence the old node before allowing the replacement to accept writes.
- Promote the best eligible replica and start the account services there.
- Update the account’s web, tool, mail, and other public endpoints to the selected node.
- Replicate website files, databases, mail state, configuration, certificates, and required secrets.
- Rebuild replication after failover so the new active node becomes the source for a new standby.
- Expose replication lag, last successful sync, failover state, data-loss estimate, and degraded conditions to administrators.

### Non-goals

This plan does not promise literally zero interruption for ordinary DNS-based failover. Recursive resolvers, operating-system caches, browser caches, existing TCP connections, and TLS sessions may continue to use the old address until their cached or connected state expires. A stable anycast/load-balancer endpoint is required for materially faster failover than DNS can provide.

This plan does not make every service active-active. Active-active is appropriate for some stateless web traffic and some database technologies, but it is unsafe to apply indiscriminately to mutable website files, mailboxes, queues, or arbitrary customer containers.

This plan does not make two nodes authoritative merely because they can see each other. A quorum and fencing authority are required to prevent split brain.

## 2. Current MangoPanel architecture and HA assessment

The repository currently has a useful control-plane/data-plane separation, but its persistence and execution assumptions are single-host assumptions.

### Current request and provisioning path

The current flow is:

```text
browser
  -> Python panel process on ports 8000/8001/8002
  -> SQLite control-plane database
  -> jobs row
  -> worker / Node Agent
  -> local account directory and generated Docker Compose
  -> local Docker account stack
  -> local Caddy edge proxy
```

The relevant implementation is distributed across:

- `mangopanel/app.py`: HTTP panels, authentication, API writes, DNS/SSL actions, job enqueueing, public tool routes, and status reads.
- `mangopanel/db.py`: SQLite schema, migrations, connection/retry behavior, seed data, nodes, settings, and jobs.
- `mangopanel/agent.py`: job dispatch, stack materialization, filesystem operations, Docker Compose execution, service checks, backups, DNS artifacts, and account actions.
- `mangopanel/stack.py`: per-account directory layout and Docker Compose generation.
- `mangopanel/providers.py`: local DNS/ACME abstractions, Cloudflare integration, and mail-edge provider abstractions.
- `docker-compose-edge.yml`: one host-local Caddy Docker proxy on ports 80 and 443.
- `user_files/data/mangopanel.sqlite3`: the control-plane source of truth.
- `user_files/accounts/uXXXXXX/`: account data, generated configuration, website roots, mailbox files, backups, certificates, and runtime artifacts.

### Current state ownership

| State | Current owner | HA risk | Required future owner |
|---|---|---|---|
| Users, admins, plans, accounts, domains, websites | SQLite | One file, one writer authority, no safe multi-host WAL | Replicated relational control-plane database with one elected writer |
| Jobs and job status | SQLite `jobs` table plus worker polling | Duplicate execution, stale claims, no distributed lease/fencing | Durable queue in the control-plane DB or HA queue with leases and idempotency |
| Node membership | `nodes` rows and local startup bootstrap | A row is not a consensus membership system | Quorum-backed membership, heartbeats, epochs, and fencing records |
| Website files | Per-account local bind mounts | Not available on another host without replication | Replicated filesystem/object-backed content with a clear write policy |
| MariaDB | One MariaDB container per account | Local volume and local container; no promotion protocol | Cell-level Galera/proxy or explicit primary/standby replication |
| PostgreSQL | One PostgreSQL container per account | Local volume and local container; no promotion protocol | HA PostgreSQL service or explicit streaming replica/promotion |
| Redis | One Redis container per account | Cache and possible application state are local | Sentinel/cluster or explicitly disposable cache semantics |
| Mail | Account mailserver plus shared mail edge | Mail queues/mailboxes/DKIM/runtime are host-local | Replicated mailbox store and HA mail edge with careful MX behavior |
| Caddy routes and certificates | Host-local Docker proxy and Caddy storage | Replacement node may not have routes/certificates | Deterministic route desired state and shared/distributed certificate storage |
| DNS | Local PowerDNS artifacts or provider API | Local authoritative service or a single API credential path | External/provider-backed authoritative DNS plus quorum-controlled updates |
| Secrets | SQLite-encrypted values and files | Key availability and rotation are host-dependent | Replicated secret store or encrypted replicated secret material with a key quorum |
| Logs and analytics | Local files/database rows | Loss or duplication during failover | Centralized append-only or object-backed logs with node identity |

### Existing important constraints

1. **SQLite WAL is not a distributed database.** SQLite’s own documentation says all processes using a WAL database must be on the same host; WAL does not work over a network filesystem. Copying the SQLite file between nodes, putting it on NFS, or allowing two panel processes to write separate copies is not a safe HA design. See [SQLite WAL](https://www.sqlite.org/wal.html) and [SQLite file format](https://www.sqlite.org/fileformat.html).
2. **A generated Docker Compose file describes one host.** The current account stack uses bind mounts, host ports, local container names, and an external `mangopanel-edge` network. A second server cannot simply run the same Compose file and see the first server’s volumes or network.
3. **The current fixed port allocation is host-local.** It is useful for direct service access, but it is not a stable service identity across nodes. Public traffic should terminate at a stable service identity and use internal service discovery or a node-local proxy.
4. **Current Caddy state is host-local.** A replacement Caddy needs the same route configuration, certificate keys, and automation state. Caddy documents that instances using the same storage can coordinate certificate management, but that storage must actually be shared through a suitable storage implementation; two unrelated local disks are not the same storage. See [Caddy Automatic HTTPS](https://caddyserver.com/docs/automatic-https).
5. **The current worker assumes local execution.** A job can write files and invoke Docker on the machine where the worker runs. HA needs job ownership, leases, fencing epochs, retry semantics, and idempotent side effects.

## 3. HA policy model

The HA switch should be an account policy, not a global mode that silently changes every account.

### Proposed account policy

```text
ha_enabled: false | true
ha_profile: standard | strong | custom
preferred_node_id: node-a
failover_node_ids: [node-b, node-c]
replication_mode: async | sync
file_replication_mode: async | sync
database_replication_mode: async | sync
dns_failover_enabled: true | false
dns_provider_scope: managed-only | provider-api | external-manual
max_replication_lag_seconds: 30
max_data_loss_seconds: 30
fencing_required: true
failover_mode: automatic | operator-approved
```

The UI should show a policy preview before enabling HA:

- eligible nodes and failure domains;
- available CPU, RAM, storage, IPv4, and IPv6;
- replication method selected for files and each database engine;
- estimated RPO and expected DNS convergence time;
- whether the DNS provider is controllable by MangoPanel;
- whether fencing is configured and testable;
- whether mail and direct service ports can fail over;
- whether the account contains unsupported state or plugins.

An account should not be allowed to enter `automatic` HA unless the platform has a tested fencing method and a healthy replica. An account can be marked `replica degraded`, but it must not be advertised as HA while its only copy is stale or missing.

### Recommended initial profile: active/passive warm standby

The first implementation should use active/passive per account:

- one active writer node;
- one warm standby in a different failure domain;
- optional third replica for disaster recovery;
- standby containers either stopped, read-only, or started in an isolated network;
- only the active node owns the public write endpoint;
- all writes are replicated from active to standby;
- promotion is serialized through a quorum-backed controller.

This is safer than active-active file and mail writes. It also maps naturally to the current account-stack model: an account remains a unit of placement, filesystem, services, and failover state.

### Strong profile

For accounts that require RPO 0 or near-zero:

- synchronous database commit to a remote eligible member;
- synchronously replicated or distributed website storage;
- quorum-backed promotion;
- failover only when a current replica is confirmed;
- write availability may pause when the required quorum is unavailable.

Strong HA trades availability and latency for durability. PostgreSQL documents that synchronous replication waits for standby confirmation and increases response time; it also explains that asynchronous replication can lose committed transactions not yet replicated at failure time. See [PostgreSQL streaming and synchronous replication](https://www.postgresql.org/docs/current/warm-standby.html).

## 4. Recommended target architecture

### 4.1 Separate the control plane from account cells

Use three logical layers:

```text
                         Stable panel/API endpoint
                                  |
                    +-------------+-------------+
                    |                           |
             Panel/API replicas          HA control services
                    |                  (DB, quorum, jobs)
                    +-------------+-------------+
                                  |
             +--------------------+--------------------+
             |                    |                    |
       Node A / cell member  Node B / cell member  Node C / witness/member
             |                    |                    |
       account active/standby   account standby     quorum, replica, edge
```

The panel processes should become stateless API replicas. They should read and write one replicated control-plane database and enqueue desired-state operations. They should not decide failover based on local observations or local SQLite files.

Each node should run a node agent and local edge proxy. The agents reconcile desired account placement from the control plane. They must not independently promote an account merely because the active node is unreachable from their own network segment.

### 4.2 Quorum and fencing

Use an odd number of independent quorum members—normally three for the first HA cell, five for larger deployments. The quorum store can be etcd or another proven consensus system. etcd requires a majority for writes and uses Raft-based consensus; a three-member cluster tolerates one member failure, while two members tolerate no failure without losing quorum. See [etcd quorum FAQ](https://etcd.io/docs/v3.3/faq/) and [etcd API guarantees](https://etcd.io/docs/v3.7/learning/api_guarantees/).

The quorum store should hold:

- node membership and node fencing state;
- account active-owner lease;
- promotion epoch and generation;
- last accepted replication position;
- failover lock;
- desired DNS target and update generation;
- controller lease and observed health reports.

The quorum store should not replace the relational database. It is for coordination and short, authoritative state—not customer billing, websites, audit history, or arbitrary relational queries.

#### Fencing is mandatory

Before promotion, the system must guarantee that the old active node cannot continue serving writes. Possible fencing mechanisms, in descending order of confidence:

1. Cloud provider power-off or reboot API (STONITH).
2. Provider network firewall/security-group rule that blocks public and replication traffic.
3. Dedicated out-of-band management controller.
4. Hypervisor-level fencing.
5. As a last resort, a lease plus a node-local self-fencing watchdog that powers down when it loses quorum.

DNS updates are not fencing. A resolver can keep the old address, an existing connection can remain open, and a partitioned node can continue writing. If fencing cannot be proven, automatic promotion must stop and require operator approval.

### 4.3 Orchestration choice

#### Option A: retain Docker Compose and build a custom HA supervisor

This is the smallest conceptual migration but the largest amount of custom correctness code. The supervisor would need to replicate files, promote databases, fence nodes, start Compose stacks, distribute Caddy routes, and manage every side effect. Docker Compose itself does not provide cross-host scheduling, replicated volumes, consensus, or promotion semantics.

Use this only as a short transitional phase for a small number of accounts. It can support active/passive stacks if the data layer and fencing are external, but it should not be called full HA merely because a supervisor runs `docker compose up` on another host.

#### Option B: Docker Swarm

Swarm provides multi-host services, placement constraints, replicated/global services, and an overlay network. Docker documents that replicated services may be placed according to constraints and that global services run on every eligible node. See [Docker Swarm services](https://docs.docker.com/engine/swarm/services/).

Swarm helps with stateless service placement, but it does not solve the hardest MangoPanel problems automatically:

- persistent per-account data still needs replicated storage;
- MariaDB/PostgreSQL promotion still needs a database design;
- shared Caddy certificate storage still needs safe shared storage;
- mail queue and mailbox consistency still need an explicit design;
- a single Docker volume is not a cross-host replicated volume;
- the current Compose assumptions and host-port bindings need redesign.

Swarm is a possible intermediate target if MangoPanel wants to stay Docker-native, but it should not be the source of truth for account HA state.

#### Option C: Kubernetes or another declarative cluster scheduler

Kubernetes provides the primitives needed for a larger platform: Deployments for stateless web services, StatefulSets for stateful services, Services for stable discovery, PersistentVolumes for storage attachment, anti-affinity/topology spreading, controllers, readiness probes, and PodDisruptionBudgets. Kubernetes also explicitly warns that PDBs protect voluntary disruption, not every node failure. See [Kubernetes disruptions](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/), [PDB guidance](https://kubernetes.io/docs/tasks/run-application/configure-pdb/), and [self-healing](https://kubernetes.io/docs/concepts/architecture/self-healing/).

Kubernetes is the strongest long-term target for many nodes and many HA accounts, but it raises the operational bar: a production control plane, storage class, network policy, ingress/gateway, secrets management, upgrades, and multi-zone quorum are required. A two-server Kubernetes installation is not automatically HA.

#### Recommendation

Define an orchestration-neutral MangoPanel HA contract first, then implement it on a three-node cell. For a small deployment, use an external HA control plane plus a custom account supervisor; for a larger deployment, compile the same contract into Kubernetes resources. Do not expose Docker Compose as the HA abstraction.

## 5. Data replication design

Replication must be designed per data type. “Replicate the account” is not one operation.

### 5.1 Website files and account filesystem

Current website roots, logs, backups, SSL artifacts, mail storage, and runtime files live below each account’s local directory. The target design should separate them:

| Data | Suggested policy | Notes |
|---|---|---|
| Website document roots | Replicated filesystem or object-backed deployment source | Customer writes need consistent POSIX semantics; object storage alone is not a drop-in filesystem for PHP applications. |
| Uploaded media | Replicated filesystem initially; object storage later | WordPress and similar applications often expect atomic rename and directory semantics. |
| Generated configs | Rebuild from control-plane desired state | Do not treat generated Compose/config files as the primary source of truth. |
| Access/error logs | Local spool plus asynchronous shipping | Logs should not block website writes or promotion. |
| Backups | Offsite object storage with versioning/retention | A standby is not a backup. |
| Temporary/cache files | Do not replicate unless application requires them | Recreate on promotion. |
| Runtime locks/PIDs | Never replicate | Node-local only. |

Possible storage implementations:

- distributed filesystem such as CephFS for a multi-node cell;
- replicated block/filesystem with a quorum and explicit primary ownership;
- a managed shared filesystem with documented failover guarantees;
- application-level object storage for applications that support it.

Do not place SQLite WAL, MariaDB data directories, or PostgreSQL data directories on an arbitrary shared network filesystem. Database engines need their own replication protocol and storage guarantees.

For active/passive website storage, the safest initial write policy is:

1. active node mounts the account filesystem read-write;
2. standby receives continuous replication but mounts it read-only or does not mount it into serving containers;
3. failover controller fences the old active;
4. replication is promoted or a writable snapshot is created;
5. standby services start;
6. the new active becomes the only writer.

### 5.2 Per-account MariaDB

The current design creates a MariaDB container inside each account stack. There are three possible future models:

1. **Per-account primary/standby replication:** preserves isolation but requires promotion, GTID/position tracking, credentials, schema drift handling, and one replication pair per HA account. It provides an asynchronous RPO unless synchronous replication is added.
2. **Cell-level MariaDB Galera cluster:** one three-node InnoDB cluster per cell, with separate databases/users per account and a stable database proxy endpoint. MariaDB documents Galera as virtually synchronous, multi-primary, and requiring at least three nodes for robust quorum; it also documents SST/IST rejoin behavior. See [MariaDB Galera HA](https://mariadb.com/docs/galera-cluster/high-availability) and [Galera replication guide](https://mariadb.com/docs/galera-cluster/galera-cluster-quickstart-guides/mariadb-galera-cluster-replication-guide).
3. **Managed HA database service:** simplest operationally if available, but changes the deployment and isolation model.

Recommendation: use a cell-level Galera cluster for HA accounts that need strong MariaDB durability, behind a stable proxy. Do not run a three-node Galera cluster separately inside every small account; the resource cost, quorum count, upgrades, and failure handling would be disproportionate. Non-HA accounts can retain the existing single container model.

Galera caveats:

- use InnoDB-compatible tables;
- preserve transaction and schema compatibility;
- configure `wsrep` health/readiness before serving traffic;
- keep cluster members in independent failure domains;
- do not allow a partitioned minority to accept writes;
- test SST/IST recovery and backup restore;
- use a proxy or service identity, not a hard-coded container IP.

### 5.3 Per-account PostgreSQL

PostgreSQL streaming replication is asynchronous by default. Synchronous replication can protect committed transactions at the cost of commit latency and possible write unavailability when the synchronous standby is not available. See [PostgreSQL warm standby and synchronous replication](https://www.postgresql.org/docs/current/warm-standby.html).

Recommended model:

- move HA account PostgreSQL into a cell-level PostgreSQL HA service;
- provide a stable read/write endpoint through a proxy or service discovery;
- use streaming replicas and an orchestrated promotion protocol;
- use synchronous replication only for strong-profile accounts or low-latency failure domains;
- use asynchronous replicas for standard-profile accounts with an explicit RPO.

If per-account PostgreSQL containers are retained, each account needs its own replication slot/standby, WAL retention policy, promotion marker, credentials, and rejoin process. That is operationally expensive and should be reserved for strict isolation requirements.

### 5.4 Redis

Redis replication is asynchronous. Redis Sentinel provides monitoring, automatic failover, and a service-discovery API, but Redis documents that Sentinel cannot guarantee every acknowledged write is retained after failure because basic replication is asynchronous. It also recommends at least three independent Sentinel instances for robust deployment. See [Redis replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/) and [Redis Sentinel](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/).

Classify current Redis data before adding HA:

- object cache: disposable; rebuild after failover;
- sessions: preferably JWT/stateless or control-plane DB-backed; do not make a single Redis keyspace the only session authority;
- queues: must not be silently lost; move durable jobs to the control-plane DB or a durable HA queue;
- locks: must use fencing tokens and expiry, not merely Redis `SETNX`;
- application data: only call it HA if the application’s durability requirement is known.

For account Redis, use Sentinel or a cell-level Redis service only when the application actually needs Redis durability. Never let Redis be the only copy of customer content.

### 5.5 Mail and mailbox data

Mail is not equivalent to web traffic:

- incoming SMTP senders retry according to their own policies;
- existing IMAP/SMTP sessions terminate on node loss;
- mailbox indexes and message files must be consistent;
- DKIM private keys must follow the account;
- outgoing queue state must not be duplicated by two active nodes;
- MX DNS changes can take time to converge.

Recommended model:

- replicate mailbox message storage and indexes using the chosen storage layer;
- run mail edge ingress on at least two nodes behind a stable endpoint or provider;
- use a single active queue owner or a mail system designed for multi-node queue safety;
- keep DKIM material in the replicated secret/control-plane layer;
- fail over MX only through a quorum-controlled DNS/provider update;
- accept that in-flight sessions will reconnect and use SMTP retry semantics.

The current shared mail-edge abstraction is a good place to add node-independent route state, but the provider itself must have multiple reachable edge endpoints.

### 5.6 Control-plane database

The current SQLite database must not be replicated by copying files or sharing a WAL file. The target control plane should use a relational database with:

- one logical writer at a time;
- automatic or operator-approved primary promotion;
- a stable read/write endpoint;
- transactions for desired state plus job creation;
- row-level leases or `SKIP LOCKED` job claims;
- point-in-time recovery and tested backups;
- encryption in transit and at rest;
- schema migrations run once under a migration lock.

PostgreSQL is the natural target because MangoPanel already uses PostgreSQL for account workloads and its official replication model explicitly supports asynchronous, synchronous, cascading, and failover designs. The control plane should still remain single-writer logically; multi-master relational writes would create conflict-resolution requirements across nearly every table.

## 6. DNS and endpoint failover

### 6.1 DNS is a convergence mechanism, not an immediate switch

The failover controller can update an A/AAAA record quickly, but recursive resolvers and clients may retain the old record for its TTL or longer. Cloudflare documents that TTL controls cache duration and that users may take longer than five minutes to observe changes even when proxied records use the default 300-second TTL. See [Cloudflare DNS TTL](https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/) and [Cloudflare DNS records/API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/).

Therefore the HA status must distinguish:

- `promoted`: replacement is serving locally;
- `dns_update_requested`: provider API accepted the change;
- `dns_observed`: authoritative nameservers show the new value;
- `dns_converging`: public resolvers may still return the old value;
- `service_available`: health probes from outside the cell succeed.

The UI must not claim “immediate failover” just because the provider API returned HTTP 200.

### 6.2 Stable endpoint is preferred

For the lowest interruption:

1. put a stable load balancer, anycast service, or provider proxy in front of nodes;
2. health-check each node;
3. route traffic away from the failed node without changing customer DNS;
4. use DNS only for the stable endpoint.

Cloudflare-proxied domains can use a provider-side load-balancing/failover product if that is acceptable for the deployment. The origin IP then remains hidden and the provider performs health-based steering. This is a different architecture from directly changing customer A records and must be reflected in the DNS provider adapter.

### 6.3 If direct DNS failover is required

Use these rules:

- keep A and AAAA records consistent; never leave an old AAAA record pointing at the failed node;
- set a low TTL before HA activation, not after failure;
- update only records the provider/API has authorized MangoPanel to manage;
- use compare-and-set or generation metadata so a delayed controller cannot overwrite a newer failover;
- update web/tool endpoint records together;
- handle mail MX separately and conservatively;
- verify authoritative and public resolver observations after updating;
- do not issue a certificate until the new endpoint passes external validation;
- preserve the previous endpoint as a rollback target until replication and fencing state are settled.

### 6.4 Endpoint inventory

The failover record set must include more than the primary website:

| Endpoint | Failover requirement |
|---|---|
| `example.com`, `www.example.com` | A/AAAA or stable proxy target |
| Per-account Filebrowser/phpMyAdmin/webmail names | Route or DNS must follow active node; SSO issuer must remain the same |
| Panel hostnames | Stable control-plane endpoint, preferably load-balanced |
| MX records | HA mail edge, not merely the web node |
| SPF/DKIM/DMARC | Values should not contain a dead node IP; DKIM key follows account |
| FTP/SFTP | Requires stable proxy/VIP or explicit endpoint failover; DNS alone does not migrate existing sessions |
| Database hostnames shown to customers | Must resolve to a stable proxy/service, not a container IP |
| ACME challenge path | Must be served by the active edge, or use DNS-01 |

## 7. TLS and certificate strategy

For a node failover design, DNS-01 or pre-provisioned wildcard certificates are preferable to relying on an HTTP-01 challenge during the incident. Let’s Encrypt documents that DNS-01 uses DNS TXT records and can support wildcard certificates, while HTTP-01 requires the challenge to be reachable over HTTP. See [Let’s Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/).

Recommended approach:

- use Caddy on every edge node with deterministic route configuration;
- store certificates/keys in replicated secure storage or use a certificate issuer that can issue independently on each node;
- prefer DNS-01 for wildcard/account namespaces where DNS API permissions are available;
- use a stable ACME account and rate-limit certificate operations;
- never copy a private certificate key through an unencrypted ad-hoc failover script;
- keep certificate state separate from customer website content;
- test certificate availability on the standby before it is declared eligible.

Caddy’s documentation says Caddy instances using the same storage can share resources and coordinate certificate management. The HA implementation must provide a real shared/distributed storage module or a controlled certificate distribution process; mounting two unrelated local Caddy data directories does not satisfy this requirement.

## 8. Failover state machine

Each HA account should have a persisted state machine with an epoch/generation. A possible state sequence is:

```text
healthy-active
    |
    | health quorum observes active failure
    v
suspect
    |
    | quorum confirms + fencing succeeds
    v
fenced
    |
    | replica lag and data-integrity gates pass
    v
promoting
    |
    | databases/files/services become ready
    v
serving-new-node
    |
    | DNS/provider update accepted and external probes pass
    v
active-degraded
    |
    | replacement replica catches up
    v
healthy-active
```

Failure states must be explicit:

- `blocked-no-quorum`: no safe authority to promote;
- `blocked-no-fence`: old node may still write;
- `blocked-replica-stale`: no replica meets RPO policy;
- `blocked-storage`: data volume cannot be mounted writable;
- `blocked-database`: database promotion/readiness failed;
- `dns-pending`: service is ready but provider/DNS has not converged;
- `manual-recovery-required`: operator must choose a source of truth.

### Promotion sequence

1. **Observe:** independent health observers check node, edge, account services, replication, and control-plane health.
2. **Debounce:** require a failure window and quorum agreement; do not promote on one missed heartbeat.
3. **Acquire epoch:** create a monotonically increasing account promotion epoch in the consensus store.
4. **Fence:** power off or network-isolate the old node and verify the fence action.
5. **Select replica:** choose the replica with the highest safe replication position that meets the account’s RPO policy.
6. **Promote storage:** make the account filesystem writable only on the selected node.
7. **Promote databases:** promote MariaDB/PostgreSQL through their supported protocol; verify role and replication position.
8. **Reconfigure services:** render the account desired state on the selected node, start the stack, and attach it to the local edge.
9. **Health gate:** verify web readiness, PHP, database connection, Filebrowser, phpMyAdmin, mail edge, required cron state, and certificate availability.
10. **Update DNS/proxy:** update the provider records using the new epoch/generation.
11. **External verify:** probe from outside the cell; report DNS convergence separately from local readiness.
12. **Rebuild standby:** after promotion stabilizes, seed a new replica from the new active and clear degraded status only when lag is within policy.

### Failback sequence

Failback must not be automatic merely because the original node returns. The old node is stale and potentially contains writes made during the outage.

1. fence or keep the returning node out of service;
2. wipe/reseed its account data from the current active or perform a verified incremental rejoin;
3. make it a standby;
4. verify replication and health;
5. perform a controlled switchover if desired;
6. update DNS only after the new target is serving.

## 9. Control-plane and job changes required later

This section intentionally describes future implementation work; it is not being applied by this document.

### Schema additions

Add explicit entities/fields for:

- `ha_policies` per account;
- `account_replicas` with node, role, replication method, position, lag, and last sync;
- `account_failover_events` with epoch, reason, observer votes, fence result, promotion result, DNS result, and operator;
- `node_memberships` with stable node UUID, failure domain, capabilities, agent version, quorum state, and fence provider;
- `account_ownership_leases` or references to the consensus epoch;
- `dns_failover_records` with provider record ID, desired target, observed target, TTL, generation, and last verification;
- `data_replication_tasks` and snapshots;
- `job_leases` with owner node, lease expiry, fencing epoch, attempt, idempotency key, and side-effect status;
- `service_health_observations` with observer identity and timestamp.

Do not overload the existing `nodes.status` or `account_stacks.status` strings to carry all of this state.

### Desired state versus runtime state

The database should hold desired state such as:

```text
account u000001:
  desired_node_set = [node-a, node-b]
  active_epoch = 42
  desired_active_node = node-b
  stack_generation = 109
  dns_generation = 76
  data_policy = strong
```

The node agent reports observed state, but never changes ownership without a valid epoch/lease. Generated Compose/Kubernetes manifests are derived artifacts and can be regenerated on any eligible node.

### Jobs

Every side-effecting job needs:

- an idempotency key;
- a desired-state generation;
- a fencing epoch;
- a lease with expiry;
- safe retry behavior;
- an explicit compensation or recovery state;
- an audit trail;
- no assumption that a local file or container still exists.

For example, a `provision_hosting_account` job must not blindly run on two nodes. It should verify that its node owns the current account epoch and that the account generation is still current before writing files, promoting a database, or updating DNS.

### Panel availability

Run multiple panel/API replicas behind a stable endpoint. JWT authentication reduces dependence on local process memory, but all token secrets, sessions that are stored server-side, rate limits, audit writes, and authorization data must use replicated shared state. The panel must not use a local `user_files` directory as an implicit database.

The worker should be separated from HTTP API replicas or use a distributed lease. Running every worker on every node without claim protection will duplicate provisioning and failover jobs.

## 10. Detailed subsystem impact analysis

### Authentication and sessions

- Preserve one cluster-wide JWT secret or use a versioned key set replicated through a secret manager.
- Rotate keys with overlapping validity windows.
- Move rate limits and TOTP challenge state to the replicated control plane or an HA cache.
- Ensure token verification does not depend on the node that issued the token.
- Revoke sessions through shared state; do not assume local process memory.
- Add node and epoch claims only for internal agent credentials, not as a user-facing workaround.

### Websites and PHP applications

- Active/passive is safest for mutable document roots.
- A PHP application may write uploads, sessions, caches, locks, cron output, and generated configuration.
- Local filesystem locks must not be replicated as live locks.
- PHP session storage must be shared or the application must use a database/centralized session backend.
- Cron jobs require a single scheduler owner or distributed scheduler lease; otherwise both nodes run duplicate jobs.
- Web health checks must include application readiness, not only a listening port.
- Existing customer applications may not be HA-safe even if the platform is HA. The UI should show “platform HA” and “application write semantics” separately.

### MariaDB and PostgreSQL client endpoints

- Existing runtime JSON must stop exposing node-local container names or IPs to customer applications.
- Inject stable cell service names or proxy addresses.
- Database grants and passwords must be replicated with the control-plane desired state.
- Promotion changes the backend, not the application-visible endpoint.
- Long-lived connections will break and must reconnect; DNS cannot update an established database TCP session.

### File Manager, phpMyAdmin, and webmail

- Tool launch JWTs remain valid only if the control plane and JWT key are available on the replacement.
- Filebrowser databases/configuration must be replicated or reconstructed deterministically.
- phpMyAdmin should connect through the stable database proxy, not the old account container name.
- Webmail must use the active mail backend and shared mailbox store.
- Caddy routes for tool subdomains must be generated from account desired state on every node.

### SSL and Caddy

- Caddy should run on every serving node or be replaced by a cluster ingress.
- Route configuration must be deterministic and versioned.
- Certificates should be available before promotion when possible.
- A certificate obtained on the old node must not be lost with its local Caddy volume.
- ACME challenge and DNS failover behavior must be tested from external networks.

### DNS providers

- The local PowerDNS mode is a single authoritative-service risk unless PowerDNS data and authoritative service are replicated across at least two nameservers.
- Cloudflare API mode is operationally simpler for DNS failover but depends on provider API credentials, permissions, rate limits, and an external control plane.
- The provider adapter must support idempotent updates, record IDs, retries, generation checks, and verification.
- If users delegate nameservers directly to a failed server, updating an A record elsewhere does not help; the authoritative nameserver service itself must be HA.
- DNSSEC, if enabled, adds key-management and signing-state requirements. A failover node must have current signing keys or use provider-managed DNSSEC.

### Backups and restore

- Replication is not backup and can replicate deletion, corruption, or ransomware.
- Keep immutable, versioned, offsite backups of control-plane DB, account files, database dumps/WAL, mailboxes, secrets, and provider configuration.
- Test restoring an account to a clean node and compare it with a normal failover.
- Record backup generation and replication generation separately.

### Resource quotas and placement

- HA reserves capacity twice: active plus standby, and sometimes a third replica.
- Node placement must account for CPU, RAM, disk, inode, network, public IPv4/IPv6, mail ports, and database capacity.
- The scheduler must not place both replicas in the same failure domain.
- An HA account should be rejected or downgraded if no eligible standby capacity exists.
- A replacement node must not overcommit all accounts during a correlated failure.

### Security

- Node-to-node replication must use mutually authenticated TLS or an equivalent authenticated private network.
- Fencing credentials are high-impact secrets and must be scoped to the target provider and account/node group.
- DNS API tokens need least privilege and should be stored outside a single host-local file.
- Replicated website data and database traffic must be encrypted in transit.
- Node agents are privileged and require signed/versioned desired state, request authentication, and audit logs.
- Never accept a failover command solely from a customer-facing HTTP request.
- Prevent a compromised standby from becoming a trusted writer without quorum authorization.

## 11. Failure scenarios and expected behavior

| Scenario | Safe response | Unsafe response |
|---|---|---|
| Active node power loss | Confirm through quorum, fence, promote current standby, then DNS update | Standby self-promotes on one missed ping |
| Active node loses only its public network | Require independent observation and fencing; do not assume disk is safe | Promote while old node can still write locally |
| Replication link breaks but active is healthy | Keep serving active; mark HA degraded; repair/reseed standby | Promote stale standby or silently claim HA |
| Control-plane DB loses quorum | Stop automatic ownership changes; keep already-serving data plane if safe | Two independent panels mutate local copies |
| DNS provider API unavailable | Keep current active if healthy; failover requires stable proxy or operator action | Assume API success or update a local file only |
| Stale AAAA record | Block direct AutoSSL/failover verification and report exact address | Queue ACME because an A record exists |
| Old node returns after failover | Fence/reseed as standby; never automatically rejoin as writer | Let it serve old routes and accept writes |
| Network partition | Majority partition continues; minority is fenced or read-only | Both partitions promote independently |
| Database replica is behind RPO | Block automatic failover or explicitly accept data loss with approval | Promote without recording possible loss |
| Mail active node dies | Promote one queue owner and shared mailbox store; rely on SMTP retries | Run two independent mutable queues without deduplication |
| Caddy certificate storage unavailable | Keep existing cert if loaded; block new promotion if replacement cannot serve valid TLS | Serve a self-signed certificate publicly |
| Whole provider/region fails | Use a separately tested DR cell and documented RPO | Assume same-cell replication survives correlated failure |

## 12. Health model and observability

An account is eligible for automatic failover only when all required signals are healthy:

- node heartbeat and agent version;
- quorum membership and clock sanity;
- fencing provider reachable;
- account file replication connected and lag within policy;
- MariaDB replication/cluster state healthy;
- PostgreSQL replication/cluster state healthy;
- Redis state policy satisfied;
- mail store and edge healthy;
- local Caddy route loaded;
- certificate valid for the endpoint;
- DNS provider credentials and record IDs valid;
- replacement capacity reserved.

Expose metrics and alerts for:

- replication lag bytes/seconds;
- last successful snapshot and incremental sync;
- database WAL/GTID/WSREP position;
- filesystem dirty bytes and pending sync;
- failover epoch and owner;
- fence attempts and verification;
- DNS update request/authoritative/public observation times;
- ACME certificate expiry and issuance failures;
- queue age, lease expiry, duplicate/idempotent job count;
- service readiness per account;
- split-brain prevention events;
- backups and restore test age.

Use a clear account status sequence in the UI, for example:

```text
HA healthy
HA degraded: standby lag 18s
Failover in progress: fencing node-a
Promoted: node-b; DNS converging
Failover blocked: no safe fence
Failover blocked: replica exceeds RPO
Manual recovery required: conflicting writers detected
```

## 13. Testing and verification plan

HA should not be considered complete until these tests are automated and repeated:

### Functional tests

- enable HA for a new account;
- create website, database, mailbox, cron job, and files;
- verify all replicas contain the expected state;
- restart the active node gracefully;
- hard-power-off the active node;
- isolate only the active node’s public network;
- fail the replication network while keeping the active node online;
- return the old node and verify it is reseeded as standby;
- perform controlled switchover and failback.

### Data correctness tests

- compare website file checksums and permissions;
- run MariaDB consistency checks and transaction probes;
- verify PostgreSQL WAL/LSN promotion and client reconnect;
- create/read/delete mail messages before and after failover;
- verify cron jobs run exactly once;
- verify Redis cache loss does not lose customer data;
- restore from backup after a simulated corruption.

### DNS and TLS tests

- verify A and AAAA records before and after failover;
- verify stale AAAA blocks or is corrected;
- probe through multiple public resolvers;
- measure authoritative update time and client convergence;
- test HTTP-01 and DNS-01 behavior;
- verify the replacement serves the correct certificate and all tool hostnames;
- test existing connections and expected reconnect behavior.

### Safety tests

- kill the controller during each promotion step;
- lose one quorum member;
- lose two quorum members and verify automatic promotion stops;
- make fencing fail and verify promotion is blocked;
- create a network partition and verify only the quorum side can write;
- submit the same failover/job request repeatedly and verify idempotency;
- delay DNS API responses and verify generation protection;
- inject clock skew and verify leases do not make unsafe decisions.

Chaos tests should be run against disposable accounts first and then against a scheduled maintenance account with an explicit rollback plan.

## 14. Rollout phases

### Phase 0: document current contracts

- classify state as desired, generated, cache, queue, or customer data;
- identify every node-local path, port, hostname, container name, and secret;
- define account RPO/RTO profiles;
- add health and replication observability without changing failover behavior.

### Phase 1: make the control plane portable

- replace SQLite as the multi-node control-plane store with HA PostgreSQL;
- make panel instances stateless;
- add distributed job leases and idempotency;
- introduce stable node IDs and account generations;
- keep failover manual.

### Phase 2: replicate account data

- choose and test replicated filesystem/storage;
- move generated artifacts to desired-state rendering;
- implement database replication/proxying;
- classify Redis and mail state;
- make Caddy routes/certificates reproducible on a clean node.

### Phase 3: introduce quorum and fencing

- deploy three quorum members across independent failure domains;
- integrate fencing provider;
- add promotion epochs and ownership leases;
- run operator-approved failover only;
- create auditable failover events.

### Phase 4: automatic active/passive failover

- enable automatic mode for test accounts;
- require all health gates and external probes;
- update DNS only after local promotion;
- keep failback manual;
- publish realistic DNS convergence and RPO status.

### Phase 5: scale to cells and optional strong HA

- separate accounts into cells with capacity and failure-domain policy;
- add cell-level MariaDB/PostgreSQL/Redis services;
- use shared/proxied edge endpoints;
- offer strong RPO 0 only where synchronous latency and quorum capacity are acceptable;
- add cross-region DR as a separate policy, not as an untested extension of same-cell HA.

## 15. Recommendation in one page

The recommended MangoPanel HA architecture is:

1. Keep account HA active/passive at first.
2. Replace SQLite multi-host use with a replicated PostgreSQL control plane; never replicate SQLite WAL between hosts.
3. Use three quorum members and a real fencing provider.
4. Make account desired state portable and render it on any eligible node.
5. Use replicated filesystem/storage for website and mailbox content.
6. Use cell-level database HA rather than one three-node database cluster inside every account.
7. Treat Redis as disposable unless Sentinel/cluster is explicitly required.
8. Run Caddy on every serving node with deterministic routes and safe certificate storage; prefer DNS-01 for failover-sensitive certificates.
9. Use DNS updates only after promotion and health validation; preconfigure low TTL and remove stale AAAA records.
10. Prefer a stable proxy/load balancer for truly fast failover; direct DNS failover is inherently convergent, not instantaneous.
11. Fence before promote, reseed before failback, and never let DNS decide ownership.
12. Expose RPO, replication lag, fencing state, DNS convergence, and failover epoch to administrators.

This design preserves MangoPanel’s account isolation concept while replacing host-local assumptions with explicit ownership, replication, fencing, and reconciliation contracts. It is intentionally conservative: an account is called HA only when the platform can prove that another node has usable state and that the old node cannot continue acting as the writer.

## References

- [MangoPanel system architecture in this repository](docs/mangopanel_system_architecture.md)
- [SQLite Write-Ahead Logging](https://www.sqlite.org/wal.html)
- [SQLite database file format and WAL network-filesystem limitation](https://www.sqlite.org/fileformat.html)
- [PostgreSQL high availability and replication](https://www.postgresql.org/docs/current/high-availability.html)
- [PostgreSQL warm standby, streaming, cascading, and synchronous replication](https://www.postgresql.org/docs/current/warm-standby.html)
- [MariaDB Galera high availability](https://mariadb.com/docs/galera-cluster/high-availability)
- [MariaDB Galera replication](https://mariadb.com/docs/galera-cluster/galera-cluster-quickstart-guides/mariadb-galera-cluster-replication-guide)
- [Redis replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/)
- [Redis Sentinel](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/)
- [Docker Swarm services and placement](https://docs.docker.com/engine/swarm/services/)
- [Kubernetes disruptions](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/)
- [Kubernetes self-healing](https://kubernetes.io/docs/concepts/architecture/self-healing/)
- [etcd quorum and failure tolerance](https://etcd.io/docs/v3.3/faq/)
- [etcd API guarantees](https://etcd.io/docs/v3.7/learning/api_guarantees/)
- [Caddy Automatic HTTPS and shared storage](https://caddyserver.com/docs/automatic-https)
- [Let’s Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/)
- [Cloudflare DNS TTL](https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/)
- [Cloudflare DNS record API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/)
