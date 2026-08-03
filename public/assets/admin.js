const { createApp } = Vue;
const IS_RESELLER = Boolean(window.IS_RESELLER_PANEL);
const ADMIN_ROUTE_PREFIX = IS_RESELLER ? "/reseller" : "/admin";
const ADMIN_PAGE_TARGETS = new Set(["overview", "clients", "plans", "reseller-plans", "reseller-users", "traffic", "storage", "networking", "cpu", "ram", "dns", "registrars", "dns-domains", "configuration", "system-backup", "system", "admins", "api-tokens", "status", "security", "default-page"]);

function adminPageFromLocation() {
  let hash = window.location.hash.replace(/^#/, "");
  if (hash === "default_page") hash = "default-page";
  return ADMIN_PAGE_TARGETS.has(hash) ? hash : "overview";
}

function getInitialToken() {
  const searchParams = new URLSearchParams(window.location.search);
  const hashStr = window.location.hash.replace(/^#/, "");
  const hashParams = new URLSearchParams(hashStr);

  // If there is an impersonation token in the hash, skip it here — it will be
  // exchanged asynchronously in mounted() for a real access token.
  if (hashParams.get("mp_impersonation_token") || hashParams.get("mp_access_token")) {
    return "";
  }

  const urlSsoToken = searchParams.get("sso_token") || searchParams.get("token") || hashParams.get("sso_token") || hashParams.get("token");
  
  if (urlSsoToken) {
    const storageKey = IS_RESELLER ? "mp_reseller_token" : "mp_admin_token";
    localStorage.setItem(storageKey, urlSsoToken);
    if (window.history && window.history.replaceState) {
      const cleanHash = window.location.hash.startsWith("#sso_token=") ? "" : window.location.hash;
      window.history.replaceState(null, "", window.location.pathname + cleanHash);
    }
    return urlSsoToken;
  }

  const storageKey = IS_RESELLER ? "mp_reseller_token" : "mp_admin_token";
  return localStorage.getItem(storageKey) || (IS_RESELLER ? (localStorage.getItem("mp_client_token") || localStorage.getItem("token")) : "") || "";
}

createApp({
  data() {
    return {
      isResellerMode: IS_RESELLER,
      token: getInitialToken(),
      activePage: adminPageFromLocation(),
      challengeToken: "",
      message: "",
      login: {
        email: "",
        password: "",
        code: "",
      },
      dashboard: {
        counts: { users: 0, hosting_accounts: 0, websites: 0, account_stacks: 0, open_incidents: 0 },
        nodes: [],
        recent_jobs: [],
        status: { overall_status: "unknown", components: [] },
      },
      stacks: [],
      clients: [],
      selectedClientId: "",
      clientSearch: "",
      clientPagination: { page: 1, page_size: 25, total: 0, total_pages: 1 },
      clientSearchTimer: null,
      clientsLoading: false,
      showClientModal: false,
      plans: [],
      configuration: { backup_time: "02:00", timezone: "UTC", modsecurity_ruleset: "baseline", ssh_motd: "" },
      modsecRuleset: "baseline",
      modsecApplying: false,
      timezoneOptions: ["UTC", "Europe/London", "Europe/Paris", "Asia/Kolkata", "Asia/Dubai", "Asia/Tokyo", "America/New_York", "America/Los_Angeles", "Australia/Sydney"],
      configurationSaving: false,
      systemBackup: { local_enabled: true, local_remove_enabled: true, remote_enabled: false, remote_remove_enabled: false, db_enabled: true, files_enabled: true, db_frequency: "daily", files_frequency: "daily", db_time: "02:00", files_time: "03:00", local_path: "", remote_endpoint: "", remote_bucket: "", remote_region: "us-east-1", remote_access_key: "", remote_secret: "", remote_prefix: "mangopanel", retention_days: 30, last_run: null },
      systemBackupSaving: false,
      systemBackupTesting: false,
      systemBackupRunning: false,
      resellerPlans: [],
      resellerUsers: [],
      showResellerPlanModal: false,
      showResellerUserModal: false,
      resellerPlanForm: { id: null, name: "", max_storage_mb: 50000, max_clients: 10, max_hosting_accounts: 20, max_ram_mb: 8192, max_websites: 50, max_databases: 50, max_subplans: 10 },
      resellerUserForm: { id: null, email: "", password: "", full_name: "", reseller_plan_id: "", status: "active" },
      recalculatingUsage: false,
      showPlanModal: false,
      planSaving: false,
      editingPlanId: null,
      applyPlanToExistingAccounts: false,
      migratePlanDomains: false,
      dnsDomains: [],
      registrars: [],
      registrarForm: { key: "resellerclub", reseller_id: "", api_base: "", api_key: "", api_token: "" },
      registrarDashboard: { stats: { managed_domains: 0, expiring_30_days: 0, registrar_accounts: 0, configured_providers: 0, balances: [], total_balance: null }, accounts: [], domains: [], providers: [] },
      registrarSearch: "",
      registrarProviderFilter: "",
      registrarSort: "expiry",
      registrarDirection: "asc",
      showRegistrarAccountModal: false,
      registrarAccountForm: { provider_key: "resellerclub", label: "", account_identifier: "", api_base: "", client_ip: "", api_key: "", api_token: "", dns_provider_account_id: "" },
      registrarAccountEditModal: { open: false, account: null, form: {}, saving: false },
      registrarSyncing: {},
      selectedRegistrarDomains: [],
      registrarAssignModal: { open: false, ids: [], search: "", user_id: "", saving: false },
      registrarManageModal: { open: false, record: null, user_id: "", nameservers: ["", ""], saving: false },
      domainForm: { user_id: "", account_id: "", domain: "", registrar_provider_id: "", register: false, nameservers: ["", ""] },
      dnsSettings: { global_mode: "local_powerdns", local: { nameservers: ["ns1.mango.test", "ns2.mango.test"], public_ipv4: "127.0.0.1", public_ipv6: "", soa_email: "hostmaster.mango.test", default_ttl: 300 }, providers: [], accounts: [], health_checks: [] },
      cloudflareAccount: { id: null, display_name: "", account_name: "", external_account_id: "", api_token: "", status: "active" },
      securityAudit: { score: 0, score_label: "Scanning...", total_checks: 0, pass_count: 0, warning_count: 0, fail_count: 0, items: [], scanned_at: null, loading: false },
      jobEvents: [],
      admins: [],
      newAdminSecret: "",
      newAdminUri: "",
      newAdminTotpCode: "",
      newAdminTotpMessage: "",
      adminPasswordModal: { open: false, admin: null, password: "", confirm: "" },
      clientProfileModal: {
        open: false,
        loading: false,
        saving: false,
        client: null,
        form: { id: null, full_name: "", email: "", status: "active", has_2fa: false, billing: {} },
        admin_password: "",
        admin_totp_code: "",
        new_password: "",
        confirm_password: "",
        totp_secret: "",
        totp_uri: "",
      },
      accountDatabasesModal: {
        open: false,
        loading: false,
        deleting: false,
        account: null,
        databases: [],
      },
      adminApiTokens: [],
      newAdminTokenName: "",
      newAdminTokenRaw: "",
      newAdminTokenPermissions: ["*"],
      storageDf: { filesystems: [], root_capacity_pct: 0, total_main_size_bytes: 0, total_main_used_bytes: 0, updated_at: "" },
      storageLive: { capacity_total_bytes: 0, capacity_used_bytes: 0, capacity_free_bytes: 0, capacity_used_pct: 0, read_rate_kbs: 0, write_rate_kbs: 0, read_rate_mbs: 0, write_rate_mbs: 0, top_writers: [], sample_interval_sec: 0.3 },
      storageLiveActive: true,
      storageLiveTimer: null,
      loadingStorage: false,
      storageQuotas: [],
      storagePaths: { paths: [], total_scanned_mb: 0 },
      storageAlerts: { warning_threshold_pct: 85, critical_threshold_pct: 95, inode_warning_pct: 80, notify_email: "admin@domain.com", enabled: true },
      storageFilter: "all",
      storageCleanupRunning: false,
      storageCleanupResult: null,
      storageAlertsSaving: false,
      storageAlertsMsg: "",
      networkOverview: { primary_ip: null, total_registered_ips: 0, shared_ips_count: 0, dedicated_ips_count: 0, interfaces: [], service_ports: [] },
      networkLive: { rx_rate_kbs: 0, tx_rate_kbs: 0, rx_rate_mbs: 0, tx_rate_mbs: 0, total_rx_human: "0 MB", total_tx_human: "0 MB", top_network_users: [], sample_interval_sec: 0.3 },
      networkLiveActive: true,
      networkLiveTimer: null,
      trafficData: { current: [], history: [], live_window_minutes: 5, history_days: 30, updated_at: "" },
      trafficLoading: false,
      trafficTimer: null,
      cpuLive: { sys_cpu_pct: 0, num_cpus: 1, load_avg_1m: 0, load_avg_5m: 0, load_avg_15m: 0, top_cpu_users: [], sample_interval_sec: 0.3 },
      cpuLiveActive: true,
      cpuLiveTimer: null,
      cpuHistory: [],
      cpuHistoryRange: "72h",
      cpuHistoryData: { range_str: "72h", hours: 72, total_points: 0, avg_cpu_pct: 0, peak_cpu_pct: 0, min_cpu_pct: 0, avg_load_1m: 0, points: [] },
      loadingCpuHistory: false,
      hoveredCpuPoint: null,
      displayCpu: { sys_cpu_pct: 0, load_avg_1m: 0, load_avg_5m: 0, load_avg_15m: 0 },
      ramLive: { total_mb: 0, used_mb: 0, free_mb: 0, available_mb: 0, buffers_cached_mb: 0, used_pct: 0, swap_total_mb: 0, swap_used_mb: 0, swap_used_pct: 0, top_ram_users: [], sample_interval_sec: 0.3 },
      ramLiveActive: true,
      ramLiveTimer: null,
      ramHistoryRange: "72h",
      ramHistoryData: { range_str: "72h", hours: 72, total_points: 0, avg_used_pct: 0, peak_used_pct: 0, min_used_pct: 0, avg_used_mb: 0, total_mb: 0, points: [] },
      loadingRamHistory: false,
      hoveredRamPoint: null,
      displayRam: { used_mb: 0, total_mb: 0, used_pct: 0, available_mb: 0, swap_used_mb: 0 },
      displayNetwork: { rx_rate_kbs: 0, tx_rate_kbs: 0, rx_rate_mbs: 0, tx_rate_mbs: 0 },
      displayStorage: { read_rate_kbs: 0, write_rate_kbs: 0, read_rate_mbs: 0, write_rate_mbs: 0 },
      serverIps: [],
      showAddIpModal: false,
      showAssignIpModal: false,
      ipForm: { id: null, ip_address: "", ip_type: "ipv4", netmask_cidr: "/24", interface: "ens160", label: "Public IP", is_primary: false },
      assignIpForm: { account_id: "", ip_id: "" },
      savingIp: false,
      assigningIp: false,
      collapsedPanels: JSON.parse(localStorage.getItem("mp_admin_collapsed_panels") || "{}"),
      sortState: { tableKey: "", colKey: "", desc: false },
      newPlan: {
        name: "",
        cpu_limit: "1",
        memory_mb: 1024,
        storage_mb: 10240,
        inode_limit: 100000,
        max_websites: 10,
        max_subdomains: 10,
        max_databases: 10,
        max_mailboxes: 10,
        max_cron_jobs: 10,
        daily_email_limit: 250,
        backup_retention_days: 7,
        backup_schedule: "daily",
        max_processes: 120,
        php_workers: 60,
        bandwidth_mb: 0,
        nameserver_1: "ns1.dns-parking.com",
        nameserver_2: "ns2.dns-parking.com",
        backup_location: "Singapore",
        frontend_frameworks: "Angular, Astro, Next.js, Nuxt, Parcel, React, Vue.js, etc.",
        backend_frameworks: "Express, Fastify, Hono, NestJS, Nuxt, React Router, SvelteKit",
        nodejs_versions: "24.x, 22.x, 20.x and 18.x",
        package_managers: "npm (default), yarn and pnpm",
        dns_default_provider: "local_powerdns",
        dns_allowed_providers: ["local_powerdns"],
        dns_allowed_provider_account_ids: [],
        dns_default_provider_account_id: "",
        dns_customer_editable: true,
        dns_max_records_per_domain: 100,
        dns_allowed_record_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"],
        dns_min_ttl: 60,
        dns_wildcard_records_allowed: true,
        dns_cloudflare_proxy_allowed: false,
        dns_dnssec_allowed: false,
        dns_dnssec_required: false,
        allow_api_access: false,
        is_reseller: false,
        max_clients: 0,
        max_reseller_subplans: 0,
      },
      newAdmin: {
        full_name: "",
        email: "",
        role: "support_admin",
        password: "",
      },
      newClient: {
        full_name: "",
        email: "",
        password: "",
      },
      newClientSecret: "",
      incident: {
        title: "",
        severity: "minor",
        message: "",
      },
      adminIncidents: [],
      adminComponents: [],
      updateIncidentForm: {},
      loadingStatus: false,
      newAccount: {
        user_id: "",
        plan_id: "",
        node_id: "",
      },
      newNode: {
        name: "",
        hostname: "",
        quota_backend: "dev-simulator",
      },
      defaultPageContent: "",
      defaultPageIsCustomized: false,
      savingDefaultPage: false,
      showDefaultPagePreviewModal: false,
    };
  },
  async mounted() {
    // Handle impersonation token for reseller panel (Login as Reseller from admin)
    if (IS_RESELLER) {
      const hashStr = window.location.hash.replace(/^#/, "");
      const hashParams = new URLSearchParams(hashStr);
      const impersonationToken = hashParams.get("mp_impersonation_token") || hashParams.get("mp_access_token");
      if (impersonationToken) {
        window.history.replaceState(null, "", window.location.pathname + "#overview");
        this.activePage = "overview";
        try {
          const res = await fetch("/api/reseller/auth/exchange-impersonation", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ impersonation_token: impersonationToken }),
          });
          const data = await res.json();
          if (res.ok && data.access_token) {
            this.token = data.access_token;
            localStorage.setItem("mp_reseller_token", data.access_token);
            await this.load();
          } else {
            this.message = data.error || "Login as reseller failed — the session link may have expired. Please try again.";
          }
        } catch (err) {
          this.message = "Login as reseller failed: " + err.message;
        }
        window.addEventListener("popstate", () => { this.activePage = adminPageFromLocation(); });
        window.addEventListener("hashchange", () => { this.activePage = adminPageFromLocation(); });
        return;
      }
    }
    if (this.token) {
      await this.load();
      this.goTo(adminPageFromLocation());
    }
    window.addEventListener("popstate", () => {
      this.goTo(adminPageFromLocation());
    });
    window.addEventListener("hashchange", () => {
      this.goTo(adminPageFromLocation());
    });

    const animateMetrics = () => {
      const now = performance.now();

      if (this.cpuAnimStartTime) {
        const progress = Math.min(1.0, Math.max(0.0, (now - this.cpuAnimStartTime) / (this.cpuAnimDuration || 300)));
        this.displayCpu.sys_cpu_pct = this.cpuAnimStart.sys_cpu_pct + (this.cpuAnimTarget.sys_cpu_pct - this.cpuAnimStart.sys_cpu_pct) * progress;
        this.displayCpu.load_avg_1m = this.cpuAnimStart.load_avg_1m + (this.cpuAnimTarget.load_avg_1m - this.cpuAnimStart.load_avg_1m) * progress;
        this.displayCpu.load_avg_5m = this.cpuAnimStart.load_avg_5m + (this.cpuAnimTarget.load_avg_5m - this.cpuAnimStart.load_avg_5m) * progress;
        this.displayCpu.load_avg_15m = this.cpuAnimStart.load_avg_15m + (this.cpuAnimTarget.load_avg_15m - this.cpuAnimStart.load_avg_15m) * progress;
      }

      if (this.ramAnimStartTime) {
        const progress = Math.min(1.0, Math.max(0.0, (now - this.ramAnimStartTime) / (this.ramAnimDuration || 300)));
        this.displayRam.used_mb = this.ramAnimStart.used_mb + (this.ramAnimTarget.used_mb - this.ramAnimStart.used_mb) * progress;
        this.displayRam.total_mb = this.ramAnimStart.total_mb + (this.ramAnimTarget.total_mb - this.ramAnimStart.total_mb) * progress;
        this.displayRam.used_pct = this.ramAnimStart.used_pct + (this.ramAnimTarget.used_pct - this.ramAnimStart.used_pct) * progress;
        this.displayRam.available_mb = this.ramAnimStart.available_mb + (this.ramAnimTarget.available_mb - this.ramAnimStart.available_mb) * progress;
        this.displayRam.swap_used_mb = this.ramAnimStart.swap_used_mb + (this.ramAnimTarget.swap_used_mb - this.ramAnimStart.swap_used_mb) * progress;
      }

      if (this.netAnimStartTime) {
        const progress = Math.min(1.0, Math.max(0.0, (now - this.netAnimStartTime) / (this.netAnimDuration || 300)));
        this.displayNetwork.rx_rate_kbs = this.netAnimStart.rx_rate_kbs + (this.netAnimTarget.rx_rate_kbs - this.netAnimStart.rx_rate_kbs) * progress;
        this.displayNetwork.tx_rate_kbs = this.netAnimStart.tx_rate_kbs + (this.netAnimTarget.tx_rate_kbs - this.netAnimStart.tx_rate_kbs) * progress;
        this.displayNetwork.rx_rate_mbs = this.netAnimStart.rx_rate_mbs + (this.netAnimTarget.rx_rate_mbs - this.netAnimStart.rx_rate_mbs) * progress;
        this.displayNetwork.tx_rate_mbs = this.netAnimStart.tx_rate_mbs + (this.netAnimTarget.tx_rate_mbs - this.netAnimStart.tx_rate_mbs) * progress;
      }

      if (this.storageAnimStartTime) {
        const progress = Math.min(1.0, Math.max(0.0, (now - this.storageAnimStartTime) / (this.storageAnimDuration || 300)));
        this.displayStorage.read_rate_kbs = this.storageAnimStart.read_rate_kbs + (this.storageAnimTarget.read_rate_kbs - this.storageAnimStart.read_rate_kbs) * progress;
        this.displayStorage.write_rate_kbs = this.storageAnimStart.write_rate_kbs + (this.storageAnimTarget.write_rate_kbs - this.storageAnimStart.write_rate_kbs) * progress;
        this.displayStorage.read_rate_mbs = this.storageAnimStart.read_rate_mbs + (this.storageAnimTarget.read_rate_mbs - this.storageAnimStart.read_rate_mbs) * progress;
        this.displayStorage.write_rate_mbs = this.storageAnimStart.write_rate_mbs + (this.storageAnimTarget.write_rate_mbs - this.storageAnimStart.write_rate_mbs) * progress;
      }
      this.animFrameId = requestAnimationFrame(animateMetrics);
    };
    this.animFrameId = requestAnimationFrame(animateMetrics);
  },
  unmounted() {
    if (this.animFrameId) cancelAnimationFrame(this.animFrameId);
    this.stopNetworkLiveStream();
    this.stopCpuLiveStream();
    this.stopRamLiveStream();
    this.stopStorageLiveStream();
    this.stopTrafficPolling();
  },
  computed: {
    managedClients() {
      if (!this.selectedClientId) return this.clients;
      return this.clients.filter((client) => Number(client.id) === Number(this.selectedClientId));
    },
    registrarDomains() {
      return this.registrarDashboard.domains || [];
    },
    allRegistrarDomainsSelected() {
      return this.registrarDomains.length > 0 && this.registrarDomains.every((item) => this.selectedRegistrarDomains.includes(item.id));
    },
    filteredFilesystems() {
      if (!this.storageDf || !this.storageDf.filesystems) return [];
      let list = this.storageDf.filesystems;
      if (this.storageFilter === "main") {
        list = list.filter((f) => !f.is_overlay);
      } else if (this.storageFilter === "docker") {
        list = list.filter((f) => f.is_overlay);
      }
      return this.getSortedList(list, "storage_df", this.sortState.colKey, ["use_percent", "size_bytes", "used_bytes"].includes(this.sortState.colKey));
    },
    storagePieChart() {
      if (!this.storageDf || !this.storageDf.total_main_size_bytes) {
        return { used_pct: 0, total_gb: "0", used_gb: "0", slices: [] };
      }
      const total = this.storageDf.total_main_size_bytes || 1;
      const used = this.storageDf.total_main_used_bytes || 0;
      const used_pct = this.storageDf.root_capacity_pct || 0;
      const total_gb = (total / (1024 * 1024 * 1024)).toFixed(1);
      const used_gb = (used / (1024 * 1024 * 1024)).toFixed(1);

      const paths = (this.storagePaths && this.storagePaths.paths) ? this.storagePaths.paths : [];
      const colors = ["#72e128", "#38bdf8", "#fdb528", "#a855f7", "#ec4899", "#64748b"];

      let cumulativePct = 0;
      const slices = paths.map((p, idx) => {
        const pct = p.share_pct || 0;
        const start = cumulativePct;
        cumulativePct += pct;
        return {
          name: p.name,
          size_mb: p.size_mb,
          pct: pct,
          color: colors[idx % colors.length],
          dashArray: `${(pct * 2.83).toFixed(1)} 283`,
          dashOffset: `-${(start * 2.83).toFixed(1)}`,
        };
      });

      return { used_pct, total_gb, used_gb, slices };
    },
    sidebarSections() {
      if (this.isResellerMode) {
        return [
          {
            label: "Reseller Management",
            items: [
              { label: "Overview", target: "overview", description: "Resource counts, node health, and service summary." },
              { label: "Sub-Clients", target: "clients", description: "Manage user accounts under your reseller profile." },
              { label: "Sub-Plans", target: "plans", description: "Create custom sub-plans for your clients." },
              { label: "Storage", target: "storage", description: "Disk capacity, read/write rates, and account storage quotas." },
              { label: "Networking", target: "networking", description: "Traffic meters and IP address allocations." },
              { label: "CPU", target: "cpu", description: "Live CPU utilization, load averages, and per-container CPU breakdown." },
              { label: "RAM", target: "ram", description: "Live RAM utilization, swap usage, and per-container RAM breakdown." },
            ],
          },
          {
            label: "DNS & Domains",
            items: [
              { label: "DNS Settings", target: "dns", description: "Global DNS mode and local nameservers." },
              { label: "Managed DNS Domains", target: "dns-domains", description: "Domain zones and DNS records." },
            ],
          },
          {
            label: "Security & Tools",
            items: [
              { label: "Security Checklist", target: "security", description: "Server security audit and WAF status." },
              { label: "Reseller API Keys", target: "api-tokens", description: "Manage Reseller API tokens." },
              { label: "Status", target: "status", description: "Platform status and service health." },
            ],
          },
        ];
      }

      return [
        {
          label: "Operations",
          items: [
            { label: "Overview", target: "overview", description: "Resource counts, node health, and service summary." },
            { label: "Clients", target: "clients", description: "Customer profiles, account status, and package moves." },
            { label: "Plans", target: "plans", description: "Hosting packages, resource limits, and DNS policy." },
            { label: "Traffic", target: "traffic", description: "Current and historical website traffic by domain." },
            { label: "Storage", target: "storage", description: "Disk capacity graph (df -h), SSE live read/write rates, MangoPanel Host Manager quotas, path sizes, and cleanup." },
            { label: "Networking", target: "networking", description: "Public IP addresses, interface topology, IP aliases, and client dedicated IP assignment." },
            { label: "CPU", target: "cpu", description: "Live CPU utilization, load averages, and per-container CPU breakdown." },
            { label: "RAM", target: "ram", description: "Live RAM utilization, swap usage, and per-container RAM breakdown." },
          ],
        },
        {
          label: "Resellers",
          items: [
            { label: "Reseller Plans", target: "reseller-plans", description: "Create and manage reseller package boundaries." },
            { label: "Reseller Users", target: "reseller-users", description: "Manage reseller partner accounts and assigned plans." },
          ],
        },
        {
          label: "DNS",
          items: [
            { label: "DNS Settings", target: "dns", description: "Global DNS mode, local nameservers, and Cloudflare account credentials." },
            { label: "Registration Providers", target: "registrars", description: "Configure domain registration accounts and API credentials." },
            { label: "Managed DNS Domains", target: "dns-domains", description: "Rebuild zones, verify delegation, export records, and migrate providers." },
          ],
        },
        {
          label: "System",
          items: [
            { label: "Configuration", target: "configuration", description: "Platform-wide backup timing and future control-plane settings." },
            { label: "System Backup", target: "system-backup", description: "Back up the control-plane database and every user and website archive locally or to S3-compatible storage." },
            { label: "Default Page", target: "default-page", description: "Default index.php template content for newly created websites." },
            { label: "Security Checklist", target: "security", description: "Server security audit, SSH hardening, firewall, SSL, and WAF status." },
            { label: "Stack & Jobs", target: "system", description: "Generated stacks, agent runs, recent jobs, and events." },
            { label: "Admins", target: "admins", description: "Admin users, TOTP secrets, nodes, and PHP availability." },
            { label: "API Tokens", target: "api-tokens", description: "Manage Admin API keys and granular permissions." },
            { label: "Status", target: "status", description: "Publish incidents and review public component status." },
          ],
        },
      ];
    },
    menuItems() {
      return this.sidebarSections.flatMap((section) => section.items);
    },
    activeMenuItem() {
      return this.menuItems.find((item) => item.target === this.activePage) || this.menuItems[0];
    },
  },
  methods: {
    goTo(target) {
      if (!ADMIN_PAGE_TARGETS.has(target)) target = "overview";
      this.activePage = target;
      const nextHash = target === "overview" ? "" : `#${target}`;
      if (window.location.hash !== nextHash) {
        window.history.pushState(null, "", `${ADMIN_ROUTE_PREFIX}${nextHash}`);
      }
      if (target === "storage") {
        this.stopNetworkLiveStream();
        this.stopCpuLiveStream();
        this.stopTrafficPolling();
        this.loadStorage();
      } else if (target === "traffic") {
        this.stopStorageLiveStream();
        this.stopNetworkLiveStream();
        this.stopCpuLiveStream();
        this.stopRamLiveStream();
        this.startTrafficPolling();
      } else if (target === "networking") {
        this.stopTrafficPolling();
        this.stopStorageLiveStream();
        this.stopCpuLiveStream();
        this.loadNetworking();
      } else if (target === "cpu") {
        this.stopTrafficPolling();
        this.stopStorageLiveStream();
        this.stopNetworkLiveStream();
        this.stopRamLiveStream();
        this.startCpuLiveStream();
        this.loadCpuHistory();
      } else if (target === "ram") {
        this.stopTrafficPolling();
        this.stopStorageLiveStream();
        this.stopNetworkLiveStream();
        this.stopCpuLiveStream();
        this.startRamLiveStream();
        this.loadRamHistory();
      } else if (target === "overview") {
        this.stopTrafficPolling();
        this.loadStorage();
        this.loadNetworking();
        this.startCpuLiveStream();
        this.startRamLiveStream();
        this.startNetworkLiveStream();
      } else if (target === "status") {
        this.stopTrafficPolling();
        this.stopStorageLiveStream();
        this.stopNetworkLiveStream();
        this.stopCpuLiveStream();
        this.stopRamLiveStream();
        this.loadStatusData();
      } else {
        this.stopTrafficPolling();
        this.stopStorageLiveStream();
        this.stopNetworkLiveStream();
        this.stopCpuLiveStream();
        this.stopRamLiveStream();
      }
    },
    togglePanel(panelId) {
      this.collapsedPanels = {
        ...this.collapsedPanels,
        [panelId]: !this.collapsedPanels[panelId]
      };
      localStorage.setItem("mp_admin_collapsed_panels", JSON.stringify(this.collapsedPanels));
    },
    isPanelCollapsed(panelId) {
      return Boolean(this.collapsedPanels[panelId]);
    },
    sortBy(tableKey, colKey) {
      if (this.sortState.tableKey === tableKey && this.sortState.colKey === colKey) {
        this.sortState.desc = !this.sortState.desc;
      } else {
        this.sortState.tableKey = tableKey;
        this.sortState.colKey = colKey;
        this.sortState.desc = false;
      }
    },
    getSortIcon(tableKey, colKey) {
      if (this.sortState.tableKey !== tableKey || this.sortState.colKey !== colKey) {
        return " ↕";
      }
      return this.sortState.desc ? " ▼" : " ▲";
    },
    getSortedList(list, tableKey, colKey, isNumeric = false) {
      if (!list || !Array.isArray(list)) return [];
      if (this.sortState.tableKey !== tableKey || this.sortState.colKey !== colKey) {
        return list;
      }
      const desc = this.sortState.desc ? -1 : 1;
      return [...list].slice().sort((a, b) => {
        let valA = a[colKey] ?? "";
        let valB = b[colKey] ?? "";
        if (isNumeric) {
          valA = Number(valA) || 0;
          valB = Number(valB) || 0;
          return (valA - valB) * desc;
        }
        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();
        if (valA < valB) return -1 * desc;
        if (valA > valB) return 1 * desc;
        return 0;
      });
    },
    formatMountPath(path) {
      if (!path) return "";
      if (path.length > 45 && path.includes("/overlayfs/")) {
        const parts = path.split("/overlayfs/");
        const hash = parts[1] || "";
        return parts[0] + "/overlayfs/" + (hash.length > 12 ? hash.slice(0, 10) + "..." : hash);
      }
      if (path.length > 55) {
        return path.slice(0, 30) + "..." + path.slice(-20);
      }
      return path;
    },
    formatTrafficBytes(value) {
      let bytes = Number(value) || 0;
      if (bytes < 1024) return `${bytes.toFixed(0)} B`;
      const units = ["KB", "MB", "GB", "TB"];
      let unit = -1;
      do {
        bytes /= 1024;
        unit += 1;
      } while (bytes >= 1024 && unit < units.length - 1);
      return `${bytes.toFixed(bytes >= 100 ? 0 : 2)} ${units[unit]}`;
    },
    formatTrafficRate(bytes, windowMinutes) {
      const seconds = Math.max(1, Number(windowMinutes || 5) * 60);
      return `${this.formatTrafficBytes((Number(bytes) || 0) / seconds)}/s`;
    },
    async loadNetworking() {
      try {
        this.networkOverview = await this.api("/api/admin/network/overview");
        this.serverIps = (await this.api("/api/admin/network/ips")).server_ips || [];
        this.startNetworkLiveStream();
      } catch (error) {
        console.error("Networking load error:", error);
      }
    },
    async loadTraffic() {
      this.trafficLoading = true;
      try {
        this.trafficData = await this.api("/api/admin/traffic");
      } catch (error) {
        this.message = error.message;
      } finally {
        this.trafficLoading = false;
      }
    },
    startTrafficPolling() {
      this.stopTrafficPolling();
      this.loadTraffic();
      this.trafficTimer = setInterval(() => {
        if (this.activePage === "traffic") this.loadTraffic();
      }, 10000);
    },
    stopTrafficPolling() {
      if (this.trafficTimer) {
        clearInterval(this.trafficTimer);
        this.trafficTimer = null;
      }
    },
    setCpuTarget(data) {
      if (!data) return;
      this.cpuAnimStart = {
        sys_cpu_pct: Number(this.displayCpu.sys_cpu_pct || 0),
        load_avg_1m: Number(this.displayCpu.load_avg_1m || 0),
        load_avg_5m: Number(this.displayCpu.load_avg_5m || 0),
        load_avg_15m: Number(this.displayCpu.load_avg_15m || 0),
      };
      this.cpuAnimTarget = {
        sys_cpu_pct: Number(data.sys_cpu_pct || 0),
        load_avg_1m: Number(data.load_avg_1m || 0),
        load_avg_5m: Number(data.load_avg_5m || 0),
        load_avg_15m: Number(data.load_avg_15m || 0),
      };
      this.cpuAnimStartTime = performance.now();
      this.cpuAnimDuration = (data.sample_interval_sec || 0.3) * 1000;
      this.cpuLive = data;
    },
    setRamTarget(data) {
      if (!data) return;
      this.ramAnimStart = {
        used_mb: Number(this.displayRam.used_mb || 0),
        total_mb: Number(this.displayRam.total_mb || 0),
        used_pct: Number(this.displayRam.used_pct || 0),
        available_mb: Number(this.displayRam.available_mb || 0),
        swap_used_mb: Number(this.displayRam.swap_used_mb || 0),
      };
      this.ramAnimTarget = {
        used_mb: Number(data.used_mb || 0),
        total_mb: Number(data.total_mb || 0),
        used_pct: Number(data.used_pct || 0),
        available_mb: Number(data.available_mb || 0),
        swap_used_mb: Number(data.swap_used_mb || 0),
      };
      this.ramAnimStartTime = performance.now();
      this.ramAnimDuration = (data.sample_interval_sec || 0.3) * 1000;
      this.ramLive = data;
    },
    setNetworkTarget(data) {
      if (!data) return;
      this.netAnimStart = {
        rx_rate_kbs: Number(this.displayNetwork.rx_rate_kbs || 0),
        tx_rate_kbs: Number(this.displayNetwork.tx_rate_kbs || 0),
        rx_rate_mbs: Number(this.displayNetwork.rx_rate_mbs || 0),
        tx_rate_mbs: Number(this.displayNetwork.tx_rate_mbs || 0),
      };
      this.netAnimTarget = {
        rx_rate_kbs: Number(data.rx_rate_kbs || 0),
        tx_rate_kbs: Number(data.tx_rate_kbs || 0),
        rx_rate_mbs: Number(data.rx_rate_mbs || 0),
        tx_rate_mbs: Number(data.tx_rate_mbs || 0),
      };
      this.netAnimStartTime = performance.now();
      this.netAnimDuration = (data.sample_interval_sec || 0.3) * 1000;
      this.networkLive = data;
    },
    setStorageTarget(data) {
      if (!data) return;
      this.storageAnimStart = {
        read_rate_kbs: Number(this.displayStorage.read_rate_kbs || 0),
        write_rate_kbs: Number(this.displayStorage.write_rate_kbs || 0),
        read_rate_mbs: Number(this.displayStorage.read_rate_mbs || 0),
        write_rate_mbs: Number(this.displayStorage.write_rate_mbs || 0),
      };
      this.storageAnimTarget = {
        read_rate_kbs: Number(data.read_rate_kbs || 0),
        write_rate_kbs: Number(data.write_rate_kbs || 0),
        read_rate_mbs: Number(data.read_rate_mbs || 0),
        write_rate_mbs: Number(data.write_rate_mbs || 0),
      };
      this.storageAnimStartTime = performance.now();
      this.storageAnimDuration = (data.sample_interval_sec || 0.3) * 1000;
      this.storageLive = data;
    },
    async startNetworkLiveStream() {
      this.stopNetworkLiveStream();
      this.networkLiveActive = true;
      try {
        const net = await this.api("/api/admin/network/live");
        if (net) this.setNetworkTarget(net);
      } catch (e) {}

      if (window.EventSource) {
        try {
          const streamPath = IS_RESELLER ? "/api/reseller/network/live/stream" : "/api/admin/network/live/stream";
          const url = `${streamPath}${this.token ? '?token=' + encodeURIComponent(this.token) : ''}`;
          const es = new EventSource(url);
          es.onmessage = (e) => {
            if (!this.networkLiveActive || (this.activePage !== "networking" && this.activePage !== "overview")) return;
            try {
              this.setNetworkTarget(JSON.parse(e.data));
            } catch (err) {}
          };
          es.onerror = () => {
            this.stopNetworkLiveStream();
            this.startNetworkPollingFallback();
          };
          this.networkLiveEs = es;
          return;
        } catch (e) {}
      }
      this.startNetworkPollingFallback();
    },
    startNetworkPollingFallback() {
      if (this.networkLiveTimer) clearInterval(this.networkLiveTimer);
      this.networkLiveTimer = setInterval(async () => {
        if (!this.networkLiveActive || (this.activePage !== "networking" && this.activePage !== "overview")) return;
        try {
          const net = await this.api("/api/admin/network/live");
          if (net) this.setNetworkTarget(net);
        } catch (e) {}
      }, 1000);
    },
    stopNetworkLiveStream() {
      if (this.networkLiveEs) {
        this.networkLiveEs.close();
        this.networkLiveEs = null;
      }
      if (this.networkLiveTimer) {
        clearInterval(this.networkLiveTimer);
        this.networkLiveTimer = null;
      }
    },
    toggleNetworkLive() {
      this.networkLiveActive = !this.networkLiveActive;
    },
    async startCpuLiveStream() {
      this.stopCpuLiveStream();
      this.cpuLiveActive = true;
      try {
        const live = await this.api("/api/admin/cpu/live");
        if (live) {
          this.setCpuTarget(live);
          if (live.sys_cpu_pct !== undefined) {
            this.cpuHistory.push({ t: new Date().toLocaleTimeString(), v: live.sys_cpu_pct });
            if (this.cpuHistory.length > 60) this.cpuHistory.shift();
          }
        }
      } catch (e) {}

      if (window.EventSource) {
        try {
          const streamPath = IS_RESELLER ? "/api/reseller/cpu/live/stream" : "/api/admin/cpu/live/stream";
          const url = `${streamPath}${this.token ? '?token=' + encodeURIComponent(this.token) : ''}`;
          const es = new EventSource(url);
          es.onmessage = (e) => {
            if (!this.cpuLiveActive || (this.activePage !== "cpu" && this.activePage !== "overview")) return;
            try {
              const data = JSON.parse(e.data);
              this.setCpuTarget(data);
              this.cpuHistory.push({ t: new Date().toLocaleTimeString(), v: data.sys_cpu_pct });
              if (this.cpuHistory.length > 60) this.cpuHistory.shift();
            } catch (err) {}
          };
          es.onerror = () => {
            this.stopCpuLiveStream();
            this.startCpuPollingFallback();
          };
          this.cpuLiveEs = es;
          return;
        } catch (e) {}
      }
      this.startCpuPollingFallback();
    },
    startCpuPollingFallback() {
      if (this.cpuLiveTimer) clearInterval(this.cpuLiveTimer);
      this.cpuLiveTimer = setInterval(async () => {
        if (!this.cpuLiveActive || (this.activePage !== "cpu" && this.activePage !== "overview")) return;
        try {
          const data = await this.api("/api/admin/cpu/live");
          if (data) this.cpuLive = data;
          if (data && data.sys_cpu_pct !== undefined) {
            this.cpuHistory.push({ t: new Date().toLocaleTimeString(), v: data.sys_cpu_pct });
            if (this.cpuHistory.length > 60) this.cpuHistory.shift();
          }
        } catch (e) {}
      }, 1000);
    },
    stopCpuLiveStream() {
      if (this.cpuLiveEs) {
        this.cpuLiveEs.close();
        this.cpuLiveEs = null;
      }
      if (this.cpuLiveTimer) {
        clearInterval(this.cpuLiveTimer);
        this.cpuLiveTimer = null;
      }
    },
    toggleCpuLive() {
      this.cpuLiveActive = !this.cpuLiveActive;
      if (this.cpuLiveActive) {
        this.startCpuLiveStream();
      } else {
        this.stopCpuLiveStream();
      }
    },
    async loadCpuHistory(rangeStr = null) {
      if (rangeStr) this.cpuHistoryRange = rangeStr;
      this.loadingCpuHistory = true;
      try {
        const data = await this.api(`/api/admin/cpu/history?range=${encodeURIComponent(this.cpuHistoryRange)}`);
        if (data) this.cpuHistoryData = data;
      } catch (error) {
        console.error("Cpu history load error:", error);
      } finally {
        this.loadingCpuHistory = false;
      }
    },
    buildCpuHistorySvgPath(points, width = 760, height = 200, key = "sys_cpu_pct", maxVal = 100) {
      if (!points || points.length < 2) return "";
      const stepX = width / Math.max(1, points.length - 1);
      return points.map((p, i) => {
        const x = (i * stepX).toFixed(1);
        const y = (height - (Math.min(maxVal, Math.max(0, p[key] || 0)) / maxVal) * (height - 20) - 10).toFixed(1);
        return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
      }).join(' ');
    },
    buildCpuHistoryAreaPath(points, width = 760, height = 200, key = "sys_cpu_pct", maxVal = 100) {
      if (!points || points.length < 2) return "";
      const linePath = this.buildCpuHistorySvgPath(points, width, height, key, maxVal);
      const lastX = width.toFixed(1);
      return `${linePath} L ${lastX} ${height} L 0 ${height} Z`;
    },
    startRamLiveStream() {
      this.stopRamLiveStream();
      this.ramLiveActive = true;
      const apiPrefix = IS_RESELLER ? "/api/reseller/ram/live" : "/api/admin/ram/live";
      this.api(apiPrefix).then((data) => {
        if (data) this.setRamTarget(data);
      }).catch(() => {});

      if (window.EventSource) {
        const streamUrl = `${apiPrefix}/stream?token=${encodeURIComponent(this.token)}`;
        const es = new EventSource(streamUrl);
        es.onmessage = (e) => {
          if (!this.ramLiveActive || (this.activePage !== "ram" && this.activePage !== "overview")) return;
          try {
            const data = JSON.parse(e.data);
            if (data) this.setRamTarget(data);
          } catch (err) {}
        };
        es.onerror = () => {
          es.close();
          if (this.ramLiveActive) {
            this.startRamPollingFallback();
          }
        };
        this._ramEventSource = es;
      } else {
        this.startRamPollingFallback();
      }
    },
    startRamPollingFallback() {
      if (this.ramLiveTimer) clearInterval(this.ramLiveTimer);
      const apiPrefix = IS_RESELLER ? "/api/reseller/ram/live" : "/api/admin/ram/live";
      this.ramLiveTimer = setInterval(async () => {
        if (!this.ramLiveActive || (this.activePage !== "ram" && this.activePage !== "overview")) return;
        try {
          const data = await this.api(apiPrefix);
          if (data) this.setRamTarget(data);
        } catch (e) {}
      }, 1000);
    },
    stopRamLiveStream() {
      this.ramLiveActive = false;
      if (this._ramEventSource) {
        this._ramEventSource.close();
        this._ramEventSource = null;
      }
      if (this.ramLiveTimer) {
        clearInterval(this.ramLiveTimer);
        this.ramLiveTimer = null;
      }
    },
    toggleRamLive() {
      this.ramLiveActive = !this.ramLiveActive;
      if (this.ramLiveActive) {
        this.startRamLiveStream();
      } else {
        this.stopRamLiveStream();
      }
    },
    async loadRamHistory(rangeStr = null) {
      if (rangeStr) this.ramHistoryRange = rangeStr;
      this.loadingRamHistory = true;
      try {
        const apiPrefix = IS_RESELLER ? "/api/reseller/ram/history" : "/api/admin/ram/history";
        const data = await this.api(`${apiPrefix}?range=${encodeURIComponent(this.ramHistoryRange)}`);
        if (data) this.ramHistoryData = data;
      } catch (error) {
        console.error("Ram history load error:", error);
      } finally {
        this.loadingRamHistory = false;
      }
    },
    buildRamHistorySvgPath(points, width = 760, height = 200, key = "used_pct", maxVal = 100) {
      if (!points || points.length < 2) return "";
      const stepX = width / Math.max(1, points.length - 1);
      return points.map((p, i) => {
        const x = (i * stepX).toFixed(1);
        const y = (height - (Math.min(maxVal, Math.max(0, p[key] || 0)) / maxVal) * (height - 20) - 10).toFixed(1);
        return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
      }).join(' ');
    },
    buildRamHistoryAreaPath(points, width = 760, height = 200, key = "used_pct", maxVal = 100) {
      if (!points || points.length < 2) return "";
      const linePath = this.buildRamHistorySvgPath(points, width, height, key, maxVal);
      const lastX = width.toFixed(1);
      return `${linePath} L ${lastX} ${height} L 0 ${height} Z`;
    },
    openAddIpModal() {
      this.ipForm = { id: null, ip_address: "", ip_type: "ipv4", netmask_cidr: "/24", interface: "ens160", label: "Public IPv4", is_primary: false };
      this.showAddIpModal = true;
    },
    editServerIp(ip) {
      this.ipForm = { id: ip.id, ip_address: ip.ip_address, ip_type: ip.ip_type, netmask_cidr: ip.netmask_cidr, interface: ip.interface, label: ip.label, is_primary: Boolean(ip.is_primary) };
      this.showAddIpModal = true;
    },
    async saveServerIp() {
      this.savingIp = true;
      try {
        if (this.ipForm.id) {
          await this.api(`/api/admin/network/ips/${this.ipForm.id}`, {
            method: "PUT",
            body: JSON.stringify(this.ipForm),
          });
        } else {
          await this.api("/api/admin/network/ips", {
            method: "POST",
            body: JSON.stringify(this.ipForm),
          });
        }
        this.showAddIpModal = false;
        await this.loadNetworking();
      } catch (error) {
        this.message = error.message;
      } finally {
        this.savingIp = false;
      }
    },
    async setPrimaryIp(ip) {
      try {
        await this.api(`/api/admin/network/ips/${ip.id}`, {
          method: "PUT",
          body: JSON.stringify({ is_primary: true }),
        });
        await this.loadNetworking();
      } catch (error) {
        this.message = error.message;
      }
    },
    async deleteServerIp(ip) {
      if (!confirm(`Are you sure you want to remove IP ${ip.ip_address}?`)) return;
      try {
        await this.api(`/api/admin/network/ips/${ip.id}`, { method: "DELETE" });
        await this.loadNetworking();
      } catch (error) {
        this.message = error.message;
      }
    },
    openAssignIpModal(ip = null) {
      this.assignIpForm = { account_id: ip && ip.assigned_account_id ? ip.assigned_account_id : "", ip_id: ip ? ip.id : "" };
      this.showAssignIpModal = true;
    },
    async submitAssignAccountIp() {
      if (!this.assignIpForm.account_id) return;
      this.assigningIp = true;
      try {
        await this.api("/api/admin/network/assign-account-ip", {
          method: "POST",
          body: JSON.stringify(this.assignIpForm),
        });
        this.showAssignIpModal = false;
        await this.loadNetworking();
      } catch (error) {
        this.message = error.message;
      } finally {
        this.assigningIp = false;
      }
    },
    async loadStorage() {
      this.loadingStorage = true;
      // Start live I/O independently of the recursive quota/path scans below.
      // Those scans can take a long time on a busy host, but they should not
      // delay the top writers/readers table or its first SSE samples.
      this.startStorageLiveStream();
      try {
        const [dfRes, quotasRes, pathsRes, alertsRes] = await Promise.all([
          this.api("/api/admin/storage/df"),
          this.api("/api/admin/storage/quotas"),
          this.api("/api/admin/storage/paths"),
          this.api("/api/admin/storage/alerts")
        ]);
        this.storageDf = dfRes;
        this.storageQuotas = quotasRes.accounts || [];
        this.storagePaths = pathsRes;
        this.storageAlerts = alertsRes;
      } catch (error) {
        console.error("Storage load error:", error);
      } finally {
        this.loadingStorage = false;
      }
    },
    startStorageLiveStream() {
      this.stopStorageLiveStream();
      this.storageLiveActive = true;
      this.fetchStorageLiveOnce();

      if (window.EventSource) {
        try {
          const streamPath = IS_RESELLER ? "/api/reseller/storage/live/stream" : "/api/admin/storage/live/stream";
          const url = `${streamPath}${this.token ? '?token=' + encodeURIComponent(this.token) : ''}`;
          const es = new EventSource(url);
          es.onmessage = (e) => {
            if (!this.storageLiveActive || (this.activePage !== "storage" && this.activePage !== "overview")) return;
            try {
              this.setStorageTarget(JSON.parse(e.data));
            } catch (err) {}
          };
          es.onerror = () => {
            this.stopStorageLiveStream();
            this.startStoragePollingFallback();
          };
          this.storageLiveEs = es;
          return;
        } catch (e) {}
      }
      this.startStoragePollingFallback();
    },
    startStoragePollingFallback() {
      if (this.storageLiveTimer) clearInterval(this.storageLiveTimer);
      this.storageLiveTimer = setInterval(() => {
        if (this.storageLiveActive && (this.activePage === "storage" || this.activePage === "overview")) {
          this.fetchStorageLiveOnce();
        }
      }, 1000);
    },
    stopStorageLiveStream() {
      if (this.storageLiveEs) {
        this.storageLiveEs.close();
        this.storageLiveEs = null;
      }
      if (this.storageLiveTimer) {
        clearInterval(this.storageLiveTimer);
        this.storageLiveTimer = null;
      }
    },
    toggleStorageLive() {
      this.storageLiveActive = !this.storageLiveActive;
      if (this.storageLiveActive) {
        this.startStorageLiveStream();
      } else {
        this.stopStorageLiveStream();
      }
    },
    async fetchStorageLiveOnce() {
      try {
        const live = await this.api("/api/admin/storage/live");
        if (live) this.setStorageTarget(live);
      } catch (e) {
        // silent background refresh
      }
    },
    async runStorageCleanup(type) {
      this.storageCleanupRunning = true;
      this.storageCleanupResult = null;
      try {
        const body = {
          clean_docker: type === 'all' || type === 'docker',
          clean_logs: type === 'all' || type === 'logs',
          clean_tmp: type === 'all' || type === 'tmp',
        };
        const res = await this.api("/api/admin/storage/cleanup", {
          method: "POST",
          body: JSON.stringify(body),
        });
        this.storageCleanupResult = res;
        await this.loadStorage();
      } catch (error) {
        this.message = error.message;
      } finally {
        this.storageCleanupRunning = false;
      }
    },
    async saveStorageAlerts() {
      this.storageAlertsSaving = true;
      this.storageAlertsMsg = "";
      try {
        await this.api("/api/admin/storage/alerts", {
          method: "POST",
          body: JSON.stringify(this.storageAlerts),
        });
        this.storageAlertsMsg = "Storage alert thresholds saved successfully!";
        setTimeout(() => { this.storageAlertsMsg = ""; }, 3000);
      } catch (error) {
        this.message = error.message;
      } finally {
        this.storageAlertsSaving = false;
      }
    },
    clearAdminSession(message = "") {
      localStorage.removeItem(IS_RESELLER ? "mp_reseller_token" : "mp_admin_token");
      this.token = "";
      this.challengeToken = "";
      this.activePage = "overview";
      this.message = message;
    },
    dismissMessage() {
      this.message = "";
    },
    statusLabel(value) {
      return String(value || "unknown").replaceAll("_", " ");
    },
    async api(path, options = {}) {
      if (IS_RESELLER && path.startsWith("/api/admin/")) {
        path = path.replace("/api/admin/", "/api/reseller/");
      }
      const headers = { Accept: "application/json", ...(options.headers || {}) };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const response = await fetch(path, { ...options, headers });
      const payload = await response.json();
      if (!response.ok) {
        if (response.status === 503 && payload.error === "database_busy" && !options._dbRetry) {
          await new Promise((r) => setTimeout(r, 500));
          return this.api(path, { ...options, _dbRetry: true });
        }
        const error = payload.error || "Request failed";
        if (["invalid_access_token", "expired_access_token", "invalid_token_subject", "wrong_actor_type"].includes(error)) {
          this.clearAdminSession("Please sign in again.");
        }
        throw new Error(error);
      }
      return payload;
    },
    async startLogin() {
      this.message = "";
      try {
        const payload = await this.api("/api/admin/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: this.login.email, password: this.login.password }),
        });
        if (payload.access_token) {
          this.token = payload.access_token;
          localStorage.setItem(IS_RESELLER ? "mp_reseller_token" : "mp_admin_token", this.token);
          this.challengeToken = "";
          await this.load();
          return;
        }
        this.challengeToken = payload.challenge_token;
        this.$nextTick(() => {
          const el = document.querySelector(".totp-input") || document.querySelector("input[inputmode='numeric']");
          if (el) el.focus();
        });
      } catch (error) {
        if (this.token || ["invalid_access_token", "expired_access_token", "invalid_token_subject", "wrong_actor_type"].includes(error.message)) {
          this.clearAdminSession("Please sign in again.");
        } else {
          this.message = error.message;
        }
      }
    },
    async finishLogin() {
      this.message = "";
      try {
        const payload = await this.api("/api/admin/auth/totp/verify", {
          method: "POST",
          body: JSON.stringify({ challenge_token: this.challengeToken, code: this.login.code }),
        });
        this.token = payload.access_token;
        localStorage.setItem(IS_RESELLER ? "mp_reseller_token" : "mp_admin_token", this.token);
        this.challengeToken = "";
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    resetChallenge() {
      this.challengeToken = "";
      this.login.code = "";
      this.message = "";
    },
    async loadSecurityAudit() {
      this.securityAudit.loading = true;
      try {
        const payload = await this.api("/api/admin/security/audit");
        if (payload && payload.security) {
          this.securityAudit = { ...payload.security, loading: false };
        }
      } catch (error) {
        this.message = error.message;
      } finally {
        this.securityAudit.loading = false;
      }
    },
    async saveConfiguration() {
      this.configurationSaving = true;
      try {
        const result = await this.api("/api/admin/configuration", { method: "PATCH", body: JSON.stringify(this.configuration) });
        // Keep the selected value if an older/cached backend response omits
        // newly added configuration fields.
        this.configuration = { ...this.configuration, ...(result.configuration || {}) };
        this.message = result.ssh_motd_job_id ? `Configuration saved; SSH message update queued (job #${result.ssh_motd_job_id})` : "Configuration saved";
      } catch (error) {
        this.message = error.message;
      } finally {
        this.configurationSaving = false;
      }
    },
    async loadSystemBackup() {
      try { const result = await this.api("/api/admin/system-backup"); this.systemBackup = { ...this.systemBackup, ...(result.backup || {}) }; } catch (error) { this.message = error.message; }
    },
    async saveSystemBackup() {
      this.systemBackupSaving = true;
      try { const result = await this.api("/api/admin/system-backup", { method: "PATCH", body: JSON.stringify(this.systemBackup) }); this.systemBackup = { ...this.systemBackup, ...(result.backup || {}), remote_secret: "" }; this.message = "System backup settings saved"; } catch (error) { this.message = error.message; } finally { this.systemBackupSaving = false; }
    },
    async testSystemBackupStorage() {
      this.systemBackupTesting = true;
      try { const result = await this.api("/api/admin/system-backup/test", { method: "POST", body: "{}" }); this.message = `Remote storage test succeeded (${result.key})`; } catch (error) { this.message = error.message; } finally { this.systemBackupTesting = false; }
    },
    async runSystemBackup(kind = "all") {
      this.systemBackupRunning = true;
      try { const result = await this.api("/api/admin/system-backup/run", { method: "POST", body: JSON.stringify({ kind }) }); this.message = `Backup queued (job #${result.job_id})`; } catch (error) { this.message = error.message; } finally { this.systemBackupRunning = false; }
    },
    async applyModsecRules() {
      this.modsecApplying = true;
      try {
        const result = await this.api("/api/admin/modsecurity/rulesets/apply", { method: "POST", body: JSON.stringify({ ruleset: this.modsecRuleset }) });
        this.configuration.modsecurity_ruleset = result.ruleset || this.modsecRuleset;
        this.message = `Ruleset queued (job #${result.job_id})`;
      } catch (error) { this.message = error.message; }
      finally { this.modsecApplying = false; }
    },
    async load() {
      try {
        this.dashboard = await this.api("/api/admin/dashboard");
        this.admins = (await this.api("/api/admin/admins")).admins.map((admin) => ({
          ...admin,
          totp_enabled: Boolean(admin.totp_enabled),
        }));
        await this.loadClients(this.clientPagination.page || 1);
        const [plansRes, configRes, backupRes, dnsRes, domsRes, regsRes, stacksRes, jobsRes] = await Promise.all([
          this.api("/api/admin/plans"),
          this.api("/api/admin/configuration"),
          this.api("/api/admin/system-backup"),
          this.api("/api/admin/dns-settings"),
          this.api("/api/admin/domains"),
          this.api("/api/admin/registrars"),
          this.api("/api/admin/account-stacks"),
          this.api("/api/admin/job-events"),
        ]);
        this.plans = plansRes.plans;
        this.configuration = { ...this.configuration, ...(configRes.configuration || {}) };
        this.systemBackup = { ...this.systemBackup, ...(backupRes.backup || {}) };
        this.modsecRuleset = this.configuration.modsecurity_ruleset || "baseline";
        this.dnsSettings = dnsRes.dns_settings;
        this.dnsDomains = domsRes.domains || [];
        this.registrars = regsRes.registrars || [];
        await this.loadRegistrarDashboard();
        this.stacks = stacksRes.account_stacks;
        this.jobEvents = jobsRes.job_events;

        if (!IS_RESELLER) {
          Promise.all([
            this.loadResellerPlans(),
            this.loadResellerUsers(),
          ]).catch(() => {});
        }

        Promise.all([
          this.loadDefaultPage(),
          this.fetchAdminApiTokens(),
          this.loadStatusData(),
        ]).catch(() => {});
      } catch (error) {
        this.message = error.message;
      }
    },
    async loadClients(page = 1) {
      this.clientsLoading = true;
      try {
        const params = new URLSearchParams({ search: this.clientSearch.trim(), page: String(page), page_size: String(this.clientPagination.page_size || 25) });
        const payload = await this.api(`/api/admin/clients?${params.toString()}`);
        this.clients = payload.clients || [];
        this.clientPagination = { ...this.clientPagination, ...(payload.pagination || {}), page: Number(payload.pagination?.page || page) };
        for (const client of this.clients) {
          client.edit = { full_name: client.full_name, email: client.email, status: client.status };
          for (const account of client.accounts || []) {
            account.selected_plan_id = account.plan_id;
            account.selected_dns_provider = account.dns_provider || "";
            account.selected_dns_account_id = account.dns_provider_account_id || "";
          }
        }
      } catch (error) {
        this.message = error.message;
      } finally {
        this.clientsLoading = false;
      }
    },
    scheduleClientSearch() {
      if (this.clientSearchTimer) clearTimeout(this.clientSearchTimer);
      this.clientSearchTimer = setTimeout(() => this.loadClients(1), 250);
    },
    goToClientPage(page) {
      const target = Math.max(1, Math.min(Number(page), Number(this.clientPagination.total_pages || 1)));
      if (target !== this.clientPagination.page) this.loadClients(target);
    },
    async loadResellerPlans() {
      try {
        const res = await this.api("/api/admin/reseller-plans");
        this.resellerPlans = res.reseller_plans || [];
      } catch (error) {
        console.error("Reseller plans load error:", error);
      }
    },
    openResellerPlanModal(plan = null) {
      if (plan) {
        this.resellerPlanForm = {
          id: plan.id,
          name: plan.name,
          max_storage_mb: plan.max_storage_mb,
          max_clients: plan.max_clients,
          max_hosting_accounts: plan.max_hosting_accounts,
          max_ram_mb: plan.max_ram_mb,
          max_websites: plan.max_websites,
          max_databases: plan.max_databases,
          max_subplans: plan.max_subplans,
        };
      } else {
        this.resellerPlanForm = { id: null, name: "", max_storage_mb: 50000, max_clients: 10, max_hosting_accounts: 20, max_ram_mb: 8192, max_websites: 50, max_databases: 50, max_subplans: 10 };
      }
      this.showResellerPlanModal = true;
    },
    async saveResellerPlan() {
      try {
        if (this.resellerPlanForm.id) {
          await this.api(`/api/admin/reseller-plans/${this.resellerPlanForm.id}`, {
            method: "PATCH",
            body: JSON.stringify(this.resellerPlanForm),
          });
        } else {
          await this.api("/api/admin/reseller-plans", {
            method: "POST",
            body: JSON.stringify(this.resellerPlanForm),
          });
        }
        this.showResellerPlanModal = false;
        await this.loadResellerPlans();
      } catch (error) {
        this.message = error.message;
      }
    },
    async deleteResellerPlan(id) {
      if (!confirm("Are you sure you want to delete this reseller plan?")) return;
      try {
        await this.api(`/api/admin/reseller-plans/${id}`, { method: "DELETE" });
        await this.loadResellerPlans();
      } catch (error) {
        this.message = error.message;
      }
    },
    async loadResellerUsers() {
      try {
        const res = await this.api("/api/admin/reseller-users");
        this.resellerUsers = res.reseller_users || [];
      } catch (error) {
        console.error("Reseller users load error:", error);
      }
    },
    openResellerUserModal(user = null) {
      if (user) {
        this.resellerUserForm = {
          id: user.id,
          email: user.email,
          password: "",
          full_name: user.full_name,
          reseller_plan_id: user.reseller_plan_id || "",
          status: user.status,
        };
      } else {
        const defaultPlan = this.resellerPlans[0] ? this.resellerPlans[0].id : "";
        this.resellerUserForm = { id: null, email: "", password: "", full_name: "", reseller_plan_id: defaultPlan, status: "active" };
      }
      this.showResellerUserModal = true;
    },
    async saveResellerUser() {
      try {
        if (this.resellerUserForm.id) {
          await this.api(`/api/admin/reseller-users/${this.resellerUserForm.id}`, {
            method: "PATCH",
            body: JSON.stringify(this.resellerUserForm),
          });
        } else {
          await this.api("/api/admin/reseller-users", {
            method: "POST",
            body: JSON.stringify(this.resellerUserForm),
          });
        }
        this.showResellerUserModal = false;
        await this.loadResellerUsers();
      } catch (error) {
        this.message = error.message;
      }
    },
    async toggleResellerUserStatus(user) {
      const nextStatus = user.status === "active" ? "suspended" : "active";
      try {
        await this.api(`/api/admin/reseller-users/${user.id}`, {
          method: "PATCH",
          body: JSON.stringify({ status: nextStatus }),
        });
        await this.loadResellerUsers();
      } catch (error) {
        this.message = error.message;
      }
    },
    async deleteResellerUser(id) {
      if (!confirm("Are you sure you want to delete this reseller user?")) return;
      try {
        await this.api(`/api/admin/reseller-users/${id}`, { method: "DELETE" });
        await this.loadResellerUsers();
      } catch (error) {
        this.message = error.message;
      }
    },
    async loginAsReseller(ru) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/reseller-users/${ru.id}/login-as`, { method: "POST" });
        window.open(payload.reseller_url, "_blank");
      } catch (error) {
        this.message = error.message;
      }
    },
    async loadDefaultPage() {
      try {
        const res = await this.api("/api/admin/system/default-page");
        this.defaultPageContent = res.default_page_content;
        this.defaultPageIsCustomized = res.is_customized;
      } catch (error) {
        this.message = error.message;
      }
    },
    async saveDefaultPage() {
      this.savingDefaultPage = true;
      try {
        const res = await this.api("/api/admin/system/default-page", {
          method: "POST",
          body: JSON.stringify({ default_page_content: this.defaultPageContent }),
        });
        this.defaultPageContent = res.default_page_content;
        this.defaultPageIsCustomized = res.is_customized;
        this.message = res.message || "Default page content saved successfully.";
      } catch (error) {
        this.message = error.message;
      } finally {
        this.savingDefaultPage = false;
      }
    },
    async resetDefaultPage() {
      if (!confirm("Reset default page content to system default template?")) return;
      try {
        const res = await this.api("/api/admin/system/default-page/reset", {
          method: "POST",
          body: "{}",
        });
        this.defaultPageContent = res.default_page_content;
        this.defaultPageIsCustomized = false;
        this.message = res.message || "Default page content reset to system default.";
      } catch (error) {
        this.message = error.message;
      }
    },
    async runAgent() {
      try {
        await this.api("/api/admin/agent/run-all", { method: "POST", body: "{}" });
        this.message = "Agent run completed";
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    registrarByKey(key) {
      return this.registrars.find((item) => item.key === key) || {};
    },
    async loadRegistrarDashboard() {
      const params = new URLSearchParams();
      if (this.registrarSearch) params.set("search", this.registrarSearch);
      if (this.registrarProviderFilter) params.set("provider", this.registrarProviderFilter);
      params.set("sort", this.registrarSort);
      params.set("direction", this.registrarDirection);
      try {
        this.registrarDashboard = await this.api(`/api/admin/registrar-dashboard?${params.toString()}`);
      } catch (error) { this.message = error.message; }
    },
    openRegistrarAccountModal() {
      this.registrarAccountForm = { provider_key: "resellerclub", label: "", account_identifier: "", api_base: "", client_ip: "", api_key: "", api_token: "", dns_provider_account_id: "" };
      this.showRegistrarAccountModal = true;
    },
    openRegistrarAccountDetails(account) {
      const settings = account.settings || {};
      this.registrarAccountEditModal = {
        open: true,
        account,
        saving: false,
        form: {
          label: account.label || "",
          account_identifier: account.account_identifier || "",
          api_base: settings.api_base || "",
          client_ip: settings.client_ip || "",
          api_key: "",
          dns_provider_account_id: account.dns_provider_account_id || "",
        },
      };
    },
    async saveRegistrarAccountDetails() {
      const modal = this.registrarAccountEditModal;
      if (!modal.account) return;
      modal.saving = true;
      try {
        const form = modal.form;
        const result = await this.api(`/api/admin/registrar-accounts/${modal.account.id}`, {
          method: "PATCH",
          body: JSON.stringify({
            label: form.label,
            account_identifier: form.account_identifier,
            settings: { api_base: form.api_base, client_ip: form.client_ip },
            api_key: form.api_key,
            dns_provider_account_id: form.dns_provider_account_id || null,
          }),
        });
        modal.open = false;
        this.message = result.updated ? "Registrar account settings updated" : "Registrar account settings saved";
        await this.loadRegistrarDashboard();
      } catch (error) { this.message = error.message; }
      finally { modal.saving = false; }
    },
    async saveRegistrarAccount() {
      try {
        const form = this.registrarAccountForm;
        if (form.provider_key === "namecheap") {
          if (!form.account_identifier) form.account_identifier = window.prompt("Enter your Namecheap account username. This is used as both ApiUser and UserName:", "") || "";
          if (!form.client_ip) form.client_ip = window.prompt("Enter the public IPv4 address whitelisted in Namecheap API Access:", "") || "";
          if (!form.account_identifier || !form.client_ip) throw new Error("Namecheap username and whitelisted server IPv4 are required");
        }
        await this.api("/api/admin/registrar-accounts", { method: "POST", body: JSON.stringify({ provider_key: form.provider_key, label: form.label, account_identifier: form.account_identifier, dns_provider_account_id: form.dns_provider_account_id || null, settings: { api_base: form.api_base, client_ip: form.client_ip }, api_key: form.api_key, api_token: form.api_token }) });
        this.showRegistrarAccountModal = false;
        this.message = "Registrar account added";
        await this.loadRegistrarDashboard();
      } catch (error) { this.message = error.message; }
    },
    async syncRegistrarAccount(account) {
      this.registrarSyncing[account.id] = true;
      try {
        const result = await this.api(`/api/admin/registrar-accounts/${account.id}/sync`, { method: "POST", body: "{}" });
        this.message = `Sync completed: ${result.imported || 0} domain(s) imported`;
        await this.loadRegistrarDashboard();
      } catch (error) { this.message = error.message; }
      finally { this.registrarSyncing[account.id] = false; }
    },
    async deleteRegistrarAccount(account) {
      if (!window.confirm(`Delete registrar account “${account.label}”?`)) return;
      const deleteRecords = window.confirm("Also delete all locally synchronized domain records? Click OK to delete them; click Cancel to keep them locally.");
      try {
        const result = await this.api(`/api/admin/registrar-accounts/${account.id}?delete_records=${deleteRecords ? "true" : "false"}`, { method: "DELETE" });
        this.message = result.records_deleted ? "Registrar and local records deleted" : "Registrar deleted; local records retained";
        this.selectedRegistrarDomains = [];
        await this.loadRegistrarDashboard();
      } catch (error) { this.message = error.message; }
    },
    toggleRegistrarDomainSelection(id) {
      const index = this.selectedRegistrarDomains.indexOf(id);
      if (index >= 0) this.selectedRegistrarDomains.splice(index, 1);
      else this.selectedRegistrarDomains.push(id);
    },
    toggleAllRegistrarDomains() {
      this.selectedRegistrarDomains = this.allRegistrarDomainsSelected ? [] : this.registrarDomains.map((item) => item.id).filter((id) => id != null);
    },
    openRegistrarManage(domain) {
      this.registrarManageModal = { open: true, record: domain, user_id: domain.client_user_id || "", nameservers: [...(domain.nameservers || []), "", ""].slice(0, 2), saving: false };
    },
    async saveRegistrarManage() {
      const modal = this.registrarManageModal;
      if (!modal.record || modal.record.id === null) return;
      modal.saving = true;
      try {
        await this.api(`/api/admin/registrar-domain-records/${modal.record.id}/manage`, { method: "POST", body: JSON.stringify({ user_id: modal.user_id || null, nameservers: modal.nameservers.filter((item) => String(item || "").trim()) }) });
        modal.open = false;
        this.message = "Registrar domain association updated";
        this.loadRegistrarDashboard();
      } catch (error) { this.message = error.message; }
      finally { modal.saving = false; }
    },
    async bulkRegistrarAction(action) {
      const ids = this.selectedRegistrarDomains.filter((id) => id != null);
      if (!ids.length) return;
      const label = action === "delete_local" ? "remove these records from the local inventory" : "unassign these domains from clients";
      if (!window.confirm(`Are you sure you want to ${label}? This will not delete domains at the registrar.`)) return;
      try {
        await this.api("/api/admin/registrar-domain-records/bulk-manage", { method: "POST", body: JSON.stringify({ ids, action }) });
        this.selectedRegistrarDomains = [];
        this.message = "Bulk registrar action completed";
        await this.loadRegistrarDashboard();
      } catch (error) { this.message = error.message; }
    },
    registrarAssignableClients() {
      const search = String(this.registrarAssignModal.search || "").trim().toLowerCase();
      return this.clients.filter((client) => !search || [client.email, client.full_name, client.id].some((value) => String(value || "").toLowerCase().includes(search)));
    },
    openRegistrarAssignModal() {
      const ids = this.selectedRegistrarDomains.filter((id) => id != null);
      if (!ids.length) return;
      this.registrarAssignModal = { open: true, ids, search: "", user_id: "", saving: false };
    },
    async submitRegistrarAssign() {
      const modal = this.registrarAssignModal;
      const userId = Number(modal.user_id);
      if (!Number.isInteger(userId) || userId <= 0) { this.message = "Select a client user first"; return; }
      modal.saving = true;
      try {
        await this.api("/api/admin/registrar-domain-records/bulk-manage", { method: "POST", body: JSON.stringify({ ids: modal.ids, action: "assign", user_id: userId }) });
        modal.open = false;
        this.selectedRegistrarDomains = [];
        this.message = "Selected domains assigned to the client user";
        await this.loadRegistrarDashboard();
      } catch (error) { this.message = error.message; }
      finally { modal.saving = false; }
    },
    async saveRegistrar() {
      try {
        const form = this.registrarForm;
        const body = { settings: { api_base: form.api_base }, reseller_id: form.reseller_id, api_key: form.api_key, api_token: form.api_token };
        await this.api(`/api/admin/registrars/${form.key}`, { method: "PATCH", body: JSON.stringify(body) });
        this.message = "Registration provider saved";
        this.registrarForm.api_key = "";
        this.registrarForm.api_token = "";
        await this.load();
      } catch (error) { this.message = error.message; }
    },
    async addClientDomain() {
      try {
        const payload = { ...this.domainForm, user_id: Number(this.domainForm.user_id), account_id: this.domainForm.account_id ? Number(this.domainForm.account_id) : null, registrar_provider_id: this.domainForm.registrar_provider_id ? Number(this.domainForm.registrar_provider_id) : null };
        await this.api("/api/admin/domains", { method: "POST", body: JSON.stringify(payload) });
        this.message = payload.register ? "Domain registered and assigned" : "Existing domain assigned";
        this.domainForm.domain = "";
        await this.load();
      } catch (error) { this.message = error.message; }
    },
    async loadStatusData() {
      this.loadingStatus = true;
      try {
        const [incRes, statusRes] = await Promise.all([
          this.api("/api/admin/status/incidents"),
          this.api("/api/admin/status")
        ]);
        this.adminIncidents = incRes.incidents || [];
        this.adminComponents = statusRes.components || [];
      } catch (err) {
        this.message = err.message;
      } finally {
        this.loadingStatus = false;
      }
    },
    async createIncident() {
      if (!this.incident.title.trim()) return;
      try {
        const payload = await this.api("/api/admin/status/incidents", {
          method: "POST",
          body: JSON.stringify({
            title: this.incident.title.trim(),
            severity: this.incident.severity,
            state: "investigating",
            message: this.incident.message.trim(),
            published: true,
          }),
        });
        this.message = `Incident #${payload.incident_id} published successfully`;
        this.incident.title = "";
        this.incident.message = "";
        await this.loadStatusData();
      } catch (error) {
        this.message = error.message;
      }
    },
    async postIncidentUpdate(incidentId) {
      if (!this.updateIncidentForm[incidentId]) return;
      const msg = (this.updateIncidentForm[incidentId].message || "").trim();
      const state = this.updateIncidentForm[incidentId].state || "identified";
      if (!msg) return;
      try {
        await this.api(`/api/admin/status/incidents/${incidentId}/updates`, {
          method: "POST",
          body: JSON.stringify({ state, message: msg }),
        });
        this.message = `Incident #${incidentId} updated to ${state}`;
        this.updateIncidentForm[incidentId].message = "";
        await this.loadStatusData();
      } catch (err) {
        this.message = err.message;
      }
    },
    async deleteIncident(incidentId) {
      if (!confirm(`Delete incident #${incidentId}?`)) return;
      try {
        await this.api(`/api/admin/status/incidents/${incidentId}`, { method: "DELETE" });
        this.message = `Incident #${incidentId} deleted`;
        await this.loadStatusData();
      } catch (err) {
        this.message = err.message;
      }
    },
    async updateComponentStatus(componentId, newStatus) {
      try {
        await this.api(`/api/admin/status/components/${componentId}`, {
          method: "PATCH",
          body: JSON.stringify({ status: newStatus }),
        });
        this.message = `Component status updated to ${newStatus}`;
        await this.loadStatusData();
      } catch (err) {
        this.message = err.message;
      }
    },
    async createAdmin() {
      this.message = "";
      this.newAdminSecret = "";
      this.newAdminUri = "";
      this.newAdminTotpCode = "";
      this.newAdminTotpMessage = "";
      try {
        const payload = await this.api("/api/admin/admins", {
          method: "POST",
          body: JSON.stringify(this.newAdmin),
        });
        this.newAdminSecret = payload.totp_secret;
        this.newAdminUri = payload.totp_uri;
        this.message = `Admin ${payload.admin.email} created`;
        this.newAdmin = { full_name: "", email: "", role: "support_admin", password: "" };
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async checkNewAdminTotp() {
      this.newAdminTotpMessage = "";
      if (!this.newAdminSecret) return;
      try {
        const response = await fetch("/api/public/totp/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ totp_secret: this.newAdminSecret, code: this.newAdminTotpCode }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "TOTP check failed");
        this.newAdminTotpMessage = payload.valid ? "The code is valid." : "The code is not valid yet.";
      } catch (error) {
        this.newAdminTotpMessage = error.message;
      }
    },
    openAdminPasswordModal(admin) {
      this.adminPasswordModal = {
        open: true,
        admin,
        password: "",
        confirm: "",
      };
    },
    closeAdminPasswordModal() {
      this.adminPasswordModal = { open: false, admin: null, password: "", confirm: "" };
    },
    async saveAdminPassword() {
      if (!this.adminPasswordModal.admin) return;
      if (this.adminPasswordModal.password !== this.adminPasswordModal.confirm) {
        this.message = "Passwords do not match";
        return;
      }
      try {
        const payload = await this.api(`/api/admin/admins/${this.adminPasswordModal.admin.id}/reset-password`, {
          method: "POST",
          body: JSON.stringify({ password: this.adminPasswordModal.password }),
        });
        this.message = `Password updated for ${payload.admin.email}`;
        this.closeAdminPasswordModal();
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async disableAdminTotp(admin) {
      try {
        const payload = await this.api(`/api/admin/admins/${admin.id}/disable-2fa`, { method: "POST", body: "{}" });
        this.message = `TOTP disabled for ${payload.admin.email}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async enableAdminTotp(admin) {
      try {
        const payload = await this.api(`/api/admin/admins/${admin.id}/enable-2fa`, { method: "POST", body: "{}" });
        this.newAdminSecret = payload.totp_secret;
        this.newAdminUri = payload.totp_uri;
        this.newAdminTotpCode = "";
        this.newAdminTotpMessage = `TOTP enabled for ${payload.admin.email}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async createPlan() {
      this.message = "";
      this.planSaving = true;
      try {
        const payload = await this.api("/api/admin/plans", {
          method: "POST",
          body: JSON.stringify(this.planPayload()),
        });
        this.message = `Plan ${payload.plan.name} created`;
        this.showPlanModal = false;
        this.newPlan = {
          name: "",
          cpu_limit: "1",
          memory_mb: 1024,
          storage_mb: 10240,
          inode_limit: 100000,
          max_websites: 10,
          max_subdomains: 10,
          max_databases: 10,
          max_mailboxes: 10,
          max_cron_jobs: 10,
          daily_email_limit: 250,
          backup_retention_days: 7,
          backup_schedule: "daily",
          max_processes: 120,
          php_workers: 60,
          bandwidth_mb: 0,
          nameserver_1: "ns1.dns-parking.com",
          nameserver_2: "ns2.dns-parking.com",
          backup_location: "Singapore",
          frontend_frameworks: "Angular, Astro, Next.js, Nuxt, Parcel, React, Vue.js, etc.",
          backend_frameworks: "Express, Fastify, Hono, NestJS, Nuxt, React Router, SvelteKit",
          nodejs_versions: "24.x, 22.x, 20.x and 18.x",
          package_managers: "npm (default), yarn and pnpm",
          dns_default_provider: "local_powerdns",
          dns_allowed_providers: ["local_powerdns"],
          dns_allowed_provider_account_ids: [],
          dns_default_provider_account_id: "",
          dns_customer_editable: true,
          dns_max_records_per_domain: 100,
          dns_allowed_record_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"],
          dns_min_ttl: 60,
          dns_wildcard_records_allowed: true,
          dns_cloudflare_proxy_allowed: false,
          dns_dnssec_allowed: false,
          dns_dnssec_required: false,
        };
        await this.load();
      } catch (error) {
        this.message = error.message;
      } finally {
        this.planSaving = false;
      }
    },
    openPlanModal() {
      this.planSaving = false;
      this.editingPlanId = null;
      this.applyPlanToExistingAccounts = false;
      this.migratePlanDomains = false;
      this.showPlanModal = true;
    },
    editPlan(plan) {
      this.planSaving = false;
      this.editingPlanId = plan.id;
      this.applyPlanToExistingAccounts = false;
      this.migratePlanDomains = false;
      this.newPlan = {
        ...this.newPlan,
        ...plan,
        dns_allowed_providers: typeof plan.dns_allowed_providers_json === "string" ? JSON.parse(plan.dns_allowed_providers_json) : plan.dns_allowed_providers,
        dns_allowed_provider_account_ids: typeof plan.dns_allowed_provider_accounts_json === "string" ? JSON.parse(plan.dns_allowed_provider_accounts_json) : (plan.dns_allowed_provider_account_ids || []),
        dns_allowed_record_types: typeof plan.dns_allowed_record_types_json === "string" ? JSON.parse(plan.dns_allowed_record_types_json) : plan.dns_allowed_record_types,
        dns_default_provider_account_id: plan.dns_default_provider_account_id || "",
        dns_customer_editable: Boolean(plan.dns_customer_editable),
        dns_wildcard_records_allowed: Boolean(plan.dns_wildcard_records_allowed),
        dns_cloudflare_proxy_allowed: Boolean(plan.dns_cloudflare_proxy_allowed),
        dns_dnssec_allowed: Boolean(plan.dns_dnssec_allowed),
        dns_dnssec_required: Boolean(plan.dns_dnssec_required),
        allow_api_access: Boolean(plan.allow_api_access),
        is_reseller: Boolean(plan.is_reseller),
        max_clients: plan.max_clients || 0,
        max_reseller_subplans: plan.max_reseller_subplans || 0,
      };
      this.showPlanModal = true;
    },
    closePlanModal() {
      this.showPlanModal = false;
      this.editingPlanId = null;
      this.applyPlanToExistingAccounts = false;
    },
    planPayload() {
      return {
        ...this.newPlan,
        memory_mb: Number(this.newPlan.memory_mb), storage_mb: Number(this.newPlan.storage_mb), inode_limit: Number(this.newPlan.inode_limit),
        max_websites: Number(this.newPlan.max_websites), max_subdomains: Number(this.newPlan.max_subdomains), max_databases: Number(this.newPlan.max_databases), max_mailboxes: Number(this.newPlan.max_mailboxes),
        max_cron_jobs: Number(this.newPlan.max_cron_jobs), daily_email_limit: Number(this.newPlan.daily_email_limit), backup_retention_days: Number(this.newPlan.backup_retention_days),
        max_processes: Number(this.newPlan.max_processes), php_workers: Number(this.newPlan.php_workers), bandwidth_mb: Number(this.newPlan.bandwidth_mb),
        dns_default_provider_account_id: this.newPlan.dns_default_provider_account_id || null,
        dns_allowed_provider_account_ids: (this.newPlan.dns_allowed_provider_account_ids || []).map((id) => Number(id)),
        dns_customer_editable: Boolean(this.newPlan.dns_customer_editable), dns_max_records_per_domain: Number(this.newPlan.dns_max_records_per_domain),
        dns_min_ttl: Number(this.newPlan.dns_min_ttl), dns_wildcard_records_allowed: Boolean(this.newPlan.dns_wildcard_records_allowed),
        dns_cloudflare_proxy_allowed: Boolean(this.newPlan.dns_cloudflare_proxy_allowed), dns_dnssec_allowed: Boolean(this.newPlan.dns_dnssec_allowed), dns_dnssec_required: Boolean(this.newPlan.dns_dnssec_required),
        allow_api_access: Boolean(this.newPlan.allow_api_access),
        is_reseller: Boolean(this.newPlan.is_reseller),
        max_clients: Number(this.newPlan.max_clients || 0),
        max_reseller_subplans: Number(this.newPlan.max_reseller_subplans || 0),
      };
    },
    async updatePlan() {
      this.message = "";
      this.planSaving = true;
      try {
        const payload = await this.api(`/api/admin/plans/${this.editingPlanId}`, {
          method: "PATCH",
          body: JSON.stringify({
            ...this.planPayload(),
            apply_to_existing_accounts: this.applyPlanToExistingAccounts,
            migrate_existing_domains: this.migratePlanDomains,
          }),
        });
        let msg = `Plan ${payload.plan.name} updated`;
        if (payload.updated_account_count) {
          msg += `; ${payload.updated_account_count} account update(s) queued`;
        }
        if (payload.migrated_domain_count) {
          msg += `; ${payload.migrated_domain_count} domain migration(s) queued`;
        }
        this.message = msg;
        this.closePlanModal();
        this.load();
      } catch (error) {
        this.message = error.message;
      } finally {
        this.planSaving = false;
      }
    },
    async recalculateUsage() {
      this.recalculatingUsage = true;
      this.message = "";
      try {
        const payload = await this.api("/api/admin/plans/recalculate_usage", {
          method: "POST",
          body: JSON.stringify({}),
        });
        this.message = payload.message || "Usage recalculation job queued.";
        await this.load();
      } catch (error) {
        this.message = error.message;
      } finally {
        this.recalculatingUsage = false;
      }
    },
    async recalculatePlanUsage(plan) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/plans/${plan.id}/recalculate_usage`, {
          method: "POST",
          body: JSON.stringify({ plan_id: plan.id }),
        });
        this.message = payload.message || `Usage recalculation job queued for plan #${plan.id}.`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async updateClient(client) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/clients/${client.id}`, {
          method: "PATCH",
          body: JSON.stringify(client.edit),
        });
        this.message = `Client ${payload.client.email} updated`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async openClientProfile(client) {
      this.clientProfileModal = {
        ...this.clientProfileModal,
        open: true,
        loading: true,
        client,
        admin_password: "",
        admin_totp_code: "",
        new_password: "",
        confirm_password: "",
        totp_secret: "",
        totp_uri: "",
      };
      try {
        const payload = await this.api(`/api/admin/clients/${client.id}/profile`);
        this.clientProfileModal.form = payload.profile;
      } catch (error) {
        this.message = error.message;
        this.closeClientProfile();
      } finally {
        this.clientProfileModal.loading = false;
      }
    },
    closeClientProfile() {
      this.clientProfileModal.open = false;
      this.clientProfileModal.client = null;
    },
    async saveClientProfile() {
      const modal = this.clientProfileModal;
      if (!modal.admin_password) {
        this.message = "Enter your admin password to authorize this profile change.";
        return;
      }
      modal.saving = true;
      try {
        const payload = await this.api(`/api/admin/clients/${modal.form.id}/profile`, {
          method: "PATCH",
          body: JSON.stringify({
            full_name: modal.form.full_name,
            email: modal.form.email,
            status: modal.form.status,
            billing: modal.form.billing,
            admin_password: modal.admin_password,
            admin_totp_code: modal.admin_totp_code,
          }),
        });
        this.message = "Client profile updated.";
        modal.form = payload.profile;
        modal.admin_password = "";
        modal.admin_totp_code = "";
        await this.load();
      } catch (error) {
        this.message = error.message;
      } finally {
        modal.saving = false;
      }
    },
    async resetClientPassword() {
      const modal = this.clientProfileModal;
      if (!modal.new_password || modal.new_password !== modal.confirm_password) {
        this.message = "Enter matching new passwords.";
        return;
      }
      if (!modal.admin_password) {
        this.message = "Enter your admin password to authorize this reset.";
        return;
      }
      try {
        await this.api(`/api/admin/clients/${modal.form.id}/password`, {
          method: "POST",
          body: JSON.stringify({
            password: modal.new_password,
            admin_password: modal.admin_password,
            admin_totp_code: modal.admin_totp_code,
          }),
        });
        this.message = "Client password reset; existing client sessions were revoked.";
        modal.new_password = "";
        modal.confirm_password = "";
        modal.admin_password = "";
        modal.admin_totp_code = "";
      } catch (error) {
        this.message = error.message;
      }
    },
    async changeClient2FA(action) {
      const modal = this.clientProfileModal;
      if (!modal.admin_password) {
        this.message = "Enter your admin password to authorize this 2FA change.";
        return;
      }
      try {
        const payload = await this.api(`/api/admin/clients/${modal.form.id}/2fa`, {
          method: "POST",
          body: JSON.stringify({ action, admin_password: modal.admin_password, admin_totp_code: modal.admin_totp_code }),
        });
        modal.form.has_2fa = Boolean(payload.enabled);
        modal.totp_secret = payload.totp_secret || "";
        modal.totp_uri = payload.totp_uri || "";
        modal.admin_password = "";
        modal.admin_totp_code = "";
        this.message = action === "disable" ? "Client 2FA disabled; existing sessions were revoked." : "Client 2FA secret changed; share the new secret securely.";
      } catch (error) {
        this.message = error.message;
      }
    },
    async loginAsClient(client) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/clients/${client.id}/login-as`, { method: "POST" });
        window.location.assign(payload.client_url);
      } catch (error) {
        this.message = error.message;
      }
    },
    async createClient() {
      this.message = "";
      this.newClientSecret = "";
      try {
        const payload = await this.api("/api/admin/clients", {
          method: "POST",
          body: JSON.stringify(this.newClient),
        });
        this.message = `Client ${payload.client.email} created`;
        this.newClientSecret = payload.totp_secret;
        this.newClient = { full_name: "", email: "", password: "" };
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    openClientModal() {
      this.newClient = { full_name: "", email: "", password: "" };
      this.newClientSecret = "";
      this.showClientModal = true;
    },
    closeClientModal() {
      this.showClientModal = false;
      this.newClient = { full_name: "", email: "", password: "" };
      this.newClientSecret = "";
    },
    async changeAccountPlan(client, account) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/hosting-accounts/${account.id}/plan`, {
          method: "PATCH",
          body: JSON.stringify({ plan_id: Number(account.selected_plan_id) }),
        });
        this.message = `${client.email} moved to ${payload.hosting_account.plan_name}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async openAccountDatabases(client, account) {
      this.accountDatabasesModal = {
        ...this.accountDatabasesModal,
        open: true,
        loading: true,
        account: { ...account, client_email: client.email },
        databases: [],
      };
      try {
        const payload = await this.api("/api/admin/hosting-accounts/" + account.id + "/databases");
        this.accountDatabasesModal.databases = payload.databases || [];
      } catch (error) {
        this.message = error.message;
        this.closeAccountDatabases();
      } finally {
        this.accountDatabasesModal.loading = false;
      }
    },
    closeAccountDatabases() {
      this.accountDatabasesModal.open = false;
      this.accountDatabasesModal.account = null;
      this.accountDatabasesModal.databases = [];
    },
    async deleteAdminDatabase(database) {
      const account = this.accountDatabasesModal.account;
      if (!account || !window.confirm("Delete database " + database.name + "? This cannot be undone.")) return;
      this.accountDatabasesModal.deleting = true;
      try {
        const payload = await this.api("/api/admin/databases/" + database.id, { method: "DELETE" });
        this.message = "Database " + database.name + " deleted. Cleanup job #" + payload.job_id + " queued.";
        this.accountDatabasesModal.databases = this.accountDatabasesModal.databases.filter((item) => item.id !== database.id);
        await this.load();
      } catch (error) {
        this.message = error.message;
      } finally {
        this.accountDatabasesModal.deleting = false;
      }
    },
    async updateAccountDnsProvider(client, account) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/hosting-accounts/${account.id}/dns-provider`, {
          method: "PATCH",
          body: JSON.stringify({
            dns_provider: account.selected_dns_provider || "",
            dns_provider_account_id: account.selected_dns_account_id ? Number(account.selected_dns_account_id) : null,
          }),
        });
        this.message = `Updated DNS provider for ${account.username} to ${payload.dns_policy.display_label}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    providerLabel(key) {
      const provider = (this.dnsSettings.providers || []).find((item) => item.key === key);
      return provider ? provider.display_name : key;
    },
    planDnsProviders() {
      return (this.dnsSettings.providers || []).filter((provider) => ["local_powerdns", "cloudflare"].includes(provider.key));
    },
    ensurePlanDefaultDnsProvider() {
      if (!(this.newPlan.dns_allowed_providers || []).includes(this.newPlan.dns_default_provider)) {
        this.newPlan.dns_allowed_providers = [...(this.newPlan.dns_allowed_providers || []), this.newPlan.dns_default_provider];
      }
      if (this.newPlan.dns_default_provider !== "cloudflare") this.newPlan.dns_default_provider_account_id = "";
    },
    ensurePlanDnsProviderChecked(providerKey) {
      if (providerKey === this.newPlan.dns_default_provider && !(this.newPlan.dns_allowed_providers || []).includes(providerKey)) {
        this.newPlan.dns_allowed_providers = [...(this.newPlan.dns_allowed_providers || []), providerKey];
      }
      if (!(this.newPlan.dns_allowed_providers || []).includes("cloudflare")) {
        this.newPlan.dns_allowed_provider_account_ids = [];
        this.newPlan.dns_default_provider_account_id = "";
      }
    },
    planCloudflareAccounts() {
      const allowed = this.newPlan.dns_allowed_provider_account_ids || [];
      return this.cloudflareAccounts().filter((account) => !allowed.length || allowed.includes(account.id) || allowed.includes(String(account.id)));
    },
    ensurePlanDefaultAccountAllowed() {
      const allowed = this.newPlan.dns_allowed_provider_account_ids || [];
      if (this.newPlan.dns_default_provider_account_id && allowed.length && !allowed.includes(this.newPlan.dns_default_provider_account_id) && !allowed.includes(Number(this.newPlan.dns_default_provider_account_id))) {
        this.newPlan.dns_default_provider_account_id = "";
      }
    },
    cloudflareAccounts() {
      return (this.dnsSettings.accounts || []).filter((account) => account.provider_key === "cloudflare");
    },
    startEditCloudflareAccount(account) {
      this.cloudflareAccount = {
        id: account.id,
        display_name: account.display_name || "",
        account_name: account.account_name || "",
        external_account_id: account.external_account_id || "",
        api_token: "",
        status: account.status || "active",
      };
    },
    clearCloudflareAccountForm() {
      this.cloudflareAccount = { id: null, display_name: "", account_name: "", external_account_id: "", api_token: "", status: "active" };
    },
    async fetchAdminApiTokens() {
      try {
        const res = await this.api("/api/admin/api-tokens");
        this.adminApiTokens = res.api_tokens || [];
      } catch (err) {
        this.message = err.message;
      }
    },
    async createAdminApiToken() {
      if (!this.newAdminTokenName.trim()) return;
      this.message = "";
      try {
        const res = await this.api("/api/admin/api-tokens", {
          method: "POST",
          body: JSON.stringify({
            name: this.newAdminTokenName.trim(),
            permissions: this.newAdminTokenPermissions
          })
        });
        this.newAdminTokenRaw = res.token;
        this.newAdminTokenName = "";
        this.fetchAdminApiTokens();
      } catch (err) {
        this.message = err.message;
      }
    },
    async deleteAdminApiToken(id) {
      if (!confirm("Revoke this Admin API Token?")) return;
      this.message = "";
      try {
        await this.api(`/api/admin/api-tokens/${id}`, { method: "DELETE" });
        this.fetchAdminApiTokens();
      } catch (err) {
        this.message = err.message;
      }
    },
    async saveDnsSettings() {
      this.message = "";
      try {
        const payload = await this.api("/api/admin/dns-settings", {
          method: "PATCH",
          body: JSON.stringify({
            global_mode: this.dnsSettings.global_mode,
            local: this.dnsSettings.local,
          }),
        });
        this.dnsSettings = payload.dns_settings;
        this.message = "DNS settings saved";
      } catch (error) {
        this.message = error.message;
      }
    },
    async createCloudflareDnsAccount() {
      this.message = "";
      try {
        const isEditing = Boolean(this.cloudflareAccount.id);
        const path = isEditing
          ? `/api/admin/dns-providers/cloudflare/accounts/${this.cloudflareAccount.id}`
          : "/api/admin/dns-providers/cloudflare/accounts";
        const method = isEditing ? "PATCH" : "POST";
        const payload = await this.api(path, {
          method,
          body: JSON.stringify(this.cloudflareAccount),
        });
        this.dnsSettings = payload.dns_settings;
        this.clearCloudflareAccountForm();
        this.message = isEditing ? "Cloudflare DNS account updated" : "Cloudflare DNS account saved";
      } catch (error) {
        this.message = error.message;
      }
    },
    async deleteCloudflareDnsAccount(account) {
      this.message = "";
      const confirmed = window.confirm(`Delete Cloudflare account "${account.display_name}"? This cannot be undone and will affect any plans or domains using this account.`);
      if (!confirmed) return;
      try {
        const payload = await this.api(`/api/admin/dns-providers/cloudflare/accounts/${account.id}`, { method: "DELETE" });
        this.dnsSettings = payload.dns_settings;
        this.message = `Cloudflare account "${account.display_name}" deleted`;
      } catch (error) {
        this.message = error.message;
      }
    },
    async toggleCloudflareDnsAccount(account) {
      this.message = "";
      const nextStatus = account.status === "active" ? "disabled" : "active";
      try {
        const payload = await this.api(`/api/admin/dns-providers/cloudflare/accounts/${account.id}`, {
          method: "PATCH",
          body: JSON.stringify({
            status: nextStatus,
          }),
        });
        this.dnsSettings = payload.dns_settings;
        this.message = `Cloudflare account "${account.display_name}" ${nextStatus === "active" ? "activated" : "disabled"}`;
      } catch (error) {
        this.message = error.message;
      }
    },
    async migrateCloudflareAccountToLocal(account) {
      this.message = "";
      const confirmed = window.confirm(`Migrate all domains using "${account.display_name}" back to local DNS?`);
      if (!confirmed) return;
      try {
        const payload = await this.api(`/api/admin/dns-providers/cloudflare/accounts/${account.id}/migrate-local`, {
          method: "POST",
          body: "{}",
        });
        this.dnsSettings = payload.dns_settings;
        this.message = `${payload.migrated} domain${payload.migrated === 1 ? "" : "s"} queued for migration back to local DNS`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async testDnsProvider(provider, account = null) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/dns-providers/${provider.id}/test`, {
          method: "POST",
          body: JSON.stringify({ provider_account_id: account ? account.id : null }),
        });
        if (payload.dns_settings) {
          this.dnsSettings = payload.dns_settings;
        }
        this.message = payload.message;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async rebuildDnsDomain(domain) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/domains/${domain.id}/dns/rebuild`, { method: "POST", body: "{}" });
        this.message = `${domain.name} DNS rebuild queued as job #${payload.job_id}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async verifyDnsDomain(domain) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/domains/${domain.id}/dns/verify-nameservers`, { method: "POST", body: "{}" });
        this.message = `${domain.name}: ${payload.verification.message}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async exportDnsDomain(domain) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/domains/${domain.id}/dns/export`);
        this.message = `${payload.dns_zone_export.domain.name} DNS zone export saved`;
      } catch (error) {
        this.message = error.message;
      }
    },
    async migrateDnsDomain(domain, providerKey) {
      this.message = "";
      const account = providerKey === "cloudflare" ? (this.cloudflareAccounts() || [])[0] : null;
      try {
        const payload = await this.api(`/api/admin/domains/${domain.id}/dns/migrate-provider`, {
          method: "POST",
          body: JSON.stringify({
            dns_provider: providerKey,
            dns_provider_account_id: account ? account.id : null,
          }),
        });
        this.message = `${domain.name} migration queued as job #${payload.job_id}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async bulkMigrateDomains(providerKey) {
      this.message = "";
      const label = providerKey === "cloudflare" ? "Cloudflare" : "Local DNS";
      const account = providerKey === "cloudflare" ? this.cloudflareAccounts()[0] : null;
      if (providerKey === "cloudflare" && !account) {
        this.message = "Add a Cloudflare account before migrating domains";
        return;
      }
      const confirmed = window.confirm(`Migrate all managed domains to ${label}?`);
      if (!confirmed) return;
      try {
        const payload = await this.api("/api/admin/domains/dns/bulk-migrate-provider", {
          method: "POST",
          body: JSON.stringify({
            all: true,
            dns_provider: providerKey,
            dns_provider_account_id: account ? account.id : null,
          }),
        });
        this.message = `Bulk migration started for ${payload.jobs ? payload.jobs.length : 0} domain(s) to ${label}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async bulkMigrateAllToGlobalMode() {
      if (!this.dnsSettings || !this.dnsSettings.global_mode) return;
      await this.bulkMigrateDomains(this.dnsSettings.global_mode);
    },
    async toggleAccountStatus(client, account) {
      this.message = "";
      const suspended = ["suspended", "hard_suspended"].includes(account.status);
      const action = suspended ? "unsuspend" : "suspend";
      try {
        const payload = await this.api(`/api/admin/hosting-accounts/${account.id}/${action}`, {
          method: "POST",
          body: "{}",
        });
        this.message = `${client.email} account ${payload.status}`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async hardSuspendAccount(client, account) {
      this.message = "";
      const confirmed = window.confirm(`Hard suspend ${account.username}? This will stop the entire hosting stack and take all of its services offline.`);
      if (!confirmed) return;
      try {
        const payload = await this.api(`/api/admin/hosting-accounts/${account.id}/hard-suspend`, {
          method: "POST",
          body: "{}",
        });
        this.message = `${client.email} account hard suspended; its stack is being stopped`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async deleteClient(client) {
      this.message = "";
      const confirmed = window.confirm(`Delete customer ${client.email}? This permanently deletes the customer and ALL of their hosting accounts and panel data.`);
      if (!confirmed) return;
      try {
        await this.api(`/api/admin/clients/${client.id}`, { method: "DELETE" });
        this.message = `Client ${client.email} deleted`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async deleteHostingAccount(client, account) {
      const confirmed = window.confirm(`Delete hosting account ${account.username} for ${client.email}? This removes only this hosting account and its panel data. The customer and other accounts will remain.`);
      if (!confirmed) return;
      try {
        const payload = await this.api(`/api/admin/hosting-accounts/${account.id}`, { method: "DELETE" });
        this.message = `Hosting account ${payload.username || account.username} deleted; the customer was kept.`;
        await this.loadClients(this.clientPagination.page);
      } catch (error) {
        this.message = error.message;
      }
    },
    async retryJob(job) {
      this.message = "";
      try {
        const payload = await this.api(`/api/admin/jobs/${job.id}/retry`, { method: "POST", body: "{}" });
        this.message = `Job #${payload.job_id} re-queued`;
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async createHostingAccount() {
      this.message = "";
      try {
        const payload = await this.api("/api/admin/hosting-accounts", {
          method: "POST",
          body: JSON.stringify({
            user_id: Number(this.newAccount.user_id),
            plan_id: Number(this.newAccount.plan_id),
            node_id: Number(this.newAccount.node_id),
          }),
        });
        this.message = `Account ${payload.hosting_account.username} provisioning (Job #${payload.job_id})`;
        this.newAccount = { user_id: "", plan_id: "", node_id: "" };
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async registerNode() {
      this.message = "";
      if (!this.newNode.name || !this.newNode.hostname) return;
      try {
        const payload = await this.api("/api/admin/nodes", {
          method: "POST",
          body: JSON.stringify(this.newNode),
        });
        this.message = `Node ${payload.node.name} registered`;
        this.newNode = { name: "", hostname: "", quota_backend: "dev-simulator" };
        await this.load();
      } catch (error) {
        this.message = error.message;
      }
    },
    async logout() {
      try {
        await this.api("/api/admin/auth/logout", { method: "POST" });
      } catch (err) {
        console.error("API logout failed:", err);
      }
      localStorage.removeItem(IS_RESELLER ? "mp_reseller_token" : "mp_admin_token");
      const host = window.location.hostname;
      const cookieNames = ["mp_client_token", "jwt"];
      cookieNames.forEach(name => {
        document.cookie = `${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        document.cookie = `${name}=; path=/; domain=.localhost; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        document.cookie = `${name}=; path=/; domain=${host}; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        if (host.includes('.')) {
          const parts = host.split('.');
          for (let i = 0; i < parts.length - 1; i++) {
            const domain = '.' + parts.slice(i).join('.');
            document.cookie = `${name}=; path=/; domain=${domain}; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
          }
        }
      });
      this.clearAdminSession("");
    },
  },
  watch: {
    "login.code"(newVal) {
      const clean = String(newVal || "").trim();
      if (clean.length === 6 && this.challengeToken) {
        this.finishLogin();
      }
    },
    challengeToken(newVal) {
      if (newVal && String(this.login.code || "").trim().length === 6) {
        this.$nextTick(() => {
          this.finishLogin();
        });
      }
    }
  }
}).mount("#admin-app");
