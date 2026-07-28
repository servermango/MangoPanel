const { createApp } = Vue;
const IS_RESELLER = Boolean(window.IS_RESELLER_PANEL);
const ADMIN_ROUTE_PREFIX = IS_RESELLER ? "/reseller" : "/admin";
const ADMIN_PAGE_TARGETS = new Set(["overview", "clients", "plans", "storage", "networking", "dns", "registrars", "dns-domains", "system", "admins", "api-tokens", "status", "security", "default-page"]);

function adminPageFromLocation() {
  let hash = window.location.hash.replace(/^#/, "");
  if (hash === "default_page") hash = "default-page";
  return ADMIN_PAGE_TARGETS.has(hash) ? hash : "overview";
}

function getInitialToken() {
  const searchParams = new URLSearchParams(window.location.search);
  const hashStr = window.location.hash.replace(/^#/, "");
  const hashParams = new URLSearchParams(hashStr);
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
      showClientModal: false,
      plans: [],
      recalculatingUsage: false,
      showPlanModal: false,
      editingPlanId: null,
      applyPlanToExistingAccounts: false,
      migratePlanDomains: false,
      dnsDomains: [],
      registrars: [],
      registrarForm: { key: "resellerclub", reseller_id: "", api_base: "", api_key: "", api_token: "" },
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
        max_databases: 10,
        max_mailboxes: 10,
        max_cron_jobs: 10,
        daily_email_limit: 250,
        backup_retention_days: 7,
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
  mounted() {
    if (this.token) this.load();
    window.addEventListener("popstate", () => {
      this.activePage = adminPageFromLocation();
    });
    window.addEventListener("hashchange", () => {
      this.activePage = adminPageFromLocation();
    });
  },
  computed: {
    managedClients() {
      if (!this.selectedClientId) return this.clients;
      return this.clients.filter((client) => Number(client.id) === Number(this.selectedClientId));
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
      return [
        {
          label: "Operations",
          items: [
            { label: "Overview", target: "overview", description: "Resource counts, node health, and service summary." },
            { label: "Clients", target: "clients", description: "Customer profiles, account status, and package moves." },
            { label: "Plans", target: "plans", description: "Hosting packages, resource limits, and DNS policy." },
            { label: "Storage", target: "storage", description: "Disk capacity graph (df -h), SSE live read/write rates, WHM quotas, path sizes, and cleanup." },
            { label: "Networking", target: "networking", description: "Public IP addresses, interface topology, IP aliases, and client dedicated IP assignment." },
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
        this.loadStorage();
      } else if (target === "networking") {
        this.stopStorageLiveStream();
        this.loadNetworking();
      } else if (target === "overview") {
        this.loadStorage();
        this.loadNetworking();
      } else if (target === "status") {
        this.stopStorageLiveStream();
        this.stopNetworkLiveStream();
        this.loadStatusData();
      } else {
        this.stopStorageLiveStream();
        this.stopNetworkLiveStream();
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
    async loadNetworking() {
      try {
        this.networkOverview = await this.api("/api/admin/network/overview");
        this.serverIps = (await this.api("/api/admin/network/ips")).server_ips || [];
        this.startNetworkLiveStream();
      } catch (error) {
        console.error("Networking load error:", error);
      }
    },
    async startNetworkLiveStream() {
      this.stopNetworkLiveStream();
      this.networkLiveActive = true;
      try {
        this.networkLive = await this.api("/api/admin/network/live");
      } catch (e) {}

      if (window.EventSource) {
        try {
          const url = `/api/admin/network/live/stream${this.token ? '?token=' + encodeURIComponent(this.token) : ''}`;
          const es = new EventSource(url);
          es.onmessage = (e) => {
            if (!this.networkLiveActive || (this.activePage !== "networking" && this.activePage !== "overview")) return;
            try {
              this.networkLive = JSON.parse(e.data);
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
          this.networkLive = await this.api("/api/admin/network/live");
        } catch (e) {}
      }, 300);
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
        this.startStorageLiveStream();
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
          const url = `/api/admin/storage/live/stream${this.token ? '?token=' + encodeURIComponent(this.token) : ''}`;
          const es = new EventSource(url);
          es.onmessage = (e) => {
            if (!this.storageLiveActive || (this.activePage !== "storage" && this.activePage !== "overview")) return;
            try {
              this.storageLive = JSON.parse(e.data);
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
      }, 300);
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
        if (live) this.storageLive = live;
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
    async load() {
      try {
        this.dashboard = await this.api("/api/admin/dashboard");
        this.admins = (await this.api("/api/admin/admins")).admins.map((admin) => ({
          ...admin,
          totp_enabled: Boolean(admin.totp_enabled),
        }));
        this.clients = (await this.api("/api/admin/clients")).clients;
        for (const client of this.clients) {
          client.edit = {
            full_name: client.full_name,
            email: client.email,
            status: client.status,
          };
          for (const account of client.accounts) {
            account.selected_plan_id = account.plan_id;
            account.selected_dns_provider = account.dns_provider || "";
            account.selected_dns_account_id = account.dns_provider_account_id || "";
          }
        }
        const [plansRes, dnsRes, domsRes, regsRes, stacksRes, jobsRes] = await Promise.all([
          this.api("/api/admin/plans"),
          this.api("/api/admin/dns-settings"),
          this.api("/api/admin/domains"),
          this.api("/api/admin/registrars"),
          this.api("/api/admin/account-stacks"),
          this.api("/api/admin/job-events"),
        ]);
        this.plans = plansRes.plans;
        this.dnsSettings = dnsRes.dns_settings;
        this.dnsDomains = domsRes.domains || [];
        this.registrars = regsRes.registrars || [];
        this.stacks = stacksRes.account_stacks;
        this.jobEvents = jobsRes.job_events;

        Promise.all([
          this.loadDefaultPage(),
          this.fetchAdminApiTokens(),
          this.loadStatusData(),
        ]).catch(() => {});
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
          max_databases: 10,
          max_mailboxes: 10,
          max_cron_jobs: 10,
          daily_email_limit: 250,
          backup_retention_days: 7,
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
      }
    },
    openPlanModal() {
      this.editingPlanId = null;
      this.applyPlanToExistingAccounts = false;
      this.migratePlanDomains = false;
      this.showPlanModal = true;
    },
    editPlan(plan) {
      this.editingPlanId = plan.id;
      this.applyPlanToExistingAccounts = false;
      this.migratePlanDomains = false;
      this.newPlan = {
        ...this.newPlan,
        ...plan,
        dns_allowed_providers: typeof plan.dns_allowed_providers_json === "string" ? JSON.parse(plan.dns_allowed_providers_json) : plan.dns_allowed_providers,
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
        max_websites: Number(this.newPlan.max_websites), max_databases: Number(this.newPlan.max_databases), max_mailboxes: Number(this.newPlan.max_mailboxes),
        max_cron_jobs: Number(this.newPlan.max_cron_jobs), daily_email_limit: Number(this.newPlan.daily_email_limit), backup_retention_days: Number(this.newPlan.backup_retention_days),
        max_processes: Number(this.newPlan.max_processes), php_workers: Number(this.newPlan.php_workers), bandwidth_mb: Number(this.newPlan.bandwidth_mb),
        dns_default_provider_account_id: this.newPlan.dns_default_provider_account_id || null,
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
        await this.load();
      } catch (error) {
        this.message = error.message;
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
      const action = account.status === "suspended" ? "unsuspend" : "suspend";
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
    async deleteClient(client) {
      this.message = "";
      const confirmed = window.confirm(`Delete ${client.email} and all panel records for their hosting accounts?`);
      if (!confirmed) return;
      try {
        await this.api(`/api/admin/clients/${client.id}`, { method: "DELETE" });
        this.message = `Client ${client.email} deleted`;
        await this.load();
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
