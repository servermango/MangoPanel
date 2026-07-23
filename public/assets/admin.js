const { createApp } = Vue;

const ADMIN_ROUTE_PREFIX = "/admin";
const ADMIN_PAGE_TARGETS = new Set(["overview", "clients", "plans", "dns", "registrars", "dns-domains", "system", "admins", "status", "security"]);

function adminPageFromLocation() {
  const hash = window.location.hash.replace(/^#/, "");
  return ADMIN_PAGE_TARGETS.has(hash) ? hash : "overview";
}

createApp({
  data() {
    return {
      token: localStorage.getItem("mp_admin_token") || "",
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
        title: "Investigating degraded service",
        severity: "minor",
        message: "We are investigating reports from the local development environment.",
      },
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
    sidebarSections() {
      return [
        {
          label: "Operations",
          items: [
            { label: "Overview", target: "overview", description: "Resource counts, node health, and service summary." },
            { label: "Clients", target: "clients", description: "Customer profiles, account status, and package moves." },
            { label: "Plans", target: "plans", description: "Hosting packages, resource limits, and DNS policy." },
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
            { label: "Security Checklist", target: "security", description: "Server security audit, SSH hardening, firewall, SSL, and WAF status." },
            { label: "Stack & Jobs", target: "system", description: "Generated stacks, agent runs, recent jobs, and events." },
            { label: "Admins", target: "admins", description: "Admin users, TOTP secrets, nodes, and PHP availability." },
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
    },
    clearAdminSession(message = "") {
      localStorage.removeItem("mp_admin_token");
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
      const headers = { Accept: "application/json", ...(options.headers || {}) };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const response = await fetch(path, { ...options, headers });
      const payload = await response.json();
      if (!response.ok) {
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
          localStorage.setItem("mp_admin_token", this.token);
          this.challengeToken = "";
          await this.load();
          return;
        }
        this.challengeToken = payload.challenge_token;
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
        localStorage.setItem("mp_admin_token", this.token);
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
          }
        }
        this.plans = (await this.api("/api/admin/plans")).plans;
        this.dnsSettings = (await this.api("/api/admin/dns-settings")).dns_settings;
        this.dnsDomains = (await this.api("/api/admin/domains")).domains || [];
        this.registrars = (await this.api("/api/admin/registrars")).registrars || [];
        this.stacks = (await this.api("/api/admin/account-stacks")).account_stacks;
        await this.loadSecurityAudit();
        this.jobEvents = (await this.api("/api/admin/job-events")).job_events;
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
    async createIncident() {
      try {
        const payload = await this.api("/api/admin/status/incidents", {
          method: "POST",
          body: JSON.stringify({
            title: this.incident.title,
            severity: this.incident.severity,
            state: "investigating",
            message: this.incident.message,
            published: true,
          }),
        });
        this.message = `Incident #${payload.incident_id} published`;
        await this.load();
      } catch (error) {
        this.message = error.message;
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
        this.dnsSettings = payload.dns_settings;
        this.message = payload.message;
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
      localStorage.removeItem("mp_admin_token");
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
}).mount("#admin-app");
