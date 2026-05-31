const { createApp } = Vue;

createApp({
  data() {
    return {
      token: localStorage.getItem("mp_admin_token") || "",
      challengeToken: "",
      message: "",
      login: {
        email: "admin@mango.test",
        password: "ChangeMe-DevOnly-123!",
        code: "000000",
      },
      dashboard: {
        counts: { users: 0, hosting_accounts: 0, websites: 0, account_stacks: 0, open_incidents: 0 },
        nodes: [],
        recent_jobs: [],
        status: { overall_status: "unknown", components: [] },
      },
      stacks: [],
      clients: [],
      plans: [],
      jobEvents: [],
      admins: [],
      newAdminSecret: "",
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
      },
      newAdmin: {
        full_name: "",
        email: "",
        role: "support_admin",
        password: "",
      },
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
  },
  methods: {
    statusLabel(value) {
      return String(value || "unknown").replaceAll("_", " ");
    },
    async api(path, options = {}) {
      const headers = { Accept: "application/json", ...(options.headers || {}) };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const response = await fetch(path, { ...options, headers });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Request failed");
      return payload;
    },
    async startLogin() {
      this.message = "";
      try {
        const payload = await this.api("/api/admin/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: this.login.email, password: this.login.password }),
        });
        this.challengeToken = payload.challenge_token;
      } catch (error) {
        this.message = error.message;
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
    async load() {
      try {
        this.dashboard = await this.api("/api/admin/dashboard");
        this.admins = (await this.api("/api/admin/admins")).admins;
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
        this.stacks = (await this.api("/api/admin/account-stacks")).account_stacks;
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
      try {
        const payload = await this.api("/api/admin/admins", {
          method: "POST",
          body: JSON.stringify(this.newAdmin),
        });
        this.newAdminSecret = payload.totp_secret;
        this.message = `Admin ${payload.admin.email} created`;
        this.newAdmin = { full_name: "", email: "", role: "support_admin", password: "" };
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
          body: JSON.stringify({
            ...this.newPlan,
            memory_mb: Number(this.newPlan.memory_mb),
            storage_mb: Number(this.newPlan.storage_mb),
            inode_limit: Number(this.newPlan.inode_limit),
            max_websites: Number(this.newPlan.max_websites),
            max_databases: Number(this.newPlan.max_databases),
            max_mailboxes: Number(this.newPlan.max_mailboxes),
            max_cron_jobs: Number(this.newPlan.max_cron_jobs),
            daily_email_limit: Number(this.newPlan.daily_email_limit),
            backup_retention_days: Number(this.newPlan.backup_retention_days),
            max_processes: Number(this.newPlan.max_processes),
            php_workers: Number(this.newPlan.php_workers),
            bandwidth_mb: Number(this.newPlan.bandwidth_mb),
            nameserver_1: this.newPlan.nameserver_1,
            nameserver_2: this.newPlan.nameserver_2,
            backup_location: this.newPlan.backup_location,
            frontend_frameworks: this.newPlan.frontend_frameworks,
            backend_frameworks: this.newPlan.backend_frameworks,
            nodejs_versions: this.newPlan.nodejs_versions,
            package_managers: this.newPlan.package_managers,
          }),
        });
        this.message = `Plan ${payload.plan.name} created`;
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
        };
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
      this.token = "";
    },
  },
}).mount("#admin-app");
