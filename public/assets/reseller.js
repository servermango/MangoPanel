const { createApp } = Vue;

createApp({
  data() {
    return {
      token: localStorage.getItem("mp_reseller_token") || localStorage.getItem("mp_client_token") || "",
      resellerInfo: JSON.parse(localStorage.getItem("mp_reseller_info") || "null"),
      activePage: location.hash.replace("#", "") || "dashboard",
      loginForm: {
        email: "",
        password: "",
      },
      loggingIn: false,
      totpChallengeToken: null,
      totpCode: "",
      errorMessage: "",
      message: "",

      dashboardStats: null,
      clients: [],
      plans: [],
      accounts: [],
      apiTokens: [],

      showClientModal: false,
      clientForm: { full_name: "", email: "", password: "" },

      showPlanModal: false,
      planForm: { name: "", memory_mb: 512, storage_mb: 5000, max_websites: 5, max_databases: 5 },

      showAccountModal: false,
      accountForm: { user_id: "", plan_id: "" },

      showTokenModal: false,
      tokenForm: { name: "" },
      newGeneratedToken: null,
    };
  },
  computed: {
    clientPanelUrl() {
      const port = window.location.port === "8002" ? "8000" : window.location.port;
      const host = window.location.hostname;
      const currentToken = this.token || localStorage.getItem("mp_reseller_token") || "";
      return `${window.location.protocol}//${host}:${port}/#sso_token=${encodeURIComponent(currentToken)}`;
    },
  },
  async mounted() {
    const hash = window.location.hash.replace("#", "?");
    const searchParams = new URLSearchParams(window.location.search);
    const hashParams = new URLSearchParams(hash);

    // Check for admin "Login as Reseller" impersonation token first
    const impersonationToken = hashParams.get("mp_impersonation_token") || hashParams.get("mp_access_token");
    if (impersonationToken) {
      try {
        const response = await fetch("/api/reseller/auth/exchange-impersonation", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ impersonation_token: impersonationToken }),
        });
        const data = await response.json();
        if (response.ok && data.access_token) {
          this.token = data.access_token;
          localStorage.setItem("mp_reseller_token", data.access_token);
        }
      } catch (err) {
        console.error("Reseller impersonation exchange failed:", err);
      }
      window.history.replaceState(null, "", "/reseller#dashboard");
    }

    // Regular SSO token (plain access JWT passed via URL)
    if (!this.token) {
      const urlSsoToken = searchParams.get("sso_token") || searchParams.get("token") || hashParams.get("sso_token") || hashParams.get("token");
      if (urlSsoToken) {
        this.token = urlSsoToken;
        localStorage.setItem("mp_reseller_token", urlSsoToken);
        if (window.history && window.history.replaceState) {
          window.history.replaceState(null, "", "/reseller#dashboard");
        }
      }
    }

    if (!this.token) {
      this.token = localStorage.getItem("mp_reseller_token") || localStorage.getItem("mp_client_token") || localStorage.getItem("token") || "";
    }
    if (this.token) {
      this.loadData();
    }
    window.addEventListener("hashchange", () => {
      this.activePage = location.hash.replace("#", "") || "dashboard";
    });
  },
  methods: {
    async api(endpoint, options = {}) {
      const headers = options.headers || {};
      if (this.token) {
        headers["Authorization"] = `Bearer ${this.token}`;
      }
      headers["Content-Type"] = "application/json";
      options.headers = headers;

      const res = await fetch(endpoint, options);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || data.detail || "API Request Failed");
      }
      return data;
    },
    async login() {
      this.loggingIn = true;
      this.errorMessage = "";
      try {
        const res = await this.api("/api/reseller/auth/login", {
          method: "POST",
          body: JSON.stringify(this.loginForm),
        });
        if (res.totp_required) {
          this.totpChallengeToken = res.challenge_token;
        } else {
          this.token = res.access_token;
          localStorage.setItem("mp_reseller_token", this.token);
          await this.loadData();
        }
      } catch (err) {
        this.errorMessage = err.message;
      } finally {
        this.loggingIn = false;
      }
    },
    async verifyTotp() {
      this.loggingIn = true;
      this.errorMessage = "";
      try {
        const res = await this.api("/api/reseller/auth/totp/verify", {
          method: "POST",
          body: JSON.stringify({
            challenge_token: this.totpChallengeToken,
            code: this.totpCode,
          }),
        });
        this.token = res.access_token;
        localStorage.setItem("mp_reseller_token", this.token);
        await this.loadData();
      } catch (err) {
        this.errorMessage = err.message;
      } finally {
        this.loggingIn = false;
      }
    },
    logout() {
      this.token = "";
      this.resellerInfo = null;
      localStorage.removeItem("mp_reseller_token");
      localStorage.removeItem("mp_reseller_info");
    },
    async loadData() {
      try {
        const dash = await this.api("/api/reseller/dashboard");
        this.dashboardStats = dash.dashboard;
        
        const clientsRes = await this.api("/api/reseller/clients");
        this.clients = clientsRes.clients || [];

        const plansRes = await this.api("/api/reseller/plans");
        this.plans = plansRes.plans || [];

        const accountsRes = await this.api("/api/reseller/storage/quotas");
        this.accounts = accountsRes.accounts || [];

        const tokensRes = await this.api("/api/reseller/api-tokens");
        this.apiTokens = tokensRes.tokens || [];
      } catch (err) {
        if (err.message.includes("reseller_access_denied") || err.message.includes("invalid_access_token") || err.message.includes("missing_bearer_token")) {
          this.logout();
        } else {
          this.message = err.message;
        }
      }
    },
    async createClient() {
      try {
        await this.api("/api/reseller/clients", {
          method: "POST",
          body: JSON.stringify(this.clientForm),
        });
        this.message = "Sub-Client created successfully!";
        this.showClientModal = false;
        this.clientForm = { full_name: "", email: "", password: "" };
        await this.loadData();
      } catch (err) {
        alert(err.message);
      }
    },
    async toggleClientStatus(client) {
      try {
        const newStatus = client.status === "active" ? "suspended" : "active";
        await this.api(`/api/reseller/clients/${client.id}`, {
          method: "PATCH",
          body: JSON.stringify({ status: newStatus }),
        });
        await this.loadData();
      } catch (err) {
        alert(err.message);
      }
    },
    async createPlan() {
      try {
        await this.api("/api/reseller/plans", {
          method: "POST",
          body: JSON.stringify(this.planForm),
        });
        this.message = "Custom sub-plan created successfully!";
        this.showPlanModal = false;
        this.planForm = { name: "", memory_mb: 512, storage_mb: 5000, max_websites: 5, max_databases: 5 };
        await this.loadData();
      } catch (err) {
        alert(err.message);
      }
    },
    async provisionAccount() {
      try {
        await this.api("/api/reseller/hosting-accounts", {
          method: "POST",
          body: JSON.stringify(this.accountForm),
        });
        this.message = "Hosting stack provisioned successfully!";
        this.showAccountModal = false;
        this.accountForm = { user_id: "", plan_id: "" };
        await this.loadData();
      } catch (err) {
        alert(err.message);
      }
    },
    async createToken() {
      try {
        const res = await this.api("/api/reseller/api-tokens", {
          method: "POST",
          body: JSON.stringify(this.tokenForm),
        });
        this.newGeneratedToken = res.token;
        this.showTokenModal = false;
        this.tokenForm = { name: "" };
        await this.loadData();
      } catch (err) {
        alert(err.message);
      }
    },
    async deleteToken(id) {
      if (!confirm("Are you sure you want to revoke this Reseller API Token?")) return;
      try {
        await this.api(`/api/reseller/api-tokens/${id}`, { method: "DELETE" });
        await this.loadData();
      } catch (err) {
        alert(err.message);
      }
    },
  },
}).mount("#app");
