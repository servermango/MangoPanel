const { createApp } = Vue;

createApp({
  data() {
    return {
      bootstrap: { admin_setup_required: false },
      message: "",
      result: null,
      totpCode: "",
      totpCheckMessage: "",
      form: {
        full_name: "",
        email: "",
        password: "",
      },
    };
  },
  mounted() {
    this.loadBootstrap();
  },
  methods: {
    async loadBootstrap() {
      const response = await fetch("/api/public/bootstrap", { headers: { Accept: "application/json" } });
      this.bootstrap = await response.json();
    },
    async setup() {
      this.message = "";
      this.totpCheckMessage = "";
      try {
        const response = await fetch("/api/public/admin-setup", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify(this.form),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Admin setup failed");
        this.result = payload;
        this.bootstrap.admin_setup_required = false;
      } catch (error) {
        this.message = error.message;
        await this.loadBootstrap();
      }
    },
    async checkTotp() {
      this.totpCheckMessage = "";
      if (!this.result || !this.result.totp_secret) return;
      try {
        const response = await fetch("/api/public/totp/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ totp_secret: this.result.totp_secret, code: this.totpCode }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "TOTP check failed");
        this.totpCheckMessage = payload.valid ? "The code is valid." : "The code is not valid yet.";
      } catch (error) {
        this.totpCheckMessage = error.message;
      }
    },
  },
}).mount("#admin-setup-app");
