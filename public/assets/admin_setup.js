const { createApp } = Vue;

createApp({
  data() {
    return {
      bootstrap: { admin_setup_required: false },
      message: "",
      result: null,
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
  },
}).mount("#admin-setup-app");

