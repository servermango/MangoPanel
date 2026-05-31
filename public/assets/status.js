const { createApp } = Vue;

createApp({
  data() {
    return {
      status: {
        overall_status: "unknown",
        components: [],
        incidents: [],
        maintenance: [],
      },
    };
  },
  computed: {
    headline() {
      if (this.status.overall_status === "operational") return "All MangoPanel systems are operational.";
      if (this.status.overall_status === "maintenance") return "Scheduled maintenance is in progress.";
      if (this.status.overall_status === "major_outage") return "A major outage is affecting the platform.";
      return "Some services are degraded.";
    },
  },
  mounted() {
    this.load();
    setInterval(this.load, 30000);
  },
  methods: {
    statusLabel(value) {
      return String(value || "unknown").replaceAll("_", " ");
    },
    async load() {
      const response = await fetch("/api/public/status", { headers: { Accept: "application/json" } });
      this.status = await response.json();
    },
  },
}).mount("#status-app");
