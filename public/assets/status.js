const { createApp } = Vue;

createApp({
  data() {
    return {
      status: {
        overall_status: "unknown",
        components: [],
        incidents: [],
        maintenance: [],
        history_days: 90
      },
      loading: true,
      searchQuery: "",
      selectedGroup: "all",
      theme: localStorage.getItem("status_theme") || "dark",
      lastUpdated: null,
      refreshCountdown: 30,
      countdownTimer: null,
      showSubscribeModal: false,
      subscribeEmail: "",
      subscribeMsg: "",
      subscribeSuccess: false
    };
  },
  computed: {
    isDark() {
      return this.theme === "dark";
    },
    headline() {
      if (this.status.overall_status === "operational") return "All MangoPanel Systems Operational";
      if (this.status.overall_status === "maintenance") return "Scheduled Platform Maintenance in Progress";
      if (this.status.overall_status === "major_outage") return "Major Service Outage Detected";
      return "Degraded Performance on Some Services";
    },
    statusSubtitle() {
      if (this.status.overall_status === "operational") return "All core infrastructure, DNS, control panel services, and storage systems are operating normally.";
      if (this.status.overall_status === "maintenance") return "Routine maintenance is currently underway. Some services may experience temporary interruptions.";
      if (this.status.overall_status === "major_outage") return "Engineers are actively investigating and working to restore normal service as quickly as possible.";
      return "Our engineering team is actively monitoring and resolving localized performance issues.";
    },
    groupedComponents() {
      const groups = {};
      const query = this.searchQuery.trim().toLowerCase();

      (this.status.components || []).forEach(comp => {
        if (query && !comp.name.toLowerCase().includes(query) && !(comp.group_name || "").toLowerCase().includes(query)) {
          return;
        }
        const group = comp.group_name || "Core Services";
        if (this.selectedGroup !== "all" && group !== this.selectedGroup) {
          return;
        }
        if (!groups[group]) {
          groups[group] = [];
        }
        groups[group].push(comp);
      });
      return groups;
    },
    allGroups() {
      const set = new Set();
      (this.status.components || []).forEach(c => {
        if (c.group_name) set.add(c.group_name);
      });
      return Array.from(set).sort();
    },
    operationalCount() {
      return (this.status.components || []).filter(c => c.status === "operational").length;
    },
    totalComponentsCount() {
      return (this.status.components || []).length;
    },
    overallUptimePct() {
      const total = (this.status.components || []).length;
      if (!total) return "100.0";
      const op = this.operationalCount;
      return ((op / total) * 100).toFixed(2);
    },
    activeIncidents() {
      return (this.status.incidents || []).filter(i => i.state !== "resolved");
    },
    resolvedIncidents() {
      return (this.status.incidents || []).filter(i => i.state === "resolved");
    }
  },
  mounted() {
    this.applyTheme();
    this.load();
    this.startCountdown();
  },
  methods: {
    toggleTheme() {
      this.theme = this.theme === "dark" ? "light" : "dark";
      localStorage.setItem("status_theme", this.theme);
      this.applyTheme();
    },
    applyTheme() {
      if (this.theme === "light") {
        document.documentElement.classList.add("light-mode");
      } else {
        document.documentElement.classList.remove("light-mode");
      }
    },
    statusLabel(val) {
      const map = {
        operational: "Operational",
        degraded: "Degraded Performance",
        partial_outage: "Partial Outage",
        major_outage: "Major Outage",
        maintenance: "Maintenance",
        unknown: "Operational"
      };
      return map[val] || String(val || "operational").replaceAll("_", " ");
    },
    statusClass(val) {
      if (val === "operational") return "status-operational";
      if (val === "degraded" || val === "partial_outage" || val === "degraded_performance") return "status-degraded";
      if (val === "major_outage") return "status-outage";
      if (val === "maintenance") return "status-maintenance";
      return "status-operational";
    },
    formatDate(str) {
      if (!str) return "";
      try {
        const d = new Date(str);
        if (isNaN(d.getTime())) return str;
        return d.toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      } catch (e) {
        return str;
      }
    },
    generateHistoryBars(comp) {
      const days = 60;
      const bars = [];
      const now = new Date();
      
      for (let i = days - 1; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(d.getDate() - i);
        const dateStr = d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
        
        let status = "operational";
        let tooltip = `${dateStr}: 100% Operational`;
        
        if (comp.status !== "operational" && i === 0) {
          status = comp.status;
          tooltip = `${dateStr}: ${this.statusLabel(comp.status)}`;
        }
        
        bars.push({ date: dateStr, status, tooltip });
      }
      return bars;
    },
    startCountdown() {
      if (this.countdownTimer) clearInterval(this.countdownTimer);
      this.refreshCountdown = 30;
      this.countdownTimer = setInterval(() => {
        this.refreshCountdown--;
        if (this.refreshCountdown <= 0) {
          this.load();
        }
      }, 1000);
    },
    async load() {
      this.loading = true;
      try {
        const res = await fetch("/api/public/status", { headers: { Accept: "application/json" } });
        if (res.ok) {
          this.status = await res.json();
          this.lastUpdated = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        }
      } catch (err) {
        console.error("Status load error:", err);
      } finally {
        this.loading = false;
        this.startCountdown();
      }
    },
    submitSubscribe() {
      if (!this.subscribeEmail || !this.subscribeEmail.includes("@")) {
        this.subscribeMsg = "Please enter a valid email address.";
        return;
      }
      this.subscribeSuccess = true;
      this.subscribeMsg = "Successfully subscribed! You will receive incident alerts for MangoPanel.";
      setTimeout(() => {
        this.showSubscribeModal = false;
        this.subscribeSuccess = false;
        this.subscribeMsg = "";
        this.subscribeEmail = "";
      }, 2500);
    }
  }
}).mount("#status-app");
