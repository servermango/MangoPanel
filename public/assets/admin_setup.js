const { createApp } = Vue;

createApp({
  data() {
    return {
      bootstrap: { admin_setup_required: false, server_ip: "" },
      currentStep: 1, // 1: Panel domain, 2: Account, 3: 2FA Setup, 4: Complete
      message: "",
      submitting: false,
      result: null,
      totpCode: "",
      totpCheckMessage: "",
      totpVerified: false,
      copied: false,
      activeSlide: 0,
      slideTimer: null,
      features: [
        {
          badge: "Web Server Stack",
          title: "OpenLiteSpeed Runtime",
          desc: "High-performance web stack with per-vhost security isolation & PHP 8.2-8.4 support.",
          icon: "bolt"
        },
        {
          badge: "DNS & SSL Suite",
          title: "Automated PowerDNS & Cloudflare",
          desc: "Seamless zone publishing, Let's Encrypt SSL certificates, and DNS record controls.",
          icon: "shield"
        },
        {
          badge: "Mail & Storage",
          title: "Full Email & Webmail Suite",
          desc: "One-click SnappyMail webmail access, DKIM/SPF protection, and Postfix/Dovecot routing.",
          icon: "mail"
        },
        {
          badge: "Control Panel Tools",
          title: "Embedded Management Tools",
          desc: "Integrated phpMyAdmin, Adminer, and web-based file manager for instant client control.",
          icon: "database"
        }
      ],
      form: {
        panel_domain: "",
        full_name: "",
        email: "",
        password: "",
        confirm_password: ""
      }
    };
  },
  computed: {
    isPanelDomainValid() {
      const domain = this.form.panel_domain.trim().toLowerCase();
      return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain);
    },
    isAccountValid() {
      return (
        this.form.full_name.trim().length > 0 &&
        this.form.email.includes("@") &&
        this.form.password.length >= 8 &&
        this.form.password === this.form.confirm_password
      );
    }
  },
  mounted() {
    this.loadBootstrap();
    this.startSlideTimer();
  },
  beforeUnmount() {
    if (this.slideTimer) clearInterval(this.slideTimer);
  },
  methods: {
    startSlideTimer() {
      this.slideTimer = setInterval(() => {
        this.activeSlide = (this.activeSlide + 1) % this.features.length;
      }, 4000);
    },
    setSlide(index) {
      this.activeSlide = index;
    },
    async loadBootstrap() {
      try {
        const response = await fetch("/api/public/bootstrap", { headers: { Accept: "application/json" } });
        this.bootstrap = await response.json();
        const currentHost = window.location.hostname.toLowerCase();
        const isIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(currentHost);
        if (!this.form.panel_domain && currentHost.includes(".") && !isIpAddress && currentHost !== "localhost") {
          this.form.panel_domain = currentHost;
        }
      } catch (e) {
        console.error("Failed to load bootstrap status:", e);
      }
    },
    continueToAccount() {
      if (!this.isPanelDomainValid) {
        this.message = "Enter a valid panel domain, such as leaf.servermango.com.";
        return;
      }
      this.message = "";
      this.currentStep = 2;
    },
    async setup() {
      this.message = "";
      this.totpCheckMessage = "";
      if (this.form.password !== this.form.confirm_password) {
        this.message = "Passwords do not match.";
        return;
      }
      if (this.form.password.length < 8) {
        this.message = "Password must be at least 8 characters long.";
        return;
      }
      this.submitting = true;
      try {
        const response = await fetch("/api/public/admin-setup", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({
            public_host: this.form.panel_domain,
            full_name: this.form.full_name,
            email: this.form.email,
            password: this.form.password
          }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Admin setup failed");
        this.result = payload;
        this.bootstrap.admin_setup_required = false;
        this.currentStep = 3; // Advance to 2FA Setup
      } catch (error) {
        this.message = error.message;
        await this.loadBootstrap();
      } finally {
        this.submitting = false;
      }
    },
    async checkTotp() {
      this.totpCheckMessage = "";
      if (!this.result || !this.result.totp_secret || !this.totpCode) return;
      try {
        const response = await fetch("/api/public/totp/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ totp_secret: this.result.totp_secret, code: this.totpCode }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "TOTP check failed");
        if (payload.valid) {
          this.totpVerified = true;
          this.totpCheckMessage = "TOTP verified successfully! You can now complete setup.";
        } else {
          this.totpVerified = false;
          this.totpCheckMessage = "Invalid authenticator code. Please check your app and try again.";
        }
      } catch (error) {
        this.totpCheckMessage = error.message;
      }
    },
    finishSetup() {
      if (!this.totpVerified) {
        this.totpCheckMessage = "Please verify your TOTP code from your authenticator app first.";
        return;
      }
      this.currentStep = 4; // Advance to Complete screen
    },
    copySecret() {
      if (!this.result || !this.result.totp_secret) return;
      navigator.clipboard.writeText(this.result.totp_secret);
      this.copied = true;
      setTimeout(() => { this.copied = false; }, 2000);
    }
  }
}).mount("#admin-setup-app");
