const { createApp } = Vue;

createApp({
  data() {
    return {
      bootstrap: { admin_setup_required: false },
      currentStep: 1, // 1: Account, 2: 2FA Setup, 3: Complete
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
        full_name: "",
        email: "",
        password: "",
        confirm_password: ""
      }
    };
  },
  computed: {
    isStep1Valid() {
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
      } catch (e) {
        console.error("Failed to load bootstrap status:", e);
      }
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
            full_name: this.form.full_name,
            email: this.form.email,
            password: this.form.password
          }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Admin setup failed");
        this.result = payload;
        this.bootstrap.admin_setup_required = false;
        this.currentStep = 2; // Advance to 2FA Setup
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
      this.currentStep = 3; // Advance to Complete screen
    },
    copySecret() {
      if (!this.result || !this.result.totp_secret) return;
      navigator.clipboard.writeText(this.result.totp_secret);
      this.copied = true;
      setTimeout(() => { this.copied = false; }, 2000);
    }
  }
}).mount("#admin-setup-app");
