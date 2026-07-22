const { createApp } = Vue;

const CLIENT_ROUTE_PREFIX = "/client";


const CLIENT_PAGE_TARGETS = new Set([
  "dashboard",
  "installer",
  "hosting-plan",
  "performance",
  "analytics",
  "security",
  "domains",
  "website",
  "files",
  "databases",
  "email",
  "cron-jobs",
  "backups",
  "git",
  "ssh-access",
  "php-configuration",
  "dns-zone-editor",
  "php-info",
  "cache-manager",
  "password-protect-directories",
  "ip-manager",
  "hotlink-protection",
  "folder-index-manager",
  "fix-file-ownership",
  "services",
  "activity",
  "settings",
  "redirects",
  "disk-usage",
  "modsecurity",
  "mysql-database-wizard",
  "api-tokens",
  "two-factor-auth",
  "ftp-accounts",
]);

const PHP_VERSIONS = ["8.2", "8.3", "8.4"];

function pageFromLocation() {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  if (path === "/" || path === CLIENT_ROUTE_PREFIX) return "dashboard";
  if (!path.startsWith(`${CLIENT_ROUTE_PREFIX}/`)) return "dashboard";
  const target = decodeURIComponent(path.slice(CLIENT_ROUTE_PREFIX.length + 1).split("/", 1)[0] || "");
  return CLIENT_PAGE_TARGETS.has(target) ? target : "dashboard";
}

function pageUrl(target) {
  const page = CLIENT_PAGE_TARGETS.has(target) ? target : "dashboard";
  return `${CLIENT_ROUTE_PREFIX}/${encodeURIComponent(page)}`;
}

function normalizedClientTarget(target) {
  const targetMap = {
    visitors: "analytics",
    errors: "analytics",
    bandwidth: "analytics",
    webalizer: "analytics",
    "raw-access": "analytics",
    "resource-usage": "performance",
    images: "files",
    "remote-mysql": "databases",
    "postgresql-databases": "databases",
    "postgresql-database-wizard": "databases",
    "site-builder": "installer",
    "ssl-tls": "security",
  };
  return targetMap[target] || target;
}

const AppIcon = {
  props: ["name"],
  computed: {
    unreadNotificationsCount() {
      return this.notifications.filter(n => !n.read).length;
    },
    activeToasts() {
      return this.notifications.filter(n => n.toastVisible);
    },
    svgContent() {
      // Each icon is a full SVG inner HTML string — allows mixing path/circle/rect/polyline etc.
      const icons = {
        // ── Navigation / Shell ───────────────────────────────────
        dashboard: `<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>`,
        bell: `<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path>`,
        download: `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>`,
        refresh: `<path d="M21 12a9 9 0 1 1-3.03-6.7"/><polyline points="21 3 21 9 15 9"/>`,
        search: `<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>`,
        user: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>`,
        logout: `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>`,
        login: `<path d="M10 17l5-5-5-5"/><path d="M15 12H3"/><path d="M21 3v18a2 2 0 0 1-2 2h-8"/>`,
        chevron: `<polyline points="6 9 12 15 18 9"/>`,
        settings: `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>`,
        plus: `<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>`,
        trash: `<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>`,
        external: `<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>`,
        check: `<polyline points="20 6 9 17 4 12"/>`,
        warning: `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`,
        info: `<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`,

        // ── Hosting / Sites ───────────────────────────────────────
        website: `<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="2" y1="7" x2="22" y2="7"/><circle cx="5" cy="5" r=".5" fill="currentColor"/><circle cx="8" cy="5" r=".5" fill="currentColor"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>`,
        domains: `<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`,
        "site-builder": `<rect x="3" y="3" width="18" height="4" rx="1"/><rect x="3" y="9" width="8" height="12" rx="1"/><rect x="13" y="9" width="8" height="5" rx="1"/><rect x="13" y="16" width="8" height="5" rx="1"/>`,
        redirects: `<path d="M5 12h14"/><path d="M12 5l7 7-7 7"/><path d="M3 5h4a4 4 0 0 1 4 4v0a4 4 0 0 1-4 4H3"/>`,
        wordpress: `<circle cx="12" cy="12" r="10"/><path d="M5 12h14M12 2c3.5 4 3.5 12 0 16M12 2c-3.5 4-3.5 12 0 16"/>`,
        installer: `<path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>`,

        // ── Files ────────────────────────────────────────────────
        files: `<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/>`,
        folder: `<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>`,
        images: `<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>`,
        "disk-usage": `<path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>`,
        ftp: `<path d="M4 17l8-8 8 8"/><path d="M4 7h16"/><line x1="8" y1="17" x2="8" y2="21"/><line x1="16" y1="17" x2="16" y2="21"/>`,
        "password-protect": `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="17" r="1" fill="currentColor"/>`,
        "folder-index": `<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="9" y1="14" x2="15" y2="14"/><line x1="9" y1="17" x2="12" y2="17"/>`,
        backup: `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>`,
        git: `<circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/>`,

        // ── Databases ─────────────────────────────────────────────
        databases: `<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.66 3.58 3 8 3s8-1.34 8-3V6"/><path d="M4 12v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>`,
        "databases-wizard": `<ellipse cx="10" cy="6" rx="7" ry="2.5"/><path d="M3 6v5c0 1.38 3.13 2.5 7 2.5 1.06 0 2.06-.1 2.97-.28"/><path d="M3 11v5c0 1.38 3.13 2.5 7 2.5.5 0 1-.03 1.47-.08"/><path d="M18 13l2 2 4-4"/><circle cx="20" cy="17" r="3"/>`,
        "remote-mysql": `<ellipse cx="8" cy="7" rx="6" ry="2.5"/><path d="M2 7v5c0 1.38 2.69 2.5 6 2.5.55 0 1.08-.04 1.58-.1"/><path d="M14 10h6a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2h-6a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2z"/><line x1="2" y1="7" x2="2" y2="17"/><line x1="14" y1="13" x2="10" y2="13"/>`,
        postgresql: `<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.66 3.58 3 8 3s8-1.34 8-3V6"/><line x1="12" y1="9" x2="12" y2="21"/><path d="M8 16a4 4 0 0 0 8 0"/>`,
        "postgresql-wizard": `<ellipse cx="10" cy="6" rx="7" ry="2.5"/><path d="M3 6v5c0 1.38 3.13 2.5 7 2.5.55 0 1.08-.04 1.6-.1"/><path d="M17 11l2 2 4-4"/>`,
        phpmyadmin: `<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><path d="M9 14h1v4"/><path d="M13 14h2a1.5 1.5 0 0 1 0 3h-2"/>`,
        phppgadmin: `<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><circle cx="9" cy="15" r="2"/><line x1="14" y1="13" x2="14" y2="18"/><line x1="17" y1="13" x2="17" y2="18"/><line x1="14" y1="15.5" x2="17" y2="15.5"/>`,

        // ── Email ─────────────────────────────────────────────────
        email: `<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22 6 12 13 2 6"/>`,
        webmail: `<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22 6 12 13 2 6"/><line x1="2" y1="18" x2="8" y2="12"/><line x1="22" y1="18" x2="16" y2="12"/>`,

        // ── Performance / Metrics ─────────────────────────────────
        performance: `<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>`,
        analytics: `<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="3" y1="20" x2="21" y2="20"/>`,
        visitors: `<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>`,
        errors: `<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`,
        bandwidth: `<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/>`,
        "raw-access": `<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>`,
        webalizer: `<path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3z"/><path d="M3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/>`,
        "resource-usage": `<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>`,
        activity: `<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>`,

        // ── Security ──────────────────────────────────────────────
        security: `<path d="M12 3l8 3v5c0 5.25-3.5 9.74-8 11-4.5-1.26-8-5.75-8-11V6l8-3z"/><polyline points="9 12 11 14 15 10"/>`,
        shield: `<path d="M12 3l8 3v5c0 5.25-3.5 9.74-8 11-4.5-1.26-8-5.75-8-11V6l8-3z"/>`,
        lock: `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`,
        key: `<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.77-7.77zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>`,
        ssl: `<rect x="5" y="11" width="14" height="11" rx="1"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><path d="M12 15v2"/><circle cx="12" cy="15" r="1" fill="currentColor"/>`,
        totp: `<rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/><path d="M9 7h1l1 3 2-3h1"/>`,
        "password-protect": `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="17" r="1" fill="currentColor"/>`,
        hotlink: `<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/><line x1="5" y1="5" x2="19" y2="19"/>`,
        ip: `<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12" y2="16"/><path d="M8 12h8"/>`,
        modsecurity: `<path d="M12 3l8 3v5c0 5.25-3.5 9.74-8 11-4.5-1.26-8-5.75-8-11V6l8-3z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/>`,
        "api-tokens": `<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.77-7.77zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>`,

        // ── Infrastructure / System ───────────────────────────────
        cpu: `<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>`,
        memory: `<path d="M6 4h12a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"/><path d="M6 13h12a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2z"/><line x1="10" y1="4" x2="10" y2="13"/><line x1="14" y1="4" x2="14" y2="13"/><line x1="10" y1="13" x2="10" y2="22"/><line x1="14" y1="13" x2="14" y2="22"/>`,
        disk: `<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="18.9" y1="5.1" x2="14.12" y2="9.88"/>`,
        network: `<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><line x1="12" y1="7" x2="12" y2="11"/><line x1="10.54" y1="12.75" x2="6.5" y2="17.25"/><line x1="13.46" y1="12.75" x2="17.5" y2="17.25"/>`,
        services: `<circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/><path d="M4.93 4.93a10 10 0 0 0 0 14.14"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M8.46 8.46a5 5 0 0 0 0 7.07"/>`,
        terminal: `<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>`,
        sftp: `<rect x="2" y="6" width="20" height="16" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/><path d="M6 14h4"/><path d="M14 17l3-3-3-3"/>`,
        dns: `<path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>`,
        cache: `<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/>`,

        // ── PHP / Code ────────────────────────────────────────────
        php: `<path d="M12 2a10 10 0 0 0-10 10 10 10 0 0 0 10 10 10 10 0 0 0 10-10A10 10 0 0 0 12 2zm-2 6h-1l-1 4H7l1-4H7M15 8h-2l-1 4h2a2 2 0 0 0 0-4zm0 5h-2l-.5 3h-1l.5-3h-1"/>`,
        code: `<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>`,
        link: `<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>`,
        fix: `<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>`,
        wrench: `<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>`,

        // ── Hosting / Plan ────────────────────────────────────────
        plan: `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/>`,
        rocket: `<path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/>`,
        cron: `<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>`,

        // ── Communication ─────────────────────────────────────────
        indexing: `<line x1="21" y1="10" x2="3" y2="10"/><line x1="21" y1="6" x2="3" y2="6"/><line x1="21" y1="14" x2="3" y2="14"/><line x1="21" y1="18" x2="13" y2="18"/>`,
        image: `<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>`,
      };
      return icons[this.name] || icons.info;
    },
  },
  template: `
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" v-html="svgContent">
    </svg>
  `,
};

const app = createApp({
  components: { AppIcon },
  data() {
    return {
      token: localStorage.getItem("mp_client_token") || "",

      challengeToken: "",
      message: "",
      notifications: [],
      notificationsOpen: false,
      sessionExpired: false,
      loadingServices: false,
      serviceStatusMap: {},
      availableServices: [
        { id: "web", name: "Web Server (OpenLiteSpeed)", icon: "website", description: "Serves PHP and static files." },
        { id: "db", name: "Database Server (MariaDB)", icon: "databases", description: "MySQL/MariaDB relational database." },
        { id: "phpmyadmin", name: "phpMyAdmin", icon: "phpmyadmin", description: "Web-based database management." },
        { id: "filebrowser", name: "File Manager", icon: "folder", description: "Web-based file manager interface." },
        { id: "sftp", name: "SFTP Service", icon: "sftp", description: "Secure FTP access." },
        { id: "cron", name: "Cron Daemon", icon: "cron", description: "Scheduled task execution engine." },
      ],
      activePage: pageFromLocation(),
      login: {
        email: "owner@example.mango.test",
        password: "ChangeMe-DevOnly-123!",
        code: "000000",
      },
      home: {
        resources: { disk_used_mb: 0, disk_limit_mb: 0, inodes_used: 0, inodes_limit: 0, cpu: "unknown", memory: "unknown" },
        warnings: [],
        accounts: [],
        websites: [],
      },
      featureStatuses: {},
      websites: [],
      domains: [],
      databases: [],
      databaseUsers: [],
      databaseGrants: [],
      pgDatabases: [],
      pgUsers: [],
      pgGrants: [],
      pgDbWizardStep: 1,
      newPgDbName: "",
      newPgDbUser: "",
      newPgDbPassword: "",
      wizardPgDbId: null,
      wizardPgUserId: null,
      // PHP Config
      phpVersions: ["8.2", "8.3", "8.4"],
      phpSwitching: {},
      editingPhpIniSite: null,
      phpIniForm: {},
      phpIniSaving: false,
      resourceUsage: { range: "30m", windows: ["1m", "5m", "10m", "30m", "2h", "1d", "7d", "30d"], current: {}, samples: [] },
      resourceRange: "30m",
      resourcePoll: null,
      resourceUsageLoading: false,
      analytics: {
        domain: "",
        website_id: null,
        analytics_enabled: true,
        filter: "top-countries",
        filters: [
          { key: "top-countries", label: "Top list" },
          { key: "access-logs", label: "Access logs" },
          { key: "5xx", label: "Error code 5xx" },
          { key: "4xx", label: "Error code 4xx" },
          { key: "total-requests", label: "Total requests" },
          { key: "unique-ips", label: "Unique IP addresses" },
          { key: "bandwidth", label: "Bandwidth" },
        ],
        summary: { total_requests: 0, unique_ip_addresses: 0, bandwidth_bytes: 0, error_4xx: 0, error_5xx: 0 },
        top_countries: [],
        access_logs: [],
        error_4xx_logs: [],
        error_5xx_logs: [],
        top_ips: [],
        top_bandwidth: [],
      },
      activity: [],
      phpInfo: { website: {}, runtime: {}, directives: {}, extensions: [], opcache: {} },
      selectedWebsiteId: "",
      siteSwitcherOpen: false,
      siteSearchQuery: "",
      searchQuery: "",
      userMenuOpen: false,
      dbModal: null,
      newDatabase: { name: "", username: "" },
      newDatabaseUser: { username: "", password: "" },
      newDatabaseGrant: { database_id: "", user_id: "", privileges: "ALL" },
      editingDatabase: null,
      editingDatabaseUser: null,
      editingDatabaseGrant: null,
      // DB Wizard
      dbWizardStep: 1,
      wizardDbName: "",
      wizardDbUser: "",
      wizardDbPass: "",
      dbTab: "databases", // 'databases', 'users', 'grants'
      backupWizard: { isOpen: false, step: 1, isRunning: false, progressText: '' },
      installer: {
        scripts: [],
        selectedScript: null,
        form: {
          website_id: "",
          site_title: "",
          admin_username: "",
          admin_email: "",
          admin_password: "",
          allow_overwrite: false,
        }
      },
      siteWizard: { isOpen: false, step: 1, type: 'blank', domain: '', site_title: 'My Site', admin_username: 'admin', admin_email: '', admin_password: '', allow_overwrite: false, createdWebsite: null, createdDomainNameservers: [], errorMessage: '' },
      connectWizard: { isOpen: false, website: null, method: 'nameservers', checking: false, result: null },
      mailboxes: [],
      mailRouting: {
        mail_domains: [],
        mail_aliases: [],
        mail_forwarders: [],
        mail_autoresponders: [],
        mail_edge_routes: [],
        mail_delivery_logs: [],
      },
      mailDomainEditor: {
        isOpen: false,
        isSaving: false,
        mailDomainId: null,
        dkim_selector: "mango",
        spf_policy: "",
        dmarc_policy: "",
        catch_all_enabled: false,
        catch_all_destination: "",
        status: "active",
        regenerate_dkim: false,
      },
      mailAliasEditor: {
        isOpen: false,
        isSaving: false,
        aliasId: null,
        source_email: "",
        destination_email: "",
        status: "active",
      },
      mailForwarderEditor: {
        isOpen: false,
        isSaving: false,
        forwarderId: null,
        source_email: "",
        destination_email: "",
        status: "active",
      },
      mailAutoresponderEditor: {
        isOpen: false,
        isSaving: false,
        autoresponderId: null,
        mailbox_id: "",
        subject: "Auto-reply",
        body: "",
        enabled: true,
      },
      mailboxWizard: { isOpen: false, mode: "create", step: 1, isCreating: false, createdMailbox: null, mailboxId: null, email: "", quota_mb: 1024, password: "", confirm_password: "", status: "active" },
      mailboxEditor: { isOpen: false, isSaving: false, mailboxId: null, email: "", quota_mb: 1024, status: "active", password: "", confirm_password: "" },
      cronJobs: [],
      newCronJob: { schedule: "*/15 * * * *", command: "" },
      backups: [],
      gitDeployments: [],
      newGitDeployment: { repository_url: "", branch: "main", deploy_path: "" },
      // DNS Zone Editor
      dnsRecords: [],
      dnsZones: [],
      selectedDomainId: "",
      nameserverEditor: { domainId: null, source: "default", values: ["", ""] },
      newDnsRecord: { domain_id: "", type: "A", name: "@", value: "", ttl: 300 },
      // Cache Manager
      cacheStatus: { object_cache: "inactive", opcode_cache: "active", last_purged: null, opcode_cache_backend: "opcache", object_cache_backend: "redis" },
      cachePurging: false,
      // IP Manager
      ipRules: [],
      newIpRule: { ip: "", type: "block" },
      // Hotlink Protection
      hotlink: { enabled: false, allowed_domains: "", saving: false },
      // Fix File Ownership
      fixOwnershipRunning: false,
      fixOwnershipResult: null,
      // Password Protect Dirs
      protectedDirs: [],
      newProtectedDir: { path: "", username: "", password: "" },
      // Redirects
      redirects: [],
      newRedirect: { website_id: "", source_path: "/", target_url: "", type: "301", match_type: "exact" },
      // Disk Usage
      diskUsage: [],
      apiTokens: [],
      newApiTokenName: "",
      newApiTokenRaw: "",
      // FTP Accounts
      ftpAccounts: [],
      newFtpUsername: "",
      newFtpPassword: "",
      newFtpPath: "public_html",
      // 2FA
      customSslCrt: "",
      customSslKey: "",
      resourceHistory: [],
      rawAccessLogs: [],
      imageOptimizeDir: "",
      siteBuilderTemplates: [],
      analyticsStats: null,
      syncJobs: [],
      has2FA: false,
      tfaSetup: { secret: null, uri: "", code: "" },
      tfaDisableCode: "",
      // Account Settings and Themes
      activeTheme: localStorage.getItem("mp_theme") || "Default",
      isChangingPassword: false,
      settingsForm: {
        current_password: "",
        new_password: "",
        confirm_password: "",
      },
    };
  },
  mounted() {
    document.body.classList.add('app-loaded');
    if (!this.token) {
      window.location.href = "/login";
      return;
    }
    this.load();
    window.addEventListener("popstate", () => {
      this.activePage = pageFromLocation();
    });
  },
  unmounted() {
    if (this.resourcePoll) window.clearInterval(this.resourcePoll);
  },
  computed: {
    unreadNotificationsCount() {
      return this.notifications.filter(n => !n.read).length;
    },
    activeToasts() {
      return this.notifications.filter(n => n.toastVisible);
    },
    currentUserEmail() {
      return this.login.email || "client@mangopanel.local";
    },
    userInitial() {
      return (this.currentUserEmail.trim()[0] || "U").toUpperCase();
    },
    selectedWebsite() {
      return this.websites.find((site) => String(site.id) === String(this.selectedWebsiteId)) || this.websites[0] || null;
    },
    selectedWebsiteLabel() {
      return this.selectedWebsiteId && this.selectedWebsite ? this.selectedWebsite.domain : "All sites";
    },
    hasHostingAccount() {
      return Array.isArray(this.home.accounts) && this.home.accounts.length > 0;
    },
    filteredSites() {
      const query = this.siteSearchQuery.trim().toLowerCase();
      if (!query) return this.websites;
      return this.websites.filter((site) => `${site.domain} ${site.status} ${site.document_root}`.toLowerCase().includes(query));
    },
    diskPercent() {
      const used = Number(this.home.resources.disk_used_mb || 0);
      const limit = Number(this.home.resources.disk_limit_mb || 1);
      return Math.min(100, limit > 0 ? (used / limit) * 100 : 0).toFixed(1);
    },
    inodePercent() {
      const used = Number(this.home.resources.inodes_used || 0);
      const limit = Number(this.home.resources.inodes_limit || 1);
      return Math.min(100, limit > 0 ? (used / limit) * 100 : 0).toFixed(1);
    },
    sidebarSections() {
      if (!this.hasHostingAccount) {
        return [
          {
            label: "Domains",
            items: [
              { label: "Domains", target: "domains", icon: "domains", description: "Domains and DNS status." },
              { label: "DNS Zone Editor", target: "dns-zone-editor", icon: "dns", description: "DNS records and zones." },
            ],
          },
        ];
      }
      return [
        {
          label: "Overview",
          items: [
            { label: "Dashboard", target: "dashboard", icon: "dashboard", description: "Resource usage, warnings, and account overview." },
            { label: "Hosting Plan", target: "hosting-plan", icon: "plan", description: "Current plan, limits, and account status." },
            { label: "Performance", target: "performance", icon: "performance", description: "Runtime health for CPU, memory, and cache." },
            { label: "Analytics", target: "analytics", icon: "analytics", description: "Traffic and object counts across your account." },
          ],
        },
        {
          label: "Build & Sites",
          items: [
            { label: "Website", target: "website", icon: "website", description: "Websites, PHP versions, SSL, and actions." },
            { label: "Domains", target: "domains", icon: "domains", description: "Domains and DNS status." },
            { label: "Redirects", target: "redirects", icon: "redirects", description: "Forwarding and redirect rules." },
            { label: "DNS Zone Editor", target: "dns-zone-editor", icon: "dns", description: "DNS records and zones." },
            { label: "Site Builder", target: "site-builder", icon: "site-builder", description: "Template-based website creation." },
            { label: "App Installer", target: "installer", icon: "wordpress", description: "Install WordPress, Joomla, and other apps." },
            { label: "PHP Configuration", target: "php-configuration", icon: "php", description: "PHP version and runtime options." },
            { label: "PHP Info", target: "php-info", icon: "info", description: "PHP runtime information." },
          ],
        },
        {
          label: "Files & Data",
          items: [
            { label: "Files", target: "files", icon: "files", description: "File manager, SFTP, and service access." },
            { label: "Disk Usage", target: "disk-usage", icon: "disk-usage", description: "Storage usage by folder and path." },
            { label: "Databases", target: "databases", icon: "databases", description: "Database names, users, and connection details." },
            { label: "Email", target: "email", icon: "email", description: "Mailboxes, SMTP, and IMAP connection details." },
            { label: "FTP Accounts", target: "ftp-accounts", icon: "ftp", description: "Manage FTP users and access." },
            { label: "Cron Jobs", target: "cron-jobs", icon: "cron", description: "Scheduled command automation." },
            { label: "Backups", target: "backups", icon: "backup", description: "Account backups and restore points." },
            { label: "Git Version Control", target: "git", icon: "git", description: "Repository deployments." },
          ],
        },
        {
          label: "Security",
          items: [
            { label: "Security", target: "security", icon: "security", description: "SSL, warnings, and protection status." },
            { label: "SSL/TLS", target: "ssl-tls", icon: "ssl", description: "Issue and manage certificates." },
            { label: "SSH Access", target: "ssh-access", icon: "terminal", description: "SFTP and shell access details." },
            { label: "IP Blocker", target: "ip-manager", icon: "ip", description: "Allow and block IP access." },
            { label: "API Tokens", target: "api-tokens", icon: "key", description: "Create and revoke API tokens." },
            { label: "ModSecurity", target: "modsecurity", icon: "shield", description: "Request filtering and protection." },
            { label: "Two-Factor Authentication", target: "two-factor-auth", icon: "totp", description: "Extra login protection." },
            { label: "Hotlink Protection", target: "hotlink-protection", icon: "hotlink", description: "Protect media from external embedding." },
            { label: "Directory Privacy", target: "password-protect-directories", icon: "password-protect", description: "Folder access restrictions." },
          ],
        },
        {
          label: "System",
          items: [
            { label: "Cache Manager", target: "cache-manager", icon: "cache", description: "Cache controls for websites." },
            { label: "Folder Index Manager", target: "folder-index-manager", icon: "folder-index", description: "Directory listing controls." },
            { label: "Fix File Ownership", target: "fix-file-ownership", icon: "fix", description: "Repair file ownership and permissions." },
            { label: "Services", target: "services", icon: "services", description: "Manage and restart background services." },
            { label: "Activity Log", target: "activity", icon: "activity", description: "Recent account events." },
          ],
        },
      ];
    },
    activeMenuItem() {
      return this.menuItems.find((item) => item.target === this.activePage) || this.menuItems[0];
    },
    activeFeatureStatus() {
      return this.featureStatus(this.activePage);
    },
    recentSyncJobs() {
      return this.syncJobs.slice(0, 5);
    },
    searchResults() {
      const query = this.searchQuery.trim().toLowerCase();
      if (!query) return [];
      const items = [];
      const add = (type, label, detail, action) => items.push({ type, label, detail, action });

      for (const item of this.menuItems) add("Function", item.label, item.group || "Client panel", () => this.goTo(item.target));
      for (const site of this.websites) add("Site", site.domain, site.status, () => this.goTo("website"));
      for (const domain of this.domains) add("Domain", domain.name, domain.status, () => this.goTo("domains"));
      for (const database of this.databases) add("Database", database.name, database.username, () => this.goTo("databases"));
      for (const user of this.databaseUsers) add("Database user", user.username, user.status, () => this.goTo("databases"));
      for (const item of this.activity) add("Activity", item.action, item.created_at, () => this.goTo("activity"));

      return items
        .filter((item) => `${item.type} ${item.label} ${item.detail || ""}`.toLowerCase().includes(query))
        .slice(0, 8);
    },
    menuItems() {
      return this.sidebarSections.flatMap((section) => section.items);
    },
    activeAdvancedTool() {
      return this.sidebarSections.flatMap((section) => section.items).find((item) => item.target === this.activePage);
    },
    resourceChartPoints() {
      return this.resourceUsage.samples || [];
    },
    latestResourceUsage() {
      return this.resourceUsage.current || {};
    },
    resourceSeries() {
      return [
        { key: "cpu_percent", label: "CPU", color: "#15835f", unit: "%", max: 100 },
        { key: "memory_mb", label: "RAM", color: "#245a97", unit: "MB", max: Math.max(Number(this.latestResourceUsage.memory_limit_mb || 0), ...this.resourceChartPoints.map((point) => Number(point.memory_mb || 0)), 1) },
        { key: "storage_mb", label: "Storage", color: "#a75d12", unit: "MB", max: Math.max(Number(this.latestResourceUsage.storage_limit_mb || 0), ...this.resourceChartPoints.map((point) => Number(point.storage_mb || 0)), 1) },
      ];
    },
    hostingPlanMetrics() {
      const account = this.home.accounts?.[0] || {};
      const resources = this.home.resources || {};
      const latest = this.latestResourceUsage || {};
      const websitesUsed = this.websites.length;
      const bandwidthUsedMb = Number(this.analytics?.summary?.bandwidth_bytes || 0) / (1024 * 1024);
      const bandwidthLimitMb = Number(account.bandwidth_mb || 0);

      const metrics = [
        {
          key: "storage",
          icon: "disk-usage",
          label: "Disk Space",
          used: Number(resources.disk_used_mb || 0),
          limit: Number(resources.disk_limit_mb || account.storage_mb || 0),
          unit: "mb",
        },
        {
          key: "memory",
          icon: "analytics",
          label: "RAM",
          used: Number(latest.memory_mb || 0),
          limit: Number(latest.memory_limit_mb || account.memory_mb || 0),
          unit: "mb",
        },
        {
          key: "cpu",
          icon: "cpu",
          label: "CPU Cores",
          used: Number(latest.cpu_percent || 0),
          limit: Number(account.cpu_limit || 0) * 100,
          unit: "percent",
          value: `${Number(latest.cpu_percent || 0).toFixed(1)}%`,
          metaLimit: `${Number(account.cpu_limit || 0)} cores`,
        },
        {
          key: "inodes",
          icon: "files",
          label: "Inodes",
          used: Number(resources.inodes_used || 0),
          limit: Number(resources.inodes_limit || account.inode_limit || 0),
          unit: "count",
        },
        {
          key: "websites",
          icon: "domains",
          label: "Addons/Websites",
          used: websitesUsed,
          limit: Number(account.max_websites || 0),
          unit: "count",
        },
        {
          key: "processes",
          icon: "performance",
          label: "Max Processes",
          used: null,
          limit: Number(account.max_processes || 0),
          unit: "count",
          metaOverride: "No live usage feed",
        },
        {
          key: "php-workers",
          icon: "server",
          label: "PHP Workers",
          used: null,
          limit: Number(account.php_workers || 0),
          unit: "count",
          metaOverride: "No live usage feed",
        },
        {
          key: "bandwidth",
          icon: "bandwidth",
          label: "Bandwidth",
          used: bandwidthUsedMb,
          limit: bandwidthLimitMb,
          unit: "mb",
          metaOverride: bandwidthLimitMb > 0 ? null : "Unlimited plan",
        },
      ];

      return metrics.map((metric) => {
        const percent = this.planUsagePercent(metric.used, metric.limit);
        const tone = this.planUsageTone(percent);
        const value = metric.value || this.formatPlanMetricValue(metric.used, metric.unit);
        const meta = metric.metaOverride || this.planUsageMeta(metric.used, metric.limit, metric.unit, metric.metaLimit);
        return { ...metric, percent, tone, value, meta };
      });
    },
    // cPanel dashboard icon grid — all features
    cpanelTiles() {
      const tiles = [
        // Files
        { label: "File Manager", target: "files", icon: "files", color: "#f59e0b", group: "Files" },
        { label: "Images", target: "images", icon: "images", color: "#f59e0b", group: "Files" },
        { label: "Directory Privacy", target: "password-protect-directories", icon: "password-protect", color: "#f59e0b", group: "Files" },
        { label: "Disk Usage", target: "disk-usage", icon: "disk-usage", color: "#f59e0b", group: "Files" },
        { label: "FTP Accounts", target: "ftp-accounts", icon: "ftp", color: "#f59e0b", group: "Files" },
        { label: "Git Version Control", target: "git", icon: "git", color: "#f59e0b", group: "Files" },
        { label: "Backups", target: "backups", icon: "backup", color: "#f59e0b", group: "Files" },

        // Databases
        { label: "phpMyAdmin", target: "files", icon: "phpmyadmin", color: "#3b82f6", group: "Databases", action: () => this.launch("phpmyadmin") },
        { label: "MySQL Databases", target: "databases", icon: "databases", color: "#3b82f6", group: "Databases" },
        { label: "MySQL Database Wizard", target: "mysql-database-wizard", icon: "databases-wizard", color: "#3b82f6", group: "Databases" },
        { label: "Remote MySQL", target: "remote-mysql", icon: "remote-mysql", color: "#3b82f6", group: "Databases" },
        { label: "PostgreSQL Databases", target: "postgresql-databases", icon: "postgresql", color: "#3b82f6", group: "Databases" },
        { label: "PostgreSQL Database Wizard", target: "postgresql-database-wizard", icon: "postgresql-wizard", color: "#3b82f6", group: "Databases" },
        { label: "phpPgAdmin", target: "phppgadmin", icon: "phppgadmin", color: "#3b82f6", group: "Databases", action: () => this.launch("phppgadmin") },

        // Domains
        { label: "Site Builder", target: "site-builder", icon: "site-builder", color: "#8b5cf6", group: "Domains" },
        { label: "Domains", target: "domains", icon: "domains", color: "#8b5cf6", group: "Domains" },
        { label: "Redirects", target: "redirects", icon: "redirects", color: "#8b5cf6", group: "Domains" },
        { label: "DNS Zone Editor", target: "dns-zone-editor", icon: "dns", color: "#8b5cf6", group: "Domains" },

        // Email
        { label: "Email", target: "email", icon: "email", color: "#06b6d4", group: "Email" },
        { label: "Webmail", target: "email", icon: "webmail", color: "#0891b2", group: "Email", action: () => this.goTo("email") },

        // Metrics
        { label: "Visitors", target: "visitors", icon: "visitors", color: "#dc2626", group: "Metrics" },
        { label: "Errors", target: "errors", icon: "errors", color: "#dc2626", group: "Metrics" },
        { label: "Bandwidth", target: "bandwidth", icon: "bandwidth", color: "#dc2626", group: "Metrics" },
        { label: "Raw Access", target: "raw-access", icon: "raw-access", color: "#dc2626", group: "Metrics" },
        { label: "Webalizer", target: "webalizer", icon: "webalizer", color: "#dc2626", group: "Metrics" },
        { label: "Resource Usage", target: "resource-usage", icon: "resource-usage", color: "#dc2626", group: "Metrics" },
        { label: "Analytics", target: "analytics", icon: "analytics", color: "#dc2626", group: "Metrics" },
        { label: "Performance", target: "performance", icon: "performance", color: "#dc2626", group: "Metrics" },

        // Security
        { label: "SSH Access", target: "ssh-access", icon: "sftp", color: "#065f46", group: "Security" },
        { label: "IP Blocker", target: "ip-manager", icon: "ip", color: "#065f46", group: "Security" },
        { label: "API Tokens", target: "api-tokens", icon: "key", color: "#065f46", group: "Security" },
        { label: "SSL/TLS", target: "ssl-tls", icon: "ssl", color: "#065f46", group: "Security" },
        { label: "ModSecurity", target: "modsecurity", icon: "shield", color: "#065f46", group: "Security" },
        { label: "Two-Factor Authentication", target: "two-factor-auth", icon: "totp", color: "#065f46", group: "Security" },
        { label: "Hotlink Protection", target: "hotlink-protection", icon: "hotlink", color: "#065f46", group: "Security" },
        { label: "Security", target: "security", icon: "security", color: "#065f46", group: "Security" },

        // Software
        { label: "App Installer", target: "installer", icon: "wordpress", color: "#2563eb", group: "Software" },
        { label: "PHP Configuration", target: "php-configuration", icon: "php", color: "#2563eb", group: "Software" },
        { label: "PHP Info", target: "php-info", icon: "info", color: "#2563eb", group: "Software" },

        // Advanced
        { label: "Cron Jobs", target: "cron-jobs", icon: "cron", color: "#4b5563", group: "Advanced" },
        { label: "Cache Manager", target: "cache-manager", icon: "cache", color: "#4b5563", group: "Advanced" },
        { label: "Folder Index Manager", target: "folder-index-manager", icon: "folder-index", color: "#4b5563", group: "Advanced" },
        { label: "Fix File Ownership", target: "fix-file-ownership", icon: "fix", color: "#4b5563", group: "Advanced" },
        { label: "Services", target: "services", icon: "services", color: "#4b5563", group: "Advanced" },
        { label: "Activity Log", target: "activity", icon: "activity", color: "#4b5563", group: "Advanced" },
      ];
      if (this.hasHostingAccount) return tiles;
      return tiles.filter((tile) => tile.group === "Domains");
    },
    cpanelGroups() {
      const groups = {};
      for (const tile of this.cpanelTiles) {
        if (!groups[tile.group]) groups[tile.group] = [];
        groups[tile.group].push(tile);
      }
      return groups;
    },
    sshInfo() {
      const runtime = this.home.accounts[0]?.runtime || {};
      return {
        host: runtime.sftp_host || window.location.hostname,
        port: runtime.sftp_port || 2222,
        user: runtime.sftp_user || (this.home.accounts[0]?.username || "—"),
        path: this.home.accounts[0]?.base_path || "/home/user",
      };
    },
    selectedDomain() {
      return this.domains.find((d) => String(d.id) === String(this.selectedDomainId)) || null;
    },
    selectedDnsZone() {
      if (!this.selectedDomainId) return null;
      return this.dnsZones.find((zone) => String(zone.domain_id) === String(this.selectedDomainId)) || null;
    },
    filteredDnsRecords() {
      if (!this.selectedDomainId) return this.dnsRecords;
      return this.dnsRecords.filter((r) => String(r.domain_id) === String(this.selectedDomainId));
    },
  },
  methods: {
    openNameserverEditor(domain) {
      const values = domain.nameservers || [];
      this.nameserverEditor = { domainId: domain.id, source: domain.nameserver_source || "default", values: [values[0] || "", values[1] || ""] };
    },
    async saveNameservers() {
      const editor = this.nameserverEditor;
      if (!editor.domainId) return;
      try {
        const payload = await this.api(`/api/client/domains/${editor.domainId}/nameservers`, { method: "POST", body: JSON.stringify({ source: editor.source, nameservers: editor.values }) });
        const index = this.domains.findIndex((domain) => domain.id === editor.domainId);
        if (index >= 0) this.domains[index] = payload.domain;
        this.notify("Nameserver change submitted to the registrar");
        editor.domainId = null;
      } catch (error) { this.notify(error.message, "error"); }
    },
    notify(text, type = "success") {
      if (type === "error" && String(text || "") === "invalid_access_token") {
        return;
      }
      const id = Date.now() + Math.random();
      const n = { id, text, type, read: false, time: new Date().toLocaleTimeString(), toastVisible: true };
      this.notifications.unshift(n);
      if (this.notifications.length > 50) this.notifications.pop();
      setTimeout(() => {
        const idx = this.notifications.findIndex(x => x.id === id);
        if (idx !== -1) this.notifications[idx].toastVisible = false;
      }, 5000);
    },
    markAllNotificationsRead() {
      this.notifications.forEach(n => n.read = true);
    },
    removeToast(id) {
      const idx = this.notifications.findIndex(n => n.id === id);
      if (idx !== -1) this.notifications[idx].toastVisible = false;
    },
    featureStatus(target) {
      const fallback = { status: "functional", label: "Functional" };
      return this.featureStatuses[target] || this.featureStatuses[normalizedClientTarget(target)] || fallback;
    },
    featureStatusClass(target) {
      return `feature-status-${this.featureStatus(target).status || "functional"}`;
    },
    isFeatureDisabled(target) {
      return this.featureStatus(target).status === "disabled";
    },
    jobStatusClass(status) {
      return `job-status-${status || "queued"}`;
    },
    formatJobType(type) {
      return String(type || "").replace(/_/g, " ");
    },
    formatJobDetail(job) {
      if (job.result?.error) return job.result.error;
      if (job.artifact?.path) return job.artifact.path;
      if (job.result?.mode) return job.result.mode;
      return `${job.target_type || "target"} #${job.target_id || "new"}`;
    },
    toggleNotifications() {
      this.notificationsOpen = !this.notificationsOpen;
      if (this.notificationsOpen) this.markAllNotificationsRead();
    },
    clearSessionState() {
      localStorage.removeItem("mp_client_token");
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
      this.challengeToken = "";
      this.userMenuOpen = false;
      this.notificationsOpen = false;
      this.siteSwitcherOpen = false;
      this.sessionExpired = true;
    },
    handleSessionExpired() {
      if (this.sessionExpired) {
        this.clearSessionState();
        window.location.href = "/login";
        return;
      }
      this.clearSessionState();
      window.location.href = "/login";
    },
    async restartService(serviceId) {
      if (!confirm(`Are you sure you want to restart this service? It will cause brief downtime.`)) return;
      this.loadingServices = true;
      try {
        const response = await this.api("/api/client/services/restart", {
          method: "POST",
          body: JSON.stringify({ service: serviceId }),
        });
        if (response.success) {
          appToast("Service restart job queued successfully.", "success");
        } else {
          appToast("Failed to queue restart.", "error");
        }
      } catch (e) {
        appToast(e.message, "error");
      } finally {
        this.loadingServices = false;
      }
    },
    serviceStatusFor(serviceId) {
      return this.serviceStatusMap[serviceId] || { service: serviceId, status: "unknown", health: "unknown", running: false, supported: true };
    },
    serviceStatusClass(serviceId) {
      const service = this.serviceStatusFor(serviceId);
      if (service.status === "running" || service.health === "healthy") return "ok";
      if (service.status === "missing" || service.status === "exited") return "danger";
      if (service.status === "simulated" || service.status === "unknown" || service.status === "docker_unavailable") return "warn";
      return "neutral";
    },
    serviceStatusLabel(serviceId) {
      const service = this.serviceStatusFor(serviceId);
      if (service.status === "running" && service.health === "healthy") return "running";
      if (service.status === "running") return "running";
      if (service.status === "missing") return "missing";
      if (service.status === "docker_unavailable") return "unavailable";
      return service.status || "unknown";
    },
    async rebootStack() {
      if (!confirm("WARNING: This will forcefully restart ALL services and abruptly kill all running processes. Your websites will be completely offline for 10-30 seconds. Are you absolutely sure?")) return;
      this.loadingServices = true;
      try {
        const response = await this.api("/api/client/services/kill-all", {
          method: "POST",
          body: "{}",
        });
        if (response.success) {
          appToast("Stack reboot job queued successfully. The environment will restart momentarily.", "success");
        } else {
          appToast("Failed to queue reboot.", "error");
        }
      } catch (e) {
        appToast(e.message, "error");
      } finally {
        this.loadingServices = false;
      }
    },
    async api(path, options = {}) {
      const headers = { Accept: "application/json", ...(options.headers || {}) };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const body = options.body && typeof options.body !== "string" ? JSON.stringify(options.body) : options.body;
      const response = await fetch(path, { ...options, body, headers });
      const payload = await response.json();
      if (!response.ok) {
        const error = payload.error || "Request failed";
        if (error === "invalid_access_token") {
          this.handleSessionExpired();
        }
        throw new Error(payload.detail ? `${error}: ${payload.detail}` : error);
      }
      return payload;
    },
    async startLogin() {
      this.notify("", "success");
      try {
        const payload = await this.api("/api/client/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: this.login.email, password: this.login.password }),
        });
        this.challengeToken = payload.challenge_token;
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async finishLogin() {
      this.notify("", "success");
      try {
        const payload = await this.api("/api/client/auth/totp/verify", {
          method: "POST",
          body: JSON.stringify({ challenge_token: this.challengeToken, code: this.login.code }),
        });
        this.sessionExpired = false;
        this.token = payload.access_token;
        localStorage.setItem("mp_client_token", this.token);
        this.challengeToken = "";
        await this.load();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async load() {
      try {
        this.featureStatuses = (await this.api("/api/client/feature-status")).features || {};
        this.home = await this.api("/api/client/home");
        this.websites = (await this.api("/api/client/websites")).websites;
        this.domains = (await this.api("/api/client/domains")).domains;
        this.cacheStatus = { ...this.cacheStatus, ...((await this.api("/api/client/cache/status")).cache_status || {}) };
        await this.loadDatabases();
        await this.loadResourceUsage();
        await this.loadAnalytics();
        this.activity = (await this.api("/api/client/activity")).activity;
        await this.loadSyncJobs();
        if (this.activePage === "php-info") {
          await this.loadPhpInfo();
        }
        if (this.activePage === "disk-usage") {
          await this.loadDiskUsage();
        }
        this.mailboxes = (await this.api("/api/client/mailboxes")).mailboxes || [];
        await this.loadMailRouting();
        this.cronJobs = (await this.api("/api/client/cron-jobs")).cron_jobs || [];
        this.backups = (await this.api("/api/client/backups")).backups || [];
        this.gitDeployments = (await this.api("/api/client/git-deployments")).git_deployments || [];
        this.ipRules = (await this.api("/api/client/ip-rules")).ip_rules || [];
        this.protectedDirs = (await this.api("/api/client/protected-directories")).protected_dirs || [];
        this.redirects = (await this.api("/api/client/redirects")).redirects || [];
        this.apiTokens = (await this.api("/api/client/api-tokens")).api_tokens || [];
        this.ftpAccounts = (await this.api("/api/client/ftp-accounts")).ftp_accounts || [];
        const hotlinkPayload = await this.api("/api/client/hotlink-protection");
        this.hotlink = { ...this.hotlink, ...(hotlinkPayload.hotlink || {}) };
        this.has2FA = this.home.has_2fa || false;
        await this.loadInstallerScripts();
        if (this.activePage === "services") {
          await this.loadServicesStatus();
        }
        if (this.selectedWebsiteId && !this.websites.some((site) => String(site.id) === String(this.selectedWebsiteId))) {
          this.selectedWebsiteId = "";
        }
        if (!this.hasHostingAccount && !["dashboard", "domains", "dns-zone-editor"].includes(this.activePage)) {
          this.activePage = "domains";
        }
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async applyDatabasePayload(payload) {
      this.databases = payload.databases || [];
      this.databaseUsers = payload.database_users || [];
      this.databaseGrants = payload.database_grants || [];
      try {
        const pgPayload = await this.api("/api/client/pg-databases");
        this.pgDatabases = pgPayload.pg_databases || [];
        this.pgUsers = pgPayload.pg_users || [];
        this.pgGrants = pgPayload.pg_grants || [];
      } catch (e) {}
    },
    async loadDatabases() {
      this.applyDatabasePayload(await this.api("/api/client/databases"));
    },
    async loadHome() {
      await this.loadDatabases();
    },
    async loadSyncJobs() {
      if (!this.token) return;
      try {
        this.syncJobs = (await this.api("/api/client/sync-jobs")).jobs || [];
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async loadServicesStatus() {
      try {
        const payload = await this.api("/api/client/services/status");
        const services = payload.services || [];
        this.serviceStatusMap = services.reduce((acc, service) => {
          acc[service.service] = service;
          return acc;
        }, {});
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async loadInstallerScripts() {
      try {
        const payload = await this.api("/api/client/installer/scripts");
        this.installer.scripts = payload.scripts || [];
      } catch (err) {
        console.error("Failed to load scripts:", err);
      }
    },
    async loadMailRouting() {
      try {
        const payload = await this.api("/api/client/mail-routing");
        this.mailRouting = {
          mail_domains: payload.mail_domains || [],
          mail_aliases: payload.mail_aliases || [],
          mail_forwarders: payload.mail_forwarders || [],
          mail_autoresponders: payload.mail_autoresponders || [],
          mail_edge_routes: payload.mail_edge_routes || [],
          mail_delivery_logs: payload.mail_delivery_logs || [],
        };
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    normalizeMailAddress(value) {
      return String(value || "").trim().toLowerCase();
    },
    mailAuthPillClass(status) {
      const value = String(status || "").toLowerCase();
      if (value === "ok") return "ok";
      if (value === "warning") return "warning";
      if (value === "missing") return "danger";
      return "active";
    },
    mailRuleStatusClass(status) {
      const value = String(status || "").toLowerCase();
      return value === "active" ? "active" : "danger";
    },
    mailEdgeRouteForDomain(domain) {
      return (this.mailRouting.mail_edge_routes || []).find((route) => (
        String(route.mail_domain_id) === String(domain.mail_domain_id)
        || String(route.domain_id) === String(domain.domain_id)
        || String(route.domain) === String(domain.name)
      )) || null;
    },
    openMailDomainEditor(domain) {
      this.mailDomainEditor = {
        isOpen: true,
        isSaving: false,
        mailDomainId: domain.mail_domain_id,
        dkim_selector: domain.dkim_selector || "mango",
        spf_policy: domain.spf_policy || "",
        dmarc_policy: domain.dmarc_policy || "",
        catch_all_enabled: Boolean(domain.catch_all_enabled),
        catch_all_destination: domain.catch_all_destination || "",
        status: domain.mail_status || "active",
        regenerate_dkim: false,
      };
    },
    closeMailDomainEditor() {
      if (this.mailDomainEditor.isSaving) return;
      this.mailDomainEditor.isOpen = false;
    },
    async saveMailDomainEditor() {
      if (this.mailDomainEditor.isSaving) return;
      try {
        this.mailDomainEditor.isSaving = true;
        await this.api(`/api/client/mail-domains/${this.mailDomainEditor.mailDomainId}`, {
          method: "PATCH",
          body: JSON.stringify({
            dkim_selector: this.mailDomainEditor.dkim_selector,
            spf_policy: this.mailDomainEditor.spf_policy,
            dmarc_policy: this.mailDomainEditor.dmarc_policy,
            catch_all_enabled: this.mailDomainEditor.catch_all_enabled,
            catch_all_destination: this.mailDomainEditor.catch_all_destination,
            status: this.mailDomainEditor.status,
            regenerate_dkim: this.mailDomainEditor.regenerate_dkim,
          }),
        });
        this.mailDomainEditor.isSaving = false;
        this.mailDomainEditor.isOpen = false;
        await this.loadMailRouting();
        this.notify("Mail domain updated", "success");
      } catch (error) {
        this.mailDomainEditor.isSaving = false;
        this.notify(error.message, "error");
      }
    },
    async rotateMailDomainDkim(domain) {
      try {
        await this.api(`/api/client/mail-domains/${domain.mail_domain_id}/dkim/rotate`, { method: "POST" });
        await this.loadMailRouting();
        this.notify(`DKIM rotated for ${domain.name}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    openMailAliasEditor(alias = null) {
      this.mailAliasEditor = {
        isOpen: true,
        isSaving: false,
        aliasId: alias?.id || null,
        source_email: alias?.source_email || "",
        destination_email: alias?.destination_email || "",
        status: alias?.status || "active",
      };
    },
    closeMailAliasEditor() {
      if (this.mailAliasEditor.isSaving) return;
      this.mailAliasEditor.isOpen = false;
    },
    async saveMailAliasEditor() {
      if (this.mailAliasEditor.isSaving) return;
      const payload = {
        source_email: this.normalizeMailAddress(this.mailAliasEditor.source_email),
        destination_email: this.normalizeMailAddress(this.mailAliasEditor.destination_email),
        status: this.mailAliasEditor.status,
      };
      try {
        this.mailAliasEditor.isSaving = true;
        if (this.mailAliasEditor.aliasId) {
          await this.api(`/api/client/mail-aliases/${this.mailAliasEditor.aliasId}`, {
            method: "PATCH",
            body: JSON.stringify(payload),
          });
        } else {
          await this.api("/api/client/mail-aliases", {
            method: "POST",
            body: JSON.stringify(payload),
          });
        }
        this.mailAliasEditor.isSaving = false;
        this.mailAliasEditor.isOpen = false;
        await this.loadMailRouting();
        this.notify("Mail alias saved", "success");
      } catch (error) {
        this.mailAliasEditor.isSaving = false;
        this.notify(error.message, "error");
      }
    },
    async deleteMailAlias(alias) {
      if (!window.confirm(`Delete mail alias ${alias.source_email}?`)) return;
      try {
        await this.api(`/api/client/mail-aliases/${alias.id}`, { method: "DELETE" });
        await this.loadMailRouting();
        this.notify("Mail alias deleted", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    openMailForwarderEditor(forwarder = null) {
      this.mailForwarderEditor = {
        isOpen: true,
        isSaving: false,
        forwarderId: forwarder?.id || null,
        source_email: forwarder?.source_email || "",
        destination_email: forwarder?.destination_email || "",
        status: forwarder?.status || "active",
      };
    },
    closeMailForwarderEditor() {
      if (this.mailForwarderEditor.isSaving) return;
      this.mailForwarderEditor.isOpen = false;
    },
    async saveMailForwarderEditor() {
      if (this.mailForwarderEditor.isSaving) return;
      const payload = {
        source_email: this.normalizeMailAddress(this.mailForwarderEditor.source_email),
        destination_email: this.normalizeMailAddress(this.mailForwarderEditor.destination_email),
        status: this.mailForwarderEditor.status,
      };
      try {
        this.mailForwarderEditor.isSaving = true;
        if (this.mailForwarderEditor.forwarderId) {
          await this.api(`/api/client/mail-forwarders/${this.mailForwarderEditor.forwarderId}`, {
            method: "PATCH",
            body: JSON.stringify(payload),
          });
        } else {
          await this.api("/api/client/mail-forwarders", {
            method: "POST",
            body: JSON.stringify(payload),
          });
        }
        this.mailForwarderEditor.isSaving = false;
        this.mailForwarderEditor.isOpen = false;
        await this.loadMailRouting();
        this.notify("Mail forwarder saved", "success");
      } catch (error) {
        this.mailForwarderEditor.isSaving = false;
        this.notify(error.message, "error");
      }
    },
    async deleteMailForwarder(forwarder) {
      if (!window.confirm(`Delete mail forwarder ${forwarder.source_email}?`)) return;
      try {
        await this.api(`/api/client/mail-forwarders/${forwarder.id}`, { method: "DELETE" });
        await this.loadMailRouting();
        this.notify("Mail forwarder deleted", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    openMailAutoresponderEditor(autoresponder = null) {
      this.mailAutoresponderEditor = {
        isOpen: true,
        isSaving: false,
        autoresponderId: autoresponder?.id || null,
        mailbox_id: autoresponder?.mailbox_id || "",
        subject: autoresponder?.subject || "Auto-reply",
        body: autoresponder?.body || "",
        enabled: autoresponder ? Boolean(autoresponder.enabled) : true,
      };
    },
    closeMailAutoresponderEditor() {
      if (this.mailAutoresponderEditor.isSaving) return;
      this.mailAutoresponderEditor.isOpen = false;
    },
    async saveMailAutoresponderEditor() {
      if (this.mailAutoresponderEditor.isSaving) return;
      const payload = {
        mailbox_id: Number(this.mailAutoresponderEditor.mailbox_id),
        subject: String(this.mailAutoresponderEditor.subject || "").trim() || "Auto-reply",
        body: String(this.mailAutoresponderEditor.body || "").trim(),
        enabled: Boolean(this.mailAutoresponderEditor.enabled),
      };
      try {
        this.mailAutoresponderEditor.isSaving = true;
        if (this.mailAutoresponderEditor.autoresponderId) {
          await this.api(`/api/client/mail-autoresponders/${this.mailAutoresponderEditor.autoresponderId}`, {
            method: "PATCH",
            body: JSON.stringify(payload),
          });
        } else {
          await this.api("/api/client/mail-autoresponders", {
            method: "POST",
            body: JSON.stringify(payload),
          });
        }
        this.mailAutoresponderEditor.isSaving = false;
        this.mailAutoresponderEditor.isOpen = false;
        await this.loadMailRouting();
        this.notify("Autoresponder saved", "success");
      } catch (error) {
        this.mailAutoresponderEditor.isSaving = false;
        this.notify(error.message, "error");
      }
    },
    async deleteMailAutoresponder(autoresponder) {
      if (!window.confirm(`Delete autoresponder for ${autoresponder.mailbox_email}?`)) return;
      try {
        await this.api(`/api/client/mail-autoresponders/${autoresponder.id}`, { method: "DELETE" });
        await this.loadMailRouting();
        this.notify("Autoresponder deleted", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },

    async loadSiteBuilderTemplates() {
      try {
        const res = await this.api("/api/client/site-builder/templates");
        this.siteBuilderTemplates = res.templates || [];
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async installSiteBuilder(templateId) {
      if (!this.siteBuilderDomain) {
        this.notify("Please select a domain first.", "error");
        return;
      }
      try {
        const payload = await this.api("/api/client/site-builder/install", { method: "POST", body: { domain: this.siteBuilderDomain, template_id: templateId } });
        this.notify(`Site Builder synced in development mode (job #${payload.job_id})`, "success");
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async optimizeImages() {
      if (!this.imagesPath) {
        this.notify("Please enter a path to optimize.", "error");
        return;
      }
      try {
        const payload = await this.api("/api/client/images/optimize", { method: "POST", body: { path: this.imagesPath } });
        this.notify(`Image optimization synced in development mode (job #${payload.job_id})`, "success");
        this.imagesPath = "";
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async toggleModSecurity(site) {
      try {
        const newVal = site.modsec_enabled ? 0 : 1;
        await this.api(`/api/client/websites/${site.id}/modsec`, { method: "POST", body: { enabled: !!newVal } });
        site.modsec_enabled = newVal;
        this.notify(`ModSecurity ${newVal ? 'enabled' : 'disabled'} for ${site.domain}`, "success");
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async loadRemoteMysqlHosts() {
      try {
        const res = await this.api("/api/client/remote-mysql");
        this.remoteMysqlHosts = res.remote_mysql_hosts || [];
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async addRemoteMysqlHost() {
      if (!this.newRemoteHost) return;
      try {
        await this.api("/api/client/remote-mysql", { method: "POST", body: { host_ip: this.newRemoteHost } });
        this.notify("Remote MySQL host added.", "success");
        this.newRemoteHost = "";
        this.loadRemoteMysqlHosts();
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async deleteRemoteMysqlHost(id) {
      try {
        await this.api(`/api/client/remote-mysql/${id}`, { method: "DELETE" });
        this.notify("Remote MySQL host removed.", "success");
        this.loadRemoteMysqlHosts();
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async downloadRawLogs(domain) {
      try {
        const res = await this.api(`/api/client/logs/raw?domain=${domain}`);
        if (res.download_url) {
          window.open(res.download_url, "_blank", "noopener,noreferrer");
        }
      } catch (e) {
        this.notify(e.message, "error");
      }
    },

    async loadResourceUsage() {
      if (!this.token) return;
      this.resourceUsageLoading = true;
      try {
        this.resourceUsage = await this.api(`/api/client/resource-usage?range=${encodeURIComponent(this.resourceRange)}`);
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        this.resourceUsageLoading = false;
      }
    },
    async refreshResourceUsage() {
      await this.loadResourceUsage();
    },
    async loadPhpInfo() {
      if (!this.token) return;
      try {
        const siteId = this.selectedWebsite?.id || "";
        this.phpInfo = await this.api(`/api/client/php-info?website_id=${encodeURIComponent(siteId)}`);
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async changeResourceRange(range) {
      this.resourceRange = range;
      await this.loadResourceUsage();
    },
    async loadAnalytics() {
      if (!this.token) return;
      try {
        const siteId = this.selectedWebsite?.id || "";
        this.analytics = await this.api(`/api/client/analytics?website_id=${encodeURIComponent(siteId)}&filter=${encodeURIComponent(this.analytics.filter)}`);
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async toggleAnalyticsTracking(site) {
      if (!site) return;
      site.savingAnalytics = true;
      const nextValue = Number(site.analytics_enabled) ? 0 : 1;
      const previousValue = Number(site.analytics_enabled) ? 1 : 0;
      site.analytics_enabled = nextValue;
      if (this.selectedWebsite && String(this.selectedWebsite.id) === String(site.id)) {
        this.analytics.analytics_enabled = !!nextValue;
      }
      try {
        const payload = await this.api(`/api/client/websites/${site.id}`, {
          method: "PATCH",
          body: JSON.stringify({ analytics_enabled: nextValue }),
        });
        const idx = this.websites.findIndex((item) => String(item.id) === String(site.id));
        if (idx !== -1) {
          this.websites[idx] = { ...this.websites[idx], ...payload.website };
        }
        this.analytics.analytics_enabled = !!payload.website.analytics_enabled;
        if (this.activePage === "analytics") {
          await this.loadAnalytics();
        }
        this.notify(`Analytics tracking ${payload.website.analytics_enabled ? "enabled" : "paused"} for ${site.domain}`, "success");
      } catch (error) {
        site.analytics_enabled = previousValue;
        if (this.selectedWebsite && String(this.selectedWebsite.id) === String(site.id)) {
          this.analytics.analytics_enabled = !!previousValue;
        }
        this.notify(error.message, "error");
      } finally {
        site.savingAnalytics = false;
      }
    },
    async changeAnalyticsFilter(filter) {
      this.analytics.filter = filter;
      await this.loadAnalytics();
    },
    async loadDnsRecords() {
      if (!this.token) return;
      try {
        const qs = this.selectedDomainId ? `?domain_id=${encodeURIComponent(this.selectedDomainId)}` : "";
        const payload = await this.api(`/api/client/dns-records${qs}`);
        this.dnsRecords = payload.dns_records || [];
        this.dnsZones = payload.dns_zones || [];
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async createDnsRecord() {
      if (!this.newDnsRecord.domain_id || !this.newDnsRecord.value) {
        this.notify("Please select a domain and enter a value.", "error");
        return;
      }
      try {
        const payload = await this.api("/api/client/dns-records", {
          method: "POST",
          body: JSON.stringify(this.newDnsRecord),
        });
        this.dnsRecords = payload.dns_records || this.dnsRecords;
        this.dnsZones = payload.dns_zones || this.dnsZones;
        this.notify(`DNS record synced in development mode (job #${payload.job_id})`, "success");
        this.newDnsRecord = { domain_id: this.newDnsRecord.domain_id, type: "A", name: "@", value: "", ttl: 300 };
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteDnsRecord(record) {
      if (!window.confirm(`Delete ${record.type} record "${record.name}"?`)) return;
      try {
        const payload = await this.api(`/api/client/dns-records/${record.id}`, { method: "DELETE" });
        this.dnsRecords = payload.dns_records || this.dnsRecords.filter((r) => r.id !== record.id);
        this.dnsZones = payload.dns_zones || this.dnsZones;
        this.notify(`DNS record removed from development zone (job #${payload.job_id})`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    dnsRecordLocked(record) {
      return Boolean(record.locked || record.system_record || (record.type === "NS" && record.name === "@") || record.type === "SOA");
    },
    async rebuildDnsZone() {
      if (!this.selectedDomainId) return;
      try {
        const payload = await this.api(`/api/client/domains/${this.selectedDomainId}/dns/rebuild`, { method: "POST", body: "{}" });
        this.notify(`DNS rebuild queued (job #${payload.job_id})`, "success");
        this.domains = (await this.api("/api/client/domains")).domains;
        await this.loadDnsRecords();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async verifyDnsZone() {
      if (!this.selectedDomainId) return;
      try {
        const payload = await this.api(`/api/client/domains/${this.selectedDomainId}/dns/verify-nameservers`, { method: "POST", body: "{}" });
        this.notify(payload.verification.message, payload.verification.status === "active" ? "success" : "error");
        this.domains = (await this.api("/api/client/domains")).domains;
        await this.loadDnsRecords();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async exportDnsZone() {
      if (!this.selectedDomainId) return;
      try {
        const payload = await this.api(`/api/client/domains/${this.selectedDomainId}/dns/export`);
        this.notify(`${payload.dns_zone_export.domain.name} DNS zone export saved`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // PHP Switcher
    async switchPhpVersion(site, version) {
      if (site.php_version === version) return;
      this.phpSwitching = { ...this.phpSwitching, [site.id]: true };
      try {
        const payload = await this.api(`/api/client/websites/${site.id}`, {
          method: "PATCH",
          body: JSON.stringify({ php_version: version }),
        });
        const idx = this.websites.findIndex((s) => s.id === site.id);
        if (idx !== -1) this.websites[idx] = { ...this.websites[idx], ...payload.website };
        this.notify(`PHP version updated to ${version} for ${site.domain}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        const s = { ...this.phpSwitching };
        delete s[site.id];
        this.phpSwitching = s;
      }
    },
    // Cache Manager
    async purgeCache(websiteId) {
      this.cachePurging = true;
      try {
        const payload = await this.api("/api/client/cache/purge", {
          method: "POST",
          body: JSON.stringify(websiteId ? { website_id: websiteId } : {}),
        });
        this.notify(`Cache purge queued (job #${payload.job_id})`, "success");
        this.cacheStatus = { ...this.cacheStatus, last_purged: new Date().toLocaleString() };
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        this.cachePurging = false;
      }
    },
    async resetOpcodeCache(websiteId) {
      this.cachePurging = true;
      try {
        const payload = await this.api("/api/client/cache/opcache/reset", {
          method: "POST",
          body: JSON.stringify(websiteId ? { website_id: websiteId } : {}),
        });
        this.notify(`OPcache reset queued (job #${payload.job_id})`, "success");
        this.cacheStatus = { ...this.cacheStatus, last_purged: new Date().toLocaleString() };
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        this.cachePurging = false;
      }
    },
    async flushObjectCache(websiteId) {
      this.cachePurging = true;
      try {
        const payload = await this.api("/api/client/cache/object-cache/flush", {
          method: "POST",
          body: JSON.stringify(websiteId ? { website_id: websiteId } : {}),
        });
        this.notify(`Object cache flush queued (job #${payload.job_id})`, "success");
        this.cacheStatus = { ...this.cacheStatus, last_purged: new Date().toLocaleString() };
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        this.cachePurging = false;
      }
    },
    // IP Manager
    async createIpRule() {
      if (!this.newIpRule.ip) return;
      try {
        const rule = await this.api("/api/client/ip-rules", {
          method: "POST",
          body: JSON.stringify(this.newIpRule),
        });
        this.ipRules = [...this.ipRules, rule];
        this.notify(`IP rule added: ${rule.type} ${rule.ip}`, "success");
        this.newIpRule = { ip: "", type: "block" };
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteIpRule(rule) {
      if (!window.confirm(`Remove IP rule for ${rule.ip}?`)) return;
      try {
        await this.api(`/api/client/ip-rules/${rule.id}`, { method: "DELETE" });
        this.ipRules = this.ipRules.filter((r) => r.id !== rule.id);
        this.notify(`IP rule removed: ${rule.ip}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // Hotlink Protection
    async saveHotlinkProtection() {
      this.hotlink.saving = true;
      try {
        const payload = await this.api("/api/client/hotlink-protection", {
          method: "POST",
          body: JSON.stringify({ enabled: this.hotlink.enabled, allowed_domains: this.hotlink.allowed_domains }),
        });
        this.hotlink = { ...this.hotlink, ...(payload.hotlink || {}) };
        this.notify(`Hotlink protection synced in development mode (job #${payload.job_id})`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        this.hotlink.saving = false;
      }
    },
    // Fix File Ownership
    async fixFileOwnership() {
      if (!window.confirm("Run fix file ownership? This will reset ownership on all account files.")) return;
      this.fixOwnershipRunning = true;
      this.fixOwnershipResult = null;
      try {
        const payload = await this.api("/api/client/fix-ownership", { method: "POST", body: "{}" });
        this.fixOwnershipResult = { success: true, message: `Job queued (#${payload.job_id}). File ownership repair is running in the background.` };
        this.notify("Fix file ownership job queued", "success");
      } catch (error) {
        this.fixOwnershipResult = { success: false, message: error.message };
        this.notify(error.message, "error");
      } finally {
        this.fixOwnershipRunning = false;
      }
    },
    // Password Protect Directories
    async addProtectedDir() {
      if (!this.newProtectedDir.path || !this.newProtectedDir.username || !this.newProtectedDir.password) {
        this.notify("Please fill all fields.", "error");
        return;
      }
      try {
        const payload = await this.api("/api/client/protected-directories", {
          method: "POST",
          body: JSON.stringify(this.newProtectedDir),
        });
        this.protectedDirs = [...this.protectedDirs, { ...this.newProtectedDir, id: payload.id }];
        this.newProtectedDir = { path: "", username: "", password: "" };
        this.notify(`Directory protection added for ${payload.path}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async removeProtectedDir(dir) {
      if (!window.confirm(`Remove protection from ${dir.path}?`)) return;
      try {
        await this.api(`/api/client/protected-directories/${dir.id}`, { method: "DELETE" });
        this.protectedDirs = this.protectedDirs.filter((d) => d.id !== dir.id);
        this.notify(`Directory protection removed from ${dir.path}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // Redirects
    async addRedirect() {
      try {
        const payload = await this.api("/api/client/redirects", {
          method: "POST",
          body: JSON.stringify(this.newRedirect),
        });
        const domain = this.websites.find(w => w.id === this.newRedirect.website_id)?.domain;
        this.redirects = [...this.redirects, { ...this.newRedirect, id: payload.id, domain: domain }];
        this.newRedirect = { website_id: "", source_path: "/", target_url: "", type: "301", match_type: "exact" };
        this.notify(`Redirect created successfully.`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteRedirect(id) {
      if (!window.confirm(`Delete this redirect?`)) return;
      try {
        await this.api(`/api/client/redirects/${id}`, { method: "DELETE" });
        this.redirects = this.redirects.filter((r) => r.id !== id);
        this.notify(`Redirect deleted.`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // Disk Usage
    async loadDiskUsage() {
      try {
        const payload = await this.api("/api/client/disk-usage");
        this.diskUsage = payload.usage || [];
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // Folder Index Manager
    async toggleFolderIndex(site) {
      site.savingIndex = true;
      try {
        const payload = await this.api(`/api/client/websites/${site.id}`, {
          method: "PATCH",
          body: JSON.stringify({ index_enabled: site.index_enabled ? 0 : 1 }),
        });
        const idx = this.websites.findIndex((s) => s.id === site.id);
        if (idx !== -1) {
          this.websites[idx] = { ...this.websites[idx], ...payload.website };
        }
        this.notify(`Directory listing ${payload.website.index_enabled ? "enabled" : "disabled"} for ${site.domain}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        site.savingIndex = false;
      }
    },
    // ModSecurity
    async toggleModSec(site) {
      site.savingModsec = true;
      try {
        const current = site.modsec_enabled === undefined ? 1 : site.modsec_enabled;
        const payload = await this.api(`/api/client/websites/${site.id}`, {
          method: "PATCH",
          body: JSON.stringify({ modsec_enabled: current ? 0 : 1 }),
        });
        const idx = this.websites.findIndex((s) => s.id === site.id);
        if (idx !== -1) {
          this.websites[idx] = { ...this.websites[idx], ...payload.website };
        }
        this.notify(`ModSecurity ${payload.website.modsec_enabled ? "enabled" : "disabled"} for ${site.domain}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        site.savingModsec = false;
      }
    },
    // API Tokens
    async createApiToken() {
      try {
        const payload = await this.api("/api/client/api-tokens", {
          method: "POST",
          body: JSON.stringify({ name: this.newApiTokenName }),
        });
        this.apiTokens = [{ id: payload.id, name: payload.name, created_at: new Date().toISOString() }, ...this.apiTokens];
        this.newApiTokenName = "";
        this.newApiTokenRaw = payload.token;
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteApiToken(id) {
      if (!window.confirm("Revoke this token? It will stop working immediately.")) return;
      try {
        await this.api(`/api/client/api-tokens/${id}`, { method: "DELETE" });
        this.apiTokens = this.apiTokens.filter((t) => t.id !== id);
        this.notify("API token revoked.", "success");
        this.newApiTokenRaw = "";
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // FTP Accounts
    async createFtpAccount() {
      try {
        const payload = await this.api("/api/client/ftp-accounts", {
          method: "POST",
          body: JSON.stringify({
            username: this.newFtpUsername,
            password: this.newFtpPassword,
            path: this.newFtpPath
          })
        });
        this.ftpAccounts.push(payload.ftp_account);
        this.newFtpUsername = "";
        this.newFtpPassword = "";
        this.newFtpPath = "public_html";
        this.notify("FTP Account created. Please wait up to a minute for it to sync.", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    openPhpIniModal(site) {
      let phpIni = {};
      if (site.php_ini) {
        try {
          phpIni = typeof site.php_ini === "string" ? JSON.parse(site.php_ini) : site.php_ini;
        } catch (error) {
          phpIni = {};
        }
      }
      this.editingPhpIniSite = site;
      this.phpIniForm = {
        memory_limit: phpIni.memory_limit || "",
        max_execution_time: phpIni.max_execution_time || "",
        upload_max_filesize: phpIni.upload_max_filesize || "",
        post_max_size: phpIni.post_max_size || "",
        max_input_vars: phpIni.max_input_vars || "",
        custom: phpIni.custom || "",
      };
    },
    async savePhpIni() {
      if (!this.editingPhpIniSite) return;
      this.phpIniSaving = true;
      try {
        const payload = await this.api(`/api/client/websites/${this.editingPhpIniSite.id}`, {
          method: "PATCH",
          body: JSON.stringify({ php_ini: this.phpIniForm }),
        });
        const idx = this.websites.findIndex((site) => site.id === this.editingPhpIniSite.id);
        if (idx !== -1) {
          this.websites[idx] = { ...this.websites[idx], ...payload.website };
        }
        this.editingPhpIniSite = null;
        this.notify(`PHP INI updated for ${payload.website.domain}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      } finally {
        this.phpIniSaving = false;
      }
    },
    async deleteFtpAccount(id) {
      if (!window.confirm("Delete this FTP account?")) return;
      try {
        await this.api(`/api/client/ftp-accounts/${id}`, { method: "DELETE" });
        this.ftpAccounts = this.ftpAccounts.filter((f) => f.id !== id);
        this.notify("FTP account deleted. Allow up to a minute for changes to take effect.", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // 2FA
    async loadSiteBuilderTemplates() {
      try {
        const res = await this.api("/api/client/site-builder/templates");
        this.siteBuilderTemplates = res.templates || [];
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    async installCustomSsl() {
      if (!this.selectedWebsiteId) {
        this.notify("Please select a website first.", "error");
        return;
      }
      try {
        await this.api("/api/client/ssl/custom", {
          method: "POST",
          body: JSON.stringify({
            website_id: this.selectedWebsiteId,
            crt: this.customSslCrt,
            key: this.customSslKey
          })
        });
        this.notify("Custom SSL Certificate installed successfully. Web server is reloading.", "success");
        this.customSslCrt = "";
        this.customSslKey = "";
      } catch (error) {
        this.notify(error.message, "error");
      }
    },

    async loadResourceHistory() {
      try {
        const res = await this.api(`/api/client/resource-usage/history`);
        this.resourceHistory = res.history || [];
      } catch (e) {
        this.notify(e.message, "error");
      }
    },

    async loadRawLogs() {
      if (!this.selectedWebsiteId) {
        this.notify("Please select a website first.", "error");
        return;
      }
      try {
        const res = await this.api(`/api/client/logs/raw?website_id=${this.selectedWebsiteId}`);
        this.rawAccessLogs = res.files || [];
      } catch (e) {
        this.notify(e.message, "error");
      }
    },
    downloadRawLog(filename) {
      if (!this.selectedWebsiteId) return;
      window.location.href = `/api/client/logs/download?website_id=${this.selectedWebsiteId}&file=${encodeURIComponent(filename)}`;
    },

    async optimizeImages() {
      if (!this.selectedWebsiteId) {
        this.notify("Please select a website first.", "error");
        return;
      }
      try {
        const payload = await this.api("/api/client/images/optimize", {
          method: "POST",
          body: JSON.stringify({ website_id: this.selectedWebsiteId, directory: this.imageOptimizeDir })
        });
        this.notify(`Image optimization synced in development mode (job #${payload.job_id})`, "success");
        this.imageOptimizeDir = "";
      } catch (error) {
        this.notify(error.message, "error");
      }
    },

    async installSiteTemplate(templateId) {
      if (!this.selectedWebsiteId) {
        this.notify("Please select a website first.", "error");
        return;
      }
      if (!window.confirm("WARNING: Installing a template will extract files into your website directory, potentially overwriting existing files. Continue?")) return;
      try {
        await this.api("/api/client/site-builder/install", {
          method: "POST",
          body: JSON.stringify({ website_id: this.selectedWebsiteId, template_id: templateId })
        });
        this.notify("Template installed successfully. Allow up to a minute for changes to take effect.", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },

    async generate2FA() {
      try {
        const payload = await this.api("/api/client/2fa/generate", { method: "POST" });
        this.tfaSetup.secret = payload.secret;
        this.tfaSetup.uri = payload.uri;
        this.tfaSetup.code = "";
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async enable2FA() {
      try {
        await this.api("/api/client/2fa/enable", {
          method: "POST",
          body: JSON.stringify({ secret: this.tfaSetup.secret, code: this.tfaSetup.code })
        });
        this.has2FA = true;
        this.tfaSetup = { secret: null, uri: "", code: "" };
        this.notify("Two-Factor Authentication enabled successfully.", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async disable2FA() {
      if (!window.confirm("Are you sure you want to disable 2FA? This will reduce the security of your account.")) return;
      try {
        await this.api("/api/client/2fa/disable", {
          method: "POST",
          body: JSON.stringify({ code: this.tfaDisableCode })
        });
        this.has2FA = false;
        this.tfaDisableCode = "";
        this.notify("Two-Factor Authentication has been disabled.", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    resourcePath(key, maxValue) {
      const points = this.resourceChartPoints;
      if (!points.length) return "";
      const width = 720;
      const height = 220;
      const max = Math.max(Number(maxValue || 1), 1);
      return points
        .map((point, index) => {
          const x = points.length === 1 ? width : (index / (points.length - 1)) * width;
          const value = Math.max(0, Math.min(max, Number(point[key] || 0)));
          const y = height - (value / max) * height;
          return `${index === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`;
        })
        .join(" ");
    },
    resourceFillPath(key, maxValue) {
      const line = this.resourcePath(key, maxValue);
      if (!line || !this.resourceChartPoints.length) return "";
      return `${line} L 720 220 L 0 220 Z`;
    },
    formatResource(value, unit) {
      const number = Number(value || 0);
      if (unit === "%") return `${number.toFixed(1)}%`;
      if (number >= 1024) return `${(number / 1024).toFixed(2)} GB`;
      return `${number.toFixed(1)} MB`;
    },
    planUsagePercent(used, limit) {
      const usedNumber = Number(used);
      const limitNumber = Number(limit);
      if (!Number.isFinite(usedNumber) || !Number.isFinite(limitNumber) || limitNumber <= 0) return null;
      return Math.max(0, Math.min(100, (usedNumber / limitNumber) * 100));
    },
    planUsageTone(percent) {
      if (percent == null) return "neutral";
      if (percent <= 20) return "low";
      if (percent <= 50) return "warn";
      if (percent <= 70) return "elevated";
      return "critical";
    },
    formatPlanMetricValue(value, unit) {
      if (value == null || Number.isNaN(Number(value))) return "Not tracked";
      const number = Number(value);
      if (unit === "percent") return `${number.toFixed(1)}%`;
      if (unit === "count") return `${Math.round(number)}`;
      return this.formatResource(number, "MB");
    },
    planUsageMeta(used, limit, unit, limitLabel = null) {
      if (limit == null || Number(limit) <= 0) return "Unlimited";
      if (used == null || Number.isNaN(Number(used))) {
        return limitLabel ? `${limitLabel} available` : "Not tracked";
      }
      return `${this.formatPlanMetricValue(used, unit)} used of ${limitLabel || this.formatPlanMetricValue(limit, unit)}`;
    },
    formatSampleTime(value) {
      if (!value) return "";
      return new Date(Number(value) * 1000).toLocaleString();
    },
    formatBytes(value) {
      const bytes = Number(value || 0);
      if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      return `${bytes} B`;
    },
    phpVersionBadgeClass(version) {
      const major = parseInt((version || "8").split(".")[0]);
      if (major >= 8) return "php-badge php-badge--8";
      if (major === 7) return "php-badge php-badge--7";
      return "php-badge";
    },
    // Website Creation Wizard
    openSiteWizard() {
      this.siteWizard = {
        isOpen: true,
        step: 1,
        type: 'blank',
        domain: '',
        site_title: 'My Site',
        admin_username: 'admin',
        admin_email: this.currentUserEmail,
        admin_password: '',
        allow_overwrite: false,
        createdWebsite: null,
        createdDomainNameservers: [],
        errorMessage: "",
      };
    },
    closeSiteWizard() {
      this.siteWizard.isOpen = false;
      this.siteWizard.errorMessage = "";
    },
    nextSiteWizardStep() {
      if (this.siteWizard.step === 2) {
        if (!this.siteWizard.domain) return;
        if (this.siteWizard.type === 'blank') {
          this.siteWizard.step = 4; // Skip installer step
          return;
        }
      }
      this.siteWizard.step++;
    },
    prevSiteWizardStep() {
      if (this.siteWizard.step === 4 && this.siteWizard.type === 'blank') {
        this.siteWizard.step = 2;
        return;
      }
      this.siteWizard.step--;
    },
    async finishSiteWizard() {
      try {
        this.siteWizard.errorMessage = "";
        this.notify("Creating website...", "success");
        const sitePayload = await this.api("/api/client/websites", {
          method: "POST",
          body: JSON.stringify({ domain: this.siteWizard.domain })
        });
        const website = sitePayload.website;
        this.siteWizard.createdWebsite = website;
        this.siteWizard.createdDomainNameservers = website.nameservers || [];
        const followupIssues = [];
        
        try {
          this.notify("Issuing SSL certificate...", "success");
          await this.api("/api/client/ssl/issue", {
            method: "POST",
            body: JSON.stringify({ website_id: website.id })
          });
        } catch (sslErr) {
          console.error("SSL Issue failed:", sslErr);
          followupIssues.push(`SSL issuance could not be queued: ${sslErr.message || sslErr}`);
        }

        if (this.siteWizard.type !== 'blank') {
          try {
            this.notify(`Installing ${this.siteWizard.type}...`, "success");
            await this.api("/api/client/installer/install", {
              method: "POST",
              body: JSON.stringify({
                script_id: this.siteWizard.type,
                website_id: website.id,
                site_title: this.siteWizard.site_title,
                admin_username: this.siteWizard.admin_username,
                admin_email: this.siteWizard.admin_email,
                admin_password: this.siteWizard.admin_password,
                allow_overwrite: this.siteWizard.allow_overwrite
              })
            });
          } catch (installErr) {
            console.error("Installer setup failed:", installErr);
            followupIssues.push(`Installer setup could not be queued: ${installErr.message || installErr}`);
          }
          if (followupIssues.length) {
            this.notify(`Website created. ${followupIssues.join(" ")}`, "warning");
          } else {
            this.notify(`Website added, SSL issued, and ${this.siteWizard.type} installation started!`, "success");
          }
        } else {
          if (followupIssues.length) {
            this.notify(`Website created. ${followupIssues.join(" ")}`, "warning");
          } else {
            this.notify("Website added and SSL issued successfully!", "success");
          }
        }

        this.siteWizard.step = 5;
        await this.refresh();
      } catch (err) {
        this.siteWizard.errorMessage = err.message || String(err);
        this.notify(String(err), "error");
      }
    },
    async createWebsite() {
      this.openSiteWizard();
    },
    async deleteWebsite(site) {
      if (!window.confirm(`Delete website ${site.domain}? This removes the panel record and queues the stack to sync.`)) return;
      try {
        await this.api(`/api/client/websites/${site.id}`, { method: "DELETE" });
        this.websites = this.websites.filter((item) => item.id !== site.id);
        if (String(this.selectedWebsiteId) === String(site.id)) this.selectedWebsiteId = "";
        await this.load();
        this.notify(`Website ${site.domain} deleted`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // Database Modals
    openDbModal(type) {
      this.dbModal = type;
      this.newDatabase = { name: "", username: "" };
      this.newDatabaseUser = { username: "", password: "" };
      this.newDatabaseGrant = { database_id: "", user_id: "", privileges: "ALL" };
    },
    closeDbModal() {
      this.dbModal = null;
      this.editingDatabase = null;
      this.editingDatabaseUser = null;
      this.editingDatabaseGrant = null;
    },
    refresh() {
      return this.load();
    },
    openEditDbModal(database) {
      this.editingDatabase = { ...database };
      this.dbModal = 'edit_database';
    },
    async saveEditDatabase() {
      try {
        await this.api(`/api/client/databases/${this.editingDatabase.id}`, {
          method: "PATCH",
          body: JSON.stringify({
            name: this.editingDatabase.name,
            status: this.editingDatabase.status
          })
        });
        this.closeDbModal();
        await this.refresh();
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    openChangePasswordModal(user) {
      this.editingDatabaseUser = { ...user, newPassword: "" };
      this.dbModal = 'change_password';
    },
    async saveChangePassword() {
      try {
        await this.api(`/api/client/database-users/${this.editingDatabaseUser.id}`, {
          method: "PATCH",
          body: JSON.stringify({
            username: this.editingDatabaseUser.username,
            status: this.editingDatabaseUser.status,
            password: this.editingDatabaseUser.newPassword
          })
        });
        this.closeDbModal();
        await this.refresh();
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    openEditGrantModal(grant) {
      this.editingDatabaseGrant = { ...grant };
      this.dbModal = 'edit_grant';
    },
    async saveEditGrant() {
      try {
        await this.api(`/api/client/database-grants/${this.editingDatabaseGrant.id}`, {
          method: "PATCH",
          body: JSON.stringify({
            privileges: this.editingDatabaseGrant.privileges,
            status: this.editingDatabaseGrant.status
          })
        });
        this.closeDbModal();
        await this.refresh();
      } catch (err) {
        this.notify(String(err), "error");
      }
    },

    // PostgreSQL Databases
    async createPgDatabase() {
      try {
        await this.api("/api/client/pg-databases", {
          method: "POST",
          body: JSON.stringify({ name: this.newDbName })
        });
        this.notify("PostgreSQL Database created.", "success");
        this.newDbName = "";
        await this.loadHome();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deletePgDatabase(id) {
      if (!window.confirm("Are you sure you want to delete this PostgreSQL database?")) return;
      try {
        await this.api(`/api/client/pg-databases/${id}`, { method: "DELETE" });
        this.notify("Database deleted.", "success");
        await this.loadHome();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async createPgUser() {
      try {
        await this.api("/api/client/pg-databases/users", {
          method: "POST",
          body: JSON.stringify({ username: this.newDbUser, password: this.newDbPassword })
        });
        this.notify("PostgreSQL User created.", "success");
        this.newDbUser = "";
        this.newDbPassword = "";
        await this.loadHome();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deletePgUser(id) {
      if (!window.confirm("Are you sure you want to delete this user?")) return;
      try {
        await this.api(`/api/client/pg-databases/users/${id}`, { method: "DELETE" });
        this.notify("User deleted.", "success");
        await this.loadHome();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async changePgUserPassword() {
      try {
        await this.api("/api/client/pg-databases/users/password", {
          method: "POST",
          body: JSON.stringify({ user_id: this.changeDbUserPasswordId, password: this.changeDbUserPasswordValue })
        });
        this.notify("Password updated successfully.", "success");
        this.changeDbUserPasswordId = null;
        this.changeDbUserPasswordValue = "";
        this.showChangeDbPasswordModal = false;
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async addPgGrant() {
      try {
        await this.api("/api/client/pg-databases/users/grants", {
          method: "POST",
          body: JSON.stringify({ database_id: this.grantDbId, user_id: this.grantUserId })
        });
        this.notify("User added to database successfully.", "success");
        this.grantDbId = "";
        this.grantUserId = "";
        await this.loadHome();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async removePgGrant(id) {
      if (!window.confirm("Revoke this user's privileges from the database?")) return;
      try {
        await this.api(`/api/client/pg-databases/users/grants/${id}`, { method: "DELETE" });
        this.notify("Privileges revoked.", "success");
        await this.loadHome();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },

    async createDatabase() {
      if (!this.newDatabase.name) return;
      try {
        await this.api("/api/client/databases", { method: "POST", body: JSON.stringify(this.newDatabase) });
        this.closeDbModal();
        this.refresh();
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    async createDatabaseUser() {
      if (!this.newDatabaseUser.username || !this.newDatabaseUser.password) return;
      try {
        await this.api("/api/client/database-users", { method: "POST", body: JSON.stringify(this.newDatabaseUser) });
        this.closeDbModal();
        this.refresh();
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    async createDatabaseGrant() {
      if (!this.newDatabaseGrant.database_id || !this.newDatabaseGrant.user_id) return;
      try {
        await this.api("/api/client/database-grants", { method: "POST", body: JSON.stringify(this.newDatabaseGrant) });
        this.closeDbModal();
        this.refresh();
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    // DB Wizard
    async wizardNextStep() {
      try {
        if (this.dbWizardStep === 1) {
          await this.api("/api/client/databases", { method: "POST", body: JSON.stringify({ name: this.wizardDbName }) });
          await this.refresh();
          this.dbWizardStep = 2;
        } else if (this.dbWizardStep === 2) {
          await this.api("/api/client/database-users", { method: "POST", body: JSON.stringify({ username: this.wizardDbUser, password: this.wizardDbPass }) });
          await this.refresh();
          this.dbWizardStep = 3;
        } else if (this.dbWizardStep === 3) {
          const db = this.databases.find(d => d.name === this.wizardDbName);
          const user = this.databaseUsers.find(u => u.username === this.wizardDbUser);
          if (db && user) {
            await this.api("/api/client/database-grants", { method: "POST", body: JSON.stringify({ database_id: db.id, user_id: user.id, privileges: "ALL" }) });
            await this.refresh();
            this.dbWizardStep = 4;
          } else {
            this.notify("Could not find created database or user.", "error");
          }
        }
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    resetDbWizard() {
      this.dbWizardStep = 1;
      this.wizardDbName = "";
      this.wizardDbUser = "";
      this.wizardDbPass = "";
      this.activePage = "databases";
    },
    // Backup Wizard
    openBackupWizard() {
      this.backupWizard = { isOpen: true, step: 1, isRunning: false, progressText: '' };
    },
    closeBackupWizard() {
      this.backupWizard.isOpen = false;
    },
    async pollBackupStatus(backupId) {
      if (!this.backupWizard.isOpen || !this.backupWizard.isRunning) return;
      try {
        const payload = await this.api("/api/client/backups");
        const backups = payload.backups || [];
        const backup = backups.find(b => b.id === backupId);
        if (backup) {
          if (backup.status === 'completed') {
            this.backupWizard.progressText = 'Backup completed successfully!';
            this.backupWizard.isRunning = false;
            this.backupWizard.step = 2;
            await this.load();
          } else if (backup.status === 'failed') {
            this.backupWizard.progressText = 'Backup failed: ' + (backup.error || 'Unknown error');
            this.backupWizard.isRunning = false;
            await this.load();
          } else if (backup.status === 'running') {
            this.backupWizard.progressText = 'Backup is running. Archiving files and databases...';
            setTimeout(() => this.pollBackupStatus(backupId), 1500);
          } else {
            this.backupWizard.progressText = 'Backup is queued. Waiting for agent...';
            setTimeout(() => this.pollBackupStatus(backupId), 1500);
          }
        } else {
          setTimeout(() => this.pollBackupStatus(backupId), 1500);
        }
      } catch (err) {
        this.backupWizard.progressText = 'Error checking backup status: ' + err.message;
        setTimeout(() => this.pollBackupStatus(backupId), 2000);
      }
    },
    async startBackupWizard() {
      this.backupWizard.step = 2;
      this.backupWizard.isRunning = true;
      this.backupWizard.progressText = 'Enqueuing backup job...';
      try {
        const payload = await this.api("/api/client/backups", { method: "POST", body: "{}" });
        this.backupWizard.progressText = `Job #${payload.job_id} queued. Starting process...`;
        this.pollBackupStatus(payload.backup_id);
      } catch (err) {
        this.backupWizard.isRunning = false;
        this.backupWizard.progressText = 'Failed to start backup: ' + err.message;
      }
    },
    async updateDatabase(database) {
      try {
        const payload = await this.api(`/api/client/databases/${database.id}`, {
          method: "PATCH",
          body: JSON.stringify({ name: database.name, status: database.status }),
        });
        this.applyDatabasePayload(payload);
        this.notify(`Database ${database.name} updated`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteDatabase(database) {
      if (!window.confirm(`Delete database ${database.name}? Grants will be removed too.`)) return;
      try {
        const payload = await this.api(`/api/client/databases/${database.id}`, { method: "DELETE" });
        this.applyDatabasePayload(payload);
        this.notify(`Database ${database.name} deleted`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async updateDatabaseUser(user) {
      try {
        const payload = await this.api(`/api/client/database-users/${user.id}`, {
          method: "PATCH",
          body: JSON.stringify({ username: user.username, status: user.status, password: user.newPassword || "" }),
        });
        this.applyDatabasePayload(payload);
        user.newPassword = "";
        this.notify(`Database user ${user.username} updated`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteDatabaseUser(user) {
      if (!window.confirm(`Delete database user ${user.username}? Grants will be removed too.`)) return;
      try {
        const payload = await this.api(`/api/client/database-users/${user.id}`, { method: "DELETE" });
        this.applyDatabasePayload(payload);
        this.notify(`Database user ${user.username} deleted`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async updateDatabaseGrant(grant) {
      try {
        const payload = await this.api(`/api/client/database-grants/${grant.id}`, {
          method: "PATCH",
          body: JSON.stringify({ privileges: grant.privileges, status: grant.status }),
        });
        this.applyDatabasePayload(payload);
        this.notify("Database user access updated", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteDatabaseGrant(grant) {
      try {
        const payload = await this.api(`/api/client/database-grants/${grant.id}`, { method: "DELETE" });
        this.applyDatabasePayload(payload);
        this.notify("Database user access removed", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async issueSsl(site) {
      try {
        await this.api("/api/client/ssl/issue", {
          method: "POST",
          body: JSON.stringify({ website_id: site.id }),
        });
        this.notify(`Local SSL issued for ${site.domain}`, "success");
        await this.load();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    openConnectWizard(site) {
      this.connectWizard = { isOpen: true, website: site, method: "nameservers", checking: false, result: null };
    },
    closeConnectWizard() {
      if (!this.connectWizard.checking) this.connectWizard.isOpen = false;
    },
    async verifyWebsiteConnection() {
      const wizard = this.connectWizard;
      if (!wizard.website) return;
      wizard.checking = true;
      wizard.result = null;
      try {
        const payload = await this.api(`/api/client/websites/${wizard.website.id}/connection-check`, { method: "POST", body: "{}" });
        wizard.result = payload;
        if (payload.verified) {
          this.notify("Connection verified. AutoSSL has been queued.", "success");
          await this.load();
        } else {
          this.notify("DNS is not pointing to this hosting account yet.", "warning");
        }
      } catch (error) { wizard.result = { verified: false, message: error.message }; this.notify(error.message, "error"); }
      finally { wizard.checking = false; }
    },
    async launch(tool, subpath = "") {
      const paths = {
        files: "/api/client/files/launch",
        phpmyadmin: "/api/client/phpmyadmin/launch",
        phppgadmin: "/api/client/phppgadmin/launch",
      };
      try {
        let endpoint = paths[tool];
        if (tool === "files" && subpath) {
          endpoint += `?path=${encodeURIComponent(subpath)}`;
        }
        const payload = await this.api(endpoint);
        if (payload.launch_url) {
          window.open(payload.launch_url, "_blank", "noopener,noreferrer");
        }
        this.notify(`Launch URL: ${payload.launch_url || "not available until the stack is provisioned"}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async createBackup() {
      try {
        const payload = await this.api("/api/client/backups", { method: "POST", body: "{}" });
        this.notify(`Backup #${payload.backup_id} queued`, "success");
        await this.load();
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async createBackupNow() {
      await this.createBackup();
    },
    async downloadBackup(backupId) {
      try {
        const response = await fetch(`/api/client/backups/${backupId}/download`, {
          headers: {
            Accept: "application/gzip",
            ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
          },
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.error || "download_failed");
        }
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `backup-${backupId}.tar.gz`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        this.notify("Backup download started.", "success");
      } catch (err) {
        this.notify(err.message, "error");
      }
    },
    async restoreBackup(backupId) {
      if (!confirm("Are you sure you want to restore this backup? This will overwrite your current files and databases.")) return;
      try {
        const payload = await this.api(`/api/client/backups/${backupId}/restore`, { method: "POST", body: "{}" });
        this.notify(`Restore job #${payload.job_id} queued`, "success");
        setTimeout(() => this.load(), 2000);
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    // Mailbox methods
    openMailboxWizard() {
      this.mailboxWizard = { isOpen: true, mode: "create", step: 1, isCreating: false, createdMailbox: null, mailboxId: null, email: "", quota_mb: 1024, password: "", confirm_password: "", status: "active" };
    },
    closeMailboxWizard() {
      if (this.mailboxWizard.isCreating) return;
      this.mailboxWizard.isOpen = false;
    },
    openMailboxEditor(mailbox) {
      this.mailboxEditor = {
        isOpen: true,
        isSaving: false,
        mailboxId: mailbox.id,
        email: mailbox.email,
        quota_mb: mailbox.quota_mb,
        status: mailbox.status,
        password: "",
        confirm_password: "",
      };
    },
    async openMailboxWebmail(mailbox) {
      try {
        const payload = await this.api(`/api/client/mailboxes/${mailbox.id}/webmail/launch`);
        if (!payload.launch_url) {
          throw new Error("webmail_launch_unavailable");
        }
        window.location.assign(payload.launch_url);
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    openMailboxLogin(mailbox) {
      const url = mailbox.webmail_login_url || mailbox.mailbox_login_url || mailbox.webmail_url;
      if (!url) {
        this.notify("Direct mailbox login is unavailable for this mailbox.", "warning");
        return;
      }
      window.location.assign(url);
    },
    closeMailboxEditor() {
      if (this.mailboxEditor.isSaving) return;
      this.mailboxEditor.isOpen = false;
    },
    async saveMailboxEditor() {
      if (this.mailboxEditor.isSaving) return;
      try {
        this.mailboxEditor.isSaving = true;
        const payload = {
          email: this.mailboxEditor.email,
          quota_mb: this.mailboxEditor.quota_mb,
          status: this.mailboxEditor.status,
        };
        if (this.mailboxEditor.password) {
          payload.password = this.mailboxEditor.password;
          payload.confirm_password = this.mailboxEditor.confirm_password;
        }
        const response = await this.api(`/api/client/mailboxes/${this.mailboxEditor.mailboxId}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        });
        Object.assign(this.mailboxEditor, { isSaving: false });
        const idx = this.mailboxes.findIndex((mailbox) => mailbox.id === this.mailboxEditor.mailboxId);
        if (idx !== -1 && response.mailbox) {
          this.mailboxes.splice(idx, 1, response.mailbox);
        } else {
          this.mailboxes = (await this.api("/api/client/mailboxes")).mailboxes || [];
        }
        this.notify(`Mailbox ${this.mailboxEditor.email} updated`, "success");
        this.mailboxEditor.isOpen = false;
      } catch (error) {
        this.mailboxEditor.isSaving = false;
        this.notify(error.message, "error");
      }
    },
    prevMailboxWizardStep() {
      if (this.mailboxWizard.step > 1 && !this.mailboxWizard.isCreating) {
        this.mailboxWizard.step -= 1;
      }
    },
    nextMailboxWizardStep() {
      if (this.mailboxWizard.isCreating) return;
      if (this.mailboxWizard.step === 1) {
        if (!this.mailboxWizard.email || !this.mailboxWizard.quota_mb) return;
        this.mailboxWizard.step = 2;
        return;
      }
      if (this.mailboxWizard.step === 2) {
        if (!this.mailboxWizard.password || this.mailboxWizard.password.length < 10) return;
        if (this.mailboxWizard.password !== this.mailboxWizard.confirm_password) return;
        this.mailboxWizard.step = 3;
      }
    },
    async createMailbox() {
      if (this.mailboxWizard.isCreating) return;
      if (!this.mailboxWizard.email || !this.mailboxWizard.password) return;
      try {
        this.mailboxWizard.isCreating = true;
        const payload = {
          email: this.mailboxWizard.email,
          quota_mb: this.mailboxWizard.quota_mb,
          password: this.mailboxWizard.password,
          confirm_password: this.mailboxWizard.confirm_password,
        };
        const response = await this.api("/api/client/mailboxes", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        this.notify(`Mailbox ${this.mailboxWizard.email} created`, "success");
        this.mailboxWizard.isCreating = false;
        this.mailboxWizard.createdMailbox = { id: response.mailbox_id, email: this.mailboxWizard.email };
        this.mailboxWizard.step = 4;
        this.mailboxWizard.password = "";
        this.mailboxWizard.confirm_password = "";
        this.mailboxes = (await this.api("/api/client/mailboxes")).mailboxes || [];
        await this.loadSyncJobs();
      } catch (error) {
        this.mailboxWizard.isCreating = false;
        this.notify(error.message, "error");
      }
    },
    async toggleMailboxStatus(mailbox) {
      const newStatus = mailbox.status === "suspended" ? "active" : "suspended";
      try {
        const payload = await this.api(`/api/client/mailboxes/${mailbox.id}`, {
          method: "PATCH",
          body: JSON.stringify({ status: newStatus }),
        });
        Object.assign(mailbox, payload.mailbox);
        this.notify(`Mailbox ${mailbox.email} ${newStatus}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteMailbox(mailbox) {
      if (!window.confirm(`Delete mailbox ${mailbox.email}? This cannot be undone.`)) return;
      try {
        await this.api(`/api/client/mailboxes/${mailbox.id}`, { method: "DELETE" });
        this.mailboxes = this.mailboxes.filter((m) => m.id !== mailbox.id);
        this.notify(`Mailbox ${mailbox.email} deleted`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // Cron job methods
    async createCronJob() {
      if (!this.newCronJob.command) return;
      try {
        await this.api("/api/client/cron-jobs", {
          method: "POST",
          body: JSON.stringify(this.newCronJob),
        });
        this.notify("Cron job created", "success");
        this.newCronJob = { schedule: "*/15 * * * *", command: "" };
        this.cronJobs = (await this.api("/api/client/cron-jobs")).cron_jobs || [];
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async toggleCronStatus(job) {
      const newStatus = job.status === "disabled" ? "enabled" : "disabled";
      try {
        await this.api(`/api/client/cron-jobs/${job.id}`, {
          method: "PATCH",
          body: JSON.stringify({ status: newStatus }),
        });
        this.cronJobs = (await this.api("/api/client/cron-jobs")).cron_jobs || [];
        this.notify(`Cron job ${newStatus}`, "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteCronJob(job) {
      if (!window.confirm(`Delete this cron job? (${job.schedule} ${job.command})`)) return;
      try {
        await this.api(`/api/client/cron-jobs/${job.id}`, { method: "DELETE" });
        this.cronJobs = this.cronJobs.filter((c) => c.id !== job.id);
        this.notify("Cron job deleted", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    // Git deployment methods
    async createGitDeployment() {
      if (!this.newGitDeployment.repository_url) return;
      try {
        await this.api("/api/client/git-deployments", {
          method: "POST",
          body: JSON.stringify(this.newGitDeployment),
        });
        this.notify(`Repository ${this.newGitDeployment.repository_url} connected`, "success");
        this.newGitDeployment = { repository_url: "", branch: "main", deploy_path: "" };
        this.gitDeployments = (await this.api("/api/client/git-deployments")).git_deployments || [];
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async deleteGitDeployment(dep) {
      if (!window.confirm(`Disconnect repository ${dep.repository_url}?`)) return;
      try {
        await this.api(`/api/client/git-deployments/${dep.id}`, { method: "DELETE" });
        this.gitDeployments = this.gitDeployments.filter((d) => d.id !== dep.id);
        this.notify("Git deployment disconnected", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    async rollbackGitDeployment(dep) {
      if (!window.confirm(`Rollback repository ${dep.repository_url} to the previous commit?`)) return;
      try {
        await this.api(`/api/client/git-deployments/${dep.id}/rollback`, { method: "POST" });
        this.gitDeployments = (await this.api("/api/client/git-deployments")).git_deployments || [];
        this.notify("Git deployment rolled back", "success");
      } catch (error) {
        this.notify(error.message, "error");
      }
    },
    goTo(target) {
      if (this.isFeatureDisabled(target)) {
        this.notify(`${this.featureStatus(target).label}: ${target}`, "error");
        return;
      }
      target = normalizedClientTarget(target);
      if (!this.hasHostingAccount && !["dashboard", "domains", "dns-zone-editor"].includes(target)) {
        target = "domains";
      }

      this.activePage = target;
      this.userMenuOpen = false;
      if (target === "performance") {
        this.refreshResourceUsage();
        if (!this.resourcePoll) this.resourcePoll = window.setInterval(() => this.loadResourceUsage(), 10000);
      } else if (target === "analytics") {
        this.loadAnalytics();
        if (this.resourcePoll) { window.clearInterval(this.resourcePoll); this.resourcePoll = null; }
      } else if (target === "php-info") {
        this.loadPhpInfo();
        if (this.resourcePoll) { window.clearInterval(this.resourcePoll); this.resourcePoll = null; }
      } else if (target === "disk-usage") {
        this.loadDiskUsage();
        if (this.resourcePoll) { window.clearInterval(this.resourcePoll); this.resourcePoll = null; }
      } else if (target === "dns-zone-editor") {
        if (this.domains.length) this.selectedDomainId = this.domains[0].id;
        this.newDnsRecord.domain_id = this.selectedDomainId;
        this.loadDnsRecords();
        if (this.resourcePoll) { window.clearInterval(this.resourcePoll); this.resourcePoll = null; }
      } else {
        if (this.resourcePoll) { window.clearInterval(this.resourcePoll); this.resourcePoll = null; }
      }
      window.history.pushState({}, "", pageUrl(target));
    },
    chooseSearchResult(result) {
      result.action();
      this.searchQuery = "";
    },
    chooseSite(siteId) {
      this.selectedWebsiteId = siteId;
      this.siteSwitcherOpen = false;
      this.siteSearchQuery = "";
      if (this.activePage === "analytics") this.loadAnalytics();
      if (this.activePage === "php-info") this.loadPhpInfo();
    },
    toggleSiteSwitcher() {
      this.siteSwitcherOpen = !this.siteSwitcherOpen;
      this.userMenuOpen = false;
    },
    toggleUserMenu() {
      this.userMenuOpen = !this.userMenuOpen;
      this.siteSwitcherOpen = false;
    },
    openInstallerModal(script) {
      this.installer.selectedScript = script;
      const form = {
        website_id: "",
        allow_overwrite: false,
      };
      if (script.required_fields) {
        for (const field of script.required_fields) {
          form[field.name] = field.default || "";
        }
      }
      this.installer.form = form;
    },
    closeInstallerModal() {
      this.installer.selectedScript = null;
    },
    async submitInstallScript() {
      if (!this.installer.form.website_id) return;
      const script = this.installer.selectedScript;
      try {
        const body = {
          script_id: script.id,
          website_id: this.installer.form.website_id,
          site_title: this.installer.form.site_title,
          admin_username: this.installer.form.admin_username,
          admin_email: this.installer.form.admin_email,
          admin_password: this.installer.form.admin_password,
          allow_overwrite: this.installer.form.allow_overwrite,
        };
        const payload = await this.api("/api/client/installer/install", {
          method: "POST",
          body: JSON.stringify(body),
        });
        this.notify(`${script.name} installation started (Job #${payload.job_id})`, "success");
        this.closeInstallerModal();
        await this.refresh();
      } catch (err) {
        this.notify(String(err), "error");
      }
    },
    tileCick(tile) {
      if (this.isFeatureDisabled(tile.target)) {
        this.notify(`${tile.label} is not available yet.`, "error");
        return;
      }
      if (tile.action) { tile.action(); return; }
      this.goTo(tile.target);
    },
    async logout() {
      try {
        await this.api("/api/client/auth/logout", { method: "POST" });
      } catch (err) {
        console.error("API logout failed:", err);
      }
      this.clearSessionState();
      window.location.href = "/login";
    },
    switchTheme(themeName) {
      this.activeTheme = themeName;
      localStorage.setItem("mp_theme", themeName);
      const themeLink = document.getElementById("theme-style");
      if (themeLink) {
        themeLink.setAttribute("href", "/assets/" + themeName + ".css");
      }
      appToast("Theme changed to " + themeName, "success");
    },
    async updatePassword() {
      const form = this.settingsForm;
      if (!form.current_password || !form.new_password || !form.confirm_password) {
        appToast("All password fields are required.", "error");
        return;
      }
      if (form.new_password !== form.confirm_password) {
        appToast("New password and confirm password do not match.", "error");
        return;
      }
      if (form.new_password.length < 10) {
        appToast("New password must be at least 10 characters long.", "error");
        return;
      }
      this.isChangingPassword = true;
      try {
        const payload = await this.api("/api/client/settings/change-password", {
          method: "POST",
          body: JSON.stringify({
            current_password: form.current_password,
            new_password: form.new_password,
          }),
        });
        if (payload.success) {
          appToast("Password changed successfully.", "success");
          form.current_password = "";
          form.new_password = "";
          form.confirm_password = "";
        }
      } catch (err) {
        appToast(err.message, "error");
      } finally {
        this.isChangingPassword = false;
      }
    },
  },
  watch: {
    activePage(newVal) {
      const newUrl = pageUrl(newVal);
      if (window.location.pathname !== newUrl) {
        window.history.pushState(null, "", newUrl);
      }
      if (newVal === "remote-mysql" && this.remoteMysqlHosts.length === 0) {
        this.loadRemoteMysqlHosts();
      }
      if (newVal === "services" && Object.keys(this.serviceStatusMap).length === 0) {
        this.loadServicesStatus();
      }
      if (newVal === "site-builder" && this.siteBuilderTemplates.length === 0) {
        this.loadSiteBuilderTemplates();
      }
      if (newVal === "disk-usage" && this.diskUsage.length === 0) {
        this.loadDiskUsage();
      }
      if (newVal === "php-info") {
        this.loadPhpInfo();
      }
    }
  }
});

async function initClientPortal() {
  const urlHashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const impersonationToken = urlHashParams.get("mp_impersonation_token") || urlHashParams.get("mp_access_token");
  if (impersonationToken) {
    try {
      const response = await fetch("/api/client/auth/exchange-impersonation", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ impersonation_token: impersonationToken }),
      });
      const data = await response.json();
      if (response.ok && data.access_token) {
        localStorage.setItem("mp_client_token", data.access_token);
      } else {
        localStorage.setItem("mp_client_token", impersonationToken);
      }
    } catch (err) {
      console.error("Exchange impersonation token failed:", err);
      localStorage.setItem("mp_client_token", impersonationToken);
    } finally {
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
    }
  }

  const vm = app.mount("#client-app");
  window.appToast = function(msg, type) { vm.notify(msg, type); };
}

initClientPortal();

