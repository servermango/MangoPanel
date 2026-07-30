import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv_file(dotenv_path):
    path = Path(dotenv_path)
    if not path.is_file():
        return
    try:
        content = path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            if k and k not in os.environ:
                os.environ[k] = v
    except Exception:
        pass


def load_all_env_files():
    user_files = Path(os.getenv("MP_USER_FILES_DIR", PROJECT_ROOT / "user_files"))
    candidates = [
        user_files / ".env",
        user_files / "data" / ".env",
        PROJECT_ROOT / ".env",
    ]
    for path in candidates:
        _load_dotenv_file(path)


class Config:
    def __init__(self):
        load_all_env_files()
        self.env = os.getenv("MP_ENV", "development")
        self.host = os.getenv("MP_HOST", "0.0.0.0")
        self.port = int(os.getenv("MP_PORT", "8000"))
        self.client_port = int(os.getenv("MP_CLIENT_PORT", "8000"))
        self.admin_port = int(os.getenv("MP_ADMIN_PORT", "8001"))
        self.reseller_port = int(os.getenv("MP_RESELLER_PORT", "8002"))
        # Single shared root in the project directory that a server admin can
        # reach directly. Both customer account files and the control-plane
        # database live under here.
        self.user_files_dir = Path(os.getenv("MP_USER_FILES_DIR", PROJECT_ROOT / "user_files"))
        self.data_dir = Path(os.getenv("MP_DATA_DIR", self.user_files_dir / "data"))
        self.db_path = Path(os.getenv("MP_DB_PATH", self.data_dir / "mangopanel.sqlite3"))
        self.agent_mode = os.getenv("MP_AGENT_MODE", "simulate")
        self.agent_inline = os.getenv("MP_AGENT_INLINE", "true").lower() == "true"
        self.account_root = Path(os.getenv("MP_ACCOUNT_ROOT", self.user_files_dir / "accounts"))
        self.public_host = os.getenv("MP_PUBLIC_HOST", "127.0.0.1")
        if self.public_host == "0.0.0.0":
            self.public_host = "127.0.0.1"
        self.account_port_base = int(os.getenv("MP_ACCOUNT_PORT_BASE", "18000"))
        self.compose_project_prefix = os.getenv("MP_COMPOSE_PROJECT_PREFIX", "mp")
        self.jwt_secret = os.getenv("MP_JWT_SECRET", "dev-only-change-me")
        self.dev_auth_test_mode = os.getenv("MP_DEV_AUTH_TEST_MODE", "false").lower() == "true"
        self.token_ttl_seconds = int(os.getenv("MP_TOKEN_TTL_SECONDS", "3600"))
        self.totp_challenge_ttl_seconds = int(os.getenv("MP_TOTP_CHALLENGE_TTL_SECONDS", "300"))
        self.powerdns_api_url = os.getenv("MP_POWERDNS_API_URL", "")
        self.powerdns_api_key = os.getenv("MP_POWERDNS_API_KEY", "")
        self.powerdns_server_id = os.getenv("MP_POWERDNS_SERVER_ID", "localhost")
        self.cloudflare_api_base = os.getenv("MP_CLOUDFLARE_API_BASE", "https://api.cloudflare.com/client/v4")
        self.expose_internal_errors = (
            os.getenv("SHOW_EXCEPTION_DETAILS", "").lower() in {"1", "true", "yes"}
            or os.getenv("MP_EXPOSE_INTERNAL_ERRORS", "").lower() in {"1", "true", "yes"}
        )
        self.trusted_proxy = os.getenv("MP_TRUSTED_PROXY", "false").lower() == "true"
        self.enable_ssl = os.getenv("MP_ENABLE_SSL", "true").lower() in {"1", "true", "yes"}
        self.ssl_cert_path = Path(os.getenv("MP_SSL_CERT", PROJECT_ROOT / "var" / "ssl" / "admin.crt"))
        self.ssl_key_path = Path(os.getenv("MP_SSL_KEY", PROJECT_ROOT / "var" / "ssl" / "admin.key"))

    @property
    def is_development(self):
        return self.env == "development" or getattr(self, "dev_auth_test_mode", False) or getattr(self, "agent_mode", "") == "simulate"


def load_config():
    load_all_env_files()
    return Config()


CONFIG = load_config()


FILEBROWSER_CUSTOM_JS = r"""(function () {
  (function ensureAuth() {
    function tryAutoLogin() {
      try {
        let jwt = localStorage.getItem('jwt');
        if (!jwt) {
          fetch('/files/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: '', password: '' })
          })
          .then(r => r.text())
          .then(token => {
            if (token && token.length > 20) {
              localStorage.setItem('jwt', token.trim());
              if (window.location.pathname.includes('/files/login') || window.location.pathname.endsWith('/login')) {
                window.location.href = '/files/';
              }
            }
          })
          .catch(() => {});
        } else if (window.location.pathname.includes('/files/login') || window.location.pathname.endsWith('/login')) {
          window.location.href = '/files/';
        }
      } catch (e) {}
    }
    tryAutoLogin();
    if (window.location.pathname.includes('/files/login') || window.location.pathname.endsWith('/login')) {
      setInterval(tryAutoLogin, 500);
    }
  })();

  let activeZipPath = null;

  function formatStorageSize(mb) {
    if (!mb && mb !== 0) return '0 MB';
    if (mb >= 1024) {
      let gb = (mb / 1024).toFixed(1);
      return gb.endsWith('.0') ? Math.round(mb / 1024) + ' GB' : gb + ' GB';
    }
    return mb + ' MB';
  }

  function renderStorageIndicator() {
    let data = window.MP_STORAGE_DATA;
    if (!data || !data.limit) return;

    let usedStr = formatStorageSize(data.used);
    let limitStr = formatStorageSize(data.limit);
    let pct = Math.min(100, Math.round((data.used / data.limit) * 100));

    let color = pct > 90 ? '#ef4444' : (pct > 75 ? '#f59e0b' : '#10b981');

    let nativeCredits = document.querySelector('.credits') || document.querySelector('[class*="credits"]') || document.querySelector('[class*="usage"]');
    if (nativeCredits) {
      let span = nativeCredits.querySelector('span') || nativeCredits.querySelector('p') || nativeCredits.querySelector('a') || nativeCredits;
      if (span) {
        span.textContent = `${usedStr} of ${limitStr} used`;
      }
    }

    let progressBars = document.querySelectorAll('.credits .progress div, .credits div div, [class*="progress"] div, div[class*="progress"]');
    progressBars.forEach(bar => {
      bar.style.setProperty('background-color', color, 'important');
      bar.style.setProperty('background', color, 'important');
    });

    let el = document.getElementById('mp-storage-pill');
    if (!el) {
      el = document.createElement('div');
      el.id = 'mp-storage-pill';
      el.style.cssText = 'position:fixed;bottom:16px;left:16px;background:#1e293b;color:#f8fafc;border:1px solid rgba(255,255,255,0.15);padding:8px 14px;border-radius:8px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:12px;font-weight:500;z-index:999999;box-shadow:0 10px 15px -3px rgba(0,0,0,0.3);display:flex;align-items:center;gap:8px;pointer-events:none;';
      (document.body || document.documentElement).appendChild(el);
    }
    el.innerHTML = `<div style="width:8px;height:8px;border-radius:50%;background:${color}"></div><span>Plan Storage: <strong>${usedStr}</strong> / ${limitStr} (${pct}%)</span>`;
  }

  try {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', renderStorageIndicator);
    } else {
      renderStorageIndicator();
    }
    setInterval(renderStorageIndicator, 1000);
  } catch (e) {}

  try {
    if (window.location.pathname.includes('/files/domains/')) {
      const style = document.createElement('style');
      style.innerHTML = `
        .breadcrumbs a[href="/files"], 
        .breadcrumbs a[href="/files/"],
        .breadcrumbs a[href="/files/domains"],
        .breadcrumbs a[href="/files/domains/"] {
          display: none !important;
          pointer-events: none !important;
        }
      `;
      document.head.appendChild(style);
    }
  } catch (e) {}

  function isArchive(name) {
    if (!name) return false;
    let value = String(name).toLowerCase().trim();
    if (value.includes('?')) value = value.split('?')[0];
    if (value.includes('#')) value = value.split('#')[0];
    if (value.includes('/')) {
      let parts = value.split('/').filter(Boolean);
      if (parts.length > 0) value = parts[parts.length - 1];
    }
    return (
      value.endsWith('.zip') ||
      value.endsWith('.tar.gz') ||
      value.endsWith('.tgz') ||
      value.endsWith('.tar') ||
      value.endsWith('.gz') ||
      value.endsWith('.7z') ||
      value.endsWith('.rar') ||
      value.endsWith('.bz2') ||
      value.endsWith('.xz')
    );
  }

  let lastActiveZipPath = null;

  function getCurrentDirectory() {
    let p = window.location.pathname || '';
    let hash = window.location.hash || '';
    let raw = '';
    if (hash && hash.includes('#')) {
      raw = hash.split('#')[1] || '';
    } else {
      raw = p;
    }
    raw = decodeURIComponent(raw.split('?')[0]);
    if (raw.startsWith('/api/public/filebrowser/proxy')) raw = raw.replace('/api/public/filebrowser/proxy', '');
    if (raw.startsWith('/files/files/')) raw = raw.replace('/files/files/', '/');
    else if (raw.startsWith('/files/files')) raw = raw.replace('/files/files', '');
    else if (raw.startsWith('/files/')) raw = raw.replace('/files/', '/');
    else if (raw.startsWith('/files')) raw = raw.replace('/files', '');
    
    if (!raw.startsWith('/')) raw = '/' + raw;
    if (raw.length > 1 && raw.endsWith('/')) raw = raw.slice(0, -1);
    return raw;
  }

  function normalizeArchivePath(rawPath) {
    if (!rawPath) return null;
    let decoded = decodeURIComponent(String(rawPath).trim());
    if (decoded.includes('://')) {
      try {
        decoded = new URL(decoded).pathname;
      } catch (e) {
        decoded = decoded.split('://').pop();
      }
    }
    if (decoded.includes('?')) decoded = decoded.split('?')[0];
    if (decoded.includes('#')) decoded = decoded.split('#')[0];
    if (decoded.startsWith('/api/public/filebrowser/proxy')) decoded = decoded.replace('/api/public/filebrowser/proxy', '');
    if (decoded.startsWith('/files/files/')) decoded = decoded.replace('/files/files/', '/');
    else if (decoded.startsWith('/files/')) decoded = decoded.replace('/files/', '/');
    else if (decoded.startsWith('/files')) decoded = decoded.replace('/files', '');
    if (decoded.startsWith('/api/resources/')) decoded = decoded.replace('/api/resources/', '/');
    else if (decoded.startsWith('/api/raw/')) decoded = decoded.replace('/api/raw/', '/');
    else if (decoded.startsWith('/api/preview/')) decoded = decoded.replace('/api/preview/', '/');
    if (!decoded.startsWith('/')) decoded = '/' + decoded;
    decoded = decoded.replace(/\/+/g, '/');
    return isArchive(decoded) ? decoded : null;
  }

  function resolveActiveArchivePath(node) {
    if (!node || !node.getAttribute) return null;

    let candidateAttrs = ['data-path', 'data-url', 'href', 'data-file-path', 'data-item-path', 'data-name', 'data-file'];
    for (let attr of candidateAttrs) {
      let raw = node.getAttribute(attr);
      if (raw) {
        let normalized = normalizeArchivePath(raw);
        if (normalized) return normalized;
      }
    }

    let name = node.getAttribute('data-name') || node.getAttribute('aria-label') || node.getAttribute('title') || '';
    if (name && isArchive(name)) {
      let curDir = getCurrentDirectory();
      if (!curDir.endsWith('/')) curDir += '/';
      return normalizeArchivePath(curDir + name);
    }

    let textCandidates = [];
    let nameEl = node.querySelector('.name') || node.querySelector('.filename') || node.querySelector('[class*="name"]') || node.querySelector('span') || node.querySelector('a') || node.querySelector('button');
    if (nameEl) {
      textCandidates.push(nameEl.innerText || nameEl.textContent || '');
    }
    if (node.innerText) {
      textCandidates.push(node.innerText || '');
    }
    if (node.textContent) {
      textCandidates.push(node.textContent || '');
    }
    for (let text of textCandidates) {
      let trimmed = String(text).trim();
      if (!trimmed) continue;
      let line = trimmed.split('\n')[0].replace(/\r/g, '').trim();
      if (isArchive(line)) {
        let curDir = getCurrentDirectory();
        if (!curDir.endsWith('/')) curDir += '/';
        return normalizeArchivePath(curDir + line);
      }
      let basename = line.split('/').filter(Boolean).pop();
      if (basename && isArchive(basename)) {
        let curDir = getCurrentDirectory();
        if (!curDir.endsWith('/')) curDir += '/';
        return normalizeArchivePath(curDir + basename);
      }
    }

    if (node.classList && (node.classList.contains('item') || node.tagName === 'TR' || node.tagName === 'LI' || node.tagName === 'A' || node.hasAttribute('aria-label'))) {
      let rowName = (node.getAttribute('aria-label') || '').trim();
      if (rowName && isArchive(rowName)) {
        let curDir = getCurrentDirectory();
        if (!curDir.endsWith('/')) curDir += '/';
        return normalizeArchivePath(curDir + rowName);
      }
    }

    return null;
  }

  function getZipPathFromTarget(target) {
    if (!target) return null;
    let curr = target;
    let depth = 0;
    while (curr && depth < 12 && curr !== document.body) {
      let resolved = resolveActiveArchivePath(curr);
      if (resolved) return resolved;
      curr = curr.parentElement;
      depth++;
    }
    return null;
  }

  function getArchivePathFromSelection() {
    let selectors = [
      '.item[aria-selected="true"]',
      '.item.selected',
      '[class*="item"][aria-selected="true"]',
      '[class*="item"].selected',
      'tr[aria-selected="true"]',
      'tr.selected',
      'div[aria-selected="true"]',
      '[aria-selected="true"]',
      '.selected'
    ];
    for (let sel of selectors) {
      let items = document.querySelectorAll(sel);
      for (let item of items) {
        let zip = getZipPathFromTarget(item);
        if (zip) return zip;
      }
    }
    return null;
  }

  function getSelectedZipPath() {
    return getArchivePathFromSelection();
  }

  /* ── Filebrowser DOM facts (from actual source code analysis):
     - Items are: div.item[data-ext=".zip"][aria-label="filename"][aria-selected]
     - Header actions: header > div#dropdown > action buttons
     - No floating context menu exists — right-click just selects the item
     - We must show our own context menu on right-click for archive files
     ─────────────────────────────────────────────────────────────────── */

  /* ── Custom context menu overlay ──────────────────────────────── */
  let mpCtxMenu = null;
  let mpCtxTarget = null;

  function ensureCtxMenu() {
    if (mpCtxMenu) return mpCtxMenu;
    let menu = document.createElement('div');
    menu.id = 'mp-extract-ctx';
    menu.style.cssText = [
      'position:fixed', 'z-index:999999', 'display:none',
      'background:#1a1a2e', 'border:1px solid rgba(255,255,255,0.1)',
      'border-radius:8px', 'box-shadow:0 12px 40px rgba(0,0,0,0.5)',
      'min-width:180px', 'padding:4px 0', 'overflow:hidden',
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif',
      'backdrop-filter:blur(10px)', '-webkit-backdrop-filter:blur(10px)',
      'animation:mpCtxFadeIn 0.12s ease-out'
    ].join(';') + ';';

    let style = document.createElement('style');
    style.textContent = '@keyframes mpCtxFadeIn{from{opacity:0;transform:scale(0.95)}to{opacity:1;transform:scale(1)}}';
    menu.appendChild(style);

    let extractBtn = document.createElement('button');
    extractBtn.id = 'mp-extract-btn';
    extractBtn.type = 'button';
    extractBtn.style.cssText = [
      'display:flex', 'align-items:center', 'width:100%', 'padding:10px 16px',
      'background:none', 'border:none', 'color:#e2e8f0', 'font-size:14px',
      'cursor:pointer', 'text-align:left', 'gap:10px', 'transition:background 0.12s ease',
      'font-family:inherit'
    ].join(';') + ';';
    extractBtn.innerHTML = '<i class="material-icons" style="font-size:20px;color:#60a5fa;">unarchive</i><span>Extract Here</span>';
    extractBtn.addEventListener('mouseenter', function() { this.style.background = 'rgba(96,165,250,0.15)'; });
    extractBtn.addEventListener('mouseleave', function() { this.style.background = 'none'; });
    extractBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      ev.stopPropagation();
      closeCtxMenu();
      if (mpCtxTarget) {
        doExtract(mpCtxTarget);
        mpCtxTarget = null;
      }
    });
    menu.appendChild(extractBtn);

    let downloadBtn = document.createElement('button');
    downloadBtn.type = 'button';
    downloadBtn.style.cssText = extractBtn.style.cssText;
    downloadBtn.innerHTML = '<i class="material-icons" style="font-size:20px;color:#94a3b8;">file_download</i><span>Download</span>';
    downloadBtn.addEventListener('mouseenter', function() { this.style.background = 'rgba(148,163,184,0.12)'; });
    downloadBtn.addEventListener('mouseleave', function() { this.style.background = 'none'; });
    downloadBtn.addEventListener('click', function(ev) {
      ev.preventDefault();
      ev.stopPropagation();
      closeCtxMenu();
      if (mpCtxTarget) {
        let dlPath = '/files/api/raw' + mpCtxTarget + '?auth=' + (localStorage.getItem('jwt') || '');
        window.open(dlPath, '_blank');
        mpCtxTarget = null;
      }
    });
    menu.appendChild(downloadBtn);

    (document.body || document.documentElement).appendChild(menu);
    mpCtxMenu = menu;
    return menu;
  }

  function openCtxMenu(x, y, archivePath) {
    mpCtxTarget = archivePath;
    let menu = ensureCtxMenu();
    menu.style.display = 'block';
    /* Force layout to get size before positioning */
    let w = menu.offsetWidth;
    let h = menu.offsetHeight;
    let maxX = window.innerWidth - w - 8;
    let maxY = window.innerHeight - h - 8;
    menu.style.left = Math.min(x, Math.max(0, maxX)) + 'px';
    menu.style.top = Math.min(y, Math.max(0, maxY)) + 'px';
  }

  function closeCtxMenu() {
    if (mpCtxMenu) {
      mpCtxMenu.style.display = 'none';
    }
    mpCtxTarget = null;
  }

  /* Close context menu on any click, scroll, or Escape */
  document.addEventListener('click', closeCtxMenu, true);
  document.addEventListener('scroll', closeCtxMenu, true);
  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeCtxMenu(); });

  /* ── Right-click intercept ───────────────────────────────────── */
  document.addEventListener('contextmenu', function(e) {
    closeCtxMenu();
    /* Walk up from the target to find a .item element with archive data */
    let archivePath = getZipPathFromTarget(e.target);

    /* Also try filebrowser's data-ext attribute on .item elements */
    if (!archivePath) {
      let el = e.target;
      let depth = 0;
      while (el && depth < 10 && el !== document.body) {
        if (el.classList && el.classList.contains('item') && el.getAttribute('data-ext')) {
          let ext = (el.getAttribute('data-ext') || '').toLowerCase();
          let name = el.getAttribute('aria-label') || '';
          if (isArchive(name) || ['.zip','.tar','.gz','.tgz','.7z','.rar','.bz2','.xz'].indexOf(ext) >= 0) {
            let curDir = getCurrentDirectory();
            if (!curDir.endsWith('/')) curDir += '/';
            archivePath = curDir + name;
            break;
          }
        }
        el = el.parentElement;
        depth++;
      }
    }

    if (!archivePath) {
      archivePath = getSelectedZipPath();
    }

    if (archivePath) {
      e.preventDefault();
      e.stopPropagation();
      lastActiveZipPath = archivePath;
      openCtxMenu(e.clientX, e.clientY, archivePath);
    }
  }, true);

  /* ── Inject "Extract" button into filebrowser's header #dropdown ── */
  function injectHeaderExtractBtn() {
    let archivePath = getSelectedZipPath() || lastActiveZipPath;
    let dropdown = document.getElementById('dropdown');
    let headerEl = document.querySelector('header');

    /* Also try to find the file-selection bar on mobile */
    let fileSelectionBar = document.getElementById('file-selection');

    let containers = [dropdown, headerEl, fileSelectionBar].filter(Boolean);

    if (archivePath && containers.length > 0) {
      containers.forEach(function(container) {
        if (container.querySelector('#mp-extract-header-btn')) return;
        let btn = document.createElement('button');
        btn.id = 'mp-extract-header-btn';
        btn.type = 'button';
        btn.title = 'Extract Archive';
        btn.setAttribute('aria-label', 'Extract Archive');
        btn.style.cssText = [
          'display:inline-flex', 'align-items:center', 'gap:5px',
          'padding:7px 14px', 'margin:0 4px',
          'background:rgba(96,165,250,0.12)', 'color:#60a5fa',
          'border:1px solid rgba(96,165,250,0.25)', 'border-radius:6px',
          'font:inherit', 'font-size:13px', 'font-weight:500',
          'cursor:pointer', 'transition:all 0.15s ease',
          'white-space:nowrap'
        ].join(';') + ';';
        btn.innerHTML = '<i class="material-icons" style="font-size:18px;">unarchive</i><span>Extract</span>';
        btn.addEventListener('mouseenter', function() {
          this.style.background = 'rgba(96,165,250,0.25)';
          this.style.borderColor = 'rgba(96,165,250,0.45)';
        });
        btn.addEventListener('mouseleave', function() {
          this.style.background = 'rgba(96,165,250,0.12)';
          this.style.borderColor = 'rgba(96,165,250,0.25)';
        });
        btn.addEventListener('click', function(ev) {
          ev.preventDefault();
          ev.stopPropagation();
          doExtract(archivePath);
        });

        /* Insert before the "more" button if it exists */
        let moreBtn = container.querySelector('#more');
        if (moreBtn) {
          container.insertBefore(btn, moreBtn);
        } else {
          container.appendChild(btn);
        }
      });
    } else {
      /* Remove if no archive selected */
      document.querySelectorAll('#mp-extract-header-btn').forEach(function(el) { el.remove(); });
    }
  }

  /* Poll for selection changes — filebrowser uses Vue reactivity so we can't
     get events, but we can detect selection via aria-selected attributes */
  setInterval(function() {
    let selected = document.querySelectorAll('.item[aria-selected="true"]');
    let hasArchive = false;
    selected.forEach(function(item) {
      let ext = (item.getAttribute('data-ext') || '').toLowerCase();
      let name = item.getAttribute('aria-label') || '';
      if (isArchive(name) || ['.zip','.tar','.gz','.tgz','.7z','.rar','.bz2','.xz'].indexOf(ext) >= 0) {
        hasArchive = true;
        let curDir = getCurrentDirectory();
        if (!curDir.endsWith('/')) curDir += '/';
        lastActiveZipPath = curDir + name;
      }
    });
    if (!hasArchive && selected.length > 0) {
      lastActiveZipPath = null;
    }
    injectHeaderExtractBtn();
  }, 500);

  async function doExtract(filePath) {
    let zipName = filePath.split('/').pop();
    showToast("Extracting " + zipName + "...", "info");
    try {
      let res = await fetch("/files/api/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: filePath })
      });
      let text = await res.text();
      let data = {};
      try {
        data = JSON.parse(text);
      } catch (e) {
        data = { error: text || "Invalid response format" };
      }
      if (res.ok && data.success) {
        showToast(data.message || "Extracted successfully!", "success");
        setTimeout(() => {
          let reloadBtn = document.querySelector('button[title*="Refresh"]') || document.querySelector('button[aria-label*="Refresh"]') || document.querySelector('#reload-button');
          if (reloadBtn) {
            reloadBtn.click();
          } else {
            window.location.reload();
          }
        }, 600);
      } else {
        showToast("Extraction failed: " + (data.error || data.message || "Unknown error"), "error");
      }
    } catch (err) {
      showToast("Error extracting file: " + err.message, "error");
    }
  }

  function showToast(msg, type) {
    let toast = document.getElementById('mp-extract-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'mp-extract-toast';
      toast.style.cssText = 'position:fixed;bottom:24px;right:24px;padding:12px 20px;background:#1e293b;color:#fff;border-radius:6px;font-family:sans-serif;font-size:14px;box-shadow:0 4px 12px rgba(0,0,0,0.3);z-index:99999;transition:all 0.3s ease;';
      document.body.appendChild(toast);
    }
    if (type === 'error') toast.style.background = '#ef4444';
    else if (type === 'success') toast.style.background = '#10b981';
    else toast.style.background = '#3b82f6';
    toast.innerText = msg;
    toast.style.display = 'block';
    toast.style.opacity = '1';
    if (type !== 'info') {
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => { toast.style.display = 'none'; }, 300);
      }, 4000);
    }
  }
})();
"""


