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


FILEBROWSER_CUSTOM_JS = """(function () {
  let activeZipPath = null;

  function isArchive(name) {
    if (!name) return false;
    name = name.toLowerCase().trim();
    return (
      name.endsWith('.zip') ||
      name.endsWith('.tar.gz') ||
      name.endsWith('.tgz') ||
      name.endsWith('.tar') ||
      name.endsWith('.gz') ||
      name.endsWith('.7z') ||
      name.endsWith('.rar')
    );
  }

  function getZipPathFromTarget(target) {
    if (!target) return null;
    let item = target.closest('.item') || target.closest('[data-ext]') || target.closest('tr') || target.closest('li') || target.closest('div[aria-label]');
    if (!item) return null;

    let ext = (item.getAttribute('data-ext') || '').toLowerCase();
    let name = '';

    let nameEl = item.querySelector('.name') || item.querySelector('.filename') || item.querySelector('span');
    if (nameEl) {
      name = (nameEl.innerText || nameEl.textContent || '').trim();
    }

    if (!name && item.getAttribute('aria-label')) {
      name = item.getAttribute('aria-label').trim();
    }
    if (!name && item.getAttribute('title')) {
      name = item.getAttribute('title').trim();
    }

    if (!name) {
      let text = (item.innerText || item.textContent || '').trim().split('\\n')[0];
      if (isArchive(text)) {
        name = text;
      }
    }

    if (!name && (ext === 'zip' || ext === 'gz' || ext === 'tar')) {
      name = (item.innerText || item.textContent || '').trim().split('\\n')[0];
    }

    if (name && (isArchive(name) || ext === 'zip' || ext === 'gz' || ext === 'tar')) {
      let curDir = getCurrentDirectory();
      if (!curDir.endsWith('/')) curDir += '/';
      return curDir + name;
    }
    return null;
  }

  function getCurrentDirectory() {
    let p = window.location.pathname || '';
    let raw = '';
    if (p.includes('/files/files/')) {
      raw = p.split('/files/files/')[1] || '';
    } else if (p.startsWith('/files/files')) {
      raw = p.replace('/files/files', '');
    } else if (p.startsWith('/files/')) {
      raw = p.replace('/files/', '');
    }
    raw = decodeURIComponent(raw.split('?')[0].split('#')[0]);
    if (!raw.startsWith('/')) raw = '/' + raw;
    return raw;
  }

  document.addEventListener('contextmenu', function (e) {
    let zipPath = getZipPathFromTarget(e.target);
    if (!zipPath) {
      let selected = document.querySelector('.item[aria-selected="true"]') || document.querySelector('.item.selected');
      if (selected) {
        zipPath = getZipPathFromTarget(selected);
      }
    }
    if (zipPath) {
      activeZipPath = zipPath;
    } else {
      activeZipPath = null;
    }
    setTimeout(tryInjectExtractOption, 50);
    setTimeout(tryInjectExtractOption, 150);
    setTimeout(tryInjectExtractOption, 300);
  }, true);

  function tryInjectExtractOption() {
    if (!activeZipPath) return;
    let menu = document.querySelector('.context-menu');
    if (!menu) return;
    if (menu.querySelector('#mp-extract-btn')) return;

    let btn = document.createElement('button');
    btn.id = 'mp-extract-btn';
    btn.type = 'button';
    btn.className = 'action';
    btn.style.cssText = 'display:flex;align-items:center;width:100%;padding:8px 16px;background:none;border:none;color:inherit;font:inherit;cursor:pointer;text-align:left;';
    btn.innerHTML = '<i class="material-icons" style="margin-right:10px;">unarchive</i><span>Extract</span>';

    btn.addEventListener('click', function (ev) {
      ev.preventDefault();
      ev.stopPropagation();
      menu.style.display = 'none';
      let path = activeZipPath;
      activeZipPath = null;
      doExtract(path);
    });

    menu.appendChild(btn);
  }

  let observer = new MutationObserver(function (mutations) {
    for (let m of mutations) {
      for (let node of m.addedNodes) {
        if (node.nodeType === 1) {
          if (node.classList && node.classList.contains('context-menu')) {
            tryInjectExtractOption();
          } else if (node.querySelector && node.querySelector('.context-menu')) {
            tryInjectExtractOption();
          }
        }
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

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


