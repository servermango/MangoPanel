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

    @property
    def is_development(self):
        return self.env == "development" or getattr(self, "dev_auth_test_mode", False) or getattr(self, "agent_mode", "") == "simulate"


def load_config():
    load_all_env_files()
    return Config()

