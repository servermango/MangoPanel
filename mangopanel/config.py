import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Config:
    def __init__(self):
        self.env = os.getenv("MP_ENV", "development")
        self.host = os.getenv("MP_HOST", "127.0.0.1")
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
        self.account_port_base = int(os.getenv("MP_ACCOUNT_PORT_BASE", "18000"))
        self.compose_project_prefix = os.getenv("MP_COMPOSE_PROJECT_PREFIX", "mp")
        self.jwt_secret = os.getenv("MP_JWT_SECRET", "dev-only-change-me")
        self.dev_auth_test_mode = os.getenv("MP_DEV_AUTH_TEST_MODE", "false").lower() == "true"
        self.token_ttl_seconds = int(os.getenv("MP_TOKEN_TTL_SECONDS", "3600"))
        self.totp_challenge_ttl_seconds = int(os.getenv("MP_TOTP_CHALLENGE_TTL_SECONDS", "300"))
    @property
    def is_development(self):
        return self.env == "development"


def load_config():
    return Config()
