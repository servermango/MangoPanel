import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mangopanel.config import load_config
from mangopanel.db import seed_dev_data


def main():
    config = load_config()
    seed_dev_data(config.db_path, config.account_root)
    print(f"Seeded development database at {config.db_path}")
    print("Admin: admin@mango.test / ChangeMe-DevOnly-123! / TOTP 000000 in dev test mode")
    print("Client: owner@example.mango.test / ChangeMe-DevOnly-123! / TOTP 000000 in dev test mode")


if __name__ == "__main__":
    main()
