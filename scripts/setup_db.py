"""Initialize the TrustVault schema; optionally insert local-only demo accounts."""

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import init_db, seed_users


def main():
    parser = argparse.ArgumentParser(description="Initialize the TrustVault SQLite database")
    parser.add_argument("--demo-users", action="store_true",
                        help="insert local-only demo accounts (never use on a public deployment)")
    args = parser.parse_args()
    db_path = os.environ.get("TRUSTVAULT_DB", "data/trustvault.sqlite3")
    init_db(db_path)
    if args.demo_users:
        seed_users(db_path)
        print(f"Initialized {db_path} and inserted local demo accounts.")
    else:
        print(f"Initialized schema at {db_path}; no accounts were created.")


if __name__ == "__main__":
    main()
