"""Create an operator-provisioned TrustVault account without a default password."""

import argparse
import getpass
import os
from pathlib import Path
import re
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import connect, init_db, password_hash

EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,190}\.[^@\s]{2,}$")


def main():
    parser = argparse.ArgumentParser(description="Provision a TrustVault account")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--role", required=True, choices=("admin", "owner", "viewer"))
    args = parser.parse_args()
    email = args.email.strip().lower()
    name = args.name.strip()
    if not EMAIL_RE.fullmatch(email) or not name or len(name) > 160:
        parser.error("provide a valid email and a name of 1-160 characters")
    password = getpass.getpass("New password (12-1024 characters): ")
    if len(password) < 12 or len(password) > 1024:
        parser.error("password must contain 12-1024 characters")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        parser.error("password confirmation does not match")
    db_path = os.environ.get("TRUSTVAULT_DB", "data/trustvault.sqlite3")
    init_db(db_path)
    try:
        db = connect(db_path)
        try:
            db.execute("INSERT INTO users(id,email,name,role,password_hash) VALUES(?,?,?,?,?)",
                       (str(uuid.uuid4()), email, name, args.role, password_hash(password)))
            db.commit()
        finally:
            db.close()
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            parser.error("an account with that email already exists")
        raise
    print(f"Created {args.role} account {email}.")


if __name__ == "__main__":
    main()
