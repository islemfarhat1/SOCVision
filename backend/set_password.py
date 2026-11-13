"""
Change le mot de passe d'un compte SOCVision.

Usage (depuis backend/) :
    python set_password.py <username>
    python set_password.py --all      # même nouveau mot de passe pour tous les comptes
"""

import getpass
import sqlite3
import sys

import bcrypt

from config.settings import DATABASE_PATH


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 1

    target = sys.argv[1]
    conn = sqlite3.connect(DATABASE_PATH)
    if target == "--all":
        usernames = [r[0] for r in conn.execute("SELECT username FROM users")]
    else:
        usernames = [r[0] for r in conn.execute("SELECT username FROM users WHERE username = ?", (target,))]
    if not usernames:
        print(f"Unknown user: {target}")
        return 1

    password = getpass.getpass("New password: ")
    if len(password) < 10:
        print("Password must be at least 10 characters.")
        return 1
    if password != getpass.getpass("Confirm: "):
        print("Passwords do not match.")
        return 1

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn.executemany("UPDATE users SET password_hash = ? WHERE username = ?", [(hashed, u) for u in usernames])
    conn.commit()
    conn.close()
    print(f"Password updated for: {', '.join(usernames)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
