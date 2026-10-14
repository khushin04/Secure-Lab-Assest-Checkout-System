from getpass import getpass
import sqlite3

from database import (
    initialize_database,
    create_user,
    log_action,
    get_connection,
)
from security import (
    validate_username,
    validate_password,
    hash_password,
)

initialize_database()

with get_connection() as conn:
    admin = conn.execute(
        "SELECT id FROM users WHERE role = ? LIMIT 1",
        ("admin",),
    ).fetchone()

if admin:
    print("An admin account already exists.")
    print("Use that admin account to log in.")
    raise SystemExit(0)

username = input("Enter new admin username: ").strip()
password = getpass("Enter new admin password: ")

valid, message = validate_username(username)
if not valid:
    print(message)
    raise SystemExit(1)

valid, message = validate_password(password)
if not valid:
    print(message)
    raise SystemExit(1)

salt, password_hash = hash_password(password)

try:
    admin_id = create_user(
        username,
        salt,
        password_hash,
        role="admin",
    )

    log_action(
        admin_id,
        username,
        "ADMIN_CREATED",
        "Administrator account created",
    )

    print("Admin account created successfully!")
    print("Username:", username)
    print("Now log in to the Streamlit application.")

except sqlite3.IntegrityError:
    print("This username already exists. Choose a different username.")