import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent / "lab_assets.db"


def get_connection():
    connection = sqlite3.connect(
        str(DB_PATH),
        timeout=10
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")

    return connection


def initialize_database():
    with get_connection() as conn:

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student'
                    CHECK(role IN ('admin', 'student')),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Available'
                    CHECK(status IN (
                        'Available', 'Checked Out', 'Maintenance'
                    )),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS checkout_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                asset_id INTEGER NOT NULL,
                request_date TEXT NOT NULL,
                due_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending'
                    CHECK(status IN (
                        'Pending', 'Approved', 'Rejected',
                        'Returned'
                    )),
                approved_by INTEGER,
                return_date TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(asset_id) REFERENCES assets(id),
                FOREIGN KEY(approved_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_checkout_user
            ON checkout_requests(user_id);

            CREATE INDEX IF NOT EXISTS idx_checkout_asset
            ON checkout_requests(asset_id);

            CREATE INDEX IF NOT EXISTS idx_checkout_status
            ON checkout_requests(status);

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_logs(timestamp);
        """)


def log_action(user_id, username, action, details):
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO audit_logs (
                user_id, username, action, details, timestamp
            )
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, username, action, details, timestamp))


def get_user_by_username(username):
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()


def create_user(username, salt, password_hash, role="student"):
    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO users (
                username, salt, password_hash, role, created_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            salt,
            password_hash,
            role,
            datetime.now(timezone.utc).isoformat()
        ))

        return cursor.lastrowid


def get_dashboard_counts():
    with get_connection() as conn:
        total_assets = conn.execute(
            "SELECT COUNT(*) FROM assets"
        ).fetchone()[0]

        available = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE status = 'Available'"
        ).fetchone()[0]

        checked_out = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE status = 'Checked Out'"
        ).fetchone()[0]

        pending = conn.execute(
            "SELECT COUNT(*) FROM checkout_requests WHERE status = 'Pending'"
        ).fetchone()[0]

        return total_assets, available, checked_out, pending
    def add_sample_assets():
      sample_assets = [
        ("AST001", "Laptop", "Electronics"),
        ("AST002", "Projector", "Electronics"),
        ("AST003", "Keyboard", "Accessories"),
        ("AST004", "Mouse", "Accessories"),
        ("AST005", "Monitor", "Electronics"),
        ("AST006", "Webcam", "Electronics"),
        ("AST007", "Printer", "Office Equipment"),
        ("AST008", "Headphones", "Accessories"),
    ]

    with get_connection() as conn:
        for asset_code, name, category in sample_assets:
            conn.execute(
                """
                INSERT OR IGNORE INTO assets
                (asset_code, name, category, status, created_at)
                VALUES (?, ?, ?, 'Available', ?)
                """,
                (
                    asset_code,
                    name,
                    category,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )