import streamlit as st
import sqlite3
import hashlib
import secrets
import re
import pandas as pd

from pathlib import Path
from datetime import date


# ---------------- CONFIGURATION ----------------

st.set_page_config(
    page_title="Secure Lab Asset Checkout",
    page_icon="🔐",
    layout="wide"
)

DB_PATH = Path(__file__).resolve().parent / "lab_assets_checkout_v2.db"


# ---------------- DATABASE ----------------

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student'
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Available',
                created_at TEXT NOT NULL
            );
        """)


initialize_database()


# ---------------- PASSWORD SECURITY ----------------

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000
    ).hex()


def register_user(username, password):
    username = username.strip()

    if len(username) < 3:
        return False, "Username must contain at least 3 characters."

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    try:
        with get_connection() as conn:

            count = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]

            role = "admin" if count == 0 else "student"

            conn.execute("""
                INSERT INTO users
                (username, password_hash, salt, role)
                VALUES (?, ?, ?, ?)
            """, (
                username,
                password_hash,
                salt,
                role
            ))

        if role == "admin":
            return True, "Admin account created successfully!"

        return True, "Student account created successfully."

    except sqlite3.IntegrityError:
        return False, "This username already exists."


def authenticate(username, password):

    with get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username.strip(),)
        ).fetchone()

    if user is None:
        return None

    entered_hash = hash_password(
        password,
        user["salt"]
    )

    if secrets.compare_digest(
        entered_hash,
        user["password_hash"]
    ):
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }

    return None


# ---------------- ASSET HELPERS ----------------

def add_asset(asset_code, name, category):

    asset_code = asset_code.strip().upper()
    name = name.strip()

    if not re.fullmatch(r"AST\d{3,}", asset_code):
        return False, "Use Asset ID format like AST001."

    if not name:
        return False, "Asset name is required."

    if not category.strip():
        return False, "Please select a category."

    try:
        with get_connection() as conn:
            conn.execute("""
                INSERT INTO assets
                (asset_code, name, category, status, created_at)
                VALUES (?, ?, ?, 'Available', ?)
            """, (
                asset_code,
                name,
                category,
                date.today().isoformat()
            ))

        return True, f"{name} added successfully!"

    except sqlite3.IntegrityError:
        return False, "This Asset ID already exists."


def read_assets(search=""):

    with get_connection() as conn:

        if search.strip():
            term = f"%{search.strip()}%"

            rows = conn.execute("""
                SELECT asset_code, name, category, status, created_at
                FROM assets
                WHERE asset_code LIKE ?
                   OR name LIKE ?
                   OR category LIKE ?
                ORDER BY id DESC
            """, (
                term,
                term,
                term
            )).fetchall()

        else:
            rows = conn.execute("""
                SELECT asset_code, name, category, status, created_at
                FROM assets
                ORDER BY id DESC
            """).fetchall()

    return pd.DataFrame(
        [dict(row) for row in rows]
    )


# ---------------- SESSION ----------------

if "user" not in st.session_state:
    st.session_state.user = None


# ---------------- LOGIN / REGISTRATION ----------------

if st.session_state.user is None:

    st.title("🔐 Secure Lab Asset Checkout")
    st.write("Laboratory Asset Management System")

    login_tab, register_tab = st.tabs([
        "Login",
        "Create Account"
    ])

    with login_tab:

        with st.form("login_form"):

            username = st.text_input("Username")

            password = st.text_input(
                "Password",
                type="password"
            )

            login_clicked = st.form_submit_button(
                "Login",
                use_container_width=True
            )

        if login_clicked:

            user = authenticate(
                username,
                password
            )

            if user:
                st.session_state.user = user
                st.rerun()

            else:
                st.error("Invalid username or password.")

    with register_tab:

        with st.form("register_form"):

            new_username = st.text_input(
                "Choose Username"
            )

            new_password = st.text_input(
                "Create Password",
                type="password"
            )

            confirm_password = st.text_input(
                "Confirm Password",
                type="password"
            )

            register_clicked = st.form_submit_button(
                "Create Account",
                use_container_width=True
            )

        if register_clicked:

            if new_password != confirm_password:
                st.error("Passwords do not match.")

            else:

                success, message = register_user(
                    new_username,
                    new_password
                )

                if success:

                    st.success(message)

                    if "Admin account" in message:
                        st.info(
                            "Your account has admin access. "
                            "Please log in."
                        )

                else:
                    st.error(message)

    st.stop()


# ---------------- NAVIGATION ----------------

user = st.session_state.user

if user["role"] == "admin":

    pages = [
        "Dashboard",
        "Add Asset",
        "View Assets",
        "Checkout Asset",
        "Return Assets"
    ]

else:

    pages = [
        "Dashboard",
        "View Assets",
        "Checkout Asset",
        "Return Assets"
    ]


with st.sidebar:

    st.title("🔐 Secure Lab")

    st.write(f"User: {user['username']}")

    st.write(
        f"Role: {user['role'].title()}"
    )

    page = st.radio(
        "Navigation",
        pages
    )

    if st.button(
        "Logout",
        use_container_width=True
    ):
        st.session_state.user = None
        st.rerun()


# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.title("📊 Lab Asset Dashboard")

    st.write(
        f"Welcome, {user['username']}!"
    )

    with get_connection() as conn:

        total = conn.execute(
            "SELECT COUNT(*) FROM assets"
        ).fetchone()[0]

        available = conn.execute(
            "SELECT COUNT(*) FROM assets "
            "WHERE status = 'Available'"
        ).fetchone()[0]

        checked_out = conn.execute(
            "SELECT COUNT(*) FROM assets "
            "WHERE status = 'Checked Out'"
        ).fetchone()[0]

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Assets",
        total
    )

    col2.metric(
        "Available Assets",
        available
    )

    col3.metric(
        "Checked Out",
        checked_out
    )

    st.subheader("📦 Assets in Your Lab")

    assets = read_assets()

    if assets.empty:

        st.info(
            "No assets added yet. "
            "Admin can open Add Asset to add equipment."
        )

    else:

        st.dataframe(
            assets,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Download Asset Report",
            data=assets.to_csv(
                index=False
            ).encode("utf-8"),
            file_name="lab_assets.csv",
            mime="text/csv"
        )


# ---------------- ADD ASSET ----------------

elif page == "Add Asset":

    st.title("➕ Add Lab Equipment")

    st.write(
        "Add laptops, desktops, keyboards, mice, "
        "monitors, projectors and other lab equipment."
    )

    with st.form(
        "add_asset_form",
        clear_on_submit=True
    ):

        asset_code = st.text_input(
            "Asset ID",
            placeholder="AST001"
        )

        asset_name = st.text_input(
            "Asset Name",
            placeholder="HP Laptop"
        )

        category = st.selectbox(
            "Category",
            [
                "Laptop",
                "Desktop",
                "Keyboard",
                "Mouse",
                "Monitor",
                "Projector",
                "Printer",
                "CPU",
                "UPS",
                "Other"
            ]
        )

        submitted = st.form_submit_button(
            "➕ Add Asset",
            use_container_width=True
        )

    if submitted:

        success, message = add_asset(
            asset_code,
            asset_name,
            category
        )

        if success:
            st.success(message)
            st.rerun()

        else:
            st.error(message)


# ---------------- VIEW ASSETS ----------------

elif page == "View Assets":

    st.title("📦 View Lab Assets")

    search = st.text_input(
        "Search by Asset ID, name or category",
        placeholder="Example: Laptop or AST001"
    )

    assets = read_assets(search)

    st.metric(
        "Assets Found",
        len(assets)
    )

    if assets.empty:

        st.info("No assets found.")

    else:

        st.dataframe(
            assets,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Download CSV",
            data=assets.to_csv(
                index=False
            ).encode("utf-8"),
            file_name="lab_assets.csv",
            mime="text/csv"
        )


# ---------------- CHECKOUT ASSET ----------------

elif page == "Checkout Asset":

    st.title("📤 Checkout Lab Asset")

    with get_connection() as conn:

        assets = conn.execute("""
            SELECT id, asset_code, name, category
            FROM assets
            WHERE status = 'Available'
            ORDER BY name
        """).fetchall()

    if not assets:

        st.info(
            "No available assets. "
            "Ask the admin to add lab equipment."
        )

    else:

        options = {
            (
                f"{a['asset_code']} - "
                f"{a['name']} ({a['category']})"
            ): a["id"]
            for a in assets
        }

        selected = st.selectbox(
            "Select Lab Equipment",
            list(options.keys())
        )

        if st.button(
            "📤 Checkout Asset",
            use_container_width=True
        ):

            with get_connection() as conn:

                cursor = conn.execute("""
                    UPDATE assets
                    SET status = 'Checked Out'
                    WHERE id = ?
                    AND status = 'Available'
                """, (
                    options[selected],
                ))

            if cursor.rowcount == 1:

                st.success(
                    "Asset checked out successfully!"
                )

            else:

                st.warning(
                    "This asset is no longer available."
                )

            st.rerun()


# ---------------- RETURN ASSETS ----------------

elif page == "Return Assets":

    st.title("📥 Return Lab Assets")

    with get_connection() as conn:

        assets = conn.execute("""
            SELECT id, asset_code, name, category, status
            FROM assets
            WHERE status = 'Checked Out'
            ORDER BY name
        """).fetchall()

    if not assets:

        st.info(
            "No checked-out assets are available to return."
        )

    else:

        options = {
            (
                f"{a['asset_code']} - "
                f"{a['name']} ({a['category']})"
            ): a["id"]
            for a in assets
        }

        selected = st.selectbox(
            "Select Asset to Return",
            list(options.keys())
        )

        if st.button(
            "📥 Return Selected Asset",
            use_container_width=True
        ):

            with get_connection() as conn:

                cursor = conn.execute("""
                    UPDATE assets
                    SET status = 'Available'
                    WHERE id = ?
                    AND status = 'Checked Out'
                """, (
                    options[selected],
                ))

            if cursor.rowcount == 1:

                st.success(
                    "Asset returned successfully!"
                )

            else:

                st.warning(
                    "This asset has already been returned."
                )

            st.rerun()