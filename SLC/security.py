import re
import hashlib
import hmac
import secrets


def validate_username(username):
    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return False, (
            "Username must be 3-30 characters "
            "and contain only letters, numbers, and underscores."
        )

    return True, username


def validate_password(password):
    if len(password) < 10:
        return False, "Password must contain at least 10 characters."

    if len(password) > 128:
        return False, "Password must not exceed 128 characters."

    return True, "Password accepted."


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )

    return salt.hex(), password_hash.hex()


def verify_password(password, salt_hex, stored_hash):
    try:
        salt = bytes.fromhex(salt_hex)
        _, calculated_hash = hash_password(password, salt)

        return hmac.compare_digest(calculated_hash, stored_hash)

    except (ValueError, TypeError):
        return False


def validate_asset_id(asset_id):
    return bool(
        re.fullmatch(r"AST[0-9]{3,6}", asset_id.strip().upper())
    )


def validate_borrower_id(borrower_id):
    return bool(
        re.fullmatch(r"BRW[0-9]{3,6}", borrower_id.strip().upper())
    )