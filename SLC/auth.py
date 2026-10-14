import sqlite3

from database import (
    create_user,
    get_user_by_username,
    log_action
)

from security import (
    validate_username,
    validate_password,
    hash_password,
    verify_password
)


def register_user(username, password):
    username = username.strip()

    valid, message = validate_username(username)

    if not valid:
        return False, message

    valid, message = validate_password(password)

    if not valid:
        return False, message

    salt, password_hash = hash_password(password)

    try:
        user_id = create_user(
            username,
            salt,
            password_hash,
            role="student"
        )

        log_action(
            user_id,
            username,
            "REGISTER",
            "Student account created"
        )

        return True, "Account created successfully. Please log in."

    except sqlite3.IntegrityError:
        return False, "Username already exists. Choose another username."


def authenticate(username, password):
    username = username.strip()

    if not username or not password:
        return None

    user = get_user_by_username(username)

    if user is None:
        return None

    if not verify_password(
        password,
        user["salt"],
        user["password_hash"]
    ):
        return None

    log_action(
        user["id"],
        user["username"],
        "LOGIN",
        "Successful login"
    )

    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }