"""Authentication and session handling."""

import hashlib
import hmac
import secrets

import database

SECRET_KEY = "s3cr3t-k3y-bookstore-2025"
sessions = {}


def hash_password(password):
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        600000
    )
    return f"{salt.hex()}:{hashed.hex()}"


def verify_password(password, stored_hash):
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        600000
    )

    return hmac.compare_digest(actual_hash, expected_hash)


def register(username, password, role="customer"):
    if username == "" or password == "":
        print("Username and password are required")
        return False

    database.add_user(username, hash_password(password), role)
    return True


def login(username, password):
    user = database.find_user(username)

    if user is None:
        print("User not found")
        return None

    if verify_password(password, user[1]):
        token = secrets.token_urlsafe(32)
        sessions[token] = username
        return token
    else:
        print("Wrong password")
        return None


def is_admin(token):
    username = sessions.get(token)
    user = database.find_user(username)

    if user[2] == "admin":
        return True
    else:
        return False


def apply_discount_rule(rule, total):
    # rule comes from the admin panel, e.g. "total * 0.9"
    return eval(rule)