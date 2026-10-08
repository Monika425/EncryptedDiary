import base64
import hashlib
import os
from cryptography.fernet import Fernet


def create_key(password, salt):
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100000
    )

    return base64.urlsafe_b64encode(key)


def encrypt_text(text, password, salt):
    key = create_key(password, salt)

    cipher = Fernet(key)

    encrypted = cipher.encrypt(
        text.encode("utf-8")
    )

    return encrypted.decode("utf-8")


def decrypt_text(encrypted_text, password, salt):
    key = create_key(password, salt)

    cipher = Fernet(key)

    decrypted = cipher.decrypt(
        encrypted_text.encode("utf-8")
    )

    return decrypted.decode("utf-8")


def get_master_key():
    secret = os.getenv(
        "SECRET_KEY",
        "local-demo-secret-key"
    )

    raw = hashlib.sha256(
        secret.encode("utf-8")
    ).digest()

    return base64.urlsafe_b64encode(raw)


def protect_key(key):
    cipher = Fernet(get_master_key())

    return cipher.encrypt(key).decode("utf-8")


def unprotect_key(value):
    cipher = Fernet(get_master_key())

    return cipher.decrypt(
        value.encode("utf-8")
    )