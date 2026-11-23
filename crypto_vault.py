import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_file_key():
    configured_key = os.environ.get("AEGIS_FILE_KEY", "").strip()
    if configured_key:
        return hashlib.sha256(configured_key.encode("utf-8")).digest()
    key_path = os.path.join(PROJECT_DIR, ".aegis_file_key")
    if not os.path.exists(key_path):
        try:
            descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(secrets.token_bytes(32))
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    if len(key) != 32:
        raise ValueError("The protected-file encryption key is invalid.")
    return key


def encrypt_file_copy(file_id, filename, filepath, cursor):
    with open(filepath, "rb") as source:
        content = source.read()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(get_file_key()).encrypt(nonce, content, filename.encode("utf-8"))
    cursor.execute(
        """INSERT INTO protected_file_blobs(file_id,nonce,ciphertext,content_hash)
           VALUES(?,?,?,?) ON CONFLICT(file_id) DO UPDATE SET nonce=excluded.nonce,
           ciphertext=excluded.ciphertext,content_hash=excluded.content_hash""",
        (file_id, nonce, ciphertext, hashlib.sha256(content).hexdigest()),
    )


def verify_encrypted_copy(filename, nonce, ciphertext, expected_hash):
    content = AESGCM(get_file_key()).decrypt(nonce, ciphertext, filename.encode("utf-8"))
    actual_hash = hashlib.sha256(content).hexdigest()
    return hmac.compare_digest(actual_hash, expected_hash)
