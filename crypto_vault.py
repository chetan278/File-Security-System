import os
import io
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_SECRET = os.environ.get("AEGIS_MASTER_KEY", "AegisPortal_SuperSecret_2026_Key").encode("utf-8")


def _derive_aes256_key(salt: bytes) -> bytes:
    """Derives a 256-bit (32-byte) AES key using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=MASTER_SECRET,
        salt=salt,
        iterations=200_000,
        dklen=32,
    )


def encrypt_to_aes256_blob(plaintext_str: str) -> str:
    """
    Encrypts plaintext string with AES-256-GCM and returns base64 string.
    Format: base64(salt [16B] + nonce [12B] + ciphertext_with_tag)
    """
    if plaintext_str is None:
        plaintext_str = ""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_aes256_key(salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_str.encode("utf-8"), associated_data=None)

    payload = salt + nonce + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt_from_aes256_blob(enc_blob: str) -> str:
    """Decrypts an AES-256-GCM base64 blob strictly in memory without disk temp files."""
    raw = base64.b64decode(enc_blob.encode("utf-8"))
    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    key = _derive_aes256_key(salt)
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext_bytes.decode("utf-8")


def decrypt_to_ephemeral_buffer(enc_blob: str) -> io.BytesIO:
    """Decrypts content into an in-memory io.BytesIO buffer."""
    plaintext_text = decrypt_from_aes256_blob(enc_blob)
    mem_buffer = io.BytesIO(plaintext_text.encode("utf-8"))
    plaintext_text = ""
    mem_buffer.seek(0)
    return mem_buffer


def wipe_buffer(buf: io.BytesIO):
    """Overwrites memory stream with zeros and closes it."""
    if buf is None:
        return
    try:
        size = buf.getbuffer().nbytes
        if size > 0:
            buf.seek(0)
            buf.write(b"\x00" * size)
    except Exception:
        pass
    finally:
        try:
            buf.close()
        except Exception:
            pass