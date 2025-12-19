# crypto_utils.py
"""Crypto helpers used by the Encrypted Messaging CLI."""

import os
import json
import base64
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DIR = "keys"


def ensure_key_dir() -> None:
    os.makedirs(KEY_DIR, exist_ok=True)


# ----- RSA helpers -----
def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename: str, password: Optional[bytes] = None) -> None:
    ensure_key_dir()
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    with open(filename, "wb") as f:
        f.write(pem)
    os.chmod(filename, 0o600)


def save_public_key(public_key, filename: str) -> None:
    ensure_key_dir()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filename, "wb") as f:
        f.write(pem)
    os.chmod(filename, 0o644)


def load_private_key(filename: str, password: Optional[bytes] = None):
    with open(filename, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password)


def load_public_key_from_pem_bytes(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def public_key_fingerprint(public_key) -> str:
    """Return a short hex fingerprint for manual verification (SHA-256, hex truncated)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pem)
    fp = digest.finalize().hex()
    return fp[:32]


# ----- RSA encrypt/decrypt (OAEP) -----
def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


# ----- AES-GCM helpers -----
def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> dict:
    # AESGCM requires a 12-byte nonce
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ct).decode()}


def aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str, associated_data: Optional[bytes] = None) -> bytes:
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)


# ----- Helpers for serializing keys or session blob -----
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def ub64(s: str) -> bytes:
    return base64.b64decode(s)


def make_session_blob(aes_key: bytes) -> str:
    # produce a JSON blob of base64-encoded session key
    return json.dumps({"k": b64(aes_key)})


def parse_session_blob(blob: str) -> bytes:
    j = json.loads(blob)
    return ub64(j["k"])

