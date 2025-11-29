"""crypto_utils.py
with open(filename, "rb") as f:
data = f.read()
return serialization.load_pem_public_key(data)




def public_key_fingerprint(public_key) -> str:
"""Return a short hex fingerprint for manual verification (SHA-256, hex truncated).
"""
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


def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> dict:
# AESGCM requires a 12-byte nonce
nonce = os.urandom(12)
aesgcm = AESGCM(key)
ct = aesgcm.encrypt(nonce, plaintext, associated_data)
return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ct).decode()}




def aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str, associated_data: bytes | None = None) -> bytes:
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
# produce a JSON blob of base64-encoded session key (could include extras like ttl)
return json.dumps({"k": b64(aes_key)})




def parse_session_blob(blob: str) -> bytes:
j = json.loads(blob)
return ub64(j["k"])
