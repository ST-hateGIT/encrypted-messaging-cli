# peer.py
# Encrypted Messaging CLI - server/client peer using RSA & AES-GCM

import argparse
import socket
import threading
import json
import os
import base64
from typing import Optional

from crypto_utils import (
    generate_rsa_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key_from_pem_bytes,
    public_key_fingerprint,
    rsa_encrypt,
    rsa_decrypt,
    aesgcm_encrypt,
    aesgcm_decrypt,
    make_session_blob,
    parse_session_blob,
    KEY_DIR,
)

KEY_PRIV_FILE = os.path.join(KEY_DIR, "my_private.pem")
KEY_PUB_FILE = os.path.join(KEY_DIR, "my_public.pem")


def send_json(sock: socket.socket, obj: dict) -> None:
    data = (json.dumps(obj) + "\n").encode()
    sock.sendall(data)


class SocketLineReader:
    """Simple newline-delimited JSON reader with internal buffer."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def recv_json_line(self) -> dict:
        while True:
            if b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                return json.loads(line.decode())
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed")
            self.buf += chunk


def handle_receive(sock: socket.socket, reader: SocketLineReader, aes_key: Optional[bytes]) -> None:
    try:
        while True:
            obj = reader.recv_json_line()
            if obj.get("type") == "message":
                payload = obj["payload"]
                if aes_key is None:
                    print("\n[peer] Received message but no AES key established.\n> ", end="", flush=True)
                    continue
                try:
                    pt = aesgcm_decrypt(aes_key, payload["nonce"], payload["ciphertext"])
                    print(f"\n[peer] {pt.decode()}\n> ", end="", flush=True)
                except Exception as e:
                    print(f"\n[peer] Failed to decrypt message: {e}\n> ", end="", flush=True)
            else:
                print(f"\n[peer] Received control message: {obj}\n> ", end="", flush=True)
    except Exception as e:
        print(f"\n[recv] connection closed or error: {e}")


def ensure_keys() -> tuple:
    if not os.path.exists(KEY_PRIV_FILE) or not os.path.exists(KEY_PUB_FILE):
        priv, pub = generate_rsa_keypair()
        save_private_key(priv, KEY_PRIV_FILE)
        save_public_key(pub, KEY_PUB_FILE)
        print("[keys] Generated new RSA keypair and saved to keys/")
        return priv, pub
    priv = load_private_key(KEY_PRIV_FILE)
    with open(KEY_PUB_FILE, "rb") as f:
        pem = f.read()
    pub = load_public_key_from_pem_bytes(pem)
    print("[keys] Loaded existing RSA keypair")
    return priv, pub


def run_peer(is_server: bool, host: str, port: int) -> None:
    priv, pub = ensure_keys()

    if is_server:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen(1)
        print(f"[server] Listening on {host}:{port} — waiting for connection...")
        conn, addr = s.accept()
        print("[server] Connection from", addr)
        sock = conn
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print("[client] Connected to", (host, port))

    reader = SocketLineReader(sock)

    # Exchange public keys
    with open(KEY_PUB_FILE, "rb") as f:
        my_pub_pem = f.read().decode()

    # send our pubkey
    send_json(sock, {"type": "pubkey", "pem": my_pub_pem})
    # receive peer pubkey
    other = reader.recv_json_line()
    if other.get("type") != "pubkey":
        raise RuntimeError("expected pubkey from peer")
    peer_pub_pem = other["pem"].encode()
    peer_pub = load_public_key_from_pem_bytes(peer_pub_pem)

    print("[keys] Peer public key fingerprint:", public_key_fingerprint(peer_pub))
    print("[info] Verify this fingerprint out-of-band if you want to avoid MITM")

    # establish AES session key: client initiates
    aes_key: Optional[bytes] = None
    if not is_server:
        aes_key = os.urandom(32)  # AES-256
        blob = make_session_blob(aes_key)
        enc = rsa_encrypt(peer_pub, blob.encode())
        send_json(sock, {"type": "session", "blob": base64.b64encode(enc).decode()})
        print("[session] Sent encrypted session blob to peer")
        # After sending, both sides use same AES key
    else:
        obj = reader.recv_json_line()
        if obj.get("type") == "session":
            enc = base64.b64decode(obj["blob"].encode())
            try:
                blob = rsa_decrypt(priv, enc).decode()
                aes_key = parse_session_blob(blob)
                print("[session] Received and decrypted session key")
            except Exception as e:
                print("[session] Failed to decrypt session blob:", e)
                raise

    # start receiving thread
    recv_thread = threading.Thread(target=handle_receive, args=(sock, reader, aes_key), daemon=True)
    recv_thread.start()

    try:
        while True:
            msg = input("> ")
            if not msg:
                continue
            if aes_key is None:
                print("[error] AES key not established yet.")
                continue
            payload = aesgcm_encrypt(aes_key, msg.encode())
            send_json(sock, {"type": "message", "payload": payload})
    except KeyboardInterrupt:
        print("\n[peer] Exiting")
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("server", "client"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    run_peer(args.mode == "server", args.host, args.port)

