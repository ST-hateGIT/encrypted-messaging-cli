"""peer.py
def send_json(sock: socket.socket, obj: dict):
data = (json.dumps(obj) + "\n").encode()
sock.sendall(data)




def recv_json_line(sock: socket.socket) -> dict:
# Read until newline
buf = b""
while True:
chunk = sock.recv(4096)
if not chunk:
raise ConnectionError("socket closed")
buf += chunk
if b"\n" in buf:
line, rest = buf.split(b"\n", 1)
# leftover isn't kept — simple implementation
return json.loads(line.decode())




def handle_receive(sock: socket.socket, aes_key: bytes | None):
try:
while True:
obj = recv_json_line(sock)
if obj.get("type") == "message":
payload = obj["payload"]
# decrypt using AES-GCM
pt = aesgcm_decrypt(aes_key, payload["nonce"], payload["ciphertext"]) if aes_key else b""
print(f"\n[peer] {pt.decode()}\n> ", end="", flush=True)
else:
print("[recv] unknown msg", obj)
except Exception as e:
print("[recv] connection closed or error:", e)




def run_peer(is_server: bool, host: str, port: int):
# Ensure or create keys
if not os.path.exists(KEY_PRIV_FILE) or not os.path.exists(KEY_PUB_FILE):
priv, pub = generate_rsa_keypair()
save_private_key(priv, KEY_PRIV_FILE)
save_public_key(pub, KEY_PUB_FILE)
print("[keys] Generated new RSA keypair and saved to keys/")
else:
priv = load_private_key(KEY_PRIV_FILE)
pub = load_public_key(KEY_PUB_FILE)
print("[keys] Loaded existing RSA keypair")


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


# 1) Exchange public keys
# Send my public key PEM
with open(KEY_PUB_FILE, "rb") as f:
my_pub_pem = f.read().decode()


send_json(sock, {"type": "pubkey", "pem": my_pub_pem})
other = recv_json_line(sock)
if other.get("type") != "pubkey":
raise RuntimeError("expected pubkey from peer")
peer_pub_pem = other["pem"].encode()


# Lo
