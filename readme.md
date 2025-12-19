
# Encrypted Messaging CLI (RSA + AES Hybrid)

## Project Description
This project is a secure command-line messaging application that uses
hybrid cryptography. RSA is used for secure key exchange, and AES is used
for encrypting message content to ensure confidentiality.

## Features
- Hybrid encryption (RSA + AES)
- Secure key generation and storage
- Encrypted message exchange between client and server
- CLI-based interaction
- Good security practices

## Installation / Setup

1. python3 -m venv .venv && source .venv/bin/activate ( To activate Venv)
2. pip install -r requirements.txt
3. In terminal A: python peer.py --mode server --port 5000
4. In terminal B: python peer.py --mode client --host 127.0.0.1 --port 5000


Type messages and press enter to send. Ctrl-C to quit.
