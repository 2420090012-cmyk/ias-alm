# CipherGuard — IAS Security Lab

An original academic cybersecurity learning suite inspired by the module structure of the reference IAS ALM-2 repository. It contains three interactive modules: **CryptoVault**, **SecureTunnel**, and **Sentinel**.

## Features

### 1. CryptoVault
- Generate RSA-2048 public/private key pairs.
- RSA-OAEP encryption and decryption (SHA-256).
- RSA-PSS digital signatures and verification.
- Generate a short-lived self-signed X.509 demo certificate.
- SHA-256, SHA-512 and SHA3-256 hashing.
- Diffie–Hellman finite-field exchange illustration.
- ElGamal signature classroom demonstration.

### 2. SecureTunnel
- Step-through TLS 1.3 handshake explanation.
- Step-through SSH handshake explanation.
- IPsec ESP Transport vs Tunnel mode packet visualization.

### 3. Sentinel
- SQLite-backed firewall rule manager (IP/CIDR, port, protocol, ALLOW/BLOCK).
- Packet simulation with newest matching rule taking precedence.
- Rule-based alerts for Telnet traffic and simulated failed logins.
- Simple per-source traffic-volume anomaly demonstration.
- Packet log, alert feed and traffic counters.

## Requirements
- Python 3.10+
- Node.js 18+

## Run locally

### Terminal 1 — backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Backend: `http://127.0.0.1:5000`

### Terminal 2 — frontend
```bash
cd frontend
npm install
npm run dev
```
Open the Vite URL shown in the terminal (normally `http://localhost:5173`). Keep both terminals running.

## Demo walkthrough
1. Open CryptoVault and generate an RSA key pair.
2. Encrypt a message with the public key, then decrypt it with the private key.
3. Sign the message and verify it. Change the message before verification to see the failure.
4. Generate a hash and compare the digest after changing one character.
5. Generate a Diffie–Hellman exchange and compare Alice's and Bob's shared secrets.
6. Open SecureTunnel and step through TLS and SSH. Compare IPsec transport and tunnel modes.
7. Open Sentinel. Add a BLOCK rule for `*` to `*` on TCP port `443`; simulate a packet on port 443.
8. Simulate traffic on port `23` to trigger a Telnet alert. Tick failed SSH login to create a login alert.
9. Send at least five packets from one source, then a much larger packet to demonstrate the anomaly threshold.

## API overview
| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Backend status |
| `/api/hash` | POST | SHA digest |
| `/api/rsa/generate` | POST | Generate RSA key pair |
| `/api/rsa/encrypt` | POST | RSA-OAEP encryption |
| `/api/rsa/decrypt` | POST | RSA-OAEP decryption |
| `/api/rsa/sign` | POST | RSA-PSS signature |
| `/api/rsa/verify` | POST | Verify signature |
| `/api/certificate` | POST | Self-signed demo certificate |
| `/api/dh` | GET | Diffie–Hellman illustration |
| `/api/elgamal` | POST | ElGamal teaching demo |
| `/api/tunnel/tls` | GET | TLS handshake stages |
| `/api/tunnel/ssh` | GET | SSH handshake stages |
| `/api/ipsec` | GET | IPsec mode description |
| `/api/firewall` | GET/POST | List or add firewall rules |
| `/api/firewall/{id}` | DELETE | Delete a firewall rule |
| `/api/traffic` | POST | Simulate packet and run IDS checks |
| `/api/ids/dashboard` | GET | Recent packets, alerts and counts |
| `/api/reset-demo` | POST | Clear demo firewall rules and logs |

## Important security limitations
This is a **classroom simulator**, not a production security product. The Sentinel module does not capture, transmit, or block real network packets and does not alter the operating-system firewall. TLS and SSH modules explain handshake stages but do not establish real network connections. Diffie–Hellman and ElGamal use deliberately small teaching parameters and are insecure. The self-signed certificate is not issued by a trusted CA. Do not use real passwords, private keys, or sensitive data in this demo. The RSA operations use the `cryptography` library's standard RSA primitives; do not treat the surrounding demo application as hardened key-management software.

## Customization
Update the project title and add your name, roll number, department, and course details to this README before submission. Do not claim features you have not tested or demonstrated.
