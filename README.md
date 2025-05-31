# 🕵️ MACShell – Covert MAC-based Shell over Ethernet (L2)

MACShell is a covert command-and-response shell that communicates at Layer 2 (Ethernet) using raw MAC frames. It's designed for stealth operations where IP traffic may be monitored or blocked. This tool leverages `Scapy` and AES encryption for secure and low-level communication.

## 🚀 Features
- Pure Layer 2 communication (no IP/TCP/UDP)
- AES-256 encrypted payloads
- Covert agent discovery using custom EtherType `0x1234`
- Interactive shell from agent to server
- Secure response channel with response queuing
- Linux support only (tested on Kali)

## ⚠️ Disclaimer
This tool is for **educational and authorized penetration testing purposes only**. Misuse of this code is prohibited.

---

## 📦 Requirements

### Agent & Server (Linux)
- Python 3.8+
- [Scapy](https://scapy.net/)
- [cryptography](https://pypi.org/project/cryptography/)

### Install
```bash
pip install -r requirements.txt
