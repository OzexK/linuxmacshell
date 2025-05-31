#  MACShell – Covert MAC-Based Shell Over Ethernet (Layer 2) V0.1

**MACShell** is a stealthy command-and-control shell that operates purely over Layer 2 (Ethernet), bypassing IP-based monitoring and filtering. It uses raw MAC frames for communication and AES encryption for confidentiality — making it ideal for red team engagements and low-noise post-exploitation.

---

##  Features

-  AES-256 encrypted payloads using `Fernet`
-  Pure Layer 2 communication — no IP, TCP, or UDP
-  Custom EtherType `0x1234` for covert signaling
-  Interactive shell interface between server and agent
-  Multi-threaded response sniffer with queuing
-  Linux-only support (tested on Kali)

---

## ⚠️ Disclaimer

> This tool is provided for **educational and authorized penetration testing purposes only**.  
> Unauthorized usage is strictly prohibited. Use at your own risk.

---

## 📦 Requirements

### Agent & Server (Linux)
- Python 3.8+
- [`scapy`](https://scapy.net/)
- [`cryptography`](https://pypi.org/project/cryptography/)

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

##  How It Works

1. The **agent** sends a `hello` packet using a custom EtherType `0x1234`.
2. The **server** listens, learns the agent's MAC, and initiates an interactive shell.
3. All communication (commands/responses) is encrypted with AES and transmitted via Ethernet frames.
4. Raw sockets are used to craft and sniff packets using Scapy.

---

##  AES Key Sharing

The AES key is pre-shared in both scripts using Python’s `Fernet`:

```python
key = b"q3yHiYdGNwFqkugDaG9f6_PRAolbQkAe6bQYRE3GE9s="  # Replace for real ops
```

To generate your own key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

##  Usage

### 1. Start the Agent (on the target)
```bash
sudo python3 agent.py
```

### 2. Start the Server (on the attacker box)
```bash
sudo python3 server.py
```

### 3. Command Shell Example
```bash
agent> whoami
agent> uname -a
agent> id
```
## 🎬 Demo

![MACShell Demo](assets/demo.gif)

---

##  Testing Notes

- Both agent and server **must be on the same Ethernet segment (L2)**.
- Ensure the correct `iface` (e.g., `eth0`, `ens33`) is set in both scripts.
- Traffic may **not work over `tun0` or Wi-Fi** unless in promiscuous mode.
- Packets typically **bypass firewalls/iptables** due to operating below IP.

---

##  Limitations & Detection

-  May be detected by advanced IDS/IPS inspecting raw Ethernet frames.
-  Can be blocked by network devices filtering unknown EtherTypes.
-  Switches with MAC learning/flood protection may hinder operation.

---

##  Tip for Stealth

- Avoid default EtherType `0x1234` in real-world scenarios.
- Use obfuscation, encryption rotation, and randomized beaconing for better OpSec.

---

Made with ❤️ by [Ozex](https://github.com/OzexK) for educational red teaming.
