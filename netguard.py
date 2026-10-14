#!/usr/bin/env python3
"""
NetGuard — by 0bscure
Scan devices connected to your own WiFi network and get a basic
security weakness assessment.

Permitted use: scanning your own personal network (your router) only.
Using this tool on networks you do not own or do not have explicit
permission to test is illegal in most jurisdictions and unethical.

Requirements (on Termux):
    pkg install python nmap
    pip install scapy requests

Run:
    python netguard.py
"""

import subprocess
import re
import sys
import socket
import ipaddress

BANNER = r"""
 _   _      _   ____                     _
| \ | | ___| |_/ ___|_   _  __ _ _ __ __| |
|  \| |/ _ \ __| |  _| | | |/ _` | '__/ _` |
| |\  |  __/ |_| |_| | |_| | (_| | | | (_| |
|_| \_|\___|\__\____|\__,_|\__,_|_|  \__,_|

        by 0bscure — Personal WiFi Audit Tool
"""

# ---------------------------------------------------------
# Ports/services considered risky if found open on the router
RISKY_PORTS = {
    21: ("FTP", "Legacy protocol that sends credentials unencrypted"),
    23: ("Telnet", "Fully unencrypted remote access, should be disabled"),
    80: ("HTTP (router admin, no SSL)", "Admin interface without encryption, prefer HTTPS"),
    445: ("SMB", "May allow unintended file sharing"),
    1900: ("UPnP", "Can open ports automatically without your knowledge"),
    5555: ("ADB/Debug", "Debug port that may allow full device access"),
}


def get_local_network():
    """Attempts to auto-detect the local network range."""
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if "/" in line and "src" in line:
                cidr = line.split()[0]
                return cidr
    except Exception:
        pass
    return None


def ping_sweep(cidr):
    """Basic live-host discovery using nmap -sn."""
    print(f"[*] Scanning network: {cidr}")
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", cidr], text=True, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        print("[!] nmap is not installed. Install it with: pkg install nmap")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("[!] Scan failed:", e)
        sys.exit(1)

    devices = []
    current_ip = None
    for line in out.splitlines():
        ip_match = re.search(r"Nmap scan report for (?:[\w.-]+ )?\(?([\d.]+)\)?", line)
        mac_match = re.search(r"MAC Address: ([0-9A-F:]{17}) \(([^)]*)\)", line)
        if ip_match:
            current_ip = ip_match.group(1)
            devices.append({"ip": current_ip, "mac": "N/A", "vendor": "N/A"})
        if mac_match and devices:
            devices[-1]["mac"] = mac_match.group(1)
            devices[-1]["vendor"] = mac_match.group(2)
    return devices


def scan_router_ports(router_ip):
    """Scan common ports on the router to assess risk."""
    print(f"[*] Scanning router ports: {router_ip}")
    open_risky = []
    try:
        ports_str = ",".join(str(p) for p in RISKY_PORTS.keys())
        out = subprocess.check_output(
            ["nmap", "-p", ports_str, router_ip], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open", line.strip())
            if m:
                port = int(m.group(1))
                if port in RISKY_PORTS:
                    open_risky.append(port)
    except Exception as e:
        print("[!] Could not scan ports:", e)
    return open_risky


def get_default_gateway():
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default"):
                return line.split()[2]
    except Exception:
        pass
    return None


def calculate_risk_score(open_risky_ports, device_count):
    """Rough weakness score from 0 to 100 based on simple indicators."""
    score = 0
    score += len(open_risky_ports) * 15
    if device_count > 10:
        score += 10
    return min(score, 100)


def risk_label(score):
    if score == 0:
        return "Excellent ✅"
    elif score < 30:
        return "Good 🙂"
    elif score < 60:
        return "Moderate ⚠️"
    else:
        return "High Risk 🔴"


def main():
    print(BANNER)
    print("⚠️  This tool is intended for auditing your own personal network only.")
    print("    Using it on networks you do not own is illegal.\n")

    confirm = input("Is this your own network, and do you have permission to scan it? (y/n): ").strip().lower()
    if confirm != "y":
        print("Aborting.")
        sys.exit(0)

    cidr = get_local_network()
    if not cidr:
        cidr = input("Could not auto-detect the network. Enter the network range (e.g. 192.168.1.0/24): ").strip()

    devices = ping_sweep(cidr)

    print(f"\n[+] Found {len(devices)} connected device(s):\n")
    print(f"{'IP':<16}{'MAC':<20}{'Vendor'}")
    print("-" * 55)
    for d in devices:
        print(f"{d['ip']:<16}{d['mac']:<20}{d['vendor']}")

    gateway = get_default_gateway()
    open_risky = []
    if gateway:
        open_risky = scan_router_ports(gateway)
        print(f"\n[+] Router scan ({gateway}):")
        if open_risky:
            for p in open_risky:
                name, desc = RISKY_PORTS[p]
                print(f"  - Port {p} ({name}) open — {desc}")
        else:
            print("  No risky ports open from the checked list.")

    score = calculate_risk_score(open_risky, len(devices))
    print(f"\n[=] Estimated security weakness score: {score}% — {risk_label(score)}")
    print("\nGeneral recommendations:")
    print("  - Change the router's default password if you haven't already.")
    print("  - Use WPA3 or WPA2 encryption only (avoid WEP).")
    print("  - Disable WPS and UPnP if you don't need them.")
    print("  - Close any unnecessary admin ports (Telnet/FTP).")


if __name__ == "__main__":
    main()
