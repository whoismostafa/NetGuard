# NetGuard

**NetGuard** is a lightweight Python tool for auditing your own home Wi-Fi network. It discovers connected devices and highlights basic security weaknesses on your router, giving you a quick, actionable snapshot of your network's health.

Built to run on **Termux** (Android) as well as standard Linux environments.

> **Scope & Legal Notice**
> NetGuard is intended **only for networks you own or have explicit authorization to test**. Scanning devices or networks without permission is illegal in most jurisdictions and against this project's intended use. The script requires explicit confirmation before running for this reason.

---

## Features

- **Device Discovery** — Automatically detects your local network range and lists connected devices (IP, MAC address, vendor).
- **Router Port Audit** — Checks your gateway for commonly risky open ports (Telnet, FTP, UPnP, unencrypted admin panels, etc.).
- **Risk Scoring** — Produces an approximate weakness percentage based on scan findings.
- **Actionable Recommendations** — Suggests concrete steps to harden your network (disable WPS/UPnP, close unused ports, use WPA2/WPA3, etc.).
- **Termux-Friendly** — No root required; works out of the box on Android via Termux.

---

## Requirements

- Python 3.7+
- [nmap](https://nmap.org/)

### Install on Termux

```bash
pkg update
pkg install python nmap
```

### Install on Linux

```bash
sudo apt install python3 nmap
```

---

## Usage

```bash
git clone https://github.com/whoismostafa/netguard.git
cd netguard
python netguard.py
```

The script will:

1. Ask you to confirm you own/are authorized to scan the target network.
2. Auto-detect your local network range (or prompt you to enter it manually).
3. Scan for connected devices and display them in a table.
4. Scan your router for known risky open ports.
5. Output an estimated risk score with a summary label (Excellent / Good / Moderate / High Risk).
6. Provide general hardening recommendations.

### Example Output

```
[+] Found 6 connected devices:

IP              MAC                 Vendor
-------------------------------------------------------
192.168.1.1     AA:BB:CC:DD:EE:FF   TP-Link Technologies
192.168.1.14    11:22:33:44:55:66   Apple, Inc.
...

[+] Router scan (192.168.1.1):
  - Port 23 (Telnet) open — unencrypted remote access, should be disabled

[=] Estimated security weakness score: 15% — Good 
```

---

## Roadmap

- [ ] WPA/WPA2/WPA3 encryption detection
- [ ] WPS status check
- [ ] Exportable JSON/HTML reports
- [ ] Historical scan comparison

---

## Disclaimer

This tool is provided for educational and personal network-security purposes only. The author assumes no liability for misuse. Always obtain explicit authorization before scanning any network you do not own.

---

## Author

**0bscure**
