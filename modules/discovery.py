from typing import Any

from bleak import BleakClient, BleakScanner

from utils.config import RACEConfig

RACE_SERVICE_UUID = "00001200-0000-1000-8000-00805f9b34fb"
RACE_TX_UUID = "00001201-0000-1000-8000-00805f9b34fb"
RACE_RX_UUID = "00001202-0000-1000-8000-00805f9b34fb"

VULNERABLE_MODELS = [
    "WH-1000XM",
    "WF-1000XM",
    "WH-CH",
    "LinkBuds",
    "ULT Wear",
    "Marshall",
    "JBL",
    "Bose",
    "Jabra",
    "Beyerdynamic",
]


async def scan_for_targets(config: RACEConfig, deep_scan: bool = False) -> list[dict[str, Any]]:
    """Scan for RACE-capable devices with optional service discovery.

    Returns a list of device dicts (``address``, ``name``, ``rssi``,
    ``vulnerable``, ``race_service``).
    """
    print(f"[*] Scanning for devices ({config.scan_timeout_s:g}s)...")

    devices = await BleakScanner.discover(timeout=config.scan_timeout_s, return_adv=True)

    found: list[dict[str, Any]] = []
    for addr, (dev, adv_data) in devices.items():
        name = dev.name if dev.name else "Unknown"
        is_vulnerable = any(model in name for model in VULNERABLE_MODELS)

        found.append(
            {
                "address": addr,
                "name": name,
                "rssi": adv_data.rssi if adv_data else "N/A",
                "vulnerable": is_vulnerable,
                "race_service": False,
            }
        )

    if deep_scan:
        print("[*] Deep scanning for RACE services...")
        for device in found:
            if device["vulnerable"]:
                print(f"  [*] Checking {device['address']}...")
                try:
                    client = BleakClient(device["address"])
                    await client.connect(timeout=5)
                    for service in client.services:
                        if service.uuid.lower() == config.service_uuid.lower():
                            device["race_service"] = True
                            device["race_tx"] = any(
                                c.uuid.lower() == config.tx_uuid.lower()
                                for c in service.characteristics
                            )
                            print("    [+] RACE service found!")
                            break
                    await client.disconnect()
                except Exception as exc:
                    print(f"    [-] Failed: {str(exc)[:50]}")
    return found


async def aggressive_scan(config: RACEConfig, timeout: int = 15) -> list[dict[str, Any]]:
    """Find ANY device with RACE service exposed."""
    print("=" * 60)
    print("  RACE HUNTER - Finding vulnerable Bluetooth devices")
    print("=" * 60)

    print("[*] Scanning for devices...")
    # return_adv=True is required for RSSI: bleak >= 0.22 removed
    # BLEDevice.rssi, and reading it raised AttributeError inside the probe
    # loop below -- which the broad except swallowed, so `hunt` reported
    # nothing even when a RACE service was found.
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)

    race_devices: list[dict[str, Any]] = []
    total = len(devices)
    checked = 0

    for address, (device, adv_data) in devices.items():
        checked += 1
        print(f"\r  [*] Checking {checked}/{total}: {address[:8]}...", end="")

        try:
            client = BleakClient(address)
            await client.connect(timeout=3)

            for service in client.services:
                if service.uuid.lower() == config.service_uuid.lower():
                    race_devices.append(
                        {
                            "address": address,
                            "name": device.name or "Unknown",
                            "rssi": adv_data.rssi if adv_data else "N/A",
                        }
                    )
                    print("\n  [+] RACE device found!")
                    break

            await client.disconnect()
        except Exception as exc:
            print(f"\r  [-] {address[:8]} probe failed: {str(exc)[:50]}")

    print("\n")  # Newline after progress
    return race_devices
