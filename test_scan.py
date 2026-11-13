"""Manual BLE scanner smoke test; requires a Bluetooth adapter."""

import asyncio

from bleak import BleakScanner


async def scan_devices() -> None:
    print("[*] Scanning for 5 seconds...")
    devices = await BleakScanner.discover(timeout=5)
    for device in devices:
        print(f"  {device.address} - {device.name}")
    print("[+] Scan complete")


if __name__ == "__main__":
    asyncio.run(scan_devices())
