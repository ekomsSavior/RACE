"""Find RACE devices and run the read-only assessment chain.

The previous wording ("OWNED!") overstated what the code proves.  A successful
``dump`` means build/address reads and one flash page read completed; the
extracted bytes are unvalidated candidates, not a demonstrated impersonation.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from modules.discovery import aggressive_scan
from modules.exploit import auto_exploit
from utils.config import RACEConfig


async def hunt_and_pwn(
    config: RACEConfig,
    timeout: int = 20,
    *,
    scanner: Any | None = None,
    client_factory: Callable[[str], Any] | None = None,
) -> None:
    """Find RACE devices and assess each one with ``action="dump"``."""
    print("=" * 60)
    print("  AUTO-HUNTER: Finding and assessing RACE devices")
    print("=" * 60)

    devices = await aggressive_scan(
        config,
        timeout,
        scanner=scanner,
        client_factory=client_factory,
    )

    if not devices:
        print("[-] No RACE devices found")
        return

    print(f"[+] Found {len(devices)} RACE device(s)")

    for dev in devices:
        print(f"\n[*] Assessing {dev['address']}...")
        result = await auto_exploit(
            dev["address"],
            "dump",
            config,
            client_factory=client_factory,
        )

        if result["status"] == "success":
            candidates = result.get("key_candidates") or []
            print(
                f"[+] {dev['address']} flash read succeeded; "
                f"{len(candidates)} unvalidated key candidate(s)"
            )
        else:
            print(f"[-] {dev['address']} failed: {result.get('message', '')}")
