"""Device discovery with injectable scanner/client factories.

The public functions default to bleak, but both seams can be replaced.  That
keeps the name heuristic and the active service probe testable without a
radio and lets the offline emulator drive ``scan``/``hunt`` end to end.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from utils.config import RACEConfig

_BleakClient: Any
_BleakScanner: Any
try:  # bleak is optional when a virtual scanner/client factory is injected
    from bleak import BleakClient as _BleakClient
    from bleak import BleakScanner as _BleakScanner
except ImportError:  # pragma: no cover - exercised on machines without bleak
    _BleakClient = None
    _BleakScanner = None

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

ClientFactory = Callable[[str], Any]


def _scanner_or_default(scanner: Any | None) -> Any:
    if scanner is not None:
        return scanner
    if _BleakScanner is None:
        raise RuntimeError(
            "bleak is not installed; install runtime dependencies or inject a scanner"
        )
    return _BleakScanner


def _client_factory_or_default(
    client_factory: ClientFactory | None,
) -> ClientFactory:
    if client_factory is not None:
        return client_factory
    if _BleakClient is None:
        raise RuntimeError(
            "bleak is not installed; install runtime dependencies or inject a client factory"
        )
    return cast(ClientFactory, _BleakClient)


async def scan_for_targets(
    config: RACEConfig,
    deep_scan: bool = False,
    *,
    scanner: Any | None = None,
    client_factory: ClientFactory | None = None,
    out: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    """Scan for RACE-capable devices with optional service discovery.

    ``scanner`` must expose ``async discover(timeout=..., return_adv=...)``.
    ``client_factory`` turns an address into a connected-capable client.  Both
    default to bleak and can be replaced by the virtual emulator.
    """
    out(f"[*] Scanning for devices ({config.scan_timeout_s:g}s)...")

    active_scanner = _scanner_or_default(scanner)
    devices = await active_scanner.discover(
        timeout=config.scan_timeout_s, return_adv=True
    )

    found: list[dict[str, Any]] = []
    for addr, (dev, adv_data) in devices.items():
        name = dev.name if dev.name else "Unknown"
        is_vulnerable = any(model in name for model in VULNERABLE_MODELS)

        found.append(
            {
                "address": addr,
                "name": name,
                "rssi": getattr(adv_data, "rssi", "N/A"),
                "vulnerable": is_vulnerable,
                "race_service": False,
            }
        )

    if deep_scan:
        out("[*] Deep scanning for RACE services...")
        factory = _client_factory_or_default(client_factory)
        for device in found:
            if device["vulnerable"]:
                out(f"  [*] Checking {device['address']}...")
                client = factory(device["address"])
                try:
                    await client.connect(timeout=5)
                    for service in client.services:
                        if service.uuid.lower() == config.service_uuid.lower():
                            device["race_service"] = True
                            device["race_tx"] = any(
                                char.uuid.lower() == config.tx_uuid.lower()
                                for char in service.characteristics
                            )
                            out("    [+] RACE service found!")
                            break
                except Exception as exc:
                    out(f"    [-] Failed: {str(exc)[:50]}")
                finally:
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
    return found


async def aggressive_scan(
    config: RACEConfig,
    timeout: int = 15,
    *,
    scanner: Any | None = None,
    client_factory: ClientFactory | None = None,
    out: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    """Find ANY device with the RACE service exposed.

    Unlike :func:`scan_for_targets`, this ignores the advertised-name
    heuristic and verifies the service UUID on every peer.
    """
    out("=" * 60)
    out("  RACE HUNTER - Finding vulnerable Bluetooth devices")
    out("=" * 60)

    out("[*] Scanning for devices...")
    active_scanner = _scanner_or_default(scanner)
    devices = await active_scanner.discover(timeout=timeout)
    factory = _client_factory_or_default(client_factory)

    race_devices: list[dict[str, Any]] = []
    total = len(devices)
    checked = 0

    for device in devices:
        checked += 1
        out(f"  [*] Checking {checked}/{total}: {device.address[:8]}...")

        client = factory(device.address)
        try:
            await client.connect(timeout=3)
            for service in client.services:
                if service.uuid.lower() == config.service_uuid.lower():
                    race_devices.append(
                        {
                            "address": device.address,
                            "name": device.name or "Unknown",
                            "rssi": getattr(device, "rssi", "N/A"),
                        }
                    )
                    out("  [+] RACE device found!")
                    break
        except Exception:
            pass
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    out("")
    return race_devices
