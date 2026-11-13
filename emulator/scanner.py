"""A virtual BLE scanner/advertiser for offline discovery tests.

The scanner implements only the surface used by
:func:`modules.discovery.scan_for_targets` and
:func:`modules.discovery.aggressive_scan`: an async ``discover`` method that
returns either a list of devices or a ``{address: (device, adv)}`` mapping.
No radio is involved.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .device import VirtualHeadphone


@dataclass(frozen=True)
class VirtualDevice:
    """Minimal advertisement record understood by ``modules.discovery``."""

    address: str
    name: str
    rssi: int

    @classmethod
    def from_headphone(cls, device: VirtualHeadphone) -> VirtualDevice:
        return cls(address=device.address, name=device.name, rssi=device.rssi)


@dataclass(frozen=True)
class VirtualAdvertisement:
    """Advertisement payload subset (only RSSI is consumed today)."""

    rssi: int


class VirtualScanner:
    """In-process stand-in for ``bleak.BleakScanner``."""

    def __init__(self, devices: Iterable[VirtualDevice] = ()) -> None:
        self.devices = tuple(devices)

    @classmethod
    def from_headphones(
        cls, devices: Iterable[VirtualHeadphone]
    ) -> VirtualScanner:
        return cls(VirtualDevice.from_headphone(device) for device in devices)

    async def discover(
        self,
        timeout: float = 0.0,
        return_adv: bool = False,
    ) -> Any:
        """Return the configured advertisements immediately.

        ``timeout`` is accepted for signature compatibility and ignored; the
        virtual devices are always present.
        """
        del timeout
        if return_adv:
            return {
                device.address: (device, VirtualAdvertisement(device.rssi))
                for device in self.devices
            }
        return list(self.devices)


__all__ = ["VirtualAdvertisement", "VirtualDevice", "VirtualScanner"]
