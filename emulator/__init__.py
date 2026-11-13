"""Virtual RACE headphone emulator.

An in-process BLE GATT peripheral that speaks the Airoha RACE protocol with
synthetic data.  It exists so protocol work, client development and teaching
can happen without a radio, without a headset, and without touching real key
material.

The package depends only on the standard library and :mod:`utils`; ``bleak``
is *not* required.  The virtual client mirrors the small part of the bleak
API that :class:`transports.ble.BLETransport` uses, so the production client
path can be exercised unchanged.

Typical use::

    from emulator import VirtualHeadphone

    async def demo() -> None:
        device = VirtualHeadphone("sony-wh1000xm5")
        async with device.client() as client:
            ...
"""

from __future__ import annotations

from .client import VirtualBleakClient
from .device import DeviceProfile, TraceEntry, VirtualHeadphone, load_profile
from .faults import FaultKind, FaultPlan, FaultRule, FaultSpecError, parse_fault_spec
from .responses import SyntheticResponder
from .session import VirtualSession

__all__ = [
    "DeviceProfile",
    "FaultKind",
    "FaultPlan",
    "FaultRule",
    "FaultSpecError",
    "SyntheticResponder",
    "TraceEntry",
    "VirtualBleakClient",
    "VirtualHeadphone",
    "VirtualSession",
    "load_profile",
    "parse_fault_spec",
]

__version__ = "1.0.0"
