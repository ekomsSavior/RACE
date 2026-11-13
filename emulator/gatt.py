"""GATT model for the virtual peripheral.

Only the attributes the RACE client resolves are modelled: a service UUID and
its characteristics.  The objects are intentionally bleak-shaped (``.uuid``,
``.characteristics``) so :class:`transports.ble.BLETransport` can walk them
without knowing it is talking to a simulation.
"""

from __future__ import annotations

from dataclasses import dataclass

from utils.config import RACEConfig


@dataclass(frozen=True)
class SimCharacteristic:
    """Minimal stand-in for ``bleak.BleakGATTCharacteristic``."""

    uuid: str
    properties: tuple[str, ...] = ("write", "notify")

    @property
    def handle(self) -> int:
        """Stable pseudo-handle derived from the UUID (for display only)."""
        return int(self.uuid.split("-", 1)[0], 16)

    def __str__(self) -> str:  # pragma: no cover - display helper
        return self.uuid


@dataclass(frozen=True)
class SimService:
    """Minimal stand-in for ``bleak.BleakGATTService``."""

    uuid: str
    characteristics: tuple[SimCharacteristic, ...] = ()

    def __str__(self) -> str:  # pragma: no cover - display helper
        return self.uuid


def build_race_service(
    config: RACEConfig | None = None,
    *,
    expose_tx: bool = True,
    expose_rx: bool = True,
) -> SimService:
    """Create the ``0x1200`` RACE service with selected characteristics.

    Hiding TX models a firmware build without a writable command endpoint;
    hiding RX models one that never notifies.  Both are useful failure modes
    to explore (``TX_NOT_FOUND`` and request timeouts respectively).
    """
    cfg = config or RACEConfig()
    characteristics: list[SimCharacteristic] = []
    if expose_tx:
        characteristics.append(
            SimCharacteristic(cfg.tx_uuid, ("write", "write-without-response"))
        )
    if expose_rx:
        characteristics.append(SimCharacteristic(cfg.rx_uuid, ("notify", "read")))
    return SimService(cfg.service_uuid, tuple(characteristics))
