"""A bleak-compatible client bound to a :class:`VirtualHeadphone`.

Only the surface used by :class:`transports.ble.BLETransport` is implemented:
``connect``/``disconnect``, ``is_connected``, ``services``, ``start_notify``,
``write_gatt_char`` and ``read_gatt_char``.  Notifications are scheduled on
the running event loop, so delayed (:attr:`FaultKind.SLOW`) responses behave
like real GATT notifications rather than blocking the write call.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .gatt import SimCharacteristic, SimService

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .device import VirtualHeadphone

NotifyHandler = Callable[[Any, bytearray], None]


class VirtualBleakClient:
    """In-process stand-in for ``bleak.BleakClient``."""

    def __init__(
        self,
        device: VirtualHeadphone,
        address: str | None = None,
    ) -> None:
        self._device = device
        self.address = address or device.address
        self._connected = False
        self._services: list[SimService] = []
        self._handlers: dict[str, list[NotifyHandler]] = {}
        self._last_value: dict[str, bytes] = {}

    # ------------------------------------------------------------------
    # Context manager / lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self) -> VirtualBleakClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        return self._connected and self._device.connected

    async def connect(self, timeout: float | None = None) -> None:
        """Attach to the virtual peripheral (no radio, timeout is ignored)."""
        if self.is_connected:
            return
        if self._device.connected:
            raise RuntimeError(
                f"{self._device.name} already has a central connected"
            )
        self._device.connect()
        self._connected = True
        self._services = list(self._device.services)
        self._last_value.clear()

    async def disconnect(self) -> None:
        self._connected = False
        self._handlers.clear()
        if self._device.connected:
            self._device.disconnect()

    # ------------------------------------------------------------------
    # GATT discovery
    # ------------------------------------------------------------------
    @property
    def services(self) -> list[SimService]:
        return list(self._services)

    def _all_characteristics(self) -> list[SimCharacteristic]:
        return [
            char
            for service in self._services
            for char in service.characteristics
        ]

    def _resolve_uuid(self, characteristic: Any) -> str:
        value = getattr(characteristic, "uuid", characteristic)
        return str(value).lower()

    def _has_characteristic(self, uuid: str) -> bool:
        return any(char.uuid.lower() == uuid for char in self._all_characteristics())

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------
    async def start_notify(
        self,
        characteristic: Any,
        handler: NotifyHandler,
    ) -> None:
        if not self.is_connected:
            raise RuntimeError("client is not connected")
        uuid = self._resolve_uuid(characteristic)
        if uuid != self._device.config.rx_uuid.lower():
            raise ValueError(
                f"characteristic {uuid} does not support notify; "
                f"subscribe to {self._device.config.rx_uuid}"
            )
        if not self._has_characteristic(uuid):
            raise ValueError("RX characteristic is not exposed by this device")
        self._handlers.setdefault(uuid, []).append(handler)

    async def stop_notify(self, characteristic: Any) -> None:
        uuid = self._resolve_uuid(characteristic)
        self._handlers.pop(uuid, None)

    def _notify_characteristic(self) -> SimCharacteristic:
        rx_uuid = self._device.config.rx_uuid.lower()
        for char in self._all_characteristics():
            if char.uuid.lower() == rx_uuid:
                return char
        return SimCharacteristic(self._device.config.rx_uuid)

    def _deliver(self, frame: bytes) -> None:
        if not self.is_connected:
            return
        uuid = self._device.config.rx_uuid.lower()
        payload = bytearray(frame)
        self._last_value[uuid] = bytes(frame)
        for handler in list(self._handlers.get(uuid, ())):
            try:
                handler(self._notify_characteristic(), payload)
            except Exception:
                # A broken observer must not take down the virtual link.
                continue

    # ------------------------------------------------------------------
    # GATT I/O
    # ------------------------------------------------------------------
    async def write_gatt_char(
        self,
        characteristic: Any,
        data: bytes | bytearray,
        response: bool = True,
    ) -> None:
        if not self.is_connected:
            raise RuntimeError("client is not connected")
        uuid = self._resolve_uuid(characteristic)
        if uuid != self._device.config.tx_uuid.lower():
            raise ValueError(
                f"characteristic {uuid} is not the RACE TX characteristic"
            )

        outbounds = self._device.handle_request(bytes(data))
        if not self._device.connected:
            self._connected = False
            return

        loop = asyncio.get_running_loop()
        for outbound in outbounds:
            if outbound.delay_s > 0:
                loop.call_later(outbound.delay_s, self._deliver, outbound.frame)
            else:
                loop.call_soon(self._deliver, outbound.frame)

    async def read_gatt_char(self, characteristic: Any) -> bytearray:
        if not self.is_connected:
            raise RuntimeError("client is not connected")
        uuid = self._resolve_uuid(characteristic)
        return bytearray(self._last_value.get(uuid, b""))

    # ------------------------------------------------------------------
    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return (
            f"VirtualBleakClient(address={self.address!r}, "
            f"connected={self.is_connected})"
        )


__all__ = ["NotifyHandler", "VirtualBleakClient"]
