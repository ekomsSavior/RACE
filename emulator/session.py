"""Small command/response session on top of the virtual GATT client.

:class:`VirtualSession` sends raw frames and collects *every* notification
produced for that write, including duplicates and delayed replies.  It is the
primitive behind the explorer; it deliberately does not reuse
:class:`transports.ble.BLETransport` because that transport consumes exactly
one notification per command and hides malformed frames behind a single
error.  Researchers exploring faults need to see the raw bytes.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from utils.capture import CaptureError, Direction, WireCapture, open_capture, tap
from utils.config import RACEConfig
from utils.packet import build_race_packet

from .client import VirtualBleakClient

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .device import VirtualHeadphone


logger = logging.getLogger("race")


class VirtualSession:
    """Open a virtual link, write frames, collect notifications."""

    def __init__(
        self,
        device: VirtualHeadphone,
        *,
        read_timeout: float = 1.0,
        settle_s: float = 0.02,
        config: RACEConfig | None = None,
    ) -> None:
        if read_timeout <= 0:
            raise ValueError("read_timeout must be positive")
        self.device = device
        self.config = config or device.config
        self.read_timeout = read_timeout
        self.settle_s = max(0.0, settle_s)
        self.client = VirtualBleakClient(device)
        self._frames: list[bytes] = []
        self._event = asyncio.Event()
        self._open = False
        # The explorer sees frames before any parser touches them, so a capture
        # taken here includes malformed and duplicate replies as they arrived.
        self._capture: WireCapture | None = None

    async def __aenter__(self) -> VirtualSession:
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def open(self) -> None:
        if self._open:
            return
        await self.client.connect()
        if self.device.rx_available:
            await self.client.start_notify(self.config.rx_uuid, self._on_notify)
        self._open = True
        self._capture = self._open_capture()

    async def close(self) -> None:
        if not self._open:
            return
        self._open = False
        await self.client.disconnect()

    def _open_capture(self) -> WireCapture | None:
        try:
            return open_capture(self.config.capture_path, self.config.capture_format)
        except (CaptureError, OSError) as exc:
            logger.warning("Wire capture disabled: %s", exc)
            return None

    def _record(self, direction: Direction, frame: bytes) -> None:
        tap(self._capture, direction, frame)

    def _on_notify(self, _sender, data: bytearray) -> None:
        self._record("rx", bytes(data))
        self._frames.append(bytes(data))
        self._event.set()

    @property
    def is_open(self) -> bool:
        return self._open and self.client.is_connected

    async def send_frame(
        self,
        frame: bytes,
        *,
        timeout: float | None = None,
    ) -> list[bytes]:
        """Write *frame* and return all notifications seen for it."""
        if not self._open:
            raise RuntimeError("session is not open")
        if not self.client.is_connected:
            raise RuntimeError("virtual link is down; reconnect first")
        if not self.device.tx_available:
            raise RuntimeError("device does not expose the RACE TX characteristic")

        self._frames = []
        self._event.clear()
        self._record("tx", frame)
        await self.client.write_gatt_char(self.config.tx_uuid, frame, response=True)

        wait_for = self.read_timeout if timeout is None else timeout
        try:
            await asyncio.wait_for(self._event.wait(), timeout=wait_for)
        except asyncio.TimeoutError:
            return []
        except asyncio.CancelledError:
            raise

        if self.settle_s:
            # Give duplicate/immediate notifications a chance to land.
            await asyncio.sleep(self.settle_s)
        return list(self._frames)

    async def send_command(
        self,
        cmd: int,
        payload: bytes = b"",
        *,
        head: int | None = None,
        timeout: float | None = None,
    ) -> list[bytes]:
        """Build a request frame and send it."""
        frame = build_race_packet(
            cmd,
            payload,
            head=self.config.head_standard if head is None else head,
            config=self.config,
        )
        return await self.send_frame(frame, timeout=timeout)

    async def send_hex(
        self,
        hex_string: str,
        *,
        timeout: float | None = None,
    ) -> list[bytes]:
        """Send a raw frame written as hex (spaces and ``0x`` allowed)."""
        cleaned = (
            hex_string.replace("0x", "")
            .replace(" ", "")
            .replace(":", "")
            .replace("-", "")
            .strip()
        )
        if len(cleaned) % 2:
            raise ValueError("hex frame must have an even number of digits")
        try:
            frame = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"invalid hex frame: {exc}") from None
        return await self.send_frame(frame, timeout=timeout)


__all__ = ["VirtualSession"]
