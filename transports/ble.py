"""BLE GATT transport with a deterministic connection lifecycle.

The transport owns its :class:`bleak.BleakClient` and guarantees cleanup
(via ``async with`` + ``finally``) even when a command fails, which also
removes the manual ``disconnect()`` calls scattered through the research
modules and prevents connection leaks under exceptions/timeouts.

A ``client_factory`` can be injected to substitute a different GATT client.
The virtual headphone emulator (:mod:`emulator`) uses this to exercise this
real transport, and the modules above it, without a radio or bleak installed.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from utils.capture import CaptureError, Direction, WireCapture, open_capture, tap
from utils.config import RACEConfig
from utils.packet import (
    FrameAssembler,
    RACEProtocolError,
    build_race_packet,
    parse_race_response,
)


def _bleak_client() -> Any:
    """Return bleak's client class, or ``None`` when bleak is not installed."""
    try:
        from bleak import BleakClient
    except ImportError:  # pragma: no cover - exercised on machines without bleak
        return None
    return BleakClient


#: bleak is optional for the offline emulator path.
_BleakClient = _bleak_client()

logger = logging.getLogger("race")

RACE_SERVICE_UUID = "00001200-0000-1000-8000-00805f9b34fb"
RACE_TX_UUID = "00001201-0000-1000-8000-00805f9b34fb"
RACE_RX_UUID = "00001202-0000-1000-8000-00805f9b34fb"


class BLETransportError(RACEProtocolError):
    """Raised when a BLE transport operation fails."""


#: A callable that turns an address into a bleak-compatible client.
ClientFactory = Callable[[str], Any]


def _default_client_factory(address: str) -> Any:
    if _BleakClient is None:
        raise BLETransportError(
            "bleak is not installed; install runtime dependencies or use the "
            "virtual emulator (python3 -m emulator)",
            code="BLEAK_MISSING",
        )
    return _BleakClient(address)


class BLETransport:
    """Facility for sending/receiving RACE commands over BLE GATT."""

    def __init__(
        self,
        address: str,
        *,
        config: RACEConfig | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self.address = address
        self.config = config or RACEConfig()
        self._client_factory = client_factory
        self._client: Any = None
        self._tx_char = None
        self._rx_char = None
        self._response_queue: asyncio.Queue[bytes] = asyncio.Queue()
        # ATT notifications may contain a fragment of a RACE frame.  The
        # assembler joins them; complete frames sit in ``_assembled`` until a
        # command consumes or discards them (stale/duplicate replies).
        self._assembler = FrameAssembler(self.config)
        self._assembled: list[bytes] = []
        self._closed = False
        # Optional pcap/btsnoop sink; opened on connect, released on disconnect.
        # The file itself is process-wide (see utils.capture.open_capture), so a
        # hunt across devices keeps appending to one capture.
        self._capture: WireCapture | None = None
        self._capture_baseline = (0, 0)

    async def __aenter__(self) -> BLETransport:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def connect(self) -> None:
        """Connect, resolve service/characteristic handles, then start notify."""
        if self._closed:
            raise BLETransportError("Transport has been closed", code="CLOSED")
        if self.is_connected:
            return

        factory = self._client_factory or _default_client_factory
        self._client = factory(self.address)
        self._assembler.reset()
        self._assembled.clear()
        try:
            await self._client.connect(timeout=self.config.connect_timeout_s)

            service = self._resolve_service()
            if service is None:
                raise BLETransportError(
                    "RACE service not found", code="SERVICE_NOT_FOUND"
                )
            self._tx_char, self._rx_char = self._resolve_characteristics(service)

            if self._tx_char is None:
                raise BLETransportError(
                    "RACE TX characteristic not found", code="TX_NOT_FOUND"
                )

            if self._rx_char is not None:
                await self._client.start_notify(
                    self._rx_char, self._notification_handler
                )
        except BaseException:
            # A failed handshake must not leave a half-open link behind.
            try:
                if self._client.is_connected:
                    await self._client.disconnect()
            except BaseException:
                pass
            self._client = None
            self._tx_char = None
            self._rx_char = None
            raise

        if self._capture is None:
            self._capture = self._open_capture()

    async def _ensure_connected(self) -> None:
        if self._closed:
            raise BLETransportError("Transport has been closed", code="CLOSED")
        if not self.is_connected:
            await self.connect()

    def _resolve_service(self):
        client = self._client
        if client is None:
            return None
        for service in client.services:
            if service.uuid.lower() == self.config.service_uuid.lower():
                return service
        return None

    def _resolve_characteristics(self, service):
        tx = rx = None
        for char in service.characteristics:
            u = char.uuid.lower()
            if u == self.config.tx_uuid.lower():
                tx = char
            elif u == self.config.rx_uuid.lower():
                rx = char
        return tx, rx

    def _notification_handler(self, _sender: Any, data: Any) -> None:
        """Capture and queue a notification payload (bleak passes ``sender, data``).

        Recording happens here, at arrival, rather than when a command dequeues
        the frame: duplicates, unsolicited notifications and replies that land
        after ``read_timeout_s`` all reach the file, stamped with the time they
        actually arrived instead of the time the next command consumed them.
        """
        payload = bytes(data)
        self._record("rx", payload)
        self._response_queue.put_nowait(payload)

    def _discard_pending(self) -> None:
        """Drop notifications/partial frames that predate the next write.

        Notification bytes were already captured on arrival; draining here only
        removes them from this command's correlation window.
        """
        while True:
            try:
                self._response_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self._assembler.reset()
        self._assembled.clear()

    async def send_command(self, cmd: int, payload: bytes = b"") -> bytes:
        """Send a RACE command and return the *matching* response payload.

        Notifications are not a one-to-one reply channel: a device can emit
        unsolicited frames, duplicate a reply, or deliver a late answer for the
        previous command.  Notifications that predate this write are drained
        first (their bytes were already captured on arrival), then every
        complete frame is correlated by response opcode; mismatched/unsolicited
        frames are discarded until the deadline.  A trailing partial frame is
        reported as a truncated reply.
        """
        await self._ensure_connected()
        client = self._client
        if client is None:
            raise BLETransportError("Transport is not connected", code="NOT_CONNECTED")

        # A late reply to a previous command can carry the same opcode we are
        # about to send.  Correlation by opcode cannot distinguish it, so
        # discard everything that arrived before this write.  The capture
        # already has those bytes with their true arrival time.
        self._discard_pending()

        packet = build_race_packet(cmd, payload, head=self.config.head_standard)
        self._record("tx", packet)
        # Outbound fragmentation/long writes are the BLE stack's job: this
        # layer hands one RACE frame to write_gatt_char.  Inbound notifications
        # arrive one ATT PDU at a time, so reassembly is done above.
        await client.write_gatt_char(self._tx_char, packet, response=True)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.config.read_timeout_s
        discarded = 0

        while True:
            while self._assembled:
                raw_frame = self._assembled.pop(0)
                try:
                    parsed = parse_race_response(raw_frame, config=self.config)
                except RACEProtocolError as exc:
                    raise BLETransportError(
                        f"Invalid response for cmd 0x{cmd:04X}: {exc}",
                        code="BAD_RESPONSE",
                    ) from exc

                if parsed.is_response() and parsed.cmd == cmd:
                    return parsed.payload

                discarded += 1
                logger.warning(
                    "Discarding %s frame cmd=0x%04X while waiting for cmd=0x%04X",
                    "response" if parsed.is_response() else "request",
                    parsed.cmd,
                    cmd,
                )

            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                raw = await asyncio.wait_for(
                    self._response_queue.get(), timeout=remaining
                )
            except asyncio.TimeoutError:
                break

            try:
                self._assembled.extend(self._assembler.feed(raw))
            except RACEProtocolError as exc:
                raise BLETransportError(
                    f"Invalid response for cmd 0x{cmd:04X}: {exc}",
                    code="BAD_RESPONSE",
                ) from exc

        if self._assembler.pending_bytes:
            raise BLETransportError(
                "Incomplete response within timeout "
                f"({len(self._assembler.pending_bytes)} byte(s) buffered)",
                code="BAD_RESPONSE",
            )
        if discarded:
            raise BLETransportError(
                f"No matching RACE response for cmd 0x{cmd:04X} within timeout; "
                f"discarded {discarded} mismatched/unsolicited frame(s)",
                code="NO_RESPONSE",
            )
        raise BLETransportError(
            "No RACE response within timeout", code="NO_RESPONSE"
        )

    async def disconnect(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._client is not None and self._client.is_connected:
                await self._client.disconnect()
        finally:
            self._client = None
            self._tx_char = None
            self._rx_char = None
            self._assembler.reset()
            self._assembled.clear()
            self._close_capture()

    # -- wire capture ------------------------------------------------------

    def _open_capture(self) -> WireCapture | None:
        """Open the configured capture sink, never failing the session."""
        try:
            capture = open_capture(self.config.capture_path, self.config.capture_format)
        except (CaptureError, OSError) as exc:
            logger.warning("Wire capture disabled: %s", exc)
            return None
        if capture is not None:
            # Frames already in the file came from an earlier connection.
            self._capture_baseline = (capture.frames, capture.bytes)
            logger.info("Wire capture -> %s [%s]", capture.path, capture.format.value)
        return capture

    def _record(self, direction: Direction, frame: Any) -> None:
        """Dump one frame to the capture sink; never raises into the call path."""
        tap(self._capture, direction, frame)

    def _close_capture(self) -> None:
        """Report this session's frames; the shared file stays open for reuse."""
        capture, self._capture = self._capture, None
        if capture is None:
            return
        base_frames, base_bytes = self._capture_baseline
        logger.info(
            "Wire capture: %s (+%d frames, +%d bytes)",
            capture.path,
            capture.frames - base_frames,
            capture.bytes - base_bytes,
        )
