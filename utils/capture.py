"""Raw wire capture: stream RACE frames to pcap or btsnoop for Wireshark.

The hook sits exactly where frames hit the packet parser (and just before they
hit the radio), so a triage session can be replayed byte-for-byte after a
packet drop instead of being reconstructed from log lines.

Two containers are supported, both holding the same synthetic HCI-ACL stream:

===========  ==========================================================
``pcap``     libpcap classic, ``LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR`` (201)
``btsnoop``  Symbian/Android/BlueZ snoop, datalink 1002 (H4 UART)
===========  ==========================================================

Both carry the same H4 bytes; the pcap pseudo-header and the btsnoop flags
both mark each record as sent (host → device) or received (device → host),
so Wireshark and ``btmon`` label directions without guessing.

Open either one directly in Wireshark; ``btsnoop`` additionally replays as
text with ``btmon -r session.btsnoop``.

Each RACE frame is wrapped in a 4-byte L2CAP header (CID ``0x0004``, ATT) plus
one ATT PDU, so Wireshark decodes the traffic as ``btatt`` with the untouched
RACE bytes as the attribute value:

* request  → ATT Write Command (``0x52``) on ``tx_handle``
* response → ATT Handle Value Notification (``0x1B``) on ``rx_handle``

That means ``btatt.value`` (or ``btatt`` alone) filters straight down to RACE
frames, and ``tshark -r session.pcap -T fields -e btatt.value`` gives you the
raw frames as hex.  Handles are configurable because the attribute table is
device-specific; the defaults are placeholders that only need to be stable
within a capture.
"""

from __future__ import annotations

import os
import struct
import time
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Literal

from .packet import RACEError

#: Environment variables consulted by :func:`open_capture` when no explicit
#: value is passed -- lets an existing invocation be captured without edits.
CAPTURE_ENV_VAR = "RACE_CAPTURE"
CAPTURE_FORMAT_ENV_VAR = "RACE_CAPTURE_FORMAT"

# libpcap classic container.
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
#: Per-packet pcap pseudo-header: big-endian direction word, bit 0 = received.
PCAP_PHDR_LEN = 4
PCAP_PHDR_SENT = 0
PCAP_PHDR_RECEIVED = 1

# btsnoop container (magic, version, datalink; records are big-endian).
BTSNOOP_MAGIC = b"btsnoop\x00"
BTSNOOP_VERSION = 1
BTSNOOP_DATALINK_H4 = 1002
#: Microseconds between the btsnoop epoch (0 AD) and the Unix epoch.
BTSNOOP_EPOCH_DELTA_US = 0x00DCDDB30F2F8000
#: btsnoop record flags: bit 0 = received (1) / sent (0), bit 1 = cmd/event.
BTSNOOP_FLAG_SENT = 0x00
BTSNOOP_FLAG_RECEIVED = 0x01

# HCI ACL framing.
H4_ACL_PACKET = 0x02
ACL_HANDLE = 0x0040  # synthetic, stable connection handle
ACL_PB_FIRST_FRAGMENT = 0x2  # PB = 0b10, first packet of an L2CAP PDU
L2CAP_CID_ATT = 0x0004

H4_HEADER_LEN = 1
ACL_HEADER_LEN = 4
L2CAP_HEADER_LEN = 4
ATT_HEADER_LEN = 3
#: Bytes added around a RACE frame by the synthetic H4/ACL/L2CAP/ATT layers.
WIRE_OVERHEAD = H4_HEADER_LEN + ACL_HEADER_LEN + L2CAP_HEADER_LEN + ATT_HEADER_LEN
#: Largest frame value that still fits the pcap snaplen and the ACL 16-bit length.
MAX_ATT_VALUE = min(
    PCAP_SNAPLEN - PCAP_PHDR_LEN - WIRE_OVERHEAD,
    0xFFFF - L2CAP_HEADER_LEN - ATT_HEADER_LEN,
)

# ATT opcodes used to make the direction explicit inside the capture.
ATT_OP_NOTIFICATION = 0x1B
ATT_OP_WRITE_CMD = 0x52
ATT_TX_HANDLE = 0x0023
ATT_RX_HANDLE = 0x0026

Direction = Literal["tx", "rx"]


class CaptureError(RACEError):
    """Raised when a capture file cannot be opened or written."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message, code=code or "CAPTURE_ERROR")


class CaptureClosedError(CaptureError):
    """Raised when a frame is recorded on a capture that has been closed."""

    def __init__(self, message: str = "Capture is closed") -> None:
        super().__init__(message, code="CAPTURE_CLOSED")


class CaptureFormat(str, Enum):
    """Container format written by :class:`WireCapture`."""

    PCAP = "pcap"
    BTSNOOP = "btsnoop"

    @classmethod
    def from_path(cls, path: str | os.PathLike[str]) -> CaptureFormat:
        """Infer the container from a filename, defaulting to ``pcap``."""
        suffix = Path(path).suffix.lower()
        if suffix in (".btsnoop", ".snoop"):
            return cls.BTSNOOP
        return cls.PCAP

    @classmethod
    def coerce(
        cls, value: CaptureFormat | str | None, path: str | os.PathLike[str]
    ) -> CaptureFormat:
        """Normalize an explicit format, or infer one when ``value`` is None."""
        if value is None:
            return cls.from_path(path)
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            supported = ", ".join(member.value for member in cls)
            raise CaptureError(
                f"Unknown capture format {value!r} (supported: {supported})",
                code="CAPTURE_FORMAT",
            ) from None


def build_att_record(
    direction: Direction,
    frame: bytes,
    *,
    tx_handle: int = ATT_TX_HANDLE,
    rx_handle: int = ATT_RX_HANDLE,
) -> bytes:
    """Wrap a RACE frame into an H4 + ACL + L2CAP + ATT packet.

    The RACE bytes are never modified: they become the ATT attribute value,
    which is what Wireshark shows (and what ``btatt.value`` extracts).
    """
    if direction == "tx":
        opcode, handle = ATT_OP_WRITE_CMD, tx_handle
    elif direction == "rx":
        opcode, handle = ATT_OP_NOTIFICATION, rx_handle
    else:
        raise CaptureError(
            f"Invalid direction {direction!r} (expected 'tx' or 'rx')",
            code="CAPTURE_DIRECTION",
        )

    att = bytes([opcode]) + struct.pack("<H", handle) + frame
    l2cap = struct.pack("<HH", len(att), L2CAP_CID_ATT) + att
    acl_header = ACL_HANDLE | (ACL_PB_FIRST_FRAGMENT << 12)
    acl = struct.pack("<HH", acl_header, len(l2cap)) + l2cap
    return bytes([H4_ACL_PACKET]) + acl


class WireCapture:
    """Append-only pcap/btsnoop writer for RACE frames.

    Records are flushed immediately, so a crashed or killed session still
    leaves a loadable capture.  Use as a context manager or call
    :meth:`open`/:meth:`close` explicitly.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        fmt: CaptureFormat | str | None = None,
        *,
        tx_handle: int = ATT_TX_HANDLE,
        rx_handle: int = ATT_RX_HANDLE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.format = CaptureFormat.coerce(fmt, self.path)
        self.tx_handle = _check_handle(tx_handle, "tx_handle")
        self.rx_handle = _check_handle(rx_handle, "rx_handle")
        self._clock = clock
        self._fh: BinaryIO | None = None
        #: Number of frames written (both directions).
        self.frames = 0
        #: Number of raw RACE bytes written, excluding synthetic headers.
        self.bytes = 0

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> WireCapture:
        """Create/truncate the file and write its container header."""
        if self._fh is not None:
            return self
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fh = self.path.open("wb")
        except OSError as exc:
            raise CaptureError(
                f"Cannot open capture {self.path}: {exc}", code="CAPTURE_OPEN"
            ) from exc
        self._fh = fh
        fh.write(self._header())
        fh.flush()
        return self

    def close(self) -> None:
        """Flush and close the capture; safe to call twice."""
        fh, self._fh = self._fh, None
        if fh is None:
            return
        try:
            fh.flush()
        finally:
            fh.close()

    def __enter__(self) -> WireCapture:
        return self.open()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._fh is None

    # -- recording ---------------------------------------------------------

    def record(self, direction: Direction, frame: bytes) -> None:
        """Append one frame exactly as it hit the parser / radio."""
        if not isinstance(frame, (bytes, bytearray, memoryview)):
            raise TypeError(f"frame must be bytes-like, got {type(frame).__name__}")
        payload = bytes(frame)
        fh = self._fh
        if fh is None:
            raise CaptureClosedError()
        packet = build_att_record(
            direction,
            payload[:MAX_ATT_VALUE],
            tx_handle=self.tx_handle,
            rx_handle=self.rx_handle,
        )
        fh.write(
            self._record(
                self._clock(),
                packet,
                orig_len=len(payload) + WIRE_OVERHEAD,
                received=direction == "rx",
            )
        )
        fh.flush()
        self.frames += 1
        self.bytes += len(payload)

    def write_tx(self, frame: bytes) -> None:
        """Record a host → device frame (a RACE request)."""
        self.record("tx", frame)

    def write_rx(self, frame: bytes) -> None:
        """Record a device → host frame (a RACE response)."""
        self.record("rx", frame)

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            f"WireCapture(path={str(self.path)!r}, format={self.format.value!r}, "
            f"{state}, frames={self.frames})"
        )

    # -- encoding ----------------------------------------------------------

    def _header(self) -> bytes:
        if self.format is CaptureFormat.BTSNOOP:
            return BTSNOOP_MAGIC + struct.pack(">II", BTSNOOP_VERSION, BTSNOOP_DATALINK_H4)
        return struct.pack(
            "<IHHiIII",
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,  # thiszone
            0,  # sigfigs
            PCAP_SNAPLEN,
            DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
        )

    def _record(self, timestamp: float, packet: bytes, *, orig_len: int, received: bool) -> bytes:
        """Encode one container record; ``packet`` is already overflow-checked."""
        if self.format is CaptureFormat.BTSNOOP:
            micros = int(timestamp * 1_000_000) + BTSNOOP_EPOCH_DELTA_US
            flags = BTSNOOP_FLAG_RECEIVED if received else BTSNOOP_FLAG_SENT
            return struct.pack(">IIIIQ", orig_len, len(packet), flags, 0, micros) + packet

        # DLT 201 prefixes each record with the direction pseudo-header.
        direction = PCAP_PHDR_RECEIVED if received else PCAP_PHDR_SENT
        data = struct.pack(">I", direction) + packet
        sec = int(timestamp)
        usec = int((timestamp - sec) * 1_000_000)
        header = struct.pack("<IIII", sec, usec, len(data), orig_len + PCAP_PHDR_LEN)
        return header + data


def _check_handle(value: int, name: str) -> int:
    if not 0 <= value <= 0xFFFF:
        raise CaptureError(f"{name} must be a 16-bit handle (0..0xFFFF)", code="CAPTURE_HANDLE")
    return value


def open_capture(
    path: str | os.PathLike[str] | None = None,
    fmt: CaptureFormat | str | None = None,
    *,
    tx_handle: int = ATT_TX_HANDLE,
    rx_handle: int = ATT_RX_HANDLE,
    clock: Callable[[], float] = time.time,
) -> WireCapture | None:
    """Open a capture from arguments or the environment.

    ``path`` falls back to :data:`CAPTURE_ENV_VAR`, and ``fmt`` falls back to
    :data:`CAPTURE_FORMAT_ENV_VAR` (then to the file extension).  Returns
    ``None`` when neither is set, which is how callers keep the hook optional:

        RACE_CAPTURE=/tmp/race.pcap race.py exploit AA:BB:CC:DD:EE:FF
    """
    target = path if path is not None else os.environ.get(CAPTURE_ENV_VAR) or None
    if target is None:
        return None
    if fmt is None:
        fmt = os.environ.get(CAPTURE_FORMAT_ENV_VAR) or None
    return WireCapture(
        target, fmt, tx_handle=tx_handle, rx_handle=rx_handle, clock=clock
    ).open()
