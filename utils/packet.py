"""RACE protocol builder/parser with strict validation and structured errors.

Frame format (per the project specification):
    Head(1B) Type(1B) Length(2B LE) CMD(2B) Payload(N)
    Length == len(CMD) + len(Payload) == 2 + len(payload)

Constants are kept in :mod:`utils.config` so callers share a single source.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .config import RACEConfig

# RACE command opcodes (from the project documentation).
CMD_GET_BUILD = 0x1E08  # Get Build Version
CMD_READ_FLASH = 0x0403  # Read Flash
CMD_WRITE_FLASH = 0x0404  # Write Flash
CMD_GET_BD_ADDR = 0x0C05  # Get Bluetooth Classic address
CMD_GET_RAM = 0x1680  # Read RAM
CMD_SET_RAM = 0x1681  # Write RAM
CMD_FOTA = 0x1E0F  # FOTA start (Head 0x15)

INVALID_PACKET = "Invalid RACE packet"
TOO_SHORT = "Packet too short"


class RACEError(Exception):
    """Base exception for all RACE protocol/transport failures."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code or "RACEError"


class RACEProtocolError(RACEError):
    """Raised when a response cannot be parsed or is malformed."""


class RACETransportError(RACEError):
    """Raised when a BLE transport operation fails."""


@dataclass(frozen=True)
class RacePacket:
    """Normalized view of a parsed RACE frame."""

    head: int
    ptype: int
    length: int
    cmd: int
    payload: bytes

    def is_response(self) -> bool:
        return self.ptype == 0x01


def _unpack_header(data: bytes) -> tuple[int, int, int]:
    if len(data) < 4:
        raise RACEProtocolError(TOO_SHORT, code="TOO_SHORT")
    head, ptype, length = struct.unpack_from("<BBH", data, 0)
    if length < 2:
        raise RACEProtocolError("Length field smaller than CMD(2B)", code="BAD_LENGTH")
    return head, ptype, length


def build_race_packet(
    cmd: int,
    payload: bytes = b"",
    *,
    head: int = 0x05,
    config: RACEConfig | None = None,
) -> bytes:
    """Build a RACE request frame."""
    config = config or RACEConfig()
    pkt_type = 0x00
    length = 2 + len(payload)
    header = config.frame_header(head, pkt_type, length)
    cmd_bytes = config.cmd(cmd)
    return header + cmd_bytes + payload


def parse_race_response(data: bytes, *, config: RACEConfig | None = None) -> RacePacket:
    """Parse a RACE response into a validated :class:`RacePacket`."""
    config = config or RACEConfig()
    if not isinstance(data, (bytes, bytearray)) or len(data) < 6:
        raise RACEProtocolError(TOO_SHORT, code="TOO_SHORT")

    head, ptype, length = _unpack_header(data)
    if head not in (config.head_standard, config.head_fota):
        raise RACEProtocolError(
            f"Unexpected frame head 0x{head:02X} (expected 0x{config.head_standard:02X} "
            f"or 0x{config.head_fota:02X})",
            code="BAD_HEAD",
        )
    if ptype not in (0x00, 0x01):
        raise RACEProtocolError(f"Invalid frame type 0x{ptype:02X}", code="BAD_TYPE")
    if length < 2:
        raise RACEProtocolError("Length smaller than CMD", code="BAD_LENGTH")

    offset = 4
    cmd = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    payload = data[offset : offset + length - 2]
    if len(payload) != length - 2:
        raise RACEProtocolError("Payload overruns frame", code="BAD_LENGTH")

    return RacePacket(head=head, ptype=ptype, length=length, cmd=cmd, payload=payload)
