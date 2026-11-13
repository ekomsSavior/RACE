"""Configuration management for the RACE framework.

Central place for protocol constants and CLI defaults so that other
modules do not hardcode UUIDs/commands again.  Everything here can be
overridden from the command line (click) or, in the future, a config
file.  The CLI passes the parsed overrides into each subsystem.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# RACE service / characteristic UUIDs (BLE).
SERVICE_UUID = "00001200-0000-1000-8000-00805f9b34fb"
TX_UUID = "00001201-0000-1000-8000-00805f9b34fb"
RX_UUID = "00001202-0000-1000-8000-00805f9b34fb"

# Frame layout per the RACE protocol specification:
#   Head(1B) Type(1B) Length(2B LE) CMD(2B) Payload(N)
# The payload length field therefore covers CMD + payload.
FRAME_HEAD_STANDARD = 0x05
FRAME_HEAD_FOTA = 0x15
FRAME_TYPE_REQUEST = 0x00
FRAME_TYPE_RESPONSE = 0x01
FRAME_HEADER_FMT = "<BBH"  # head, type, length
FRAME_CMD_FMT = "<H"  # little-endian command opcode


@dataclass(frozen=True)
class RACEConfig:
    """Invariant defaults.  CLI defaults are produced by
    ``RACEConfig.cli_defaults()`` and merged over this object.
    """

    service_uuid: str = SERVICE_UUID
    tx_uuid: str = TX_UUID
    rx_uuid: str = RX_UUID
    head_standard: int = FRAME_HEAD_STANDARD
    head_fota: int = FRAME_HEAD_FOTA
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 5.0
    scan_timeout_s: float = 10.0
    # Optional wire capture: path is ``None`` until a session asks for one
    # (``--capture`` or ``RACE_CAPTURE``); format is inferred from the
    # extension when ``None``.  See :mod:`utils.capture`.
    capture_path: str | None = None
    capture_format: str | None = None

    def frame_header(self, head: int, ptype: int, payload_len: int) -> bytes:
        return struct.pack(FRAME_HEADER_FMT, head, ptype, payload_len)

    def cmd(self, opcode: int) -> bytes:
        return struct.pack(FRAME_CMD_FMT, opcode)

    @classmethod
    def cli_defaults(cls) -> RACEConfig:
        return cls()
