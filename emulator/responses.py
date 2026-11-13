"""Synthetic RACE responses for the virtual headphone.

Everything here is generated locally from a seed:

* the build string is an explicit ``EMU`` banner, never a scraped real one
* the Classic address uses documentation-style values
* flash pages contain deterministic *marker* blocks (``EMUK``) that trigger
  the framework's key-scan heuristic without resembling real key material

The responder is transport-agnostic: it takes a command, the request payload
and the request head, and returns the payload the device would notify.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass

from utils.config import FRAME_HEAD_FOTA, FRAME_HEAD_STANDARD
from utils.packet import (
    CMD_FOTA,
    CMD_GET_BD_ADDR,
    CMD_GET_BUILD,
    CMD_GET_RAM,
    CMD_READ_FLASH,
    CMD_SET_RAM,
    CMD_WRITE_FLASH,
)

from .opcodes import opcode_name
from .status import (
    STATUS_BAD_REQUEST,
    STATUS_OK,
    STATUS_OUT_OF_RANGE,
    STATUS_READ_ONLY,
    STATUS_UNSUPPORTED,
    status_name,
)

#: Marker that makes synthetic key candidates obvious in a hex dump.
KEY_MARKER = b"EMUK"
SETTINGS_MARKER = b"EMU-SETTINGS v1"

DEFAULT_FLASH_SIZE = 0x20000  # 128 KiB: covers 0x1A000-0x1DFFF
DEFAULT_PAGE_SIZE = 0x100    # 256 B per page read
DEFAULT_RAM_SIZE = 0x4000
MAX_PAGES_PER_READ = 16
MAX_RAM_READ = 512

#: Offsets inside the flash image that hold synthetic key-like blocks.
KEY_BLOCK_OFFSETS = (0x1A020, 0x1A070, 0x1B020)
SETTINGS_OFFSET = 0x1C000
CALIBRATION_OFFSET = 0x1C040


@dataclass(frozen=True)
class Response:
    """A synthetic reply before it is framed."""

    cmd: int
    payload: bytes
    head: int = FRAME_HEAD_STANDARD
    note: str = ""


class SyntheticResponder:
    """Deterministic RACE command handler with a local flash/RAM image."""

    def __init__(
        self,
        *,
        build: str,
        bd_addr: bytes,
        seed: int = 0,
        flash_size: int = DEFAULT_FLASH_SIZE,
        page_size: int = DEFAULT_PAGE_SIZE,
        ram_size: int = DEFAULT_RAM_SIZE,
        read_only: bool = False,
    ) -> None:
        if len(bd_addr) != 6:
            raise ValueError("bd_addr must be exactly 6 bytes")
        if flash_size <= 0 or page_size <= 0 or ram_size <= 0:
            raise ValueError("flash/page/RAM sizes must be positive")
        if page_size > flash_size:
            raise ValueError("page_size cannot exceed flash_size")

        self.build = build
        self.bd_addr = bytes(bd_addr)
        self.seed = seed
        self.flash_size = flash_size
        self.page_size = page_size
        self.ram_size = ram_size
        self.read_only = read_only

        self.flash = bytearray(flash_size)
        self.ram = bytearray(ram_size)
        self.fota_bytes = 0
        self.flash_writes = 0
        self._populate()

    # ------------------------------------------------------------------
    # Synthetic memory
    # ------------------------------------------------------------------
    def _deterministic_bytes(self, tag: str, count: int) -> bytes:
        rng = random.Random(f"{self.seed}:{tag}")
        return bytes(rng.randrange(1, 256) for _ in range(count))

    def _put(self, offset: int, data: bytes) -> None:
        if 0 <= offset < len(self.flash):
            end = min(offset + len(data), len(self.flash))
            self.flash[offset:end] = data[: end - offset]

    def _populate(self) -> None:
        """Fill the image with recognisably synthetic content."""
        for index, offset in enumerate(KEY_BLOCK_OFFSETS):
            block = KEY_MARKER + self._deterministic_bytes(f"ltk-{index}", 12)
            self._put(offset, block)

        self._put(SETTINGS_OFFSET, SETTINGS_MARKER + b"\x00")
        self._put(
            CALIBRATION_OFFSET,
            self._deterministic_bytes("calibration", 64),
        )

        # A small pattern at the start of RAM, so RAM reads are not all zero.
        for index in range(0, min(256, self.ram_size), 4):
            self.ram[index : index + 4] = struct.pack("<I", index * 0x01010101 & 0xFFFFFFFF)

    def regenerate(self) -> None:
        """Reset flash/RAM to their seeded contents."""
        self.flash[:] = b"\x00" * self.flash_size
        self.ram[:] = b"\x00" * self.ram_size
        self.fota_bytes = 0
        self.flash_writes = 0
        self._populate()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def respond(self, cmd: int, payload: bytes, request_head: int) -> Response:
        """Return the synthetic reply for a request frame."""
        head = (
            FRAME_HEAD_FOTA
            if request_head == FRAME_HEAD_FOTA
            else FRAME_HEAD_STANDARD
        )
        payload = bytes(payload)

        if cmd == CMD_GET_BUILD:
            return Response(
                cmd,
                self.build.encode("utf-8") + b"\x00",
                head,
                note="synthetic build banner",
            )
        if cmd == CMD_GET_BD_ADDR:
            return Response(cmd, self.bd_addr, head, note="6-byte Classic address")
        if cmd == CMD_READ_FLASH:
            return self._read_flash(cmd, payload, head)
        if cmd == CMD_WRITE_FLASH:
            return self._write_flash(cmd, payload, head)
        if cmd == CMD_GET_RAM:
            return self._read_ram(cmd, payload, head)
        if cmd == CMD_SET_RAM:
            return self._write_ram(cmd, payload, head)
        if cmd == CMD_FOTA:
            self.fota_bytes += len(payload)
            return Response(
                cmd,
                struct.pack("<H", STATUS_OK),
                head,
                note=f"FOTA accepted ({self.fota_bytes} bytes total)",
            )

        return self._status(
            cmd,
            STATUS_UNSUPPORTED,
            head,
            note=f"opcode not implemented by emulator ({opcode_name(cmd)})",
        )

    # ------------------------------------------------------------------
    # Individual commands
    # ------------------------------------------------------------------
    def _status(self, cmd: int, code: int, head: int, note: str = "") -> Response:
        return Response(
            cmd,
            struct.pack("<H", code),
            head,
            note=note or status_name(code),
        )

    def _read_flash(self, cmd: int, payload: bytes, head: int) -> Response:
        if len(payload) < 7:
            return self._status(
                cmd, STATUS_BAD_REQUEST, head, "flash read needs 7-byte descriptor"
            )

        _reserved, count, offset = struct.unpack_from("<BHI", payload, 0)
        pages = max(1, min(count, MAX_PAGES_PER_READ))
        if offset >= self.flash_size:
            return self._status(
                cmd,
                STATUS_OUT_OF_RANGE,
                head,
                f"flash offset 0x{offset:05X} outside 0x{self.flash_size:05X}",
            )

        end = min(offset + pages * self.page_size, self.flash_size)
        data = bytes(self.flash[offset:end])
        body = struct.pack("<HI", STATUS_OK, offset) + data
        return Response(
            cmd,
            body,
            head,
            note=(
                f"flash 0x{offset:05X} +{len(data)} B "
                f"({pages} page(s), status {status_name(STATUS_OK)})"
            ),
        )

    def _write_flash(self, cmd: int, payload: bytes, head: int) -> Response:
        if len(payload) < 7:
            return self._status(
                cmd, STATUS_BAD_REQUEST, head, "flash write needs 7-byte descriptor"
            )
        if self.read_only:
            return self._status(
                cmd, STATUS_READ_ONLY, head, "virtual device is read-only"
            )

        _reserved, _count, offset = struct.unpack_from("<BHI", payload, 0)
        data = payload[7:]
        if offset >= self.flash_size or offset + len(data) > self.flash_size:
            return self._status(
                cmd,
                STATUS_OUT_OF_RANGE,
                head,
                f"flash write 0x{offset:05X} +({len(data)} B) is out of range",
            )

        self.flash[offset : offset + len(data)] = data
        self.flash_writes += 1
        return self._status(
            cmd,
            STATUS_OK,
            head,
            f"flash write 0x{offset:05X} +{len(data)} B accepted",
        )

    def _read_ram(self, cmd: int, payload: bytes, head: int) -> Response:
        address = 0
        length = 64
        if len(payload) >= 4:
            address = struct.unpack_from("<I", payload, 0)[0]
        if len(payload) >= 6:
            length = struct.unpack_from("<H", payload, 4)[0]
        length = max(1, min(length, MAX_RAM_READ))

        if address >= self.ram_size:
            return self._status(
                cmd,
                STATUS_OUT_OF_RANGE,
                head,
                f"RAM address 0x{address:04X} outside 0x{self.ram_size:04X}",
            )

        end = min(address + length, self.ram_size)
        data = bytes(self.ram[address:end])
        body = struct.pack("<HI", STATUS_OK, address) + data
        return Response(
            cmd,
            body,
            head,
            note=f"RAM 0x{address:04X} +{len(data)} B",
        )

    def _write_ram(self, cmd: int, payload: bytes, head: int) -> Response:
        if len(payload) < 6:
            return self._status(
                cmd, STATUS_BAD_REQUEST, head, "RAM write needs a 6-byte descriptor"
            )
        if self.read_only:
            return self._status(
                cmd, STATUS_READ_ONLY, head, "virtual device is read-only"
            )

        address, length = struct.unpack_from("<IH", payload, 0)
        data = payload[6:]
        if address >= self.ram_size or address + len(data) > self.ram_size:
            return self._status(
                cmd,
                STATUS_OUT_OF_RANGE,
                head,
                f"RAM write 0x{address:04X} +({len(data)} B) is out of range",
            )

        self.ram[address : address + len(data)] = data[:length] if length else data
        return self._status(
            cmd,
            STATUS_OK,
            head,
            f"RAM write 0x{address:04X} +{len(data)} B accepted",
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def report(self) -> dict[str, object]:
        return {
            "build": self.build,
            "bd_addr": self.bd_addr.hex(":").upper(),
            "flash_size": self.flash_size,
            "page_size": self.page_size,
            "ram_size": self.ram_size,
            "flash_writes": self.flash_writes,
            "fota_bytes": self.fota_bytes,
            "read_only": self.read_only,
            "key_block_offsets": [f"0x{offset:05X}" for offset in KEY_BLOCK_OFFSETS],
        }


__all__ = [
    "CALIBRATION_OFFSET",
    "DEFAULT_FLASH_SIZE",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_RAM_SIZE",
    "KEY_BLOCK_OFFSETS",
    "KEY_MARKER",
    "Response",
    "SETTINGS_MARKER",
    "SETTINGS_OFFSET",
    "SyntheticResponder",
]
