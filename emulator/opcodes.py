"""Friendly opcode names shared by the emulator, explorer and fault parser.

Keeping aliases in one place means a researcher can type ``flash_read`` on
the command line instead of remembering ``0x0403``, while the wire still
carries the numeric opcode.
"""

from __future__ import annotations

from utils.packet import (
    CMD_FOTA,
    CMD_GET_BD_ADDR,
    CMD_GET_BUILD,
    CMD_GET_RAM,
    CMD_READ_FLASH,
    CMD_SET_RAM,
    CMD_WRITE_FLASH,
)

#: Accepted aliases (lower-case) mapped to wire opcodes.
COMMAND_NAMES: dict[str, int] = {
    "build": CMD_GET_BUILD,
    "get_build": CMD_GET_BUILD,
    "build_version": CMD_GET_BUILD,
    "bd_addr": CMD_GET_BD_ADDR,
    "bdaddr": CMD_GET_BD_ADDR,
    "get_bd_addr": CMD_GET_BD_ADDR,
    "flash_read": CMD_READ_FLASH,
    "read_flash": CMD_READ_FLASH,
    "flash": CMD_READ_FLASH,
    "flash_write": CMD_WRITE_FLASH,
    "write_flash": CMD_WRITE_FLASH,
    "ram_read": CMD_GET_RAM,
    "read_ram": CMD_GET_RAM,
    "ram": CMD_GET_RAM,
    "ram_write": CMD_SET_RAM,
    "write_ram": CMD_SET_RAM,
    "fota": CMD_FOTA,
}

#: Canonical short name per opcode, used for display.
CANONICAL_NAMES: dict[int, str] = {
    CMD_GET_BUILD: "build",
    CMD_GET_BD_ADDR: "bd_addr",
    CMD_READ_FLASH: "flash_read",
    CMD_WRITE_FLASH: "flash_write",
    CMD_GET_RAM: "ram_read",
    CMD_SET_RAM: "ram_write",
    CMD_FOTA: "fota",
}


class OpcodeError(ValueError):
    """Raised when a textual opcode cannot be resolved."""


def resolve_opcode(text: str) -> int:
    """Resolve ``0x1E08``, ``7784``, ``build`` or ``flash_read`` to an opcode."""
    value = text.strip().lower()
    if not value:
        raise OpcodeError("empty opcode")

    if value in COMMAND_NAMES:
        return COMMAND_NAMES[value]

    try:
        number = int(value, 16) if value.startswith("0x") else int(value, 0)
    except ValueError:
        raise OpcodeError(
            f"unknown opcode {text!r}; use a number (0x1E08) or one of "
            f"{', '.join(sorted(COMMAND_NAMES))}"
        ) from None

    if not 0 <= number <= 0xFFFF:
        raise OpcodeError(f"opcode {text!r} is outside the 16-bit range")
    return number


def opcode_name(cmd: int) -> str:
    """Return the canonical name for *cmd*, or a hex literal when unknown."""
    return CANONICAL_NAMES.get(cmd, f"0x{cmd:04X}")


def is_known(cmd: int) -> bool:
    """True when the opcode is implemented by the synthetic responder."""
    return cmd in CANONICAL_NAMES
