"""Status words used by the synthetic RACE peripheral.

The real protocol returns a little-endian status word for commands that do
not have a data payload (flash write, RAM write, FOTA).  The emulator uses
the same shape and reserves ``0x7E01`` for injected faults so a faulted
reply is distinguishable from a genuine command failure.
"""

from __future__ import annotations

STATUS_OK = 0x0000
STATUS_UNSUPPORTED = 0x0001
STATUS_OUT_OF_RANGE = 0x0002
STATUS_BAD_REQUEST = 0x0003
STATUS_READ_ONLY = 0x0004
STATUS_INJECTED = 0x7E01

STATUS_NAMES: dict[int, str] = {
    STATUS_OK: "OK",
    STATUS_UNSUPPORTED: "UNSUPPORTED",
    STATUS_OUT_OF_RANGE: "OUT_OF_RANGE",
    STATUS_BAD_REQUEST: "BAD_REQUEST",
    STATUS_READ_ONLY: "READ_ONLY",
    STATUS_INJECTED: "INJECTED_FAULT",
}


def status_name(code: int) -> str:
    """Return a stable, human-readable name for a status word."""
    return STATUS_NAMES.get(code, f"UNKNOWN(0x{code:04X})")
