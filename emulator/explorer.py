"""Interactive / scripted protocol explorer for the virtual headphone.

This is the "lab bench" for the emulator: every exchange is printed as raw
frame bytes next to a decoded summary, so the frame layout, status words and
fault effects are visible without a radio or a packet capture.

It is deliberately dependency-free (no click, no colorama) and is shared by
``python3 -m emulator`` and ``python3 race.py emulate``.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Iterable, Sequence

from utils.config import RACEConfig
from utils.packet import (
    CMD_FOTA,
    CMD_GET_BD_ADDR,
    CMD_GET_BUILD,
    CMD_GET_RAM,
    CMD_READ_FLASH,
    CMD_SET_RAM,
    CMD_WRITE_FLASH,
    RACEError,
    RacePacket,
    build_race_packet,
    parse_race_response,
)

from .device import PROFILES, DeviceProfile, VirtualHeadphone, profile_names
from .faults import FaultSpecError, parse_fault_spec
from .opcodes import OpcodeError, opcode_name, resolve_opcode
from .responses import KEY_BLOCK_OFFSETS
from .session import VirtualSession
from .status import status_name

HEX_COLUMN = 56
HELP_TEXT = """\
Commands
  build                      read build version (0x1E08)
  bdaddr                     read Classic address (0x0C05)
  flash OFFSET [COUNT]       read flash page(s) (0x0403), e.g. flash 0x1A000
  write-flash OFF HEX        write flash bytes (0x0404), e.g. write-flash 0x1A020 DEADBEEF
  ram [ADDR] [LEN]           read RAM (0x1680)
  fota [HEX]                 send FOTA bytes with head 0x15 (0x1E0F)
  cmd OPCODE [HEX]           send any command, e.g. cmd 0x1E08
  send HEX                   send a raw frame, e.g. send 05000200081E
  fault SPEC                 add a fault, e.g. fault 0x1E08:silent
  faults                     list active fault rules
  clear-faults               remove every fault rule
  dump OFFSET [LEN]          hexdump the device's local flash image
  scan                       show the virtual advertisement
  profiles                   list built-in synthetic profiles
  state                      show counters, memory and fault state
  reset                      reset counters, fault counters and flash image
  help                       show this text
  quit / exit                leave the explorer"""


def hex_bytes(data: bytes, limit: int = 14) -> str:
    """Format bytes for the trace column, truncating long frames."""
    shown = data[:limit].hex(" ").upper()
    if len(data) > limit:
        shown += f" ... (+{len(data) - limit} B)"
    return shown


def _status_from(payload: bytes) -> int | None:
    if len(payload) < 2:
        return None
    return struct.unpack_from("<H", payload, 0)[0]


def describe_response(pkt: RacePacket) -> str:
    """Summarise a parsed response payload in one line."""
    payload = pkt.payload
    cmd = pkt.cmd

    if cmd == CMD_GET_BUILD:
        text = payload.decode("utf-8", errors="replace").strip("\x00")
        return f'"{text}"'

    if cmd == CMD_GET_BD_ADDR:
        if len(payload) >= 6:
            return f"BD_ADDR {payload[:6].hex(':').upper()}"
        return f"short BD_ADDR payload ({len(payload)} B)"

    if cmd == CMD_READ_FLASH:
        if len(payload) == 2:
            status = _status_from(payload)
            return f"status 0x{status:04X} ({status_name(status)})"
        if len(payload) >= 6:
            status, offset = struct.unpack_from("<HI", payload, 0)
            return (
                f"status {status_name(status)} offset 0x{offset:05X} "
                f"data {len(payload) - 6} B"
            )
        return f"data {len(payload)} B (no status prefix)"

    if cmd in (CMD_WRITE_FLASH, CMD_FOTA):
        status = _status_from(payload)
        if status is not None:
            return f"status 0x{status:04X} ({status_name(status)})"
        return f"{len(payload)} B"

    if cmd == CMD_GET_RAM:
        if len(payload) >= 6:
            status, address = struct.unpack_from("<HI", payload, 0)
            return (
                f"status {status_name(status)} address 0x{address:04X} "
                f"data {len(payload) - 6} B"
            )
        return f"data {len(payload)} B"

    if cmd == CMD_SET_RAM:
        status = _status_from(payload)
        if status is not None:
            return f"status 0x{status:04X} ({status_name(status)})"
        return f"{len(payload)} B"

    return f"payload {hex_bytes(payload, 12)}"


def describe_frame(frame: bytes) -> str:
    """Decode a complete frame, including malformed/pathological ones."""
    try:
        pkt = parse_race_response(frame)
    except RACEError as exc:
        return f"parse error {exc.code}: {exc}"
    kind = "response" if pkt.is_response() else "request"
    detail = describe_response(pkt) if pkt.is_response() else ""
    text = (
        f"{kind} {opcode_name(pkt.cmd)}(0x{pkt.cmd:04X}) "
        f"len={pkt.length} head=0x{pkt.head:02X}"
    )
    return f"{text} | {detail}" if detail else text


def hexdump(data: bytes, base: int = 0, width: int = 16) -> list[str]:
    """Classic offset / hex / ASCII dump used by the ``dump`` command."""
    lines: list[str] = []
    for index in range(0, len(data), width):
        chunk = data[index : index + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        lines.append(f"  0x{base + index:05X}  {hex_part:<47}  {ascii_part}")
    return lines


class Explorer:
    """Drive a :class:`VirtualHeadphone` with text commands."""

    def __init__(
        self,
        device: VirtualHeadphone,
        *,
        out: Callable[[str], None] = print,
        read_timeout: float = 1.0,
        config: RACEConfig | None = None,
    ) -> None:
        self.device = device
        self.config = config or device.config
        self.out = out
        self.session = VirtualSession(
            device, read_timeout=read_timeout, config=self.config
        )
        self._open = False

    async def __aenter__(self) -> Explorer:
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def open(self) -> None:
        if not self._open:
            await self.session.open()
            self._open = True

    async def close(self) -> None:
        if self._open:
            self._open = False
            await self.session.close()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _show_request(self, frame: bytes) -> None:
        self.out(
            f"{'REQ':<4} {hex_bytes(frame):<{HEX_COLUMN}} | {describe_frame(frame)}"
        )

    def _show_responses(self, responses: Sequence[bytes]) -> None:
        if not responses:
            self.out(
                f"{'RSP':<4} {'-- no response --':<{HEX_COLUMN}} | "
                f"nothing within {self.session.read_timeout:g}s"
            )
            return
        for index, frame in enumerate(responses, start=1):
            label = "RSP" if len(responses) == 1 else f"RSP{index}"
            self.out(
                f"{label:<4} {hex_bytes(frame):<{HEX_COLUMN}} | {describe_frame(frame)}"
            )

    async def exchange(self, label: str, frame: bytes) -> list[bytes]:
        self.out(f"[{label}]")
        self._show_request(frame)
        responses = await self.session.send_frame(frame)
        self._show_responses(responses)
        return responses

    async def command(
        self,
        cmd: int,
        payload: bytes = b"",
        *,
        head: int | None = None,
    ) -> list[bytes]:
        label = opcode_name(cmd)
        frame_head = self.config.head_standard if head is None else head
        frame = build_race_packet(
            cmd, payload, head=frame_head, config=self.config
        )
        return await self.exchange(label, frame)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    async def execute(self, line: str) -> bool:
        """Execute one explorer command.  Returns ``False`` to stop."""
        text = line.strip()
        if not text or text.startswith("#"):
            return True
        parts = text.split()
        name = parts[0].lower()
        args = parts[1:]

        if name in ("quit", "exit", "q"):
            return False
        if name in ("help", "?"):
            self.out(HELP_TEXT)
            return True
        if name == "build":
            await self.command(CMD_GET_BUILD)
            return True
        if name in ("bdaddr", "bd-addr", "bd_addr"):
            await self.command(CMD_GET_BD_ADDR)
            return True
        if name in ("flash", "flash-read", "flash_read", "read-flash"):
            await self._cmd_flash_read(args)
            return True
        if name in ("write-flash", "write_flash", "flash-write"):
            await self._cmd_flash_write(args)
            return True
        if name in ("ram", "ram-read", "ram_read"):
            await self._cmd_ram_read(args)
            return True
        if name in ("write-ram", "write_ram", "ram-write"):
            await self._cmd_ram_write(args)
            return True
        if name == "fota":
            payload = self._parse_hex("".join(args)) if args else b""
            await self.command(CMD_FOTA, payload, head=self.config.head_fota)
            return True
        if name == "cmd":
            await self._cmd_generic(args)
            return True
        if name == "send":
            await self._cmd_send(args)
            return True
        if name == "fault":
            self._cmd_fault(args)
            return True
        if name == "faults":
            self._cmd_faults()
            return True
        if name in ("clear-faults", "clear_faults"):
            self.device.fault_plan.clear()
            self.out("[*] all fault rules cleared")
            return True
        if name == "dump":
            self._cmd_dump(args)
            return True
        if name == "scan":
            self._cmd_scan()
            return True
        if name == "profiles":
            self._cmd_profiles()
            return True
        if name == "state":
            self._cmd_state()
            return True
        if name == "reset":
            self.device.reset()
            self.out("[*] counters, fault counters and synthetic memory reset")
            return True

        self.out(f"[!] unknown command {name!r}; type 'help'")
        return True

    async def _cmd_flash_read(self, args: Sequence[str]) -> None:
        if not args:
            self.out("[!] usage: flash OFFSET [COUNT]   e.g. flash 0x1A000")
            return
        offset = self._parse_int(args[0], "offset")
        count = self._parse_int(args[1], "count") if len(args) > 1 else 1
        payload = struct.pack("<BHI", 0x00, count, offset)
        await self.command(CMD_READ_FLASH, payload)

    async def _cmd_flash_write(self, args: Sequence[str]) -> None:
        if len(args) < 2:
            self.out("[!] usage: write-flash OFFSET HEX   e.g. write-flash 0x1A020 DEADBEEF")
            return
        offset = self._parse_int(args[0], "offset")
        data = self._parse_hex("".join(args[1:]))
        payload = struct.pack("<BHI", 0x00, max(1, (len(data) + 0xFF) // 0x100), offset)
        self.out(f"[*] {len(data)} B of data in the 0x0404 request")
        await self.command(CMD_WRITE_FLASH, payload + data)

    async def _cmd_ram_read(self, args: Sequence[str]) -> None:
        address = self._parse_int(args[0], "address") if args else 0
        length = self._parse_int(args[1], "length") if len(args) > 1 else 64
        payload = struct.pack("<IH", address, length)
        await self.command(CMD_GET_RAM, payload)

    async def _cmd_ram_write(self, args: Sequence[str]) -> None:
        if len(args) < 2:
            self.out("[!] usage: write-ram ADDRESS HEX")
            return
        address = self._parse_int(args[0], "address")
        data = self._parse_hex("".join(args[1:]))
        payload = struct.pack("<IH", address, len(data)) + data
        await self.command(CMD_SET_RAM, payload)

    async def _cmd_generic(self, args: Sequence[str]) -> None:
        if not args:
            self.out("[!] usage: cmd OPCODE [HEX]")
            return
        try:
            cmd = resolve_opcode(args[0])
        except OpcodeError as exc:
            self.out(f"[!] {exc}")
            return
        payload = self._parse_hex("".join(args[1:])) if len(args) > 1 else b""
        head = self.config.head_fota if cmd == CMD_FOTA else self.config.head_standard
        await self.command(cmd, payload, head=head)

    async def _cmd_send(self, args: Sequence[str]) -> None:
        if not args:
            self.out("[!] usage: send HEX   e.g. send 05000200081E")
            return
        try:
            frame = self._parse_hex("".join(args))
        except ValueError as exc:
            self.out(f"[!] {exc}")
            return
        await self.exchange("raw", frame)

    def _cmd_fault(self, args: Sequence[str]) -> None:
        if not args:
            self.out("[!] usage: fault SPEC   e.g. fault 0x1E08:silent")
            return
        spec = " ".join(args)
        try:
            rule = parse_fault_spec(spec)
        except FaultSpecError as exc:
            self.out(f"[!] {exc}")
            return
        self.device.fault_plan.add(rule)
        self.out(f"[*] fault added: {rule.describe()}")

    def _cmd_faults(self) -> None:
        rules = self.device.fault_plan.rules
        if not rules:
            self.out("[*] no fault rules")
            return
        self.out("[*] fault rules (first match wins):")
        for index, rule in enumerate(rules, start=1):
            self.out(f"  {index}. {rule.describe()}")

    def _cmd_dump(self, args: Sequence[str]) -> None:
        offset = self._parse_int(args[0], "offset") if args else 0x1A000
        length = self._parse_int(args[1], "length") if len(args) > 1 else 0x100
        flash = self.device.flash
        if offset >= len(flash):
            self.out(f"[!] offset 0x{offset:05X} is outside the flash image")
            return
        end = min(offset + length, len(flash))
        self.out(
            f"[*] local flash image 0x{offset:05X}-0x{end - 1:05X} "
            f"({end - offset} B, no radio traffic)"
        )
        for line in hexdump(bytes(flash[offset:end]), base=offset):
            self.out(line)

    def _cmd_scan(self) -> None:
        device = self.device
        self.out("[*] virtual advertisement (in-process, no radio):")
        self.out(
            f"    {device.address}  {device.name}  rssi={device.rssi} dBm"
        )
        if device.expose_service:
            chars = ", ".join(
                char.uuid for char in device.services[0].characteristics
            ) or "none"
            self.out(
                f"    RACE service {device.config.service_uuid} exposed"
                f" (characteristics: {chars})"
            )
        else:
            self.out("    no RACE service exposed (SERVICE_NOT_FOUND scenario)")

    def _cmd_profiles(self) -> None:
        self.out("[*] built-in profiles:")
        for key in profile_names():
            profile: DeviceProfile = PROFILES[key]
            self.out(f"    {key:<18} {profile.name:<24} {profile.description}")

    def _cmd_state(self) -> None:
        device = self.device
        session = device.stats
        self.out("[*] virtual headphone state:")
        self.out(f"    profile        {device.profile.key} ({device.name})")
        self.out(f"    address        {device.address}   bd_addr {device.bd_addr}")
        self.out(f"    build          {device.build}")
        self.out(f"    connected      {device.connected}")
        self.out(
            f"    requests       {session.requests} "
            f"(responses {session.responses}, faults {session.faults_fired}, "
            f"malformed {session.malformed_requests}, drops {session.disconnects})"
        )
        self.out(
            f"    memory         {len(device.flash)} B flash, "
            f"{device.responder.page_size} B/page, "
            f"{len(KEY_BLOCK_OFFSETS)} synthetic key block(s)"
        )
        if device.fault_plan.rules:
            self.out("    faults         " + "; ".join(
                rule.describe() for rule in device.fault_plan
            ))
        else:
            self.out("    faults         none")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_int(text: str, label: str) -> int:
        try:
            value = int(text, 0)
        except ValueError:
            raise ValueError(f"invalid {label} {text!r} (use decimal or 0x hex)") from None
        if value < 0:
            raise ValueError(f"{label} must not be negative")
        return value

    @staticmethod
    def _parse_hex(text: str) -> bytes:
        cleaned = (
            text.replace("0x", "")
            .replace(" ", "")
            .replace(":", "")
            .replace("-", "")
            .strip()
        )
        if not cleaned:
            return b""
        if len(cleaned) % 2:
            raise ValueError("hex payload must have an even number of digits")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"invalid hex payload: {exc}") from None

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------
    async def run_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            text = line.rstrip("\n")
            if not text.strip():
                continue
            try:
                keep_going = await self.execute(text)
            except (ValueError, OpcodeError, FaultSpecError) as exc:
                self.out(f"[!] {exc}")
                continue
            except RuntimeError as exc:
                self.out(f"[!] {exc}")
                break
            if not keep_going:
                break

    async def run_interactive(self, prompt: str = "emu> ") -> None:
        self.out("Type 'help' for commands, 'quit' to leave.")
        while True:
            try:
                line = input(prompt)
            except (EOFError, KeyboardInterrupt):
                self.out("")
                break
            try:
                keep_going = await self.execute(line)
            except (ValueError, OpcodeError, FaultSpecError, RuntimeError) as exc:
                self.out(f"[!] {exc}")
                continue
            if not keep_going:
                break


__all__ = [
    "Explorer",
    "HELP_TEXT",
    "describe_frame",
    "describe_response",
    "hex_bytes",
    "hexdump",
]
