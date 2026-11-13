"""The virtual headphone: a simulated RACE GATT peripheral.

``VirtualHeadphone`` owns the device state (identity, flash, RAM, fault plan),
accepts request frames on the TX characteristic and returns the frames the
device would notify on RX.  It has no radio, no sockets and no dependency on
bleak — :mod:`emulator.client` adapts it to the small bleak surface the real
transport uses.

Faults are evaluated per request and can change four things: whether a reply
is produced at all, when it is delivered, what status word it carries, and
whether the raw frame is well-formed.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from utils.config import (
    FRAME_TYPE_REQUEST,
    FRAME_TYPE_RESPONSE,
    RACEConfig,
)

from .faults import FaultKind, FaultPlan, FaultRule
from .gatt import SimService, build_race_service
from .opcodes import is_known, opcode_name
from .responses import (
    DEFAULT_FLASH_SIZE,
    DEFAULT_PAGE_SIZE,
    Response,
    SyntheticResponder,
)
from .status import status_name

#: Bytes returned for :attr:`FaultKind.GARBAGE` — stable, clearly not RACE.
GARBAGE_FRAME = b"\xde\xad\xbe\xef\x00\x01\x02\x03"


@dataclass(frozen=True)
class DeviceProfile:
    """Synthetic identity advertised by a virtual headphone."""

    key: str
    name: str
    build: str
    address: str
    rssi: int = -42
    seed: int = 0
    description: str = ""

    @property
    def bd_addr_bytes(self) -> bytes:
        raw = bytes.fromhex(self.address.replace(":", ""))
        if len(raw) != 6:
            raise ValueError(f"profile {self.key!r} has an invalid address")
        return raw


#: Built-in profiles.  Every value is synthetic; no real device is cloned.
PROFILES: dict[str, DeviceProfile] = {
    "sony-wh1000xm5": DeviceProfile(
        key="sony-wh1000xm5",
        name="WH-1000XM5",
        build="EMU AB1585 SDK 1.2.3 build 2026-01-01 profile=sony-wh1000xm5",
        address="A0:12:34:56:78:90",
        rssi=-42,
        seed=0x1E08,
        description="over-ear, standard RACE service, answers every command",
    ),
    "sony-wf1000xm5": DeviceProfile(
        key="sony-wf1000xm5",
        name="WF-1000XM5",
        build="EMU AB1571 SDK 1.1.0 build 2025-11-14 profile=sony-wf1000xm5",
        address="A0:12:34:56:78:91",
        rssi=-55,
        seed=0x1E09,
        description="in-ear, slower responder, useful for timeout exercises",
    ),
    "marshall-major-v": DeviceProfile(
        key="marshall-major-v",
        name="MAJOR V",
        build="EMU AB1565 SDK 0.9.7 build 2025-08-02 profile=marshall-major-v",
        address="B4:0E:2D:11:22:33",
        rssi=-61,
        seed=0x0BAD,
        description="headband profile with a smaller flash window content set",
    ),
    "jbl-live-buds-3": DeviceProfile(
        key="jbl-live-buds-3",
        name="Live Buds 3",
        build="EMU AB1562 SDK 1.0.4 build 2025-09-19 profile=jbl-live-buds-3",
        address="C8:5A:CF:44:55:66",
        rssi=-67,
        seed=0x0403,
        description="earbud profile; good baseline for fault comparisons",
    ),
    "bose-qc-earbuds-3": DeviceProfile(
        key="bose-qc-earbuds-3",
        name="QuietComfort Earbuds III",
        build="EMU AB1585 SDK 1.3.0 build 2026-02-11 profile=bose-qc-earbuds-3",
        address="D4:9C:28:77:88:99",
        rssi=-59,
        seed=0x0C05,
        description="profile that exposes the full service table",
    ),
    "generic-airoha": DeviceProfile(
        key="generic-airoha",
        name="RACE Reference Design",
        build="EMU AB1600 SDK 2.0.0-rc1 build 2026-03-01 profile=generic-airoha",
        address="E8:9F:6D:AA:BB:CC",
        rssi=-48,
        seed=0x1600,
        description="neutral reference profile for protocol teaching",
    ),
}

DEFAULT_PROFILE = "sony-wh1000xm5"


def profile_names() -> list[str]:
    return list(PROFILES)


def load_profile(name: str) -> DeviceProfile:
    """Look up a profile by key or advertised name."""
    key = name.strip().lower()
    if key in PROFILES:
        return PROFILES[key]
    for profile in PROFILES.values():
        if profile.name.lower() == key:
            return profile
    raise KeyError(
        f"unknown profile {name!r}; available: {', '.join(PROFILES)}"
    )


@dataclass
class TraceEntry:
    """One line of the emulator's request/response log."""

    direction: str  # "req", "rsp" or "note"
    frame: bytes = b""
    note: str = ""
    fault: FaultKind | None = None


@dataclass(frozen=True)
class Outbound:
    """A frame ready to be notified, optionally after a delay."""

    frame: bytes
    delay_s: float = 0.0
    fault: FaultKind | None = None


@dataclass
class DeviceStats:
    connections: int = 0
    requests: int = 0
    responses: int = 0
    faults_fired: int = 0
    malformed_requests: int = 0
    disconnects: int = 0


class VirtualHeadphone:
    """A simulated Airoha-style headphone exposing the RACE GATT service."""

    def __init__(
        self,
        profile: DeviceProfile | str = DEFAULT_PROFILE,
        *,
        config: RACEConfig | None = None,
        errors: Iterable[FaultRule] = (),
        fault_plan: FaultPlan | None = None,
        fault_seed: int | float | str | None = 0,
        expose_service: bool = True,
        expose_tx: bool = True,
        expose_rx: bool = True,
        flash_size: int = DEFAULT_FLASH_SIZE,
        page_size: int = DEFAULT_PAGE_SIZE,
        slow_response_s: float = 6.0,
        answer_unknown: bool = True,
        read_only: bool = False,
        att_mtu: int | None = None,
    ) -> None:
        self.profile = load_profile(profile) if isinstance(profile, str) else profile
        self.config = config or RACEConfig()

        if att_mtu is not None and not 4 <= att_mtu <= 517:
            raise ValueError("att_mtu must be between 4 and 517")
        self.att_mtu = att_mtu

        self.expose_service = expose_service
        self.expose_tx = expose_tx
        self.expose_rx = expose_rx
        self.slow_response_s = slow_response_s
        self.answer_unknown = answer_unknown

        self.responder = SyntheticResponder(
            build=self.profile.build,
            bd_addr=self.profile.bd_addr_bytes,
            seed=self.profile.seed,
            flash_size=flash_size,
            page_size=page_size,
            read_only=read_only,
        )
        self.fault_plan = fault_plan or FaultPlan(seed=fault_seed)
        self.fault_plan.extend(errors)

        self.connected = False
        self.stats = DeviceStats()
        self.trace: list[TraceEntry] = []
        # Virtual GATT long-write reassembly: the client chunks a request at
        # ATT MTU - 3, the peripheral joins the chunks before dispatching one
        # logical RACE request.
        self._write_buffer = bytearray()
        self._service = build_race_service(
            self.config,
            expose_tx=self.expose_tx,
            expose_rx=self.expose_rx,
        )

    # ------------------------------------------------------------------
    # Identity / GATT
    # ------------------------------------------------------------------
    @property
    def address(self) -> str:
        return self.profile.address

    @property
    def name(self) -> str:
        return self.profile.name

    @property
    def rssi(self) -> int:
        return self.profile.rssi

    @property
    def build(self) -> str:
        return self.responder.build

    @property
    def bd_addr_bytes(self) -> bytes:
        return self.responder.bd_addr

    @property
    def bd_addr(self) -> str:
        return self.responder.bd_addr.hex(":").upper()

    @property
    def flash(self) -> bytearray:
        return self.responder.flash

    @property
    def services(self) -> list[SimService]:
        """GATT table exposed to a central (empty if the service is hidden)."""
        return [self._service] if self.expose_service else []

    @property
    def rx_available(self) -> bool:
        return self.expose_service and self.expose_rx

    @property
    def tx_available(self) -> bool:
        return self.expose_service and self.expose_tx

    @property
    def notification_size(self) -> int | None:
        """Maximum notification payload (``ATT_MTU - 3``), or ``None``.

        ``None`` keeps the emulator's historical one-notification-per-frame
        behaviour; an explicit MTU (23 is the BLE default) fragments responses
        exactly as a real link would.
        """
        if self.att_mtu is None:
            return None
        return self.att_mtu - 3

    # ------------------------------------------------------------------
    # Link lifecycle
    # ------------------------------------------------------------------
    def connect(self) -> None:
        if self.connected:
            raise RuntimeError(
                f"{self.name} already has a central connected; call disconnect() first"
            )
        self.connected = True
        self.stats.connections += 1
        self.trace.append(TraceEntry("note", note="central connected"))

    def disconnect(self) -> None:
        self._write_buffer.clear()
        if self.connected:
            self.connected = False
            self.trace.append(TraceEntry("note", note="central disconnected"))

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------
    def handle_write(self, data: bytes) -> list[Outbound]:
        """Reassemble a possibly-fragmented ATT write, then dispatch it.

        The virtual client splits requests larger than ``ATT_MTU - 3``.  This
        method buffers those chunks and calls :meth:`handle_request` once a
        complete frame is available.  A malformed header is handed to
        ``handle_request`` immediately so it is counted and ignored, matching
        the direct-write behaviour.
        """
        self._write_buffer.extend(data)
        if len(self._write_buffer) < 4:
            return []

        head, ptype, length = struct.unpack_from("<BBH", self._write_buffer, 0)
        if (
            ptype != FRAME_TYPE_REQUEST
            or head not in (self.config.head_standard, self.config.head_fota)
            or length < 2
        ):
            malformed = bytes(self._write_buffer)
            self._write_buffer.clear()
            return self.handle_request(malformed)

        total = 4 + length
        if len(self._write_buffer) < total:
            return []

        frame = bytes(self._write_buffer[:total])
        del self._write_buffer[:total]
        return self.handle_request(frame)

    def handle_request(self, data: bytes) -> list[Outbound]:
        """Process one written request frame and return pending notifications.

        A request that is not a well-formed RACE frame is ignored, exactly as
        a real peripheral would ignore a malformed ATT write.
        """
        frame = bytes(data)
        self.stats.requests += 1
        self.trace.append(TraceEntry("req", frame))

        parsed = self._parse_request(frame)
        if parsed is None:
            self.stats.malformed_requests += 1
            self.trace.append(
                TraceEntry("note", note="malformed request ignored")
            )
            return []

        head, cmd, payload = parsed
        fault = self.fault_plan.choose(cmd)
        if fault is not None:
            self.stats.faults_fired += 1
            self.trace.append(
                TraceEntry(
                    "note",
                    note=f"fault {fault.kind.value} on {opcode_name(cmd)}",
                    fault=fault.kind,
                )
            )
            if fault.kind is FaultKind.DISCONNECT:
                self.stats.disconnects += 1
                self.connected = False
                self.trace.append(TraceEntry("note", note="link dropped by fault"))
                return []
            if fault.kind is FaultKind.SILENT:
                return []

        if not self.answer_unknown and not is_known(cmd):
            self.trace.append(
                TraceEntry("note", note=f"unknown opcode {opcode_name(cmd)} ignored")
            )
            return []

        response = self.responder.respond(cmd, payload, head)
        if fault is not None and fault.kind is FaultKind.STATUS:
            response = Response(
                cmd,
                struct.pack("<H", fault.status),
                response.head,
                note=f"injected status 0x{fault.status:04X} ({status_name(fault.status)})",
            )

        frame_out = self._build_frame(response)
        frames = [frame_out]

        if fault is not None:
            frame_out = self._corrupt(frame_out, fault.kind)
            frames = [frame_out, frame_out] if fault.kind is FaultKind.DUPLICATE else [frame_out]

        delay = 0.0
        if fault is not None and fault.kind is FaultKind.SLOW:
            delay = (
                fault.delay_s
                if fault.delay_s is not None
                else self.slow_response_s
            )

        outbounds: list[Outbound] = []
        for pending in frames:
            self.stats.responses += 1
            self.trace.append(
                TraceEntry(
                    "rsp",
                    pending,
                    note=response.note,
                    fault=fault.kind if fault else None,
                )
            )
            outbounds.append(
                Outbound(pending, delay_s=delay, fault=fault.kind if fault else None)
            )
        return outbounds

    def _parse_request(self, data: bytes) -> tuple[int, int, bytes] | None:
        if len(data) < 6:
            return None
        head, ptype, length = struct.unpack_from("<BBH", data, 0)
        if ptype != FRAME_TYPE_REQUEST:
            return None
        if head not in (self.config.head_standard, self.config.head_fota):
            return None
        if length < 2 or 4 + length > len(data):
            return None
        cmd = struct.unpack_from("<H", data, 4)[0]
        payload = data[6 : 4 + length]
        return head, cmd, payload

    def _build_frame(self, response: Response) -> bytes:
        length = 2 + len(response.payload)
        header = struct.pack(
            "<BBH", response.head, FRAME_TYPE_RESPONSE, length
        )
        return header + struct.pack("<H", response.cmd) + response.payload

    def _corrupt(self, frame: bytes, kind: FaultKind) -> bytes:
        """Break a well-formed response frame according to *kind*."""
        if kind is FaultKind.TRUNCATE:
            return frame[:3]
        if kind is FaultKind.BAD_HEAD:
            return bytes([frame[0] ^ 0x02]) + frame[1:]
        if kind is FaultKind.BAD_TYPE:
            return frame[:1] + b"\x02" + frame[2:]
        if kind is FaultKind.BAD_LENGTH:
            return frame[:2] + b"\x00\x00" + frame[4:]
        if kind is FaultKind.GARBAGE:
            return GARBAGE_FRAME
        return frame

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------
    def client(self, address: str | None = None):
        """Create a bleak-compatible client bound to this device."""
        from .client import VirtualBleakClient

        return VirtualBleakClient(self, address=address or self.address)

    def reset_stats(self) -> None:
        self.stats = DeviceStats()
        self.trace.clear()

    def reset(self) -> None:
        """Reset counters, fault counters and the synthetic memory image."""
        self._write_buffer.clear()
        self.reset_stats()
        self.fault_plan.reset()
        self.responder.regenerate()

    def report(self) -> dict[str, Any]:
        """JSON-serialisable snapshot for ``--json`` and ``state``."""
        return {
            "profile": self.profile.key,
            "name": self.name,
            "address": self.address,
            "bd_addr": self.bd_addr,
            "build": self.build,
            "rssi": self.rssi,
            "connected": self.connected,
            "service_uuid": self.config.service_uuid,
            "expose_service": self.expose_service,
            "expose_tx": self.expose_tx,
            "expose_rx": self.expose_rx,
            "att_mtu": self.att_mtu,
            "notification_size": self.notification_size,
            "stats": {
                "connections": self.stats.connections,
                "requests": self.stats.requests,
                "responses": self.stats.responses,
                "faults_fired": self.stats.faults_fired,
                "malformed_requests": self.stats.malformed_requests,
                "disconnects": self.stats.disconnects,
            },
            "faults": [rule.describe() for rule in self.fault_plan],
            "memory": self.responder.report(),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return (
            f"VirtualHeadphone(profile={self.profile.key!r}, "
            f"address={self.address!r}, connected={self.connected})"
        )


__all__ = [
    "DEFAULT_PROFILE",
    "GARBAGE_FRAME",
    "DeviceProfile",
    "DeviceStats",
    "Outbound",
    "PROFILES",
    "TraceEntry",
    "VirtualHeadphone",
    "load_profile",
    "profile_names",
]
