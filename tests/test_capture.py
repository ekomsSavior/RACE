"""Tests for the raw pcap/btsnoop wire-capture hook."""

import asyncio
import logging
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from transports.ble import BLETransport
from utils.capture import (
    ACL_HANDLE,
    ATT_OP_NOTIFICATION,
    ATT_OP_WRITE_CMD,
    ATT_RX_HANDLE,
    ATT_TX_HANDLE,
    BTSNOOP_DATALINK_H4,
    BTSNOOP_EPOCH_DELTA_US,
    BTSNOOP_MAGIC,
    CAPTURE_ENV_VAR,
    CAPTURE_FILE_MODE,
    CAPTURE_FORMAT_ENV_VAR,
    DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
    H4_ACL_PACKET,
    L2CAP_CID_ATT,
    PCAP_MAGIC,
    PCAP_PHDR_LEN,
    PCAP_PHDR_RECEIVED,
    PCAP_PHDR_SENT,
    PCAP_SNAPLEN,
    WIRE_OVERHEAD,
    CaptureClosedError,
    CaptureError,
    CaptureFormat,
    WireCapture,
    build_att_record,
    close_captures,
    open_capture,
    tap,
)
from utils.config import RACEConfig
from utils.packet import CMD_GET_BUILD, build_race_packet

FRAME_TX = build_race_packet(CMD_GET_BUILD)
FRAME_RX = bytes.fromhex("05 01 04 00 08 1e aa bb")

PCAP_HEADER = struct.Struct("<IHHiIII")
PCAP_RECORD = struct.Struct("<IIII")
BTSNOOP_HEADER = struct.Struct(">II")
BTSNOOP_RECORD = struct.Struct(">IIIIQ")


@pytest.fixture(autouse=True)
def _isolate_captures():
    """Drop shared capture handles between tests (temp dirs disappear)."""
    close_captures()
    yield
    close_captures()


def _clock(value):
    return lambda: value


def _pcap_records(path):
    """Split a pcap into (ts_sec, ts_usec, orig_len, payload) tuples."""
    blob = path.read_bytes()
    assert len(blob) >= PCAP_HEADER.size
    offset = PCAP_HEADER.size
    records = []
    while offset < len(blob):
        ts_sec, ts_usec, incl_len, orig_len = PCAP_RECORD.unpack_from(blob, offset)
        offset += PCAP_RECORD.size
        records.append((ts_sec, ts_usec, orig_len, blob[offset : offset + incl_len]))
        offset += incl_len
    return records


def _btsnoop_records(path):
    blob = path.read_bytes()
    offset = len(BTSNOOP_MAGIC) + BTSNOOP_HEADER.size
    records = []
    while offset < len(blob):
        orig_len, incl_len, flags, drops, ts = BTSNOOP_RECORD.unpack_from(blob, offset)
        offset += BTSNOOP_RECORD.size
        records.append((flags, drops, ts, blob[offset : offset + incl_len]))
        offset += incl_len
    return records


def _att_fields(packet, *, phdr=PCAP_PHDR_LEN):
    """Decode a record (optionally behind a pcap pseudo-header) into ATT fields."""
    direction = struct.unpack_from(">I", packet, 0)[0] if phdr else None
    h4 = packet[phdr:]
    assert h4[0] == H4_ACL_PACKET
    handle_flags, acl_len = struct.unpack_from("<HH", h4, 1)
    l2cap_len, cid = struct.unpack_from("<HH", h4, 5)
    opcode, att_handle = struct.unpack_from("<BH", h4, 9)
    return {
        "direction": direction,
        "handle_flags": handle_flags,
        "acl_len": acl_len,
        "l2cap_len": l2cap_len,
        "cid": cid,
        "opcode": opcode,
        "att_handle": att_handle,
        "value": h4[12:],
    }


# -- format selection ------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("race.pcap", CaptureFormat.PCAP),
        ("race.cap", CaptureFormat.PCAP),
        ("race.btsnoop", CaptureFormat.BTSNOOP),
        ("race.snoop", CaptureFormat.BTSNOOP),
        ("RACE.BTSNOOP", CaptureFormat.BTSNOOP),
        ("no-extension", CaptureFormat.PCAP),
    ],
)
def test_format_is_inferred_from_extension(name, expected):
    assert CaptureFormat.from_path(name) is expected


def test_explicit_format_wins_over_extension(tmp_path):
    assert CaptureFormat.coerce("btsnoop", tmp_path / "x.pcap") is CaptureFormat.BTSNOOP
    assert CaptureFormat.coerce("PCAP", tmp_path / "x.btsnoop") is CaptureFormat.PCAP


def test_native_format_enum_is_passed_through(tmp_path):
    native = CaptureFormat.BTSNOOP
    assert CaptureFormat.coerce(native, tmp_path / "x.pcap") is native


def test_unknown_format_is_rejected(tmp_path):
    with pytest.raises(CaptureError) as error:
        CaptureFormat.coerce("pcapng", tmp_path / "x.pcapng")
    assert error.value.code == "CAPTURE_FORMAT"


def test_handles_must_fit_in_16_bits(tmp_path):
    with pytest.raises(CaptureError) as error:
        WireCapture(tmp_path / "x.pcap", tx_handle=0x10000)
    assert error.value.code == "CAPTURE_HANDLE"


# -- pcap container --------------------------------------------------------


def test_pcap_global_header_is_hci_h4_with_phdr(tmp_path):
    path = tmp_path / "race.pcap"
    with WireCapture(path):
        pass
    magic, major, minor, thiszone, sigfigs, snaplen, network = PCAP_HEADER.unpack_from(
        path.read_bytes()
    )
    assert (magic, major, minor, thiszone, sigfigs) == (PCAP_MAGIC, 2, 4, 0, 0)
    assert snaplen == PCAP_SNAPLEN
    assert network == DLT_BLUETOOTH_HCI_H4_WITH_PHDR == 201


def test_pcap_record_preserves_frame_and_timestamp(tmp_path):
    path = tmp_path / "race.pcap"
    with WireCapture(path, clock=_clock(1_700_000_000.25)) as capture:
        capture.write_tx(FRAME_TX)

    (record,) = _pcap_records(path)
    ts_sec, ts_usec, orig_len, packet = record
    assert (ts_sec, ts_usec) == (1_700_000_000, 250_000)
    assert orig_len == len(packet)

    att = _att_fields(packet)
    assert att["direction"] == PCAP_PHDR_SENT
    assert att["cid"] == L2CAP_CID_ATT
    assert att["opcode"] == ATT_OP_WRITE_CMD
    assert att["att_handle"] == ATT_TX_HANDLE
    assert att["value"] == FRAME_TX
    assert att["l2cap_len"] == att["acl_len"] - 4 == len(packet) - PCAP_PHDR_LEN - 9
    assert att["handle_flags"] & 0x0FFF == ACL_HANDLE


def test_rx_frames_are_notifications(tmp_path):
    path = tmp_path / "race.pcap"
    with WireCapture(path, rx_handle=0x0042) as capture:
        capture.write_rx(FRAME_RX)

    (_, _, _, packet) = _pcap_records(path)[0]
    att = _att_fields(packet)
    assert att["direction"] == PCAP_PHDR_RECEIVED
    assert att["opcode"] == ATT_OP_NOTIFICATION
    assert att["att_handle"] == 0x0042
    assert att["value"] == FRAME_RX


def test_oversized_frame_is_truncated_but_length_is_recorded(tmp_path):
    path = tmp_path / "race.pcap"
    with WireCapture(path) as capture:
        capture.write_tx(b"\x05" * (PCAP_SNAPLEN + 100))

    (_, _, orig_len, packet) = _pcap_records(path)[0]
    # Snap to the snaplen but keep the true on-wire length in the header.
    assert len(packet) == PCAP_SNAPLEN
    assert orig_len == PCAP_SNAPLEN + 100 + WIRE_OVERHEAD + PCAP_PHDR_LEN


# -- btsnoop container -----------------------------------------------------


def test_btsnoop_header_is_h4_datalink(tmp_path):
    path = tmp_path / "race.btsnoop"
    with WireCapture(path):
        pass
    blob = path.read_bytes()
    assert blob.startswith(BTSNOOP_MAGIC)
    version, datalink = BTSNOOP_HEADER.unpack_from(blob, len(BTSNOOP_MAGIC))
    assert version == 1
    assert datalink == BTSNOOP_DATALINK_H4 == 1002


def test_btsnoop_direction_flags_and_epoch(tmp_path):
    path = tmp_path / "race.btsnoop"
    clock = 1_700_000_000.5
    with WireCapture(path, clock=_clock(clock)) as capture:
        capture.write_tx(FRAME_TX)
        capture.write_rx(FRAME_RX)

    tx, rx = _btsnoop_records(path)
    assert tx[0] == 0x00  # sent (host -> controller)
    assert rx[0] == 0x01  # received (controller -> host)
    assert tx[1] == rx[1] == 0  # no cumulative drops
    assert tx[2] == int(clock * 1_000_000) + BTSNOOP_EPOCH_DELTA_US
    assert _att_fields(tx[3], phdr=0)["value"] == FRAME_TX
    assert _att_fields(rx[3], phdr=0)["value"] == FRAME_RX
    assert _att_fields(tx[3], phdr=0)["att_handle"] == ATT_TX_HANDLE
    assert _att_fields(rx[3], phdr=0)["att_handle"] == ATT_RX_HANDLE


# -- recording semantics ---------------------------------------------------


def test_counts_bytes_and_close_are_tracked(tmp_path):
    path = tmp_path / "race.pcap"
    capture = WireCapture(path)
    capture.open()
    capture.open()  # idempotent
    capture.write_tx(FRAME_TX)
    capture.write_rx(FRAME_RX)
    assert capture.frames == 2
    assert capture.bytes == len(FRAME_TX) + len(FRAME_RX)
    assert not capture.closed

    capture.close()
    capture.close()  # idempotent
    assert capture.closed
    with pytest.raises(CaptureClosedError) as error:
        capture.write_rx(FRAME_RX)
    assert error.value.code == "CAPTURE_CLOSED"


@pytest.mark.parametrize("direction", ["up", "down", ""])
def test_unknown_direction_is_rejected(direction):
    with pytest.raises(CaptureError) as error:
        build_att_record(direction, FRAME_TX)
    assert error.value.code == "CAPTURE_DIRECTION"


def test_non_bytes_frames_are_rejected(tmp_path):
    with WireCapture(tmp_path / "race.pcap") as capture:
        with pytest.raises(TypeError):
            capture.record("tx", "not-bytes")  # type: ignore[arg-type]


def test_repr_names_path_and_state(tmp_path):
    capture = WireCapture(tmp_path / "race.btsnoop")
    assert "race.btsnoop" in repr(capture)
    assert "btsnoop" in repr(capture)
    capture.open()
    try:
        assert "open" in repr(capture)
    finally:
        capture.close()
    assert "closed" in repr(capture)


# -- open_capture / environment wiring -------------------------------------


def test_open_capture_returns_none_when_unconfigured(tmp_path, monkeypatch):
    monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
    assert open_capture() is None
    assert open_capture(str(tmp_path / "explicit.pcap")) is not None


def test_open_capture_reads_environment(tmp_path, monkeypatch):
    path = tmp_path / "env.btsnoop"
    monkeypatch.setenv(CAPTURE_ENV_VAR, str(path))
    monkeypatch.delenv(CAPTURE_FORMAT_ENV_VAR, raising=False)

    capture = open_capture()
    assert capture is not None
    try:
        assert capture.path == path
        assert capture.format is CaptureFormat.BTSNOOP
    finally:
        capture.close()
    assert path.exists()


def test_environment_format_overrides_extension(tmp_path, monkeypatch):
    path = tmp_path / "env.pcap"
    monkeypatch.setenv(CAPTURE_ENV_VAR, str(path))
    monkeypatch.setenv(CAPTURE_FORMAT_ENV_VAR, "btsnoop")
    capture = open_capture()
    assert capture is not None
    try:
        assert capture.format is CaptureFormat.BTSNOOP
    finally:
        capture.close()
    assert path.read_bytes().startswith(BTSNOOP_MAGIC)


def test_explicit_arguments_beat_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(CAPTURE_ENV_VAR, str(tmp_path / "env.pcap"))
    monkeypatch.setenv(CAPTURE_FORMAT_ENV_VAR, "btsnoop")
    explicit = tmp_path / "explicit.pcap"
    capture = open_capture(explicit, "pcap")
    assert capture is not None
    try:
        assert capture.path == explicit
        assert capture.format is CaptureFormat.PCAP
    finally:
        capture.close()


def test_open_capture_shares_one_sink_per_path(tmp_path, monkeypatch):
    monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
    path = tmp_path / "shared.pcap"

    first = open_capture(path)
    second = open_capture(path)
    assert first is second
    assert tap(first, "tx", FRAME_TX)
    assert tap(second, "rx", FRAME_RX)

    (capture,) = close_captures()
    assert capture is first
    assert capture.closed
    assert [att["value"] for att in map(_att_fields, (r[3] for r in _pcap_records(path)))] == [
        FRAME_TX,
        FRAME_RX,
    ]

    # A closed sink is dropped from the registry, so a later session starts clean.
    reopened = open_capture(path)
    assert reopened is not None
    assert reopened is not first
    assert not reopened.closed


def test_tap_is_best_effort(tmp_path):
    assert tap(None, "tx", FRAME_TX) is False  # capture disabled
    assert tap(WireCapture(tmp_path / "x.pcap"), "tx", FRAME_TX) is False  # not open

    capture = WireCapture(tmp_path / "y.pcap").open()
    try:
        assert tap(capture, "tx", object()) is False  # type: ignore[arg-type]
        assert tap(capture, "tx", FRAME_TX) is True
        capture.close()
        assert tap(capture, "tx", FRAME_TX) is False  # closed file is swallowed
    finally:
        capture.close()


def test_open_creates_parent_directories(tmp_path):
    path = tmp_path / "sessions" / "2026" / "race.pcap"
    with WireCapture(path):
        pass
    assert path.exists()


def test_unwritable_path_raises_capture_error(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    with pytest.raises(CaptureError) as error:
        WireCapture(blocker / "race.pcap").open()
    assert error.value.code == "CAPTURE_OPEN"


def test_reopen_failure_is_reported_as_capture_error(tmp_path, monkeypatch):
    def explode(_fd, _length):
        raise OSError("injected ftruncate failure")

    monkeypatch.setattr("utils.capture.os.ftruncate", explode)
    with pytest.raises(CaptureError) as error:
        WireCapture(tmp_path / "race.pcap").open()
    assert error.value.code == "CAPTURE_OPEN"

    # The failed descriptor is closed, so a retry can take the lock.
    monkeypatch.undo()
    capture = WireCapture(tmp_path / "race.pcap")
    assert capture.open() is capture
    capture.close()


@pytest.mark.skipif(os.name != "posix", reason="flock is POSIX-only")
def test_capture_file_is_owner_only(tmp_path):
    path = tmp_path / "race.pcap"
    with WireCapture(path):
        pass
    assert path.stat().st_mode & 0o777 == CAPTURE_FILE_MODE == 0o600


@pytest.mark.skipif(os.name != "posix", reason="flock is POSIX-only")
def test_lock_contention_is_reported(tmp_path, monkeypatch):
    import fcntl

    def busy(_fd, _operation):
        raise OSError("resource temporarily unavailable")

    monkeypatch.setattr(fcntl, "flock", busy)
    with pytest.raises(CaptureError) as error:
        WireCapture(tmp_path / "race.pcap").open()
    assert error.value.code == "CAPTURE_LOCKED"


def test_failed_lock_releases_the_descriptor(tmp_path, monkeypatch):
    def explode(_fd):
        raise CaptureError("already locked", code="CAPTURE_LOCKED")

    monkeypatch.setattr("utils.capture._lock", explode)
    with pytest.raises(CaptureError):
        WireCapture(tmp_path / "race.pcap").open()

    monkeypatch.undo()
    capture = WireCapture(tmp_path / "race.pcap")  # retry must not block on a leak
    assert capture.open() is capture
    capture.close()


@pytest.mark.skipif(os.name != "posix", reason="flock is POSIX-only")
def test_second_process_cannot_clobber_an_open_capture(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    path = tmp_path / "race.pcap"
    first = WireCapture(path, clock=_clock(1_700_000_000.0)).open()
    first.write_tx(FRAME_TX)
    try:
        script = (
            "import sys\n"
            "from utils.capture import CaptureError, WireCapture\n"
            f"try:\n    WireCapture({str(path)!r}).open()\n"
            "except CaptureError as exc:\n    print(exc.code)\n    sys.exit(0)\n"
            "print('OPENED')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "CAPTURE_LOCKED"
        # The rejected opener must not have truncated the live file.
        assert [r[3][PCAP_PHDR_LEN] for r in _pcap_records(path)] == [H4_ACL_PACKET]
    finally:
        first.close()

    # Once the writer is gone, the same path can be opened again.
    with WireCapture(path):
        pass


def test_capture_failures_are_logged_once(tmp_path, caplog):
    capture = WireCapture(tmp_path / "race.pcap").open()
    capture.close()

    caplog.set_level(logging.WARNING, logger="race")
    for _ in range(5):
        assert tap(capture, "tx", FRAME_TX) is False

    messages = [r.message for r in caplog.records if "Wire capture write failed" in r.message]
    assert len(messages) == 1
    assert "suppressed" in messages[0]


def test_conflicting_format_request_warns_once(tmp_path, caplog, monkeypatch):
    monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
    path = tmp_path / "race.pcap"

    first = open_capture(path, "pcap")
    caplog.set_level(logging.WARNING, logger="race")
    second = open_capture(path, "btsnoop")
    open_capture(path, "btsnoop")

    assert second is first
    assert second.format is CaptureFormat.PCAP
    warnings = [r.message for r in caplog.records if "already open as pcap" in r.message]
    assert len(warnings) == 1


def test_enabling_a_capture_notes_its_sensitivity(tmp_path, caplog, monkeypatch):
    monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
    caplog.set_level(logging.INFO, logger="race")

    open_capture(tmp_path / "race.pcap")

    assert any("key material" in r.message for r in caplog.records)


# -- transport integration -------------------------------------------------


class _FakeChar:
    def __init__(self, uuid):
        self.uuid = uuid


class _FakeService:
    uuid = "00001200-0000-1000-8000-00805f9b34fb"
    characteristics = [
        _FakeChar("00001201-0000-1000-8000-00805f9b34fb"),
        _FakeChar("00001202-0000-1000-8000-00805f9b34fb"),
    ]


class _FakeClient:
    """Minimal stand-in for BleakClient: answers every write with FRAME_RX."""

    def __init__(self, address):
        self.address = address
        self.services = [_FakeService()]
        self.is_connected = False
        self.notify_handler = None

    async def connect(self, timeout=None):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = False

    async def start_notify(self, char, handler):
        self.notify_handler = handler

    async def write_gatt_char(self, char, data, response=True):
        self.notify_handler(None, FRAME_RX)


def _run_transport(capture_path=None):
    from dataclasses import replace

    config = RACEConfig.cli_defaults()
    if capture_path is not None:
        config = replace(config, capture_path=str(capture_path))

    async def session():
        async with BLETransport(
            "AA:BB:CC:DD:EE:FF", config=config, client_factory=_FakeClient
        ) as transport:
            return await transport.send_command(CMD_GET_BUILD)

    return asyncio.run(session())


def test_transport_captures_both_directions(tmp_path, monkeypatch):
    monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
    path = tmp_path / "session.pcap"

    payload = _run_transport(path)
    assert payload == FRAME_RX[6:]

    tx_record, rx_record = _pcap_records(path)
    assert _att_fields(tx_record[3])["value"] == FRAME_TX
    assert _att_fields(rx_record[3])["value"] == FRAME_RX
    assert _att_fields(tx_record[3])["opcode"] == ATT_OP_WRITE_CMD
    assert _att_fields(rx_record[3])["opcode"] == ATT_OP_NOTIFICATION
    assert _att_fields(tx_record[3])["direction"] == PCAP_PHDR_SENT
    assert _att_fields(rx_record[3])["direction"] == PCAP_PHDR_RECEIVED


def test_transport_honours_capture_environment(tmp_path, monkeypatch):
    path = tmp_path / "env-session.btsnoop"
    monkeypatch.setenv(CAPTURE_ENV_VAR, str(path))

    _run_transport()

    tx, rx = _btsnoop_records(path)
    assert _att_fields(tx[3], phdr=0)["value"] == FRAME_TX
    assert _att_fields(rx[3], phdr=0)["value"] == FRAME_RX
    assert _att_fields(tx[3], phdr=0)["att_handle"] == ATT_TX_HANDLE
    assert _att_fields(rx[3], phdr=0)["att_handle"] == ATT_RX_HANDLE


def test_transport_survives_unwritable_capture(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    # Capture cannot open -> session must continue without one.
    assert _run_transport(blocker / "race.pcap") == FRAME_RX[6:]


def test_transport_ignores_non_byte_frames(tmp_path):
    path = tmp_path / "session.pcap"
    config = RACEConfig(capture_path=str(path))

    async def session():
        async with BLETransport(
            "AA:BB:CC:DD:EE:FF", config=config, client_factory=_FakeClient
        ) as transport:
            transport._record("rx", object())  # e.g. an un-awaited coroutine
            transport._record("rx", b"\x05\x01\x02\x00\x08\x1e")

    asyncio.run(session())
    (record,) = _pcap_records(path)
    assert _att_fields(record[3])["value"] == b"\x05\x01\x02\x00\x08\x1e"


class _DuplicateClient(_FakeClient):
    """Emits a duplicate notification for every write, like the emulator's fault."""

    async def write_gatt_char(self, char, data, response=True):
        self.notify_handler(None, FRAME_RX)
        self.notify_handler(None, FRAME_RX)


def test_every_notification_is_captured_not_just_the_consumed_one(tmp_path):
    # A duplicate or late reply must reach the file even though the transport
    # dequeues only one frame per command.
    path = tmp_path / "dup.pcap"
    config = RACEConfig(capture_path=str(path))

    async def session():
        async with BLETransport(
            "AA:BB:CC:DD:EE:FF", config=config, client_factory=_DuplicateClient
        ) as transport:
            return await transport.send_command(CMD_GET_BUILD)

    assert asyncio.run(session()) == FRAME_RX[6:]

    values = [_att_fields(r[3])["value"] for r in _pcap_records(path)]
    assert values == [FRAME_TX, FRAME_RX, FRAME_RX]


def test_sequential_connections_append_to_one_capture(tmp_path, monkeypatch):
    # huntandpwn connects per device; the file must accumulate, not truncate.
    monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
    path = tmp_path / "hunt.pcap"

    _run_transport(path)
    _run_transport(path)

    records = _pcap_records(path)
    assert [r[3][PCAP_PHDR_LEN] for r in records] == [H4_ACL_PACKET] * 4
    assert [att["value"] for att in map(_att_fields, (r[3] for r in records))] == [
        FRAME_TX,
        FRAME_RX,
        FRAME_TX,
        FRAME_RX,
    ]
