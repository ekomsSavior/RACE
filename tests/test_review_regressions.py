"""Offline regression checks for capture safety and public lifecycle/config APIs."""

import asyncio
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

import modules.auto_hunter
import race
from emulator import VirtualHeadphone
from transports.ble import BLETransport, BLETransportError
from utils.capture import CaptureError, WireCapture


def test_capture_rejects_symlink_without_touching_target(tmp_path):
    target = tmp_path / "keep.txt"
    target.write_bytes(b"keep this file")
    target.chmod(0o644)
    before = target.stat().st_mode
    path = tmp_path / "capture.pcap"
    path.symlink_to(target)
    with pytest.raises(CaptureError):
        WireCapture(path).open()
    assert target.read_bytes() == b"keep this file"
    assert target.stat().st_mode == before


def test_capture_rejects_hard_link_without_touching_target(tmp_path):
    target = tmp_path / "keep.txt"
    target.write_bytes(b"keep this file")
    path = tmp_path / "capture.pcap"
    os.link(target, path)
    with pytest.raises(CaptureError):
        WireCapture(path).open()
    assert target.read_bytes() == b"keep this file"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
def test_capture_rejects_fifo_without_waiting_for_reader(tmp_path):
    path = tmp_path / "capture.pcap"
    os.mkfifo(path)
    with pytest.raises(CaptureError):
        WireCapture(path).open()


def test_capture_rejects_file_substitution_before_open(tmp_path, monkeypatch):
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"old capture")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"keep replacement")
    real_open = os.open

    def replace_before_open(filename, flags, mode):
        replacement.replace(filename)
        return real_open(filename, flags, mode)

    monkeypatch.setattr("utils.capture.os.open", replace_before_open)
    with pytest.raises(CaptureError):
        WireCapture(path).open()
    assert path.read_bytes() == b"keep replacement"
    monkeypatch.undo()
    # The rejected descriptor must not leak or retain a file lock.
    with WireCapture(path):
        pass


def test_capture_rejects_creation_race(tmp_path, monkeypatch):
    path = tmp_path / "capture.pcap"
    real_open = os.open

    def create_before_open(filename, flags, mode):
        Path(filename).write_bytes(b"created by another writer")
        return real_open(filename, flags, mode)

    monkeypatch.setattr("utils.capture.os.open", create_before_open)
    with pytest.raises(CaptureError):
        WireCapture(path).open()
    assert path.read_bytes() == b"created by another writer"


def test_closed_transport_rejects_reentry_without_opening_client():
    async def scenario():
        device = VirtualHeadphone("generic-airoha")
        clients = []

        def factory(_address):
            client = device.client()
            clients.append(client)
            return client

        transport = BLETransport(device.address, client_factory=factory)
        async with transport:
            assert clients[0].is_connected
        with pytest.raises(BLETransportError) as error:
            async with transport:
                pytest.fail("closed transport reopened")
        assert error.value.code == "CLOSED"
        assert len(clients) == 1
        assert not clients[0].is_connected

    asyncio.run(scenario())


def test_hunt_timeout_reaches_scanner_without_radio(monkeypatch):
    seen = []

    async def fake_scan(config, timeout, **_kwargs):
        seen.append((config.scan_timeout_s, timeout))
        return []

    monkeypatch.setattr(modules.auto_hunter, "aggressive_scan", fake_scan)
    result = CliRunner().invoke(race.cli, ["huntandpwn", "--timeout", "1"])
    assert result.exit_code == 0, result.output
    assert seen == [(1.0, 1)]
