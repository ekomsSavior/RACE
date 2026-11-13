"""CLI plumbing tests: group-level capture options reach the session config."""

import pytest
from click.testing import CliRunner

import race
from tests.test_capture import _att_fields, _pcap_records
from utils.capture import CAPTURE_ENV_VAR, close_captures
from utils.packet import CMD_GET_BUILD, build_race_packet

TARGET = "A0:12:34:56:78:90"


@pytest.fixture(autouse=True)
def _isolate_captures():
    close_captures()
    yield
    close_captures()


def _invoke(monkeypatch, argv, env=None):
    """Run the CLI with ``auto_exploit`` stubbed to capture the config."""
    seen = {}

    async def fake_exploit(target, action, config):
        seen["target"] = target
        seen["action"] = action
        seen["config"] = config
        return {"status": "success", "build": "RACE-TEST", "bd_addr": TARGET}

    monkeypatch.setattr(race, "auto_exploit", fake_exploit)
    result = CliRunner().invoke(race.cli, argv, env=env or {})
    assert result.exit_code == 0, result.output
    return seen


def test_capture_option_reaches_config(monkeypatch):
    seen = _invoke(monkeypatch, ["--capture", "/tmp/session.pcap", "exploit", TARGET])
    assert seen["config"].capture_path == "/tmp/session.pcap"
    assert seen["config"].capture_format is None  # inferred from the extension


def test_capture_format_option_reaches_config(monkeypatch):
    seen = _invoke(
        monkeypatch,
        ["--capture", "/tmp/session.pcap", "--capture-format", "btsnoop", "exploit", TARGET],
    )
    assert seen["config"].capture_path == "/tmp/session.pcap"
    assert seen["config"].capture_format == "btsnoop"


def test_capture_environment_reaches_config(monkeypatch):
    seen = _invoke(
        monkeypatch,
        ["exploit", TARGET],
        env={"RACE_CAPTURE": "/tmp/env.pcap", "RACE_CAPTURE_FORMAT": "btsnoop"},
    )
    assert seen["config"].capture_path == "/tmp/env.pcap"
    assert seen["config"].capture_format == "btsnoop"


def test_no_capture_by_default(monkeypatch):
    seen = _invoke(monkeypatch, ["exploit", TARGET])
    assert seen["config"].capture_path is None
    assert seen["config"].capture_format is None


def test_timeout_and_capture_combine_on_scan(monkeypatch):
    # RACEConfig is frozen, so overrides must go through dataclasses.replace.
    seen = {}

    async def fake_scan(config, deep):
        seen["config"] = config
        return []

    monkeypatch.setattr(race, "scan_for_targets", fake_scan)
    result = CliRunner().invoke(
        race.cli, ["--capture", "/tmp/scan.pcap", "scan", "--timeout", "3"]
    )
    assert result.exit_code == 0, result.output
    assert seen["config"].scan_timeout_s == 3.0
    assert seen["config"].capture_path == "/tmp/scan.pcap"


def test_emulate_captures_virtual_traffic(tmp_path, monkeypatch):
    monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
    path = tmp_path / "virtual.pcap"

    result = CliRunner().invoke(
        race.cli, ["--capture", str(path), "emulate", "--command", "build"]
    )

    assert result.exit_code == 0, result.output
    tx_record, rx_record = _pcap_records(path)
    assert _att_fields(tx_record[3])["value"] == build_race_packet(CMD_GET_BUILD)
    assert _att_fields(rx_record[3])["value"].startswith(bytes.fromhex("05 01"))
