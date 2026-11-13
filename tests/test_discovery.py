"""Discovery tests: RSSI reporting and per-device probe failures."""

import asyncio

from modules import discovery
from utils.config import RACEConfig

ADDRESS = "AA:BB:CC:DD:EE:FF"


class _FakeAdvertisement:
    def __init__(self, rssi: int = -42) -> None:
        self.rssi = rssi


class _FakeDevice:
    def __init__(self, address: str = ADDRESS, name: str | None = "WH-1000XM5") -> None:
        self.address = address
        self.name = name


class _FakeService:
    uuid = discovery.RACE_SERVICE_UUID
    characteristics: list[object] = []


class _FakeClient:
    def __init__(self, address: str, *, fail: bool = False) -> None:
        self.address = address
        self.services = [_FakeService()]
        self._fail = fail

    async def connect(self, timeout: float | None = None) -> None:
        if self._fail:
            raise RuntimeError("connect failed")

    async def disconnect(self) -> None:
        return None


def _patch_scan(monkeypatch, devices, kwargs_seen):
    async def fake_discover(timeout: float = 5.0, **kwargs):
        kwargs_seen.update(kwargs, timeout=timeout)
        return devices

    monkeypatch.setattr(discovery.BleakScanner, "discover", fake_discover)


def test_aggressive_scan_reports_rssi_from_advertisement(monkeypatch):
    # bleak >= 0.22 removed BLEDevice.rssi; reading it raised AttributeError
    # inside the probe loop, and the broad except turned that into "no devices
    # found". This test pins the advertisement-based RSSI instead.
    kwargs = {}
    _patch_scan(
        monkeypatch,
        {ADDRESS: (_FakeDevice(), _FakeAdvertisement(-42))},
        kwargs,
    )
    monkeypatch.setattr(discovery, "BleakClient", _FakeClient)

    found = asyncio.run(discovery.aggressive_scan(RACEConfig(), timeout=1))

    assert kwargs == {"timeout": 1, "return_adv": True}
    assert found == [{"address": ADDRESS, "name": "WH-1000XM5", "rssi": -42}]


def test_aggressive_scan_survives_a_failing_probe(monkeypatch):
    other = "11:22:33:44:55:66"
    _patch_scan(
        monkeypatch,
        {
            ADDRESS: (_FakeDevice(), _FakeAdvertisement(-70)),
            other: (_FakeDevice(other, None), _FakeAdvertisement(-80)),
        },
        {},
    )

    def factory(address: str) -> _FakeClient:
        return _FakeClient(address, fail=address == ADDRESS)

    monkeypatch.setattr(discovery, "BleakClient", factory)

    found = asyncio.run(discovery.aggressive_scan(RACEConfig(), timeout=1))

    assert found == [{"address": other, "name": "Unknown", "rssi": -80}]


def test_aggressive_scan_keeps_devices_without_advertisement_data(monkeypatch):
    _patch_scan(monkeypatch, {ADDRESS: (_FakeDevice(), None)}, {})
    monkeypatch.setattr(discovery, "BleakClient", _FakeClient)

    found = asyncio.run(discovery.aggressive_scan(RACEConfig(), timeout=1))

    assert found == [{"address": ADDRESS, "name": "WH-1000XM5", "rssi": "N/A"}]
