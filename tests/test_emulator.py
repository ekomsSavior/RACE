"""Tests for the virtual headphone emulator and its client integration.

Run with::

    python3 -m unittest discover -s tests -t . -v

The suite is standard-library only: no hardware, no bleak, no pytest.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import struct
import unittest

from emulator import (
    FaultKind,
    FaultPlan,
    FaultRule,
    FaultSpecError,
    VirtualHeadphone,
    VirtualSession,
    load_profile,
    parse_fault_spec,
)
from emulator.cli import run as run_emulator
from emulator.device import PROFILES, profile_names
from emulator.responses import KEY_MARKER
from emulator.status import (
    STATUS_INJECTED,
    STATUS_OK,
    STATUS_OUT_OF_RANGE,
    STATUS_UNSUPPORTED,
)
from modules.exploit import auto_exploit
from modules.fingerprint import fingerprint
from transports.ble import BLETransport, BLETransportError
from utils.config import RACEConfig
from utils.packet import (
    CMD_FOTA,
    CMD_GET_BD_ADDR,
    CMD_GET_BUILD,
    CMD_GET_RAM,
    CMD_READ_FLASH,
    CMD_SET_RAM,
    CMD_WRITE_FLASH,
    build_race_packet,
    parse_race_response,
)


def fast_config(read_timeout: float = 0.2) -> RACEConfig:
    return RACEConfig(read_timeout_s=read_timeout, connect_timeout_s=0.5)


def make_transport(device: VirtualHeadphone, *, read_timeout: float = 0.2) -> BLETransport:
    return BLETransport(
        device.address,
        config=fast_config(read_timeout),
        client_factory=lambda _address: device.client(),
    )


class ProtocolEncodingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.device = VirtualHeadphone("generic-airoha")

    def test_build_request_matches_documented_bytes(self) -> None:
        request = build_race_packet(CMD_GET_BUILD)
        self.assertEqual(request.hex(" ").upper(), "05 00 02 00 08 1E")
        outbound = self.device.handle_request(request)
        self.assertEqual(len(outbound), 1)

        packet = parse_race_response(outbound[0].frame)
        self.assertEqual(packet.cmd, CMD_GET_BUILD)
        self.assertEqual(packet.head, 0x05)
        self.assertEqual(packet.ptype, 0x01)
        self.assertEqual(packet.length, 2 + len(packet.payload))
        self.assertEqual(
            packet.payload, self.device.build.encode("utf-8") + b"\x00"
        )

    def test_bd_addr_response(self) -> None:
        outbound = self.device.handle_request(build_race_packet(CMD_GET_BD_ADDR))
        packet = parse_race_response(outbound[0].frame)
        self.assertEqual(packet.payload, self.device.bd_addr_bytes)

    def test_flash_read_returns_status_offset_and_synthetic_key_blocks(self) -> None:
        payload = struct.pack("<BHI", 0x00, 1, 0x1A000)
        outbound = self.device.handle_request(
            build_race_packet(CMD_READ_FLASH, payload)
        )
        packet = parse_race_response(outbound[0].frame)
        status, offset = struct.unpack_from("<HI", packet.payload, 0)
        self.assertEqual(status, STATUS_OK)
        self.assertEqual(offset, 0x1A000)

        data = packet.payload[6:]
        self.assertEqual(len(data), self.device.responder.page_size)
        self.assertIn(KEY_MARKER, data)
        self.assertTrue(data[0x20:0x24] == KEY_MARKER)
        self.assertTrue(data[0x70:0x74] == KEY_MARKER)

    def test_flash_write_round_trip(self) -> None:
        data = b"\xDE\xAD\xBE\xEF" * 4
        payload = struct.pack("<BHI", 0x00, 1, 0x1A100) + data
        response = self.device.handle_request(
            build_race_packet(CMD_WRITE_FLASH, payload)
        )
        packet = parse_race_response(response[0].frame)
        self.assertEqual(struct.unpack_from("<H", packet.payload, 0)[0], STATUS_OK)
        self.assertEqual(bytes(self.device.flash[0x1A100 : 0x1A110]), data)

    def test_flash_read_out_of_range(self) -> None:
        payload = struct.pack("<BHI", 0x00, 1, 0x40000)
        response = self.device.handle_request(
            build_race_packet(CMD_READ_FLASH, payload)
        )
        packet = parse_race_response(response[0].frame)
        status = struct.unpack_from("<H", packet.payload, 0)[0]
        self.assertEqual(status, STATUS_OUT_OF_RANGE)

    def test_ram_read_and_write(self) -> None:
        read_payload = struct.pack("<IH", 0x10, 8)
        response = self.device.handle_request(
            build_race_packet(CMD_GET_RAM, read_payload)
        )
        packet = parse_race_response(response[0].frame)
        status, address = struct.unpack_from("<HI", packet.payload, 0)
        self.assertEqual(status, STATUS_OK)
        self.assertEqual(address, 0x10)
        self.assertEqual(len(packet.payload) - 6, 8)

        write_payload = struct.pack("<IH", 0x10, 4) + b"\x01\x02\x03\x04"
        response = self.device.handle_request(
            build_race_packet(CMD_SET_RAM, write_payload)
        )
        packet = parse_race_response(response[0].frame)
        self.assertEqual(struct.unpack_from("<H", packet.payload, 0)[0], STATUS_OK)
        self.assertEqual(bytes(self.device.responder.ram[0x10:0x14]), b"\x01\x02\x03\x04")

    def test_read_only_rejects_writes(self) -> None:
        device = VirtualHeadphone("generic-airoha", read_only=True)
        payload = struct.pack("<BHI", 0x00, 1, 0x1A000) + b"\xAA" * 4
        response = device.handle_request(build_race_packet(CMD_WRITE_FLASH, payload))
        packet = parse_race_response(response[0].frame)
        self.assertNotEqual(struct.unpack_from("<H", packet.payload, 0)[0], STATUS_OK)

    def test_unknown_opcode_returns_unsupported_status(self) -> None:
        response = self.device.handle_request(build_race_packet(0x7777))
        packet = parse_race_response(response[0].frame)
        self.assertEqual(
            struct.unpack_from("<H", packet.payload, 0)[0], STATUS_UNSUPPORTED
        )

    def test_fota_uses_fota_head(self) -> None:
        response = self.device.handle_request(
            build_race_packet(CMD_FOTA, b"\x01\x02\x03", head=0x15)
        )
        packet = parse_race_response(response[0].frame)
        self.assertEqual(packet.head, 0x15)
        self.assertEqual(struct.unpack_from("<H", packet.payload, 0)[0], STATUS_OK)

    def test_malformed_requests_are_ignored(self) -> None:
        self.assertEqual(self.device.handle_request(b"\x00\x01"), [])
        self.assertEqual(self.device.handle_request(b"\x05\x01\x02\x00\x08\x1E"), [])
        self.assertEqual(self.device.stats.malformed_requests, 2)
        self.assertEqual(self.device.stats.requests, 2)


class FaultTests(unittest.IsolatedAsyncioTestCase):
    async def test_silent_fault_causes_transport_timeout(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.SILENT)]
        )
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device) as transport:
                await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(ctx.exception.code, "NO_RESPONSE")
        self.assertEqual(device.stats.faults_fired, 1)

    async def test_bad_head_produces_bad_response(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.BAD_HEAD)]
        )
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device) as transport:
                await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(ctx.exception.code, "BAD_RESPONSE")

    async def test_truncated_frame_produces_bad_response(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.TRUNCATE)]
        )
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device) as transport:
                await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(ctx.exception.code, "BAD_RESPONSE")

    async def test_disconnect_fault_drops_link(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.DISCONNECT)]
        )
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device) as transport:
                await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(ctx.exception.code, "NO_RESPONSE")
        self.assertFalse(device.connected)
        self.assertEqual(device.stats.disconnects, 1)

    async def test_duplicate_fault_sends_two_notifications(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_GET_BD_ADDR, kind=FaultKind.DUPLICATE)]
        )
        async with VirtualSession(device, read_timeout=0.2) as session:
            responses = await session.send_command(CMD_GET_BD_ADDR)
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0], responses[1])

    async def test_slow_fault_delivers_after_delay(self) -> None:
        device = VirtualHeadphone(
            errors=[
                FaultRule(
                    cmd=CMD_GET_BUILD,
                    kind=FaultKind.SLOW,
                    delay_s=0.05,
                )
            ]
        )
        async with VirtualSession(device, read_timeout=0.4) as session:
            responses = await session.send_command(CMD_GET_BUILD)
        self.assertEqual(len(responses), 1)

    async def test_slow_fault_exceeds_transport_read_timeout(self) -> None:
        device = VirtualHeadphone(
            errors=[
                FaultRule(
                    cmd=CMD_GET_BUILD,
                    kind=FaultKind.SLOW,
                    delay_s=0.2,
                )
            ]
        )
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device, read_timeout=0.05) as transport:
                await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(ctx.exception.code, "NO_RESPONSE")
        # Let the delayed notification land so the loop is clean.
        await asyncio.sleep(0.25)

    async def test_status_fault_overrides_payload(self) -> None:
        device = VirtualHeadphone(
            errors=[
                FaultRule(
                    cmd=CMD_READ_FLASH,
                    kind=FaultKind.STATUS,
                    status=0x0042,
                )
            ]
        )
        async with VirtualSession(device, read_timeout=0.2) as session:
            responses = await session.send_command(
                CMD_READ_FLASH, struct.pack("<BHI", 0, 1, 0x1A000)
            )
        self.assertEqual(len(responses), 1)
        packet = parse_race_response(responses[0])
        self.assertEqual(struct.unpack_from("<H", packet.payload, 0)[0], 0x0042)

    async def test_times_limit_stops_injection(self) -> None:
        device = VirtualHeadphone(
            errors=[
                FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.SILENT, times=1)
            ]
        )
        async with VirtualSession(device, read_timeout=0.1) as session:
            first = await session.send_command(CMD_GET_BUILD)
            second = await session.send_command(CMD_GET_BUILD)
        self.assertEqual(first, [])
        self.assertEqual(len(second), 1)

    async def test_zero_probability_never_fires(self) -> None:
        plan = FaultPlan(
            [FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.SILENT, probability=0.0)]
        )
        device = VirtualHeadphone(fault_plan=plan)
        async with VirtualSession(device, read_timeout=0.1) as session:
            responses = await session.send_command(CMD_GET_BUILD)
        self.assertEqual(len(responses), 1)
        self.assertEqual(device.stats.faults_fired, 0)

    async def test_status_word_default_is_injected_marker(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.STATUS)]
        )
        async with VirtualSession(device, read_timeout=0.2) as session:
            responses = await session.send_command(CMD_GET_BUILD)
        packet = parse_race_response(responses[0])
        self.assertEqual(
            struct.unpack_from("<H", packet.payload, 0)[0], STATUS_INJECTED
        )


class TransportIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_build_over_real_transport(self) -> None:
        device = VirtualHeadphone("sony-wh1000xm5")
        async with make_transport(device) as transport:
            payload = await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(payload, device.build.encode("utf-8") + b"\x00")

    async def test_fingerprint_module(self) -> None:
        device = VirtualHeadphone("jbl-live-buds-3")
        result = await fingerprint(
            device.address,
            fast_config(),
            client_factory=lambda _address: device.client(),
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["build"], device.build)

    async def test_auto_exploit_dump(self) -> None:
        device = VirtualHeadphone("bose-qc-earbuds-3")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = await auto_exploit(
                device.address,
                "dump",
                fast_config(),
                client_factory=lambda _address: device.client(),
            )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["build"], device.build)
        self.assertEqual(result["bd_addr"], device.bd_addr)
        self.assertIn("Potential Link Key", buffer.getvalue())
        self.assertIn(KEY_MARKER.hex(), buffer.getvalue().lower())

    async def test_missing_service(self) -> None:
        device = VirtualHeadphone("generic-airoha", expose_service=False)
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device):
                pass
        self.assertEqual(ctx.exception.code, "SERVICE_NOT_FOUND")
        self.assertFalse(device.connected)

    async def test_missing_tx_characteristic(self) -> None:
        device = VirtualHeadphone("generic-airoha", expose_tx=False)
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device):
                pass
        self.assertEqual(ctx.exception.code, "TX_NOT_FOUND")
        self.assertFalse(device.connected)

    async def test_missing_rx_means_no_notifications(self) -> None:
        device = VirtualHeadphone("generic-airoha", expose_rx=False)
        with self.assertRaises(BLETransportError) as ctx:
            async with make_transport(device) as transport:
                await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(ctx.exception.code, "NO_RESPONSE")


class FaultSpecParsingTests(unittest.TestCase):
    def test_any_opcode(self) -> None:
        rule = parse_fault_spec("silent")
        self.assertIsNone(rule.cmd)
        self.assertIs(rule.kind, FaultKind.SILENT)

    def test_numeric_target(self) -> None:
        rule = parse_fault_spec("0x0403:bad_length")
        self.assertEqual(rule.cmd, CMD_READ_FLASH)
        self.assertIs(rule.kind, FaultKind.BAD_LENGTH)

    def test_named_target_probability_and_count(self) -> None:
        rule = parse_fault_spec("flash_read:bad_type:0.25#2")
        self.assertEqual(rule.cmd, CMD_READ_FLASH)
        self.assertAlmostEqual(rule.probability, 0.25)
        self.assertEqual(rule.times, 2)

    def test_slow_delay(self) -> None:
        rule = parse_fault_spec("0x0403:slow:2.5s:0.5")
        self.assertAlmostEqual(rule.delay_s or 0.0, 2.5)
        self.assertAlmostEqual(rule.probability, 0.5)

    def test_status_word(self) -> None:
        rule = parse_fault_spec("0x0403:status:0x0002")
        self.assertEqual(rule.status, 0x0002)

    def test_unknown_kind(self) -> None:
        with self.assertRaises(FaultSpecError):
            parse_fault_spec("0x0403:explode")

    def test_unknown_target(self) -> None:
        with self.assertRaises(FaultSpecError):
            parse_fault_spec("nonsense:silent")

    def test_bad_probability(self) -> None:
        with self.assertRaises(FaultSpecError):
            parse_fault_spec("0x0403:silent:1.5")

    def test_empty(self) -> None:
        with self.assertRaises(FaultSpecError):
            parse_fault_spec("   ")

    def test_describe(self) -> None:
        self.assertEqual(
            parse_fault_spec("build:silent").describe(), "0x1E08:silent"
        )
        self.assertIn("p=0.5", parse_fault_spec("*:garbage:0.5").describe())

    def test_rule_accepts_string_kind(self) -> None:
        rule = FaultRule(cmd=CMD_GET_BUILD, kind="silent")  # type: ignore[arg-type]
        self.assertIs(rule.kind, FaultKind.SILENT)

    def test_rule_rejects_unknown_string_kind(self) -> None:
        with self.assertRaises(FaultSpecError):
            FaultRule(kind="explode")  # type: ignore[arg-type]


class ProfileTests(unittest.TestCase):
    def test_all_profiles_load_and_have_six_byte_addresses(self) -> None:
        self.assertTrue(profile_names())
        for key in profile_names():
            profile = load_profile(key)
            self.assertEqual(len(profile.bd_addr_bytes), 6)

    def test_lookup_by_advertised_name(self) -> None:
        self.assertEqual(load_profile("WH-1000XM5").key, "sony-wh1000xm5")

    def test_unknown_profile(self) -> None:
        with self.assertRaises(KeyError):
            load_profile("does-not-exist")

    def test_profile_build_is_explicitly_synthetic(self) -> None:
        for key in PROFILES:
            self.assertTrue(PROFILES[key].build.startswith("EMU "))


class SessionExplorerTests(unittest.IsolatedAsyncioTestCase):
    async def test_raw_frames_and_decode(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        async with VirtualSession(device, read_timeout=0.2) as session:
            responses = await session.send_hex("05000200081E")
        self.assertEqual(len(responses), 1)
        self.assertEqual(parse_race_response(responses[0]).cmd, CMD_GET_BUILD)

    async def test_session_rejects_bad_hex(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        async with VirtualSession(device) as session:
            with self.assertRaises(ValueError):
                await session.send_hex("050")

    async def test_state_report_contains_synthetic_markers(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        report = device.report()
        self.assertEqual(report["profile"], "generic-airoha")
        self.assertTrue(report["build"].startswith("EMU "))
        self.assertIn("0x1A020", report["memory"]["key_block_offsets"])

    async def test_second_client_is_rejected_until_disconnect(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        first = device.client()
        await first.connect()
        with self.assertRaises(RuntimeError):
            await device.client().connect()
        await first.disconnect()

    async def test_answer_unknown_can_be_disabled(self) -> None:
        device = VirtualHeadphone("generic-airoha", answer_unknown=False)
        async with VirtualSession(device, read_timeout=0.05) as session:
            responses = await session.send_command(0x7777)
        self.assertEqual(responses, [])

    async def test_cli_script_output_and_json(self) -> None:
        lines: list[str] = []
        code = await run_emulator(
            profile="marshall-major-v",
            commands=["build", "bdaddr", "flash 0x1A000"],
            json_output=True,
            out=lines.append,
        )
        self.assertEqual(code, 0)
        text = "\n".join(lines)
        self.assertIn("REQ", text)
        self.assertIn("BD_ADDR", text)
        self.assertIn('"profile": "marshall-major-v"', text)

    async def test_cli_fault_from_spec(self) -> None:
        lines: list[str] = []
        code = await run_emulator(
            error_specs=["build:silent"],
            commands=["build"],
            read_timeout=0.05,
            out=lines.append,
        )
        self.assertEqual(code, 0)
        self.assertIn("no response", "\n".join(lines))

    async def test_cli_rejects_unknown_profile_and_spec(self) -> None:
        lines: list[str] = []
        self.assertEqual(
            await run_emulator(profile="nope", out=lines.append), 2
        )
        self.assertEqual(
            await run_emulator(error_specs=["bogus"], out=lines.append), 2
        )


if __name__ == "__main__":
    unittest.main()
