"""Tests for the virtual headphone emulator and its client integration.

Run with::

    python3 -m unittest discover -s tests -t . -v

The suite is standard-library only: no hardware, no bleak, no pytest.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
import struct
import tempfile
import unittest

from emulator import (
    FaultKind,
    FaultPlan,
    FaultRule,
    FaultSpecError,
    VirtualHeadphone,
    VirtualScanner,
    VirtualSession,
    load_profile,
    parse_fault_spec,
)
from emulator.cli import main
from emulator.cli import run as run_emulator
from emulator.device import PROFILES, profile_names
from emulator.responses import KEY_MARKER
from emulator.status import (
    STATUS_INJECTED,
    STATUS_OK,
    STATUS_OUT_OF_RANGE,
    STATUS_UNSUPPORTED,
)
from modules.auto_hunter import hunt_and_pwn
from modules.discovery import aggressive_scan, scan_for_targets
from modules.exploit import auto_exploit, find_key_candidates, struct_pack_flash
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


class ExploitHeuristicTests(unittest.TestCase):
    def test_candidate_scan_includes_last_full_stride(self) -> None:
        data = b"\x01" * 16 + b"\x00" * 224 + b"\x01" * 16
        candidates = find_key_candidates(data, 0x1A000)
        self.assertEqual([c["offset"] for c in candidates], [0x1A000, 0x1A0F0])

    def test_candidates_are_never_marked_validated(self) -> None:
        candidates = find_key_candidates(b"\xff" * 32, 0)
        self.assertTrue(candidates)
        self.assertTrue(all(c["validated"] is False for c in candidates))

    def test_flash_payload_is_seven_bytes_and_checks_range(self) -> None:
        payload = struct_pack_flash(0x1A000)
        self.assertEqual(payload, struct.pack("<BHI", 0, 1, 0x1A000))
        self.assertEqual(len(payload), 7)
        with self.assertRaises(ValueError):
            struct_pack_flash(-1)
        with self.assertRaises(ValueError):
            struct_pack_flash(0x1_0000_0000)


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
        self.assertTrue(result["key_candidates"])
        self.assertFalse(result["key_candidates"][0]["validated"])
        self.assertIn("Key candidate (unvalidated)", buffer.getvalue())
        self.assertIn(KEY_MARKER.hex(), buffer.getvalue().lower())

    async def test_auto_exploit_flash_failure_is_an_error(self) -> None:
        device = VirtualHeadphone(
            "bose-qc-earbuds-3",
            errors=[FaultRule(cmd=CMD_READ_FLASH, kind=FaultKind.SILENT)],
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = await auto_exploit(
                device.address,
                "dump",
                fast_config(0.03),
                client_factory=lambda _address: device.client(),
            )
        self.assertEqual(result["status"], "error")
        self.assertIn("flash read failed at every offset", result["message"])
        self.assertEqual(result["flash"]["status"], "error")
        self.assertEqual(len(result["flash"]["errors"]), 4)
        self.assertNotIn("Key candidate", buffer.getvalue())

    async def test_auto_exploit_full_never_claims_impersonation(self) -> None:
        device = VirtualHeadphone("bose-qc-earbuds-3")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = await auto_exploit(
                device.address,
                "full",
                fast_config(),
                client_factory=lambda _address: device.client(),
            )
        output = buffer.getvalue()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["impersonation"], "not_attempted")
        self.assertIn("Candidate key material found", output)
        self.assertIn("replay validation is required", output)
        self.assertIn("not implemented", output)
        self.assertNotIn("can be impersonated", output)

    async def test_full_with_silent_flash_skips_impersonation(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_READ_FLASH, kind=FaultKind.SILENT)]
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = await auto_exploit(
                device.address,
                "full",
                fast_config(0.03),
                client_factory=lambda _address: device.client(),
            )
        output = buffer.getvalue()
        self.assertEqual(result["status"], "error")
        self.assertIn("Impersonation stage skipped", output)
        self.assertNotIn("Candidate key material", output)
        self.assertNotIn("can be impersonated", output)

    async def test_stale_duplicate_is_discarded_by_opcode_correlation(self) -> None:
        device = VirtualHeadphone(
            errors=[FaultRule(cmd=CMD_GET_BD_ADDR, kind=FaultKind.DUPLICATE)]
        )
        async with make_transport(device) as transport:
            first = await transport.send_command(CMD_GET_BD_ADDR)
            second = await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(first, device.bd_addr_bytes)
        self.assertEqual(second, device.build.encode("utf-8") + b"\x00")

    async def test_unsolicited_frame_is_ignored(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        async with make_transport(device) as transport:
            # Inject a reply for a different command before issuing the read.
            transport._response_queue.put_nowait(  # noqa: SLF001 - deliberate test seam
                bytes.fromhex("05 01 08 00 05 0C A0 12 34 56 78 90")
            )
            payload = await transport.send_command(CMD_GET_BUILD)
        self.assertEqual(payload, device.build.encode("utf-8") + b"\x00")

    async def test_only_mismatched_frames_raise_no_response(self) -> None:
        device = VirtualHeadphone("generic-airoha", answer_unknown=False)
        transport = make_transport(device, read_timeout=0.05)
        await transport.connect()
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon(
                transport._response_queue.put_nowait,  # noqa: SLF001 - test seam
                bytes.fromhex("05 01 08 00 05 0C A0 12 34 56 78 90"),
            )
            with self.assertRaises(BLETransportError) as ctx:
                await transport.send_command(0x7777)
        finally:
            await transport.disconnect()
        self.assertEqual(ctx.exception.code, "NO_RESPONSE")

    async def test_late_same_opcode_reply_is_drained_before_next_write(self) -> None:
        device = VirtualHeadphone(
            errors=[
                FaultRule(
                    cmd=CMD_GET_BUILD,
                    kind=FaultKind.SLOW,
                    delay_s=0.15,
                    times=1,
                )
            ]
        )
        transport = make_transport(device, read_timeout=0.05)
        await transport.connect()
        try:
            with self.assertRaises(BLETransportError):
                await transport.send_command(CMD_GET_BUILD)
            await asyncio.sleep(0.25)  # late reply is now queued
            device.responder.build = "SECOND BUILD"
            payload = await transport.send_command(CMD_GET_BUILD)
        finally:
            await transport.disconnect()
        self.assertEqual(payload, b"SECOND BUILD\x00")

    async def test_att_fragmentation_is_reassembled_by_transport(self) -> None:
        device = VirtualHeadphone("generic-airoha", att_mtu=23)
        self.assertEqual(device.notification_size, 20)
        async with make_transport(device) as transport:
            payload = await transport.send_command(
                CMD_READ_FLASH, struct.pack("<BHI", 0, 1, 0x1A000)
            )
        self.assertGreater(len(payload), 256)
        self.assertEqual(payload[6 + 0x20 : 6 + 0x24], KEY_MARKER)

    async def test_session_reassembles_fragments_and_can_keep_raw(self) -> None:
        device = VirtualHeadphone("generic-airoha", att_mtu=23)
        async with VirtualSession(device, read_timeout=0.2) as session:
            joined = await session.send_command(CMD_GET_BUILD)
        self.assertEqual(len(joined), 1)
        self.assertEqual(parse_race_response(joined[0]).cmd, CMD_GET_BUILD)

        async with VirtualSession(
            device, read_timeout=0.2, reassemble=False
        ) as raw_session:
            chunks = await raw_session.send_command(CMD_GET_BUILD)
        self.assertGreater(len(chunks), 1)
        self.assertEqual(b"".join(chunks), joined[0])

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


class DiscoveryInjectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_for_targets_with_virtual_scanner(self) -> None:
        device = VirtualHeadphone("sony-wh1000xm5")
        scanner = VirtualScanner.from_headphones([device])
        results = await scan_for_targets(
            fast_config(),
            deep_scan=True,
            scanner=scanner,
            client_factory=lambda _address: device.client(),
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["address"], device.address)
        self.assertTrue(results[0]["vulnerable"])
        self.assertTrue(results[0]["race_service"])
        self.assertTrue(results[0]["race_tx"])

    async def test_aggressive_scan_with_virtual_scanner(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        scanner = VirtualScanner.from_headphones([device])
        results = await aggressive_scan(
            fast_config(),
            timeout=1,
            scanner=scanner,
            client_factory=lambda _address: device.client(),
        )
        self.assertEqual(
            results, [{"address": device.address, "name": device.name, "rssi": device.rssi}]
        )

    async def test_hunt_and_pwn_offline_reports_assessment_not_ownership(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        scanner = VirtualScanner.from_headphones([device])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            await hunt_and_pwn(
                fast_config(),
                timeout=1,
                scanner=scanner,
                client_factory=lambda _address: device.client(),
            )
        output = buffer.getvalue()
        self.assertIn("flash read succeeded", output)
        self.assertIn("unvalidated key candidate(s)", output)
        self.assertNotIn("OWNED", output)

    async def test_virtual_scanner_exposes_both_discovery_shapes(self) -> None:
        device = VirtualHeadphone("generic-airoha")
        scanner = VirtualScanner.from_headphones([device])
        plain = await scanner.discover()
        advertised = await scanner.discover(return_adv=True)
        self.assertEqual(plain[0].address, device.address)
        advertised_device, adv = advertised[device.address]
        self.assertEqual(advertised_device.name, device.name)
        self.assertEqual(adv.rssi, device.rssi)


class AttMtuTests(unittest.IsolatedAsyncioTestCase):
    def test_invalid_mtu_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            VirtualHeadphone(att_mtu=3)

    async def test_report_records_mtu(self) -> None:
        device = VirtualHeadphone(att_mtu=185)
        self.assertEqual(device.report()["att_mtu"], 185)
        self.assertEqual(device.report()["notification_size"], 182)

    async def test_large_write_is_chunked_and_reassembled(self) -> None:
        device = VirtualHeadphone("generic-airoha", att_mtu=23)
        data = b"\xAB" * 40
        payload = struct.pack("<BHI", 0, 1, 0x1A100) + data
        async with make_transport(device) as transport:
            response = await transport.send_command(CMD_WRITE_FLASH, payload)
        self.assertEqual(struct.unpack_from("<H", response, 0)[0], STATUS_OK)
        self.assertEqual(device.stats.requests, 1)
        self.assertEqual(bytes(device.flash[0x1A100 : 0x1A128]), data)


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

    async def test_explorer_command_surface(self) -> None:
        lines: list[str] = []
        commands = [
            "help",
            "build",
            "bdaddr",
            "flash",
            "flash bad",
            "flash 0x1A000 1",
            "write-flash",
            "write-flash bad DEADBEEF",
            "write-flash 0x1A100 DEADBEEF",
            "ram",
            "ram bad",
            "ram 0x10 8",
            "write-ram",
            "write-ram 0x10 0102",
            "fota 0102",
            "cmd",
            "cmd nonsense",
            "cmd 0x1E08",
            "send",
            "send 050",
            "send 05000200081E",
            "fault",
            "fault bogus",
            "fault build:silent",
            "faults",
            "clear-faults",
            "dump",
            "dump 0x40000",
            "dump 0x1A000 32",
            "scan",
            "profiles",
            "state",
            "reset",
            "bogus",
            "quit",
        ]
        code = await run_emulator(commands=commands, out=lines.append)
        self.assertEqual(code, 0)
        text = "\n".join(lines)
        self.assertIn("Commands", text)
        self.assertIn("unknown command", text)
        self.assertIn("virtual advertisement", text)
        self.assertIn("built-in profiles", text)
        self.assertIn("virtual headphone state", text)
        self.assertIn("outside the flash image", text)

    def test_cli_main_entry_points(self) -> None:
        self.assertEqual(main(["--list-profiles"]), 0)
        self.assertEqual(main(["--mtu", "3", "--command", "build"]), 2)
        self.assertEqual(main(["--error", "bogus"]), 2)
        self.assertEqual(main(["--script", "/does/not/exist"]), 2)
        self.assertEqual(main(["--command", "build", "--json"]), 0)
        self.assertEqual(main(["--action", "fingerprint"]), 0)

    async def test_cli_script_file_and_mtu(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("build\nbdaddr\n")
            path = handle.name
        try:
            lines: list[str] = []
            code = await run_emulator(
                script_path=path,
                att_mtu=23,
                out=lines.append,
            )
        finally:
            os.unlink(path)
        self.assertEqual(code, 0)
        text = "\n".join(lines)
        self.assertIn("ATT MTU      23", text)
        self.assertIn("REQ", text)

    async def test_cli_action_failure_returns_nonzero(self) -> None:
        lines: list[str] = []
        code = await run_emulator(
            action="dump",
            error_specs=["flash_read:silent"],
            read_timeout=0.03,
            out=lines.append,
        )
        self.assertEqual(code, 1)
        text = "\n".join(lines)
        self.assertIn("auto_exploit failed", text)
        self.assertNotIn("can be impersonated", text)

    async def test_cli_discover_uses_virtual_scanner(self) -> None:
        lines: list[str] = []
        code = await run_emulator(discover=True, out=lines.append)
        self.assertEqual(code, 0)
        text = "\n".join(lines)
        self.assertIn("scan_for_targets()", text)
        self.assertIn("RACE service found", text)
        self.assertIn("discovery found 1 device(s)", text)


if __name__ == "__main__":
    unittest.main()
