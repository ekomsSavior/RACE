"""Deterministic fuzz/property tests for the RACE frame parser.

The repository does not depend on Hypothesis, so these tests use a fixed-seed
PRNG.  They assert the important safety property: arbitrary bytes either parse
into a coherent packet or raise ``RACEProtocolError`` — never an unrelated
exception such as IndexError/struct.error.
"""

from __future__ import annotations

import random
import struct

import pytest

from utils.packet import (
    CMD_GET_BUILD,
    FrameAssembler,
    RACEError,
    build_race_packet,
    parse_race_response,
)

SEED = 0x1E08


def test_parser_never_raises_unexpected_exceptions() -> None:
    rng = random.Random(SEED)
    for _ in range(1500):
        length = rng.randrange(0, 40)
        data = bytes(rng.randrange(256) for _ in range(length))
        try:
            packet = parse_race_response(data)
        except RACEError:
            continue
        assert packet.length == 2 + len(packet.payload)
        assert len(data) >= 6 + len(packet.payload) - 2


def test_build_and_parse_round_trip_for_random_payloads() -> None:
    rng = random.Random(SEED + 1)
    for _ in range(500):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
        cmd = rng.randrange(0x10000)
        frame = build_race_packet(cmd, payload)
        packet = parse_race_response(frame)
        assert packet.cmd == cmd
        assert packet.payload == payload
        assert packet.length == 2 + len(payload)


def test_assembler_rejoins_arbitrary_fragmentations() -> None:
    rng = random.Random(SEED + 2)
    for _ in range(200):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 32)))
        frame = build_race_packet(CMD_GET_BUILD, payload)
        cuts = sorted(
            {
                0,
                len(frame),
                *(rng.randrange(0, len(frame) + 1) for _ in range(3)),
            }
        )
        chunks = [frame[start:end] for start, end in zip(cuts, cuts[1:])]
        assembler = FrameAssembler()
        frames = []
        for chunk in chunks:
            frames.extend(assembler.feed(chunk))
        assert frames == [frame]
        assert assembler.pending_bytes == b""


def test_assembler_returns_multiple_frames_from_one_notification() -> None:
    first = build_race_packet(CMD_GET_BUILD)
    second = build_race_packet(0x0C05, b"\x01\x02\x03")
    assembler = FrameAssembler()
    assert assembler.feed(first + second) == [first, second]


def test_assembler_keeps_incomplete_frame_pending() -> None:
    frame = build_race_packet(CMD_GET_BUILD, b"abcdef")
    assembler = FrameAssembler()
    assert assembler.feed(frame[:5]) == []
    assert assembler.pending_bytes == frame[:5]
    assert assembler.feed(frame[5:]) == [frame]


@pytest.mark.parametrize(
    ("frame", "code"),
    [
        (bytes.fromhex("06 01 02 00 08 1e"), "BAD_HEAD"),
        (bytes.fromhex("05 02 02 00 08 1e"), "BAD_TYPE"),
        (bytes.fromhex("05 01 01 00 08 1e"), "BAD_LENGTH"),
    ],
)
def test_assembler_rejects_bad_headers(frame: bytes, code: str) -> None:
    assembler = FrameAssembler()
    with pytest.raises(RACEError) as error:
        assembler.feed(frame)
    assert error.value.code == code


def test_assembler_rejects_non_bytes() -> None:
    assembler = FrameAssembler()
    with pytest.raises(TypeError):
        assembler.feed("not bytes")  # type: ignore[arg-type]


def test_assembler_reset_discards_pending_bytes() -> None:
    frame = build_race_packet(CMD_GET_BUILD, b"abcdef")
    assembler = FrameAssembler()
    assembler.feed(frame[:4])
    assert assembler.pending_bytes
    assembler.reset()
    assert assembler.pending_bytes == b""


def test_assembly_matches_header_lengths_for_oversized_buffer() -> None:
    frame = build_race_packet(0x0403, struct.pack("<BHI", 0, 1, 0x1A000))
    assembler = FrameAssembler()
    frames = assembler.feed(frame * 3)
    assert frames == [frame] * 3
