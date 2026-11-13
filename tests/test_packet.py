import pytest

from utils.packet import (
    CMD_GET_BUILD,
    RACEProtocolError,
    build_race_packet,
    parse_race_response,
)


def test_build_packet_encodes_header_command_and_payload():
    assert build_race_packet(CMD_GET_BUILD, b"\xaa\xbb") == bytes.fromhex("05 00 04 00 08 1e aa bb")


def test_parse_response_round_trip():
    packet = parse_race_response(bytes.fromhex("05 01 04 00 08 1e aa bb"))
    assert packet.head == 0x05
    assert packet.is_response()
    assert packet.cmd == CMD_GET_BUILD
    assert packet.payload == b"\xaa\xbb"


@pytest.mark.parametrize(
    ("data", "code"),
    [(b"", "TOO_SHORT"), (bytes.fromhex("05 01 01 00 08 1e"), "BAD_LENGTH")],
)
def test_parse_rejects_malformed_frames(data, code):
    with pytest.raises(RACEProtocolError) as error:
        parse_race_response(data)
    assert error.value.code == code


def test_parse_rejects_unknown_head():
    with pytest.raises(RACEProtocolError, match="Unexpected frame head"):
        parse_race_response(bytes.fromhex("06 01 02 00 08 1e"))
