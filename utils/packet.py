import struct

HEAD_STANDARD = 0x05
HEAD_FOTA = 0x15
CMD_GET_BUILD = 0x1E08
CMD_READ_FLASH = 0x0403
CMD_GET_BD_ADDR = 0x0C05

def build_race_packet(cmd: int, payload: bytes = b'', head: int = HEAD_STANDARD) -> bytes:
    pkt_type = 0x00
    length = 2 + len(payload)
    header = struct.pack('<BBH', head, pkt_type, length)
    cmd_bytes = struct.pack('<H', cmd)
    return header + cmd_bytes + payload

def parse_race_response(data: bytes) -> dict:
    if len(data) < 6:
        return {"error": "Packet too short"}
    head, pkt_type, length = struct.unpack_from('<BBH', data, 0)
    cmd = struct.unpack_from('<H', data, 4)[0]
    payload = data[6:6+length-2]
    return {"head": hex(head), "type": pkt_type, "length": length, "cmd": hex(cmd), "payload": payload}
