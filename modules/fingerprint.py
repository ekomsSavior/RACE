from transports.ble import BLETransport
from utils.packet import parse_race_response

async def fingerprint(target: str):
    print(f"[*] Fingerprinting {target}...")
    transport = BLETransport(target)
    try:
        await transport.connect()
        raw_response = await transport.send_command(0x1E08)
        parsed = parse_race_response(raw_response)
        build_string = parsed['payload'].decode('utf-8', errors='ignore').strip('\x00')
        return {"status": "success", "build": build_string}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await transport.disconnect()
