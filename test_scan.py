import asyncio
from bleak import BleakScanner

async def test():
    print("[*] Scanning for 5 seconds...")
    devices = await BleakScanner.discover(timeout=5)
    for d in devices:
        print(f"  {d.address} - {d.name}")
    print("[+] Scan complete")

asyncio.run(test())
