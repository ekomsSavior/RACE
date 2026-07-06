import asyncio
from bleak import BleakClient

RACE_SERVICE_UUID = "00001200-0000-1000-8000-00805f9b34fb"
RACE_TX_UUID = "00001201-0000-1000-8000-00805f9b34fb"
RACE_RX_UUID = "00001202-0000-1000-8000-00805f9b34fb"

class BLETransport:
    def __init__(self, address: str):
        self.address = address
        self.client = None
        self.tx_char = None
        self.rx_char = None
        self.response_queue = asyncio.Queue()

    async def connect(self):
        self.client = BleakClient(self.address)
        await self.client.connect()
        
        for service in self.client.services:
            if service.uuid.lower() == RACE_SERVICE_UUID.lower():
                for char in service.characteristics:
                    if char.uuid.lower() == RACE_TX_UUID.lower():
                        self.tx_char = char
                    if char.uuid.lower() == RACE_RX_UUID.lower():
                        self.rx_char = char
        
        if not self.tx_char:
            raise Exception("RACE TX characteristic not found")
        
        if self.rx_char:
            await self.client.start_notify(self.rx_char, self._notification_handler)
        
        return True

    def _notification_handler(self, sender, data):
        self.response_queue.put_nowait(data)

    async def send_command(self, cmd: int, payload: bytes = b'') -> bytes:
        from utils.packet import build_race_packet
        packet = build_race_packet(cmd, payload)
        await self.client.write_gatt_char(self.tx_char, packet, response=True)
        
        try:
            response = await asyncio.wait_for(self.response_queue.get(), timeout=5.0)
            return response
        except asyncio.TimeoutError:
            raise TimeoutError("No RACE response")

    async def disconnect(self):
        if self.client:
            await self.client.disconnect()
