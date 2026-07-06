import asyncio
from bleak import BleakScanner, BleakClient
from colorama import Fore, Style, init
init(autoreset=True)

RACE_SERVICE_UUID = "00001200-0000-1000-8000-00805f9b34fb"
RACE_TX_UUID = "00001201-0000-1000-8000-00805f9b34fb"
RACE_RX_UUID = "00001202-0000-1000-8000-00805f9b34fb"

VULNERABLE_MODELS = [
    "WH-1000XM", "WF-1000XM", "WH-CH", "LinkBuds", "ULT Wear",
    "Marshall", "JBL", "Bose", "Jabra", "Beyerdynamic"
]

async def scan_for_targets(timeout: int = 10, deep_scan: bool = False):
    """Scan for RACE-capable devices with service discovery"""
    print(f"{Fore.CYAN}[*] Scanning for devices ({timeout}s)...{Style.RESET_ALL}")
    
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    
    found = []
    for addr, (dev, adv_data) in devices.items():
        name = dev.name if dev.name else "Unknown"
        is_vulnerable = any(model in name for model in VULNERABLE_MODELS)
        
        found.append({
            "address": addr,
            "name": name,
            "rssi": adv_data.rssi if adv_data else "N/A",
            "vulnerable": is_vulnerable,
            "race_service": False
        })
    
    if deep_scan:
        print(f"{Fore.YELLOW}[*] Deep scanning for RACE services...{Style.RESET_ALL}")
        for device in found:
            if device['vulnerable']:
                print(f"  {Fore.CYAN}Checking {device['address']}...{Style.RESET_ALL}")
                try:
                    client = BleakClient(device['address'])
                    await client.connect(timeout=5)
                    for service in client.services:
                        if service.uuid.lower() == RACE_SERVICE_UUID.lower():
                            device['race_service'] = True
                            device['race_tx'] = any(c.uuid.lower() == RACE_TX_UUID.lower() 
                                                   for c in service.characteristics)
                            print(f"    {Fore.GREEN}[+] RACE service found!{Style.RESET_ALL}")
                            break
                    await client.disconnect()
                except Exception as e:
                    print(f"    {Fore.RED}[-] Failed: {str(e)[:50]}{Style.RESET_ALL}")
    
    return found

async def aggressive_scan(timeout: int = 15):
    """Find ANY device with RACE service exposed"""
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.RED}  RACE HUNTER - Finding vulnerable Bluetooth devices{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}[*] Scanning for devices...{Style.RESET_ALL}")
    devices = await BleakScanner.discover(timeout=timeout)
    
    race_devices = []
    total = len(devices)
    checked = 0
    
    for device in devices:
        checked += 1
        print(f"\r  {Fore.YELLOW}[*] Checking {checked}/{total}: {device.address[:8]}...{Style.RESET_ALL}", end="")
        
        try:
            client = BleakClient(device.address)
            await client.connect(timeout=3)
            
            for service in client.services:
                if service.uuid.lower() == RACE_SERVICE_UUID.lower():
                    race_devices.append({
                        "address": device.address,
                        "name": device.name or "Unknown",
                        "rssi": device.rssi
                    })
                    print(f"\n  {Fore.GREEN}[+] RACE device found!{Style.RESET_ALL}")
                    break
            
            await client.disconnect()
        except:
            pass
    
    print("\n")  # Newline after progress
    return race_devices
