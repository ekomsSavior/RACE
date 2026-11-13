#!/usr/bin/env python3
"""RACE Framework - CLI entry point.

Separates presentation (CLI) from behaviour (modules): the CLI only parses
arguments, logs results, and wires the transport/config together.  No
research logic lives here.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from typing import Any

import click
from colorama import Fore, Style, init

from emulator.cli import DEFAULT_PROFILE
from emulator.cli import list_profiles as print_profiles
from emulator.cli import run as run_emulator
from modules.auto_hunter import hunt_and_pwn
from modules.discovery import aggressive_scan, scan_for_targets
from modules.exploit import auto_exploit
from modules.fingerprint import fingerprint
from utils.config import RACEConfig

# colorama only for the banner (structured logging below uses plain text).
init(autoreset=True)

logger = logging.getLogger("race")

BANNER = f"""\
{Fore.RED}██████╗  █████╗  ██████╗███████╗
{Fore.RED}██╔══██╗██╔══██╗██╔════╝██╔════╝
{Fore.RED}██████╔╝███████║██║     █████╗
{Fore.RED}██╔══██╗██╔══██║██║     ██╔══╝
{Fore.RED}██║  ██║██║  ██║╚██████╗███████╗
{Fore.RED}╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
{Fore.RED}
{Fore.YELLOW}  Bluetooth Headphone Jacking Framework
{Fore.CYAN}  Church of Malware x ek0ms savi0r
{Fore.RED}  {"=" * 55}
{Fore.WHITE}  Research: Airoha RACE Vulnerabilities
{Fore.WHITE}  CVEs: 2025-20700, 2025-20701, 2025-20702
{Fore.RED}  {"=" * 55}{Style.RESET_ALL}
"""


@dataclass(frozen=True)
class CLIOptions:
    """Group-level options forwarded to every subcommand."""

    capture_path: str | None = None
    capture_format: str | None = None


def _build_config(ctx: click.Context, *, timeout: int | None = None) -> RACEConfig:
    """Merge group options (wire capture, timeout) over the defaults."""
    options = ctx.obj if isinstance(ctx.obj, CLIOptions) else CLIOptions()
    overrides: dict[str, Any] = {}
    if timeout is not None:
        overrides["scan_timeout_s"] = float(timeout)
    if options.capture_path is not None:
        overrides["capture_path"] = options.capture_path
    if options.capture_format is not None:
        overrides["capture_format"] = options.capture_format
    return replace(RACEConfig.cli_defaults(), **overrides)


def _note_discovery_only(config: RACEConfig) -> None:
    """Report that a requested capture stays empty: discovery opens no transport."""
    if config.capture_path is not None:
        logger.info(
            "Wire capture: nothing written - scan/hunt only enumerate; "
            "use exploit, info, huntandpwn or emulate to record RACE frames"
        )


def _console_result(status: str, result: dict[str, Any]) -> None:
    if status == "success":
        logger.info("Exploit successful")
        if "build" in result:
            logger.info("Build: %s", result["build"])
        if "bd_addr" in result:
            logger.info("BD_ADDR: %s", result["bd_addr"])
    else:
        logger.error("Exploit failed: %s", result.get("message", "Unknown error"))


@click.group()
@click.option(
    "--capture",
    "capture_path",
    metavar="PATH",
    default=None,
    envvar="RACE_CAPTURE",
    help="Dump raw RACE frames to PATH (.pcap for Wireshark, .btsnoop for btmon).",
)
@click.option(
    "--capture-format",
    "capture_format",
    type=click.Choice(["pcap", "btsnoop"]),
    default=None,
    envvar="RACE_CAPTURE_FORMAT",
    help="Capture container format; inferred from the PATH extension when omitted.",
)
@click.pass_context
def cli(ctx: click.Context, capture_path: str | None, capture_format: str | None) -> None:
    """RACE Framework - Institutional Edition."""
    ctx.obj = CLIOptions(capture_path, capture_format)
    print(BANNER)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


@cli.command()
@click.option(
    "--timeout",
    default=10,
    type=int,
    help="Scan duration in seconds.",
)
@click.option(
    "--deep",
    is_flag=True,
    help="Perform deep service discovery.",
)
@click.pass_context
def scan(ctx: click.Context, timeout: int, deep: bool) -> None:
    """Discover vulnerable Bluetooth headphones."""
    config = _build_config(ctx, timeout=timeout)
    results = asyncio.run(scan_for_targets(config, deep))
    _note_discovery_only(config)
    if not results:
        logger.info("No devices found")
        return
    logger.info("Found %d device(s)", len(results))
    for dev in results:
        vuln = "[VULN]" if dev["vulnerable"] else ""
        race = "[RACE]" if dev.get("race_service", False) else ""
        logger.info(
            "  %s - %s %s %s (RSSI: %s)",
            Fore.YELLOW + dev["address"] + Style.RESET_ALL,
            dev["name"],
            vuln,
            race,
            dev["rssi"],
        )


@cli.command()
@click.option(
    "--timeout",
    default=15,
    type=int,
    help="Scan duration in seconds.",
)
@click.pass_context
def hunt(ctx: click.Context, timeout: int) -> None:
    """Aggressively hunt for RACE services."""
    config = _build_config(ctx, timeout=timeout)
    results = asyncio.run(aggressive_scan(config, timeout))
    _note_discovery_only(config)
    if not results:
        logger.info("No RACE devices found")
        return
    logger.info("Found %d RACE device(s)", len(results))
    for dev in results:
        logger.info("  %s - %s (RSSI: %s)", dev["address"], dev["name"], dev["rssi"])


@cli.command()
@click.argument("target_address")
@click.option(
    "--action",
    default="fingerprint",
    type=click.Choice(["fingerprint", "dump", "full"]),
    help="Exploit action to perform.",
)
@click.pass_context
def exploit(ctx: click.Context, target_address: str, action: str) -> None:
    """Auto-exploit a RACE device."""
    config = _build_config(ctx)
    result = asyncio.run(auto_exploit(target_address, action, config))
    _console_result(result["status"], result)


@cli.command()
@click.argument("target_address")
@click.pass_context
def info(ctx: click.Context, target_address: str) -> None:
    """Get build info from target."""
    config = _build_config(ctx)
    result = asyncio.run(fingerprint(target_address, config))
    if result["status"] == "success":
        logger.info("Device Fingerprint")
        logger.info("  Build Info: %s", result["build"])
    else:
        logger.error("Failed: %s", result.get("message", "Unknown error"))


@cli.command()
@click.option(
    "--timeout",
    default=20,
    type=int,
    help="Scan duration in seconds.",
)
@click.pass_context
def huntandpwn(ctx: click.Context, timeout: int) -> None:
    """Auto-hunt and exploit all RACE devices."""
    config = _build_config(ctx, timeout=timeout)
    asyncio.run(hunt_and_pwn(config, timeout=timeout))


@cli.command()
@click.option(
    "--profile",
    default=DEFAULT_PROFILE,
    show_default=True,
    help="Synthetic device profile to emulate.",
)
@click.option(
    "--error",
    "errors",
    multiple=True,
    metavar="SPEC",
    help="Inject a fault, e.g. 'build:silent' or 'flash_read:bad_length:0.5'.",
)
@click.option(
    "--command",
    "commands",
    multiple=True,
    metavar="CMD",
    help="Explorer command to run, e.g. 'flash 0x1A000' (repeatable).",
)
@click.option(
    "--script",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="File of explorer commands, one per line.",
)
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    help="Open the interactive protocol explorer.",
)
@click.option(
    "--action",
    type=click.Choice(["fingerprint", "dump", "full"]),
    help="Run the real auto_exploit() against the virtual link.",
)
@click.option(
    "--list-profiles",
    is_flag=True,
    help="List built-in synthetic profiles and exit.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Print a JSON device report after the session.",
)
@click.pass_context
def emulate(
    ctx: click.Context,
    profile: str,
    errors: tuple[str, ...],
    commands: tuple[str, ...],
    script: str | None,
    interactive: bool,
    action: str | None,
    list_profiles: bool,
    json_output: bool,
) -> None:
    """Explore RACE against a virtual headphone (no radio, no hardware)."""
    if list_profiles:
        print_profiles(click.echo)
        return

    code = asyncio.run(
        run_emulator(
            profile=profile,
            error_specs=errors,
            commands=commands,
            script_path=script,
            interactive=interactive,
            action=action,
            json_output=json_output,
            config=_build_config(ctx),
            out=click.echo,
        )
    )
    ctx.exit(code)


if __name__ == "__main__":
    cli()
