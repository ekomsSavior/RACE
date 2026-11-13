"""Command-line entry points for the virtual headphone emulator.

Two front ends share this module:

* ``python3 -m emulator ...`` — argparse, standard library only
* ``python3 race.py emulate ...`` — click wrapper in :mod:`race`

Keeping the logic here means the offline path works even when ``click``,
``colorama`` or ``bleak`` are not installed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from utils.config import RACEConfig

from .device import (
    DEFAULT_PROFILE,
    PROFILES,
    DeviceProfile,
    VirtualHeadphone,
    profile_names,
)
from .explorer import Explorer
from .faults import FaultSpecError, parse_fault_spec
from .responses import KEY_BLOCK_OFFSETS

Out = Callable[[str], None]

#: Commands run when no script, command, action or interactive flag is given.
DEFAULT_SCRIPT: tuple[str, ...] = (
    "build",
    "bdaddr",
    "flash 0x1A000 1",
)


def list_profiles(out: Out = print) -> None:
    """Print the built-in synthetic device profiles."""
    out("Built-in virtual headphone profiles:")
    for key in profile_names():
        profile: DeviceProfile = PROFILES[key]
        out(
            f"  {key:<18} {profile.name:<26} {profile.address:<18} "
            f"rssi={profile.rssi:<4} {profile.description}"
        )


def _print_header(
    device: VirtualHeadphone,
    *,
    read_timeout: float,
    out: Out,
) -> None:
    out("RACE virtual headphone emulator - offline, synthetic data only")
    out(f"  profile      {device.profile.key} ({device.name})")
    out(f"  address      {device.address}   bd_addr {device.bd_addr}")
    out(f"  build        {device.build}")
    out(
        f"  RACE         service {device.config.service_uuid} "
        f"(TX {device.config.tx_uuid}, RX {device.config.rx_uuid})"
    )
    out(
        f"  faults       {len(device.fault_plan)} rule(s)"
        if device.fault_plan
        else "  faults       none"
    )
    out(
        f"  memory       {len(device.flash)} B flash, "
        f"{device.responder.page_size} B/page, "
        f"{len(KEY_BLOCK_OFFSETS)} synthetic key block(s)"
    )
    if device.att_mtu is None:
        out("  ATT MTU      unfragmented (emulator default)")
    else:
        out(
            f"  ATT MTU      {device.att_mtu} "
            f"({device.notification_size} B notification payload)"
        )
    out(f"  read timeout {read_timeout:g}s")
    out("")


async def _run_action(
    device: VirtualHeadphone,
    action: str,
    *,
    config: RACEConfig,
    out: Out,
) -> bool:
    """Run the framework's real exploit module over the virtual GATT link."""
    try:
        from modules.exploit import auto_exploit
    except ImportError as exc:  # colorama is cosmetic but imported eagerly
        out(f"[!] cannot import modules.exploit: {exc}")
        out("    install runtime dependencies with: pip install -e .")
        return False

    out(f"[*] exercising the real auto_exploit(..., action={action!r}) path")
    result = await auto_exploit(
        device.address,
        action,
        config,
        client_factory=lambda _address: device.client(),
    )
    status = result.get("status")
    if status == "success":
        out(
            f"[+] auto_exploit finished: build={result.get('build')!r} "
            f"bd_addr={result.get('bd_addr')}"
        )
        flash = result.get("flash") or {}
        if flash.get("status") == "ok":
            candidates = flash.get("key_candidates") or []
            out(
                f"    flash read 0x{flash['offset']:05X}: "
                f"{flash['data_bytes']} B, "
                f"{len(candidates)} unvalidated key candidate(s)"
            )
        else:
            out("    flash read was not part of this action")
    else:
        out(f"[-] auto_exploit failed: {result.get('message')}")
    out("")
    return status == "success"


def _load_script(path: str, out: Out) -> list[str] | None:
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        out(f"[!] cannot read script {path!r}: {exc}")
        return None


async def run(
    *,
    profile: str = DEFAULT_PROFILE,
    error_specs: Sequence[str] = (),
    commands: Sequence[str] = (),
    script_path: str | None = None,
    interactive: bool = False,
    action: str | None = None,
    read_timeout: float = 1.0,
    slow_seconds: float = 6.0,
    seed: int | None = None,
    read_only: bool = False,
    json_output: bool = False,
    att_mtu: int | None = None,
    discover: bool = False,
    config: RACEConfig | None = None,
    out: Out = print,
) -> int:
    """Run an emulator session.  Returns a process-style exit code.

    ``config`` carries caller settings (notably the wire-capture path) into the
    transport and explorer; ``read_timeout`` is applied on top of it.
    """
    try:
        from .device import load_profile

        profile_obj = load_profile(profile)
    except KeyError as exc:
        out(f"[!] {exc}")
        return 2

    rules = []
    for spec in error_specs:
        try:
            rules.append(parse_fault_spec(spec))
        except FaultSpecError as exc:
            out(f"[!] invalid --error {spec!r}: {exc}")
            return 2

    try:
        device = VirtualHeadphone(
            profile_obj,
            errors=rules,
            slow_response_s=slow_seconds,
            fault_seed=0 if seed is None else seed,
            read_only=read_only,
            att_mtu=att_mtu,
        )
    except ValueError as exc:
        out(f"[!] {exc}")
        return 2

    if read_timeout <= 0:
        out("[!] --read-timeout must be positive")
        return 2

    session_config = replace(config or device.config, read_timeout_s=read_timeout)
    _print_header(device, read_timeout=read_timeout, out=out)

    lines: list[str] = []
    if script_path:
        loaded = _load_script(script_path, out)
        if loaded is None:
            return 2
        lines.extend(loaded)
    lines.extend(commands)

    action_ok = True
    try:
        if discover:
            from modules.discovery import scan_for_targets

            from .scanner import VirtualScanner

            out("[*] running scan_for_targets() over the virtual advertisement")
            results = await scan_for_targets(
                session_config,
                deep_scan=True,
                scanner=VirtualScanner.from_headphones([device]),
                client_factory=lambda _address: device.client(),
                out=out,
            )
            out(f"[+] discovery found {len(results)} device(s)")
            out("")

        if action:
            action_ok = await _run_action(
                device, action, config=session_config, out=out
            )

        should_explore = interactive or bool(lines) or not action
        if should_explore:
            if not lines and not interactive:
                lines = list(DEFAULT_SCRIPT)
                out("[*] running the default exploration script")
                out("")

            explorer = Explorer(
                device, out=out, read_timeout=read_timeout, config=session_config
            )
            await explorer.open()
            try:
                if lines:
                    await explorer.run_lines(lines)
                if interactive:
                    await explorer.run_interactive()
            finally:
                await explorer.close()

        out("")
        out(
            f"[*] session: {device.stats.requests} request(s), "
            f"{device.stats.responses} response(s), "
            f"{device.stats.faults_fired} injected fault(s), "
            f"{device.stats.malformed_requests} malformed request(s)"
        )
    except RuntimeError as exc:
        out(f"[!] session aborted: {exc}")
        return 1

    if json_output:
        out(json.dumps(device.report(), indent=2, sort_keys=True))
    return 0 if action_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m emulator",
        description=(
            "Virtual RACE headphone: a simulated BLE GATT peripheral with "
            "synthetic responses and configurable faults.  No radio, no "
            "headset, no real key material."
        ),
        epilog=(
            "Fault spec: [TARGET:]KIND[:RATE[#COUNT]]  where TARGET is an "
            "opcode or name (build, bd_addr, flash_read, ...) and KIND is "
            "one of silent, slow, truncate, bad_head, bad_type, bad_length, "
            "garbage, disconnect, status, duplicate.  Example: "
            "--error 0x1E08:silent --error flash_read:bad_length:0.5#2"
        ),
    )
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help=f"synthetic device profile (default: {DEFAULT_PROFILE})",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="list built-in profiles and exit",
    )
    parser.add_argument(
        "--error",
        dest="errors",
        action="append",
        default=[],
        metavar="SPEC",
        help="inject a fault (repeatable)",
    )
    parser.add_argument(
        "--command",
        dest="commands",
        action="append",
        default=[],
        metavar="CMD",
        help="run an explorer command, e.g. --command 'flash 0x1A000' (repeatable)",
    )
    parser.add_argument(
        "--script",
        metavar="PATH",
        help="read explorer commands from a file (one per line)",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="open the interactive explorer",
    )
    parser.add_argument(
        "--action",
        choices=("fingerprint", "dump", "full"),
        help="run the framework's real auto_exploit() over the virtual link",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=1.0,
        help="seconds to wait for a notification (default: 1.0)",
    )
    parser.add_argument(
        "--slow-seconds",
        type=float,
        default=6.0,
        help="delay used by the 'slow' fault kind (default: 6.0)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="fault-injection RNG seed (default: deterministic 0)",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="reject flash/RAM writes with a READ_ONLY status",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="exercise scan_for_targets() over the virtual advertisement",
    )
    parser.add_argument(
        "--mtu",
        type=int,
        default=None,
        metavar="BYTES",
        help=(
            "emulate ATT MTU fragmentation (23 is the BLE default; "
            "omit for one notification per frame)"
        ),
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="print a JSON device report after the session",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_profiles:
        list_profiles()
        return 0
    try:
        return asyncio.run(
            run(
                profile=args.profile,
                error_specs=args.errors,
                commands=args.commands,
                script_path=args.script,
                interactive=args.interactive,
                action=args.action,
                read_timeout=args.read_timeout,
                slow_seconds=args.slow_seconds,
                seed=args.seed,
                read_only=args.read_only,
                json_output=args.json_output,
                att_mtu=args.mtu,
                discover=args.discover,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130


__all__ = [
    "DEFAULT_SCRIPT",
    "build_parser",
    "list_profiles",
    "main",
    "run",
]
