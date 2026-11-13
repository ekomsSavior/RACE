from typing import Any

from transports.ble import BLETransport
from utils.config import RACEConfig
from utils.packet import CMD_GET_BUILD


async def fingerprint(target: str, config: RACEConfig | None = None) -> dict[str, Any]:
    """Fingerprint a RACE device's build info.

    Returns ``{"status": "success", "build": str}`` on success or
    ``{"status": "error", "message": str}`` on failure.
    """
    cfg = config or RACEConfig()
    result: dict[str, Any] = {"status": "error", "message": "not run"}

    try:
        async with BLETransport(target, config=cfg) as transport:
            raw = await transport.send_command(CMD_GET_BUILD)
            build_string = raw.decode("utf-8", errors="ignore").strip("\x00")
            result = {"status": "success", "build": build_string}
    except Exception as exc:
        result = {"status": "error", "message": str(exc)}

    return result
