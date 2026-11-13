"""Configurable fault injection for the virtual RACE peripheral.

A fault is a rule that matches an opcode (or every opcode) and changes how
the emulated device answers: silently, slowly, with a corrupted frame, with
an error status, or by dropping the link.  Rules support a probability and a
finite occurrence count, so a session can mix clean and faulty responses.

The same rules are available three ways:

* programmatically — ``FaultRule(cmd=CMD_GET_BUILD, kind=FaultKind.SILENT)``
* from the CLI — ``--error 0x1E08:silent``
* from the explorer — ``fault flash_read:bad_length:0.5#2``

Spec grammar::

    SPEC  := [TARGET:]KIND[:PROBABILITY[#COUNT]]
    TARGET:= * | <opcode> | <name>          # omit for every opcode
    KIND  := silent | slow | truncate | bad_head | bad_type
           | bad_length | garbage | disconnect | status | duplicate

``slow`` accepts a duration (``slow:2.5s``), ``status`` accepts a status word
(``status:0x0002``), and ``PROBABILITY`` is the remaining bare float.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum

from .opcodes import OpcodeError, resolve_opcode
from .status import STATUS_INJECTED, status_name


class FaultKind(str, Enum):
    """How an injected fault manifests on the wire."""

    SILENT = "silent"           # no notification at all -> client read timeout
    SLOW = "slow"               # valid response, delivered after a delay
    TRUNCATE = "truncate"       # response cut to 3 bytes -> TOO_SHORT
    BAD_HEAD = "bad_head"       # unknown frame head -> BAD_HEAD
    BAD_TYPE = "bad_type"       # type outside 0x00/0x01 -> BAD_TYPE
    BAD_LENGTH = "bad_length"   # length field zeroed -> BAD_LENGTH
    GARBAGE = "garbage"         # non-RACE bytes -> BAD_HEAD/TOO_SHORT
    DISCONNECT = "disconnect"   # link drops, no reply
    STATUS = "status"           # valid frame carrying an error status word
    DUPLICATE = "duplicate"     # the same response sent twice


class FaultSpecError(ValueError):
    """Raised when a textual fault specification cannot be parsed."""


@dataclass(frozen=True)
class FaultRule:
    """One fault-injection rule.

    ``cmd=None`` matches every opcode.  ``probability`` is evaluated per
    request.  ``times`` caps how often the rule fires (``None`` = unlimited).
    ``delay_s`` applies to :attr:`FaultKind.SLOW`; ``status`` to
    :attr:`FaultKind.STATUS`.
    """

    cmd: int | None = None
    kind: FaultKind = FaultKind.SILENT
    probability: float = 1.0
    times: int | None = None
    delay_s: float | None = None
    status: int = STATUS_INJECTED

    def __post_init__(self) -> None:
        try:
            kind = FaultKind(self.kind)
        except ValueError:
            raise FaultSpecError(
                f"unknown fault kind {self.kind!r}"
            ) from None
        if kind is not self.kind:
            object.__setattr__(self, "kind", kind)
        if self.cmd is not None and not 0 <= self.cmd <= 0xFFFF:
            raise FaultSpecError(f"opcode {self.cmd!r} is outside the 16-bit range")
        if not 0.0 <= self.probability <= 1.0:
            raise FaultSpecError("probability must be between 0.0 and 1.0")
        if self.times is not None and self.times < 1:
            raise FaultSpecError("times must be >= 1 when set")
        if self.delay_s is not None and self.delay_s < 0:
            raise FaultSpecError("delay must be >= 0 seconds")
        if not 0 <= self.status <= 0xFFFF:
            raise FaultSpecError("status must be a 16-bit value")

    @property
    def target(self) -> str:
        return "*" if self.cmd is None else f"0x{self.cmd:04X}"

    def describe(self) -> str:
        """Compact one-line description used by the explorer."""
        parts = [f"{self.target}:{self.kind.value}"]
        if self.kind is FaultKind.SLOW and self.delay_s is not None:
            parts.append(f"{self.delay_s:g}s")
        if self.kind is FaultKind.STATUS:
            parts.append(f"0x{self.status:04X} ({status_name(self.status)})")
        if self.probability < 1.0:
            parts.append(f"p={self.probability:g}")
        if self.times is not None:
            parts.append(f"x{self.times}")
        return " ".join(parts)


class FaultPlan:
    """Ordered rule set that decides whether a request is faulted."""

    def __init__(
        self,
        rules: Iterable[FaultRule] = (),
        *,
        seed: int | float | str | None = 0,
    ) -> None:
        self._rules: list[FaultRule] = []
        self._used: list[int] = []
        self._rng = random.Random(seed)
        self.total_fired = 0
        for rule in rules:
            self.add(rule)

    @property
    def rules(self) -> tuple[FaultRule, ...]:
        return tuple(self._rules)

    def __bool__(self) -> bool:
        return any(self._active(rule, index) for index, rule in enumerate(self._rules))

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[FaultRule]:
        return iter(self._rules)

    def add(self, rule: FaultRule) -> FaultRule:
        """Append a rule.  Earlier rules take priority."""
        if not isinstance(rule, FaultRule):
            raise TypeError("FaultPlan.add() expects a FaultRule")
        self._rules.append(rule)
        self._used.append(0)
        return rule

    def extend(self, rules: Iterable[FaultRule]) -> None:
        for rule in rules:
            self.add(rule)

    def clear(self) -> None:
        self._rules.clear()
        self._used.clear()

    def reset(self) -> None:
        """Reset occurrence counters and statistics, keeping the rules."""
        self._used = [0] * len(self._rules)
        self.total_fired = 0

    def _active(self, rule: FaultRule, index: int) -> bool:
        return rule.times is None or self._used[index] < rule.times

    def choose(self, cmd: int) -> FaultRule | None:
        """Return the first rule that fires for *cmd*, or ``None``."""
        for index, rule in enumerate(self._rules):
            if rule.cmd is not None and rule.cmd != cmd:
                continue
            if not self._active(rule, index):
                continue
            if rule.probability <= 0.0:
                continue
            if self._rng.random() >= rule.probability:
                continue
            self._used[index] += 1
            self.total_fired += 1
            return rule
        return None


def parse_fault_spec(spec: str) -> FaultRule:
    """Parse a ``TARGET:KIND[:RATE]`` fault specification."""
    text = spec.strip()
    if not text:
        raise FaultSpecError("empty fault specification")

    times: int | None = None
    if "#" in text:
        text, count_text = text.rsplit("#", 1)
        try:
            times = int(count_text, 0)
        except ValueError:
            raise FaultSpecError(f"invalid occurrence count {count_text!r}") from None

    parts = [part for part in text.split(":") if part != ""]
    kinds = {kind.value: kind for kind in FaultKind}

    kind_index: int | None = None
    for candidate in (0, 1):
        if candidate < len(parts) and parts[candidate].lower() in kinds:
            kind_index = candidate
            break
    if kind_index is None:
        raise FaultSpecError(
            f"missing fault kind in {spec!r}; choose from {', '.join(sorted(kinds))}"
        )

    kind = kinds[parts[kind_index].lower()]
    target_tokens = parts[:kind_index]
    tail = parts[kind_index + 1 :]
    if len(target_tokens) > 1:
        raise FaultSpecError(f"ambiguous target in {spec!r}")

    cmd: int | None = None
    if target_tokens:
        target = target_tokens[0].strip()
        if target not in ("*", "any", "all"):
            try:
                cmd = resolve_opcode(target)
            except OpcodeError as exc:
                raise FaultSpecError(str(exc)) from None

    probability = 1.0
    delay_s: float | None = None
    status = STATUS_INJECTED
    for token in tail:
        low = token.lower()
        if kind is FaultKind.SLOW and low.endswith("s"):
            try:
                delay_s = float(low[:-1])
            except ValueError:
                raise FaultSpecError(f"invalid delay {token!r}") from None
        elif kind is FaultKind.STATUS and low.startswith("0x"):
            try:
                status = int(low, 16)
            except ValueError:
                raise FaultSpecError(f"invalid status word {token!r}") from None
        else:
            try:
                probability = float(low)
            except ValueError:
                raise FaultSpecError(f"invalid probability {token!r}") from None

    try:
        return FaultRule(
            cmd=cmd,
            kind=kind,
            probability=probability,
            times=times,
            delay_s=delay_s,
            status=status,
        )
    except FaultSpecError:
        raise
    except ValueError as exc:  # defensive: dataclass validation
        raise FaultSpecError(str(exc)) from None


def parse_fault_specs(specs: Iterable[str]) -> list[FaultRule]:
    """Parse several specifications, preserving order."""
    return [parse_fault_spec(spec) for spec in specs]
