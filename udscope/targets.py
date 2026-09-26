"""ECU target definitions - ISO-TP address pairs for known/demo targets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Target:
    name: str
    tx_id: int
    rx_id: int
    description: str = ""


TARGETS: Dict[str, Target] = {
    "demo": Target("demo", 0x7E0, 0x7E8, "udscope demo ECU (run `udscope sim`)"),
}

FUNCTIONAL_REQUEST_ID = 0x7DF

STANDARD_ECUs: List[Target] = [
    Target(f"obd{i}", 0x7E0 + i, 0x7E8 + i, f"ISO 15765-4 standard ECU slot {i}")
    for i in range(8)
]


def resolve(name_or_id: str) -> Target:
    if name_or_id in TARGETS:
        return TARGETS[name_or_id]
    try:
        raw = int(name_or_id, 0)
    except ValueError:
        raise KeyError(f"unknown target {name_or_id!r}; known: {', '.join(TARGETS)}") from None
    for target in list(TARGETS.values()) + STANDARD_ECUs:
        if target.tx_id == raw:
            return target
    raise KeyError(f"no target with request ID 0x{raw:X}")
