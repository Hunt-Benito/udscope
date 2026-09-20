"""Pluggable seed-key (security access 0x27) algorithm registry.

Every algorithm here is either synthetic (invented for the udscope demo ECU
and the accompanying articles) or comes from a publicly cited paper, verified
against the original publication. Nothing in this module derives from private
reverse-engineering material.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List


@dataclass
class SeedKeyAlgorithm:
    name: str
    seed_len: int
    key_len: int
    fn: Callable[[int, int], int]
    description: str
    origin: str


REGISTRY: Dict[str, SeedKeyAlgorithm] = {}


def register(algo: SeedKeyAlgorithm) -> None:
    REGISTRY[algo.name] = algo


def get(name: str) -> SeedKeyAlgorithm:
    try:
        return REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"unknown algorithm {name!r}; registered: {', '.join(sorted(REGISTRY))}"
        ) from None


def list_algorithms() -> List[SeedKeyAlgorithm]:
    return sorted(REGISTRY.values(), key=lambda a: a.name)


def _rol32(value: int, n: int) -> int:
    n &= 31
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


def xor_shift_demo(seed: int, level: int = 0) -> int:
    """Synthetic rotate/xor/add chain — the demo ECU's level 0x11 algorithm.

    Invented for udscope; deliberately built from the classic patterns found
    in real seed-key implementations (rotates, constant XOR, constant ADD) so
    it can be reverse-engineered as an exercise.
    """
    key = _rol32(seed, 7)
    key ^= 0x5A5AA5A5
    key = (key + 0x0BADA5C0) & 0xFFFFFFFF
    key ^= _rol32(seed, 13)
    return key


def table_mix_demo(seed: int, level: int = 0) -> int:
    """Synthetic nibble-table mixer — a table-lookup pattern exercise.

    Each nibble of the seed indexes a synthetic 16-entry table; results are
    accumulated with rotate mixing. Invented for udscope.
    """
    table = [
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
        0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
    ]
    key = 0x13579BDF
    for i in range(8):
        nibble = (seed >> (4 * i)) & 0xF
        key = _rol32(key ^ (table[nibble] << (4 * i % 24)), 3)
    return key


register(SeedKeyAlgorithm(
    name="xor_shift_demo",
    seed_len=4, key_len=4,
    fn=xor_shift_demo,
    description="rotate/XOR/ADD chain (synthetic, demo ECU level 0x11)",
    origin="synthetic (udscope)",
))

register(SeedKeyAlgorithm(
    name="table_mix_demo",
    seed_len=4, key_len=4,
    fn=table_mix_demo,
    description="nibble table lookup with rotate mixing (synthetic)",
    origin="synthetic (udscope)",
))
