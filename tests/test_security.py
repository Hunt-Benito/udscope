"""Unit tests for the seed-key algorithm registry."""

import pytest

from udscope import security


def test_registry_lists_algorithms():
    names = {a.name for a in security.list_algorithms()}
    assert {"xor_shift_demo", "table_mix_demo"} <= names


def test_unknown_algorithm_raises():
    with pytest.raises(KeyError):
        security.get("does_not_exist")


def test_xor_shift_demo_is_deterministic():
    assert security.xor_shift_demo(0x01234567) == security.xor_shift_demo(0x01234567)


def test_xor_shift_demo_changes_output():
    assert security.xor_shift_demo(0x01234567) != security.xor_shift_demo(0x01234568)


def test_xor_shift_demo_known_vector():
    seed = 0x00000001
    expected = security._rol32(security._rol32(seed, 7) ^ 0x5A5AA5A5, 0)
    expected = (security._rol32(seed, 7) ^ 0x5A5AA5A5) + 0x0BADA5C0 & 0xFFFFFFFF
    expected ^= security._rol32(seed, 13)
    assert security.xor_shift_demo(seed) == expected & 0xFFFFFFFF


def test_table_mix_demo_bounds():
    for seed in (0, 1, 0xFFFFFFFF, 0xDEADBEEF):
        assert 0 <= security.table_mix_demo(seed) <= 0xFFFFFFFF
