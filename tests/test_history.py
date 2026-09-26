"""Tests for shell history features."""

import os

import pytest

from udscope import cli


def test_format_history_full():
    entries = ["session 0x03", "read-did F190", "22 f1 90"]
    out = cli.format_history(entries)
    lines = out.splitlines()
    assert lines[0].strip().startswith("1")
    assert "session 0x03" in lines[0]
    assert lines[2].endswith("22 f1 90")


def test_format_history_last_n():
    entries = ["a", "b", "c", "d"]
    out = cli.format_history(entries, 2)
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[0].strip().startswith("3")
    assert lines[1].endswith("d")


def test_format_history_empty():
    assert cli.format_history([]) == ""


@pytest.mark.skipif(cli.readline is None, reason="readline unavailable")
def test_history_file_round_trip(monkeypatch, tmp_path):
    path = tmp_path / "shell_history"
    monkeypatch.setattr(cli, "HISTORY_FILE", str(path))
    cli.readline.clear_history()
    cli.readline.add_history("session 0x03")
    cli._save_readline_history()
    assert path.exists()
    cli.readline.clear_history()
    cli._init_readline_history()
    assert cli.readline.get_history_item(1) == "session 0x03"


def test_ascii_repr():
    from udscope.cli import ascii_repr
    assert ascii_repr(b"\x62\xf2\x2b\x00\x64\x00\xc8") == "b.+.d.."
    assert ascii_repr(b"UDSCOPE") == "UDSCOPE"


def test_hexdump_format():
    from udscope.cli import hexdump
    out = hexdump(b"UDSCOPE DEMO FIR")
    lines = out.splitlines()
    assert lines[0].startswith("  00000000: 55 44 53")
    assert lines[0].endswith("|UDSCOPE DEMO FIR|")


def test_hexdump_partial_line_padding():
    from udscope.cli import hexdump
    out = hexdump(b"AB")
    assert "|AB|" in out
    assert "61" not in out.split("|")[0]


def test_shell_completion_commands():
    from udscope.cli import shell_candidates
    assert shell_candidates("se", 0, "se") == ["session", "secaccess"]
    assert shell_candidates("sc", 0, "sc") == []
    assert shell_candidates("read", 0, "read") == ["read-did"]
    assert shell_candidates("ke", 0, "ke") == ["keepalive"]
    from udscope.cli import SHELL_COMMANDS
    assert shell_candidates("", 0, "") == SHELL_COMMANDS


def test_shell_completion_arguments():
    from udscope.cli import shell_candidates
    assert shell_candidates("keepalive o", 11, "o") == ["on", "off"]
    algos = shell_candidates("secaccess xor", 11, "xor")
    assert algos == ["xor_shift_demo"]
    sessions = shell_candidates("session 0x0", 8, "0x0")
    assert sessions == ["0x01", "0x02", "0x03"]
    dids = shell_candidates("read-did 0xF2", 10, "0xF2")
    assert "0xF242" in dids and "0xF22B" in dids
