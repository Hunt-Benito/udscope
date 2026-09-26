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
