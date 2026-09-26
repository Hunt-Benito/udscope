"""Unit tests for automatic vcan interface management."""

import pytest

from udscope import vcan


class FakeRunner:
    def __init__(self, exists=False, up=False, sudo_ok=True, track=None):
        self.exists = exists
        self.up = up
        self.sudo_ok = sudo_ok
        self.track = track if track is not None else []

    def __call__(self, cmd):
        self.track.append(cmd)
        import subprocess
        result = subprocess.CompletedProcess(cmd, 0, b"", b"")
        if cmd[:2] == ["sudo", "-p"]:
            if not self.sudo_ok:
                return subprocess.CompletedProcess(cmd, 1, b"", b"auth failed")
            cmd = cmd[3:]
        if cmd[:3] == ["ip", "link", "show"] or cmd[:3] == ["ip", "-brief", "link", "show"][:3]:
            if not self.exists:
                return subprocess.CompletedProcess(cmd, 1, b"", b"Cannot find device")
            if cmd[1] == "-brief":
                state = b"UP" if self.up else b"DOWN"
                out = b"vcan0 UNKNOWN " + state + b" <NOARP>\n"
                return subprocess.CompletedProcess(cmd, 0, out, b"")
        if cmd[:3] == ["ip", "link", "add"]:
            self.exists = True
            self.up = False
        if cmd[:4] == ["ip", "link", "set", "up"]:
            self.up = True
        return result


def test_present_and_up_requires_no_changes():
    track = []
    ok = vcan.ensure_vcan(runner=FakeRunner(exists=True, up=True, track=track), quiet=True)
    assert ok is True
    assert track == [["ip", "link", "show", "vcan0"], ["ip", "-brief", "link", "show", "vcan0"]]


def test_missing_interface_created_via_sudo():
    track = []
    ok = vcan.ensure_vcan(runner=FakeRunner(exists=False, track=track), quiet=True)
    assert ok is True
    sudo_cmds = [c for c in track if c[0] == "sudo"]
    assert len(sudo_cmds) == 3
    underlying = [c[3:] for c in sudo_cmds]
    assert underlying[0][:2] == ["modprobe", "vcan"]
    assert underlying[1][:3] == ["ip", "link", "add"]
    assert underlying[2][:4] == ["ip", "link", "set", "up"]
    assert "root needed to create virtual CAN interface vcan0" in sudo_cmds[0][2]


def test_sudo_failure_returns_false():
    track = []
    ok = vcan.ensure_vcan(runner=FakeRunner(exists=False, sudo_ok=False, track=track), quiet=True)
    assert ok is False


def test_non_vcan_channel_is_never_managed():
    track = []
    ok = vcan.ensure_vcan(channel="can0", runner=FakeRunner(exists=False, track=track), quiet=True)
    assert ok is True
    assert track == []


def test_env_disable(monkeypatch):
    monkeypatch.setenv("UDSCOPE_NO_AUTO_SETUP", "1")
    track = []
    ok = vcan.ensure_vcan(runner=FakeRunner(exists=False, track=track), quiet=True)
    assert ok is False
    assert track == [["ip", "link", "show", "vcan0"]]


def test_down_interface_brought_up():
    track = []
    runner = FakeRunner(exists=True, up=False, track=track)
    ok = vcan.ensure_vcan(runner=runner, quiet=True)
    assert ok is True
    sudo_cmds = [c for c in track if c[0] == "sudo"]
    assert len(sudo_cmds) == 1
    assert sudo_cmds[0][3:][:4] == ["ip", "link", "set", "up"]
