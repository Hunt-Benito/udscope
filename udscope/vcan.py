"""Automatic virtual CAN (vcan) interface management.

Only channels whose name starts with ``vcan`` on the ``socketcan`` interface
are managed — real hardware buses (can0, slcan, pcan, ...) are never touched.
Creating a vcan interface requires root (module load + link creation), so a
sudo password prompt is shown; the prompt text itself explains why root is
needed. Set ``UDSCOPE_NO_AUTO_SETUP=1`` to disable automatic management.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable, List, Optional

SUDO_PROMPT = (
    "udscope: root needed to create virtual CAN interface %s "
    "(one-time: modprobe vcan, ip link add, ip link set up) — password for %%p: "
)

MANUAL_INSTRUCTIONS = """create the interface manually and retry:
  sudo modprobe vcan
  sudo ip link add dev {channel} type vcan
  sudo ip link set up {channel}"""


def _run(cmd: List[str]) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def interface_exists(channel: str, runner: Callable = _run) -> bool:
    return runner(["ip", "link", "show", channel]).returncode == 0


def interface_is_up(channel: str, runner: Callable = _run) -> bool:
    result = runner(["ip", "-brief", "link", "show", channel])
    if result.returncode != 0:
        return False
    return b"UP" in result.stdout


def _sudo_cmd(cmd: List[str], channel: str) -> List[str]:
    return ["sudo", "-p", SUDO_PROMPT % channel] + cmd


def ensure_vcan(
    channel: str = "vcan0",
    interface: str = "socketcan",
    runner: Callable = _run,
    quiet: bool = False,
) -> bool:
    """Make sure ``channel`` exists and is up, creating it via sudo if needed.

    Returns True when the interface is ready. Returns False when creation was
    not possible (missing tools, sudo declined/failed) — callers should print
    the manual instructions and abort.
    """
    if interface != "socketcan" or not channel.startswith("vcan"):
        return True
    already_ok = interface_exists(channel, runner) and interface_is_up(channel, runner)
    if os.environ.get("UDSCOPE_NO_AUTO_SETUP") == "1":
        return already_ok
    if already_ok:
        return True

    if shutil.which("ip") is None:
        return False

    steps: List[List[str]] = []
    if not interface_exists(channel, runner):
        steps.append(["modprobe", "vcan"])
        steps.append(["ip", "link", "add", "dev", channel, "type", "vcan"])
    steps.append(["ip", "link", "set", "up", channel])

    if not quiet:
        print(f"[setup] {channel} is missing or down — "
              f"root privileges are required to create/enable the virtual CAN interface")
    if os.geteuid() == 0:
        for step in steps:
            if runner(step).returncode != 0:
                return False
    else:
        if shutil.which("sudo") is None:
            return False
        for step in steps:
            if runner(_sudo_cmd(step, channel)).returncode != 0:
                return False
    return interface_exists(channel, runner) and interface_is_up(channel, runner)
