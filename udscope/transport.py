"""ISO-TP (ISO 15765-2) transport links over python-can."""

from __future__ import annotations

import can
import isotp
from typing import Callable, Optional


def _default_logger(direction: str, arb_id: int, data: bytes) -> None:
    print(f"[{direction}] {arb_id:03X}  {data.hex(' ')}")


class IsotpLink:
    """One ISO-TP connection between a tester and an ECU address pair.

    Wraps ``isotp.CanStack`` on top of a python-can bus. Create one link per
    ECU you talk to. On ``socketcan`` several links may share one bus object;
    on the ``virtual`` interface each link needs its own bus instance (a
    virtual bus does not loop frames back to the sending instance).
    """

    def __init__(
        self,
        tx_id: int,
        rx_id: int,
        bus: Optional[can.BusABC] = None,
        channel: str = "vcan0",
        interface: str = "socketcan",
        address_mode: int = isotp.AddressingMode.Normal_11bits,
        logger: Optional[Callable[[str, int, bytes], None]] = None,
        stmin: int = 5,
        blocksize: int = 8,
    ):
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.logger = logger or _default_logger
        self._owns_bus = bus is None
        if bus is None:
            bus = can.Bus(interface=interface, channel=channel)
        self.bus = bus
        address = isotp.Address(address_mode, txid=tx_id, rxid=rx_id)
        params = {"stmin": stmin, "blocksize": blocksize}
        self.stack = isotp.CanStack(bus=bus, address=address, params=params)

    def start(self) -> None:
        self.stack.start()

    def stop(self) -> None:
        self.stack.stop()
        if self._owns_bus:
            self.bus.shutdown()

    def send(self, payload: bytes) -> None:
        self.logger("TX", self.tx_id, bytes(payload))
        self.stack.send(payload)

    def recv(self, block: bool = True, timeout: Optional[float] = None) -> Optional[bytes]:
        data = self.stack.recv(block=block, timeout=timeout)
        if data is not None:
            self.logger("RX", self.rx_id, bytes(data))
        return bytes(data) if data is not None else None


def make_bus(channel: str = "vcan0", interface: str = "socketcan") -> can.BusABC:
    """Create a python-can bus that can be shared between several links."""
    return can.Bus(interface=interface, channel=channel)
