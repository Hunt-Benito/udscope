"""UDS (ISO 14229) service identifiers, negative response codes, and a client."""

from __future__ import annotations

import time
from typing import Optional

from .transport import IsotpLink


class Session:
    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED = 0x03
    SAFETY = 0x4F
    DEVELOPER = 0x60


class SID:
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    CLEAR_DTC = 0x14
    READ_DTC = 0x19
    READ_BY_ID = 0x22
    READ_BY_ADDRESS = 0x23
    SECURITY_ACCESS = 0x27
    COMMUNICATION_CONTROL = 0x28
    WRITE_BY_ID = 0x2E
    INPUT_OUTPUT_CONTROL = 0x2F
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    REQUEST_UPLOAD = 0x35
    TRANSFER_DATA = 0x36
    TRANSFER_EXIT = 0x37
    TESTER_PRESENT = 0x3E

    @classmethod
    def names(cls) -> dict:
        return {v: k for k, v in cls.__dict__.items() if isinstance(v, int) and not k.startswith("_")}


NRC = {
    0x10: "general reject",
    0x11: "service not supported",
    0x12: "sub-function not supported",
    0x13: "incorrect message length or invalid format",
    0x14: "response too long",
    0x21: "busy repeat request",
    0x22: "conditions not correct",
    0x24: "request sequence error",
    0x31: "request out of range",
    0x33: "security access denied",
    0x35: "invalid key",
    0x36: "exceeded number of attempts",
    0x37: "required time delay not expired",
    0x70: "upload/download not accepted",
    0x71: "transfer data suspended",
    0x72: "general programming failure",
    0x73: "wrong block sequence counter",
    0x78: "response pending",
    0x7E: "sub-function not supported in active session",
    0x7F: "service not supported in active session",
}


class NegativeResponseError(Exception):
    """Raised when the ECU answers a request with a negative response (0x7F)."""

    def __init__(self, sid: int, nrc: int):
        self.sid = sid
        self.nrc = nrc
        self.description = NRC.get(nrc, f"unknown NRC 0x{nrc:02X}")
        service = SID.names().get(sid, f"0x{sid:02X}")
        super().__init__(f"negative response to {service}: NRC 0x{nrc:02X} ({self.description})")

    def __str__(self) -> str:
        return self.message if hasattr(self, "message") else super().__str__()


class TimeoutError_(Exception):
    """Raised when the ECU does not answer within the configured timeout."""


class UdsClient:
    """Minimal UDS client on top of an ISO-TP link.

    ``request`` handles negative responses, including NRC 0x78
    (response pending) re-polling up to the overall timeout.
    """

    def __init__(self, link: IsotpLink, timeout: float = 2.0, p2_star_max: float = 10.0):
        self.link = link
        self.timeout = timeout
        self.p2_star_max = p2_star_max

    def request(self, data: bytes, timeout: Optional[float] = None) -> bytes:
        deadline = time.monotonic() + (timeout or self.timeout)
        self.link.send(bytes(data))
        pending = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError_(
                    f"no response within {timeout or self.timeout:.1f}s"
                    + (f" (after {pending} NRC 0x78 pending)" if pending else "")
                )
            resp = self.link.recv(block=True, timeout=remaining)
            if resp is None:
                raise TimeoutError_(
                    f"no response within {timeout or self.timeout:.1f}s"
                    + (f" (after {pending} NRC 0x78 pending)" if pending else "")
                )
            if len(resp) >= 3 and resp[0] == 0x7F and resp[2] == 0x78:
                pending += 1
                continue
            if len(resp) >= 3 and resp[0] == 0x7F:
                raise NegativeResponseError(resp[1], resp[2])
            return resp

    def set_session(self, level: int) -> bytes:
        return self.request(bytes([SID.DIAGNOSTIC_SESSION_CONTROL, level & 0x7F]))

    def ecu_reset(self, sub: int = 0x01) -> bytes:
        return self.request(bytes([SID.ECU_RESET, sub & 0x7F]))

    def tester_present(self) -> bytes:
        return self.request(bytes([SID.TESTER_PRESENT, 0x00]))

    def read_did(self, did: int) -> bytes:
        return self.request(bytes([SID.READ_BY_ID, (did >> 8) & 0xFF, did & 0xFF]))

    def read_vin(self) -> str:
        resp = self.read_did(0xF190)
        return resp[3:].decode("ascii", errors="replace").strip()

    def read_by_address(self, address: int, length: int, addr_bytes: int = 4) -> bytes:
        if addr_bytes not in (2, 3, 4):
            raise ValueError("addr_bytes must be 2, 3 or 4")
        if length > 0xFFFF:
            raise ValueError("length must fit in 16 bits")
        req = bytes([SID.READ_BY_ADDRESS, (addr_bytes << 4) | 0x2])
        req += address.to_bytes(addr_bytes, "big") + length.to_bytes(2, "big")
        resp = self.request(req)
        return resp[1 + addr_bytes:]

    def security_access(self, send_level: int, key_fn) -> bytes:
        """Run the 0x27 seed-key handshake using ``key_fn(seed: int) -> int``."""
        resp = self.request(bytes([SID.SECURITY_ACCESS, send_level & 0x7F]))
        if resp[0] != 0x67:
            raise ValueError(f"unexpected positive response {resp.hex()}")
        seed = int.from_bytes(resp[2:], "big")
        key = key_fn(seed)
        key_len = max(1, (key.bit_length() + 7) // 8)
        key_bytes = key.to_bytes(key_len, "big")
        return self.request(bytes([SID.SECURITY_ACCESS, (send_level + 1) & 0xFF]) + key_bytes)
