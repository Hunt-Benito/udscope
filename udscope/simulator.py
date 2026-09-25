"""A synthetic UDS ECU simulator — the virtual target every demo talks to.

The demo ECU implements a small, realistic subset of ISO 14229:

* 0x10 diagnostic session control (default 0x01 / extended 0x03 / developer 0x60)
* 0x11 ECU reset (hard reset)
* 0x22 read data by identifier (VIN, IDs, session-gated DIDs)
* 0x23 read memory by address (developer session + unlocked only)
* 0x27 security access (level 0x11 seed / 0x12 key, synthetic algorithm,
  3 attempts then a 10 s penalty — NRC 0x36 / 0x37 behaviour)
* 0x3E tester present (S3 timeout of 5 s relocks and drops to default session)
"""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

from . import security
from .transport import IsotpLink
from .uds import SID, Session

S3_TIMEOUT = 5.0
MAX_KEY_ATTEMPTS = 3
PENALTY_SECONDS = 10.0
SECURITY_ALGORITHM = "xor_shift_demo"
SEND_KEY_LEVEL = 0x11
DEV_SESSION_UNLOCK_LEVEL = 0x11

MEMORY_MAP = {
    (0x00C0DE00, 0x00C0DE80): (
        b"UDSCOPE DEMO FIRMWARE v0.2 | THIS REGION IS SERVED BY THE SIMULATOR "
        b"FOR READ-MEMORY-BY-ADDRESS DEMOS. PAD PAD PAD PAD PAD PAD PAD"
    )[:0x80].ljust(0x80, b"."),
}

DID_DB = {
    0xF190: {"data": b"UDSCOPEDEMOECU001", "sessions": {Session.DEFAULT, Session.EXTENDED, Session.DEVELOPER}},
    0xF187: {"data": b"UDS-DEMO-ECU-01", "sessions": {Session.DEFAULT, Session.EXTENDED, Session.DEVELOPER}},
    0xF18A: {"data": b"HB-DEMO-0001", "sessions": {Session.DEFAULT, Session.EXTENDED, Session.DEVELOPER}},
    0xF195: {"data": b"UDS01.000.000", "sessions": {Session.DEFAULT, Session.EXTENDED, Session.DEVELOPER}},
    0xF22B: {"data": b"\x00\x64\x00\xC8", "sessions": {Session.EXTENDED, Session.DEVELOPER}},
    0xF22C: {"data": os.urandom(8), "sessions": {Session.DEVELOPER}},
}

SESSIONS_SUPPORTED = {Session.DEFAULT, Session.EXTENDED, Session.DEVELOPER}


class DemoEcu:
    """Serves one ISO-TP address pair. Run :meth:`serve_forever` in a thread."""

    def __init__(self, link: IsotpLink):
        self.link = link
        self._reset_state()
        self._stop = False
        self._last_activity = time.monotonic()

    def _reset_state(self) -> None:
        self.session = Session.DEFAULT
        self.unlocked = False
        self.key_attempts = 0
        self.penalty_until = 0.0
        self._pending_seed: Optional[bytes] = None
        self._algo = security.get(SECURITY_ALGORITHM)

    def stop(self) -> None:
        self._stop = True

    def serve_forever(self, poll_timeout: float = 0.05) -> None:
        self.link.start()
        try:
            while not self._stop:
                data = self.link.recv(block=True, timeout=poll_timeout)
                if data is not None:
                    resp = self._handle(data)
                    if resp is not None:
                        self.link.send(resp)
                    self._last_activity = time.monotonic()
                if self.session != Session.DEFAULT and time.monotonic() - self._last_activity > S3_TIMEOUT:
                    self._on_s3_timeout()
        finally:
            self.link.stop()

    def _on_s3_timeout(self) -> None:
        self.session = Session.DEFAULT
        self.unlocked = False
        self._pending_seed = None

    def _nrc(self, sid: int, code: int) -> bytes:
        return bytes([0x7F, sid, code])

    def _handle(self, data: bytes) -> Optional[bytes]:
        if not data:
            return self._nrc(0x10, 0x13)
        sid = data[0]
        handler = {
            SID.DIAGNOSTIC_SESSION_CONTROL: self._hdl_session,
            SID.ECU_RESET: self._hdl_reset,
            SID.READ_BY_ID: self._hdl_read_by_id,
            SID.READ_BY_ADDRESS: self._hdl_read_by_address,
            SID.SECURITY_ACCESS: self._hdl_security_access,
            SID.TESTER_PRESENT: self._hdl_tester_present,
        }.get(sid)
        if handler is None:
            return self._nrc(sid, 0x11)
        try:
            return handler(data)
        except Exception:
            return self._nrc(sid, 0x10)

    def _hdl_session(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.DIAGNOSTIC_SESSION_CONTROL, 0x13)
        level = data[1] & 0x7F
        if level not in SESSIONS_SUPPORTED:
            return self._nrc(SID.DIAGNOSTIC_SESSION_CONTROL, 0x12)
        if level == Session.DEVELOPER and not self.unlocked:
            return self._nrc(SID.DIAGNOSTIC_SESSION_CONTROL, 0x33)
        if level != Session.DEVELOPER:
            self.unlocked = False
            self._pending_seed = None
        self.session = level
        return bytes([0x50, level, 0x00, 0x05, 0x01, 0xF4])

    def _hdl_reset(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.ECU_RESET, 0x13)
        sub = data[1] & 0x7F
        if sub != 0x01:
            return self._nrc(SID.ECU_RESET, 0x12)
        resp = bytes([0x51, 0x01])
        self._reset_state()
        return resp

    def _hdl_read_by_id(self, data: bytes) -> bytes:
        if len(data) != 3:
            return self._nrc(SID.READ_BY_ID, 0x13)
        did = (data[1] << 8) | data[2]
        entry = DID_DB.get(did)
        if entry is None:
            return self._nrc(SID.READ_BY_ID, 0x31)
        if self.session not in entry["sessions"]:
            return self._nrc(SID.READ_BY_ID, 0x7E)
        return bytes([0x62, data[1], data[2]]) + entry["data"]

    def _hdl_read_by_address(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.READ_BY_ADDRESS, 0x13)
        fmt = data[1]
        addr_bytes = fmt >> 4
        len_bytes = fmt & 0x0F
        if addr_bytes not in (1, 2, 3, 4) or len_bytes != 2:
            return self._nrc(SID.READ_BY_ADDRESS, 0x13)
        if self.session != Session.DEVELOPER:
            return self._nrc(SID.READ_BY_ADDRESS, 0x7E)
        if not self.unlocked:
            return self._nrc(SID.READ_BY_ADDRESS, 0x33)
        rest = data[2:]
        if len(rest) < addr_bytes + 2:
            return self._nrc(SID.READ_BY_ADDRESS, 0x13)
        address = int.from_bytes(rest[:addr_bytes], "big")
        length = int.from_bytes(rest[addr_bytes:addr_bytes + 2], "big")
        for (start, end), blob in MEMORY_MAP.items():
            if start <= address and address + length <= end:
                offset = address - start
                return bytes([0x63]) + rest[:addr_bytes] + blob[offset:offset + length]
        return self._nrc(SID.READ_BY_ADDRESS, 0x31)

    def _hdl_security_access(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.SECURITY_ACCESS, 0x13)
        sub = data[1] & 0x7F
        if sub == SEND_KEY_LEVEL:
            if self.session == Session.DEFAULT:
                return self._nrc(SID.SECURITY_ACCESS, 0x7E)
            if self.unlocked:
                return bytes([0x67, sub])
            if time.monotonic() < self.penalty_until:
                return self._nrc(SID.SECURITY_ACCESS, 0x37)
            seed = os.urandom(4)
            self._pending_seed = seed
            return bytes([0x67, sub]) + seed
        if sub == SEND_KEY_LEVEL + 1:
            if self.session == Session.DEFAULT:
                return self._nrc(SID.SECURITY_ACCESS, 0x7E)
            if self.unlocked:
                return bytes([0x67, sub])
            if time.monotonic() < self.penalty_until:
                return self._nrc(SID.SECURITY_ACCESS, 0x37)
            if self._pending_seed is None:
                return self._nrc(SID.SECURITY_ACCESS, 0x24)
            if len(data) < 2 + self._algo.key_len:
                return self._nrc(SID.SECURITY_ACCESS, 0x13)
            seed = int.from_bytes(self._pending_seed, "big")
            supplied = int.from_bytes(data[2:2 + self._algo.key_len], "big")
            expected = self._algo.fn(seed, sub)
            if supplied == expected:
                self.unlocked = True
                self.key_attempts = 0
                self._pending_seed = None
                return bytes([0x67, sub])
            self.key_attempts += 1
            if self.key_attempts >= MAX_KEY_ATTEMPTS:
                self.penalty_until = time.monotonic() + PENALTY_SECONDS
                self.key_attempts = 0
                self._pending_seed = None
                return self._nrc(SID.SECURITY_ACCESS, 0x36)
            return self._nrc(SID.SECURITY_ACCESS, 0x35)
        return self._nrc(SID.SECURITY_ACCESS, 0x12)

    def _hdl_tester_present(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.TESTER_PRESENT, 0x13)
        sub = data[1] & 0x7F
        if sub != 0x00:
            return self._nrc(SID.TESTER_PRESENT, 0x12)
        return bytes([0x7E, 0x00])
