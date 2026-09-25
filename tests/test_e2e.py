"""End-to-end tests: UdsClient <-> DemoEcu over a python-can virtual bus."""

from __future__ import annotations

import threading
import time
import uuid

import can
import pytest

from udscope import security
from udscope.simulator import DemoEcu, PENALTY_SECONDS
from udscope.transport import IsotpLink
from udscope.uds import NegativeResponseError, Session, UdsClient


@pytest.fixture()
def pair():
    channel = f"uds-test-{uuid.uuid4().hex[:8]}"
    server_bus = can.Bus(interface="virtual", channel=channel)
    client_bus = can.Bus(interface="virtual", channel=channel)
    server_link = IsotpLink(0x7E8, 0x7E0, bus=server_bus, logger=lambda *a: None)
    client_link = IsotpLink(0x7E0, 0x7E8, bus=client_bus, logger=lambda *a: None)
    ecu = DemoEcu(server_link)
    t = threading.Thread(target=ecu.serve_forever, daemon=True)
    t.start()
    client = UdsClient(client_link, timeout=2.0)
    client_link.start()
    yield client
    ecu.stop()
    client_link.stop()
    server_bus.shutdown()
    client_bus.shutdown()


def test_vin_in_default_session(pair):
    assert pair.read_vin() == "UDSCOPEDEMOECU001"


def test_read_did_gated_by_session(pair):
    with pytest.raises(NegativeResponseError) as exc:
        pair.read_did(0xF22B)
    assert exc.value.nrc == 0x7E
    pair.set_session(Session.EXTENDED)
    resp = pair.read_did(0xF22B)
    assert resp[:3] == bytes([0x62, 0xF2, 0x2B])
    with pytest.raises(NegativeResponseError) as exc:
        pair.read_did(0xF22C)
    assert exc.value.nrc == 0x7E


def test_security_access_success(pair):
    pair.set_session(Session.EXTENDED)
    resp = pair.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
    assert resp[:2] == bytes([0x67, 0x12])


def test_security_access_wrong_key(pair):
    pair.set_session(Session.EXTENDED)
    with pytest.raises(NegativeResponseError) as exc:
        pair.security_access(0x11, lambda seed: 0xDEADBEEF)
    assert exc.value.nrc == 0x35


def test_security_access_penalty_after_three_failures(pair):
    pair.set_session(Session.EXTENDED)
    for _ in range(3):
        with pytest.raises(NegativeResponseError) as exc:
            pair.security_access(0x11, lambda seed: 0xDEADBEEF)
    assert exc.value.nrc in (0x35, 0x36)
    with pytest.raises(NegativeResponseError) as exc:
        pair.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
    assert exc.value.nrc == 0x37


def test_seed_request_denied_in_default_session(pair):
    with pytest.raises(NegativeResponseError) as exc:
        pair.request(bytes([0x27, 0x11]))
    assert exc.value.nrc == 0x7E


def test_developer_session_requires_unlock(pair):
    pair.set_session(Session.EXTENDED)
    with pytest.raises(NegativeResponseError) as exc:
        pair.set_session(Session.DEVELOPER)
    assert exc.value.nrc == 0x33
    pair.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
    resp = pair.set_session(Session.DEVELOPER)
    assert resp[:2] == bytes([0x50, 0x60])


def test_read_by_address_requires_dev_session_and_unlock(pair):
    pair.set_session(Session.EXTENDED)
    with pytest.raises(NegativeResponseError) as exc:
        pair.read_by_address(0x00C0DE00, 16)
    assert exc.value.nrc == 0x7E
    pair.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
    pair.set_session(Session.DEVELOPER)
    blob = pair.read_by_address(0x00C0DE00, 16)
    assert blob.startswith(b"UDSCOPE DEMO FIR")


def test_read_by_address_out_of_range(pair):
    pair.set_session(Session.EXTENDED)
    pair.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
    pair.set_session(Session.DEVELOPER)
    with pytest.raises(NegativeResponseError) as exc:
        pair.read_by_address(0x00D00000, 8)
    assert exc.value.nrc == 0x31


def test_ecu_reset_relocks(pair):
    pair.set_session(Session.EXTENDED)
    pair.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
    pair.ecu_reset()
    time.sleep(0.1)
    with pytest.raises(NegativeResponseError) as exc:
        pair.set_session(Session.DEVELOPER)
    assert exc.value.nrc == 0x33


def test_unknown_service_nrc(pair):
    with pytest.raises(NegativeResponseError) as exc:
        pair.request(bytes([0xA5, 0x00]))
    assert exc.value.nrc == 0x11
    assert "service not supported" in str(exc.value)


def test_s3_timeout_relocks(pair):
    pair.set_session(Session.EXTENDED)
    pair.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
    time.sleep(5.3)
    with pytest.raises(NegativeResponseError) as exc:
        pair.read_did(0xF22B)
    assert exc.value.nrc == 0x7E


def test_sim_address_pair_orientation():
    from udscope.cli import sim_address_pair
    tx, rx = sim_address_pair()
    assert tx == 0x7E8 and rx == 0x7E0


def test_keepalive_holds_session_across_s3(pair):
    pair.set_session(Session.EXTENDED)
    pair.start_keepalive(period=1.0)
    try:
        time.sleep(5.5)
        resp = pair.read_did(0xF22B)
        assert resp[:3] == bytes([0x62, 0xF2, 0x2B])
    finally:
        pair.stop_keepalive()
