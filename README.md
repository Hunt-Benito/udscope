# udscope

**UDS + scope** — a Linux-first toolkit for exploring **Unified Diagnostic Services (ISO 14229)** over CAN (ISO-TP / ISO 15765-2), with a virtual ECU simulator so every exercise is reproducible **without any hardware**.

udscope is the companion framework of the automotive security article series on [hunt-benito.com/blog](https://www.hunt-benito.com/blog). Each article extends it with the techniques it covers.

> **Ethics & scope**: udscope is built for security research and education on systems **you own or are authorized to test** — bench ECUs, virtual buses, test benches. It contains no vendor security constants and ships only synthetic (or publicly published, cited) seed-key algorithms.

## Features

- **UDS client** — request/response with negative-response (NRC) decoding, `0x78` response-pending handling, and helpers for the services you use most: session control, tester present, read/write DID, security access, read-memory-by-address.
- **ECU simulator** (`udscope sim`) — a synthetic ECU on `vcan0` implementing a realistic UDS subset: session gating (default/extended/developer), security access with attempt limiting and lockout penalty, DID database, memory reads, S3 tester-present timeout.
- **Pluggable seed-key registry** — register `seed -> key` algorithms and use them in the `0x27` handshake. Ships with synthetic exercises; add your own (from papers you are licensed to use) in one function.
- **CLI** — `scan`, `ident`, `vin`, `session`, `read-did`, `secaccess`, `demo`, `algorithms`, `sweep-dids` (DID inventory), `dump` (memory-range dumper via 0x23).
- **Session keep-alive** — optional background TesterPresent so long campaigns survive the S3 timeout on real ECUs.
- **Library** — everything the CLI does is available programmatically (`UdsClient`, `IsotpLink`, `DemoEcu`).

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install git+https://github.com/Hunt-Benito/udscope
```

Requires Python 3.9+, `python-can` and `can-isotp` (installed automatically).

> **Note** — on Debian 12 / Ubuntu 23.04+ the system Python is "externally managed" (PEP 668) and
> `pip install` outside a virtualenv fails with `error: externally-managed-environment`. Use the
> venv as shown above (or `pipx` if you only want the CLI).

## Set up a virtual CAN bus (no hardware needed)

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

## Quickstart (two terminals)

Both terminals must have the venv active (`source .venv/bin/activate` in each).

Terminal 1 — start the demo ECU:

```console
$ source .venv/bin/activate
$ udscope sim
udscope 0.2.0 — demo ECU on socketcan:vcan0 (0x7E0 -> 0x7E8)
Level 0x11 seed-key algorithm: xor_shift_demo | Ctrl-C to stop
```

Terminal 2 — run the guided walkthrough:

```console
$ source .venv/bin/activate
$ udscope demo
== udscope guided demo against socketcan:vcan0 ==
[TX] 7E0  3e 00
[RX] 7E8  7e 00
...VIN: UDSCOPEDEMOECU001
...security access GRANTED
...UDSCOPE DEMO FIRMWARE v0.1 | THI
demo complete.
```

Other commands:

```bash
udscope scan                 # probe ISO 15765-4 slots 0x7E0-0x7E7 for responders
udscope ident                # read common identification DIDs
udscope sweep-dids           # DID inventory over a range (extend of 'sweepDIDs')
udscope dump --start 0x00C0DE00 --length 0x80 --out dump.bin
udscope session --level 0x03
udscope read-did --did 0xF190
udscope secaccess --algo xor_shift_demo
udscope algorithms           # list registered seed-key algorithms
```

Every transport command takes `--bus` / `--channel` (defaults: `socketcan` / `vcan0`) and `--target` (a named target or a raw request ID, e.g. `--target 0x7E1`).

> **Note on the `virtual` bus**: python-can's `virtual` interface is **in-process only** — use it for tests and library experiments, not between two terminals. Across terminals use `vcan0` as shown above.

## Library use

```python
from udscope.transport import IsotpLink
from udscope.uds import Session, UdsClient
from udscope import security

link = IsotpLink(0x7E0, 0x7E8, channel="vcan0")
link.start()
client = UdsClient(link)

print(client.read_vin())
client.set_session(Session.EXTENDED)
client.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
client.set_session(Session.DEVELOPER)
blob = client.read_by_address(0x00080000, 32)
link.stop()
```

### Registering a seed-key algorithm

```python
from udscope.security import SeedKeyAlgorithm, register

def my_algorithm(seed: int, level: int) -> int:
    return ((seed ^ 0xA5A5A5A5) << 3) & 0xFFFFFFFF

register(SeedKeyAlgorithm(
    name="my_algorithm", seed_len=4, key_len=4, fn=my_algorithm,
    description="example registration", origin="your source/citation",
))
```

## Development

```bash
pip install -e ".[test]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
