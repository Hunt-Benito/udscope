"""udscope command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time

try:
    import readline
except ImportError:
    readline = None

from . import __version__, security
from .simulator import DemoEcu, MEMORY_MAP
from .targets import FUNCTIONAL_REQUEST_ID, STANDARD_ECUs, TARGETS, resolve
from .transport import IsotpLink, make_bus
from .uds import NegativeResponseError, Session, SID, TimeoutError_ as UdsTimeout, UdsClient
from .vcan import MANUAL_INSTRUCTIONS, ensure_vcan


def prepare_bus(args) -> bool:
    ok = ensure_vcan(channel=args.channel, interface=args.bus)
    if not ok:
        print(f"[setup] could not prepare {args.channel}\n" + MANUAL_INSTRUCTIONS.format(
            channel=args.channel), file=sys.stderr)
    return ok


def add_transport_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bus", default="socketcan", help="python-can interface (default: socketcan)")
    parser.add_argument("--channel", default="vcan0", help="CAN channel (default: vcan0)")
    parser.add_argument("--target", default="demo", help="target name or hex request ID (default: demo)")
    parser.add_argument("--txid", type=lambda x: int(x, 0), default=None, help="override request CAN ID")
    parser.add_argument("--rxid", type=lambda x: int(x, 0), default=None, help="override response CAN ID")
    parser.add_argument("--timeout", type=float, default=2.0, help="response timeout in seconds")


def build_client(args) -> UdsClient:
    if not prepare_bus(args):
        sys.exit(2)
    target = resolve(args.target)
    tx_id = args.txid if args.txid is not None else target.tx_id
    rx_id = args.rxid if args.rxid is not None else target.rx_id
    link = IsotpLink(tx_id, rx_id, channel=args.channel, interface=args.bus)
    link.start()
    return UdsClient(link, timeout=args.timeout)


def ascii_repr(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        pad = " " * (3 * (width - len(chunk)))
        lines.append(f"  {off:08X}: {hexpart}{pad}  |{ascii_repr(chunk)}|")
    return "\n".join(lines)


def quiet_logger(direction: str, arb_id: int, data: bytes) -> None:
    pass


def make_sim_link(args) -> IsotpLink:
    return IsotpLink(*sim_address_pair(), channel=args.channel, interface=args.bus)


def sim_address_pair():
    return 0x7E8, 0x7E0


def cmd_setup(args) -> int:
    if args.channel.startswith("vcan") and args.bus == "socketcan":
        if ensure_vcan(channel=args.channel, interface=args.bus):
            print(f"{args.channel} is present and up")
            return 0
        print("could not set up the interface automatically.\n"
              + MANUAL_INSTRUCTIONS.format(channel=args.channel), file=sys.stderr)
        return 1
    print("automatic setup only manages vcan* channels on the socketcan interface —\n"
          f"nothing to do for {args.bus}:{args.channel}", file=sys.stderr)
    return 1


def cmd_sim(args) -> int:
    if not prepare_bus(args):
        return 2
    link = make_sim_link(args)
    ecu = DemoEcu(link)
    print(f"udscope {__version__} — demo ECU on {args.bus}:{args.channel} "
          f"(requests 0x7E0, responses 0x7E8)")
    print("Level 0x11 seed-key algorithm: xor_shift_demo | Ctrl-C to stop")
    try:
        ecu.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping simulator")
    ecu.stop()
    return 0


def cmd_scan(args) -> int:
    if not prepare_bus(args):
        return 2
    bus = make_bus(args.channel, args.bus)
    found = 0
    worst = len(STANDARD_ECUs) * args.timeout
    print(f"probing standard ISO 15765-4 slots on {args.bus}:{args.channel} "
          f"(please wait, up to ~{worst:.0f} s — one timeout per silent slot) ...")
    for target in STANDARD_ECUs:
        print(f"  0x{target.tx_id:03X}/0x{target.rx_id:03X} ", end="", flush=True)
        link = IsotpLink(target.tx_id, target.rx_id, bus=bus, logger=quiet_logger)
        link.start()
        client = UdsClient(link, timeout=args.timeout)
        try:
            resp = client.tester_present()
            print(f"-> responds ({resp.hex(' ')})")
            found += 1
        except (UdsTimeout, NegativeResponseError):
            print("-> no answer")
        finally:
            link.stop()
    print(f"{found} responding address(es)")
    bus.shutdown()
    return 0


def cmd_vin(args) -> int:
    client = build_client(args)
    try:
        print(client.read_vin())
    except (NegativeResponseError, UdsTimeout) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.link.stop()
    return 0


def cmd_ident(args) -> int:
    client = build_client(args)
    dids = {0xF190: "VIN", 0xF187: "Part number", 0xF18A: "ECU ID", 0xF195: "System name"}
    for did, label in dids.items():
        try:
            resp = client.read_did(did)
            value = resp[3:].decode("ascii", errors="replace").strip()
            print(f"  {label:<12} 0x{did:04X}  {value}")
        except (NegativeResponseError, UdsTimeout) as exc:
            print(f"  {label:<12} 0x{did:04X}  [{exc}]")
    client.link.stop()
    return 0


def cmd_session(args) -> int:
    client = build_client(args)
    try:
        resp = client.set_session(args.level)
        print(f"session 0x{args.level:02X} accepted: {resp.hex(' ')}")
    except (NegativeResponseError, UdsTimeout) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.link.stop()
    return 0


def cmd_read_did(args) -> int:
    client = build_client(args)
    try:
        resp = client.read_did(args.did)
        print(f"0x{args.did:04X}: {resp.hex(' ')}  |{ascii_repr(resp)}|")
    except (NegativeResponseError, UdsTimeout) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.link.stop()
    return 0


def cmd_secaccess(args) -> int:
    client = build_client(args)
    algo = security.get(args.algo)
    try:
        client.set_session(Session.EXTENDED)
        resp = client.security_access(0x11, lambda seed: algo.fn(seed, 0x11))
        print(f"security access GRANTED: {resp.hex(' ')}")
        return 0
    except NegativeResponseError as exc:
        print(f"security access DENIED: {exc}")
        return 1
    except UdsTimeout as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        client.link.stop()


HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".config", "udscope", "shell_history")


def _init_readline_history() -> None:
    if readline is None:
        return
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        if os.path.exists(HISTORY_FILE):
            readline.read_history_file(HISTORY_FILE)
    except OSError:
        pass


def _save_readline_history() -> None:
    if readline is None:
        return
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        readline.write_history_file(HISTORY_FILE)
    except OSError:
        pass


def format_history(entries, count=None) -> str:
    shown = entries if count is None else entries[-max(0, count):]
    start = len(entries) - len(shown) + 1
    return "\n".join(f"  {i:4d}  {item}" for i, item in enumerate(shown, start=start))


def cmd_shell(args) -> int:
    client = build_client(args)
    client.start_keepalive()
    _init_readline_history()
    session_history = []
    print(f"udscope {__version__} shell — target {args.target} on {args.bus}:{args.channel}")
    print("type 'help' for commands, raw UDS hex also works, Ctrl-D to quit")
    while True:
        try:
            line = input("udscope> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        session_history.append(line)
        if readline is not None:
            length = readline.get_current_history_length()
            if length == 0 or readline.get_history_item(length) != line:
                readline.add_history(line)
        parts = line.split()
        verb = parts[0].lower()
        rest = parts[1:]
        try:
            if verb in ("quit", "exit"):
                break
            elif verb == "help":
                print(SHELL_HELP)
            elif verb == "keepalive":
                flag = rest[0].lower() if rest else ""
                if flag == "off":
                    client.stop_keepalive()
                    print("keep-alive off — non-default sessions now expire after S3 (5 s)")
                elif flag == "on":
                    client.start_keepalive()
                    print("keep-alive on")
                else:
                    print("usage: keepalive on|off")
            elif verb == "session":
                resp = client.set_session(int(rest[0], 0))
                print(f"session accepted: {resp.hex(' ')}")
            elif verb in ("read-did", "did"):
                did = int(rest[0], 0)
                resp = client.read_did(did)
                print(f"0x{did:04X}: {resp.hex(' ')}  |{ascii_repr(resp)}|")
            elif verb == "vin":
                print(client.read_vin())
            elif verb == "ident":
                for did, label in ((0xF190, "VIN"), (0xF187, "Part number"),
                                   (0xF18A, "ECU ID"), (0xF195, "System name")):
                    try:
                        resp = client.read_did(did)
                        print(f"  {label:<12} 0x{did:04X}  "
                              f"{resp[3:].decode('ascii', errors='replace').strip()}")
                    except (NegativeResponseError, UdsTimeout) as exc:
                        print(f"  {label:<12} 0x{did:04X}  [{exc}]")
            elif verb == "secaccess":
                name = "xor_shift_demo"
                if rest:
                    if rest[0] in ("--algo", "-a"):
                        if len(rest) < 2:
                            print("usage: secaccess [--algo] <name>")
                            continue
                        name = rest[1]
                    else:
                        name = rest[0]
                algo = security.get(name)
                resp = client.security_access(0x11, lambda seed: algo.fn(seed, 0x11))
                print(f"security access GRANTED: {resp.hex(' ')}")
            elif verb == "algorithms":
                for algo in security.list_algorithms():
                    print(f"  {algo.name:<16} {algo.description}")
            elif verb == "history":
                count = None
                if rest:
                    try:
                        count = int(rest[0])
                    except ValueError:
                        print("usage: history [n]")
                        continue
                out = format_history(session_history, count)
                print(out if out else "(no history yet)")
            elif verb == "reset":
                resp = client.ecu_reset()
                print(f"reset accepted: {resp.hex(' ')}")
            else:
                tokens = line.replace(" ", "")
                if len(tokens) % 2 or not all(c in "0123456789abcdefABCDEF" for c in tokens):
                    print(f"unrecognized command or bad hex: {line!r} (try 'help')")
                    continue
                resp = client.request(bytes.fromhex(tokens))
                print(f"-> {resp.hex(' ')}")
        except IndexError:
            print("missing argument (try 'help')")
        except NegativeResponseError as exc:
            print(f"NRC {exc.nrc:02X}: {exc.description}")
        except UdsTimeout as exc:
            print(f"timeout: {exc}")
        except ValueError as exc:
            print(f"error: {exc}")
    client.stop_keepalive()
    client.link.stop()
    _save_readline_history()
    return 0


SHELL_HELP = """commands:
  session <level>       switch diagnostic session (e.g. session 03)
  read-did <did>        read a data identifier (e.g. read-did F190)
  vin                   read the VIN
  ident                 read common identification DIDs
  secaccess [algo]       run the 0x27 seed-key handshake, e.g. secaccess xor_shift_demo
                         (also accepts: secaccess --algo <name>)
  algorithms            list registered seed-key algorithms
  keepalive on|off      background TesterPresent (default: on)
  history [n]           show session command history (last n; up-arrow recalls it,
                       and it persists across sessions in ~/.config/udscope/shell_history)
  reset                 hard-reset the ECU (sessions relock)
  quit                  exit the shell
any other input is sent as raw UDS hex, e.g.:  22 f1 90   or   10 03"""


def cmd_algorithms(args) -> int:
    for algo in security.list_algorithms():
        print(f"  {algo.name:<16} seed={algo.seed_len}B key={algo.key_len}B  {algo.description}")
    return 0


def cmd_sweep_dids(args) -> int:
    client = build_client(args)
    found = 0
    try:
        client.set_session(args.level)
        client.start_keepalive()
        print(f"sweeping DIDs 0x{args.start:04X}-0x{args.end:04X} in session 0x{args.level:02X} "
              f"(Ctrl-C to abort)")
        for did in range(args.start, args.end + 1):
            try:
                resp = client.read_did(did)
            except NegativeResponseError:
                continue
            except UdsTimeout:
                continue
            data = resp[3:]
            print(f"  0x{did:04X}  len={len(data):3d}  {data[:16].hex(' '):<49}  |{ascii_repr(data[:24])}|")
            found += 1
        print(f"{found} DIDs responded")
        return 0
    except KeyboardInterrupt:
        print(f"\naborted, {found} DIDs found so far")
        return 1
    finally:
        client.stop_keepalive()
        client.link.stop()


def cmd_dump(args) -> int:
    client = build_client(args)
    algo = security.get(args.algo)
    try:
        client.set_session(Session.EXTENDED)
        client.security_access(args.seclevel, lambda seed: algo.fn(seed, args.seclevel))
        client.set_session(Session.DEVELOPER)
        client.start_keepalive()
        print(f"dumping 0x{args.start:08X}-0x{args.start + args.length - 1:08X} "
              f"in {args.chunk}-byte chunks -> {args.out}")
        blob = bytearray()
        offset = 0
        while offset < args.length:
            n = min(args.chunk, args.length - offset)
            for attempt in (1, 2):
                try:
                    chunk = client.read_by_address(args.start + offset, n)
                    break
                except UdsTimeout:
                    if attempt == 2:
                        raise
            blob += chunk
            offset += len(chunk)
            if len(chunk) < n:
                print(f"\n  note: ECU returned {len(chunk)} of {n} requested bytes at "
                      f"0x{args.start + offset:08X}")
            done = 100 * offset // args.length
            print(f"\r  {offset}/{args.length} bytes  [{done:3d}%]", end="", flush=True)
        print()
        with open(args.out, "wb") as fh:
            fh.write(blob)
        print(f"wrote {len(blob)} bytes to {args.out}")
        preview = bytes(blob[:128])
        print(hexdump(preview))
        if len(blob) > len(preview):
            print(f"  ... {len(blob) - len(preview)} more bytes in {args.out}")
        return 0
    finally:
        client.stop_keepalive()
        client.link.stop()


def cmd_demo(args) -> int:
    client = build_client(args)
    print(f"== udscope guided demo against {args.bus}:{args.channel} ==")
    try:
        print("\n[1] tester present")
        print("   ", client.tester_present().hex(" "))
        print("\n[2] identification")
        print("    VIN:", client.read_vin())
        print("\n[3] switch to extended session 0x03")
        print("   ", client.set_session(Session.EXTENDED).hex(" "))
        print("\n[4] security access level 0x11 with 'xor_shift_demo'")
        resp = client.security_access(0x11, lambda seed: security.xor_shift_demo(seed, 0x11))
        print("   ", resp.hex(" "), "-> unlocked")
        print("\n[5] enter developer session 0x60")
        print("   ", client.set_session(Session.DEVELOPER).hex(" "))
        demo_address = next(iter(MEMORY_MAP))[0]
        print(f"\n[6] read memory by address 0x{demo_address:08X}, 32 bytes")
        blob = client.read_by_address(demo_address, 32)
        print("   ", blob[:32].decode("ascii", errors="replace"))
        print("\ndemo complete.")
        return 0
    except (NegativeResponseError, UdsTimeout) as exc:
        print(f"\ndemo stopped: {exc}", file=sys.stderr)
        return 1
    finally:
        client.link.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="udscope",
        description="UDS exploration toolkit (ISO 14229 over ISO-TP/CAN)",
    )
    parser.add_argument("--version", action="version", version=f"udscope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("setup", help="verify the vcan interface exists; create it via sudo if missing")
    add_transport_args(p)
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("sim", help="run the demo ECU simulator")
    add_transport_args(p)
    p.set_defaults(func=cmd_sim)

    p = sub.add_parser("scan", help="probe standard diagnostic address slots for responders")
    add_transport_args(p)
    p.set_defaults(func=cmd_scan, timeout=0.5)

    p = sub.add_parser("vin", help="read VIN (DID 0xF190)")
    add_transport_args(p)
    p.set_defaults(func=cmd_vin)

    p = sub.add_parser("ident", help="read common identification DIDs")
    add_transport_args(p)
    p.set_defaults(func=cmd_ident)

    p = sub.add_parser("session", help="switch diagnostic session")
    add_transport_args(p)
    p.add_argument("--level", type=lambda x: int(x, 0), required=True, help="session level, e.g. 0x03")
    p.set_defaults(func=cmd_session)

    p = sub.add_parser("read-did", help="read a data identifier")
    add_transport_args(p)
    p.add_argument("--did", type=lambda x: int(x, 0), required=True, help="DID, e.g. 0xF190")
    p.set_defaults(func=cmd_read_did)

    p = sub.add_parser("secaccess", help="run the 0x27 seed-key handshake")
    add_transport_args(p)
    p.add_argument("--algo", default="xor_shift_demo", help="algorithm name (default: xor_shift_demo)")
    p.add_argument("--level", type=lambda x: int(x, 0), default=0x11, help="send-seed level (default: 0x11)")
    p.set_defaults(func=cmd_secaccess)

    p = sub.add_parser("shell", help="interactive UDS shell (stateful, keep-alive on)")
    add_transport_args(p)
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("algorithms", help="list registered seed-key algorithms")
    p.set_defaults(func=cmd_algorithms)

    p = sub.add_parser("sweep-dids", help="inventory DIDs by probing a range (0x22 sweep)")
    add_transport_args(p)
    p.add_argument("--start", type=lambda x: int(x, 0), default=0xF000, help="first DID (default 0xF000)")
    p.add_argument("--end", type=lambda x: int(x, 0), default=0xF2FF, help="last DID (default 0xF2FF)")
    p.add_argument("--level", type=lambda x: int(x, 0), default=Session.EXTENDED,
                   help="session level for the sweep (default 0x03)")
    p.set_defaults(func=cmd_sweep_dids)

    p = sub.add_parser("dump", help="dump an ECU memory range via ReadMemoryByAddress (0x23)")
    add_transport_args(p)
    p.add_argument("--start", type=lambda x: int(x, 0), required=True, help="start address")
    p.add_argument("--length", type=lambda x: int(x, 0), required=True, help="number of bytes")
    p.add_argument("--chunk", type=lambda x: int(x, 0), default=128, help="bytes per 0x23 request")
    p.add_argument("--out", default="dump.bin", help="output file (default dump.bin)")
    p.add_argument("--seclevel", type=lambda x: int(x, 0), default=0x11,
                   help="security access send-seed level (default 0x11)")
    p.add_argument("--algo", default="xor_shift_demo",
                   help="seed-key algorithm name (default xor_shift_demo)")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("demo", help="guided end-to-end walkthrough (needs `udscope sim` running)")
    add_transport_args(p)
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
