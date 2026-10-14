"""Command line entry point: run a real drone on the swarm.

    dronekonek run --id drone-01 --swarm alpha --broker 192.168.1.10
    dronekonek sim --drones 4 --seconds 30 --formation v
    dronekonek listen --swarm alpha --broker 192.168.1.10
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from typing import List, Optional

from dronekonek import __version__


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", dest="drone_id", default="drone-01", help="this drone's unique id")
    parser.add_argument("--swarm", dest="swarm_id", default="swarm", help="swarm name; must match the others")
    parser.add_argument("--broker", default="127.0.0.1", help="MQTT broker host (a drone or the ground station)")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--tls", action="store_true", help="use TLS to the broker")
    parser.add_argument("--tls-ca", default=None, help="CA bundle path for TLS")
    parser.add_argument("--proxy", default=None,
                        help="SOCKS5 proxy (host:port) to hide the drone's real IP from the broker")


def _add_security(parser: argparse.ArgumentParser) -> None:
    """Flags for encrypted mode. Shared by run and listen."""
    g = parser.add_argument_group("security")
    g.add_argument("--secure", action="store_true",
                   help="encrypt and authenticate swarm traffic (needs --key and --identity)")
    g.add_argument("--key", dest="key_path", default=None, help="swarm key file (from 'dronekonek keygen')")
    g.add_argument("--identity", dest="identity_path", default=None, help="this drone's identity file")
    g.add_argument("--keyring", dest="keyring_path", default=None,
                   help="pinned public keys; without it, unknown drones are trusted on first use")
    g.add_argument("--strict", action="store_true",
                   help="only believe drones pinned in the keyring; refuse unknown senders")
    g.add_argument("--insecure-skip-verify", action="store_true",
                   help="do NOT verify the broker's TLS certificate (bench testing only)")
    g.add_argument("--max-clock-skew", type=float, default=30.0,
                   help="seconds of clock drift tolerated before a message is refused")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dronekonek", description="Drones that share coordinates over WiFi")
    parser.add_argument("--version", action="version", version=f"dronekonek {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="fly one real drone on the swarm")
    _add_common(run_p)
    _add_security(run_p)
    run_p.add_argument("--mavlink", default="udp:127.0.0.1:14550", help="autopilot link, e.g. /dev/ttyUSB0 or udp:...")
    run_p.add_argument("--baud", type=int, default=57600)
    run_p.add_argument("--hz", type=float, default=2.0, help="position broadcast rate")
    run_p.add_argument("--caution", type=float, default=30.0, help="meters: start warning")
    run_p.add_argument("--peer-timeout", type=float, default=10.0, help="seconds before a silent peer is dropped")
    run_p.add_argument("--avoid", action="store_true", help="ENABLE autonomous avoidance (default is warn only)")
    run_p.add_argument("--mission", default=None,
                       help="path to a JSON file with waypoints ([[lat,lon], ...] or [[lat,lon,alt], ...])")
    run_p.add_argument("--arrival-radius", type=float, default=3.0,
                       help="meters from waypoint that counts as arrived (default: 3)")
    run_p.add_argument("--arrival-timeout", type=float, default=120.0,
                       help="seconds before aborting an unreachable waypoint (default: 120)")
    run_p.add_argument("--geofence-lat", type=float, default=None)
    run_p.add_argument("--geofence-lon", type=float, default=None)
    run_p.add_argument("--geofence-radius", type=float, default=None, help="meters")

    sim_p = sub.add_parser("sim", help="fly a simulated swarm on one machine")
    sim_p.add_argument("--drones", type=int, default=3)
    sim_p.add_argument("--seconds", type=float, default=30.0)
    sim_p.add_argument("--formation", choices=["grid", "line", "column", "v", "circle"], default=None)
    sim_p.add_argument("--altitude", type=float, default=20.0)
    sim_p.add_argument("--speed", type=float, default=5.0)
    sim_p.add_argument("--quiet", action="store_true", help="only print the final report")
    sim_p.add_argument("--secure", action="store_true",
                       help="seal every message end to end (exercises the crypto path)")
    sim_p.add_argument("--log", default=None, help="write a JSONL trace of every step")
    sim_p.add_argument("--json", action="store_true")

    listen_p = sub.add_parser("listen", help="watch a swarm without flying (ground station)")
    _add_common(listen_p)
    _add_security(listen_p)
    listen_p.add_argument("--interval", type=float, default=2.0, help="seconds between status prints")
    listen_p.add_argument("--count", type=int, default=0, help="stop after N prints (0 = forever)")

    mission_p = sub.add_parser("mission", help="fly a pre-determined mission (autopilot to waypoints)")
    _add_common(mission_p)
    _add_security(mission_p)
    mission_p.add_argument("--mission", required=True,
                           help="path to a JSON file with waypoints ([[lat,lon], ...] or [[lat,lon,alt], ...])")
    mission_p.add_argument("--arrival-radius", type=float, default=3.0,
                           help="meters from waypoint that counts as arrived (default: 3)")
    mission_p.add_argument("--arrival-timeout", type=float, default=120.0,
                           help="seconds before aborting an unreachable waypoint (default: 120)")
    mission_p.add_argument("--mavlink", default="udp:127.0.0.1:14550")
    mission_p.add_argument("--baud", type=int, default=57600)
    mission_p.add_argument("--hz", type=float, default=2.0)
    mission_p.add_argument("--caution", type=float, default=30.0)
    mission_p.add_argument("--peer-timeout", type=float, default=10.0)
    mission_p.add_argument("--avoid", action="store_true")
    mission_p.add_argument("--geofence-lat", type=float, default=None)
    mission_p.add_argument("--geofence-lon", type=float, default=None)
    mission_p.add_argument("--geofence-radius", type=float, default=None)

    key_p = sub.add_parser("keygen", help="provision a swarm key and one identity per drone")
    key_p.add_argument("--swarm", dest="swarm_id", required=True, help="swarm name to provision")
    key_p.add_argument("--drones", required=True,
                       help="comma-separated drone ids, e.g. drone-01,drone-02,drone-03")
    key_p.add_argument("--out", default="keys", help="directory to write keys into (default: keys)")
    key_p.add_argument("--force", action="store_true", help="overwrite an existing key set")

    return parser


def _parse_proxy(proxy_str):
    """Parse a 'host:port' string into (host, port). Returns (None, None) if empty."""
    if not proxy_str:
        return None, None
    if ":" not in proxy_str:
        raise ValueError(f"--proxy must be host:port, got {proxy_str!r}")
    host, port_str = proxy_str.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"--proxy port must be a number, got {port_str!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"--proxy port out of range: {port}")
    return host, port


def _build_transport(args, *, default_port: int = 1883):
    """Build the right transport for the flags given.

    Plaintext mode is the default and stays exactly as it was. Secure mode needs
    a swarm key and an identity, both provisioned by ``dronekonek keygen``, and
    it seals every payload end to end regardless of whether TLS is also in use.
    """
    from dronekonek.crypto import CryptoError, Identity, Keyring, SwarmKey

    proxy_host, proxy_port = _parse_proxy(getattr(args, "proxy", None))

    if not getattr(args, "secure", False):
        from dronekonek.mqtt_transport import MQTTTransport

        return MQTTTransport(
            host=args.broker, port=args.port or default_port, drone_id=args.drone_id, swarm_id=args.swarm_id,
            username=args.username, password=args.password, tls=args.tls, tls_ca=args.tls_ca,
            proxy_addr=proxy_host, proxy_port=proxy_port or 1080,
        )

    if not args.key_path or not args.identity_path:
        raise CryptoError(
            "secure mode needs both --key and --identity.\n"
            "  create them with:  dronekonek keygen --swarm %s --drones %s\n"
            "  then copy the swarm key and ONE identity onto each drone."
            % (args.swarm_id, args.drone_id)
        )

    from dronekonek.secure_transport import secure_transport_for

    swarm_key = SwarmKey.load(args.key_path)
    identity = Identity.load(args.identity_path)

    if identity.drone_id != args.drone_id:
        raise CryptoError(
            f"--id is {args.drone_id!r} but {args.identity_path} belongs to {identity.drone_id!r}.\n"
            f"  An identity is per aircraft; using the wrong one means peers will reject you."
        )
    if swarm_key.swarm_id != args.swarm_id:
        raise CryptoError(
            f"--swarm is {args.swarm_id!r} but the key file is for {swarm_key.swarm_id!r}"
        )

    keyring = Keyring.load(args.keyring_path, allow_tofu=not args.strict) if args.keyring_path else None
    if args.strict and keyring is None:
        raise CryptoError("--strict needs a --keyring to pin the allowed drones")

    # Secure mode speaks TLS by default; port 8883 unless told otherwise.
    port = args.port if args.port != 1883 else 8883
    return secure_transport_for(
        swarm_key, identity,
        keyring=keyring,
        host=args.broker, port=port,
        username=args.username, password=args.password,
        ca_certs=args.tls_ca,
        insecure_skip_verify=args.insecure_skip_verify,
        require_signature=True,
        max_clock_skew_s=args.max_clock_skew,
        qos=1,
        proxy_addr=proxy_host,
        proxy_port=proxy_port or 1080,
    )


def cmd_keygen(args: argparse.Namespace) -> int:
    import os

    from dronekonek.crypto import CryptoError, provision

    drone_ids = [d.strip() for d in args.drones.split(",") if d.strip()]
    if not drone_ids:
        raise CryptoError("--drones needs at least one drone id")
    if len(set(drone_ids)) != len(drone_ids):
        raise CryptoError("--drones contains duplicate ids")

    key_path = os.path.join(args.out, "swarm.key")
    if os.path.exists(key_path) and not args.force:
        raise CryptoError(
            f"{args.out} already holds a key set; refusing to overwrite.\n"
            f"  Re-provisioning invalidates the keys on every drone already deployed.\n"
            f"  Pass --force if that is really what you want."
        )

    paths = provision(args.out, args.swarm_id, drone_ids)

    print(f"provisioned swarm {args.swarm_id!r} in {args.out}/\n")
    print("  swarm key (copy to EVERY drone, keep it secret):")
    print(f"    {paths['swarm_key']}")
    print("\n  identities (copy exactly ONE per drone):")
    for drone_id in drone_ids:
        print(f"    {drone_id:<12} -> {paths[drone_id]}")
    print(f"\n  keyring (pinned public keys): {paths['keyring']}")
    print("\n  Deploy:")
    print(f"    swarm key    -> each drone, e.g. /etc/dronekonek/swarm.key")
    print(f"    identity     -> only the matching drone, e.g. /etc/dronekonek/{drone_ids[0]}.identity")
    print(f"    keyring      -> optional on each drone; use with --strict to refuse unknown senders")
    print("\n  Then run each drone with:")
    print(f"    dronekonek run --id {drone_ids[0]} --swarm {args.swarm_id} --secure \\")
    print(f"        --key /etc/dronekonek/swarm.key --identity /etc/dronekonek/{drone_ids[0]}.identity \\")
    print(f"        --broker <host> --tls-ca <ca.pem>")
    return 0


def _load_mission(path: str):
    """Load waypoints from a JSON file.

    Accepts [[lat, lon], ...] or [[lat, lon, alt], ...]. Returns a list of
    Waypoint objects ready to fly.
    """
    from dronekonek.mission import mission_from_coordinates

    with open(path, "r", encoding="utf-8") as fh:
        coords = json.load(fh)
    if not isinstance(coords, list):
        raise ValueError("mission file must be a JSON array of [lat, lon] or [lat, lon, alt]")
    return mission_from_coordinates(coords)


def cmd_run(args: argparse.Namespace) -> int:
    from dronekonek.geo import Position
    from dronekonek.mavlink_link import MAVLinkLink
    from dronekonek.node import DroneNode

    transport = _build_transport(args)
    link = MAVLinkLink(connection=args.mavlink, baud=args.baud)

    geofence_center = None
    if args.geofence_lat is not None and args.geofence_lon is not None:
        geofence_center = Position(lat=args.geofence_lat, lon=args.geofence_lon, alt=0.0)

    def on_collision(w):
        print(f"!! {w}")

    node = DroneNode(
        drone_id=args.drone_id,
        swarm_id=args.swarm_id,
        transport=transport,
        link=link,
        broadcast_hz=args.hz,
        caution_m=args.caution,
        warning_m=args.caution * 0.5,
        critical_m=args.caution * 0.2,
        peer_timeout_s=args.peer_timeout,
        avoidance_enabled=args.avoid,
        geofence_center=geofence_center,
        geofence_radius_m=args.geofence_radius,
        on_collision=on_collision,
    )

    mission = None
    if args.mission:
        from dronekonek.mission import Mission
        waypoints = _load_mission(args.mission)
        mission = Mission(
            waypoints, link,
            arrival_radius_m=args.arrival_radius,
            arrival_timeout_s=args.arrival_timeout,
            on_waypoint=lambda i, w: print(f"  -> waypoint {i + 1}/{len(waypoints)}: {w.name}"),
            on_complete=lambda r: print(f"mission complete: {r.waypoints_reached}/{r.waypoints_total} waypoints"),
            on_abort=lambda reason: print(f"mission aborted: {reason}"),
        )

    stopping = {"flag": False}

    def handle_signal(signum, frame):
        stopping["flag"] = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    node.start()
    print(f"drone {args.drone_id} online in swarm {args.swarm_id} via {args.broker}:{args.port}")
    if not args.avoid:
        print("avoidance OFF: this drone will warn but never move itself")
    if mission:
        mission.start()
        print(f"mission started: {len(mission.waypoints)} waypoints")
    try:
        while not stopping["flag"]:
            time.sleep(1.0)
            snap = node.snapshot()
            print(json.dumps({k: snap[k] for k in ("drone_id", "peer_count", "collisions")}))
    finally:
        if mission:
            mission.stop("operator shutdown")
        node.stop(reason="operator shutdown")
    return 0


def cmd_sim(args: argparse.Namespace) -> int:
    from dronekonek.simulator import main as sim_main

    argv: List[str] = ["--drones", str(args.drones), "--seconds", str(args.seconds),
                       "--altitude", str(args.altitude), "--speed", str(args.speed)]
    if args.formation:
        argv += ["--formation", args.formation]
    if args.log:
        argv += ["--log", args.log]
    if args.json:
        argv += ["--json"]
    if args.quiet:
        argv += ["--quiet"]
    if getattr(args, "secure", False):
        argv += ["--secure"]
    return sim_main(argv)


def cmd_listen(args: argparse.Namespace) -> int:
    from dronekonek.messages import Message, MessageError
    from dronekonek.swarm import SwarmRegistry

    registry = SwarmRegistry(drone_id="ground-station", swarm_id=args.swarm_id)
    transport = _build_transport(args)

    def on_message(topic: str, payload: bytes) -> None:
        try:
            registry.observe(Message.from_json(payload))
        except MessageError as exc:
            print(f"bad payload: {exc}")

    transport.subscribe_swarm(on_message)
    transport.start()
    print(f"listening on swarm {args.swarm_id} at {args.broker}:{args.port} (ctrl-c to stop)")
    prints = 0
    try:
        while args.count == 0 or prints < args.count:
            time.sleep(args.interval)
            registry.prune()
            print(json.dumps(registry.snapshot(), indent=2))
            prints += 1
    except KeyboardInterrupt:
        pass
    finally:
        transport.stop()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.command == "run":
            return cmd_run(args)
        if args.command == "mission":
            return cmd_run(args)
        if args.command == "sim":
            return cmd_sim(args)
        if args.command == "listen":
            return cmd_listen(args)
        if args.command == "keygen":
            return cmd_keygen(args)
    except ModuleNotFoundError as exc:
        # The network commands need paho-mqtt, the real-drone path needs
        # pymavlink, and secure mode needs cryptography. Say which one and how
        # to get it instead of dumping a traceback at somebody on a flight line.
        missing = (exc.name or "").split(".")[0]
        extras = {
            "paho": ("mqtt", "paho-mqtt"),
            "pymavlink": ("mavlink", "pymavlink"),
            "cryptography": ("crypto", "cryptography"),
        }
        if missing in extras:
            extra, package = extras[missing]
            parser.exit(
                3,
                f"error: {args.command} needs the '{package}' package.\n"
                f"       install it with:  pip install 'dronekonek[{extra}]'\n"
                f"       or:               pip install {package}\n",
            )
        raise
    except Exception as exc:
        # A CryptoError here is a configuration mistake the operator can fix
        # (wrong key file, mismatched identity). Print it, do not traceback.
        from dronekonek.crypto import CryptoError

        if isinstance(exc, CryptoError):
            parser.exit(4, f"error: {exc}\n")
        raise
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
