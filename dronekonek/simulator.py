"""A swarm in one process: fly N simulated drones against the in-memory broker.

Real enough to catch the bugs that matter (ordering, timeouts, formations,
collision math) on a laptop with no hardware and no broker. The physics is
deliberately dumb: constant speed straight at the target.

    python -m dronekonek.simulator --drones 4 --seconds 30 --formation v
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
import time
from typing import Dict, List, Optional

from dronekonek.formation import formation_slots
from dronekonek.geo import Position, bearing, horizontal_distance, offset_position
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.node import DroneNode
from dronekonek.memory_secure import InMemorySecureTransport
from dronekonek.swarm import CollisionWarning
from dronekonek.transport import InMemoryBroker, InMemoryTransport


def build_swarm(
    count: int = 3,
    swarm_id: str = "sim",
    origin: Optional[Position] = None,
    spacing_m: float = 20.0,
    broadcast_hz: float = 2.0,
    avoidance_enabled: bool = True,
    caution_m: float = 25.0,
    peer_timeout_s: float = 10.0,
    secure: bool = False,
) -> List[DroneNode]:
    """Create N drones sharing one broker, lined up on the ground.

    Default spacing is 20m against a 25m caution radius, so a swarm sitting on
    the pad only ever trips the quiet "caution" tier. Real warnings then mean
    somebody actually converged, which is the whole point of the readout.

    With ``secure=True`` each simulated drone gets its own keypair and a sealed
    transport, so the encryption path is exercised end to end without hardware.
    """
    origin = origin or Position(lat=47.397742, lon=8.545594, alt=0.0)
    broker = InMemoryBroker()
    nodes: List[DroneNode] = []

    key = None
    idents = None
    keyring = None
    if secure:
        from dronekonek.crypto import Identity, Keyring, SwarmKey

        key = SwarmKey.generate(swarm_id)
        idents = {f"drone-{i + 1:02d}": Identity.generate(f"drone-{i + 1:02d}") for i in range(count)}
        keyring = Keyring(allow_tofu=False)
        for drone_id, ident in idents.items():
            keyring.pin(drone_id, ident.public_key_bytes)

    for i in range(count):
        drone_id = f"drone-{i + 1:02d}"
        start = offset_position(origin, north_m=0.0, east_m=i * spacing_m, up_m=0.0)
        link = MockMAVLinkLink(start)
        if secure:
            transport = InMemorySecureTransport(key, idents[drone_id], keyring, broker=broker)
        else:
            transport = InMemoryTransport(broker, swarm_id=swarm_id)
        node = DroneNode(
            drone_id=drone_id,
            swarm_id=swarm_id,
            transport=transport,
            link=link,
            broadcast_hz=broadcast_hz,
            caution_m=caution_m,
            warning_m=caution_m * 0.5,
            critical_m=caution_m * 0.2,
            peer_timeout_s=peer_timeout_s,
            avoidance_enabled=avoidance_enabled,
        )
        nodes.append(node)
    return nodes


def run(
    count: int = 3,
    seconds: float = 30.0,
    formation: Optional[str] = None,
    altitude_m: float = 20.0,
    speed_mps: float = 5.0,
    dt: float = 0.1,
    origin: Optional[Position] = None,
    verbose: bool = True,
    log_path: Optional[str] = None,
    secure: bool = False,
) -> Dict[str, object]:
    """Fly the swarm for ``seconds`` and return a report.

    The steps per iteration are the whole point: move the physics first, then
    let each node broadcast and react, exactly like the real loop but faster.
    """
    origin = origin or Position(lat=47.397742, lon=8.545594, alt=0.0)
    nodes = build_swarm(count=count, origin=origin, secure=secure)
    events: List[Dict[str, object]] = []
    log_file = open(log_path, "w") if log_path else None

    try:
        for node in nodes:
            node.link.takeoff(altitude_m)  # type: ignore[attr-defined]
            node.start()

        # Give everyone a beat to hear the hellos before any order is issued.
        time.sleep(0.2)
        for node in nodes:
            node.broadcast_position()
        for node in nodes:
            node.tick()

        if formation:
            center = offset_position(origin, north_m=60.0, up_m=altitude_m)
            ids = [n.drone_id for n in nodes]
            slots = formation_slots(ids, formation, center, spacing_m=10.0)
            for node in nodes:
                node.link.goto(slots[node.drone_id])  # type: ignore[attr-defined]

        steps = max(1, int(seconds / dt))
        # Track conflict *episodes* rather than one row per tick. A pair that
        # closes and separates is one event with its closest approach, which is
        # what an operator can actually read; the old per-tick dump was noise.
        active: Dict[tuple, Dict[str, object]] = {}
        severity_rank = {"caution": 0, "warning": 1, "critical": 2}

        for step in range(steps):
            for node in nodes:
                node.link.step(dt, speed_mps=speed_mps)  # type: ignore[attr-defined]
            # Publish first, then react: each drone sees the same round of fixes
            # before anybody decides anything, so nobody acts on a half-updated map.
            for node in nodes:
                node.broadcast_position()

            still_conflicting = set()
            for node in nodes:
                warnings = node.tick()
                for w in warnings or []:
                    if w.severity not in ("warning", "critical"):
                        continue
                    key = (node.drone_id, w.other_id)
                    still_conflicting.add(key)
                    rec = active.get(key)
                    if rec is None:
                        active[key] = {
                            "t_start": round(step * dt, 2),
                            "drone": node.drone_id,
                            "with": w.other_id,
                            "min_distance_m": round(w.distance_m, 2),
                            "severity": w.severity,
                        }
                    else:
                        if w.distance_m < rec["min_distance_m"]:
                            rec["min_distance_m"] = round(w.distance_m, 2)
                        if severity_rank[w.severity] > severity_rank[rec["severity"]]:
                            rec["severity"] = w.severity

            # Anything that was conflicting and is not any more is a closed episode.
            for key in [k for k in active if k not in still_conflicting]:
                rec = active.pop(key)
                rec["t_end"] = round(step * dt, 2)
                events.append(rec)

            if verbose and step % max(1, int(1.0 / dt)) == 0:
                print(_status_line(nodes, step * dt))
            if log_file is not None:
                log_file.write(json.dumps({"t": round(step * dt, 2), "swarm": [n.snapshot() for n in nodes]}) + "\n")

        # Conflicts still running when the clock stopped count as episodes too.
        for rec in active.values():
            rec["t_end"] = round(seconds, 2)
            events.append(rec)
        events.sort(key=lambda e: e["min_distance_m"])

        report = {
            "drones": count,
            "seconds": seconds,
            "formation": formation,
            "secure": secure,
            "events": events,
            "final": [n.snapshot() for n in nodes],
            "stats": {n.drone_id: dict(n.stats) for n in nodes},
        }
        return report
    finally:
        for node in nodes:
            node.stop(reason="sim end")
        if log_file is not None:
            log_file.close()


def _status_line(nodes: List[DroneNode], t: float) -> str:
    parts = []
    for n in nodes:
        pos = n.registry.self_position
        peers = len(n.peers())
        alt = f"{pos.alt:.0f}m" if pos else "--"
        parts.append(f"{n.drone_id} alt={alt} peers={peers}")
    return f"t={t:5.1f}s | " + " | ".join(parts)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="dronekonek-sim", description="Simulate a DroneKonek swarm")
    parser.add_argument("--drones", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--formation", choices=["grid", "line", "column", "v", "circle"], default=None)
    parser.add_argument("--altitude", type=float, default=20.0)
    parser.add_argument("--speed", type=float, default=5.0)
    parser.add_argument("--dt", type=float, default=0.1)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--log", default=None, help="write a JSONL trace of every step here")
    parser.add_argument("--json", action="store_true", help="print the final report as JSON")
    parser.add_argument("--secure", action="store_true",
                        help="seal every message end to end (exercises the crypto path)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.ERROR if args.quiet else logging.INFO, format="%(levelname)s %(message)s")

    report = run(
        count=args.drones,
        seconds=args.seconds,
        formation=args.formation,
        altitude_m=args.altitude,
        speed_mps=args.speed,
        dt=args.dt,
        verbose=not args.quiet and not args.json,
        log_path=args.log,
        secure=args.secure,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print()
        mode = "sealed (authenticated encryption)" if report.get("secure") else "plaintext"
        print(f"swarm of {report['drones']} flew {report['seconds']}s [{mode}]")
        print(f"conflict episodes: {len(report['events'])}")
        for ev in report["events"][:10]:
            print(
                f"  {ev['drone']} vs {ev['with']}: closest {ev['min_distance_m']}m "
                f"({ev['severity']}) at t={ev['t_start']}-{ev['t_end']}s"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
