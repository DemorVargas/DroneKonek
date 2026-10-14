#!/usr/bin/env python3
"""Two drones on one machine, trading coordinates. No hardware, no broker.

    python examples/two_drones.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.geo import Position, offset_position
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.node import DroneNode
from dronekonek.transport import InMemoryBroker, InMemoryTransport

ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)


def main() -> None:
    broker = InMemoryBroker()

    alpha = DroneNode(
        "alpha", "demo",
        transport=InMemoryTransport(broker),
        link=MockMAVLinkLink(offset_position(ORIGIN, north_m=0.0)),
        broadcast_hz=2.0,
        on_collision=lambda w: print(f"  !! ALPHA: {w}"),
    )
    bravo = DroneNode(
        "bravo", "demo",
        transport=InMemoryTransport(broker),
        link=MockMAVLinkLink(offset_position(ORIGIN, north_m=80.0)),
        broadcast_hz=2.0,
        on_collision=lambda w: print(f"  !! BRAVO: {w}"),
    )

    alpha.start()
    bravo.start()
    print("two drones online in swarm 'demo'\n")

    # Send bravo in toward alpha, and have alpha hold its ground.
    target = alpha.registry.self_position
    bravo.link.goto(target)
    alpha.link.goto(alpha.registry.self_position)

    try:
        for step in range(20):
            bravo.link.step(0.5, speed_mps=8.0)
            alpha.tick()
            bravo.tick()

            a_pos = alpha.registry.self_position
            b_pos = bravo.registry.self_position
            gap = alpha.registry.nearest()
            gap_txt = f"{gap[1]:.1f}m to {gap[0].drone_id}" if gap else "no peers"
            print(f"t={step * 0.5:4.1f}s alpha sees {len(alpha.peers())} peer(s), nearest {gap_txt}")
            if b_pos:
                print(f"          bravo at {b_pos.lat:.6f},{b_pos.lon:.6f} alt {b_pos.alt:.1f}")
            time.sleep(0.25)
    finally:
        alpha.stop()
        bravo.stop()
        print("\nboth drones offline")


if __name__ == "__main__":
    main()
