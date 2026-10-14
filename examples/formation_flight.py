#!/usr/bin/env python3
"""Four drones flying a V formation, driven by a shared coordinate broadcast.

    python examples/formation_flight.py

Every drone computes the same slots from the same membership list, so there is
no leader handing out orders: the formation emerges from the shared state.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.formation import formation_slots
from dronekonek.geo import Position, offset_position
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.node import DroneNode
from dronekonek.transport import InMemoryBroker, InMemoryTransport

ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)
ALT = 25.0
DRONE_IDS = ["drone-01", "drone-02", "drone-03", "drone-04"]


def main() -> None:
    broker = InMemoryBroker()
    nodes = []
    for i, drone_id in enumerate(DRONE_IDS):
        nodes.append(
            DroneNode(
                drone_id, "formation",
                transport=InMemoryTransport(broker),
                link=MockMAVLinkLink(offset_position(ORIGIN, east_m=i * 15.0, up_m=ALT)),
                broadcast_hz=2.0,
                caution_m=25.0,
                on_collision=lambda w: print(f"  !! {w}"),
            )
        )

    for node in nodes:
        node.start()
    time.sleep(0.3)
    for node in nodes:
        node.tick()

    # The rendezvous point every drone is told about in advance.
    center = offset_position(ORIGIN, north_m=120.0, up_m=ALT)
    slots = formation_slots(DRONE_IDS, "v", center, spacing_m=12.0)
    print("V formation targets:")
    for drone_id, slot in slots.items():
        print(f"  {drone_id}: {slot.lat:.6f}, {slot.lon:.6f} alt {slot.alt:.1f}")
    print()

    for node in nodes:
        node.link.goto(slots[node.drone_id])

    try:
        for step in range(30):
            for node in nodes:
                node.link.step(0.4, speed_mps=7.0)
            for node in nodes:
                node.tick()
            time.sleep(0.2)

            worst = None
            for node in nodes:
                near = node.registry.nearest()
                if near and (worst is None or near[1] < worst[1]):
                    worst = near
            gap = f"{worst[1]:.1f}m ({worst[0].drone_id})" if worst else "n/a"
            spread = nodes[0].registry.spread_m()
            print(f"t={step * 0.4:4.1f}s tightest pair {gap:22s} swarm spread {spread:6.1f}m")
    finally:
        for node in nodes:
            node.stop()
        print("\nformation landed")


if __name__ == "__main__":
    main()
