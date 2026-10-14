#!/usr/bin/env python3
"""End-to-end check: two DroneNodes talking over a REAL MQTT broker.

Run with the project venv (needs paho-mqtt for the transport and amqtt for the
broker):

    .venv/bin/python tools/mqtt_e2e_check.py

The in-memory tests prove the swarm logic. This proves the WiFi path: a real
broker on a real socket, paho on both ends, discovery over the wildcard topic.
"""

import asyncio
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.geo import Position, horizontal_distance, offset_position
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.mqtt_transport import MQTTTransport
from dronekonek.node import DroneNode

ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_broker(port: int, ready: threading.Event, stop: threading.Event) -> None:
    """A minimal anonymous MQTT broker in its own thread and event loop.

    amqtt's Broker grabs the running loop in its constructor, so the broker
    object has to be built *inside* the coroutine, not before run_until_complete.
    """
    from amqtt.broker import Broker

    config = {
        "listeners": {"default": {"type": "tcp", "bind": f"127.0.0.1:{port}"}},
        "sys_interval": 0,
        "auth": {"allow-anonymous": True, "plugins": ["auth_anonymous"]},
        "topic-check": {"enabled": False},
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def serve():
        broker = Broker(config)
        await broker.start()
        ready.set()
        while not stop.is_set():
            await asyncio.sleep(0.1)
        await broker.shutdown()

    try:
        loop.run_until_complete(serve())
    except Exception as exc:  # pragma: no cover - surfaces broker startup problems
        print(f"broker error: {exc}")
        ready.set()
    finally:
        loop.close()


def main() -> int:
    port = free_port()
    ready = threading.Event()
    stop = threading.Event()
    t = threading.Thread(target=run_broker, args=(port, ready, stop), daemon=True)
    t.start()
    if not ready.wait(timeout=15):
        print("FAIL: broker never came up")
        return 1
    time.sleep(0.5)
    print(f"broker listening on 127.0.0.1:{port}")

    def make(drone_id: str, start: Position) -> DroneNode:
        return DroneNode(
            drone_id, "e2e",
            transport=MQTTTransport(host="127.0.0.1", port=port, drone_id=drone_id, swarm_id="e2e"),
            link=MockMAVLinkLink(start),
            broadcast_hz=4.0,
            caution_m=30.0,
            on_collision=lambda w: print(f"  !! {w}"),
        )

    alpha = make("alpha", offset_position(ORIGIN, north_m=0.0, up_m=20.0))
    bravo = make("bravo", offset_position(ORIGIN, north_m=200.0, up_m=20.0))

    failures = []
    alpha.start()
    bravo.start()
    print("alpha and bravo online, waiting for discovery over MQTT...")

    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            time.sleep(0.5)
            if alpha.peers() and bravo.peers():
                break

        if not alpha.peers():
            failures.append("alpha never discovered bravo over MQTT")
        if not bravo.peers():
            failures.append("bravo never discovered alpha over MQTT")

        if alpha.peers():
            peer = alpha.peers()[0]
            dist = horizontal_distance(alpha.registry.self_position, peer.position)
            print(f"alpha sees {peer.drone_id} at {dist:.1f}m (expected ~200m)")
            if not (180.0 < dist < 220.0):
                failures.append(f"alpha peer distance {dist:.1f}m is not ~200m")

        # Now fly bravo in and confirm the conflict fires across the broker.
        # 60 x 0.5s at 8 m/s is 240m of travel, comfortably more than the 200m gap.
        seen = []
        alpha.on_collision = lambda w: seen.append(w)
        bravo.link.goto(alpha.registry.self_position)
        for _ in range(60):
            bravo.link.step(0.5, speed_mps=8.0)
            time.sleep(0.05)
        deadline = time.time() + 10
        while time.time() < deadline and not seen:
            time.sleep(0.3)
        if not seen:
            failures.append("no collision warning after bravo closed in over MQTT")
        else:
            print(f"collision warning fired: {seen[0]}")

        # A clean goodbye must remove the peer on the other side.
        bravo.stop(reason="e2e done")
        deadline = time.time() + 10
        while time.time() < deadline and alpha.peers():
            time.sleep(0.3)
        if alpha.peers():
            failures.append("bravo's goodbye did not clear it from alpha's peer list")
        else:
            print("goodbye propagated: alpha's peer list is empty")

        print()
        print(f"alpha stats: {alpha.stats}")
        print(f"bravo stats: {bravo.stats}")
    finally:
        alpha.stop()
        stop.set()
        t.join(timeout=10)

    print()
    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS: real MQTT discovery, position sharing, conflict warning and goodbye all work")
    return 0


if __name__ == "__main__":
    sys.exit(main())
