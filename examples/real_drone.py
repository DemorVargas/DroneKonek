#!/usr/bin/env python3
"""A real-drone runner skeleton: wire a Pixhawk and an MQTT broker to a node.

    python examples/real_drone.py --id drone-01 --swarm alpha --broker 192.168.1.10 \
        --mavlink /dev/ttyUSB0 --baud 57600 --caution 30

This is the file to copy onto the Raspberry Pi. It starts the node, prints a
status line, and shuts down cleanly on ctrl-c so the drone publishes a goodbye
instead of just vanishing off the network.
"""

import argparse
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.geo import Position
from dronekonek.mavlink_link import MAVLinkLink
from dronekonek.mqtt_transport import MQTTTransport
from dronekonek.node import DroneNode


def main() -> int:
    ap = argparse.ArgumentParser(description="Run one DroneKonek drone on real hardware")
    ap.add_argument("--id", dest="drone_id", required=True)
    ap.add_argument("--swarm", dest="swarm_id", default="alpha")
    ap.add_argument("--broker", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--username", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--mavlink", default="udp:127.0.0.1:14550")
    ap.add_argument("--baud", type=int, default=57600)
    ap.add_argument("--hz", type=float, default=2.0)
    ap.add_argument("--caution", type=float, default=30.0)
    ap.add_argument("--avoid", action="store_true", help="let the drone move itself out of a conflict")
    ap.add_argument("--geofence-lat", type=float, default=None)
    ap.add_argument("--geofence-lon", type=float, default=None)
    ap.add_argument("--geofence-radius", type=float, default=None)
    ap.add_argument("--status-every", type=float, default=3.0)
    args = ap.parse_args()

    transport = MQTTTransport(
        host=args.broker, port=args.port, drone_id=args.drone_id, swarm_id=args.swarm_id,
        username=args.username, password=args.password,
    )
    link = MAVLinkLink(connection=args.mavlink, baud=args.baud)

    geofence = None
    if args.geofence_lat is not None and args.geofence_lon is not None:
        geofence = Position(lat=args.geofence_lat, lon=args.geofence_lon, alt=0.0)

    node = DroneNode(
        drone_id=args.drone_id,
        swarm_id=args.swarm_id,
        transport=transport,
        link=link,
        broadcast_hz=args.hz,
        caution_m=args.caution,
        warning_m=args.caution * 0.5,
        critical_m=args.caution * 0.2,
        avoidance_enabled=args.avoid,
        geofence_center=geofence,
        geofence_radius_m=args.geofence_radius,
        on_collision=lambda w: print(f"!! CONFLICT: {w}"),
        on_peer=lambda pid, pos: print(f"++ peer {pid} at {pos.lat:.6f},{pos.lon:.6f} alt {pos.alt:.1f}"),
    )

    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))

    node.start()
    print(f"{args.drone_id} online in swarm {args.swarm_id}; avoidance {'ON' if args.avoid else 'OFF'}")

    last_status = 0.0
    try:
        while not stop["flag"]:
            time.sleep(0.5)
            if time.time() - last_status >= args.status_every:
                last_status = time.time()
                print(json.dumps(node.snapshot()))
    finally:
        node.stop(reason="operator shutdown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
