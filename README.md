# DroneKonek

Drones that find each other on WiFi and share coordinates. Each drone broadcasts
its position over MQTT; every drone subscribes to the whole swarm with one
wildcard. On top of that: proximity warnings, collision avoidance, and
leaderless formations. Built for ArduPilot / PX4 on a Raspberry Pi, with the
swarm logic in plain Python so it runs and tests without hardware.

Topics: `dronekonek/v1/<swarm_id>/<type>/<drone_id>`

## Install

    pip install 'dronekonek[all]'     # mqtt + mavlink + crypto + secure

## Quick start (no hardware)

    dronekonek sim --drones 4 --seconds 20 --formation v
    dronekonek sim --drones 4 --seconds 20 --formation v --secure

## Run on real drones

    dronekonek run \
        --id drone-01 --swarm alpha \
        --broker 192.168.1.10 \
        --mavlink /dev/ttyUSB0 --baud 57600 \
        --hz 2 --caution 30

Each aircraft gets its own `--id`. Broker can be a ground station or one drone.
Add `--avoid` only when you want autonomous movement (default is warn-only).

Watch a swarm without flying:

    dronekonek listen --swarm alpha --broker 192.168.1.10

## Secure mode

Seals every message end to end with ChaCha20-Poly1305 and Ed25519. The broker
only ever sees ciphertext on an HMAC-derived topic. An outsider cannot read
coordinates, forge positions, or even enumerate your swarm.

Provision once, on a trusted machine:

    dronekonek keygen --swarm alpha --drones drone-01,drone-02,drone-03

Copy the swarm key to every drone, exactly one identity to its drone:

    dronekonek run --id drone-01 --swarm alpha --secure \
        --key /etc/dronekonek/swarm.key \
        --identity /etc/dronekonek/drone-01.identity \
        --keyring /etc/dronekonek/keyring.json --strict \
        --broker 192.168.1.10 --tls-ca /etc/dronekonek/ca.pem \
        --mavlink /dev/ttyUSB0

Use `--strict` with a keyring for anything real. Without it, a rogue member
holding the swarm key can invent new drone ids.

## IP privacy

Drones talk to a broker, not each other, so drone-to-drone IPs are already
hidden. What was fixed in this build:

- MQTT client_id is now random (`dk-<hex>`), no drone_id or swarm_id embedded.
  The broker and $SYS watchers can no longer tie an IP to a specific drone.
- Both transports support SOCKS5 proxy: `--proxy host:port`. The broker sees
  the proxy's IP, not yours.
- Plaintext topics in non-secure mode leak swarm/drone names to anyone sniffing.
  Use `--secure` for opaque HMAC-derived topics.
- For untrusted WiFi, run a VPN (WireGuard, Tailscale) on each aircraft and
  point `--broker` at the VPN address. The LAN only sees tunnel traffic.

## Autonomous missions

Fly pre-determined waypoints from satellite image analysis. Create a JSON file
with coordinates, pass it to `dronekonek mission`, and the drone flies to each
one, then disarms and shuts down on arrival.

Mission file format (`mission.json`):

    [[47.397742, 8.545594], [47.398000, 8.546000, 30.0]]

Each entry is `[lat, lon]` or `[lat, lon, alt]`. Altitude defaults to 20m.

Run it:

    dronekonek mission \
        --id drone-01 --swarm alpha \
        --broker 192.168.1.10 \
        --mission mission.json \
        --arrival-radius 3.0 --arrival-timeout 120 \
        --mavlink /dev/ttyUSB0

The drone arms, takes off, flies to each waypoint in order, loiters if the
waypoint has a hold time, and disarms when the last one is reached. Press
Ctrl-C to abort; the drone loiters in place.

Use `--secure` with `--key`, `--identity`, and `--keyring --strict` to seal
the mission traffic end to end.

## Safety defaults

- Warn, do not act. Avoidance is opt-in via `--avoid`.
- Never dive. Separation resolves by climbing.
- Never underground. Altitude clamped to zero.
- Geofence respected when configured.
- Clean shutdown publishes goodbye; hard drop uses MQTT last-will.

This is a coordination aid, not a certified collision-avoidance system.

## Tests

    python3 -m unittest discover -s tests -v

130 tests, stdlib unittest. Covers geodesic math, wire format, registry,
formations, collision tiers, avoidance clamping, simulated flights, and the
adversarial crypto cases: tampering, spoofing, replay, key swap, nonce reuse.

## Project layout

    dronekonek/
      geo.py              distance, bearing, geofence (stdlib only)
      messages.py         JSON wire format and MQTT topics
      swarm.py            peer tracking, collision warnings, separation
      formation.py        leaderless formation slots
      mqtt_transport.py   plaintext MQTT link (paho-mqtt)
      secure_transport.py TLS + sealed payloads
      crypto.py           keys, seal/unseal, replay defence
      memory_secure.py    sealed transport, no broker (tests/sim)
      mavlink_link.py     autopilot link (pymavlink) + mock
      node.py             DroneNode: what you run on the Pi
      simulator.py        fly a whole swarm in one process
      cli.py              keygen / run / sim / listen

## License

MIT
