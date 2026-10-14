#!/usr/bin/env python3
"""End-to-end security check: sealed traffic over a REAL TLS MQTT broker.

    .venv/bin/python tools/secure_e2e_check.py

Needs: paho-mqtt, cryptography, amqtt  (pip install paho-mqtt cryptography amqtt)

This climbs past the unit tests. It proves, against a real broker on a real TLS
socket, that:

  1. Two provisioned drones discover each other and share coordinates.
  2. The broker sees ciphertext: no coordinates, no drone ids, no swarm name.
  3. A sniffer subscribed to the raw topic gets nothing usable.
  4. An attacker WITHOUT the swarm key cannot inject a position.
  5. An attacker WITH the swarm key but the WRONG identity is rejected.
  6. A replayed message is refused.
  7. The goodbye handshake still works.
"""

import asyncio
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.crypto import Identity, Keyring, Sealer, SwarmKey, Unsealer, provision
from dronekonek.geo import Position, horizontal_distance, offset_position
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.node import DroneNode
from dronekonek.secure_transport import build_tls_context, secure_transport_for

ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)
CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def ensure_certs(force: bool = False) -> bool:
    """Generate a throwaway CA and broker cert once, into tools/certs/.

    The extensions matter: a CA without basicConstraints/keyUsage is rejected by
    strict verification, which is exactly the failure a sloppy test CA produces.
    """
    ca = os.path.join(CERTS, "ca.pem")
    if not force and os.path.exists(ca) and os.path.exists(os.path.join(CERTS, "broker.pem")):
        return True
    os.makedirs(CERTS, exist_ok=True)

    def write(name: str, text: str) -> str:
        path = os.path.join(CERTS, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    ca_ext = write("ca_ext.cnf", (
        "[v3_ca]\n"
        "basicConstraints = critical, CA:TRUE\n"
        "keyUsage = critical, keyCertSign, cRLSign, digitalSignature\n"
        "subjectKeyIdentifier = hash\n"
    ))
    srv_ext = write("srv_ext.cnf", (
        "[v3_srv]\n"
        "basicConstraints = CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = DNS:localhost, IP:127.0.0.1\n"
    ))

    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", os.path.join(CERTS, "ca.key"), "-out", ca,
             "-days", "3650", "-subj", "/CN=DroneKonek Test CA",
             "-extensions", "v3_ca", "-config", ca_ext],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", os.path.join(CERTS, "broker.key"), "-out", os.path.join(CERTS, "broker.csr"),
             "-subj", "/CN=localhost"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "x509", "-req", "-in", os.path.join(CERTS, "broker.csr"),
             "-CA", ca, "-CAkey", os.path.join(CERTS, "ca.key"), "-CAcreateserial",
             "-out", os.path.join(CERTS, "broker.pem"), "-days", "3650",
             "-extfile", srv_ext, "-extensions", "v3_srv"],
            check=True, capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        detail = getattr(exc, "stderr", b"")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        print(f"could not generate test certificates: {exc} {detail}")
        return False


def run_broker(port: int, ready: threading.Event, stop: threading.Event, failed: list) -> None:
    """Anonymous broker listening on TLS only."""
    from amqtt.broker import Broker

    config = {
        "listeners": {
            "default": {
                "type": "tcp",
                "bind": f"127.0.0.1:{port}",
                "ssl": True,  # amqtt wants a real bool here, not "on"
                "cafile": os.path.join(CERTS, "ca.pem"),
                "certfile": os.path.join(CERTS, "broker.pem"),
                "keyfile": os.path.join(CERTS, "broker.key"),
            }
        },
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
    except Exception as exc:
        # Record the failure and signal readiness anyway, so the caller does not
        # sit on a timeout. The check then fails loudly instead of pretending the
        # broker came up and blaming the drones.
        failed.append(str(exc))
        print(f"broker error: {exc}")
        ready.set()
    finally:
        loop.close()


def raw_sniffer(port: int, topic: str, ca: str, captured: list, stop: threading.Event) -> None:
    """A plain paho client subscribed to the swarm topic, recording raw bytes.

    This is the attacker who can reach the broker but has no swarm key.
    """
    import paho.mqtt.client as mqtt

    def on_connect(client, userdata, flags, rc, properties=None):
        client.subscribe(topic, qos=1)

    def on_message(client, userdata, msg):
        captured.append((msg.topic, bytes(msg.payload)))

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="sniffer")
    client.tls_set_context(build_tls_context(ca_certs=ca))
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect("127.0.0.1", port, keepalive=10)
        client.loop_start()
        while not stop.is_set():
            time.sleep(0.2)
        client.loop_stop()
    except Exception as exc:
        print(f"sniffer error: {exc}")


def main() -> int:
    if not ensure_certs():
        return 1

    ca = os.path.join(CERTS, "ca.pem")
    port = free_port()
    ready = threading.Event()
    stop = threading.Event()
    broker_failed: list = []
    t = threading.Thread(target=run_broker, args=(port, ready, stop, broker_failed), daemon=True)
    t.start()
    if not ready.wait(timeout=20):
        print("FAIL: TLS broker never came up")
        return 1
    if broker_failed:
        print(f"FAIL: TLS broker failed to start: {broker_failed[0]}")
        return 1
    # Prove the port actually accepts a TLS connection before blaming anything else.
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as probe:
            build_tls_context(ca_certs=ca).wrap_socket(probe, server_hostname="localhost").close()
    except Exception as exc:
        print(f"FAIL: could not complete a TLS handshake with the broker: {exc}")
        return 1
    print(f"TLS broker listening and handshaking on 127.0.0.1:{port}")

    workdir = tempfile.mkdtemp(prefix="dronekonek-secure-")
    paths = provision(workdir, "alpha", ["drone-01", "drone-02"])
    key = SwarmKey.load(paths["swarm_key"])
    keyring = Keyring.load(paths["keyring"], allow_tofu=False)
    print(f"provisioned swarm 'alpha' with 2 drones in {workdir}")
    print(f"opaque swarm topic: {key.topic()}\n")

    failures = []

    # --- the sniffer, subscribed to the real topic with no swarm key ---------
    captured: list = []
    sniffer_stop = threading.Event()
    sn = threading.Thread(target=raw_sniffer, args=(port, key.topic(), ca, captured, sniffer_stop), daemon=True)
    sn.start()
    time.sleep(1.0)

    def make(drone_id: str, start: Position) -> DroneNode:
        return DroneNode(
            drone_id, "alpha",
            transport=secure_transport_for(
                key, Identity.load(paths[drone_id]),
                keyring=Keyring.load(paths["keyring"], allow_tofu=False),
                host="127.0.0.1", port=port, ca_certs=ca, qos=1,
            ),
            link=MockMAVLinkLink(start),
            broadcast_hz=4.0,
            caution_m=30.0,
        )

    alpha = make("drone-01", offset_position(ORIGIN, north_m=0.0, up_m=20.0))
    bravo = make("drone-02", offset_position(ORIGIN, north_m=200.0, up_m=20.0))

    alpha.start()
    bravo.start()
    print("two secure drones online over TLS...")

    try:
        # --- 1. discovery over sealed TLS traffic ---------------------------
        deadline = time.time() + 25
        while time.time() < deadline:
            time.sleep(0.5)
            if alpha.peers() and bravo.peers():
                break
        if alpha.peers() and bravo.peers():
            peer = alpha.peers()[0]
            dist = horizontal_distance(alpha.registry.self_position, peer.position)
            print(f"[1] PASS discovery: drone-01 sees {peer.drone_id} at {dist:.1f}m")
            if not (180.0 < dist < 220.0):
                failures.append(f"peer distance {dist:.1f}m is not ~200m")
        else:
            failures.append("secure discovery failed")
            print("[1] FAIL discovery")

        # --- 2 & 3. what the broker and the sniffer can see -----------------
        time.sleep(1.5)
        if not captured:
            failures.append("sniffer captured nothing; the check proved nothing")
            print("[2] FAIL sniffer saw no traffic (check is meaningless)")
        else:
            blob = b"".join(p for _t, p in captured)
            leaks = []
            # Only ASCII needles: a base64 ciphertext can randomly contain any
            # short byte string, so short needles would be false positives.
            for needle, what in [
                (b"47.397742", "latitude"),
                (b"8.545594", "longitude"),
                (b"drone-01", "drone id"),
                (b"drone-02", "drone id"),
                (b"alpha", "swarm name"),
                (b"position", "message type"),
                (b"swarm_id", "field name"),
            ]:
                if needle in blob:
                    leaks.append(what)
            print(f"[2] sniffer captured {len(captured)} messages, {len(blob)} bytes on the wire")
            if leaks:
                failures.append(f"sniffer could read: {', '.join(sorted(set(leaks)))}")
                print(f"[2] FAIL leaked {sorted(set(leaks))}")
            else:
                print("[2] PASS ciphertext only: no coordinates, ids, or swarm name on the wire")

            # And confirm the captured bytes really are sealed envelopes.
            try:
                sample = json.loads(captured[0][1])
                sealed = all(k in sample for k in ("ct", "nonce", "sig", "st"))
                print(f"[3] PASS captured payload is a sealed envelope: {sealed}")
                if not sealed:
                    failures.append("captured payload is not a sealed envelope")
            except Exception as exc:
                failures.append(f"captured payload is not an envelope: {exc}")

            # The sniffer's Unsealer with no key must not open anything.
            from dronekonek.crypto import CryptoError as _CE
            outsider = Unsealer(SwarmKey.generate("alpha"), Keyring(allow_tofu=True))
            opened_any = 0
            for _t, payload in captured:
                try:
                    outsider.unseal(payload)
                    opened_any += 1
                except _CE:
                    pass
            print(f"[3] outsider with a different key opened {opened_any}/{len(captured)} messages")
            if opened_any:
                failures.append("an outsider without the swarm key opened sealed traffic")

        # --- 4. attacker with NO swarm key cannot inject ---------------------
        from dronekonek.crypto import CryptoError

        rogue_key = SwarmKey.generate("alpha")
        rogue_sealer = Sealer(rogue_key, Identity.generate("drone-03"))
        injected = rogue_sealer.seal(
            __import__("dronekonek.messages", fromlist=["position_message"])
            .position_message("drone-03", "alpha", offset_position(ORIGIN, north_m=9999.0)).to_json().encode()
        )
        try:
            alpha.transport.unsealer.unseal(injected, topic=key.topic())
            failures.append("injection with a foreign key was accepted")
            print("[4] FAIL foreign-key injection accepted")
        except CryptoError as exc:
            print(f"[4] PASS foreign-key injection refused ({type(exc).__name__})")

        # --- 5. attacker WITH the swarm key but wrong identity ---------------
        impostor = Sealer(key, Identity.generate("drone-02"))
        forged = impostor.seal(
            __import__("dronekonek.messages", fromlist=["position_message"])
            .position_message("drone-02", "alpha", offset_position(ORIGIN, north_m=9999.0)).to_json().encode()
        )
        try:
            alpha.transport.unsealer.unseal(forged, topic=key.topic())
            failures.append("impostor identity was accepted in strict mode")
            print("[5] FAIL impostor identity accepted")
        except CryptoError as exc:
            print(f"[5] PASS impostor identity refused in strict mode ({type(exc).__name__})")

        # --- 5b. rogue MEMBER forging another drone's position ---------------
        # drone-02 is a real member with a real identity, but it lies about being
        # drone-01. Only the sender-binding check catches this.
        legit = Sealer(key, Identity.load(paths["drone-02"]))
        lying = legit.seal(
            __import__("dronekonek.messages", fromlist=["position_message"])
            .position_message("drone-01", "alpha", offset_position(ORIGIN, north_m=8888.0)).to_json().encode()
        )
        # The binding check now lives inside unseal, so a forged payload is
        # refused at the door rather than handed on to be checked later.
        try:
            opened = alpha.transport.unsealer.unseal(lying, topic=key.topic())
            bound = alpha.transport._sender_matches_payload(opened)
            print(f"[5b] rogue member's forged position passed the binding check: {bound}")
            if bound:
                failures.append("a member forged another drone's position and it passed")
            else:
                print("[5b] PASS transport binding refused the forged position")
        except CryptoError as exc:
            print(f"[5b] PASS rogue member's forged position refused at unseal ({exc})")

        # --- 6. replay -------------------------------------------------------
        real = Sealer(key, Identity.load(paths["drone-02"]))
        one = real.seal(
            __import__("dronekonek.messages", fromlist=["position_message"])
            .position_message("drone-02", "alpha", ORIGIN).to_json().encode()
        )
        alpha.transport.unsealer.unseal(one, topic=key.topic())
        try:
            alpha.transport.unsealer.unseal(one, topic=key.topic())
            failures.append("a replayed message was accepted")
            print("[6] FAIL replay accepted")
        except CryptoError:
            print("[6] PASS replay refused")

        # --- 7. goodbye ------------------------------------------------------
        bravo.stop(reason="e2e done")
        deadline = time.time() + 12
        while time.time() < deadline and alpha.peers():
            time.sleep(0.3)
        if alpha.peers():
            failures.append("sealed goodbye did not clear the peer")
            print("[7] FAIL goodbye")
        else:
            print("[7] PASS sealed goodbye propagated")

        print()
        print(f"alpha transport stats: {alpha.transport.stats}")
        print(f"alpha unsealer stats:  {alpha.transport.unsealer.stats}")
    finally:
        alpha.stop()
        sniffer_stop.set()
        stop.set()
        t.join(timeout=10)

    print()
    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS: sealed traffic over TLS; broker and sniffer see ciphertext only;")
    print("      foreign keys, impostor identities, forged positions and replays all refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
