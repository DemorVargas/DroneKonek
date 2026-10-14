#!/usr/bin/env python3
"""Two drones sharing coordinates with everything sealed end to end.

    python examples/secure_swarm.py

No broker, no hardware, no files to copy: this generates a swarm key and two
identities in memory, then flies the pair and shows you what an eavesdropper
sitting on the same network would actually see (ciphertext, and nothing else).

Needs the cryptography package:  pip install 'dronekonek[crypto]'
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.crypto import CryptoError, Identity, Keyring, SwarmKey
from dronekonek.geo import Position, offset_position
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.memory_secure import InMemorySecureTransport
from dronekonek.node import DroneNode
from dronekonek.transport import InMemoryBroker

ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)


def main() -> int:
    # --- provisioning (in real life: dronekonek keygen, copied onto each drone)
    swarm_id = "demo"
    key = SwarmKey.generate(swarm_id)
    ident_a = Identity.generate("alpha")
    ident_b = Identity.generate("bravo")
    keyring = Keyring(allow_tofu=False)  # strict: only these two are believed
    keyring.pin("alpha", ident_a.public_key_bytes)
    keyring.pin("bravo", ident_b.public_key_bytes)

    print(f"swarm:  {swarm_id}")
    print(f"topic:  {key.topic()}   <- an HMAC of the key, not the name")
    print(f"alpha tag: {key.sender_tag_for('alpha').hex()[:16]}...  <- what the wire shows")
    print()

    broker = InMemoryBroker()

    alpha = DroneNode(
        "alpha", swarm_id,
        transport=InMemorySecureTransport(key, ident_a, keyring, broker=broker),
        link=MockMAVLinkLink(offset_position(ORIGIN, north_m=0.0, up_m=20.0)),
        broadcast_hz=2.0,
        on_collision=lambda w: print(f"  !! ALPHA: {w}"),
    )
    bravo = DroneNode(
        "bravo", swarm_id,
        transport=InMemorySecureTransport(key, ident_b, keyring, broker=broker),
        link=MockMAVLinkLink(offset_position(ORIGIN, north_m=90.0, up_m=20.0)),
        broadcast_hz=2.0,
        on_collision=lambda w: print(f"  !! BRAVO: {w}"),
    )

    alpha.start()
    bravo.start()
    print("both drones online; every message is sealed\n")

    # Bravo closes in on alpha so you can watch a warning cross the sealed link.
    bravo.link.goto(alpha.registry.self_position)

    try:
        for step in range(16):
            bravo.link.step(0.5, speed_mps=8.0)
            alpha.tick()
            bravo.tick()

            gap = alpha.registry.nearest()
            gap_txt = f"{gap[1]:.1f}m to {gap[0].drone_id}" if gap else "no peers"
            print(f"t={step * 0.5:4.1f}s alpha sees {len(alpha.peers())} peer(s), nearest {gap_txt}")
            time.sleep(0.25)

        print("\n--- what an eavesdropper on this network captured ---")
        for topic, payload in broker.published[-2:]:
            preview = payload[:150].decode("utf-8", "replace")
            print(f"topic: {topic}")
            print(f"bytes: {preview}{'...' if len(payload) > 150 else ''}")
        print("\nNo coordinates. No drone ids. No swarm name. Just sealed envelopes.")

        # Show a foreign key being refused, using a third party's own key.
        print("\n--- an outsider with a different swarm key tries to speak ---")
        before = dict(alpha.transport.stats)
        outsider_key = SwarmKey.generate(swarm_id)
        outsider = InMemorySecureTransport(
            outsider_key, Identity.generate("intruder"), Keyring(allow_tofu=True), broker=broker
        )
        outsider.start()
        outsider.publish("x", b'{"type":"position","drone_id":"intruder","position":{"lat":0,"lon":0}}')
        # Its envelope goes out on a different keyed topic, so alpha's
        # subscription never even fires: it is isolated before any crypto runs.
        new_rejections = alpha.transport.stats["rejected"] - before["rejected"]
        print(f"alpha received it at all: {'yes' if new_rejections else 'no'}")
        print(f"alpha's topic: {alpha.transport.topic}")
        print(f"outsider's topic: {outsider.topic}  <- different, so it never arrives")

        # And a member trying to forge another member's position.
        print("\n--- a real member tries to forge the other drone's position ---")
        from dronekonek.crypto import Sealer
        from dronekonek.messages import position_message

        lying = Sealer(key, ident_b).seal(
            position_message("alpha", swarm_id, offset_position(ORIGIN, north_m=9999.0)).to_json().encode()
        )
        try:
            alpha.transport.unsealer.unseal(lying, topic=key.topic())
            print("  !! forge was accepted, which is a bug")
        except CryptoError as exc:
            print(f"  refused: {exc}")
    finally:
        alpha.stop()
        bravo.stop()
        print("\nboth drones offline")

    return 0


if __name__ == "__main__":
    sys.exit(main())
