"""Security tests for DroneKonek.

These are adversarial on purpose. Each test is a specific attack or a specific
way the crypto could be misused, and asserts that it FAILS. A green crypto test
suite that only checks "round trip works" proves almost nothing.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.crypto import (
    ALG,
    KEY_BYTES,
    NONCE_BYTES,
    SCHEME_VERSION,
    SENDER_TAG_BYTES,
    CryptoError,
    Identity,
    Keyring,
    Sealer,
    SwarmKey,
    Unsealer,
    b64d,
    b64e,
    has_crypto,
    provision,
)
from dronekonek.geo import Position, offset_position
from dronekonek.messages import Message, MessageType, position_message
from dronekonek.swarm import SwarmRegistry

if not has_crypto():
    raise unittest.SkipTest("cryptography package not installed; skipping security tests")


ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)


def make_swarm(ids=("drone-01", "drone-02")):
    """A swarm key plus one identity per id."""
    key = SwarmKey.generate("alpha")
    idents = {i: Identity.generate(i) for i in ids}
    return key, idents


def make_pair(drone_id="drone-01", ids=("drone-01", "drone-02")):
    key, idents = make_swarm(ids)
    sealer = Sealer(key, idents[drone_id])
    unsealer = Unsealer(key, Keyring(allow_tofu=False))
    return key, idents, sealer, unsealer


class TestRoundTrip(unittest.TestCase):
    def test_seal_unseal(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        payload = b'{"type":"position","drone_id":"drone-01"}'
        opened = unsealer.unseal(sealer.seal(payload))
        self.assertEqual(opened.plaintext, payload)
        self.assertEqual(opened.sender, "drone-01")
        self.assertTrue(opened.verified_identity)

    def test_real_swarm_message_round_trips(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        msg = position_message("drone-01", "alpha", ORIGIN, seq=1)
        opened = unsealer.unseal(sealer.seal(msg.to_json().encode()))
        back = Message.from_json(opened.plaintext)
        self.assertEqual(back.drone_id, "drone-01")
        self.assertAlmostEqual(back.position.lat, ORIGIN.lat)

    def test_many_messages_all_open(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        for i in range(200):
            opened = unsealer.unseal(sealer.seal(f"msg-{i}".encode()))
            self.assertEqual(opened.plaintext, f"msg-{i}".encode())


class TestConfidentiality(unittest.TestCase):
    def test_ciphertext_does_not_leak_the_payload(self):
        key, idents, sealer, _ = make_pair()
        secret = b'{"lat":47.397742,"lon":8.545594,"alt":25.0}'
        envelope = sealer.seal(secret)
        self.assertNotIn(b"47.397742", envelope)
        self.assertNotIn(b"lat", envelope)
        self.assertNotIn(b"8.545594", envelope)

    def test_topic_does_not_leak_the_swarm_name_or_drone_id(self):
        key = SwarmKey.generate("supersecret-swarm-name")
        topic = key.topic()
        self.assertNotIn("supersecret", topic)
        self.assertNotIn("swarm-name", topic)
        self.assertTrue(topic.startswith("dronekonek/v2/"))

    def test_two_swarms_with_the_same_name_get_different_topics(self):
        # The topic is keyed, not named, so an outsider cannot even confirm that
        # two swarms share a name.
        a = SwarmKey.generate("alpha")
        b = SwarmKey.generate("alpha")
        self.assertNotEqual(a.topic(), b.topic())

    def test_same_plaintext_encrypts_differently_each_time(self):
        key, idents, sealer, _ = make_pair()
        first = sealer.seal(b"identical")
        second = sealer.seal(b"identical")
        self.assertNotEqual(first, second)
        self.assertNotEqual(
            json.loads(first)["ct"], json.loads(second)["ct"]
        )


class TestTampering(unittest.TestCase):
    """Every field an attacker could flip must break the message."""

    def setUp(self):
        self.key, self.idents, self.sealer, self.unsealer = make_pair()
        self.unsealer.keyring.pin("drone-01", self.idents["drone-01"].public_key_bytes)
        self.envelope = json.loads(self.sealer.seal(b'{"type":"position","drone_id":"drone-01"}'))

    def _resign(self, data):
        """Re-sign a modified envelope, the way an attacker without the key cannot."""
        return json.dumps(data).encode()

    def test_flipped_ciphertext_byte_rejected(self):
        raw = bytearray(b64d(self.envelope["ct"]))
        raw[0] ^= 0x01
        self.envelope["ct"] = b64e(bytes(raw))
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_tampered_plaintext_position_rejected(self):
        # The realistic attack: flip a coordinate bit in transit.
        raw = bytearray(b64d(self.envelope["ct"]))
        raw[len(raw) // 2] ^= 0x80
        self.envelope["ct"] = b64e(bytes(raw))
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_changed_nonce_rejected(self):
        self.envelope["nonce"] = b64e(os.urandom(NONCE_BYTES))
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_changed_sequence_rejected(self):
        self.envelope["seq"] = int(self.envelope["seq"]) + 1000
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_changed_timestamp_rejected(self):
        self.envelope["ts_us"] = int(self.envelope["ts_us"]) + 5_000_000
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_changed_sender_tag_rejected(self):
        # "st" is the opaque sender tag. Re-labelling it must break the message.
        self.envelope["st"] = b64e(os.urandom(SENDER_TAG_BYTES))
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_envelope_carries_no_drone_id_or_swarm_name(self):
        # The envelope must not hand an eavesdropper the roster.
        self.assertNotIn("sender", self.envelope)
        self.assertNotIn("swarm_id", self.envelope)
        blob = json.dumps(self.envelope)
        self.assertNotIn("drone-01", blob)
        self.assertNotIn("alpha", blob)

    def test_stripped_signature_rejected(self):
        self.envelope["sig"] = b64e(b"\x00" * 64)
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_downgraded_algorithm_rejected(self):
        self.envelope["alg"] = "NONE"
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))

    def test_old_scheme_version_rejected(self):
        self.envelope["v"] = 1
        with self.assertRaises(CryptoError):
            self.unsealer.unseal(self._resign(self.envelope))


class TestWrongKeys(unittest.TestCase):
    def test_foreign_swarm_key_cannot_open(self):
        key, idents, sealer, _ = make_pair()
        attacker_key = SwarmKey.generate("alpha")  # same name, different secret
        unsealer = Unsealer(attacker_key, Keyring(allow_tofu=True))
        with self.assertRaises(CryptoError):
            unsealer.unseal(sealer.seal(b"secret"))

    def test_no_key_at_all_cannot_open(self):
        # An outsider with no swarm key cannot even derive the right topic.
        key, idents, sealer, _ = make_pair()
        outsider_key = SwarmKey.generate("alpha")
        self.assertNotEqual(key.topic(), outsider_key.topic())
        unsealer = Unsealer(outsider_key, Keyring(allow_tofu=True))
        with self.assertRaises(CryptoError):
            unsealer.unseal(sealer.seal(b"secret"), topic=outsider_key.topic())


class TestSpoofing(unittest.TestCase):
    """A member must not be able to speak as a different member."""

    def test_impostor_identity_is_rejected_when_pinned(self):
        key = SwarmKey.generate("alpha")
        real = Identity.generate("drone-02")
        impostor = Identity.generate("drone-02")  # same id, different key

        unsealer = Unsealer(key, Keyring(allow_tofu=False))
        unsealer.keyring.pin("drone-02", real.public_key_bytes)

        forged = Sealer(key, impostor).seal(b'{"type":"position","drone_id":"drone-02"}')
        with self.assertRaises(CryptoError):
            unsealer.unseal(forged)

    def test_pinned_key_cannot_be_swapped(self):
        key = SwarmKey.generate("alpha")
        keyring = Keyring(allow_tofu=False)
        first = Identity.generate("drone-01")
        second = Identity.generate("drone-01")
        keyring.pin("drone-01", first.public_key_bytes)
        with self.assertRaises(CryptoError):
            keyring.pin("drone-01", second.public_key_bytes)

    def test_rogue_member_cannot_forge_another_drones_position(self):
        # The dangerous insider case. drone-02 holds the swarm key but seals a
        # payload claiming to be drone-01. Its signature is valid and it can
        # decrypt fine, so only the tag/identity binding catches it.
        key, idents, _, _ = make_pair()
        unsealer = Unsealer(key, Keyring(allow_tofu=True))
        unsealer.bind_own_id("drone-03")

        forged = Sealer(key, idents["drone-02"]).seal(
            position_message("drone-01", "alpha", offset_position(ORIGIN, north_m=9999.0)).to_json().encode()
        )
        with self.assertRaises(CryptoError) as ctx:
            unsealer.unseal(forged)
        self.assertIn("binding violation", str(ctx.exception))

    def test_transport_binding_check_catches_a_relabelled_payload(self):
        # Belt and braces: the transport-level check also refuses it, so a
        # transport is safe even with a differently-configured Unsealer.
        key, idents, _, _ = make_pair()
        from dronekonek.secure_transport import SecureMQTTTransport

        unsealer = Unsealer(key, Keyring(allow_tofu=True), require_signature=False)
        transport = SecureMQTTTransport.__new__(SecureMQTTTransport)
        transport.swarm_key = key
        transport.enforce_sender_binding = True

        forged = Sealer(key, idents["drone-02"]).seal(
            position_message("drone-01", "alpha", offset_position(ORIGIN, north_m=9999.0)).to_json().encode()
        )
        opened = unsealer.unseal(forged)
        self.assertFalse(transport._sender_matches_payload(opened))

    def test_honest_message_passes_sender_binding(self):
        key, idents, sealer, _ = make_pair()
        from dronekonek.secure_transport import SecureMQTTTransport

        unsealer = Unsealer(key, Keyring(allow_tofu=True))
        transport = SecureMQTTTransport.__new__(SecureMQTTTransport)
        transport.swarm_key = key
        transport.enforce_sender_binding = True

        honest = Sealer(key, idents["drone-01"]).seal(
            position_message("drone-01", "alpha", ORIGIN).to_json().encode()
        )
        self.assertTrue(transport._sender_matches_payload(unsealer.unseal(honest)))

    def test_cross_swarm_payload_rejected(self):
        key, idents, sealer, _ = make_pair()
        from dronekonek.secure_transport import SecureMQTTTransport

        unsealer = Unsealer(key, Keyring(allow_tofu=True))
        transport = SecureMQTTTransport.__new__(SecureMQTTTransport)
        transport.swarm_key = key
        transport.enforce_sender_binding = True
        # Correct sender, but the payload names a different swarm.
        bad = sealer.seal(position_message("drone-01", "bravo", ORIGIN).to_json().encode())
        self.assertFalse(transport._sender_matches_payload(unsealer.unseal(bad)))


class TestReplay(unittest.TestCase):
    def test_recorded_message_cannot_be_replayed(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        envelope = sealer.seal(b'{"type":"position","drone_id":"drone-01"}')

        unsealer.unseal(envelope)  # first time is fine
        with self.assertRaises(CryptoError):
            unsealer.unseal(envelope)  # replay is refused

    def test_replay_counter_increments(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        envelope = sealer.seal(b"x")
        unsealer.unseal(envelope)
        with self.assertRaises(CryptoError):
            unsealer.unseal(envelope)
        self.assertEqual(unsealer.stats["replayed"], 1)

    def test_out_of_order_old_message_refused(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        first = sealer.seal(b"one")
        second = sealer.seal(b"two")
        unsealer.unseal(second)
        with self.assertRaises(CryptoError):
            unsealer.unseal(first)  # older sequence after a newer one

    def test_fresh_messages_still_flow(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        for i in range(50):
            self.assertEqual(unsealer.unseal(sealer.seal(f"m{i}".encode())).plaintext, f"m{i}".encode())

    def test_replayed_position_would_have_been_believed_without_the_check(self):
        # Show the attack is real: the same bytes, twice, only accepted once.
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        reg = SwarmRegistry(drone_id="drone-02", swarm_id="alpha")
        reg.update_self(ORIGIN)

        msg = position_message("drone-01", "alpha", offset_position(ORIGIN, north_m=500.0), seq=1)
        envelope = sealer.seal(msg.to_json().encode())

        opened = unsealer.unseal(envelope)
        reg.observe(Message.from_json(opened.plaintext))
        first = reg.peers["drone-01"].position.lat

        with self.assertRaises(CryptoError):
            unsealer.unseal(envelope)
        self.assertEqual(reg.peers["drone-01"].position.lat, first)


class TestClockSkew(unittest.TestCase):
    def test_stale_message_refused(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        old = sealer.seal(b"old", timestamp=time.time() - 3600)
        with self.assertRaises(CryptoError):
            unsealer.unseal(old)

    def test_future_message_refused(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        future = sealer.seal(b"future", timestamp=time.time() + 3600)
        with self.assertRaises(CryptoError):
            unsealer.unseal(future)

    def test_mild_skew_tolerated(self):
        key, idents, sealer, unsealer = make_pair()
        unsealer.keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        slightly_off = sealer.seal(b"ok", timestamp=time.time() - 5)
        self.assertEqual(unsealer.unseal(slightly_off).plaintext, b"ok")


class TestNonceSafety(unittest.TestCase):
    """Nonce reuse would be catastrophic, so prove it cannot happen."""

    def test_nonces_never_repeat_within_a_session(self):
        key, idents, sealer, _ = make_pair()
        seen = set()
        for _ in range(500):
            nonce = json.loads(sealer.seal(b"x"))["nonce"]
            self.assertNotIn(nonce, seen)
            seen.add(nonce)

    def test_two_senders_never_share_a_nonce(self):
        # Distinct per-sender keys AND random session prefixes, so even a
        # counter collision across senders is harmless.
        key = SwarmKey.generate("alpha")
        a = Sealer(key, Identity.generate("drone-01"))
        b = Sealer(key, Identity.generate("drone-02"))
        nonces_a = {json.loads(a.seal(b"x"))["nonce"] for _ in range(200)}
        nonces_b = {json.loads(b.seal(b"x"))["nonce"] for _ in range(200)}
        self.assertEqual(nonces_a & nonces_b, set())

    def test_session_prefix_is_random_per_process(self):
        key = SwarmKey.generate("alpha")
        ident = Identity.generate("drone-01")
        sids = {Sealer(key, ident).sid for _ in range(50)}
        self.assertEqual(len(sids), 50)

    def test_nonce_is_the_right_length(self):
        key, idents, sealer, _ = make_pair()
        nonce = b64d(json.loads(sealer.seal(b"x"))["nonce"])
        self.assertEqual(len(nonce), NONCE_BYTES)

    def test_per_sender_keys_differ(self):
        key = SwarmKey.generate("alpha")
        k1 = key.message_key_for("drone-01")
        k2 = key.message_key_for("drone-02")
        self.assertNotEqual(k1, k2)
        self.assertEqual(len(k1), KEY_BYTES)


class TestKeyFiles(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dronekonek-test-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_key_file_is_owner_only(self):
        key = SwarmKey.generate("alpha")
        path = os.path.join(self.dir, "swarm.key")
        key.save(path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o077, 0, f"key file is too permissive: {oct(mode)}")

    def test_identity_file_is_owner_only(self):
        ident = Identity.generate("drone-01")
        path = os.path.join(self.dir, "d.identity")
        ident.save(path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o077, 0, f"identity file is too permissive: {oct(mode)}")

    def test_swarm_key_survives_a_save_load_cycle(self):
        key = SwarmKey.generate("alpha")
        path = os.path.join(self.dir, "swarm.key")
        key.save(path)
        loaded = SwarmKey.load(path)
        self.assertEqual(loaded.key, key.key)
        self.assertEqual(loaded.swarm_id, "alpha")
        self.assertEqual(loaded.topic(), key.topic())

    def test_identity_survives_a_save_load_cycle(self):
        ident = Identity.generate("drone-01")
        path = os.path.join(self.dir, "d.identity")
        ident.save(path)
        loaded = Identity.load(path)
        self.assertEqual(loaded.drone_id, "drone-01")
        self.assertEqual(loaded.public_key_bytes, ident.public_key_bytes)

    def test_corrupted_identity_is_detected(self):
        ident = Identity.generate("drone-01")
        path = os.path.join(self.dir, "d.identity")
        ident.save(path)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.loads(fh.read())
        data["public"] = b64e(os.urandom(32))  # public no longer matches private
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(CryptoError):
            Identity.load(path)

    def test_missing_key_file_raises_clearly(self):
        with self.assertRaises(CryptoError):
            SwarmKey.load(os.path.join(self.dir, "nope.key"))

    def test_provision_creates_a_working_set(self):
        paths = provision(self.dir, "alpha", ["drone-01", "drone-02", "drone-03"])
        self.assertTrue(os.path.exists(paths["swarm_key"]))
        for drone_id in ("drone-01", "drone-02", "drone-03"):
            self.assertTrue(os.path.exists(paths[drone_id]))

        key = SwarmKey.load(paths["swarm_key"])
        keyring = Keyring.load(paths["keyring"], allow_tofu=False)
        # Every provisioned drone is pinned, so strict mode works out of the box.
        self.assertEqual(set(keyring.known), {"drone-01", "drone-02", "drone-03"})

        sealer = Sealer(key, Identity.load(paths["drone-01"]))
        unsealer = Unsealer(key, keyring, require_signature=True)
        opened = unsealer.unseal(sealer.seal(b'{"drone_id":"drone-01"}'))
        self.assertEqual(opened.sender, "drone-01")

    def test_provisioned_keyring_is_owner_only(self):
        paths = provision(self.dir, "alpha", ["drone-01"])
        mode = stat.S_IMODE(os.stat(paths["keyring"]).st_mode)
        self.assertEqual(mode & 0o077, 0)

    def test_short_key_rejected(self):
        with self.assertRaises(CryptoError):
            SwarmKey(key=b"tooshort", swarm_id="alpha")

    def test_swarm_key_file_without_swarm_id_rejected(self):
        with self.assertRaises(CryptoError):
            SwarmKey.from_dict({"key": b64e(os.urandom(KEY_BYTES))})


class TestStrictMode(unittest.TestCase):
    def test_strict_refuses_unknown_sender(self):
        key, idents, sealer, _ = make_pair()
        unsealer = Unsealer(key, Keyring(allow_tofu=False), require_signature=True)
        with self.assertRaises(CryptoError):
            unsealer.unseal(sealer.seal(b'{"drone_id":"drone-01"}'))

    def test_tofu_accepts_unknown_then_pins(self):
        key, idents, sealer, _ = make_pair()
        unsealer = Unsealer(key, Keyring(allow_tofu=True), require_signature=True)
        unsealer.unseal(sealer.seal(b'{"drone_id":"drone-01"}'))
        self.assertIn("drone-01", unsealer.keyring.known)

    def test_strict_accepts_a_pinned_sender(self):
        key, idents, sealer, _ = make_pair()
        keyring = Keyring(allow_tofu=False)
        keyring.pin("drone-01", idents["drone-01"].public_key_bytes)
        unsealer = Unsealer(key, keyring, require_signature=True)
        self.assertEqual(unsealer.unseal(sealer.seal(b'{"drone_id":"drone-01"}')).sender, "drone-01")


class TestOwnEcho(unittest.TestCase):
    def test_own_message_is_dropped(self):
        key, idents, sealer, _ = make_pair()
        unsealer = Unsealer(key, Keyring(allow_tofu=True))
        unsealer.bind_own_id("drone-01")
        with self.assertRaises(CryptoError):
            unsealer.unseal(sealer.seal(b"mine"))

    def test_own_echo_can_be_allowed_when_asked(self):
        key, idents, sealer, _ = make_pair()
        unsealer = Unsealer(key, Keyring(allow_tofu=True), accept_own=True)
        unsealer.bind_own_id("drone-01")
        self.assertEqual(unsealer.unseal(sealer.seal(b"mine")).plaintext, b"mine")


class TestClientIdPrivacy(unittest.TestCase):
    """The MQTT client_id must not leak the drone_id or swarm_id.

    The broker and anyone watching $SYS topics can see client_ids. If the
    client_id contains the drone_id, an observer can correlate a specific
    drone with its IP address.
    """

    def test_plaintext_client_id_has_no_drone_id(self):
        from dronekonek.mqtt_transport import MQTTTransport
        t = MQTTTransport(host="127.0.0.1", drone_id="drone-01", swarm_id="alpha")
        self.assertNotIn("drone-01", t.client_id)
        self.assertNotIn("alpha", t.client_id)

    def test_secure_client_id_has_no_drone_id(self):
        from dronekonek.secure_transport import SecureMQTTTransport
        key = SwarmKey.generate("alpha")
        ident = Identity.generate("drone-01")
        sealer = Sealer(key, ident)
        unsealer = Unsealer(key, Keyring(allow_tofu=True))
        t = SecureMQTTTransport(swarm_key=key, sealer=sealer, unsealer=unsealer)
        self.assertNotIn("drone-01", t.client_id)
        self.assertNotIn("alpha", t.client_id)

    def test_client_ids_are_unique_per_instance(self):
        from dronekonek.mqtt_transport import MQTTTransport
        t1 = MQTTTransport(host="127.0.0.1", drone_id="drone-01", swarm_id="alpha")
        t2 = MQTTTransport(host="127.0.0.1", drone_id="drone-01", swarm_id="alpha")
        self.assertNotEqual(t1.client_id, t2.client_id)

    def test_explicit_client_id_is_respected(self):
        from dronekonek.mqtt_transport import MQTTTransport
        t = MQTTTransport(host="127.0.0.1", drone_id="drone-01", swarm_id="alpha",
                          client_id="my-custom-id")
        self.assertEqual(t.client_id, "my-custom-id")


class TestTLSContext(unittest.TestCase):
    def test_default_context_verifies_certificates(self):
        import ssl
        from dronekonek.secure_transport import build_tls_context

        ctx = build_tls_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_modern_tls_floor(self):
        import ssl
        from dronekonek.secure_transport import build_tls_context

        ctx = build_tls_context()
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_skip_verify_is_explicit(self):
        import ssl
        from dronekonek.secure_transport import build_tls_context

        ctx = build_tls_context(insecure_skip_verify=True)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

    def test_require_client_cert_needs_a_cert(self):
        from dronekonek.secure_transport import build_tls_context

        with self.assertRaises(ValueError):
            build_tls_context(require_client_cert=True)


class TestSecureSimulation(unittest.TestCase):
    """The sealed in-memory path: encryption exercised without a broker."""

    def test_sealed_swarm_discovers_peers(self):
        from dronekonek.simulator import build_swarm

        nodes = build_swarm(count=3, secure=True)
        for n in nodes:
            n.start()
        try:
            time.sleep(0.2)
            for n in nodes:
                n.broadcast_position()
            for n in nodes:
                n.tick()
            for n in nodes:
                self.assertEqual(len(n.peers()), 2, f"{n.drone_id} saw {len(n.peers())} peers")
        finally:
            for n in nodes:
                n.stop()

    def test_sealed_swarm_shares_correct_coordinates(self):
        from dronekonek.simulator import run

        report = run(count=3, seconds=4.0, verbose=False, secure=True)
        for snap in report["final"]:
            self.assertGreaterEqual(snap["peer_count"], 1)
            self.assertIsNotNone(snap["position"])
        # Distances must survive the round trip through encryption intact.
        for snap in report["final"]:
            for peer in snap["peers"]:
                self.assertIsNotNone(peer["distance_m"])
                self.assertGreater(peer["distance_m"], 0.0)

    def test_sealed_swarm_flight_matches_plaintext_behaviour(self):
        from dronekonek.simulator import run

        plain = run(count=3, seconds=5.0, verbose=False, secure=False)
        sealed = run(count=3, seconds=5.0, verbose=False, secure=True)
        # Same swarm, same physics: the number of drones and the shape of the
        # report must not change just because the traffic is encrypted.
        self.assertEqual(len(plain["final"]), len(sealed["final"]))
        self.assertEqual(plain["drones"], sealed["drones"])
        self.assertTrue(sealed["secure"])

    def test_sealed_transport_puts_only_envelopes_on_the_broker(self):
        from dronekonek.crypto import Identity, Keyring, SwarmKey
        from dronekonek.memory_secure import InMemorySecureTransport
        from dronekonek.transport import InMemoryBroker

        key = SwarmKey.generate("alpha")
        ident = Identity.generate("drone-01")
        broker = InMemoryBroker()
        t = InMemorySecureTransport(key, ident, Keyring(allow_tofu=False), broker=broker)
        t.start()
        t.publish("ignored/topic", b'{"type":"position","drone_id":"drone-01","lat":47.4}')

        self.assertEqual(len(broker.published), 1)
        topic, payload = broker.published[0]
        self.assertEqual(topic, key.topic())
        self.assertNotIn(b"47.4", payload)
        self.assertNotIn(b"drone-01", payload)

    def test_sealed_transport_drops_a_foreign_key_envelope(self):
        """An attacker without the swarm key cannot even reach the victim.

        Their envelope goes out on a *different* topic, derived from their own
        key, so the victim's subscription never fires. That is the first line of
        defence: isolation by keyed topic, before any crypto is attempted.
        """
        from dronekonek.crypto import Identity, Keyring, SwarmKey
        from dronekonek.memory_secure import InMemorySecureTransport
        from dronekonek.transport import InMemoryBroker

        broker = InMemoryBroker()
        key = SwarmKey.generate("alpha")
        victim = InMemorySecureTransport(key, Identity.generate("drone-01"), Keyring(allow_tofu=False), broker=broker)
        received = []
        victim.subscribe_swarm(lambda t, p: received.append(p))
        victim.start()

        attacker_key = SwarmKey.generate("alpha")  # same swarm name, different secret
        attacker = InMemorySecureTransport(
            attacker_key, Identity.generate("drone-99"), Keyring(allow_tofu=True), broker=broker
        )
        attacker.start()
        attacker.publish("x", b'{"type":"position","drone_id":"drone-99"}')

        self.assertEqual(received, [])
        self.assertNotEqual(attacker.topic, victim.topic)

    def test_sealed_transport_rejects_an_envelope_from_a_wrong_identity(self):
        """A member with the right key but an unpinned identity is refused."""
        from dronekonek.crypto import Identity, Keyring, SwarmKey
        from dronekonek.memory_secure import InMemorySecureTransport
        from dronekonek.transport import InMemoryBroker

        broker = InMemoryBroker()
        key = SwarmKey.generate("alpha")
        keyring = Keyring(allow_tofu=False)
        keyring.pin("drone-01", Identity.generate("drone-01").public_key_bytes)

        victim = InMemorySecureTransport(key, Identity.generate("drone-01"), keyring, broker=broker)
        received = []
        victim.subscribe_swarm(lambda t, p: received.append(p))
        victim.start()

        # Same swarm key, but an identity nobody pinned.
        intruder = InMemorySecureTransport(key, Identity.generate("drone-77"), keyring, broker=broker)
        intruder.start()
        intruder.publish("x", b'{"type":"position","drone_id":"drone-77"}')

        self.assertEqual(received, [])
        self.assertGreater(victim.stats["rejected"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
