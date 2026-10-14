"""Cryptography for DroneKonek: confidentiality and authenticity for the swarm.

Threat model this is built against:

* **Passive sniffing.** Somebody on the same WiFi reads the MQTT traffic. Without
  this module they get every drone's coordinates as plain JSON.
* **Injection and spoofing.** Somebody publishes a fake position claiming to be
  one of your drones. A swarm that trusts an unauthenticated position will dodge
  a ghost or fly into a real aircraft. This is the dangerous one.
* **Replay.** A recorded message replayed later drags the swarm off course.
* **Untrusted broker.** The broker is just a machine on the network. It should
  see ciphertext, not coordinates, and it must not be able to read or forge.

Design:

* One 32-byte **swarm key**, provisioned out of band (you physically copy it onto
  each aircraft). It provides confidentiality: only key holders can read or
  produce valid messages.
* A per-drone **Ed25519 identity**, so member A cannot impersonate member B even
  though they share the swarm key. The swarm key proves "someone in the swarm";
  the signature proves "this specific drone".
* **ChaCha20-Poly1305** for the AEAD. Chosen over AES-GCM because it is fast in
  software with no AES hardware requirement, which is what you want on a
  Raspberry Pi.
* **Per-sender keys** derived with HKDF, plus a random per-session nonce prefix
  and a counter. Two senders can never collide nonces, and a restart gets a fresh
  prefix, so a nonce is never reused under the same key. Nonce reuse in a stream
  cipher is catastrophic, so this is the part that has to be right.
* **Opaque topics.** The MQTT topic is an HMAC of the swarm key, so an outsider
  cannot even enumerate your swarm or learn its drone ids from the wire.

Needs the `cryptography` package:  pip install 'dronekonek[crypto]'
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

SCHEME_VERSION = 2
ALG = "CHACHA20POLY1305"
SIGN_ALG = "ED25519"
KEY_BYTES = 32
NONCE_BYTES = 12
SID_BYTES = 8          # random per-session prefix
COUNTER_BYTES = 4      # monotonic within a session; wraps after ~4 billion msgs
SENDER_TAG_BYTES = 8
AAD_SEP = "\x1f"

TOPIC_ROOT_V2 = "dronekonek/v2"
_TOPIC_LABEL = b"dronekonek/topic/v2"
_KEY_LABEL = b"dronekonek/msgkey/v2"
_SENDER_LABEL = b"dronekonek/sender/v2"

# How far a message timestamp may be from local time before it is refused.
DEFAULT_MAX_CLOCK_SKEW_S = 30.0
# How many out-of-order sequence numbers we tolerate per session.
DEFAULT_REPLAY_WINDOW = 64

_KEY_FILE_MODE = 0o600


class CryptoError(Exception):
    """Anything that makes a message untrustworthy."""


class CryptoUnavailable(CryptoError):
    """The `cryptography` package is not installed."""


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
    except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
        raise CryptoUnavailable(
            "secure mode needs the 'cryptography' package.\n"
            "  install it with:  pip install 'dronekonek[crypto]'\n"
            "  or:               pip install cryptography"
        ) from exc


def has_crypto() -> bool:
    """True when the crypto backend is importable. Lets callers degrade safely."""
    try:
        _require_crypto()
        return True
    except CryptoUnavailable:
        return False


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise CryptoError(f"bad base64: {exc}") from exc


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


# ---------------------------------------------------------------------------
# Keys and identities
# ---------------------------------------------------------------------------


@dataclass
class SwarmKey:
    """The shared secret for one swarm. Provision it onto every drone by hand."""

    key: bytes
    swarm_id: str
    created: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if len(self.key) != KEY_BYTES:
            raise CryptoError(f"swarm key must be {KEY_BYTES} bytes, got {len(self.key)}")
        if not self.swarm_id:
            raise CryptoError("swarm_id is required")

    @classmethod
    def generate(cls, swarm_id: str) -> "SwarmKey":
        return cls(key=secrets.token_bytes(KEY_BYTES), swarm_id=swarm_id)

    def to_dict(self) -> dict:
        return {
            "v": SCHEME_VERSION,
            "swarm_id": self.swarm_id,
            "key": b64e(self.key),
            "created": self.created,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "SwarmKey":
        if not isinstance(data, dict) or "key" not in data:
            raise CryptoError("swarm key file is missing a 'key' field")
        swarm_id = data.get("swarm_id")
        if not swarm_id:
            raise CryptoError("swarm key file is missing 'swarm_id'")
        return cls(key=b64d(data["key"]), swarm_id=str(swarm_id), created=float(data.get("created", time.time())))

    @classmethod
    def from_json(cls, text: str) -> "SwarmKey":
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise CryptoError(f"swarm key file is not valid JSON: {exc}") from exc

    def save(self, path: str) -> None:
        """Write the key with owner-only permissions and refuse to leak it."""
        _write_secret(path, self.to_json())

    @classmethod
    def load(cls, path: str) -> "SwarmKey":
        _warn_if_world_readable(path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return cls.from_json(fh.read())
        except FileNotFoundError as exc:
            raise CryptoError(f"swarm key file not found: {path}") from exc

    def sender_tag_for(self, drone_id: str) -> bytes:
        """An opaque, stable handle for a drone id.

        The envelope carries this instead of the drone id, so an eavesdropper who
        knows the topic learns that *a* member is speaking but not which one. It
        is an HMAC of the swarm key, so only key holders can compute or invert it.
        """
        return hmac.new(self.key, _SENDER_LABEL + drone_id.encode(), hashlib.sha256).digest()[:SENDER_TAG_BYTES]

    def message_key_for_tag(self, sender_tag: bytes) -> bytes:
        """Per-sender AEAD key, derived from the opaque tag.

        Deriving from the tag rather than the id is what lets a receiver decrypt
        without the envelope telling it the sender's identity.
        """
        return derive_key(self.key, salt=self.topic_tag_bytes(), info=_KEY_LABEL + b"/" + sender_tag)

    def message_key_for(self, drone_id: str) -> bytes:
        """Per-sender AEAD key from a drone id. Distinct senders get distinct keys."""
        return self.message_key_for_tag(self.sender_tag_for(drone_id))

    def topic_tag_bytes(self) -> bytes:
        return hmac.new(self.key, _TOPIC_LABEL, hashlib.sha256).digest()[:10]

    def topic(self) -> str:
        """The single opaque MQTT topic every drone in this swarm uses."""
        return f"{TOPIC_ROOT_V2}/{_b32(self.topic_tag_bytes())}"

    def topic_filter(self) -> str:
        return self.topic()


def derive_key(master: bytes, *, salt: bytes, info: bytes, length: int = KEY_BYTES) -> bytes:
    """HKDF-SHA256. The right tool for turning one secret into many subkeys."""
    _require_crypto()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(master)


@dataclass
class Identity:
    """A drone's signing keypair. Proves which drone sent a message."""

    drone_id: str
    private_key: object  # ed25519.Ed25519PrivateKey
    created: float = field(default_factory=time.time)

    @classmethod
    def generate(cls, drone_id: str) -> "Identity":
        _require_crypto()
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if not drone_id:
            raise CryptoError("drone_id is required")
        return cls(drone_id=drone_id, private_key=ed25519.Ed25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def to_dict(self) -> dict:
        from cryptography.hazmat.primitives import serialization

        raw = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return {
            "v": SCHEME_VERSION,
            "drone_id": self.drone_id,
            "alg": SIGN_ALG,
            "private": b64e(raw),
            "public": b64e(self.public_key_bytes),
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Identity":
        _require_crypto()
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if not isinstance(data, dict) or "private" not in data:
            raise CryptoError("identity file is missing a 'private' field")
        drone_id = data.get("drone_id")
        if not drone_id:
            raise CryptoError("identity file is missing 'drone_id'")
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64d(data["private"]))
        ident = cls(drone_id=str(drone_id), private_key=priv, created=float(data.get("created", time.time())))
        # Catch a corrupted or swapped identity file now, not at flight time.
        if "public" in data and b64d(data["public"]) != ident.public_key_bytes:
            raise CryptoError("identity file public key does not match its private key")
        return ident

    def save(self, path: str) -> None:
        _write_secret(path, json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str) -> "Identity":
        _warn_if_world_readable(path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return cls.from_dict(json.loads(fh.read()))
        except FileNotFoundError as exc:
            raise CryptoError(f"identity file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise CryptoError(f"identity file is not valid JSON: {exc}") from exc


def _write_secret(path: str, text: str) -> None:
    """Create the file 0600 from the start, never chmod-after-write."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, _KEY_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        raise
    os.chmod(path, _KEY_FILE_MODE)


def _warn_if_world_readable(path: str) -> None:
    """A key anyone can read is not a key. Say so loudly, do not silently pass."""
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        import sys

        print(
            f"WARNING: {path} is readable by other users (mode {oct(mode)}); "
            f"fix it with: chmod 600 {path}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Keyring: which drones are allowed to speak
# ---------------------------------------------------------------------------


class Keyring:
    """Known drone public keys.

    Strict mode (``allow_tofu=False``) is the safe one: only drones whose public
    key you pinned in advance are believed. TOFU is convenient for bringing up a
    swarm but it means anyone holding the swarm key can join under a fresh id,
    so it does not protect you from a rogue member. It does still protect you
    from anyone *without* the swarm key, because they cannot encrypt at all.
    """

    def __init__(self, pinned: Optional[Dict[str, bytes]] = None, allow_tofu: bool = True) -> None:
        self._pinned: Dict[str, bytes] = dict(pinned or {})
        self.allow_tofu = allow_tofu
        self._lock = threading.RLock()
        self.rejected: Dict[str, int] = {}
        # Public keys seen from senders whose id we could not resolve (bare
        # hellos). Recorded so a TOFU swarm still refuses a key swap later.
        self._tag_pinned: Dict[str, bytes] = {}

    @property
    def known(self) -> Dict[str, bytes]:
        with self._lock:
            return dict(self._pinned)

    def get(self, drone_id: str) -> Optional[bytes]:
        with self._lock:
            return self._pinned.get(drone_id)

    def is_known_key(self, public_key: bytes) -> bool:
        """True when this exact key is already trusted, under any label."""
        with self._lock:
            return public_key in self._pinned.values() or public_key in self._tag_pinned.values()

    def pin_tag(self, sender_tag: str, public_key: bytes) -> None:
        """Pin a key that arrived on a payload naming no drone (a bare hello)."""
        with self._lock:
            existing = self._tag_pinned.get(sender_tag)
            if existing is not None and existing != public_key:
                raise CryptoError(f"refusing to repin tag {sender_tag}: a different key is trusted")
            self._tag_pinned[sender_tag] = public_key

    def verify_raw(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature against the key carried in the envelope.

        No identity is involved, so this cannot be fooled by a claimed name: it
        only establishes that the holder of this private key signed this bytes.
        Identity binding happens separately, after decryption.
        """
        _require_crypto()
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            self._reject("<unverified>")
            return False

    def pin(self, drone_id: str, public_key: bytes) -> None:
        with self._lock:
            existing = self._pinned.get(drone_id)
            if existing is not None and existing != public_key:
                raise CryptoError(
                    f"refusing to repin {drone_id}: a different key is already trusted "
                    f"(this is what a key-swap attack looks like)"
                )
            self._pinned[drone_id] = public_key

    def forget(self, drone_id: str) -> None:
        with self._lock:
            self._pinned.pop(drone_id, None)

    def _reject(self, drone_id: str) -> None:
        with self._lock:
            self.rejected[drone_id] = self.rejected.get(drone_id, 0) + 1

    def to_dict(self) -> dict:
        with self._lock:
            return {k: b64e(v) for k, v in sorted(self._pinned.items())}

    @classmethod
    def from_dict(cls, data: dict, allow_tofu: bool = True) -> "Keyring":
        return cls(pinned={k: b64d(v) for k, v in dict(data or {}).items()}, allow_tofu=allow_tofu)

    def save(self, path: str) -> None:
        _write_secret(path, json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str, allow_tofu: bool = True) -> "Keyring":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.loads(fh.read()), allow_tofu=allow_tofu)


# ---------------------------------------------------------------------------
# Sealing and unsealing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Unsealed:
    """A message that passed every check: decrypts, authenticates, and is fresh."""

    sender: str
    swarm_id: str
    sid: str
    seq: int
    timestamp: float
    plaintext: bytes
    verified_identity: bool
    sender_tag: str = ""


def _claimed_drone_id(plaintext: bytes) -> Optional[str]:
    """The drone_id a payload claims, if it names one. None for non-swarm payloads."""
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    claimed = data.get("drone_id")
    return str(claimed) if claimed is not None else None


def _aad(*parts) -> bytes:
    """Canonical associated data. Integers and strings only, no float formatting."""
    return AAD_SEP.join(str(p) for p in parts).encode("utf-8")


class Sealer:
    """Encrypts and signs outgoing messages for one swarm member."""

    def __init__(self, swarm_key: SwarmKey, identity: Identity, max_payload: int = 65536) -> None:
        _require_crypto()
        if identity.drone_id is None:
            raise CryptoError("identity has no drone_id")
        self.swarm_key = swarm_key
        self.identity = identity
        self.max_payload = max_payload
        self._key = swarm_key.message_key_for(identity.drone_id)
        self._tag = swarm_key.sender_tag_for(identity.drone_id)
        self._tag_b64 = b64e(self._tag)
        self._sid = secrets.token_bytes(SID_BYTES)
        self._counter = 0
        self._lock = threading.RLock()

    @property
    def sid(self) -> str:
        return b64e(self._sid)

    @property
    def sender_tag(self) -> str:
        """The opaque handle this sender puts on the wire instead of its id."""
        return self._tag_b64

    @property
    def topic(self) -> str:
        return self.swarm_key.topic()

    def _next_nonce_and_seq(self) -> Tuple[bytes, int]:
        """A nonce is (random session prefix || monotonic counter).

        Unique per key by construction: the prefix is fresh per process, and the
        counter never repeats within a process. This is the invariant the whole
        scheme rests on, so it is computed under a lock and never derived from
        anything an attacker can influence.
        """
        with self._lock:
            self._counter += 1
            seq = self._counter
            if seq >= 2 ** (8 * COUNTER_BYTES):
                raise CryptoError("sequence counter exhausted; restart the process")
        nonce = self._sid + seq.to_bytes(COUNTER_BYTES, "big")
        assert len(nonce) == NONCE_BYTES, "nonce must be 12 bytes"
        return nonce, seq

    def seal(self, plaintext: bytes, *, timestamp: Optional[float] = None) -> bytes:
        """Return the JSON envelope bytes to publish on the swarm topic.

        The envelope carries the sender's *opaque tag*, never its drone id, and
        no swarm name at all: both would hand an eavesdropper the swarm roster.
        """
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        if not isinstance(plaintext, (bytes, bytearray)):
            raise CryptoError("plaintext must be bytes")
        if len(plaintext) > self.max_payload:
            raise CryptoError(f"payload of {len(plaintext)} bytes exceeds the {self.max_payload} limit")

        ts = time.time() if timestamp is None else timestamp
        ts_us = int(round(ts * 1_000_000))
        nonce, seq = self._next_nonce_and_seq()
        sid = b64e(self._sid)
        topic = self.topic
        tag = self._tag_b64

        # The plaintext still names the sender (that is the swarm's own data
        # model); the envelope does not. Binding the tag into the AAD stops a
        # member from re-labelling a captured ciphertext under a different tag.
        header = _aad(SCHEME_VERSION, ALG, tag, sid, seq, ts_us, topic)
        ct = ChaCha20Poly1305(self._key).encrypt(nonce, bytes(plaintext), header)
        signature = self.identity.sign(header + ct)

        envelope = {
            "v": SCHEME_VERSION,
            "alg": ALG,
            "sig_alg": SIGN_ALG,
            "st": tag,
            "sid": sid,
            "seq": seq,
            "ts_us": ts_us,
            "nonce": b64e(nonce),
            "ct": b64e(ct),
            "sig": b64e(signature),
            "pk": b64e(self.identity.public_key_bytes),
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


class Unsealer:
    """Decrypts, authenticates, and de-replays incoming messages."""

    def __init__(
        self,
        swarm_key: SwarmKey,
        keyring: Optional[Keyring] = None,
        *,
        require_signature: bool = True,
        max_clock_skew_s: float = DEFAULT_MAX_CLOCK_SKEW_S,
        replay_window: int = DEFAULT_REPLAY_WINDOW,
        accept_own: bool = False,
    ) -> None:
        _require_crypto()
        self.swarm_key = swarm_key
        self.keyring = keyring if keyring is not None else Keyring()
        self.require_signature = require_signature
        self.max_clock_skew_s = max_clock_skew_s
        self.replay_window = replay_window
        self.accept_own = accept_own
        self._keys: Dict[str, bytes] = {}
        self._seen: Dict[Tuple[str, str], int] = {}  # (sender_tag, sid) -> highest seq
        self._own_id: Optional[str] = None
        self._own_tag: Optional[str] = None
        self._lock = threading.RLock()
        self.stats: Dict[str, int] = {
            "accepted": 0, "bad_format": 0, "decrypt_failed": 0,
            "bad_signature": 0, "replayed": 0, "skewed": 0, "own_echo": 0,
        }

    def bind_own_id(self, drone_id: str) -> None:
        """Tell the unsealer which id is ours so we can drop our own echoes."""
        self._own_id = drone_id
        self._own_tag = b64e(self.swarm_key.sender_tag_for(drone_id))

    def _key_for_tag(self, sender_tag: str) -> bytes:
        with self._lock:
            key = self._keys.get(sender_tag)
            if key is None:
                key = self.swarm_key.message_key_for_tag(b64d(sender_tag))
                self._keys[sender_tag] = key
            return key

    def _check_freshness(self, sender: str, sid: str, seq: int, ts_us: int) -> bool:
        """Refuse replays and messages from a clock that is obviously wrong."""
        now_us = int(time.time() * 1_000_000)
        if abs(now_us - ts_us) > int(self.max_clock_skew_s * 1_000_000):
            self.stats["skewed"] += 1
            return False

        with self._lock:
            key = (sender, sid)
            highest = self._seen.get(key)
            if highest is None:
                self._seen[key] = seq
                return True
            if seq <= highest:
                # Already seen, or an older message replayed. Refuse.
                self.stats["replayed"] += 1
                return False
            if seq > highest + self.replay_window:
                # A jump this large means messages were dropped, not that time
                # went backwards; accept and resync rather than lock the drone out.
                pass
            self._seen[key] = seq
            return True

    def unseal(self, envelope: bytes, *, topic: Optional[str] = None) -> Unsealed:
        """Validate and open an envelope. Raises CryptoError on anything suspect."""
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        if isinstance(envelope, str):
            envelope = envelope.encode("utf-8")
        if not isinstance(envelope, (bytes, bytearray)):
            raise CryptoError("envelope must be bytes")
        try:
            data = json.loads(bytes(envelope).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.stats["bad_format"] += 1
            raise CryptoError(f"envelope is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            self.stats["bad_format"] += 1
            raise CryptoError("envelope is not a JSON object")

        try:
            version = int(data["v"])
            alg = str(data["alg"])
            sender_tag = str(data["st"])
            sid = str(data["sid"])
            seq = int(data["seq"])
            ts_us = int(data["ts_us"])
            nonce = b64d(data["nonce"])
            ct = b64d(data["ct"])
            signature = b64d(data["sig"])
            pubkey = b64d(data["pk"])
        except KeyError as exc:
            self.stats["bad_format"] += 1
            raise CryptoError(f"envelope is missing field {exc}") from exc
        except (TypeError, ValueError) as exc:
            self.stats["bad_format"] += 1
            raise CryptoError(f"envelope field has the wrong type: {exc}") from exc
        except CryptoError:
            self.stats["bad_format"] += 1
            raise

        if version != SCHEME_VERSION:
            self.stats["bad_format"] += 1
            raise CryptoError(f"unsupported scheme version {version}")
        if alg != ALG:
            self.stats["bad_format"] += 1
            raise CryptoError(f"unsupported algorithm {alg!r}")
        if len(nonce) != NONCE_BYTES:
            self.stats["bad_format"] += 1
            raise CryptoError(f"nonce must be {NONCE_BYTES} bytes")
        if topic is not None and topic != self.swarm_key.topic():
            self.stats["decrypt_failed"] += 1
            raise CryptoError("envelope arrived on a topic that is not this swarm's")
        if not self.accept_own and self._own_tag is not None and sender_tag == self._own_tag:
            self.stats["own_echo"] += 1
            raise CryptoError("own echo")

        # Build the associated data exactly once. Both the signature and the AEAD
        # are bound to it, so if these two ever disagree nothing verifies at all.
        header = _aad(version, alg, sender_tag, sid, seq, ts_us, self.swarm_key.topic())

        # 1. Signature over the raw public key. This needs no identity: it just
        #    proves whoever holds that private key produced this ciphertext.
        if self.require_signature:
            if not self.keyring.verify_raw(pubkey, header + ct, signature):
                self.stats["bad_signature"] += 1
                raise CryptoError("signature check failed")

        # 2. Decrypt. The per-sender key comes from the opaque tag, so this needs
        #    no identity either.
        try:
            plaintext = ChaCha20Poly1305(self._key_for_tag(sender_tag)).decrypt(nonce, ct, header)
        except InvalidTag as exc:
            self.stats["decrypt_failed"] += 1
            raise CryptoError("message failed authentication; wrong swarm key or tampered payload") from exc

        # 3. Bind an identity. Only now, with the plaintext in hand, can we say
        #    which drone this is, and the tag must agree with it.
        if self.require_signature:
            sender = self._bind_identity(_claimed_drone_id(plaintext), pubkey, sender_tag)
        else:
            # Unsigned mode cannot authenticate anything. Label by tag so no
            # caller is tempted to trust a claimed id that nobody vouched for.
            sender = sender_tag

        if not self._check_freshness(sender_tag, sid, seq, ts_us):
            raise CryptoError("message is a replay or has a bad timestamp")

        self.stats["accepted"] += 1
        return Unsealed(
            sender=sender,
            swarm_id=self.swarm_key.swarm_id,
            sid=sid,
            seq=seq,
            timestamp=ts_us / 1_000_000.0,
            plaintext=plaintext,
            verified_identity=self.require_signature,
            sender_tag=sender_tag,
        )

    def _bind_identity(self, claimed: Optional[str], pubkey: bytes, sender_tag: str) -> str:
        """Tie an authenticated public key to a drone id, or refuse the message.

        The id comes from the decrypted plaintext, which is only reachable by
        someone holding the swarm key. The opaque tag must match that id, so a
        member cannot relabel a captured ciphertext as another drone.
        """
        if claimed is None:
            # A payload that names no drone (a bare hello) can only be labelled
            # by its tag. There is nothing to bind, so pin the key to the tag.
            if self.keyring.allow_tofu:
                self.keyring.pin_tag(sender_tag, pubkey)
            elif not self.keyring.is_known_key(pubkey):
                raise CryptoError("unidentified sender refused in strict mode")
            return sender_tag

        expected_tag = b64e(self.swarm_key.sender_tag_for(claimed))
        if expected_tag != sender_tag:
            self.stats["bad_signature"] += 1
            raise CryptoError(
                f"sender binding violation: payload claims {claimed!r} but the envelope tag is different"
            )

        known = self.keyring.get(claimed)
        if known is None:
            if not self.keyring.allow_tofu:
                self.stats["bad_signature"] += 1
                raise CryptoError(f"unknown sender {claimed!r} refused in strict mode")
            self.keyring.pin(claimed, pubkey)
        elif known != pubkey:
            self.stats["bad_signature"] += 1
            raise CryptoError(
                f"key swap for {claimed!r}: a different public key is already trusted"
            )
        return claimed


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


def provision(directory: str, swarm_id: str, drone_ids) -> Dict[str, str]:
    """Create a swarm key and one identity per drone. Returns the paths written.

    This is the out-of-band provisioning step: run it once on a trusted machine,
    then copy the swarm key and exactly one identity onto each aircraft.
    """
    os.makedirs(directory, exist_ok=True)
    paths: Dict[str, str] = {}

    key = SwarmKey.generate(swarm_id)
    key_path = os.path.join(directory, "swarm.key")
    key.save(key_path)
    paths["swarm_key"] = key_path

    keyring = Keyring(allow_tofu=False)
    for drone_id in drone_ids:
        ident = Identity.generate(drone_id)
        path = os.path.join(directory, f"{drone_id}.identity")
        ident.save(path)
        paths[drone_id] = path
        keyring.pin(drone_id, ident.public_key_bytes)

    keyring_path = os.path.join(directory, "keyring.json")
    keyring.save(keyring_path)
    paths["keyring"] = keyring_path
    return paths
