"""An in-memory transport that seals every payload.

Same guarantees as the MQTT secure transport (sealed, signed, replay-checked)
but with no socket and no broker, so the encrypted path is exercisable in the
simulator and in the unit tests on a bare machine.

The broker only ever holds envelopes, exactly like the real one.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional, Tuple

from dronekonek.crypto import CryptoError, Identity, Keyring, Sealer, SwarmKey, Unsealer
from dronekonek.transport import Handler, InMemoryBroker, Transport

log = logging.getLogger("dronekonek.memory_secure")


class InMemorySecureTransport(Transport):
    """Seals on publish, opens on delivery, drops anything that fails."""

    def __init__(
        self,
        swarm_key: SwarmKey,
        identity: Identity,
        keyring: Optional[Keyring] = None,
        broker: Optional[InMemoryBroker] = None,
        enforce_sender_binding: bool = True,
    ) -> None:
        self.swarm_key = swarm_key
        self.identity = identity
        self.broker = broker if broker is not None else InMemoryBroker()
        self.sealer = Sealer(swarm_key, identity)
        self.unsealer = Unsealer(
            swarm_key,
            keyring if keyring is not None else Keyring(allow_tofu=False),
            require_signature=True,
        )
        self.unsealer.bind_own_id(identity.drone_id)
        self.enforce_sender_binding = enforce_sender_binding
        self.topic = swarm_key.topic()
        self._subs: List[Tuple[str, Handler]] = []
        self._running = False
        self._lock = threading.RLock()
        self.stats: Dict[str, int] = {"sent": 0, "received": 0, "dropped": 0, "rejected": 0}

    def start(self) -> None:
        self._running = True
        with self._lock:
            subs = list(self._subs)
        for topic_filter, _handler in subs:
            self.broker.subscribe(self.topic, self._on_envelope)

    def subscribe(self, topic_filter: str, handler: Handler) -> None:
        """Register a handler. The topic filter is ignored: one topic carries all."""
        with self._lock:
            self._subs.append((topic_filter, handler))
        if self._running:
            self.broker.subscribe(self.topic, self._on_envelope)

    def subscribe_swarm(self, handler: Handler) -> None:
        self.subscribe(self.topic, handler)

    def publish(self, topic: str, payload: bytes) -> None:
        """Seal the plaintext and hand the envelope to the broker.

        The caller's topic is ignored on purpose: the sealed swarm topic is
        derived from the key, so a caller cannot leak an identifying name.
        """
        envelope = self.sealer.seal(payload)
        self.stats["sent"] += 1
        self.broker.publish(self.topic, envelope)

    def stop(self) -> None:
        self._running = False

    @property
    def connected(self) -> bool:
        return self._running

    def _on_envelope(self, topic: str, payload: bytes) -> None:
        self.stats["received"] += 1
        try:
            opened = self.unsealer.unseal(payload, topic=topic)
        except CryptoError as exc:
            self.stats["rejected"] += 1
            log.warning("rejected sealed message: %s", exc)
            return

        if self.enforce_sender_binding and not self._sender_matches_payload(opened):
            self.stats["rejected"] += 1
            return

        with self._lock:
            handlers = [h for _f, h in self._subs]
        for handler in handlers:
            try:
                handler(self.topic, opened.plaintext)
            except Exception:
                self.stats["dropped"] += 1
                log.exception("handler failed on a sealed message")

    def _sender_matches_payload(self, opened) -> bool:
        """Refuse a payload claiming a drone or swarm other than the verified one."""
        import json as _json

        try:
            data = _json.loads(opened.plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        if not isinstance(data, dict):
            return False
        claimed = data.get("drone_id")
        if claimed is not None and str(claimed) != opened.sender:
            log.warning("sender binding violation: %s claimed to be %r", opened.sender, claimed)
            return False
        claimed_swarm = data.get("swarm_id")
        if claimed_swarm is not None and str(claimed_swarm) != self.swarm_key.swarm_id:
            log.warning("swarm binding violation: %s sent for swarm %r", opened.sender, claimed_swarm)
            return False
        return True
