"""Transport abstraction so swarm logic never imports a broker library.

Two implementations ship here:

* ``InMemoryBroker`` / ``InMemoryTransport`` -- a tiny loopback pub/sub used by
  the tests and the simulator. No network, no dependencies.
* ``MQTTTransport`` in ``dronekonek.mqtt_transport`` -- the real thing, on the
  drone's WiFi link, using paho-mqtt.

A transport only has to do three things: publish bytes to a topic, hand
incoming (topic, payload) pairs to a callback, and stop cleanly.
"""

from __future__ import annotations

import threading
from typing import Callable, Dict, List, Optional, Tuple

from dronekonek.messages import swarm_subscription

Handler = Callable[[str, bytes], None]


class Transport:
    """Interface every transport implements."""

    def start(self) -> None:
        raise NotImplementedError

    def publish(self, topic: str, payload: bytes) -> None:
        raise NotImplementedError

    def subscribe(self, topic_filter: str, handler: Handler) -> None:
        raise NotImplementedError

    def subscribe_swarm(self, handler: Handler) -> None:
        """Subscribe to every message this swarm's members publish.

        The transport owns this filter because only the transport knows what the
        topic actually looks like: plaintext mode uses the readable
        ``dronekonek/v1/<swarm>/#`` scheme, secure mode uses an opaque keyed
        topic. A caller that hard-codes the plaintext filter would silently
        receive nothing in secure mode.
        """
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    @property
    def connected(self) -> bool:
        raise NotImplementedError


def _topic_matches(topic_filter: str, topic: str) -> bool:
    """MQTT wildcard matching for + and #, so the loopback broker behaves."""
    f = topic_filter.split("/")
    t = topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t):
            return False
        if part != "+" and part != t[i]:
            return False
    return len(f) == len(t)


class InMemoryBroker:
    """Loopback pub/sub broker. Thread safe, dependency free, for tests."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subs: List[Tuple[str, Handler]] = []
        self.published: List[Tuple[str, bytes]] = []

    def subscribe(self, topic_filter: str, handler: Handler) -> None:
        with self._lock:
            self._subs.append((topic_filter, handler))

    def publish(self, topic: str, payload: bytes) -> None:
        with self._lock:
            self.published.append((topic, payload))
            targets = [h for f, h in self._subs if _topic_matches(f, topic)]
        for handler in targets:
            handler(topic, payload)


class InMemoryTransport(Transport):
    """A transport backed by a shared in-process broker."""

    def __init__(self, broker: InMemoryBroker, swarm_id: Optional[str] = None) -> None:
        self._broker = broker
        self._swarm_id = swarm_id
        self._subs: List[Tuple[str, Handler]] = []
        self._running = False

    def start(self) -> None:
        self._running = True
        for topic_filter, handler in self._subs:
            self._broker.subscribe(topic_filter, handler)

    def subscribe(self, topic_filter: str, handler: Handler) -> None:
        self._subs.append((topic_filter, handler))
        if self._running:
            self._broker.subscribe(topic_filter, handler)

    def subscribe_swarm(self, handler: Handler) -> None:
        # A broker is per-swarm in the simulator and tests, so a wildcard is
        # correct here; a named swarm scopes it when one is configured.
        if self._swarm_id:
            self.subscribe(swarm_subscription(self._swarm_id), handler)
        else:
            self.subscribe("#", handler)

    def publish(self, topic: str, payload: bytes) -> None:
        self._broker.publish(topic, payload)

    def stop(self) -> None:
        self._running = False

    @property
    def connected(self) -> bool:
        return self._running


class LoopbackTransport(InMemoryTransport):
    """One broker per transport: a drone talking to itself. Useful for dry runs."""

    def __init__(self) -> None:
        super().__init__(InMemoryBroker())
