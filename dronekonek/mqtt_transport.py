"""MQTT transport: the real WiFi link between drones.

Every drone connects to the same broker (one drone carries it, or a ground
station does). Each drone publishes to its own id-suffixed topics and
subscribes to the whole swarm with a single wildcard, so peer discovery is
automatic: nobody has to be configured with a list of the others.

The last-will is the important part. If a drone drops off the network hard,
the broker publishes its goodbye for it, so the rest of the swarm stops
expecting it instead of waiting out the timeout.
"""

from __future__ import annotations

import secrets
from typing import Optional

from dronekonek.messages import TOPIC_ROOT, Message, MessageType, position_topic, swarm_subscription
from dronekonek.transport import Handler, Transport


class MQTTTransport(Transport):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1883,
        drone_id: str = "drone",
        swarm_id: str = "swarm",
        username: Optional[str] = None,
        password: Optional[str] = None,
        keepalive: int = 15,
        qos: int = 0,
        client_id: Optional[str] = None,
        tls: bool = False,
        tls_ca: Optional[str] = None,
        reconnect_min_delay: int = 1,
        reconnect_max_delay: int = 16,
        proxy_addr: Optional[str] = None,
        proxy_port: int = 1080,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.drone_id = drone_id
        self.swarm_id = swarm_id
        self.username = username
        self.password = password
        self.keepalive = keepalive
        self.qos = qos
        self.tls = tls
        self.tls_ca = tls_ca
        self.client_id = client_id or f"dk-{secrets.token_hex(8)}"
        self.reconnect_min_delay = reconnect_min_delay
        self.reconnect_max_delay = reconnect_max_delay
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self._client = None
        self._subs = []

    def _build_client(self):
        import paho.mqtt.client as mqtt

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.client_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
        )
        if self.username:
            client.username_pw_set(self.username, self.password)
        if self.tls:
            client.tls_set(ca_certs=self.tls_ca)
        client.reconnect_delay_set(min_delay=self.reconnect_min_delay, max_delay=self.reconnect_max_delay)
        if self.proxy_addr:
            client.proxy_set(
                proxy_type=mqtt.ProxyType.SOCKS5,
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password,
            )
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        # Last will: the broker announces our exit if we vanish.
        will = Message(MessageType.GOODBYE, self.drone_id, self.swarm_id, text="link lost")
        client.will_set(will.topic(), will.to_json(), qos=1, retain=False)
        return client

    def start(self) -> None:
        self._client = self._build_client()
        self._client.connect(self.host, self.port, keepalive=self.keepalive)
        # loop_start runs the network thread; connect() above is what we wait on
        # so a bad broker address fails loudly here instead of silently later.
        self._client.loop_start()

    def subscribe(self, topic_filter: str, handler: Handler) -> None:
        self._subs.append((topic_filter, handler))
        if self._client is not None and self._client.is_connected():
            self._client.subscribe(topic_filter, qos=self.qos)

    def subscribe_swarm(self, handler: Handler) -> None:
        """Subscribe to every message any drone in this swarm publishes."""
        self.subscribe(swarm_subscription(self.swarm_id), handler)

    def publish(self, topic: str, payload: bytes) -> None:
        if self._client is None:
            raise RuntimeError("transport not started")
        info = self._client.publish(topic, payload, qos=self.qos)
        if info.rc != 0:
            raise RuntimeError(f"publish to {topic} failed with rc={info.rc}")

    def publish_message(self, message: Message) -> None:
        self.publish(message.topic(), message.to_json().encode("utf-8"))

    def stop(self) -> None:
        if self._client is None:
            return
        try:
            self._client.disconnect()
        finally:
            self._client.loop_stop()
            self._client = None

    @property
    def connected(self) -> bool:
        return self._client is not None and bool(self._client.is_connected())

    # ---- paho callbacks -------------------------------------------------

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if getattr(reason_code, "is_failure", False) or reason_code != 0:
            return
        for topic_filter, _handler in self._subs:
            client.subscribe(topic_filter, qos=self.qos)
        # Announce ourselves the moment the link comes up, including after a
        # reconnect: peers that timed us out need to know we are back.
        hello = Message(MessageType.HELLO, self.drone_id, self.swarm_id)
        client.publish(hello.topic(), hello.to_json(), qos=self.qos)

    def _on_message(self, client, userdata, msg) -> None:
        for topic_filter, handler in self._subs:
            if _filter_hit(topic_filter, msg.topic):
                handler(msg.topic, msg.payload)


def _filter_hit(topic_filter: str, topic: str) -> bool:
    from dronekonek.transport import _topic_matches

    return _topic_matches(topic_filter, topic)
