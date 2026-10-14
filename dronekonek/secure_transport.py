"""Secure transport: TLS on the wire plus end-to-end authenticated encryption.

Two independent layers, because they defend different things:

* **TLS** protects the hop between a drone and the broker. It stops passive
  sniffing of that link, but it does *nothing* about the broker itself or about
  a member of your swarm who has gone rogue, because the broker terminates TLS.
* **The sealed envelope** (`dronekonek.crypto`) protects the message end to end.
  The broker only ever sees ciphertext, cannot read coordinates, cannot forge a
  position, and cannot replay an old one. Only a holder of the swarm key can
  produce a message that any drone will accept.

The topic is an HMAC of the swarm key rather than the swarm name, so an outsider
cannot even enumerate swarms or learn drone ids from the wire.

Needs paho-mqtt for the link and `cryptography` for the sealing:
    pip install 'dronekonek[secure]'
"""

from __future__ import annotations

import logging
import secrets
import ssl
import threading
import time
from typing import Dict, Optional

from dronekonek.crypto import (
    CryptoError,
    Keyring,
    Sealer,
    SwarmKey,
    Unsealer,
    has_crypto,
)
from dronekonek.transport import Handler, Transport, _topic_matches

log = logging.getLogger("dronekonek.secure_transport")


def build_tls_context(
    ca_certs: Optional[str] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    *,
    insecure_skip_verify: bool = False,
    require_client_cert: bool = False,
) -> "ssl.SSLContext":
    """A strict TLS client context.

    Certificate verification is on and hostname checking is on. The only way to
    turn verification off is the explicit ``insecure_skip_verify`` flag, which
    exists for bench testing against a self-signed broker and is named so that
    nobody sets it by accident.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_certs)
    if insecure_skip_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        log.warning("TLS certificate verification is DISABLED; use only for bench testing")
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
    # A modern floor. No SSLv3, no TLS 1.0/1.1, no anonymous ciphers.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if certfile:
        ctx.load_cert_chain(certfile, keyfile)
    if require_client_cert and not certfile:
        raise ValueError("require_client_cert needs a client certificate")
    return ctx


class SecureMQTTTransport(Transport):
    """MQTT transport that seals every payload and opens every incoming one.

    Publishes on one opaque swarm topic. Anything that fails to decrypt,
    authenticate, or pass the replay check is dropped and counted, never handed
    to the swarm as if it were real.
    """

    def __init__(
        self,
        swarm_key: SwarmKey,
        sealer: Sealer,
        unsealer: Unsealer,
        host: str = "127.0.0.1",
        port: int = 8883,
        username: Optional[str] = None,
        password: Optional[str] = None,
        tls_context: Optional["ssl.SSLContext"] = None,
        keepalive: int = 15,
        qos: int = 1,
        client_id: Optional[str] = None,
        reconnect_min_delay: int = 1,
        reconnect_max_delay: int = 16,
        enforce_sender_binding: bool = True,
        proxy_addr: Optional[str] = None,
        proxy_port: int = 1080,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
    ) -> None:
        if not has_crypto():
            raise CryptoError(
                "secure mode needs the 'cryptography' package.\n"
                "  install it with:  pip install 'dronekonek[crypto]'"
            )
        self.swarm_key = swarm_key
        self.sealer = sealer
        self.unsealer = unsealer
        self.enforce_sender_binding = enforce_sender_binding
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.tls_context = tls_context
        self.keepalive = keepalive
        self.qos = qos
        self.client_id = client_id or f"dk-{secrets.token_hex(8)}"
        self.reconnect_min_delay = reconnect_min_delay
        self.reconnect_max_delay = reconnect_max_delay
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self._client = None
        self._subs = []
        self._lock = threading.RLock()
        self.topic = swarm_key.topic()
        self.stats: Dict[str, int] = {"sent": 0, "received": 0, "dropped": 0, "rejected": 0}

    # ---- lifecycle ------------------------------------------------------

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
        if self.tls_context is not None:
            client.tls_set_context(self.tls_context)
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
        # The last will is sealed too. A plaintext will on a secure swarm would
        # leak the drone id and the swarm to anyone watching, and peers would
        # reject it anyway.
        will = self.sealer.seal(b'{"type":"goodbye","text":"link lost"}')
        client.will_set(self.topic, will, qos=1, retain=False)
        return client

    def start(self) -> None:
        self._client = self._build_client()
        self._client.connect(self.host, self.port, keepalive=self.keepalive)
        self._client.loop_start()

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

    # ---- publish --------------------------------------------------------

    def publish(self, topic: str, payload: bytes) -> None:
        """Seal and publish. The topic argument is ignored: secure mode uses one.

        Callers pass the plaintext message bytes. The swarm topic is derived from
        the key, not from the caller, so a caller cannot accidentally leak an
        identifying topic name onto the wire.
        """
        if self._client is None:
            raise RuntimeError("transport not started")
        envelope = self.sealer.seal(payload)
        info = self._client.publish(self.topic, envelope, qos=self.qos)
        if info.rc != 0:
            raise RuntimeError(f"publish failed with rc={info.rc}")
        self.stats["sent"] += 1

    def subscribe(self, topic_filter: str, handler: Handler) -> None:
        """Register a handler. Topic filters are ignored; one topic carries all."""
        with self._lock:
            self._subs.append((topic_filter, handler))
        if self._client is not None and self._client.is_connected():
            self._client.subscribe(self.topic, qos=self.qos)

    def subscribe_swarm(self, handler: Handler) -> None:
        self.subscribe(self.topic, handler)

    # ---- paho callbacks -------------------------------------------------

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if getattr(reason_code, "is_failure", False) or reason_code != 0:
            log.error("broker refused connection: %s", reason_code)
            return
        client.subscribe(self.topic, qos=self.qos)
        # Sealed hello so peers learn we are back without anything leaking.
        hello = self.sealer.seal(b'{"type":"hello"}')
        client.publish(self.topic, hello, qos=self.qos)

    def _on_message(self, client, userdata, msg) -> None:
        self.stats["received"] += 1
        try:
            opened = self.unsealer.unseal(msg.payload, topic=msg.topic)
        except CryptoError as exc:
            # Someone is talking on our topic who cannot prove they belong, or
            # the broker handed us a stale replay. Drop it, count it, move on.
            self.stats["rejected"] += 1
            log.warning("rejected swarm message: %s", exc)
            return

        if self.enforce_sender_binding and not self._sender_matches_payload(opened):
            self.stats["rejected"] += 1
            return

        with self._lock:
            handlers = [(f, h) for f, h in self._subs if _topic_matches(f, self.topic)]
        for _topic_filter, handler in handlers:
            try:
                # Hand the handler the authenticated sender's plaintext.
                handler(self.topic, opened.plaintext)
            except Exception:
                self.stats["dropped"] += 1
                log.exception("handler failed on a sealed message")

    def _sender_matches_payload(self, opened) -> bool:
        """Refuse a message whose content claims a different drone or swarm.

        The unsealer already enforces this when it can resolve the sender's
        identity. This is the belt-and-braces check at the transport boundary, so
        a transport is safe even if it is handed an Unsealer built differently.
        """
        import json as _json

        try:
            data = _json.loads(opened.plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            log.warning("sealed payload is not JSON; rejecting")
            return False
        if not isinstance(data, dict):
            log.warning("sealed payload is not a JSON object; rejecting")
            return False

        claimed = data.get("drone_id")
        if claimed is not None and str(claimed) != opened.sender:
            log.warning(
                "sender binding violation: %s sealed a payload claiming to be %r",
                opened.sender, claimed,
            )
            return False
        claimed_swarm = data.get("swarm_id")
        if claimed_swarm is not None and str(claimed_swarm) != self.swarm_key.swarm_id:
            log.warning(
                "swarm binding violation: %s sealed a payload for swarm %r",
                opened.sender, claimed_swarm,
            )
            return False
        return True


def secure_transport_for(
    swarm_key: SwarmKey,
    identity,
    *,
    keyring: Optional[Keyring] = None,
    host: str = "127.0.0.1",
    port: int = 8883,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ca_certs: Optional[str] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    insecure_skip_verify: bool = False,
    require_signature: bool = True,
    max_clock_skew_s: float = 30.0,
    qos: int = 1,
    proxy_addr: Optional[str] = None,
    proxy_port: int = 1080,
    proxy_username: Optional[str] = None,
    proxy_password: Optional[str] = None,
) -> SecureMQTTTransport:
    """Wire a Sealer, an Unsealer, and a TLS context into one transport."""
    sealer = Sealer(swarm_key, identity)
    unsealer = Unsealer(
        swarm_key,
        keyring=keyring if keyring is not None else Keyring(allow_tofu=not require_signature),
        require_signature=require_signature,
        max_clock_skew_s=max_clock_skew_s,
    )
    unsealer.bind_own_id(identity.drone_id)
    ctx = build_tls_context(ca_certs, certfile, keyfile, insecure_skip_verify=insecure_skip_verify)
    return SecureMQTTTransport(
        swarm_key=swarm_key,
        sealer=sealer,
        unsealer=unsealer,
        host=host,
        port=port,
        username=username,
        password=password,
        tls_context=ctx,
        qos=qos,
        proxy_addr=proxy_addr,
        proxy_port=proxy_port,
        proxy_username=proxy_username,
        proxy_password=proxy_password,
    )
