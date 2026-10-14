"""DroneNode: one drone, its link to the autopilot, and its link to the swarm.

This is the piece you actually run on the Raspberry Pi. It owns a timer that
reads the autopilot, broadcasts the position, folds in what the other drones
said, and warns (or acts) when someone gets too close.

Safety posture, because these are real aircraft: the node warns by default and
only nudges when you explicitly turn ``avoidance_enabled`` on. If it ever loses
its own fix or the swarm goes stale, it says so loudly instead of guessing.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from dronekonek.geo import Position
from dronekonek.mavlink_link import MAVLinkLink, MockMAVLinkLink
from dronekonek.messages import (
    Message,
    MessageError,
    MessageType,
    goodbye_message,
    hello_message,
    position_message,
)
from dronekonek.swarm import CollisionWarning, SwarmRegistry
from dronekonek.transport import Transport

log = logging.getLogger("dronekonek.node")


class DroneNode:
    """A drone that shares its coordinates and listens to its neighbours."""

    def __init__(
        self,
        drone_id: str,
        swarm_id: str = "swarm",
        transport: Optional[Transport] = None,
        link: Optional[object] = None,
        broadcast_hz: float = 2.0,
        peer_timeout_s: float = 10.0,
        caution_m: float = 30.0,
        warning_m: float = 15.0,
        critical_m: float = 5.0,
        avoidance_enabled: bool = False,
        avoidance_gain: float = 0.5,
        max_avoidance_step_m: float = 10.0,
        geofence_center: Optional[Position] = None,
        geofence_radius_m: Optional[float] = None,
        on_collision: Optional[Callable[[CollisionWarning], None]] = None,
        on_peer: Optional[Callable[[str, Position], None]] = None,
    ) -> None:
        self.drone_id = drone_id
        self.swarm_id = swarm_id
        self.transport = transport
        self.link = link if link is not None else MockMAVLinkLink()
        self.broadcast_hz = broadcast_hz
        self.avoidance_enabled = avoidance_enabled
        self.avoidance_gain = avoidance_gain
        self.max_avoidance_step_m = max_avoidance_step_m
        self.geofence_center = geofence_center
        self.geofence_radius_m = geofence_radius_m
        self.on_collision = on_collision
        self.on_peer = on_peer

        self.registry = SwarmRegistry(
            drone_id=drone_id,
            swarm_id=swarm_id,
            caution_m=caution_m,
            warning_m=warning_m,
            critical_m=critical_m,
            peer_timeout_s=peer_timeout_s,
        )
        self._seq = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._last_broadcast = 0.0
        self._last_collision_ids: set = set()
        self.stats: Dict[str, int] = {"sent": 0, "received": 0, "dropped": 0, "collisions": 0}

    # ---- lifecycle ------------------------------------------------------

    def start(self) -> None:
        """Connect the autopilot and the swarm, then start the broadcast loop."""
        if self.transport is None:
            raise RuntimeError("no transport configured; pass a Transport to DroneNode")
        if not self.link.connected:
            self.link.connect()
        self.link.request_streams(rate_hz=max(1, int(self.broadcast_hz)))
        self.transport.subscribe_swarm(self._on_wire_message)
        self.transport.start()
        self._running = True
        self._announce(hello_message(self.drone_id, self.swarm_id, self.registry.self_position))
        self._thread = threading.Thread(target=self._loop, name=f"dronekonek-{self.drone_id}", daemon=True)
        self._thread.start()
        log.info("drone %s joined swarm %s", self.drone_id, self.swarm_id)

    def stop(self, reason: str = "shutdown") -> None:
        if not self._running:
            return
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        try:
            self._announce(goodbye_message(self.drone_id, self.swarm_id, reason))
        except Exception:  # never let a farewell crash shutdown
            log.debug("goodbye publish failed", exc_info=True)
        if self.transport is not None:
            self.transport.stop()
        try:
            self.link.close()
        except Exception:
            log.debug("link close failed", exc_info=True)
        log.info("drone %s left swarm %s", self.drone_id, self.swarm_id)

    def __enter__(self) -> "DroneNode":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()

    # ---- the loop -------------------------------------------------------

    def _loop(self) -> None:
        """Drive tick() and publish on the broadcast schedule.

        Publishing lives here rather than inside tick() so that stepping the
        node by hand (tests, the simulator) never races a hidden timer: tick()
        only reads and reacts, and whoever owns the clock calls broadcast.
        """
        period = 1.0 / max(self.broadcast_hz, 0.1)
        while self._running:
            started = time.time()
            try:
                self.tick()
                if (started - self._last_broadcast) >= period:
                    self.broadcast_position()
                    self._last_broadcast = started
            except Exception:
                log.exception("tick failed on %s", self.drone_id)
            elapsed = time.time() - started
            time.sleep(max(0.0, period - elapsed))

    def tick(self) -> Optional[List[CollisionWarning]]:
        """One cycle: read self, prune peers, check for conflicts. No publishing."""
        position = self.link.position()
        if position is not None:
            self.registry.update_self(position)

        gone = self.registry.prune()
        for pid in gone:
            log.warning("peer %s timed out", pid)

        warnings = self.registry.collisions()
        self._handle_warnings(warnings)
        return warnings

    def broadcast_position(self, battery: Optional[float] = None) -> None:
        if self.registry.self_position is None:
            log.warning("no position fix on %s; not broadcasting", self.drone_id)
            return
        if battery is None:
            try:
                battery = self.link.battery_percent()
            except Exception:
                battery = None
        self._seq += 1
        msg = position_message(self.drone_id, self.swarm_id, self.registry.self_position, seq=self._seq, battery=battery)
        self._announce(msg)
        self.stats["sent"] += 1

    def _announce(self, msg: Message) -> None:
        if self.transport is None:
            return
        self.transport.publish(msg.topic(), msg.to_json().encode("utf-8"))

    # ---- inbound --------------------------------------------------------

    def _on_wire_message(self, topic: str, payload: bytes) -> None:
        try:
            msg = Message.from_json(payload)
        except MessageError as exc:
            log.warning("bad swarm payload on %s: %s", topic, exc)
            self.stats["dropped"] += 1
            return
        self.ingest(msg)

    def ingest(self, msg: Message) -> bool:
        """Public entry point for a decoded message (used by tests too)."""
        self.stats["received"] += 1
        changed = self.registry.observe(msg)
        if changed and msg.position is not None and self.on_peer is not None:
            try:
                self.on_peer(msg.drone_id, msg.position)
            except Exception:
                log.exception("on_peer callback failed")
        return changed

    # ---- conflict handling ---------------------------------------------

    def _handle_warnings(self, warnings: List[CollisionWarning]) -> None:
        current = {w.other_id for w in warnings}
        new_ids = current - self._last_collision_ids
        for w in warnings:
            if w.other_id in new_ids:
                self.stats["collisions"] += 1
                log.warning("drone %s: %s", self.drone_id, w)
                if self.on_collision is not None:
                    try:
                        self.on_collision(w)
                    except Exception:
                        log.exception("on_collision callback failed")
        self._last_collision_ids = current

        if not self.avoidance_enabled or self.registry.self_position is None:
            return
        worst = warnings[0] if warnings else None
        if worst is None or worst.severity != "critical":
            return
        self._apply_avoidance()

    def _apply_avoidance(self) -> None:
        """Nudge away from the pack, bounded, and never outside the geofence."""
        from dronekonek.geo import clamp_to_geofence, offset_position

        north, east, up = self.registry.combined_separation()
        if north == 0.0 and east == 0.0 and up == 0.0:
            return
        scale = min(1.0, self.max_avoidance_step_m / max(1e-6, (north ** 2 + east ** 2 + up ** 2) ** 0.5))
        target = offset_position(
            self.registry.self_position,
            north_m=north * self.avoidance_gain * scale,
            east_m=east * self.avoidance_gain * scale,
            up_m=up * self.avoidance_gain * scale,
        )
        if self.geofence_center is not None and self.geofence_radius_m is not None:
            target = clamp_to_geofence(target, self.geofence_center, self.geofence_radius_m)
        if target.alt < 0.0:
            # A separation move must never put a drone underground.
            target = Position(lat=target.lat, lon=target.lon, alt=0.0,
                              heading=target.heading, speed=target.speed)
        log.warning("drone %s avoidance move to (%.6f, %.6f, %.1f)", self.drone_id, target.lat, target.lon, target.alt)
        self.link.goto(target)

    # ---- convenience ----------------------------------------------------

    def peers(self):
        return self.registry.active_peers()

    def snapshot(self) -> Dict[str, object]:
        snap = self.registry.snapshot()
        snap["stats"] = dict(self.stats)
        snap["avoidance_enabled"] = self.avoidance_enabled
        return snap
