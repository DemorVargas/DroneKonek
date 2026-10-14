"""Swarm state: who is out there, where, and who is about to hit whom.

The registry is the single source of truth on each drone. Every incoming
position message updates it; every drone asks it "am I too close to anyone"
before it decides to move.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from dronekonek.geo import Position, bearing, horizontal_distance, slant_distance
from dronekonek.messages import Message, MessageType


@dataclass
class Peer:
    """Another drone in the swarm, as this drone last heard from it."""

    drone_id: str
    position: Position
    last_seen: float
    battery: Optional[float] = None
    seq: int = 0
    name: Optional[str] = None

    @property
    def age(self) -> float:
        return time.time() - self.last_seen

    def is_stale(self, max_age_s: float) -> bool:
        return self.age > max_age_s


@dataclass
class CollisionWarning:
    """Two drones closer than the operator's comfort allows."""

    other_id: str
    distance_m: float
    vertical_m: float
    bearing_deg: float
    severity: str  # "caution" | "warning" | "critical"

    def __str__(self) -> str:
        return (
            f"{self.severity.upper()}: {self.other_id} is {self.distance_m:.1f}m away "
            f"at bearing {self.bearing_deg:.0f} (dz {self.vertical_m:+.1f}m)"
        )


def _severity(distance_m: float, caution_m: float, warning_m: float, critical_m: float) -> str:
    if distance_m <= critical_m:
        return "critical"
    if distance_m <= warning_m:
        return "warning"
    return "caution"


@dataclass
class SwarmRegistry:
    """Tracks every peer this drone knows about, plus our own position."""

    drone_id: str
    swarm_id: str
    caution_m: float = 30.0
    warning_m: float = 15.0
    critical_m: float = 5.0
    peer_timeout_s: float = 10.0
    self_position: Optional[Position] = None
    peers: Dict[str, Peer] = field(default_factory=dict)
    _seen_sequence: Dict[str, int] = field(default_factory=dict, repr=False)
    dropped: int = field(default=0, repr=False)

    # ---- ingest ---------------------------------------------------------

    def observe(self, msg: Message, received_at: Optional[float] = None) -> bool:
        """Fold a message into swarm state. Returns True if anything changed.

        Out-of-order and duplicate packets are dropped rather than trusted:
        WiFi on a drone is not a reliable ordered channel, and a stale fix
        applied over a fresh one is how you fly two aircraft into each other.
        """
        if msg.swarm_id != self.swarm_id:
            return False
        if msg.drone_id == self.drone_id:
            return False
        now = received_at if received_at is not None else time.time()

        if msg.msg_type is MessageType.GOODBYE:
            if self.peers.pop(msg.drone_id, None) is not None:
                self._seen_sequence.pop(msg.drone_id, None)
                return True
            return False

        if msg.position is None:
            return False

        last_seq = self._seen_sequence.get(msg.drone_id)
        if last_seq is not None and msg.seq and msg.seq <= last_seq:
            self.dropped += 1
            return False
        if msg.seq:
            self._seen_sequence[msg.drone_id] = msg.seq

        self.peers[msg.drone_id] = Peer(
            drone_id=msg.drone_id,
            position=msg.position,
            last_seen=now,
            battery=msg.battery,
            seq=msg.seq,
            name=msg.extra.get("name") if isinstance(msg.extra, dict) else None,
        )
        return True

    def update_self(self, position: Position) -> None:
        self.self_position = position

    # ---- queries --------------------------------------------------------

    def prune(self, now: Optional[float] = None) -> List[str]:
        """Forget peers that went quiet. Returns the ids that were dropped."""
        now = now if now is not None else time.time()
        gone = [pid for pid, peer in self.peers.items() if (now - peer.last_seen) > self.peer_timeout_s]
        for pid in gone:
            self.peers.pop(pid, None)
            self._seen_sequence.pop(pid, None)
        return gone

    def active_peers(self, now: Optional[float] = None) -> List[Peer]:
        now = now if now is not None else time.time()
        return [p for p in self.peers.values() if (now - p.last_seen) <= self.peer_timeout_s]

    def nearest(self) -> Optional[Tuple[Peer, float]]:
        """Closest active peer and the 3D distance to it."""
        if self.self_position is None:
            return None
        best: Optional[Tuple[Peer, float]] = None
        for peer in self.active_peers():
            d = slant_distance(self.self_position, peer.position)
            if best is None or d < best[1]:
                best = (peer, d)
        return best

    def collisions(self) -> List[CollisionWarning]:
        """Every active peer closer than the caution radius, worst first."""
        warnings: List[CollisionWarning] = []
        if self.self_position is None:
            return warnings
        me = self.self_position
        for peer in self.active_peers():
            dist = slant_distance(me, peer.position)
            if dist <= self.caution_m:
                warnings.append(
                    CollisionWarning(
                        other_id=peer.drone_id,
                        distance_m=dist,
                        vertical_m=peer.position.alt - me.alt,
                        bearing_deg=bearing(me, peer.position),
                        severity=_severity(dist, self.caution_m, self.warning_m, self.critical_m),
                    )
                )
        warnings.sort(key=lambda w: w.distance_m)
        return warnings

    def separation_vectors(self) -> Dict[str, Tuple[float, float, float]]:
        """Push-away vectors for nearby peers, in local NED meters.

        Each value is (north, east, up) that this drone should move to open the
        gap. Magnitude grows as the gap shrinks, so it behaves like a spring.

        Vertical resolution always favours climbing. Sending a drone down to
        open a gap is how you fly one into the ground, so when two aircraft are
        at the same altitude the tie is broken upward on purpose.
        """
        out: Dict[str, Tuple[float, float, float]] = {}
        if self.self_position is None:
            return out
        me = self.self_position
        for peer in self.active_peers():
            dist = slant_distance(me, peer.position)
            if dist > self.caution_m:
                continue
            if dist < 1e-6:
                # Perfectly overlapping fixes: push north and up, it is as good
                # as any and at least it does not aim at the dirt.
                out[peer.drone_id] = (-self.caution_m, 0.0, self.warning_m)
                continue
            brg = math.radians(bearing(me, peer.position))
            strength = (self.caution_m - dist) / self.caution_m  # 0..1
            north = -math.cos(brg) * self.caution_m * strength
            east = -math.sin(brg) * self.caution_m * strength
            up = 0.0
            dz = peer.position.alt - me.alt
            if abs(dz) < self.warning_m:
                # Same band: climb. Otherwise separate vertically the short way,
                # but never downward past the ground.
                up = self.warning_m * strength if dz <= 0 else -self.warning_m * strength
                if me.alt + up < 0.0:
                    up = max(0.0, -me.alt)
            out[peer.drone_id] = (north, east, up)
        return out

    def combined_separation(self) -> Tuple[float, float, float]:
        """Sum of every separation vector: one move that opens all gaps."""
        north = east = up = 0.0
        for n, e, u in self.separation_vectors().values():
            north += n
            east += e
            up += u
        return (north, east, up)

    def swarm_centroid(self) -> Optional[Position]:
        """Average position of every active drone including us."""
        points: List[Position] = []
        if self.self_position is not None:
            points.append(self.self_position)
        points.extend(p.position for p in self.active_peers())
        if not points:
            return None
        return Position(
            lat=sum(p.lat for p in points) / len(points),
            lon=sum(p.lon for p in points) / len(points),
            alt=sum(p.alt for p in points) / len(points),
        )

    def spread_m(self) -> float:
        """Max pairwise ground distance in the swarm: how tight we are flying."""
        points: List[Position] = []
        if self.self_position is not None:
            points.append(self.self_position)
        points.extend(p.position for p in self.active_peers())
        worst = 0.0
        for i in range(len(points)):
            for j in range(i + 1, len(points)):
                worst = max(worst, horizontal_distance(points[i], points[j]))
        return worst

    def snapshot(self) -> Dict[str, object]:
        """Serializable view for logging, the CLI, or a ground station."""
        me = self.self_position
        peers = self.active_peers()
        return {
            "drone_id": self.drone_id,
            "swarm_id": self.swarm_id,
            "position": me.to_dict() if me else None,
            "peer_count": len(peers),
            "peers": [
                {
                    "drone_id": p.drone_id,
                    "position": p.position.to_dict(),
                    "age_s": round(p.age, 2),
                    "battery": p.battery,
                    "distance_m": round(slant_distance(me, p.position), 1) if me else None,
                }
                for p in sorted(peers, key=lambda p: p.drone_id)
            ],
            "collisions": [
                {"with": w.other_id, "distance_m": round(w.distance_m, 1), "severity": w.severity}
                for w in self.collisions()
            ],
        }
