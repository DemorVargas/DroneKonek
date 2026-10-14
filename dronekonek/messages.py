"""Wire format for DroneKonek swarm traffic.

One JSON object per MQTT payload, one topic per message kind. The schema is
deliberately boring: a Raspberry Pi parses it with the stdlib json module and a
drone that speaks an older version still understands the position fields.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from dronekonek.geo import Position

TOPIC_ROOT = "dronekonek/v1"
SCHEMA_VERSION = 1


class MessageType(str, Enum):
    HELLO = "hello"          # a drone joined the swarm
    HEARTBEAT = "heartbeat"  # still alive, no fresh fix
    POSITION = "position"    # full coordinate broadcast
    INTENT = "intent"        # "I am heading here" (waypoint / formation slot)
    TEXT = "text"            # operator chatter
    GOODBYE = "goodbye"      # leaving the swarm on purpose


class MessageError(ValueError):
    """Raised when a payload cannot be trusted as a swarm message."""


def position_topic(swarm_id: str, msg_type: MessageType, drone_id: str) -> str:
    return f"{TOPIC_ROOT}/{swarm_id}/{msg_type.value}/{drone_id}"


def swarm_subscription(swarm_id: str) -> str:
    """Everything anyone in this swarm says."""
    return f"{TOPIC_ROOT}/{swarm_id}/#"


def parse_topic(topic: str) -> Optional[Dict[str, str]]:
    parts = topic.split("/")
    if len(parts) != 5 or f"{parts[0]}/{parts[1]}" != TOPIC_ROOT:
        return None
    return {"swarm_id": parts[2], "type": parts[3], "drone_id": parts[4]}


@dataclass
class Message:
    msg_type: MessageType
    drone_id: str
    swarm_id: str
    timestamp: float = field(default_factory=time.time)
    seq: int = 0
    position: Optional[Position] = None
    target: Optional[Position] = None
    battery: Optional[float] = None
    text: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    version: int = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "v": self.version,
            "type": self.msg_type.value,
            "drone_id": self.drone_id,
            "swarm_id": self.swarm_id,
            "ts": self.timestamp,
            "seq": self.seq,
        }
        if self.position is not None:
            payload["position"] = self.position.to_dict()
        if self.target is not None:
            payload["target"] = self.target.to_dict()
        if self.battery is not None:
            payload["battery"] = self.battery
        if self.text is not None:
            payload["text"] = self.text
        if self.extra:
            payload["extra"] = self.extra
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    def topic(self) -> str:
        return position_topic(self.swarm_id, self.msg_type, self.drone_id)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        if not isinstance(data, dict):
            raise MessageError("payload is not a JSON object")
        try:
            msg_type = MessageType(data["type"])
        except KeyError as exc:
            raise MessageError("missing 'type'") from exc
        except ValueError as exc:
            raise MessageError(f"unknown message type: {data.get('type')!r}") from exc

        drone_id = data.get("drone_id")
        swarm_id = data.get("swarm_id")
        if not drone_id or not swarm_id:
            raise MessageError("missing 'drone_id' or 'swarm_id'")

        position = None
        if data.get("position") is not None:
            position = _safe_position(data["position"])
        target = None
        if data.get("target") is not None:
            target = _safe_position(data["target"])

        if msg_type is MessageType.POSITION and position is None:
            raise MessageError("position message without a position")

        battery = data.get("battery")
        if battery is not None:
            try:
                battery = float(battery)
            except (TypeError, ValueError) as exc:
                raise MessageError("battery is not a number") from exc

        return cls(
            msg_type=msg_type,
            drone_id=str(drone_id),
            swarm_id=str(swarm_id),
            timestamp=float(data.get("ts", time.time())),
            seq=int(data.get("seq", 0)),
            position=position,
            target=target,
            battery=battery,
            text=data.get("text"),
            extra=dict(data.get("extra") or {}),
            version=int(data.get("v", SCHEMA_VERSION)),
        )

    @classmethod
    def from_json(cls, raw: Any) -> "Message":
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")
        if not isinstance(raw, str):
            raise MessageError("payload must be str or bytes")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MessageError(f"invalid JSON: {exc}") from exc
        return cls.from_dict(data)


def _safe_position(raw: Any) -> Position:
    if not isinstance(raw, dict):
        raise MessageError("position must be an object")
    if "lat" not in raw or "lon" not in raw:
        raise MessageError("position needs lat and lon")
    try:
        pos = Position.from_dict(raw)
    except (TypeError, ValueError) as exc:
        raise MessageError(f"bad position values: {exc}") from exc
    if not (-90.0 <= pos.lat <= 90.0):
        raise MessageError(f"lat out of range: {pos.lat}")
    if not (-180.0 <= pos.lon <= 180.0):
        raise MessageError(f"lon out of range: {pos.lon}")
    return pos


def position_message(drone_id: str, swarm_id: str, position: Position, seq: int = 0,
                     battery: Optional[float] = None) -> Message:
    return Message(MessageType.POSITION, drone_id, swarm_id, seq=seq, position=position, battery=battery)


def hello_message(drone_id: str, swarm_id: str, position: Optional[Position] = None) -> Message:
    return Message(MessageType.HELLO, drone_id, swarm_id, position=position)


def goodbye_message(drone_id: str, swarm_id: str, reason: str = "") -> Message:
    return Message(MessageType.GOODBYE, drone_id, swarm_id, text=reason or None)
