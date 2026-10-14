"""DroneKonek: drones that find each other and share coordinates over WiFi."""

from dronekonek.geo import Position, haversine, horizontal_distance, offset_position, bearing, is_inside_geofence
from dronekonek.messages import Message, MessageType, TOPIC_ROOT
from dronekonek.swarm import Peer, SwarmRegistry, CollisionWarning
from dronekonek.transport import Transport, InMemoryBroker, InMemoryTransport
from dronekonek.node import DroneNode

# Crypto is stdlib-plus-optional: importing these names never pulls in the
# `cryptography` package, because every heavy import inside it is lazy.
from dronekonek.crypto import (
    CryptoError,
    CryptoUnavailable,
    Identity,
    Keyring,
    Sealer,
    SwarmKey,
    Unsealed,
    Unsealer,
    has_crypto,
    provision,
)

__version__ = "0.1.0"

__all__ = [
    "Position",
    "haversine",
    "horizontal_distance",
    "offset_position",
    "bearing",
    "is_inside_geofence",
    "Message",
    "MessageType",
    "TOPIC_ROOT",
    "Peer",
    "SwarmRegistry",
    "CollisionWarning",
    "Transport",
    "InMemoryBroker",
    "InMemoryTransport",
    "DroneNode",
    "CryptoError",
    "CryptoUnavailable",
    "Identity",
    "Keyring",
    "Sealer",
    "SwarmKey",
    "Unsealed",
    "Unsealer",
    "has_crypto",
    "provision",
    "__version__",
]
