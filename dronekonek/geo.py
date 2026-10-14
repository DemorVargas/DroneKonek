"""Geodesic math for DroneKonek.

Pure stdlib so the swarm logic runs on a Raspberry Pi with nothing installed
and stays trivially unit-testable. Distances are meters, angles are degrees.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace

EARTH_RADIUS_M = 6371008.8


@dataclass(frozen=True)
class Position:
    """A point in space the drone can be told about or told to go to."""

    lat: float
    lon: float
    alt: float = 0.0
    heading: float = 0.0  # degrees, 0 = north, increasing clockwise
    speed: float = 0.0  # m/s ground speed

    def to_dict(self) -> dict:
        return {
            "lat": self.lat,
            "lon": self.lon,
            "alt": self.alt,
            "heading": self.heading,
            "speed": self.speed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Position":
        return cls(
            lat=float(data["lat"]),
            lon=float(data["lon"]),
            alt=float(data.get("alt", 0.0)),
            heading=float(data.get("heading", 0.0)),
            speed=float(data.get("speed", 0.0)),
        )

    def moved(self, north_m: float = 0.0, east_m: float = 0.0, up_m: float = 0.0) -> "Position":
        """Return this position shifted by a local NED offset."""
        return offset_position(self, north_m=north_m, east_m=east_m, up_m=up_m)


def _meters_per_degree_lat() -> float:
    return math.pi * EARTH_RADIUS_M / 180.0


def horizontal_distance(a: Position, b: Position) -> float:
    """Great-circle distance between two positions, ignoring altitude."""
    lat1 = math.radians(a.lat)
    lat2 = math.radians(b.lat)
    dlat = lat2 - lat1
    dlon = math.radians(b.lon - a.lon)
    h = math.sin(dlat / 2.0) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2.0) ** 2
    return 2.0 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(h)))


# Name kept because it reads better at call sites that only care about ground track.
haversine = horizontal_distance


def slant_distance(a: Position, b: Position) -> float:
    """Straight-line 3D distance, the one that actually matters for collisions."""
    ground = horizontal_distance(a, b)
    dz = b.alt - a.alt
    return math.sqrt(ground * ground + dz * dz)


def offset_position(base: Position, north_m: float = 0.0, east_m: float = 0.0, up_m: float = 0.0) -> Position:
    """Shift a position by a local north/east/up offset in meters.

    Equirectangular approximation, exact enough for swarm spacing (well under a
    kilometer) and far cheaper than a full geodesic solution.
    """
    lat_deg_per_m = 1.0 / _meters_per_degree_lat()
    cos_lat = math.cos(math.radians(base.lat))
    # Guard the pole case so we never divide by ~zero.
    lon_deg_per_m = 1.0 / (_meters_per_degree_lat() * cos_lat) if abs(cos_lat) > 1e-12 else 0.0
    return replace(
        base,
        lat=base.lat + north_m * lat_deg_per_m,
        lon=base.lon + east_m * lon_deg_per_m,
        alt=base.alt + up_m,
    )


def bearing(a: Position, b: Position) -> float:
    """Compass bearing from a to b in degrees [0, 360)."""
    lat1 = math.radians(a.lat)
    lat2 = math.radians(b.lat)
    dlon = math.radians(b.lon - a.lon)
    y = math.sin(dlon) * math.cos(lat2)
    x = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def is_inside_geofence(pos: Position, center: Position, radius_m: float) -> bool:
    """True when pos is within radius_m of center (horizontal only)."""
    return horizontal_distance(pos, center) <= radius_m


def clamp_to_geofence(pos: Position, center: Position, radius_m: float) -> Position:
    """Pull a position back onto the geofence boundary if it strayed outside."""
    dist = horizontal_distance(pos, center)
    if dist <= radius_m or dist == 0.0:
        return pos
    brg = math.radians(bearing(center, pos))
    north = math.cos(brg) * radius_m
    east = math.sin(brg) * radius_m
    return offset_position(center, north_m=north, east_m=east, up_m=pos.alt - center.alt)
