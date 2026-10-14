"""Formation slots: turning "hold this shape" into coordinates per drone.

Everyone in the swarm computes the same slot for the same drone id, so a
formation needs no negotiation and no leader broadcasting individual targets.
Give each drone the same formation name and centre, and they sort themselves
out by id.
"""

from __future__ import annotations

import math
from typing import Callable, Dict, List

from dronekonek.geo import Position, offset_position


def _slot_grid(index: int, spacing_m: float) -> tuple:
    """Row-major square grid, so index 0 is the centre of the front row."""
    side = int(math.ceil(math.sqrt(index + 1)))
    row = index // side
    col = index % side
    east = (col - (side - 1) / 2.0) * spacing_m
    north = -row * spacing_m
    return (north, east)


def _slot_line(index: int, spacing_m: float) -> tuple:
    """Side by side, perpendicular to travel."""
    return (0.0, (index - 0.5) * spacing_m)


def _slot_column(index: int, spacing_m: float) -> tuple:
    """Nose to tail, following the leader."""
    return (-index * spacing_m, 0.0)


def _slot_v(index: int, spacing_m: float) -> tuple:
    """Classic V, alternating left and right behind the leader."""
    if index == 0:
        return (0.0, 0.0)
    rank = (index + 1) // 2
    side = 1.0 if index % 2 else -1.0
    return (-rank * spacing_m, side * rank * spacing_m * 0.5)


def _slot_circle(index: int, spacing_m: float, count: int) -> tuple:
    """Evenly spread on a ring whose radius fits the whole swarm."""
    radius = max(spacing_m, spacing_m * count / (2.0 * math.pi))
    angle = 2.0 * math.pi * index / max(1, count)
    return (radius * math.cos(angle), radius * math.sin(angle))


FORMATIONS: Dict[str, Callable[..., tuple]] = {
    "grid": _slot_grid,
    "line": _slot_line,
    "column": _slot_column,
    "v": _slot_v,
    "circle": _slot_circle,
}


def slot_offset(formation: str, index: int, count: int, spacing_m: float = 10.0) -> tuple:
    """Local (north, east) offset for a slot. Raises on an unknown formation."""
    if formation not in FORMATIONS:
        raise ValueError(f"unknown formation {formation!r}; have {sorted(FORMATIONS)}")
    fn = FORMATIONS[formation]
    if formation == "circle":
        return fn(index, spacing_m, count)
    return fn(index, spacing_m)


def formation_slots(
    drone_ids: List[str],
    formation: str,
    center: Position,
    spacing_m: float = 10.0,
) -> Dict[str, Position]:
    """Assign each drone id a target coordinate in the formation.

    Ids are sorted so every drone computes the identical assignment from the
    same membership list. Ties are broken by id, not by arrival order, because
    arrival order differs per drone.
    """
    ordered = sorted(drone_ids)
    count = len(ordered)
    out: Dict[str, Position] = {}
    for index, drone_id in enumerate(ordered):
        north, east = slot_offset(formation, index, count, spacing_m)
        out[drone_id] = offset_position(center, north_m=north, east_m=east, up_m=0.0)
    return out


def slot_for(
    drone_id: str,
    drone_ids: List[str],
    formation: str,
    center: Position,
    spacing_m: float = 10.0,
) -> Position:
    """This drone's own slot, without needing to look at the whole dict."""
    slots = formation_slots(drone_ids, formation, center, spacing_m)
    if drone_id not in slots:
        raise KeyError(f"{drone_id} is not in the formation membership list")
    return slots[drone_id]
