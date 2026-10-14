"""Autonomous mission: fly to pre-determined waypoints and shut down on arrival.

The coordinates come from satellite image analysis done offline. You feed the
mission a list of (lat, lon, alt) tuples, the drone flies to each one in order,
and when it reaches the final waypoint it disarms and shuts down.

This is opt-in. A drone without a mission behaves exactly as before: it shares
its position, warns about conflicts, and does not move unless avoidance is
explicitly enabled.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from dronekonek.geo import Position, horizontal_distance

log = logging.getLogger("dronekonek.mission")


@dataclass
class Waypoint:
    """One stop on the mission."""

    lat: float
    lon: float
    alt: float = 20.0
    hold_s: float = 0.0  # seconds to loiter at this waypoint before proceeding
    name: str = ""

    def to_position(self) -> Position:
        return Position(lat=self.lat, lon=self.lon, alt=self.alt)


@dataclass
class MissionResult:
    """What happened when the mission ran."""

    completed: bool
    waypoints_total: int
    waypoints_reached: int
    final_position: Optional[Position] = None
    reason: str = ""


class Mission:
    """A sequence of waypoints the drone flies autonomously.

    Call ``start()`` to begin, ``stop()`` to abort. The mission runs in its
    own thread and calls back into the link for goto/disarm operations.
    """

    def __init__(
        self,
        waypoints: List[Waypoint],
        link,
        arrival_radius_m: float = 3.0,
        arrival_timeout_s: float = 120.0,
        on_waypoint: Optional[Callable[[int, Waypoint], None]] = None,
        on_complete: Optional[Callable[[MissionResult], None]] = None,
        on_abort: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not waypoints:
            raise ValueError("mission needs at least one waypoint")
        self.waypoints = list(waypoints)
        self.link = link
        self.arrival_radius_m = arrival_radius_m
        self.arrival_timeout_s = arrival_timeout_s
        self.on_waypoint = on_waypoint
        self.on_complete = on_complete
        self.on_abort = on_abort

        self._current = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._stop_reason = "operator abort"
        self._lock = threading.RLock()
        self._result: Optional[MissionResult] = None

    @property
    def current_index(self) -> int:
        with self._lock:
            return self._current

    @property
    def running(self) -> bool:
        return self._running

    @property
    def result(self) -> Optional[MissionResult]:
        return self._result

    def start(self) -> None:
        """Arm, take off, and fly the mission."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._current = 0
            self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run, name=f"mission-{id(self):x}", daemon=True
        )
        self._thread.start()
        log.info("mission started: %d waypoints", len(self.waypoints))

    def stop(self, reason: str = "operator abort") -> None:
        """Abort the mission. The drone loiters in place."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_reason = reason
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        log.info("mission aborted: %s", reason)

    def _run(self) -> None:
        """The mission loop: fly to each waypoint, then disarm."""
        try:
            self._arm_and_takeoff()
            for i, wp in enumerate(self.waypoints):
                if self._stop_event.is_set():
                    self._abort(self._stop_reason)
                    return

                with self._lock:
                    self._current = i

                if self.on_waypoint is not None:
                    try:
                        self.on_waypoint(i, wp)
                    except Exception:
                        log.exception("on_waypoint callback failed")

                reached = self._fly_to(wp, i)
                if not reached:
                    if self._stop_event.is_set():
                        self._abort(self._stop_reason)
                    else:
                        self._abort("could not reach waypoint %d within %.0fs" % (i + 1, self.arrival_timeout_s))
                    return

                if wp.hold_s > 0:
                    self._loiter(wp.hold_s)

            # All waypoints reached. Disarm and shut down.
            self._complete()
        except Exception as exc:
            log.exception("mission thread failed")
            self._abort(str(exc))

    def _arm_and_takeoff(self) -> None:
        """Arm the motors and take off to the first waypoint's altitude."""
        first = self.waypoints[0]
        alt = max(first.alt, 5.0)  # never take off below 5m
        log.info("arming and taking off to %.1fm", alt)
        self.link.arm()
        self.link.set_mode("GUIDED")
        self.link.takeoff(alt)
        # Give the autopilot a moment to switch modes and begin takeoff
        time.sleep(2.0)

    def _fly_to(self, wp: Waypoint, index: int) -> bool:
        """Fly to one waypoint. Returns True if arrived, False on timeout."""
        target = wp.to_position()
        log.info("flying to waypoint %d/%d: %s (%.1fm)",
                 index + 1, len(self.waypoints), wp.name or "unnamed", wp.alt)

        self.link.goto(target)
        deadline = time.time() + self.arrival_timeout_s

        while time.time() < deadline:
            if self._stop_event.is_set():
                return False

            pos = self.link.position()
            if pos is not None:
                dist = horizontal_distance(pos, target)
                alt_diff = abs(pos.alt - target.alt)
                if dist <= self.arrival_radius_m and alt_diff <= 5.0:
                    log.info("reached waypoint %d (%.1fm from target)", index + 1, dist)
                    return True

            time.sleep(0.5)

        return False

    def _loiter(self, seconds: float) -> None:
        """Hold position for a few seconds."""
        log.info("loitering for %.1fs", seconds)
        deadline = time.time() + seconds
        while time.time() < deadline and not self._stop_event.is_set():
            time.sleep(0.2)

    def _complete(self) -> None:
        """Disarm and report success."""
        final_pos = self.link.position()
        log.info("mission complete: all %d waypoints reached, disarming", len(self.waypoints))

        try:
            self.link.set_mode("LAND")
            time.sleep(1.0)
        except Exception:
            log.warning("could not set LAND mode before disarm", exc_info=True)
        try:
            self.link.disarm()
        except Exception:
            log.exception("disarm failed")

        result = MissionResult(
            completed=True,
            waypoints_total=len(self.waypoints),
            waypoints_reached=len(self.waypoints),
            final_position=final_pos,
            reason="all waypoints reached",
        )
        with self._lock:
            self._result = result
            self._running = False

        if self.on_complete is not None:
            try:
                self.on_complete(result)
            except Exception:
                log.exception("on_complete callback failed")

    def _abort(self, reason: str) -> None:
        """Report failure. The drone loiters in place."""
        final_pos = self.link.position()
        log.warning("mission aborted: %s", reason)

        result = MissionResult(
            completed=False,
            waypoints_total=len(self.waypoints),
            waypoints_reached=self._current,
            final_position=final_pos,
            reason=reason,
        )
        with self._lock:
            self._result = result
            self._running = False

        if self.on_abort is not None:
            try:
                self.on_abort(reason)
            except Exception:
                log.exception("on_abort callback failed")


def mission_from_coordinates(
    coordinates: list,
    default_alt: float = 20.0,
    arrival_radius_m: float = 3.0,
) -> List[Waypoint]:
    """Build a waypoint list from raw (lat, lon) or (lat, lon, alt) tuples.

    This is the bridge from satellite image analysis: you extract target
    coordinates from imagery, pass them here, and get a mission plan.
    """
    if not coordinates:
        raise ValueError("coordinates list cannot be empty")
    waypoints: List[Waypoint] = []
    for i, coord in enumerate(coordinates):
        if len(coord) == 2:
            lat, lon = coord
            alt = default_alt
        elif len(coord) == 3:
            lat, lon, alt = coord
        else:
            raise ValueError(
                "coordinate %d must be (lat, lon) or (lat, lon, alt), got %r" % (i, coord)
            )
        waypoints.append(Waypoint(lat=lat, lon=lon, alt=alt, name=f"wp-{i + 1:02d}"))
    return waypoints
