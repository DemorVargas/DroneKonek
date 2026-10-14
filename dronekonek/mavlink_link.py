"""MAVLink bridge: where the drone's own autopilot meets the swarm.

Talks to ArduPilot or PX4 over a serial port, UDP, or TCP, reads the live
position, and can command a goto. The swarm layer above never touches MAVLink
directly, so the same code runs against a simulator, a Pixhawk, or a mock.

Needs pymavlink:  pip install 'dronekonek[mavlink]'
"""

from __future__ import annotations

import math
import threading
import time
from typing import Optional

from dronekonek.geo import Position

DEFAULT_BAUD = 57600


class MAVLinkLink:
    """A live connection to one autopilot."""

    def __init__(
        self,
        connection: str = "udp:127.0.0.1:14550",
        baud: int = DEFAULT_BAUD,
        source_system: int = 255,
        wait_heartbeat_s: float = 30.0,
    ) -> None:
        self.connection = connection
        self.baud = baud
        self.source_system = source_system
        self.wait_heartbeat_s = wait_heartbeat_s
        self._master = None
        self._lock = threading.RLock()
        self._target_system = 1
        self._target_component = 1
        self._last_position: Optional[Position] = None

    # ---- lifecycle ------------------------------------------------------

    def connect(self) -> None:
        from pymavlink import mavutil

        if self.connection.startswith(("udp:", "tcp:", "udpin:", "udpout:")):
            self._master = mavutil.mavlink_connection(self.connection, source_system=self.source_system)
        else:
            self._master = mavutil.mavlink_connection(
                self.connection, baud=self.baud, source_system=self.source_system
            )
        # Blocks until the autopilot says hello. Without this, the first goto
        # goes into the void and the operator blames the swarm code.
        self._master.wait_heartbeat(timeout=self.wait_heartbeat_s)
        self._target_system = self._master.target_system
        self._target_component = self._master.target_component

    def close(self) -> None:
        with self._lock:
            if self._master is not None:
                self._master.close()
                self._master = None

    @property
    def connected(self) -> bool:
        return self._master is not None

    # ---- read -----------------------------------------------------------

    def position(self) -> Optional[Position]:
        """Latest known position, from the message stream with no blocking."""
        from pymavlink import mavutil

        if self._master is None:
            raise RuntimeError("not connected")
        msg = self._master.recv_match(
            type=["GLOBAL_POSITION_INT", "GPS_RAW_INT"], blocking=False
        )
        if msg is not None:
            self._last_position = self._decode_position(msg)
        return self._last_position

    def position_blocking(self, timeout: float = 5.0) -> Optional[Position]:
        """Wait for one fresh position. Use at startup, not in the main loop."""
        from pymavlink import mavutil

        if self._master is None:
            raise RuntimeError("not connected")
        msg = self._master.recv_match(
            type=["GLOBAL_POSITION_INT", "GPS_RAW_INT"], blocking=True, timeout=timeout
        )
        if msg is None:
            return None
        self._last_position = self._decode_position(msg)
        return self._last_position

    def _decode_position(self, msg) -> Optional[Position]:
        kind = msg.get_type()
        if kind == "GLOBAL_POSITION_INT":
            return Position(
                lat=msg.lat / 1e7,
                lon=msg.lon / 1e7,
                alt=msg.relative_alt / 1000.0,
                heading=(msg.hdg / 100.0) if msg.hdg != 65535 else 0.0,
                speed=math.hypot(msg.vx, msg.vy) / 100.0,
            )
        if kind == "GPS_RAW_INT":
            return Position(
                lat=msg.lat / 1e7,
                lon=msg.lon / 1e7,
                alt=msg.alt / 1000.0,
                heading=(msg.cog / 100.0) if getattr(msg, "cog", 65535) != 65535 else 0.0,
                speed=msg.vel / 100.0 if getattr(msg, "vel", 0) else 0.0,
            )
        return None

    def battery_percent(self) -> Optional[float]:
        if self._master is None:
            raise RuntimeError("not connected")
        msg = self._master.recv_match(type="SYS_STATUS", blocking=False)
        if msg is None or not msg.voltage_battery:
            return None
        return float(msg.battery_remaining) if msg.battery_remaining >= 0 else None

    # ---- command --------------------------------------------------------

    def goto(self, target: Position, hold_s: float = 0.0) -> None:
        """Send the drone to a coordinate (GUIDED mode, ArduPilot/PX4)."""
        from pymavlink import mavutil

        if self._master is None:
            raise RuntimeError("not connected")
        with self._lock:
            self._master.mav.set_position_target_global_int_send(
                0,  # time_boot_ms, ignored
                self._target_system,
                self._target_component,
                mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
                0b0000111111111000,  # position only, ignore velocity/accel/yaw
                int(target.lat * 1e7),
                int(target.lon * 1e7),
                float(target.alt),
                0, 0, 0,
                0, 0, 0,
                math.radians(target.heading), 0,
            )

    def set_mode(self, mode: str) -> None:
        from pymavlink import mavutil

        if self._master is None:
            raise RuntimeError("not connected")
        mapping = self._master.mode_mapping() or {}
        if mode not in mapping:
            raise ValueError(f"autopilot does not know mode {mode!r}; has {sorted(mapping)}")
        with self._lock:
            self._master.set_mode(mapping[mode])

    def arm(self, force: bool = False) -> None:
        if self._master is None:
            raise RuntimeError("not connected")
        with self._lock:
            self._master.arducopter_arm()
            if force:
                self._master.motors_armed_wait()

    def disarm(self) -> None:
        if self._master is None:
            raise RuntimeError("not connected")
        with self._lock:
            self._master.arducopter_disarm()

    def takeoff(self, altitude_m: float) -> None:
        if self._master is None:
            raise RuntimeError("not connected")
        with self._lock:
            self._master.mav.command_long_send(
                self._target_system,
                self._target_component,
                22,  # MAV_CMD_NAV_TAKEOFF
                0, 0, 0, 0, 0, 0, 0,
                float(altitude_m),
            )

    def request_streams(self, rate_hz: int = 4) -> None:
        """Ask the autopilot for a steady position stream instead of polling blind."""
        if self._master is None:
            raise RuntimeError("not connected")
        with self._lock:
            self._master.mav.request_data_stream_send(
                self._target_system,
                self._target_component,
                0,  # MAV_DATA_STREAM_ALL
                rate_hz,
                1,  # start
            )


class MockMAVLinkLink:
    """Drop-in stand-in for MAVLinkLink: no hardware, no pymavlink.

    Used by the simulator and the tests so the swarm loop can be exercised
    end to end on a laptop. Implements exactly the surface DroneNode calls.
    """

    def __init__(self, position: Optional[Position] = None) -> None:
        self._position = position or Position(lat=47.397742, lon=8.545594, alt=0.0)
        self._target: Optional[Position] = None
        self.armed = False
        self.mode = "STABILIZE"
        self.goto_calls = 0
        self.takeoff_calls = 0
        self._lock = threading.RLock()

    def connect(self) -> None:
        pass

    def close(self) -> None:
        pass

    @property
    def connected(self) -> bool:
        return True

    def position(self) -> Optional[Position]:
        # Simulate autopilot movement toward the target on each poll.
        # This is what the real autopilot does: it flies the goto command
        # and reports its position via GLOBAL_POSITION_INT.
        with self._lock:
            if self._target is not None and self.armed:
                from dronekonek.geo import bearing, horizontal_distance, offset_position
                dist = horizontal_distance(self._position, self._target)
                if dist > 0.5:
                    step_m = min(dist, 5.0 * 0.5)  # 5 m/s, polled every 0.5s
                    brg = math.radians(bearing(self._position, self._target))
                    self._position = offset_position(
                        self._position,
                        north_m=math.cos(brg) * step_m,
                        east_m=math.sin(brg) * step_m,
                        up_m=max(-5.0 * 0.5, min(self._target.alt - self._position.alt, 5.0 * 0.5)),
                    )
                    self._position = Position(
                        lat=self._position.lat,
                        lon=self._position.lon,
                        alt=self._position.alt,
                        heading=bearing(self._position, self._target),
                        speed=5.0,
                    )
        return self._position

    def position_blocking(self, timeout: float = 5.0) -> Optional[Position]:
        return self._position

    def battery_percent(self) -> Optional[float]:
        return 100.0

    def set_position(self, position: Position) -> None:
        with self._lock:
            self._position = position

    def step(self, dt: float, speed_mps: float = 5.0) -> None:
        """Fly toward the last commanded target. The simulator's physics."""
        with self._lock:
            if self._target is None:
                return
            from dronekonek.geo import bearing, horizontal_distance, offset_position

            dist = horizontal_distance(self._position, self._target)
            if dist < 0.5:
                return
            step_m = min(dist, speed_mps * dt)
            brg = math.radians(bearing(self._position, self._target))
            self._position = offset_position(
                self._position,
                north_m=math.cos(brg) * step_m,
                east_m=math.sin(brg) * step_m,
                up_m=max(-speed_mps * dt, min(self._target.alt - self._position.alt, speed_mps * dt)),
            )
            self._position = Position(
                lat=self._position.lat,
                lon=self._position.lon,
                alt=self._position.alt,
                heading=bearing(self._position, self._target),
                speed=speed_mps,
            )

    def goto(self, target: Position, hold_s: float = 0.0) -> None:
        with self._lock:
            self._target = target
            self.goto_calls += 1

    def set_mode(self, mode: str) -> None:
        valid_modes = {"STABILIZE", "GUIDED", "LAND", "RTL", "AUTO", "LOITER"}
        if mode not in valid_modes:
            raise ValueError(f"unknown mode: {mode}")
        self.mode = mode

    def arm(self, force: bool = False) -> None:
        self.armed = True

    def disarm(self) -> None:
        self.armed = False

    def takeoff(self, altitude_m: float) -> None:
        self.takeoff_calls += 1
        self._position = Position(
            lat=self._position.lat, lon=self._position.lon, alt=altitude_m,
            heading=self._position.heading, speed=self._position.speed,
        )

    def request_streams(self, rate_hz: int = 4) -> None:
        pass
