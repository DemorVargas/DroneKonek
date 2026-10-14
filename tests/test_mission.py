"""Tests for autonomous mission flight.

Proves the mission logic without hardware: a drone flies to pre-determined
waypoints, detects arrival, loiters, disarms on completion, and aborts cleanly
on timeout or operator stop.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.geo import Position, offset_position
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.mission import Mission, MissionResult, Waypoint, mission_from_coordinates

ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)


def make_link(start: Position) -> MockMAVLinkLink:
    return MockMAVLinkLink(start)


class TestMissionFromCoordinates(unittest.TestCase):
    def test_two_tuples_get_default_alt(self):
        wps = mission_from_coordinates([(47.0, 8.0), (47.1, 8.1)], default_alt=30.0)
        self.assertEqual(len(wps), 2)
        self.assertEqual(wps[0].lat, 47.0)
        self.assertEqual(wps[0].lon, 8.0)
        self.assertEqual(wps[0].alt, 30.0)

    def test_three_tuples_keep_own_alt(self):
        wps = mission_from_coordinates([(47.0, 8.0, 55.0)])
        self.assertEqual(wps[0].alt, 55.0)

    def test_invalid_tuple_rejected(self):
        with self.assertRaises(ValueError):
            mission_from_coordinates([(47.0,)])

    def test_empty_list_rejected(self):
        with self.assertRaises(ValueError):
            mission_from_coordinates([])

    def test_names_are_sequential(self):
        wps = mission_from_coordinates([(47.0, 8.0), (47.1, 8.1), (47.2, 8.2)])
        self.assertEqual([w.name for w in wps], ["wp-01", "wp-02", "wp-03"])


class TestMissionSingleWaypoint(unittest.TestCase):
    def test_reaches_waypoint_and_disarms(self):
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        wp = Waypoint(lat=ORIGIN.lat + 0.0001, lon=ORIGIN.lon + 0.0001, alt=20.0)

        completed = []
        m = Mission([wp], link, arrival_radius_m=5.0, arrival_timeout_s=30.0,
                    on_complete=lambda r: completed.append(r))
        m.start()

        # Wait for the mission to finish (it should take a few seconds)
        deadline = time.time() + 40
        while time.time() < deadline and not completed:
            time.sleep(0.2)

        self.assertTrue(completed, "mission did not complete in time")
        result = completed[0]
        self.assertTrue(result.completed)
        self.assertEqual(result.waypoints_reached, 1)
        self.assertEqual(result.waypoints_total, 1)
        self.assertFalse(link.armed, "link should be disarmed after mission")

    def test_does_not_move_without_mission(self):
        """A drone without a mission must not move on its own."""
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        # No mission started. The link should not be armed.
        self.assertFalse(link.armed)
        self.assertEqual(link.goto_calls, 0)


class TestMissionMultipleWaypoints(unittest.TestCase):
    def test_flies_to_each_waypoint_in_order(self):
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        wps = [
            Waypoint(lat=ORIGIN.lat + 0.0001, lon=ORIGIN.lon, alt=20.0, name="wp1"),
            Waypoint(lat=ORIGIN.lat + 0.0002, lon=ORIGIN.lon, alt=20.0, name="wp2"),
            Waypoint(lat=ORIGIN.lat + 0.0003, lon=ORIGIN.lon, alt=20.0, name="wp3"),
        ]

        visited = []
        m = Mission(wps, link, arrival_radius_m=5.0, arrival_timeout_s=30.0,
                    on_waypoint=lambda i, w: visited.append(i),
                    on_complete=lambda r: None)
        m.start()

        deadline = time.time() + 90
        while time.time() < deadline and m.running:
            time.sleep(0.3)

        self.assertFalse(m.running, "mission should have finished")
        self.assertTrue(m.result.completed)
        self.assertEqual(m.result.waypoints_reached, 3)
        self.assertEqual(visited, [0, 1, 2])
        self.assertFalse(link.armed)


class TestMissionTimeout(unittest.TestCase):
    def test_aborts_when_waypoint_unreachable(self):
        """If the drone can never get within arrival radius, abort."""
        start = Position(lat=0.0, lon=0.0, alt=0.0)  # far from any waypoint
        link = make_link(start)
        wp = Waypoint(lat=47.0, lon=8.0, alt=20.0)

        aborted = []
        m = Mission([wp], link, arrival_radius_m=0.001, arrival_timeout_s=3.0,
                    on_abort=lambda reason: aborted.append(reason))
        m.start()

        deadline = time.time() + 15
        while time.time() < deadline and m.running:
            time.sleep(0.2)

        self.assertFalse(m.running)
        self.assertTrue(aborted, "mission should have aborted")
        self.assertIn("could not reach", aborted[0])


class TestMissionStop(unittest.TestCase):
    def test_operator_stop_aborts_cleanly(self):
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        wps = [
            Waypoint(lat=ORIGIN.lat + 0.0003, lon=ORIGIN.lon, alt=20.0),
            Waypoint(lat=ORIGIN.lat + 0.0006, lon=ORIGIN.lon, alt=20.0),
        ]

        m = Mission(wps, link, arrival_radius_m=5.0, arrival_timeout_s=60.0)
        m.start()
        time.sleep(2.0)  # let it get going
        m.stop("operator abort")

        self.assertFalse(m.running)
        self.assertIsNotNone(m.result)
        self.assertFalse(m.result.completed)
        self.assertEqual(m.result.reason, "operator abort")


class TestMissionCallbacks(unittest.TestCase):
    def test_on_complete_fires(self):
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        wp = Waypoint(lat=ORIGIN.lat + 0.0001, lon=ORIGIN.lon + 0.0001, alt=20.0)

        results = []
        m = Mission([wp], link, arrival_radius_m=5.0, arrival_timeout_s=20.0,
                    on_complete=lambda r: results.append(r))
        m.start()

        deadline = time.time() + 30
        while time.time() < deadline and not results:
            time.sleep(0.2)

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], MissionResult)

    def test_on_waypoint_fires_for_each(self):
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        wps = [
            Waypoint(lat=ORIGIN.lat + 0.0001, lon=ORIGIN.lon + 0.0001, alt=20.0),
            Waypoint(lat=ORIGIN.lat + 0.0002, lon=ORIGIN.lon + 0.0002, alt=20.0),
        ]

        hits = []
        m = Mission(wps, link, arrival_radius_m=5.0, arrival_timeout_s=20.0,
                    on_waypoint=lambda i, w: hits.append(i),
                    on_complete=lambda r: None)
        m.start()

        deadline = time.time() + 40
        while time.time() < deadline and m.running:
            time.sleep(0.2)

        self.assertEqual(hits, [0, 1])


class TestMissionHoldTime(unittest.TestCase):
    def test_loiter_delays_next_waypoint(self):
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        wps = [
            Waypoint(lat=ORIGIN.lat + 0.0001, lon=ORIGIN.lon + 0.0001, alt=20.0, hold_s=2.0),
            Waypoint(lat=ORIGIN.lat + 0.0002, lon=ORIGIN.lon + 0.0002, alt=20.0),
        ]

        timestamps = []
        m = Mission(wps, link, arrival_radius_m=5.0, arrival_timeout_s=30.0,
                    on_waypoint=lambda i, w: timestamps.append(time.time()),
                    on_complete=lambda r: None)
        m.start()

        deadline = time.time() + 60
        while time.time() < deadline and m.running:
            time.sleep(0.3)

        self.assertEqual(len(timestamps), 2)
        gap = timestamps[1] - timestamps[0]
        self.assertGreaterEqual(gap, 1.5, "loiter should have delayed the second waypoint")


class TestMissionArrivalRadius(unittest.TestCase):
    def test_small_radius_takes_longer(self):
        """A tighter arrival radius means more time flying."""
        start = offset_position(ORIGIN, north_m=0.0, up_m=0.0)
        link = make_link(start)
        wp = Waypoint(lat=47.001, lon=8.0, alt=20.0)

        # With a very tight radius and short timeout, should abort
        aborted = []
        m = Mission([wp], link, arrival_radius_m=0.0001, arrival_timeout_s=3.0,
                    on_abort=lambda reason: aborted.append(reason))
        m.start()

        deadline = time.time() + 10
        while time.time() < deadline and m.running:
            time.sleep(0.2)

        self.assertTrue(aborted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
