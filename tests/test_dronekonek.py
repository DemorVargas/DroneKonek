"""Test suite for DroneKonek. Pure stdlib, no broker, no hardware.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import math
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dronekonek.formation import formation_slots, slot_for, slot_offset
from dronekonek.geo import (
    Position,
    bearing,
    clamp_to_geofence,
    horizontal_distance,
    is_inside_geofence,
    offset_position,
    slant_distance,
)
from dronekonek.mavlink_link import MockMAVLinkLink
from dronekonek.messages import (
    Message,
    MessageError,
    MessageType,
    parse_topic,
    position_message,
    swarm_subscription,
)
from dronekonek.node import DroneNode
from dronekonek.simulator import build_swarm, run
from dronekonek.swarm import SwarmRegistry
from dronekonek.transport import InMemoryBroker, InMemoryTransport, _topic_matches


ORIGIN = Position(lat=47.397742, lon=8.545594, alt=0.0)


class TestGeo(unittest.TestCase):
    def test_zero_distance(self):
        self.assertAlmostEqual(horizontal_distance(ORIGIN, ORIGIN), 0.0, places=6)

    def test_known_distance_one_degree_lat(self):
        # One degree of latitude is ~111.19 km on the mean sphere.
        b = Position(lat=ORIGIN.lat + 1.0, lon=ORIGIN.lon)
        self.assertAlmostEqual(horizontal_distance(ORIGIN, b), 111195.0, delta=500.0)

    def test_offset_round_trip(self):
        moved = offset_position(ORIGIN, north_m=100.0, east_m=50.0)
        self.assertAlmostEqual(horizontal_distance(ORIGIN, moved), math.hypot(100.0, 50.0), delta=1.0)

    def test_offset_pure_north(self):
        moved = offset_position(ORIGIN, north_m=100.0)
        self.assertGreater(moved.lat, ORIGIN.lat)
        self.assertAlmostEqual(moved.lon, ORIGIN.lon, places=9)

    def test_slant_distance_uses_altitude(self):
        above = Position(lat=ORIGIN.lat, lon=ORIGIN.lon, alt=30.0)
        self.assertAlmostEqual(slant_distance(ORIGIN, above), 30.0, places=3)
        self.assertAlmostEqual(horizontal_distance(ORIGIN, above), 0.0, places=6)

    def test_bearing_cardinal(self):
        north = offset_position(ORIGIN, north_m=100.0)
        east = offset_position(ORIGIN, east_m=100.0)
        self.assertAlmostEqual(bearing(ORIGIN, north), 0.0, delta=1.0)
        self.assertAlmostEqual(bearing(ORIGIN, east), 90.0, delta=1.0)

    def test_geofence(self):
        inside = offset_position(ORIGIN, north_m=50.0)
        outside = offset_position(ORIGIN, north_m=500.0)
        self.assertTrue(is_inside_geofence(inside, ORIGIN, 100.0))
        self.assertFalse(is_inside_geofence(outside, ORIGIN, 100.0))

    def test_clamp_pulls_back_to_boundary(self):
        outside = offset_position(ORIGIN, north_m=500.0)
        clamped = clamp_to_geofence(outside, ORIGIN, 100.0)
        self.assertAlmostEqual(horizontal_distance(ORIGIN, clamped), 100.0, delta=1.0)

    def test_clamp_leaves_inside_alone(self):
        inside = offset_position(ORIGIN, north_m=50.0)
        self.assertEqual(clamp_to_geofence(inside, ORIGIN, 100.0), inside)


class TestMessages(unittest.TestCase):
    def test_round_trip(self):
        pos = Position(lat=1.5, lon=2.5, alt=10.0, heading=90.0, speed=3.0)
        msg = position_message("d1", "s1", pos, seq=7, battery=88.0)
        back = Message.from_json(msg.to_json())
        self.assertEqual(back.msg_type, MessageType.POSITION)
        self.assertEqual(back.drone_id, "d1")
        self.assertEqual(back.seq, 7)
        self.assertEqual(back.battery, 88.0)
        self.assertAlmostEqual(back.position.lat, 1.5)
        self.assertAlmostEqual(back.position.alt, 10.0)

    def test_topic_shape(self):
        msg = position_message("d1", "alpha", ORIGIN)
        self.assertEqual(msg.topic(), "dronekonek/v1/alpha/position/d1")
        parsed = parse_topic(msg.topic())
        self.assertEqual(parsed["swarm_id"], "alpha")
        self.assertEqual(parsed["drone_id"], "d1")

    def test_subscription_wildcard(self):
        self.assertEqual(swarm_subscription("alpha"), "dronekonek/v1/alpha/#")

    def test_rejects_garbage(self):
        for bad in ["", "not json", "[]", '{"type":"nope","drone_id":"a","swarm_id":"b"}']:
            with self.assertRaises(MessageError):
                Message.from_json(bad)

    def test_rejects_position_without_coords(self):
        with self.assertRaises(MessageError):
            Message.from_json('{"type":"position","drone_id":"a","swarm_id":"b"}')

    def test_rejects_out_of_range_lat(self):
        with self.assertRaises(MessageError):
            Message.from_json('{"type":"position","drone_id":"a","swarm_id":"b","position":{"lat":999,"lon":0}}')

    def test_accepts_bytes_payload(self):
        msg = position_message("d1", "s1", ORIGIN)
        self.assertEqual(Message.from_json(msg.to_json().encode()).drone_id, "d1")


class TestTransport(unittest.TestCase):
    def test_topic_matching(self):
        self.assertTrue(_topic_matches("a/b/#", "a/b/c/d"))
        self.assertTrue(_topic_matches("a/+/c", "a/b/c"))
        self.assertFalse(_topic_matches("a/+/c", "a/b/d"))
        self.assertFalse(_topic_matches("a/b", "a/b/c"))

    def test_pub_sub_delivers(self):
        broker = InMemoryBroker()
        got = []
        broker.subscribe("dronekonek/v1/s1/#", lambda t, p: got.append((t, p)))
        broker.publish("dronekonek/v1/s1/position/d1", b"x")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0][0], "dronekonek/v1/s1/position/d1")

    def test_transport_subscribe_after_start(self):
        broker = InMemoryBroker()
        t = InMemoryTransport(broker)
        t.start()
        got = []
        t.subscribe("a/#", lambda topic, payload: got.append(topic))
        t.publish("a/b", b"1")
        self.assertEqual(got, ["a/b"])


class TestSwarmRegistry(unittest.TestCase):
    def setUp(self):
        self.reg = SwarmRegistry(drone_id="me", swarm_id="s1", caution_m=30.0, warning_m=15.0, critical_m=5.0)
        self.reg.update_self(ORIGIN)

    def _msg(self, drone_id, north_m, east_m=0.0, alt=0.0, seq=1):
        pos = offset_position(ORIGIN, north_m=north_m, east_m=east_m, up_m=alt)
        return position_message(drone_id, "s1", pos, seq=seq)

    def test_ignores_own_messages(self):
        self.assertFalse(self.reg.observe(self._msg("me", 10.0)))

    def test_ignores_other_swarm(self):
        pos = offset_position(ORIGIN, north_m=10.0)
        msg = position_message("other", "different-swarm", pos)
        self.assertFalse(self.reg.observe(msg))

    def test_tracks_peer(self):
        self.assertTrue(self.reg.observe(self._msg("p1", 10.0)))
        self.assertEqual(len(self.reg.active_peers()), 1)

    def test_stale_sequence_dropped(self):
        self.reg.observe(self._msg("p1", 100.0, seq=5))
        self.assertFalse(self.reg.observe(self._msg("p1", 10.0, seq=4)))
        peer = self.reg.peers["p1"]
        # The old fix must not have overwritten the new one.
        self.assertAlmostEqual(horizontal_distance(ORIGIN, peer.position), 100.0, delta=2.0)

    def test_newer_sequence_accepted(self):
        self.reg.observe(self._msg("p1", 100.0, seq=5))
        self.assertTrue(self.reg.observe(self._msg("p1", 20.0, seq=6)))
        peer = self.reg.peers["p1"]
        self.assertAlmostEqual(horizontal_distance(ORIGIN, peer.position), 20.0, delta=2.0)

    def test_goodbye_removes_peer(self):
        self.reg.observe(self._msg("p1", 10.0))
        bye = Message(MessageType.GOODBYE, "p1", "s1")
        self.assertTrue(self.reg.observe(bye))
        self.assertEqual(len(self.reg.peers), 0)

    def test_collision_detected(self):
        self.reg.observe(self._msg("p1", 4.0))
        warnings = self.reg.collisions()
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].severity, "critical")
        self.assertEqual(warnings[0].other_id, "p1")

    def test_collision_severity_levels(self):
        self.reg.observe(self._msg("far", 25.0))
        self.assertEqual(self.reg.collisions()[0].severity, "caution")
        self.reg.observe(self._msg("mid", 10.0))
        sev = {w.other_id: w.severity for w in self.reg.collisions()}
        self.assertEqual(sev["mid"], "warning")
        self.assertEqual(sev["far"], "caution")

    def test_collision_includes_vertical(self):
        self.reg.observe(self._msg("above", 0.0, alt=3.0))
        w = self.reg.collisions()[0]
        self.assertAlmostEqual(w.distance_m, 3.0, delta=0.5)
        self.assertAlmostEqual(w.vertical_m, 3.0, delta=0.5)

    def test_collisions_sorted_worst_first(self):
        self.reg.observe(self._msg("near", 3.0))
        self.reg.observe(self._msg("mid", 12.0))
        self.assertEqual(self.reg.collisions()[0].other_id, "near")

    def test_separation_vector_points_away(self):
        # Peer is due north, so the push must be southward (negative north).
        self.reg.observe(self._msg("p1", 5.0))
        vec = self.reg.separation_vectors()["p1"]
        self.assertLess(vec[0], 0.0)
        self.assertAlmostEqual(vec[1], 0.0, delta=1.0)

    def test_separation_never_pushes_downward(self):
        # Two drones at the same altitude must not be told to dive to separate.
        self.reg.observe(self._msg("p1", 5.0))
        vec = self.reg.separation_vectors()["p1"]
        self.assertGreaterEqual(vec[2], 0.0)

    def test_separation_never_commands_below_ground(self):
        # Start low and close, so the naive vector would dig into the dirt.
        self.reg.update_self(Position(lat=ORIGIN.lat, lon=ORIGIN.lon, alt=1.0))
        self.reg.observe(self._msg("p1", 3.0, alt=1.0))
        from dronekonek.geo import offset_position as off
        n, e, u = self.reg.combined_separation()
        target = off(self.reg.self_position, north_m=n, east_m=e, up_m=u)
        self.assertGreaterEqual(target.alt, 0.0)

    def test_separation_stronger_when_closer(self):
        self.reg.observe(self._msg("p1", 25.0))
        far = abs(self.reg.separation_vectors()["p1"][0])
        self.reg.observe(self._msg("p1", 3.0, seq=2))
        near = abs(self.reg.separation_vectors()["p1"][0])
        self.assertGreater(near, far)

    def test_no_separation_when_clear(self):
        self.reg.observe(self._msg("p1", 500.0))
        self.assertEqual(self.reg.separation_vectors(), {})

    def test_prune_drops_silent_peer(self):
        self.reg.observe(self._msg("p1", 10.0), received_at=time.time() - 60.0)
        self.assertEqual(self.reg.prune(), ["p1"])
        self.assertEqual(len(self.reg.peers), 0)

    def test_centroid_includes_self(self):
        self.reg.observe(self._msg("p1", 100.0))
        c = self.reg.swarm_centroid()
        self.assertAlmostEqual(horizontal_distance(ORIGIN, c), 50.0, delta=2.0)

    def test_snapshot_is_json_serializable(self):
        self.reg.observe(self._msg("p1", 4.0))
        json.dumps(self.reg.snapshot())

    def test_dropped_counter(self):
        self.reg.observe(self._msg("p1", 10.0, seq=5))
        self.reg.observe(self._msg("p1", 10.0, seq=3))
        self.assertEqual(self.reg.dropped, 1)


class TestFormation(unittest.TestCase):
    def test_unknown_formation_raises(self):
        with self.assertRaises(ValueError):
            slot_offset("triangle", 0, 3, 10.0)

    def test_line_is_side_by_side(self):
        ids = ["a", "b", "c"]
        slots = formation_slots(ids, "line", ORIGIN, spacing_m=10.0)
        d_ab = horizontal_distance(slots["a"], slots["b"])
        self.assertAlmostEqual(d_ab, 10.0, delta=0.5)
        # Same latitude band, so a line really is lateral.
        self.assertAlmostEqual(slots["a"].lat, slots["b"].lat, places=5)

    def test_column_is_nose_to_tail(self):
        ids = ["a", "b"]
        slots = formation_slots(ids, "column", ORIGIN, spacing_m=10.0)
        self.assertGreater(slots["a"].lat, slots["b"].lat)
        self.assertAlmostEqual(horizontal_distance(slots["a"], slots["b"]), 10.0, delta=0.5)

    def test_assignment_is_order_independent(self):
        forward = formation_slots(["a", "b", "c"], "v", ORIGIN, 10.0)
        backward = formation_slots(["c", "b", "a"], "v", ORIGIN, 10.0)
        self.assertEqual(forward, backward)

    def test_v_leader_is_first(self):
        slots = formation_slots(["a", "b", "c"], "v", ORIGIN, 10.0)
        self.assertAlmostEqual(horizontal_distance(ORIGIN, slots["a"]), 0.0, delta=0.5)

    def test_circle_spreads_everyone(self):
        ids = [f"d{i}" for i in range(6)]
        slots = formation_slots(ids, "circle", ORIGIN, spacing_m=10.0)
        distances = [horizontal_distance(ORIGIN, p) for p in slots.values()]
        # All on the same ring.
        self.assertLess(max(distances) - min(distances), 1.0)

    def test_slot_for_matches_bulk(self):
        ids = ["a", "b", "c"]
        slots = formation_slots(ids, "grid", ORIGIN, 10.0)
        self.assertEqual(slot_for("b", ids, "grid", ORIGIN, 10.0), slots["b"])

    def test_slot_for_unknown_drone(self):
        with self.assertRaises(KeyError):
            slot_for("zz", ["a", "b"], "grid", ORIGIN, 10.0)


class TestMockLink(unittest.TestCase):
    def test_step_moves_toward_target(self):
        link = MockMAVLinkLink(ORIGIN)
        target = offset_position(ORIGIN, north_m=100.0)
        link.goto(target)
        # 5 m/s in 0.1s slices is 0.5m per step, so 100m needs 200 steps.
        for _ in range(200):
            link.step(0.1, speed_mps=5.0)
        pos = link.position()
        self.assertLess(horizontal_distance(pos, target), 5.0)

    def test_takeoff_sets_altitude(self):
        link = MockMAVLinkLink(ORIGIN)
        link.takeoff(25.0)
        self.assertAlmostEqual(link.position().alt, 25.0)

    def test_goto_counted(self):
        link = MockMAVLinkLink(ORIGIN)
        link.goto(offset_position(ORIGIN, north_m=10.0))
        self.assertEqual(link.goto_calls, 1)


class TestNode(unittest.TestCase):
    def _pair(self, gap_m):
        broker = InMemoryBroker()
        a = DroneNode("a", "s1", InMemoryTransport(broker), MockMAVLinkLink(ORIGIN), broadcast_hz=100.0)
        b = DroneNode(
            "b", "s1", InMemoryTransport(broker),
            MockMAVLinkLink(offset_position(ORIGIN, north_m=gap_m)), broadcast_hz=100.0,
        )
        return a, b

    def test_nodes_hear_each_other(self):
        a, b = self._pair(50.0)
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            self.assertEqual(len(a.peers()), 1)
            self.assertEqual(a.peers()[0].drone_id, "b")
        finally:
            a.stop()
            b.stop()

    def test_collision_callback_fires(self):
        a, b = self._pair(4.0)
        seen = []
        a.on_collision = lambda w: seen.append(w)
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            self.assertTrue(seen)
            self.assertEqual(seen[0].severity, "critical")
        finally:
            a.stop()
            b.stop()

    def test_avoidance_off_means_no_goto(self):
        a, b = self._pair(3.0)
        a.avoidance_enabled = False
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            self.assertEqual(a.link.goto_calls, 0)
        finally:
            a.stop()
            b.stop()

    def test_avoidance_on_commands_a_move(self):
        a, b = self._pair(3.0)
        a.avoidance_enabled = True
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            self.assertGreater(a.link.goto_calls, 0)
        finally:
            a.stop()
            b.stop()

    def test_avoidance_respects_geofence(self):
        a, b = self._pair(3.0)
        a.avoidance_enabled = True
        a.geofence_center = ORIGIN
        a.geofence_radius_m = 1.0  # absurdly tight: the move must be clamped
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            target = a.link._target
            self.assertIsNotNone(target)
            self.assertLessEqual(horizontal_distance(ORIGIN, target), 1.0 + 0.5)
        finally:
            a.stop()
            b.stop()

    def test_avoidance_move_never_goes_underground(self):
        a, b = self._pair(3.0)
        a.avoidance_enabled = True
        a.link.set_position(Position(lat=ORIGIN.lat, lon=ORIGIN.lon, alt=1.0))
        a.registry.update_self(a.link.position())
        b.link.set_position(offset_position(ORIGIN, north_m=3.0, up_m=1.0))
        b.registry.update_self(b.link.position())
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            target = a.link._target
            self.assertIsNotNone(target)
            self.assertGreaterEqual(target.alt, 0.0)
        finally:
            a.stop()
            b.stop()

    def test_bad_payload_is_counted_not_crashed(self):
        a, b = self._pair(50.0)
        a.start()
        try:
            a._on_wire_message("dronekonek/v1/s1/position/zz", b"{not json")
            self.assertEqual(a.stats["dropped"], 1)
        finally:
            a.stop()
            b.stop()

    def test_goodbye_clears_peer(self):
        a, b = self._pair(50.0)
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            self.assertEqual(len(a.peers()), 1)
            b.stop()
            for _ in range(3):
                a.tick()
            self.assertEqual(len(a.peers()), 0)
        finally:
            a.stop()

    def test_snapshot_json_serializable(self):
        a, b = self._pair(50.0)
        a.start()
        b.start()
        try:
            for _ in range(5):
                a.tick()
                b.tick()
            json.dumps(a.snapshot())
        finally:
            a.stop()
            b.stop()

    def test_requires_transport(self):
        node = DroneNode("a", "s1", transport=None, link=MockMAVLinkLink(ORIGIN))
        with self.assertRaises(RuntimeError):
            node.start()


class TestSimulator(unittest.TestCase):
    def test_build_swarm(self):
        nodes = build_swarm(count=4)
        self.assertEqual(len(nodes), 4)
        self.assertEqual([n.drone_id for n in nodes], ["drone-01", "drone-02", "drone-03", "drone-04"])

    def test_short_flight_produces_report(self):
        report = run(count=3, seconds=3.0, verbose=False)
        self.assertEqual(report["drones"], 3)
        self.assertEqual(len(report["final"]), 3)
        for snap in report["final"]:
            self.assertGreaterEqual(snap["peer_count"], 1)

    def test_formation_flight_keeps_them_apart(self):
        report = run(count=4, seconds=12.0, formation="line", verbose=False, speed_mps=6.0)
        # Spacing is 10m and the warning line is half of caution; nothing should
        # be critically close in a line formation.
        critical = [e for e in report["events"] if e["severity"] == "critical"]
        self.assertEqual(critical, [])

    def test_drones_actually_move(self):
        report = run(count=2, seconds=8.0, verbose=False, altitude_m=20.0)
        for snap in report["final"]:
            self.assertAlmostEqual(snap["position"]["alt"], 20.0, delta=0.5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
