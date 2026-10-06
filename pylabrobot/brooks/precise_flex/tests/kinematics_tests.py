import math
import unittest

from pylabrobot.brooks.precise_flex import kinematics


class TestClassifyPF400Reach(unittest.TestCase):
  """Link lengths are classified as standard, extended, or unknown reach."""

  def test_classify_pf400_reach(self):
    self.assertEqual(kinematics._classify_pf400_reach((225, 210)), "standard")
    self.assertEqual(kinematics._classify_pf400_reach((302, 289)), "extended")
    self.assertEqual(kinematics._classify_pf400_reach((303, 288)), "extended")  # within tolerance
    self.assertEqual(kinematics._classify_pf400_reach((500, 500)), "unknown")


class TestOutlineClearance(unittest.TestCase):
  """How far apart two convex outlines stand, and how deep they overlap."""

  SQUARE = [(0.0, 0.0), (10.0, 0.0), (10.0, 10.0), (0.0, 10.0)]

  def moved(self, x: float, y: float):
    return [(point_x + x, point_y + y) for point_x, point_y in self.SQUARE]

  def test_apart_is_the_gap_between_them(self):
    self.assertAlmostEqual(
      kinematics.compute_outline_clearance(self.SQUARE, self.moved(13.0, 0.0)), 3.0
    )
    self.assertAlmostEqual(
      kinematics.compute_outline_clearance(self.moved(0.0, -17.0), self.SQUARE), 7.0
    )

  def test_overlapping_is_negative_by_how_deep(self):
    self.assertAlmostEqual(
      kinematics.compute_outline_clearance(self.SQUARE, self.moved(8.0, 1.0)), -2.0
    )

  def test_it_is_never_more_than_the_true_distance(self):
    # Corner to corner the squares are 5 mm apart; the widest gap an edge leaves is 4 mm.
    self.assertAlmostEqual(
      kinematics.compute_outline_clearance(self.SQUARE, self.moved(14.0, 13.0)), 4.0
    )


class TestElbowAndWrist(unittest.TestCase):
  """Where the two joints stand: the one place the links' trigonometry is written."""

  def test_stretched_out_folded_back_and_turned(self):
    p = kinematics.PF400Params()  # links 302 and 289
    for shoulder, elbow, want_elbow, want_wrist in (
      (0.0, 0.0, (302.0, 0.0), (591.0, 0.0)),
      (0.0, 180.0, (302.0, 0.0), (13.0, 0.0)),
      (90.0, 0.0, (0.0, 302.0), (0.0, 591.0)),
      (0.0, 90.0, (302.0, 0.0), (302.0, 289.0)),
    ):
      got_elbow, got_wrist = kinematics.compute_elbow_and_wrist(
        p, math.radians(shoulder), math.radians(elbow)
      )
      for got, want in ((got_elbow, want_elbow), (got_wrist, want_wrist)):
        self.assertAlmostEqual(got[0], want[0])
        self.assertAlmostEqual(got[1], want[1])

  def test_the_gripper_pose_is_the_wrist_joint_and_the_tool_beyond_it(self):
    p = kinematics.PF400Params(gripper_length=162.0)
    joints = {
      kinematics.Axis.BASE: 100.0,
      kinematics.Axis.SHOULDER: 30.0,
      kinematics.Axis.ELBOW: 70.0,
      kinematics.Axis.WRIST: -40.0,
    }
    _, wrist = kinematics.compute_elbow_and_wrist(p, math.radians(30.0), math.radians(70.0))
    pose = kinematics.fk(joints, p)
    yaw = math.radians(30.0 + 70.0 - 40.0)
    # A coordinate keeps four decimal places.
    self.assertAlmostEqual(pose.location.x, wrist[0] + 162.0 * math.cos(yaw), places=3)
    self.assertAlmostEqual(pose.location.y, wrist[1] + 162.0 * math.sin(yaw), places=3)
