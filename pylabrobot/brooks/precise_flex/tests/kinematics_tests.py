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
