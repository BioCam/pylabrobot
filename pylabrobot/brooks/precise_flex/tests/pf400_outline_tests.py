import unittest
from typing import Sequence, Tuple

from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis, pf400_end_effector

Outline = Sequence[Tuple[float, float]]

# Each outline, its part's cuboid, and how far the outline may stand outside that cuboid, in mm.
OUTLINES: Tuple[Tuple[str, Outline, Tuple[float, ...], float], ...] = (
  ("column", pf400_chassis.Z_COLUMN_OUTLINE, pf400_chassis.Z_COLUMN_SIZE_XY, 0.5),
  ("body", pf400_end_effector.GRIPPER_BODY_OUTLINE, pf400_end_effector.GRIPPER_BODY_SIZE, 0.5),
)


def area(outline: Outline) -> float:
  following = list(outline[1:]) + list(outline[:1])
  return sum(x_1 * y_2 - x_2 * y_1 for (x_1, y_1), (x_2, y_2) in zip(outline, following)) / 2


class TestOutlines(unittest.TestCase):
  """A part seen from above, where its cuboid says more than the part covers."""

  def test_an_outline_lies_about_its_parts_cuboid(self):
    for name, outline, size, outside in OUTLINES:
      with self.subTest(part=name):
        for x, y in outline:
          self.assertTrue(-outside <= x <= size[0] + outside, (x, y))
          self.assertTrue(-outside <= y <= size[1] + outside, (x, y))

  def test_an_outline_runs_counter_clockwise_and_never_turns_back(self):
    for name, outline, _, _ in OUTLINES:
      with self.subTest(part=name):
        self.assertGreater(area(outline), 0.0)
        count = len(outline)
        for index in range(count):
          (x_1, y_1), (x_2, y_2), (x_3, y_3) = (
            outline[(index + step) % count] for step in range(3)
          )
          self.assertGreaterEqual((x_2 - x_1) * (y_3 - y_2) - (y_2 - y_1) * (x_3 - x_2), 0.0)

  def test_an_outline_covers_less_than_the_box_around_it(self):
    for name, outline, _, _ in OUTLINES:
      with self.subTest(part=name):
        size_x = max(x for x, _ in outline) - min(x for x, _ in outline)
        size_y = max(y for _, y in outline) - min(y for _, y in outline)
        self.assertLess(area(outline), size_x * size_y)
        self.assertGreater(area(outline), 0.75 * size_x * size_y)
