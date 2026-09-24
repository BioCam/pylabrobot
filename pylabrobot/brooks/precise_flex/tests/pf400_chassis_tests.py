import unittest

from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis
from pylabrobot.resources.coordinate import Coordinate


class TestTheShoulderAxis(unittest.TestCase):
  """The point the controller reports from stands within the plate."""

  def test_the_axis_stands_above_the_plates_front_edge_centred_across_it(self):
    plate = pf400_chassis.base_plate()
    self.assertEqual(
      pf400_chassis.SHOULDER_AXIS,
      Coordinate(plate.get_size_x(), plate.get_size_y() / 2, 62.0),
    )


class TestTheColumn(unittest.TestCase):
  """The column stands on the plate and reaches the height the arm stands."""

  def test_it_stands_on_the_plates_top_face_centred_across_it(self):
    plate = pf400_chassis.base_plate()
    column = pf400_chassis.z_column()
    location = pf400_chassis.Z_COLUMN_LOCATION
    self.assertEqual(location.z, plate.get_size_z())
    self.assertEqual(2 * location.y + column.get_size_y(), plate.get_size_y())

  def test_a_column_reaches_the_height_the_arm_stands(self):
    # Measured from the plate's bottom, which is its own frame's zero.
    for z_travel, height in ((400.0, 712.0), (750.0, 1062.0), (1160.0, 1472.0)):
      column = pf400_chassis.z_column(height=pf400_chassis.z_column_height(z_travel))
      self.assertEqual(pf400_chassis.Z_COLUMN_LOCATION.z + column.get_size_z(), height)

  def test_a_column_whose_travel_is_unread_has_no_height(self):
    self.assertEqual(pf400_chassis.z_column().get_size_z(), 0.0)


class TestEveryPart(unittest.TestCase):
  """Each part is a cuboid that says what it is."""

  def test_each_part_names_a_category_and_a_model(self):
    parts = (pf400_chassis.base_plate(), pf400_chassis.z_column())
    self.assertEqual(
      [(part.category, part.model) for part in parts],
      [
        ("base_plate", "brooks_pf400_base_plate"),
        ("z_column", "brooks_pf400_z_column"),
      ],
    )
