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
    column = pf400_chassis.z_column("column", 700.0)
    location = pf400_chassis.Z_COLUMN_LOCATION
    self.assertEqual(location.z, plate.get_size_z())
    self.assertEqual(2 * location.y + column.get_size_y(), plate.get_size_y())

  def test_a_column_reaches_the_height_the_arm_stands(self):
    # Measured from the plate's bottom, which is its own frame's zero.
    for z_travel, height in ((400.0, 712.0), (750.0, 1062.0), (1160.0, 1472.0)):
      column = pf400_chassis.z_column("column", height=pf400_chassis.z_column_height(z_travel))
      self.assertEqual(pf400_chassis.Z_COLUMN_LOCATION.z + column.get_size_z(), height)


class TestTheCarriage(unittest.TestCase):
  """What the J1 drive moves, and where a reading puts it."""

  def test_it_rides_the_columns_front_face_centred_across_it(self):
    column = pf400_chassis.z_column("column", 700.0)
    carriage = pf400_chassis.z_carriage()
    location = pf400_chassis.z_carriage_location(0.0)
    self.assertEqual(location.x, column.get_size_x())
    self.assertEqual(2 * location.y + carriage.get_size_y(), column.get_size_y())

  def test_the_drive_reports_the_shoulder_axis_at_the_flange_plane(self):
    reference = pf400_chassis.Z_CARRIAGE_REFERENCE_POINT
    self.assertEqual(reference, Coordinate(67.5, 55.0, -104.2))

  def test_a_reading_moves_it_by_what_it_read(self):
    stood = pf400_chassis.z_carriage_location(0.0)
    raised = pf400_chassis.z_carriage_location(250.0)
    self.assertEqual(raised - stood, Coordinate(0.0, 0.0, 250.0))


class TestEveryPart(unittest.TestCase):
  """Each part is a cuboid that says what it is."""

  def test_each_part_names_a_category_and_a_model(self):
    parts = (
      pf400_chassis.base_plate(),
      pf400_chassis.z_column("column", 700.0),
      pf400_chassis.z_carriage(),
    )
    self.assertEqual(
      [(part.category, part.model) for part in parts],
      [
        ("base_plate", "brooks_pf400_base_plate"),
        ("z_column", "brooks_pf400_z_column"),
        ("z_carriage", "brooks_pf400_z_carriage"),
      ],
    )
