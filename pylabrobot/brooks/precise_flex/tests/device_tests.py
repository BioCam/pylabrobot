import unittest

from pylabrobot.brooks.precise_flex.device import PreciseFlex400
from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis
from pylabrobot.resources.coordinate import Coordinate


class TestTheChassisStandsInOneTree(unittest.TestCase):
  """The plate is the machine's, and the column is the plate's."""

  def setUp(self):
    self.device = PreciseFlex400(name="pf400", z_travel=400.0)
    self.plate = self.device.children[0]
    self.column = self.plate.children[0]

  def test_the_plate_and_the_column_are_named_after_the_machine(self):
    self.assertEqual([self.plate.name, self.column.name], ["pf400_base_plate", "pf400_z_column"])

  def test_the_column_stands_on_the_plates_top_face(self):
    self.assertEqual(self.column.location, pf400_chassis.Z_COLUMN_LOCATION)
    self.assertEqual(self.column.get_absolute_location().z, self.plate.get_size_z())

  def test_the_machine_is_as_tall_as_it_stands(self):
    self.assertEqual(self.device.get_size_z(), 712.0)

  def test_a_taller_travel_makes_a_taller_machine(self):
    for z_travel, height in ((750.0, 1062.0), (1160.0, 1472.0)):
      self.assertEqual(PreciseFlex400(name="pf400", z_travel=z_travel).get_size_z(), height)


class TestWhereTheControllerReportsFrom(unittest.TestCase):
  """The shoulder axis stands where it was measured, in the machine's own frame."""

  def test_the_axis_stands_at_the_front_of_the_machine(self):
    device = PreciseFlex400(name="pf400", z_travel=400.0)
    plate = device.children[0]
    axis = plate.get_absolute_location() + pf400_chassis.SHOULDER_AXIS
    self.assertEqual(axis, Coordinate(device.get_size_x(), device.get_size_y() / 2, 62.0))
