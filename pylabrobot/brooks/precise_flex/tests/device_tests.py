import unittest

from pylabrobot.brooks.precise_flex.device import PreciseFlex400, PreciseFlexDevice
from pylabrobot.brooks.precise_flex.driver.master import PreciseFlexDriver
from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis
from pylabrobot.resources.coordinate import Coordinate


def pf400(z_travel: float = 400.0, **declared) -> PreciseFlexDevice:
  driver = PreciseFlexDriver(
    host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
  )
  return PreciseFlex400(driver, name="pf400", z_travel=z_travel, **declared)


class TestTheDevice(unittest.TestCase):
  """The device carries its workspace and hands it to its driver."""

  def setUp(self):
    self.device = pf400()

  def test_the_workspace_is_its_child_and_the_drivers(self):
    self.assertIs(self.device.workspace.parent, self.device)
    self.assertIs(self.device.driver.workspace, self.device.workspace)
    self.assertEqual(self.device.workspace.name, "pf400_workspace")

  def test_the_workspace_reports_from_the_shoulder_axis(self):
    workspace = self.device.workspace
    origin = workspace.get_absolute_location() + workspace.reference_point
    self.assertEqual(origin, pf400_chassis.SHOULDER_AXIS)

  def test_the_workspace_is_swept_from_what_is_declared(self):
    self.assertEqual((self.device.workspace.z_min, self.device.workspace.z_max), (0.0, 400.0))
    ahead = Coordinate(700.0, 0.0, 200.0)
    self.assertTrue(self.device.workspace.is_reachable(ahead))
    self.assertFalse(pf400(reach_class="standard").workspace.is_reachable(ahead))

  def test_it_reaches_the_drivers_features(self):
    self.assertIs(self.device.arm, self.device.driver.arm)
    self.assertIs(self.device.gripper, self.device.driver.gripper)
    self.assertIsNone(self.device.rail)
    self.assertIsNone(self.device.vision)

  def test_a_driver_without_a_workspace_models_nothing(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    self.assertIsNone(driver.workspace)


class TestTheChassisStandsInOneTree(unittest.TestCase):
  """The plate is the machine's, and the column is the plate's."""

  def setUp(self):
    self.device = pf400()
    self.plate = self.device.get_resource("pf400_base_plate")
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
      self.assertEqual(pf400(z_travel).get_size_z(), height)


class TestWhereTheControllerReportsFrom(unittest.TestCase):
  """The shoulder axis stands where it was measured, in the machine's own frame."""

  def test_the_axis_stands_at_the_front_of_the_machine(self):
    device = pf400()
    plate = device.get_resource("pf400_base_plate")
    axis = plate.get_absolute_location() + pf400_chassis.SHOULDER_AXIS
    self.assertEqual(axis, Coordinate(device.get_size_x(), device.get_size_y() / 2, 62.0))


class TestTheCarriageOnTheMachine(unittest.TestCase):
  """A carriage on the column stands where the J1 drive says it is."""

  def setUp(self):
    self.device = pf400()
    self.column = self.device.get_resource("pf400_z_column")
    self.carriage = pf400_chassis.z_carriage(name="pf400_z_carriage")

  def _flange_plane(self, z: float) -> Coordinate:
    self.carriage.location = pf400_chassis.z_carriage_location(z)
    return self.carriage.get_absolute_location() + pf400_chassis.Z_CARRIAGE_REFERENCE_POINT

  def test_at_zero_the_flange_plane_stands_at_the_shoulder_axis(self):
    self.column.assign_child_resource(self.carriage, location=pf400_chassis.z_carriage_location(0))
    self.assertEqual(self._flange_plane(0.0).z, pf400_chassis.SHOULDER_AXIS.z)

  def test_the_flange_plane_rises_with_the_reading(self):
    self.column.assign_child_resource(self.carriage, location=pf400_chassis.z_carriage_location(0))
    self.assertEqual(self._flange_plane(250.0).z, pf400_chassis.SHOULDER_AXIS.z + 250.0)

  def test_it_stays_on_the_shoulder_axis_however_high_it_stands(self):
    self.column.assign_child_resource(self.carriage, location=pf400_chassis.z_carriage_location(0))
    plate = self.device.get_resource("pf400_base_plate")
    axis = plate.get_absolute_location() + pf400_chassis.SHOULDER_AXIS
    for z in (0.0, 175.0, 400.0):
      here = self._flange_plane(z)
      self.assertEqual((here.x, here.y), (axis.x, axis.y))

  def test_the_carriage_stays_within_the_columns_travel(self):
    top = pf400_chassis.z_carriage_location(400.0).z + self.carriage.get_size_z()
    self.assertLessEqual(top, self.column.get_size_z())
