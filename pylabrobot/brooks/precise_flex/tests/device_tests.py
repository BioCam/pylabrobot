import unittest

from pylabrobot.brooks.precise_flex import kinematics
from pylabrobot.brooks.precise_flex.device import PreciseFlex400, PreciseFlexDevice
from pylabrobot.brooks.precise_flex.driver.configuration import Axis, PreciseFlexConfiguration
from pylabrobot.brooks.precise_flex.driver.features.arm import PreciseFlexArmConfiguration
from pylabrobot.brooks.precise_flex.driver.features.gripper import PreciseFlexGripperConfiguration
from pylabrobot.brooks.precise_flex.driver.master import PreciseFlexDriver
from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper
from pylabrobot.resources.manipulator import LinkBody


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


def configuration(links=kinematics.ARM_LINKS_EXTENDED, z_range=(1.5, 401.5)):
  """What an extended-reach arm on a 400 mm column reports, as far as the model reads it."""
  return PreciseFlexConfiguration(
    manufacturer="",
    controller_model="",
    hardware_version="",
    gpl_version="",
    controller_serial="",
    robot_name="PF400",
    robot_type=12,
    tcs_version="",
    modules=(),
    num_axes=5,
    extra_axes=0,
    axis_mask=47,
    arm=PreciseFlexArmConfiguration(
      soft_limits={Axis.BASE: z_range, Axis.SHOULDER: (-93.0, 93.0), Axis.ELBOW: (12.0, 348.0)},
      hard_limits={},
      max_joint_speed={},
      max_joint_acceleration={},
      max_joint_deceleration={},
      max_cartesian_speed=0.0,
      max_cartesian_acceleration=0.0,
      kinematics=kinematics.PF400Params(l1=links[0], l2=links[1], gripper_length=162.0),
    ),
    gripper=PreciseFlexGripperConfiguration(
      soft_limit_range=(60.0, 145.0),
      hard_limit_range=(0.0, 0.0),
      max_speed=0.0,
      max_acceleration=0.0,
      max_deceleration=0.0,
    ),
  )


class TestTheDriverHangsTheArm(unittest.TestCase):
  """At setup the driver hangs the carriage, the links and the gripper, each by its joint."""

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_capability_resources()

  def test_the_chain_runs_from_the_column_to_the_gripper(self):
    carriage = self.device.get_resource("pf400_z_carriage")
    self.assertIs(carriage.parent, self.device.get_resource("pf400_z_column"))
    self.assertIs(self.driver.arm.resource, carriage)
    first, second, hand = (
      self.driver.arm.link_1,
      self.driver.arm.link_2,
      self.driver.gripper.resource,
    )
    self.assertIsInstance(first, LinkBody)
    self.assertIsInstance(hand, MechanicalGripper)
    self.assertEqual([first.parent, second.parent, hand.parent], [carriage, first, second])
    self.assertEqual((first.length, second.length, hand.tool_center_point.x), (302.0, 289.0, 162.0))

  def test_every_joint_lands_on_the_one_before_it(self):
    first, second, hand = (
      self.driver.arm.link_1,
      self.driver.arm.link_2,
      self.driver.gripper.resource,
    )
    shoulder = first.get_location_wrt(self.device) + first.proximal_joint
    axis = pf400_chassis.SHOULDER_AXIS
    self.assertAlmostEqual(shoulder.x, axis.x)
    self.assertAlmostEqual(shoulder.y, axis.y)
    elbow = second.get_location_wrt(self.device) + second.proximal_joint
    self.assertAlmostEqual(elbow.x - shoulder.x, 302.0)
    wrist = hand.get_location_wrt(self.device) + hand.proximal_joint
    self.assertAlmostEqual(wrist.x - elbow.x, 289.0)
    # The wrist joint is in the flange plane, which is the shoulder axis's height at Z 0.
    self.assertAlmostEqual(wrist.z, axis.z)
    self.assertAlmostEqual(elbow.z, axis.z)

  def test_a_second_setup_hangs_nothing_twice(self):
    before = len(self.device.get_all_children())
    self.driver._create_capability_resources()
    self.assertEqual(len(self.device.get_all_children()), before)

  def test_a_workspace_declared_for_another_arm_is_refused(self):
    for other in (
      configuration(links=kinematics.ARM_LINKS_STANDARD),
      configuration(z_range=(0.0, 750.0)),
    ):
      device = pf400()
      device.driver._configuration = other
      with self.assertRaises(ValueError):
        device.driver._create_capability_resources()
      self.assertIsNone(device.driver.arm.resource)

  def test_a_driver_without_a_workspace_hangs_nothing(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    driver._configuration = configuration()
    driver._create_capability_resources()
    self.assertIsNone(driver.arm.resource)
