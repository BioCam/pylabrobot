import random
import unittest
from typing import List, Optional, Tuple, cast
from unittest.mock import AsyncMock, patch

from pylabrobot.brooks.precise_flex import kinematics
from pylabrobot.brooks.precise_flex.device import (
  RECORDING_PF400,
  PreciseFlex400,
  PreciseFlexDevice,
)
from pylabrobot.brooks.precise_flex.driver.configuration import (
  Axis,
  PreciseFlexConfiguration,
  read_configuration,
)
from pylabrobot.brooks.precise_flex.driver.errors import PreciseFlexError
from pylabrobot.brooks.precise_flex.driver.features.arm import PreciseFlexArmConfiguration
from pylabrobot.brooks.precise_flex.driver.features.gripper import PreciseFlexGripperConfiguration
from pylabrobot.brooks.precise_flex.driver.master import PreciseFlexDriver
from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper
from pylabrobot.resources.manipulator import LinkBody
from pylabrobot.resources.resource import Resource


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
      soft_limits={
        Axis.BASE: z_range,
        Axis.SHOULDER: (-93.0, 93.0),
        Axis.ELBOW: (12.0, 348.0),
        Axis.WRIST: (-970.0, 970.0),
      },
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


def hung(driver: PreciseFlexDriver) -> Tuple[Resource, LinkBody, LinkBody, MechanicalGripper]:
  """The carriage, both links and the gripper the driver hung, which are None before it has."""
  return (
    cast(Resource, driver.arm.resource),
    cast(LinkBody, driver.arm.link_1),
    cast(LinkBody, driver.arm.link_2),
    cast(MechanicalGripper, driver.gripper.resource),
  )


def pf400(declared: Optional[str] = None) -> PreciseFlexDevice:
  driver = PreciseFlexDriver(
    host="localhost",
    gripper_length=162.0,
    gripper_z_offset=0.0,
    closed_gripper_position=60.0,
    declared_configuration_json=declared,
  )
  return PreciseFlex400(driver, name="pf400")


def built() -> PreciseFlexDevice:
  """A device whose driver has read the stand-in configuration and built the arm from it."""
  device = pf400()
  device.driver._configuration = configuration()
  device.driver._create_feature_resources(device.driver.configuration)
  return device


class TestTheDevice(unittest.IsolatedAsyncioTestCase):
  """The device carries its workspace and hands it to its driver."""

  def setUp(self):
    self.device = pf400()

  def test_the_workspace_is_its_child_and_the_drivers(self):
    self.assertIs(self.device.workspace.parent, self.device)
    self.assertIs(self.device.driver.workspace, self.device.workspace)
    self.assertEqual(self.device.workspace.name, "pf400_workspace")

  def test_before_a_configuration_only_the_base_plate_stands(self):
    self.assertEqual(
      [r.name for r in self.device.get_all_children()], ["pf400_workspace", "pf400_base_plate"]
    )
    self.assertEqual(self.device.workspace.boundary, [])
    self.assertFalse(self.device.workspace.is_reachable(Coordinate(400.0, 0.0, 200.0)))
    self.assertIsNone(self.device.arm.resource)

  def test_its_own_cuboid_is_the_base_plate_it_stands_on(self):
    base_plate = self.device.get_resource("pf400_base_plate")
    self.assertEqual(self.device.get_size_z(), base_plate.get_size_z())

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


class TestBuiltFromADeclaredConfiguration(unittest.IsolatedAsyncioTestCase):
  """A driver given a declared configuration builds the arm from it at once, before any setup."""

  def test_the_recorded_arm_stands_before_it_is_connected(self):
    device = pf400(RECORDING_PF400)
    column = device.get_resource("pf400_z_column")
    # From the base plate's top face: the shoulder axis, the travel, and the headroom above it.
    self.assertAlmostEqual(column.get_size_z(), 62.0 + 401.5 + 250.0 - 9.6)
    self.assertEqual((device.workspace.z_min, device.workspace.z_max), (1.5, 401.5))
    self.assertTrue(device.workspace.is_reachable(Coordinate(700.0, 0.0, 200.0)))
    _, first, second, hand = hung(device.driver)
    self.assertEqual((first.length, second.length, hand.tool_center_point.x), (302.0, 289.0, 162.0))
    self.assertEqual(hand.jaw_range, (69.0, 134.0))

  def test_the_workspace_reports_from_the_shoulder_axis(self):
    workspace = pf400(RECORDING_PF400).workspace
    origin = cast(Coordinate, workspace.location) + workspace.reference_point
    self.assertEqual(
      (origin.x, origin.y), (pf400_chassis.SHOULDER_AXIS.x, pf400_chassis.SHOULDER_AXIS.y)
    )
    # The tool point is at the shoulder axis's height with the Z drive at 0.
    self.assertEqual(origin.z, pf400_chassis.SHOULDER_AXIS.z)

  def test_a_taller_arm_is_built_taller(self):
    device = pf400(RECORDING_PF400.replace("400mm", "1160mm_rail_derived"))
    column = device.get_resource("pf400_z_column")
    self.assertAlmostEqual(column.get_size_z(), 62.0 + 1161.5 + 250.0 - 9.6)
    self.assertEqual(device.workspace.z_max, 1161.5)

  def test_setup_builds_nothing_twice(self):
    device = pf400(RECORDING_PF400)
    before = [r.name for r in device.get_all_children()]
    device.driver._create_feature_resources(read_configuration(RECORDING_PF400))
    self.assertEqual([r.name for r in device.get_all_children()], before)


class TestTheChassisStandsInOneTree(unittest.IsolatedAsyncioTestCase):
  """The base plate is the device's, and the column is the base plate's."""

  def setUp(self):
    self.device = built()
    self.base_plate = self.device.get_resource("pf400_base_plate")
    self.column = self.base_plate.children[0]

  def test_the_base_plate_and_the_column_are_named_after_the_device(self):
    self.assertEqual(
      [self.base_plate.name, self.column.name], ["pf400_base_plate", "pf400_z_column"]
    )

  def test_the_column_stands_on_the_base_plates_top_face(self):
    self.assertEqual(self.column.location, pf400_chassis.Z_COLUMN_LOCATION)
    self.assertEqual(self.column.get_absolute_location().z, self.base_plate.get_size_z())


class TestWhereTheControllerReportsFrom(unittest.IsolatedAsyncioTestCase):
  """The shoulder axis stands where it was measured, in the device's own frame."""

  def test_the_axis_stands_at_the_front_of_the_device(self):
    device = pf400()
    base_plate = device.get_resource("pf400_base_plate")
    axis = base_plate.get_absolute_location() + pf400_chassis.SHOULDER_AXIS
    self.assertEqual(axis, Coordinate(device.get_size_x(), device.get_size_y() / 2, 62.0))


class TestTheCarriageOnTheDevice(unittest.IsolatedAsyncioTestCase):
  """The carriage on the column stands where the J1 drive says it is."""

  def setUp(self):
    self.device = built()
    self.column = self.device.get_resource("pf400_z_column")
    self.carriage = self.device.get_resource("pf400_z_carriage")

  def _flange_plane(self, z: float) -> Coordinate:
    self.carriage.location = pf400_chassis.z_carriage_location(z)
    return self.carriage.get_absolute_location() + pf400_chassis.Z_CARRIAGE_REFERENCE_POINT

  def test_at_zero_the_flange_plane_stands_at_the_shoulder_axis(self):
    self.assertEqual(self._flange_plane(0.0).z, pf400_chassis.SHOULDER_AXIS.z)

  def test_the_flange_plane_rises_with_the_reading(self):
    self.assertEqual(self._flange_plane(250.0).z, pf400_chassis.SHOULDER_AXIS.z + 250.0)

  def test_it_stays_on_the_shoulder_axis_however_high_it_stands(self):
    base_plate = self.device.get_resource("pf400_base_plate")
    axis = base_plate.get_absolute_location() + pf400_chassis.SHOULDER_AXIS
    for z in (0.0, 175.0, 400.0):
      here = self._flange_plane(z)
      self.assertEqual((here.x, here.y), (axis.x, axis.y))

  def test_the_carriage_stays_within_the_columns_travel(self):
    top = pf400_chassis.z_carriage_location(400.0).z + self.carriage.get_size_z()
    self.assertLessEqual(top, self.column.get_size_z())


class TestTheDriverHangsTheArm(unittest.IsolatedAsyncioTestCase):
  """At setup the driver hangs the carriage, the links and the gripper, each by its joint."""

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_feature_resources(self.driver.configuration)

  def test_the_chain_runs_from_the_column_to_the_gripper(self):
    carriage, first, second, hand = hung(self.driver)
    self.assertIs(carriage, self.device.get_resource("pf400_z_carriage"))
    self.assertIs(carriage.parent, self.device.get_resource("pf400_z_column"))
    self.assertEqual([first.parent, second.parent, hand.parent], [carriage, first, second])
    self.assertEqual((first.length, second.length, hand.tool_center_point.x), (302.0, 289.0, 162.0))

  def test_every_joint_lands_on_the_one_before_it(self):
    _, first, second, hand = hung(self.driver)
    axis = pf400_chassis.SHOULDER_AXIS
    shoulder = first.get_location_wrt(self.device) + first.proximal_joint
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
    self.driver._create_feature_resources(self.driver.configuration)
    self.assertEqual(len(self.device.get_all_children()), before)

  def test_a_driver_without_a_workspace_hangs_nothing(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    driver._configuration = configuration()
    driver._create_feature_resources(driver.configuration)
    self.assertIsNone(driver.arm.resource)


class TestTheModelFollowsTheJoints(unittest.IsolatedAsyncioTestCase):
  """A joint state stands the carriage and turns each member about the joint it turns on."""

  REPLY = "301.12 92.0 179.48 -184.25 120.0"

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_feature_resources(self.driver.configuration)
    self.carriage, self.first, self.second, self.hand = hung(self.driver)

  def test_the_carriage_stands_where_the_z_drive_is(self):
    self.driver.arm.update_joint_state(
      {Axis.BASE: 250.0, Axis.SHOULDER: 0.0, Axis.ELBOW: 0.0, Axis.WRIST: 0.0}
    )
    self.assertEqual(self.carriage.location, pf400_chassis.z_carriage_location(250.0))

  def test_each_member_turns_to_its_joints_angle(self):
    self.driver.arm.update_joint_state(
      {Axis.BASE: 0.0, Axis.SHOULDER: 92.0, Axis.ELBOW: 179.5, Axis.WRIST: -184.25}
    )
    self.assertAlmostEqual(self.first.rotation.z, 92.0)
    self.assertAlmostEqual(self.second.rotation.z, 179.5)
    self.assertAlmostEqual(self.hand.rotation.z % 360.0, -184.25 % 360.0)

  def test_the_joints_stay_joined_when_the_members_turn(self):
    joints = {Axis.BASE: 100.0, Axis.SHOULDER: 90.0, Axis.ELBOW: 0.0, Axis.WRIST: 0.0}
    self.driver.arm.update_joint_state(joints)
    pose = self.driver.arm._forward_kinematics(joints)
    # Straight out along +y: the wrist joint is both link lengths from the shoulder axis.
    self.assertAlmostEqual(pose.wrist_joint_location.y, 591.0)
    self.assertAlmostEqual(self.second.rotation.z, 0.0)

  def test_the_jaws_follow_a_width_within_their_range_only(self):
    self.driver.gripper.update_width(100.0)
    self.assertEqual(self.hand.jaw_width, 100.0)
    with self.assertLogs("pylabrobot.brooks.precise_flex.driver.features.gripper", "WARNING"):
      self.driver.gripper.update_width(200.0)
    self.assertEqual(self.hand.jaw_width, 100.0)

  async def test_a_joint_read_records_what_it_read(self):
    with patch.object(self.driver, "send_command", AsyncMock(return_value=self.REPLY)):
      with patch.object(self.driver.arm, "_wait_for_eom", AsyncMock()):
        await self.driver.arm.request_joint_state()
    self.assertEqual(self.carriage.location, pf400_chassis.z_carriage_location(301.12))
    self.assertAlmostEqual(self.first.rotation.z, 92.0)
    self.assertEqual(self.hand.jaw_width, 120.0)

  async def test_a_driver_without_a_workspace_reads_as_before(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    with patch.object(driver, "send_command", AsyncMock(return_value=self.REPLY)):
      with patch.object(driver.arm, "_wait_for_eom", AsyncMock()):
        joints = await driver.arm.request_joint_state()
    self.assertEqual(joints[Axis.SHOULDER], 92.0)


class TestTheGripperIsKeptClearOfTheColumn(unittest.IsolatedAsyncioTestCase):
  """A target that would stand the gripper in or against the column is refused before it is sent."""

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_feature_resources(self.driver.configuration)

  @staticmethod
  def joints(shoulder: float, elbow: float, wrist: float, jaws: float):
    return {
      Axis.BASE: 301.1,
      Axis.SHOULDER: shoulder,
      Axis.ELBOW: elbow,
      Axis.WRIST: wrist,
      Axis.GRIPPER: jaws,
    }

  def test_the_pose_where_a_finger_touched_the_column_is_refused(self):
    # Open to 120, a jaw reaches out past the gripper's body, and it is the jaw that touches.
    with self.assertRaisesRegex(ValueError, "pf400_gripper_jaw_left would stand -0.1 mm"):
      self.driver.arm._check_pose_reachable(self.joints(92.0, 179.48, -184.25, 120.0))

  def test_an_open_jaw_alone_is_enough(self):
    # The same angles pass with the jaws at 70.7 and are refused with them open.
    self.driver.arm._check_pose_reachable(self.joints(92.0, 179.48, 15.0, 70.7))
    with self.assertRaisesRegex(ValueError, "pf400_gripper_jaw_right would stand 1.8 mm"):
      self.driver.arm._check_pose_reachable(self.joints(92.0, 179.48, 15.0, 145.0))

  def test_the_poses_the_arm_homes_to_and_parks_at_pass(self):
    for pose in (
      self.joints(93.3, 179.4, 83.93, 70.7),
      self.joints(93.3, 179.4, -215.9, 70.7),
      self.joints(0.0, 180.0, 180.0, 120.0),
      self.joints(0.0, 90.0, 0.0, 120.0),
    ):
      with self.subTest(pose=pose):
        self.driver.arm._check_pose_reachable(pose)

  def test_the_model_is_left_where_it_was(self):
    before = self.device.serialize()
    with self.assertRaises(ValueError):
      self.driver.arm._check_pose_reachable(self.joints(92.0, 179.48, -184.25, 120.0))
    self.assertEqual(self.device.serialize(), before)

  def test_an_arm_that_is_not_modelled_is_not_checked(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    driver.arm._check_pose_reachable(self.joints(92.0, 179.48, -184.25, 120.0))

  async def test_a_refused_move_is_never_sent(self):
    sent = AsyncMock(return_value="301.1 0.0 180.0 180.0 120.0")
    with patch.object(self.driver, "send_command", sent):
      with patch.object(self.driver.arm, "_wait_for_eom", AsyncMock()):
        with self.assertRaises(ValueError):
          await self.driver.arm._guarded_move_j(
            lambda _current: self.joints(92.0, 179.48, -184.25, 120.0)
          )
    self.assertEqual([call.args[0] for call in sent.call_args_list], ["wherej"])

  async def jaws_to(self, width: float, stood: str) -> List[str]:
    """What is sent for a jaw move to `width`, from where `stood` has the arm."""
    self.driver.gripper.configuration = self.driver.configuration.gripper
    sent = AsyncMock(return_value=stood)
    with patch.object(self.driver, "send_command", sent):
      with patch.object(self.driver.arm, "_wait_for_eom", AsyncMock()):
        try:
          await self.driver.gripper.move_to_jaw_position(width)
        finally:
          self.sent = [call.args[0] for call in sent.call_args_list]
    return self.sent

  async def test_jaws_opened_against_the_column_are_never_sent(self):
    # Clear of the column by 5.8 mm with the jaws at 70.7; opened, a finger would reach it.
    with self.assertRaisesRegex(ValueError, "pf400_gripper_finger_right would stand"):
      await self.jaws_to(134.0, stood="301.1 92.0 179.48 10.0 70.7")
    self.assertEqual(self.sent, ["wherej"])

  async def test_jaws_closed_next_to_the_column_are_sent(self):
    # They stand nearer than is kept clear, and closing takes them away from it.
    sent = await self.jaws_to(70.7, stood="301.1 92.0 179.48 10.0 134.0")
    self.assertIn("gripper 2", sent)


class TestAMoveKeepsTheModelInStep(unittest.IsolatedAsyncioTestCase):
  """The target is written to the model as a move is sent; the arm is read once it has stopped."""

  STOOD = "301.1 0.0 180.0 180.0 100.0"
  TARGET = {Axis.SHOULDER: 30.0}

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_feature_resources(self.driver.configuration)
    _, self.first, _, self.hand = hung(self.driver)
    self.seen: List[Tuple[float, float]] = []

  def controller(self, after_the_move: str, refuse: bool = False) -> AsyncMock:
    """Answers `wherej` with where the arm stood, then with `after_the_move` once a move is sent."""
    moved: List[str] = []

    async def respond(command: str) -> str:
      if command == "wherej":
        return after_the_move if moved else self.STOOD
      if command.startswith(("moveJ", "gripper")):
        # What the model says while the move is under way.
        self.seen.append((self.first.rotation.z, self.hand.jaw_width))
        moved.append(command)
        if refuse:
          raise PreciseFlexError(-1012, "refused")
      return ""

    return AsyncMock(side_effect=respond)

  async def move(self, sent: AsyncMock, call) -> None:
    with patch.object(self.driver, "send_command", sent):
      with patch("pylabrobot.brooks.precise_flex.driver.features.arm.asyncio.sleep", AsyncMock()):
        await call()

  async def test_the_model_stands_at_the_target_while_the_arm_travels(self):
    sent = self.controller(after_the_move="301.1 30.0 180.0 180.0 100.0")
    await self.move(sent, lambda: self.driver.arm.move_to_joint_state(dict(self.TARGET)))
    self.assertEqual(self.seen, [(30.0, 100.0)])
    self.assertEqual([call.args[0] for call in sent.call_args_list][-1], "wherej")

  async def test_where_the_arm_stopped_has_the_last_word(self):
    sent = self.controller(after_the_move="301.1 29.6 180.0 180.0 100.0")
    await self.move(sent, lambda: self.driver.arm.move_to_joint_state(dict(self.TARGET)))
    self.assertAlmostEqual(self.first.rotation.z, 29.6)

  async def test_a_refused_move_leaves_the_model_where_the_arm_is_and_keeps_its_error(self):
    self.driver._recover_out_of_range = False
    sent = self.controller(after_the_move=self.STOOD, refuse=True)
    with self.assertRaises(PreciseFlexError) as raised:
      await self.move(sent, lambda: self.driver.arm.move_to_joint_state(dict(self.TARGET)))
    self.assertEqual(raised.exception.replycode, -1012)
    self.assertEqual(self.seen, [(30.0, 100.0)])
    self.assertAlmostEqual(self.first.rotation.z, 0.0)

  async def test_a_read_that_fails_after_a_refused_move_does_not_replace_its_error(self):
    self.driver._recover_out_of_range = False
    sent = self.controller(after_the_move="", refuse=True)
    with self.assertLogs("pylabrobot.brooks.precise_flex.driver.features.arm", "WARNING") as logs:
      with self.assertRaises(PreciseFlexError) as raised:
        await self.move(sent, lambda: self.driver.arm.move_to_joint_state(dict(self.TARGET)))
    self.assertEqual(raised.exception.replycode, -1012)
    self.assertIn("its model is stale", "\n".join(logs.output))

  async def test_the_jaws_stand_at_the_target_then_where_they_stopped(self):
    # Force-sensed jaws stop on what they hold: sent to 80, they stop at 86.2.
    sent = self.controller(after_the_move="301.1 0.0 180.0 180.0 86.2")
    self.driver.gripper.configuration = self.driver.configuration.gripper
    await self.move(sent, lambda: self.driver.gripper.move_to_jaw_position(80.0))
    self.assertEqual(self.seen, [(0.0, 80.0)])
    self.assertEqual(self.hand.jaw_width, 86.2)


class TestTheGripperIsKeptClearOfTheColumnOnTheWay(unittest.IsolatedAsyncioTestCase):
  """A joint move is refused for what the gripper sweeps through, not only for where it ends."""

  HOMED = (93.3, 179.4, -215.9, 70.7)

  def setUp(self):
    self.device = pf400()
    self.arm = self.device.driver.arm
    self.device.driver._configuration = configuration()
    self.device.driver._create_feature_resources(self.device.driver.configuration)

  @staticmethod
  def joints(shoulder: float, elbow: float, wrist: float, jaws: float):
    return {
      Axis.BASE: 301.1,
      Axis.SHOULDER: shoulder,
      Axis.ELBOW: elbow,
      Axis.WRIST: wrist,
      Axis.GRIPPER: jaws,
    }

  def test_a_swing_past_the_column_is_refused_though_it_ends_clear(self):
    # Turning the wrist away from the column never comes near it.
    self.arm._check_path_reachable(self.joints(*self.HOMED), self.joints(93.3, 179.4, -250.0, 70.7))
    # Parking with the wrist at 180 ends clear, and turns the gripper past the column to get there.
    parked = self.joints(0.0, 180.0, 180.0, 70.7)
    self.arm._check_pose_reachable(parked)
    with self.assertRaisesRegex(ValueError, "on the way, with the shoulder at 8"):
      self.arm._check_path_reachable(self.joints(*self.HOMED), parked)

  def poses_looked_at(self, current, target) -> int:
    """How many poses a path check places the gripper's outlines at."""
    with patch.object(
      self.arm, "_get_column_clearance", wraps=self.arm._get_column_clearance
    ) as placed:
      self.arm._check_path_reachable(current, target)
    return placed.call_count

  def test_far_from_the_column_few_poses_are_looked_at(self):
    stretched = (self.joints(-90.0, 30.0, 0.0, 120.0), self.joints(90.0, 30.0, 0.0, 120.0))
    self.assertLessEqual(self.poses_looked_at(*stretched), 2)
    parking = (self.joints(*self.HOMED), self.joints(0.0, 180.0, -180.0, 70.7))
    self.assertLess(self.poses_looked_at(*parking), 80)

  def test_the_gripper_reaches_further_from_the_wrist_joint_than_its_tool_length(self):
    # The outer front corner of a finger, with the jaws at the 145 this stand-in arm opens to.
    reach = max(
      (x * x + y * y) ** 0.5
      for outline in self.arm._get_gripper_outlines(145.0).values()
      for x, y in outline
    )
    self.assertAlmostEqual(reach, 187.0, delta=0.1)
    self.assertGreater(reach, self.device.driver._kinematics_params.gripper_length)

  def test_what_it_allows_never_touches_and_what_it_refuses_comes_too_near(self):
    """Against the same moves looked at every 3 mm of travel or less, which is slow and thorough."""
    generator = random.Random(7)

    def pose():
      return self.joints(
        generator.uniform(-93.0, 93.0),
        generator.uniform(12.0, 348.0),
        generator.uniform(-360.0, 360.0),
        generator.uniform(69.0, 134.0),
      )

    for _ in range(6):
      current, target = pose(), pose()
      if cast(Tuple[str, float], self.arm._get_column_clearance(current))[1] < 5.0:
        continue  # an arm that starts too near is judged by another rule
      nearest = min(
        cast(
          Tuple[str, float],
          self.arm._get_column_clearance(
            {axis: current[axis] + (target[axis] - current[axis]) * step / 1500 for axis in target}
          ),
        )[1]
        for step in range(1501)
      )
      try:
        self.arm._check_path_reachable(current, target)
        self.assertGreater(nearest, 0.0)
      except ValueError:
        self.assertLess(nearest, 5.0)

  def test_the_same_park_by_the_shorter_turn_is_allowed(self):
    self.arm._check_path_reachable(self.joints(*self.HOMED), self.joints(0.0, 180.0, -180.0, 70.7))

  def test_an_arm_that_starts_too_near_may_move_away_and_no_nearer(self):
    stood = self.joints(92.087, 179.417, -185.505, 70.703)
    with self.assertRaises(ValueError):
      self.arm._check_pose_reachable(stood)
    self.arm._check_path_reachable(stood, self.joints(92.087, 179.417, -200.0, 70.703))
    with self.assertRaisesRegex(ValueError, "on the way"):
      self.arm._check_path_reachable(stood, self.joints(92.087, 179.417, -180.0, 70.703))

  def test_a_long_sweep_in_front_of_the_column_is_allowed(self):
    self.arm._check_path_reachable(
      self.joints(-90.0, 30.0, 0.0, 120.0), self.joints(90.0, 30.0, 0.0, 120.0)
    )

  def test_an_arm_that_is_not_modelled_is_not_checked(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    driver.arm._check_path_reachable(self.joints(*self.HOMED), self.joints(0.0, 180.0, 180.0, 70.7))

  async def test_a_refused_swing_is_never_sent(self):
    sent = AsyncMock(return_value="301.1 93.3 179.4 -215.9 70.7")
    with patch.object(self.device.driver, "send_command", sent):
      with patch.object(self.arm, "_wait_for_eom", AsyncMock()):
        with self.assertRaisesRegex(ValueError, "on the way"):
          await self.arm.move_to_joint_state(
            {Axis.SHOULDER: 0.0, Axis.ELBOW: 180.0, Axis.WRIST: 180.0}
          )
    self.assertEqual([call.args[0] for call in sent.call_args_list], ["wherej"])


class TestParkingTakesAClearTurn(unittest.IsolatedAsyncioTestCase):
  """A parking pose is a heading: the wrist reaches it by whichever full turn the way is clear."""

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.read = configuration()
    self.driver._configuration = self.read
    # As setup adopts them, so the soft limits are known to the arm.
    self.driver.arm.configuration = self.read.arm
    self.driver.gripper.configuration = self.read.gripper
    self.driver._create_feature_resources(self.driver.configuration)
    self.driver.arm.parking_position = dict(self.driver.arm.PARKING_POSITION_RIGHT)

  async def park(self, stood: str) -> List[str]:
    sent = AsyncMock(return_value=stood)
    with patch.object(self.driver, "send_command", sent):
      with patch.object(self.driver.arm, "_wait_for_eom", AsyncMock()):
        await self.driver.arm.park()
    return [call.args[0] for call in sent.call_args_list if call.args[0].startswith("moveJ")]

  async def test_the_pose_as_written_is_taken_when_its_way_is_clear(self):
    self.assertEqual(
      await self.park("301.1 92.0 179.4 83.93 70.7"), ["moveJ 1 301.125 0.0 180.0 180.0 70.7"]
    )

  async def test_a_full_turn_the_other_way_is_taken_when_the_written_one_passes_the_column(self):
    with self.assertLogs("pylabrobot.brooks.precise_flex.driver.features.arm", "INFO") as logs:
      moves = await self.park("301.1 92.0 179.4 -215.9 70.7")
    self.assertEqual(moves, ["moveJ 1 301.125 0.0 180.0 -180.0 70.7"])
    self.assertIn("parking with the wrist at -180.0, not 180.0", "\n".join(logs.output))

  async def test_a_turn_past_the_wrists_soft_limit_is_not_taken(self):
    # From -215.9 the clear turn is -180, which this wrist may not reach: nothing is sent.
    self.read.arm.soft_limits[Axis.WRIST] = (-970.0, -200.0)
    with self.assertRaisesRegex(ValueError, "WRIST target 180.0 is outside its soft limit"):
      await self.park("301.1 92.0 179.4 -215.9 70.7")

  async def test_a_pose_no_turn_reaches_clear_is_refused_as_written(self):
    self.driver.arm.parking_position = {Axis.SHOULDER: 92.0, Axis.ELBOW: 179.4, Axis.WRIST: -150.0}
    with self.assertRaisesRegex(ValueError, "would stand"):
      await self.park("301.1 92.0 179.4 -215.9 70.7")

  async def test_an_arm_that_is_not_modelled_parks_as_written(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    driver.arm.parking_position = dict(driver.arm.PARKING_POSITION_RIGHT)
    sent = AsyncMock(return_value="301.1 92.0 179.4 -215.9 70.7")
    with patch.object(driver, "send_command", sent):
      with patch.object(driver.arm, "_wait_for_eom", AsyncMock()):
        await driver.arm.park()
    moves = [call.args[0] for call in sent.call_args_list if call.args[0].startswith("moveJ")]
    self.assertEqual(moves, ["moveJ 1 301.1 0.0 180.0 180.0 70.7"])


class TestEveryMotionPathIsCheckedAndKeepsTheModelInStep(unittest.IsolatedAsyncioTestCase):
  """Recovery, a route of poses, and the controller's own pick and place, on a modelled arm."""

  HOMED = "301.1 92.0 179.4 -215.9 70.7"
  # A station that stands the gripper against the column, and one well clear of it.
  AT_THE_COLUMN = {
    Axis.BASE: 301.1,
    Axis.SHOULDER: 92.0,
    Axis.ELBOW: 179.48,
    Axis.WRIST: -184.25,
    Axis.GRIPPER: 120.0,
  }
  # The parking pose by the short turn of the wrist, which the way from the homed pose is clear to.
  CLEAR = {
    Axis.BASE: 301.1,
    Axis.SHOULDER: 0.0,
    Axis.ELBOW: 180.0,
    Axis.WRIST: -180.0,
    Axis.GRIPPER: 70.7,
  }

  def setUp(self):
    self.device = built()
    self.driver = self.device.driver
    self.driver.arm.configuration = self.driver.configuration.arm
    self.driver.gripper.configuration = self.driver.configuration.gripper
    _, self.first, _, _ = hung(self.driver)

  async def sent_by(self, call, stood: str = HOMED) -> List[str]:
    sent = AsyncMock(side_effect=lambda command: stood if command == "wherej" else "1")
    with patch.object(self.driver, "send_command", sent):
      with patch.object(self.driver.arm, "_wait_for_eom", AsyncMock()):
        await call()
    return [call.args[0].split()[0] for call in sent.call_args_list if call.args[0] != "wherej"]

  async def test_a_pick_at_the_column_is_refused_before_the_station_is_written(self):
    with self.assertRaisesRegex(ValueError, "would stand"):
      await self.sent_by(lambda: self.driver.arm._pick_plate_j(dict(self.AT_THE_COLUMN)))

  async def test_a_place_at_the_column_is_refused(self):
    with self.assertRaisesRegex(ValueError, "would stand"):
      await self.sent_by(lambda: self.driver.arm._place_plate_j(dict(self.AT_THE_COLUMN)))

  async def test_a_pick_clear_of_the_column_is_sent_and_the_model_reads_where_it_stopped(self):
    sent = await self.sent_by(lambda: self.driver.arm._pick_plate_j(dict(self.CLEAR)))
    self.assertEqual(sent, ["locAngles", "StationType", "pickplate"])
    # The stand-in controller still answers the homed pose, so that is where the model ends.
    self.assertAlmostEqual(self.first.rotation.z, 92.0)

  async def test_a_recovery_move_is_written_to_the_model_and_read_back(self):
    out_of_range = "301.1 93.3 179.4 -215.9 70.7"
    seen = []

    async def respond(command: str) -> str:
      if command.startswith("MoveOneAxis"):
        seen.append(self.first.rotation.z)
      return out_of_range if command == "wherej" else "1 50"

    with patch.object(self.driver, "send_command", AsyncMock(side_effect=respond)):
      with patch.object(self.driver.arm, "_wait_for_eom", AsyncMock()):
        recovered = await self.driver.arm.recover_axes_within_limits()
    self.assertEqual(recovered, {Axis.SHOULDER: 92.0})
    self.assertEqual(seen, [92.0])

  async def test_every_leg_of_a_route_of_poses_is_checked_as_it_is_planned(self):
    arm = self.driver.arm
    ahead = arm._forward_kinematics(dict(self.CLEAR)).gripper_pose
    sent = AsyncMock(side_effect=lambda command: self.HOMED if command == "wherej" else "")
    with patch.object(self.driver, "send_command", sent):
      with patch.object(arm, "_wait_for_eom", AsyncMock()):
        with patch.object(arm, "_check_path_reachable", wraps=arm._check_path_reachable) as checked:
          targets = await arm._plan_cartesian_pose_route([ahead, ahead])
    self.assertEqual(checked.call_count, 2)
    # Each leg from where the one before it ends.
    self.assertEqual(checked.call_args_list[1].args[0], targets[0])
