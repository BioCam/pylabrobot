import unittest
from typing import List, Tuple, cast
from unittest.mock import AsyncMock, patch

from pylabrobot.brooks.precise_flex import kinematics
from pylabrobot.brooks.precise_flex.device import PreciseFlex400, PreciseFlexDevice
from pylabrobot.brooks.precise_flex.driver.configuration import Axis, PreciseFlexConfiguration
from pylabrobot.brooks.precise_flex.driver.errors import PreciseFlexError
from pylabrobot.brooks.precise_flex.driver.features.arm import PreciseFlexArmConfiguration
from pylabrobot.brooks.precise_flex.driver.features.gripper import PreciseFlexGripperConfiguration
from pylabrobot.brooks.precise_flex.driver.master import PreciseFlexDriver
from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper
from pylabrobot.resources.manipulator import LinkBody
from pylabrobot.resources.resource import Resource


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


def hung(driver: PreciseFlexDriver) -> Tuple[Resource, LinkBody, LinkBody, MechanicalGripper]:
  """The carriage, both links and the gripper the driver hung, which are None before it has."""
  return (
    cast(Resource, driver.arm.resource),
    cast(LinkBody, driver.arm.link_1),
    cast(LinkBody, driver.arm.link_2),
    cast(MechanicalGripper, driver.gripper.resource),
  )


class TestTheDriverHangsTheArm(unittest.TestCase):
  """At setup the driver hangs the carriage, the links and the gripper, each by its joint."""

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_feature_resources()

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
    self.driver._create_feature_resources()
    self.assertEqual(len(self.device.get_all_children()), before)

  def test_a_workspace_declared_for_another_arm_is_refused(self):
    for other in (
      configuration(links=kinematics.ARM_LINKS_STANDARD),
      configuration(z_range=(0.0, 750.0)),
    ):
      device = pf400()
      device.driver._configuration = other
      with self.assertRaises(ValueError):
        device.driver._create_feature_resources()
      self.assertIsNone(device.driver.arm.resource)

  def test_a_driver_without_a_workspace_hangs_nothing(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    driver._configuration = configuration()
    driver._create_feature_resources()
    self.assertIsNone(driver.arm.resource)


class TestTheModelFollowsTheJoints(unittest.IsolatedAsyncioTestCase):
  """A joint state stands the carriage and turns each member about the joint it turns on."""

  REPLY = "301.12 92.0 179.48 -184.25 120.0"

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_feature_resources()
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
    self.driver._create_feature_resources()

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
    with self.assertRaisesRegex(ValueError, "pf400_gripper_body would stand 0.5 mm"):
      self.driver.arm._check_pose_reachable(self.joints(92.0, 179.48, -184.25, 120.0))

  def test_a_finger_alone_is_enough(self):
    # The same angles pass with the jaws at 70.7 and are refused with them open.
    self.driver.arm._check_pose_reachable(self.joints(92.0, 179.48, 15.0, 70.7))
    with self.assertRaisesRegex(ValueError, "pf400_gripper_finger_right would stand 1.8 mm"):
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


class TestAMoveKeepsTheModelInStep(unittest.IsolatedAsyncioTestCase):
  """The target is written to the model as a move is sent; the arm is read once it has stopped."""

  STOOD = "301.1 0.0 180.0 180.0 100.0"
  TARGET = {Axis.SHOULDER: 30.0}

  def setUp(self):
    self.device = pf400()
    self.driver = self.device.driver
    self.driver._configuration = configuration()
    self.driver._create_feature_resources()
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
    self.driver.gripper._gripper_soft_min, self.driver.gripper._gripper_soft_max = 60.0, 145.0
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
    self.device.driver._create_feature_resources()

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
    with self.assertRaisesRegex(ValueError, "on the way, with the shoulder at 85.4"):
      self.arm._check_path_reachable(self.joints(*self.HOMED), parked)

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
