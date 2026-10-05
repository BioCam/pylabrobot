import json
import os
import tempfile
import unittest

from pylabrobot.brooks.precise_flex import kinematics
from pylabrobot.brooks.precise_flex.driver.configuration import (
  Axis,
  PreciseFlexConfiguration,
  read_configuration,
  to_jsonable,
)
from pylabrobot.brooks.precise_flex.driver.features.arm import PreciseFlexArmConfiguration
from pylabrobot.brooks.precise_flex.driver.features.gripper import PreciseFlexGripperConfiguration
from pylabrobot.brooks.precise_flex.driver.features.rail import PreciseFlexRailConfiguration
from pylabrobot.brooks.precise_flex.driver.master import PreciseFlexDriver


def configuration(rail=None) -> PreciseFlexConfiguration:
  per_axis = {axis: float(axis) for axis in (Axis.BASE, Axis.SHOULDER, Axis.ELBOW, Axis.WRIST)}
  return PreciseFlexConfiguration(
    manufacturer="Precise Automation",
    controller_model="G1400",
    hardware_version="B",
    gpl_version="4.2",
    controller_serial="",
    robot_name="PreciseFlex 400SX",
    robot_type=12,
    tcs_version="3.0",
    modules=("PARobot Module 3.0", "IntelliGuide 1.0"),
    num_axes=5,
    extra_axes=0,
    axis_mask=47,
    arm=PreciseFlexArmConfiguration(
      soft_limits={
        Axis.BASE: (1.5, 401.5),
        Axis.SHOULDER: (-93.0, 93.0),
        Axis.ELBOW: (12.0, 348.0),
        Axis.WRIST: (-970.0, 970.0),
      },
      hard_limits={Axis.BASE: (0.0, 403.0)},
      max_joint_speed=per_axis,
      max_joint_acceleration=per_axis,
      max_joint_deceleration=per_axis,
      max_cartesian_speed=500.0,
      max_cartesian_acceleration=2500.0,
      kinematics=kinematics.PF400Params(gripper_length=162.0),
      kinematics_source="device",
      reach_class="extended",
    ),
    gripper=PreciseFlexGripperConfiguration(
      soft_limit_range=(69.0, 134.0),
      hard_limit_range=(60.0, 145.0),
      max_speed=100.0,
      max_acceleration=1000.0,
      max_deceleration=1000.0,
    ),
    rail=rail,
    has_vision_gripper=True,
    _power_state=20,
  )


class TestSavedConfiguration(unittest.TestCase):
  """A configuration is written to a file and read back as the dataclasses it was."""

  def round_trip(self, written: PreciseFlexConfiguration) -> PreciseFlexConfiguration:
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    driver._configuration = written
    with tempfile.TemporaryDirectory() as directory:
      path = os.path.join(directory, "configuration.json")
      driver.save_configuration(path)
      with open(path, encoding="utf-8") as f:
        self.saved = json.load(f)
      return read_configuration(path)

  def test_it_reads_back_what_was_written(self):
    written = configuration()
    read = self.round_trip(written)
    self.assertEqual(read.arm, written.arm)
    self.assertEqual(read.gripper, written.gripper)
    self.assertEqual(read.modules, written.modules)
    self.assertEqual(read.robot_name, "PreciseFlex 400SX")
    self.assertIsNone(read.rail)

  def test_axes_are_written_by_name_and_read_back_as_axes(self):
    read = self.round_trip(configuration())
    self.assertEqual(
      list(self.saved["device"]["arm"]["soft_limits"]), list("BASE SHOULDER ELBOW WRIST".split())
    )
    self.assertEqual(read.arm.soft_limits[Axis.SHOULDER], (-93.0, 93.0))
    self.assertIsInstance(read.arm.kinematics, kinematics.PF400Params)

  def test_a_rail_is_read_back_with_what_it_did_not_report_left_out(self):
    read = self.round_trip(configuration(rail=PreciseFlexRailConfiguration((0.0, 1000.0))))
    self.assertEqual(read.rail, PreciseFlexRailConfiguration(soft_limit_range=(0.0, 1000.0)))
    self.assertTrue(read.has_rail)

  def test_live_state_is_not_written(self):
    read = self.round_trip(configuration())
    self.assertNotIn("_power_state", self.saved["device"])
    self.assertIsNone(read._power_state)

  def test_a_field_this_driver_no_longer_has_is_left_out(self):
    saved = {"device": {**to_jsonable(configuration()), "dropped_since": 1}}
    with tempfile.TemporaryDirectory() as directory:
      path = os.path.join(directory, "configuration.json")
      with open(path, "w", encoding="utf-8") as f:
        json.dump(saved, f)
      self.assertEqual(read_configuration(path).arm, configuration().arm)

  def test_nothing_is_saved_before_setup(self):
    driver = PreciseFlexDriver(
      host="localhost", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=60.0
    )
    with self.assertRaises(RuntimeError):
      driver.save_configuration("unused.json")
