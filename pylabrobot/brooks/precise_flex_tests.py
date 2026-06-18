import unittest
from typing import Tuple
from unittest.mock import AsyncMock, MagicMock

from pylabrobot.brooks.precise_flex import (
  Axis,
  PreciseFlex400Backend,
  PreciseFlexConfiguration,
  StereoParameters,
)


def _make_backend(
  closed_gripper_position: float = 500.0,
) -> Tuple[PreciseFlex400Backend, MagicMock]:
  driver = MagicMock()
  driver.send_command = AsyncMock(return_value="")
  driver.io._host = "localhost"
  backend = PreciseFlex400Backend(
    driver=driver,
    gripper_length=162.0,
    gripper_z_offset=0.0,
    closed_gripper_position=closed_gripper_position,
  )
  return backend, driver


class TestPreciseFlex400Gripper(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    # closed_gripper_position=500 ⇒ min_gripper_width(60mm) maps to 500 units.
    self.backend, self.driver = _make_backend(closed_gripper_position=500.0)

  def _sent_commands(self) -> list[str]:
    return [c.args[0] for c in self.driver.send_command.call_args_list]

  async def test_move_gripper_force_sensing_false_opens_with_position(self):
    # 80 mm ⇒ 500 + (80 - 60) = 520 firmware units.
    await self.backend.move_gripper(width=80.0, force_sensing=False)
    self.assertEqual(self._sent_commands(), ["GripOpenPos 520.0", "gripper 1"])

  async def test_move_gripper_force_sensing_true_closes_with_position(self):
    # 60 mm (the closed reference) ⇒ exactly closed_gripper_position.
    await self.backend.move_gripper(width=60.0, force_sensing=True)
    self.assertEqual(self._sent_commands(), ["GripClosePos 500.0", "gripper 2"])

  async def test_move_gripper_position_command_precedes_move(self):
    await self.backend.move_gripper(width=120.0, force_sensing=False)
    commands = self._sent_commands()
    self.assertLess(
      commands.index("GripOpenPos 560.0"),
      commands.index("gripper 1"),
      "Position must be set before the gripper move command fires.",
    )

  async def test_force_sensing_branches_use_different_firmware_commands(self):
    await self.backend.move_gripper(width=90.0, force_sensing=False)
    await self.backend.move_gripper(width=90.0, force_sensing=True)
    commands = self._sent_commands()
    self.assertIn("gripper 1", commands)
    self.assertIn("gripper 2", commands)
    self.assertIn("GripOpenPos 530.0", commands)
    self.assertIn("GripClosePos 530.0", commands)

  async def test_closed_gripper_position_shifts_units(self):
    # Different anchor ⇒ same width yields a different firmware-unit target.
    backend, driver = _make_backend(closed_gripper_position=1000.0)
    await backend.move_gripper(width=80.0, force_sensing=False)
    commands = [c.args[0] for c in driver.send_command.call_args_list]
    # 80 mm ⇒ 1000 + (80 - 60) = 1020 units.
    self.assertEqual(commands, ["GripOpenPos 1020.0", "gripper 1"])

  def test_mm_to_firmware_units_helper(self):
    # Direct check of the linear mapping.
    self.assertEqual(self.backend._mm_to_firmware_units(60.0), 500.0)
    self.assertEqual(self.backend._mm_to_firmware_units(145.0), 585.0)
    self.assertEqual(self.backend._mm_to_firmware_units(100.0), 540.0)


class TestPreciseFlex400OutOfRangeRecovery(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    self.backend, self.driver = _make_backend()
    self.driver._wait_for_eom = AsyncMock()
    self.backend._request_speed = AsyncMock(return_value=50.0)
    # Minimal stub configuration: only the soft limits the recovery logic reads.
    self.backend._configuration = MagicMock(
      soft_limits={
        Axis.SHOULDER: (-93.0, 93.0),
        Axis.ELBOW: (12.0, 348.0),
        Axis.WRIST: (-960.0, 960.0),
      }
    )

  def _move_one_axis_cmds(self) -> list[str]:
    return [
      c.args[0]
      for c in self.driver.send_command.call_args_list
      if c.args[0].startswith("MoveOneAxis")
    ]

  async def test_recover_moves_offenders_toward_limit_in_order_and_skips_wrist(self):
    """Each recoverable offender is driven 1 unit *inside* the violated limit (above-max down,
    below-min up), shoulder before elbow per _RECOVERY_ORDER; the wrist is never auto-moved."""
    self.backend.request_joint_position = AsyncMock(
      return_value={Axis.SHOULDER: 93.5, Axis.ELBOW: 9.0, Axis.WRIST: 962.0}
    )
    recovered = await self.backend.recover_axes_within_limits()
    self.assertEqual(recovered, {Axis.SHOULDER: 92.0, Axis.ELBOW: 13.0})  # wrist excluded
    cmds = self._move_one_axis_cmds()
    self.assertEqual(
      cmds, ["MoveOneAxis 2 92.0 1", "MoveOneAxis 3 13.0 1"]
    )  # shoulder (2) before elbow (3)

  async def test_recover_skips_axis_too_far_out_of_range(self):
    """An axis past its limit by more than max_distance is left in place (no unattended big sweep)."""
    self.backend.request_joint_position = AsyncMock(
      return_value={Axis.SHOULDER: 120.0}  # 27 deg past the 93 limit, beyond the 5 cap
    )
    recovered = await self.backend.recover_axes_within_limits()
    self.assertEqual(recovered, {})
    self.assertEqual(self._move_one_axis_cmds(), [])


class TestPreciseFlex400StereoParameters(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    self.backend, self.driver = _make_backend()
    # stereo commands are guarded; advertise a vision gripper with IntelliGuide loaded.
    self.backend._configuration = MagicMock(
      is_vision_gripper=True, has_vision_module=True, robot_name="PF400-VS"
    )

  async def test_request_stereo_parameters_sends_command_and_parses_reply(self):
    """request_stereo_parameters issues `StereoParam <robot> <camera>` and parses the 10
    space-separated reply fields in order (observed wire format)."""
    self.driver.send_command = AsyncMock(
      return_value="aruco_dual default_tool 100.0 1.5 4 10 11 50.0 2.0 200"
    )
    params = await self.backend.request_stereo_parameters(robot_number=1, camera_number=1)
    self.driver.send_command.assert_awaited_once_with("StereoParam 1 1")
    self.assertEqual(params.process_name, "aruco_dual")
    self.assertEqual(params.aruco1_number, 10)
    self.assertEqual(params.wait_msecs, 200)

  async def test_set_stereo_parameters_sends_twelve_field_command(self):
    """set_stereo_parameters issues `StereoParam <robot> <camera>` followed by the 10 config
    fields in order (12 args total)."""
    params = StereoParameters(
      process_name="aruco_dual",
      tool_name="default_tool",
      optimum_distance_to_target=100.0,
      optimum_window_scale_factor=1.5,
      wrist_axis_index=4,
      aruco1_number=10,
      aruco2_number=11,
      distance_between_arucos=50.0,
      max_aruco_distance_estimate_error=2.0,
      wait_msecs=200,
    )
    await self.backend.set_stereo_parameters(params, robot_number=1, camera_number=2)
    self.driver.send_command.assert_awaited_once_with(
      "StereoParam 1 2 aruco_dual default_tool 100.0 1.5 4 10 11 50.0 2.0 200"
    )

  def test_from_reply_rejects_wrong_field_count(self):
    """A reply without exactly 10 fields is malformed and raises rather than mis-parsing."""
    with self.assertRaises(ValueError):
      StereoParameters.from_reply("too few fields")

  async def test_locate_target_sends_command_and_parses_cartesian(self):
    """locate_target issues `StereoLocate <robot> <camera>` and maps the 6-field reply
    (X Y Z Yaw Pitch Roll) into a robot-frame pose: yaw->rotation.z, pitch->rotation.y,
    roll->rotation.x. Distinct angle values lock the mapping."""
    self.driver.send_command = AsyncMock(return_value="100.0 200.0 50.0 30.0 60.0 90.0")
    pose = await self.backend.locate_target(robot_number=1, camera_number=1)
    self.driver.send_command.assert_awaited_once_with("StereoLocate 1 1")
    self.assertEqual((pose.location.x, pose.location.y, pose.location.z), (100.0, 200.0, 50.0))
    self.assertEqual(pose.rotation.z, 30.0)  # yaw
    self.assertEqual(pose.rotation.y, 60.0)  # pitch
    self.assertEqual(pose.rotation.x, 90.0)  # roll


class TestPreciseFlex400CameraImage(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    self.backend, self.driver = _make_backend()
    # vision commands are guarded; advertise a vision gripper with IntelliGuide loaded.
    self.backend._configuration = MagicMock(
      is_vision_gripper=True, has_vision_module=True, robot_name="PF400-VS"
    )

  async def test_request_camera_count_reads_system_cameracount(self):
    """request_camera_count reads `VToolProperty System CameraCount`. VToolProperty replies
    with a bare value (not `<code> <data>`), so the raw reply is read directly and parsed."""
    self.driver.io.write = AsyncMock()
    self.driver.io.readline = AsyncMock(return_value=b"2\r\n")
    count = await self.backend.request_camera_count()
    self.driver.io.write.assert_awaited_once_with(b"VToolProperty System CameraCount\n")
    self.assertEqual(count, 2)

  async def test_request_vision_tool_property_raises_on_bare_error_code(self):
    """A bare negative reply (e.g. -4016) is a vision error code, not a value, so it raises
    instead of being returned as the property value."""
    from pylabrobot.brooks.precise_flex import PreciseFlexError

    self.driver.io.write = AsyncMock()
    self.driver.io.readline = AsyncMock(return_value=b"-4016\r\n")
    with self.assertRaises(PreciseFlexError):
      await self.backend.request_vision_tool_property("System", "Info")

  async def test_set_vision_tool_property_appends_value(self):
    """set_vision_tool_property issues the write form (3 args): tool, property, value. The
    value arg distinguishes a write from a read."""
    await self.backend.set_vision_tool_property("acq1", "acquiremode", "ACQUIRE_AND_SAVE")
    self.driver.send_command.assert_awaited_once_with(
      "VToolProperty acq1 acquiremode ACQUIRE_AND_SAVE"
    )

  async def test_run_vision_process_sends_named_process(self):
    """run_vision_process issues `Vprocess <name>`."""
    self.driver.send_command = AsyncMock(return_value="0 1")
    await self.backend.run_vision_process("snap")
    self.driver.send_command.assert_awaited_once_with("Vprocess snap")

  async def test_capture_image_toggles_acquire_mode_around_process(self):
    """capture_image flips the acquire tool to ACQUIRE_AND_SAVE, applies the
    prefix/path overrides, runs the process, then restores NORMAL_ACQUIRE - in that order."""
    self.driver.send_command = AsyncMock(return_value="0 1")
    await self.backend.capture_image("Camera1", "acq1", acquire_prefix="cap", acquire_path="Images")
    self.assertEqual(
      [c.args[0] for c in self.driver.send_command.await_args_list],
      [
        "VToolProperty acq1 acquiremode ACQUIRE_AND_SAVE",
        "VToolProperty acq1 acquirepath Images",
        "VToolProperty acq1 acquireprefix cap",
        "Vprocess Camera1",
        "VToolProperty acq1 acquiremode NORMAL_ACQUIRE",
      ],
    )

  async def test_capture_image_restores_mode_on_failure(self):
    """If the process errors, the acquire tool is still restored to NORMAL_ACQUIRE (finally)."""
    self.driver.send_command = AsyncMock(side_effect=[None, RuntimeError("boom"), None])
    with self.assertRaises(RuntimeError):
      await self.backend.capture_image("Camera1", "acq1")
    self.assertEqual(
      self.driver.send_command.await_args_list[-1].args[0],
      "VToolProperty acq1 acquiremode NORMAL_ACQUIRE",
    )

  async def test_capture_rejects_without_vision_module(self):
    """capture_image is VToolProperty-based, so it needs IntelliGuide loaded; without
    it the guard raises a clear error and sends nothing (would otherwise be -2805)."""
    self.backend._configuration = MagicMock(has_vision_module=False, robot_name="PF400")
    with self.assertRaises(RuntimeError):
      await self.backend.capture_image("Camera1", "acq1")
    self.driver.send_command.assert_not_awaited()

  async def test_run_vision_process_rejects_non_vision_gripper(self):
    """run_vision_process is a base Cmd.gpl command (no IntelliGuide needed), so it is gated on
    the vision gripper itself, not the vision module."""
    self.backend._configuration = MagicMock(is_vision_gripper=False, robot_name="PF400")
    with self.assertRaises(RuntimeError):
      await self.backend.run_vision_process("Camera1")
    self.driver.send_command.assert_not_awaited()

  async def test_capture_requires_setup(self):
    """Before setup the guard raises (configuration unavailable) rather than crashing."""
    self.backend._configuration = None
    with self.assertRaises(RuntimeError):
      await self.backend.capture_image("Camera1", "acq1")
    self.driver.send_command.assert_not_awaited()


class TestPreciseFlex400VisionCapability(unittest.TestCase):
  @staticmethod
  def _config(modules) -> PreciseFlexConfiguration:
    return PreciseFlexConfiguration(
      manufacturer="",
      controller_model="",
      hardware_version="",
      gpl_version="",
      controller_serial="",
      robot_name="PF400",
      robot_type=0,
      tcs_version="",
      modules=tuple(modules),
      num_axes=0,
      extra_axes=0,
      axis_mask=0,
      soft_limits={},
      hard_limits={},
      max_joint_speed={},
      max_joint_accel={},
      max_joint_decel={},
      max_cartesian_speed=0.0,
      max_cartesian_accel=0.0,
      power_state=0,
    )

  def test_has_vision_module_detects_intelliguide(self):
    """has_vision_module keys off the IntelliGuide entry in the version module list."""
    self.assertTrue(self._config(["IntelliGuide 1.0 05-22-2024"]).has_vision_module)
    self.assertFalse(self._config(["PARobot Module 3.0", "SSGrip Module 3.0"]).has_vision_module)
