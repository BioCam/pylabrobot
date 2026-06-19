import unittest
from typing import Tuple
from unittest.mock import AsyncMock, MagicMock, patch

from pylabrobot.brooks.precise_flex import (
  Axis,
  PreciseFlex400,
  PreciseFlex400Backend,
  PreciseFlexConfiguration,
  PreciseFlexDriver,
  PreciseFlexError,
  PreciseFlexVisionBackend,
  StereoParameters,
)
from pylabrobot.brooks.vision_introspection import (
  assemble_available,
  enumerate_vision_project,
  parse_project_member_name,
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


class TestPreciseFlex400VisionSetupHelpers(unittest.IsolatedAsyncioTestCase):
  """Vision bits that stay on the arm backend: the setup-time camera-count read and the
  StereoParameters reply parser (the orchestrations themselves moved to driver.vision)."""

  def setUp(self):
    self.backend, self.driver = _make_backend()

  async def test_try_request_camera_count_returns_positive_count(self):
    """_try_request_camera_count routes the bare CameraCount read through driver.vtool_property."""
    self.driver.vtool_property = AsyncMock(return_value="2")
    self.assertEqual(await self.backend._try_request_camera_count(), 2)
    self.driver.vtool_property.assert_awaited_once_with("System", "CameraCount")

  async def test_try_request_camera_count_treats_error_code_as_zero(self):
    """A vision error (e.g. -4016, engine absent) raised by the read resolves to 0, not a raise."""
    self.driver.vtool_property = AsyncMock(side_effect=PreciseFlexError(-4016, ""))
    self.assertEqual(await self.backend._try_request_camera_count(), 0)

  async def test_try_request_camera_count_swallows_io_failure(self):
    """An I/O failure during the read returns 0 (degrade gracefully), never raises."""
    self.driver.vtool_property = AsyncMock(side_effect=OSError("boom"))
    self.assertEqual(await self.backend._try_request_camera_count(), 0)

  def test_from_reply_rejects_wrong_field_count(self):
    """A StereoParam reply without exactly 10 fields is malformed and raises, not mis-parses."""
    with self.assertRaises(ValueError):
      StereoParameters.from_reply("too few fields")


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


class TestPreciseFlexDriverVisionPrimitives(unittest.IsolatedAsyncioTestCase):
  """The unconditional driver-level wire primitives (no guards)."""

  def setUp(self):
    self.driver = PreciseFlexDriver(host="localhost")
    self.driver.send_command = AsyncMock(return_value="")
    self.driver.io = MagicMock()

  async def test_vtool_property_write_uses_send_command(self):
    """A write (value given) goes through the normal reply parser."""
    await self.driver.vtool_property("acq1", "acquiremode", "ACQUIRE_AND_SAVE")
    self.driver.send_command.assert_awaited_once_with(
      "VToolProperty acq1 acquiremode ACQUIRE_AND_SAVE"
    )

  async def test_vtool_property_read_returns_bare_value(self):
    """A read (no value) reads the raw bare reply, bypassing the <code> <data> parser."""
    self.driver.io.write = AsyncMock()
    self.driver.io.readline = AsyncMock(return_value=b"2\r\n")
    self.assertEqual(await self.driver.vtool_property("System", "CameraCount"), "2")
    self.driver.io.write.assert_awaited_once_with(b"VToolProperty System CameraCount\n")

  async def test_vtool_property_read_raises_on_error_code(self):
    """A bare negative reply is a vision error code, not a value, so it raises."""
    self.driver.io.write = AsyncMock()
    self.driver.io.readline = AsyncMock(return_value=b"-4016\r\n")
    with self.assertRaises(PreciseFlexError):
      await self.driver.vtool_property("System", "Info")

  async def test_vprocess_sends_named_process(self):
    await self.driver.vprocess("snap")
    self.driver.send_command.assert_awaited_once_with("Vprocess snap")

  async def test_vresult_info_string_addresses_result_and_strips(self):
    """A specific result sends `VresultInfoString <tool> <idx>` and strips the leading-space pad."""
    self.driver.send_command = AsyncMock(return_value=" Code128 ABC123")
    value = await self.driver.vresult_info_string("barcode_read1", 1)
    self.driver.send_command.assert_awaited_once_with("VresultInfoString barcode_read1 1")
    self.assertEqual(value, "Code128 ABC123")

  async def test_vresult_info_string_rejects_partial_args(self):
    with self.assertRaises(ValueError):
      await self.driver.vresult_info_string("barcode_read1")

  async def test_start_led_sets_bank_brightness_then_runs_process(self):
    """start_led maps camera->Bank, sets brightness, then runs the light process - in order."""
    await self.driver.start_led("bottom", brightness=80)
    self.assertEqual(
      [c.args[0] for c in self.driver.send_command.await_args_list],
      ["VToolProperty led Bank 2", "VToolProperty led Brightness 80", "Vprocess LightControl"],
    )

  async def test_start_led_rejects_bad_camera(self):
    with self.assertRaises(ValueError):
      await self.driver.start_led("left")


class TestVisionIntrospection(unittest.TestCase):
  """FTP-based enumeration of the loaded vision project (best-effort, never raises)."""

  def test_parse_project_member_name_reads_name_field(self):
    text = "[VisionProcess]\n@Count=1\n[Name]\n@Count=1\nValue=Camera1\n[ToolCount]\n"
    self.assertEqual(parse_project_member_name(text), "Camera1")

  def test_parse_project_member_name_none_without_name_section(self):
    self.assertIsNone(parse_project_member_name("[Foo]\n@Count=1\nValue=x\n"))

  def test_assemble_available_splits_by_extension_and_ignores_others(self):
    files = {
      "Camera1.process": "[Name]\nValue=Camera1\n",
      "led.tool": "[Name]\nValue=led\n",
      "DirectShow_CameraCalibration_1.dat": "ignored",
    }
    self.assertEqual(assemble_available(files), {"processes": ["Camera1"], "tools": ["led"]})

  def test_assemble_available_falls_back_to_filename_stem(self):
    self.assertEqual(
      assemble_available({"acq1.tool": "[Foo]\n@Count=1\n"}),
      {"processes": [], "tools": ["acq1"]},
    )

  def test_enumerate_returns_none_without_credentials_or_target(self):
    self.assertIsNone(enumerate_vision_project(None, None, None, "proj"))
    self.assertIsNone(enumerate_vision_project("vhost", "user", "pw", None))

  def test_enumerate_returns_none_on_ftp_failure(self):
    """Any FTP error degrades to None, never raises (the device error backstops)."""
    with patch("ftplib.FTP") as MockFTP:
      MockFTP.return_value.connect.side_effect = OSError("unreachable")
      self.assertIsNone(enumerate_vision_project("vhost", "user", "pw", "proj"))


class TestPreciseFlexVisionBackend(unittest.IsolatedAsyncioTestCase):
  """The vision capability backend - orchestrations delegate to the driver's wire primitives."""

  def setUp(self):
    self.driver = MagicMock()
    self.driver.vtool_property = AsyncMock(return_value="")
    self.driver.vprocess = AsyncMock(return_value="0 1")
    self.driver.vresult_info_string = AsyncMock(return_value="Code128 ABC123")
    self.driver.start_led = AsyncMock()
    self.driver.send_command = AsyncMock(return_value="")
    self.vision = PreciseFlexVisionBackend(self.driver)

  async def test_capture_image_toggles_acquire_mode_around_process(self):
    await self.vision.capture_image("Camera1", "acq1", acquire_prefix="cap", acquire_path="Images")
    self.assertEqual(
      [c.args for c in self.driver.vtool_property.await_args_list],
      [
        ("acq1", "acquiremode", "ACQUIRE_AND_SAVE"),
        ("acq1", "acquirepath", "Images"),
        ("acq1", "acquireprefix", "cap"),
        ("acq1", "acquiremode", "NORMAL_ACQUIRE"),
      ],
    )
    self.driver.vprocess.assert_awaited_once_with("Camera1")

  async def test_read_barcode_runs_process_then_reads_result(self):
    value = await self.vision.read_barcode("Camera1", "barcode_read1", 1)
    self.driver.vprocess.assert_awaited_once_with("Camera1")
    self.driver.vresult_info_string.assert_awaited_once_with("barcode_read1", 1)
    self.assertEqual(value, "Code128 ABC123")

  async def test_request_camera_count_uses_vtool_property(self):
    self.driver.vtool_property = AsyncMock(return_value="2")
    self.assertEqual(await self.vision.request_camera_count(), 2)
    self.driver.vtool_property.assert_awaited_once_with("System", "CameraCount")

  async def test_set_lighting_delegates_to_start_led(self):
    await self.vision.set_lighting("bottom", brightness=80)
    self.driver.start_led.assert_awaited_once_with(
      "bottom", brightness=80, delay=None, light_tool="led", light_process="LightControl"
    )

  async def test_locate_target_sends_command_and_maps_pose(self):
    self.driver.send_command = AsyncMock(return_value="100.0 200.0 50.0 30.0 60.0 90.0")
    pose = await self.vision.locate_target(1, 1)
    self.driver.send_command.assert_awaited_once_with("StereoLocate 1 1")
    self.assertEqual((pose.location.x, pose.location.y, pose.location.z), (100.0, 200.0, 50.0))
    self.assertEqual((pose.rotation.z, pose.rotation.y, pose.rotation.x), (30.0, 60.0, 90.0))

  async def test_request_stereo_parameters_parses_reply(self):
    self.driver.send_command = AsyncMock(
      return_value="aruco_dual default_tool 100.0 1.5 4 10 11 50.0 2.0 200"
    )
    params = await self.vision.request_stereo_parameters(1, 1)
    self.driver.send_command.assert_awaited_once_with("StereoParam 1 1")
    self.assertEqual(
      (params.process_name, params.aruco1_number, params.wait_msecs), ("aruco_dual", 10, 200)
    )

  async def test_set_stereo_parameters_sends_twelve_field_command(self):
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
    await self.vision.set_stereo_parameters(params, 1, 2)
    self.driver.send_command.assert_awaited_once_with(
      "StereoParam 1 2 aruco_dual default_tool 100.0 1.5 4 10 11 50.0 2.0 200"
    )


class TestPreciseFlex400VisionExposure(unittest.IsolatedAsyncioTestCase):
  """PreciseFlex400.setup exposes self.vision iff the backend built driver.vision and skip_vision
  is not set."""

  def _device(self) -> PreciseFlex400:
    dev = PreciseFlex400(host="localhost", closed_gripper_position=500.0)
    dev._capabilities = []  # skip the real arm _on_setup (no I/O in this unit test)
    dev.driver.setup = AsyncMock()  # Device.setup calls driver.setup()
    return dev

  async def test_vision_exposed_when_driver_vision_built(self):
    dev = self._device()
    sentinel = object()
    dev.driver.vision = sentinel  # what the backend's _on_setup would have built
    await dev.setup()
    self.assertIs(dev.vision, sentinel)

  async def test_vision_skipped_with_skip_vision_flag(self):
    dev = self._device()
    dev.driver.vision = object()
    await dev.setup(skip_vision=True)
    self.assertIsNone(dev.vision)

  async def test_no_vision_when_not_installed(self):
    dev = self._device()
    dev.driver.vision = None
    await dev.setup()
    self.assertIsNone(dev.vision)
