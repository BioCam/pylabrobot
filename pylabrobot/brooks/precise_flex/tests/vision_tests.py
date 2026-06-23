import unittest
from typing import Tuple
from unittest.mock import AsyncMock, MagicMock, patch

from pylabrobot.brooks.precise_flex import (
  PreciseFlex400,
  PreciseFlex3400,
  PreciseFlexArmBackend,
  PreciseFlexConfiguration,
  PreciseFlexError,
)
from pylabrobot.brooks.precise_flex.confirmed_firmware_versions import is_confirmed_vision_version
from pylabrobot.brooks.precise_flex.vision_backend import (
  PreciseFlexVisionBackend,
  StereoParameters,
  VisionConfiguration,
  requires_vision_tool,
)
from pylabrobot.brooks.precise_flex.vision_driver import PreciseVisionDriver


def _make_backend(
  closed_gripper_position: float = 500.0,
) -> Tuple[PreciseFlexArmBackend, MagicMock]:
  driver = MagicMock()
  driver.send_command = AsyncMock(return_value="")
  driver.io._host = "localhost"
  backend = PreciseFlexArmBackend(
    driver=driver,
    gripper_length=162.0,
    gripper_z_offset=0.0,
    closed_gripper_position=closed_gripper_position,
  )
  return backend, driver


class TestVisionSetupHelpers(unittest.IsolatedAsyncioTestCase):
  """The setup-time camera-count probe (runs before the vision capability exists) and the
  StereoParameters reply parser."""

  def setUp(self):
    self.backend, self.driver = _make_backend()

  async def test_try_request_camera_count_returns_positive_count(self):
    """The probe reads the bare CameraCount over driver.query_raw before configuration exists."""
    self.driver.query_raw = AsyncMock(return_value="2")
    self.assertEqual(await self.backend._try_request_camera_count(), 2)
    self.driver.query_raw.assert_awaited_once_with("VToolProperty System CameraCount")

  async def test_try_request_camera_count_treats_error_reply_as_zero(self):
    """A bare negative reply (e.g. -4016, engine absent) is not a count, so it resolves to 0."""
    self.driver.query_raw = AsyncMock(return_value="-4016")
    self.assertEqual(await self.backend._try_request_camera_count(), 0)

  async def test_try_request_camera_count_swallows_io_failure(self):
    """An I/O failure during the probe returns 0 (degrade gracefully), never raises."""
    self.driver.query_raw = AsyncMock(side_effect=OSError("boom"))
    self.assertEqual(await self.backend._try_request_camera_count(), 0)

  def test_stereo_parameters_from_reply_rejects_wrong_field_count(self):
    """A StereoParam reply without exactly 10 fields is malformed and raises, not mis-parses."""
    with self.assertRaises(ValueError):
      StereoParameters.from_reply("too few fields")


class TestVisionModuleDetection(unittest.TestCase):
  """``configuration.has_vision_module`` keys off the version module list."""

  @staticmethod
  def _config(modules) -> PreciseFlexConfiguration:
    return PreciseFlexConfiguration(
      manufacturer="",
      controller_model="",
      hardware_version="",
      gpl_version="",
      controller_serial="",
      robot_name="PF400",
      robot_type=12,  # the only recorded PreciseFlex robot type (PF400, DataID 116)
      tcs_version="",
      modules=tuple(modules),
      num_axes=0,
      extra_axes=0,
      axis_mask=0,
      soft_limits={},
      hard_limits={},
      max_joint_speed={},
      max_joint_acceleration={},
      max_joint_deceleration={},
      max_cartesian_speed=0.0,
      max_cartesian_acceleration=0.0,
      power_state=0,
    )

  def test_has_vision_module_detects_intelliguide(self):
    self.assertTrue(self._config(["IntelliGuide 1.0 05-22-2024"]).has_vision_module)
    self.assertFalse(self._config(["PARobot Module 3.0", "SSGrip Module 3.0"]).has_vision_module)


class TestVisionWirePrimitives(unittest.IsolatedAsyncioTestCase):
  """The GPL vision wire primitives on the vision backend, translated over the driver transport."""

  def setUp(self):
    self.driver = MagicMock()
    self.driver.send_command = AsyncMock(return_value="")
    self.driver.query_raw = AsyncMock(return_value="")
    self.vision = PreciseFlexVisionBackend(self.driver)

  async def test_vtool_property_write_uses_send_command(self):
    """A write (value given) goes through the normal reply parser."""
    await self.vision.vtool_property("acq1", "acquiremode", "ACQUIRE_AND_SAVE")
    self.driver.send_command.assert_awaited_once_with(
      "VToolProperty acq1 acquiremode ACQUIRE_AND_SAVE"
    )

  async def test_vtool_property_read_returns_bare_value(self):
    """A read (no value) reads the raw bare reply via query_raw, bypassing the code parser."""
    self.driver.query_raw = AsyncMock(return_value="2")
    self.assertEqual(await self.vision.vtool_property("System", "CameraCount"), "2")
    self.driver.query_raw.assert_awaited_once_with("VToolProperty System CameraCount")

  async def test_vtool_property_read_raises_on_error_code(self):
    """A bare negative reply is a vision error code, not a value, so it raises."""
    self.driver.query_raw = AsyncMock(return_value="-4016")
    with self.assertRaises(PreciseFlexError):
      await self.vision.vtool_property("System", "Info")

  async def test_run_vision_process_sends_named_process(self):
    await self.vision.run_vision_process("snap")
    self.driver.send_command.assert_awaited_once_with("Vprocess snap")

  async def test_vresult_info_string_addresses_result_and_strips(self):
    """A specific result sends `VresultInfoString <tool> <idx>` and strips the leading-space pad."""
    self.driver.send_command = AsyncMock(return_value=" Code128 ABC123")
    value = await self.vision.vresult_info_string("barcode_read1", 1)
    self.driver.send_command.assert_awaited_once_with("VresultInfoString barcode_read1 1")
    self.assertEqual(value, "Code128 ABC123")

  async def test_vresult_info_string_rejects_partial_args(self):
    with self.assertRaises(ValueError):
      await self.vision.vresult_info_string("barcode_read1")

  async def test_start_led_sets_bank_brightness_then_runs_process(self):
    """start_led maps camera->Bank, sets brightness, then runs the light process - in order."""
    await self.vision.start_led("bottom", brightness=80)
    self.assertEqual(
      [c.args[0] for c in self.driver.send_command.await_args_list],
      ["VToolProperty led Bank 2", "VToolProperty led Brightness 80", "Vprocess LightControl"],
    )

  async def test_start_led_rejects_bad_camera(self):
    with self.assertRaises(ValueError):
      await self.vision.start_led("left")  # type: ignore[arg-type]


class TestVisionBackendOrchestrations(unittest.IsolatedAsyncioTestCase):
  """The vision orchestrations compose the wire primitives over the driver transport. Mocking the
  driver (not the backend methods) exercises the real primitive path through to the wire."""

  def setUp(self):
    self.driver = MagicMock()
    self.driver.send_command = AsyncMock(return_value="")
    self.driver.query_raw = AsyncMock(return_value="")
    self.vision = PreciseFlexVisionBackend(self.driver)

  async def test_capture_image_toggles_acquire_mode_around_process(self):
    await self.vision.capture_image("Camera1", "acq1", acquire_prefix="cap", acquire_path="Images")
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

  async def test_read_barcode_runs_process_then_reads_result(self):
    self.driver.send_command = AsyncMock(side_effect=["0 1", " Code128 ABC123"])
    value = await self.vision.read_barcode("Camera1", "barcode_read1", 1)
    self.assertEqual(
      [c.args[0] for c in self.driver.send_command.await_args_list],
      ["Vprocess Camera1", "VresultInfoString barcode_read1 1"],
    )
    self.assertEqual(value, "Code128 ABC123")

  async def test_request_camera_count_uses_vtool_property(self):
    self.driver.query_raw = AsyncMock(return_value="2")
    self.assertEqual(await self.vision.request_camera_count(), 2)
    self.driver.query_raw.assert_awaited_once_with("VToolProperty System CameraCount")

  async def test_set_lighting_drives_bank_brightness_then_runs_process(self):
    await self.vision.set_lighting("bottom", brightness=80)
    self.assertEqual(
      [c.args[0] for c in self.driver.send_command.await_args_list],
      ["VToolProperty led Bank 2", "VToolProperty led Brightness 80", "Vprocess LightControl"],
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

  async def test_set_stereo_parameters_sends_command(self):
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

  async def test_request_camera_image_delegates_to_vision_driver(self):
    vision_driver = MagicMock()
    vision_driver.request_camera_image = AsyncMock(return_value=b"jpegbytes")
    vision = PreciseFlexVisionBackend(self.driver, vision_driver=vision_driver)
    self.assertEqual(await vision.request_camera_image(2), b"jpegbytes")
    vision_driver.request_camera_image.assert_awaited_once_with(2)

  async def test_request_camera_image_none_without_engine_configured(self):
    self.assertIsNone(await self.vision.request_camera_image(1))  # no vision_driver on self.vision


class TestPreciseFlex400VisionExposure(unittest.IsolatedAsyncioTestCase):
  """PreciseFlex400.setup exposes self.vision iff the backend built driver.vision and skip_vision
  is not set."""

  def _device(self) -> PreciseFlex400:
    dev = PreciseFlex400(host="localhost", closed_gripper_position=500.0)
    dev._capabilities = []  # skip the real arm _on_setup (no I/O in this unit test)
    return dev

  async def test_vision_exposed_when_driver_vision_built(self):
    dev = self._device()
    built = PreciseFlexVisionBackend(dev.driver)  # what the backend's _on_setup would have built
    dev.driver.vision = built
    with patch.object(dev.driver, "setup", AsyncMock()):
      await dev.setup()
    self.assertIs(dev.vision, built)

  async def test_vision_skipped_with_skip_vision_flag(self):
    dev = self._device()
    dev.driver.vision = PreciseFlexVisionBackend(dev.driver)
    with patch.object(dev.driver, "setup", AsyncMock()):
      await dev.setup(skip_vision=True)
    self.assertIsNone(dev.vision)

  async def test_no_vision_when_not_installed(self):
    dev = self._device()
    dev.driver.vision = None
    with patch.object(dev.driver, "setup", AsyncMock()):
      await dev.setup()
    self.assertIsNone(dev.vision)


class TestPreciseFlex3400(unittest.IsolatedAsyncioTestCase):
  """The PF3400 device wrapper composes its own backend and gates vision like the PF400."""

  def _device(self) -> PreciseFlex3400:
    dev = PreciseFlex3400(host="localhost", closed_gripper_position=500.0, gripper_length=140.0)
    dev._capabilities = []  # skip the real arm _on_setup (no I/O in this unit test)
    return dev

  def test_composes_pf3400_backend(self):
    self.assertIsInstance(self._device().arm.backend, PreciseFlexArmBackend)

  def test_gripper_length_is_required(self):
    """Unlike the PF400 there is no stock gripper_length default - it must be supplied."""
    with self.assertRaises(TypeError):
      PreciseFlex3400(host="localhost", closed_gripper_position=500.0)  # type: ignore[call-arg]

  async def test_vision_exposed_and_skippable_like_pf400(self):
    dev = self._device()
    built = PreciseFlexVisionBackend(dev.driver)  # what the backend's _on_setup would have built
    dev.driver.vision = built
    with patch.object(dev.driver, "setup", AsyncMock()):
      await dev.setup()
    self.assertIs(dev.vision, built)
    skipped = self._device()
    skipped.driver.vision = PreciseFlexVisionBackend(skipped.driver)
    with patch.object(skipped.driver, "setup", AsyncMock()):
      await skipped.setup(skip_vision=True)
    self.assertIsNone(skipped.vision)


class TestVisionEngineDelegation(unittest.IsolatedAsyncioTestCase):
  """Backend methods that delegate to the held PreciseVision engine client."""

  def setUp(self):
    self.engine = MagicMock()
    self.engine.set_vision_tool_property = AsyncMock()
    self.engine.run_vision_tool = AsyncMock()
    self.vision = PreciseFlexVisionBackend(MagicMock())
    self.vision.vision_driver = self.engine  # type: ignore[assignment]

  async def test_set_camera_setting_targets_acq_tool_and_applies(self):
    """set_camera_setting writes acq<N>.<setting> and applies it (apply=True)."""
    await self.vision.set_camera_setting(2, "brightness", 4)
    self.engine.set_vision_tool_property.assert_awaited_once_with(
      "acq2", "brightness", 4, apply=True
    )

  async def test_set_barcode_symbologies_enables_each_stored(self):
    """Each symbology is set 'true' and stored (apply=False) for the next barcode run."""
    await self.vision.set_barcode_symbologies("barcode_read1", ["code128", "qrcode"])
    calls = self.engine.set_vision_tool_property.await_args_list
    self.assertEqual(len(calls), 2)
    self.assertEqual(calls[0].args, ("barcode_read1", "code128", "true"))
    self.assertEqual(calls[0].kwargs, {"apply": False})
    self.assertEqual(calls[1].args, ("barcode_read1", "qrcode", "true"))

  async def test_engine_methods_raise_without_engine(self):
    """Engine-dependent methods raise a clear error when no engine was configured."""
    no_engine = PreciseFlexVisionBackend(MagicMock())
    with self.assertRaises(RuntimeError):
      await no_engine.run_vision_tool("acq1")


class TestVisionConfigurationDiscovery(unittest.IsolatedAsyncioTestCase):
  """discover_configuration builds and caches a capability snapshot from the engine reads."""

  def _engine(self):
    e = MagicMock()
    e.request_vision_tools = AsyncMock(return_value=["acq1", "aruco1"])
    e.request_vision_tool_type = AsyncMock(
      side_effect=lambda t: {"acq1": "Acquire", "aruco1": "FiducialLocator"}[t]
    )
    e.request_vision_tool_properties = AsyncMock(return_value=["brightness", "hue"])
    e.request_camera_count = AsyncMock(return_value=1)
    e.request_camera_name = AsyncMock(return_value="Cam1")
    e.request_camera_type = AsyncMock(return_value="DirectShow")
    e.request_camera_width = AsyncMock(return_value=2592)
    e.request_camera_height = AsyncMock(return_value=1944)
    e.request_camera_resolutions = AsyncMock(return_value=["640x480"])
    e.request_vision_version = AsyncMock(return_value="5.3.3.0")
    e.request_is_licensed = AsyncMock(return_value=True)
    e.request_vision_tool_types = AsyncMock(
      return_value=["Acquire", "FiducialLocator", "BarcodeRead"]
    )
    e.request_projects = AsyncMock(return_value=["VisionTest", "vision_project"])
    e.request_project_name = AsyncMock(return_value="VisionTest")
    e.request_processes = AsyncMock(return_value=["Camera1"])
    return e

  async def test_discover_builds_and_caches(self):
    """Discovery populates the typed snapshot (tools with type+props, cameras, palette) and caches it."""
    vision = PreciseFlexVisionBackend(MagicMock())
    vision.vision_driver = self._engine()  # type: ignore[assignment]
    config = await vision.discover_configuration()
    self.assertIs(config, vision.configuration)
    self.assertTrue(config.discovered)
    self.assertEqual(config.vision_version, "5.3.3.0")
    self.assertTrue(config.has_vision_tool("aruco1"))
    self.assertEqual(config.vision_tools["aruco1"].type, "FiducialLocator")
    self.assertEqual(config.vision_tools["acq1"].properties, ["brightness", "hue"])
    self.assertTrue(config.has_vision_tool_type("BarcodeRead"))
    self.assertEqual(config.cameras[1].width, 2592)

  async def test_discover_without_engine_is_undiscovered(self):
    """With no engine configured, discovery returns an empty, undiscovered configuration."""
    vision = PreciseFlexVisionBackend(MagicMock())  # vision_driver defaults to None
    config = await vision.discover_configuration()
    self.assertFalse(config.discovered)
    self.assertEqual(config.vision_tools, {})

  async def test_to_dict_records_snapshot(self):
    """to_dict serialises the cached configuration for recording."""
    vision = PreciseFlexVisionBackend(MagicMock())
    vision.vision_driver = self._engine()  # type: ignore[assignment]
    await vision.discover_configuration()
    snapshot = vision.configuration.to_dict()
    self.assertEqual(snapshot["vision_version"], "5.3.3.0")
    self.assertEqual(snapshot["vision_tools"]["aruco1"]["type"], "FiducialLocator")

  def test_confirmed_vision_version_record(self):
    """The confirmed-versions record flags validated vs untested engines."""
    self.assertTrue(is_confirmed_vision_version("5.3.3.0"))
    self.assertFalse(is_confirmed_vision_version("9.9.9.9"))

  async def test_discover_reproduces_real_visiontest_project(self):
    """Discovery reproduces the REAL VisionTest project (captured ground truth), not a hand-mock."""
    real_types = {
      "acq1": "Acquire",
      "acq2": "Acquire",
      "aruco1": "FiducialLocator",
      "aruco2": "FiducialLocator",
      "barcode_read1": "BarcodeRead",
      "barcode_read2": "BarcodeRead",
      "led": "LightControl",
      "sharpness_detector1": "SharpnessDetector",
      "sharpness_detector2": "SharpnessDetector",
    }
    palette = (
      "ObjectFinder Classifier BarcodeRead Acquire ArcFitter ClearGrip ComputedLine "
      "ComputeIntersection ComputePointOnLine EdgeFinder SharpnessDetector FindBlob FindMid "
      "FixedFrame ImageProcess FiducialLocator LightControl LineFitter PixelWindow PixelWindowColor "
      "PointFinder SensorWindow"
    ).split()
    e = MagicMock()
    e.request_vision_tools = AsyncMock(return_value=list(real_types))
    e.request_vision_tool_type = AsyncMock(side_effect=lambda t: real_types[t])
    e.request_vision_tool_properties = AsyncMock(return_value=["brightness", "hue", "exposure"])
    e.request_camera_count = AsyncMock(return_value=2)
    e.request_camera_name = AsyncMock(side_effect=lambda c: f"Cam{c}")
    e.request_camera_type = AsyncMock(return_value="DirectShow")
    e.request_camera_width = AsyncMock(return_value=2592)
    e.request_camera_height = AsyncMock(return_value=1944)
    e.request_camera_resolutions = AsyncMock(return_value=["640x480"])
    e.request_vision_version = AsyncMock(return_value="5.3.3.0")
    e.request_is_licensed = AsyncMock(return_value=True)
    e.request_vision_tool_types = AsyncMock(return_value=palette)
    e.request_projects = AsyncMock(
      return_value=["arucos_cam1", "arucos_cam2", "VisionTest", "vision_project"]
    )
    e.request_project_name = AsyncMock(return_value="VisionTest")
    e.request_processes = AsyncMock(return_value=["Camera1", "Camera2", "LightControl"])
    vision = PreciseFlexVisionBackend(MagicMock())
    vision.vision_driver = e  # type: ignore[assignment]
    cfg = await vision.discover_configuration()
    self.assertEqual(set(cfg.vision_tools), set(real_types))
    self.assertEqual(cfg.vision_tools["aruco1"].type, "FiducialLocator")
    self.assertEqual(cfg.vision_tools["led"].type, "LightControl")
    self.assertEqual(len(cfg.vision_tool_types), 22)
    self.assertEqual(cfg.active_project, "VisionTest")
    self.assertEqual((cfg.cameras[1].width, cfg.cameras[2].height), (2592, 1944))


class TestVisionCapabilityGating(unittest.IsolatedAsyncioTestCase):
  """@requires_vision_tool_type / @requires_vision_tool gate methods against the discovered configuration."""

  def _backend(self, types):
    vision = PreciseFlexVisionBackend(MagicMock())
    vision.driver.send_command = AsyncMock(return_value="0 1")
    vision.driver.query_raw = AsyncMock(return_value="")
    vision.configuration = VisionConfiguration(discovered=True, vision_tool_types=types)
    return vision

  async def test_gate_blocks_missing_tool_type(self):
    """A discovered engine lacking the required type raises before the method runs."""
    vision = self._backend([])  # no BarcodeRead
    with self.assertRaises(RuntimeError):
      await vision.read_barcode("Camera1")

  async def test_gate_allows_present_tool_type(self):
    """The method runs when the required type is present."""
    vision = self._backend(["BarcodeRead"])
    self.assertEqual(await vision.read_barcode("Camera1"), "0 1")

  async def test_gate_sends_no_command_when_blocked(self):
    """Sequential logic: the gate fires BEFORE any wire command is sent (no half-execution)."""
    vision = self._backend([])  # no BarcodeRead
    with self.assertRaises(RuntimeError):
      await vision.read_barcode("Camera1")
    vision.driver.send_command.assert_not_awaited()

  async def test_gate_noops_before_discovery(self):
    """An undiscovered configuration never blocks - the method runs."""
    vision = PreciseFlexVisionBackend(MagicMock())
    vision.driver.send_command = AsyncMock(return_value="0 1")
    self.assertEqual(await vision.read_barcode("Camera1"), "0 1")  # discovered defaults False

  async def test_requires_vision_tool_distinguishes_provisionable_from_unsupported(self):
    """A missing instance whose type exists is provisionable; otherwise unsupported."""

    class Dummy:
      configuration = VisionConfiguration(
        discovered=True, vision_tool_types=["FiducialLocator"], active_project="P"
      )

      @requires_vision_tool("aruco9", tool_type="FiducialLocator")
      async def needs_present_type(self) -> str:
        return "ran"

      @requires_vision_tool("widget1", tool_type="Widget")
      async def needs_absent_type(self) -> str:
        return "ran"

    dummy = Dummy()
    with self.assertRaisesRegex(RuntimeError, "provision"):
      await dummy.needs_present_type()
    with self.assertRaisesRegex(RuntimeError, "not available"):
      await dummy.needs_absent_type()


class TestVisionCommandSequences(unittest.IsolatedAsyncioTestCase):
  """Sequential logic: the ORDER of commands a behaviour emits on the wire, end to end."""

  def _backend_with_real_driver(self):
    """Backend whose vision client is a real PreciseVisionDriver over a mocked socket."""
    prop = MagicMock()
    prop.write = AsyncMock()
    prop.readline = AsyncMock(return_value=b"0\r\n")
    driver = PreciseVisionDriver("127.0.0.1")
    driver.io_property = prop  # type: ignore[assignment]
    vision = PreciseFlexVisionBackend(MagicMock())
    vision.vision_driver = driver  # type: ignore[assignment]
    return vision, prop

  async def test_set_camera_setting_writes_then_applies_on_the_wire(self):
    """set_camera_setting emits the stored write, THEN the runtool that applies it - in that order."""
    vision, prop = self._backend_with_real_driver()
    await vision.set_camera_setting(2, "brightness", 4)
    self.assertEqual(
      [c.args[0] for c in prop.write.await_args_list],
      [b"property set acq2.brightness 4\r\n", b"property set system.runtool acq2\r\n"],
    )

  async def test_run_vision_tool_without_set_emits_only_runtool(self):
    """Running a tool directly is a single command - no stray property write precedes it."""
    vision, prop = self._backend_with_real_driver()
    await vision.run_vision_tool("acq1")
    self.assertEqual(
      [c.args[0] for c in prop.write.await_args_list], [b"property set system.runtool acq1\r\n"]
    )
