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
from pylabrobot.brooks.precise_flex.driver import PreciseFlexDriver
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
  """The StereoParameters reply parser."""

  def setUp(self):
    self.backend, self.driver = _make_backend()

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
  """The vision orchestrations over a mocked driver, asserting which driver primitive each calls.

  The controller property reads/writes are now primitives on the driver (tested for their wire bytes
  in TestControllerVisionPrimitives), so here the driver is mocked and we assert the backend delegates
  to ``driver.request_vision_tool_property`` / ``driver._set_vision_tool_property`` with the right args.
  """

  def setUp(self):
    self.driver = MagicMock()
    self.driver.send_command = AsyncMock(return_value="")
    self.driver.request_vision_tool_property = AsyncMock(return_value="")
    self.driver._set_vision_tool_property = AsyncMock(return_value="")
    self.vision = PreciseFlexVisionBackend(self.driver)

  async def test_run_vision_process_sends_named_process(self):
    await self.vision._run_vision_process("snap")
    self.driver.send_command.assert_awaited_once_with("Vprocess snap")

  async def test_vresult_info_string_addresses_result_and_strips(self):
    """A specific result sends `VresultInfoString <tool> <idx>` and strips the leading-space pad."""
    self.driver.send_command = AsyncMock(return_value=" Code128 ABC123")
    value = await self.vision._vresult_info_string("barcode_read1", 1)
    self.driver.send_command.assert_awaited_once_with("VresultInfoString barcode_read1 1")
    self.assertEqual(value, "Code128 ABC123")

  async def test_vresult_info_string_rejects_partial_args(self):
    with self.assertRaises(ValueError):
      await self.vision._vresult_info_string("barcode_read1")

  async def test_start_led_sets_bank_brightness_then_runs_process(self):
    """start_led writes Bank then Brightness via the controller primitive, then runs the light process."""
    await self.vision.start_led("bottom", brightness=80)
    self.assertEqual(
      [c.args for c in self.driver._set_vision_tool_property.await_args_list],
      [("led", "Bank", "2"), ("led", "Brightness", "80")],
    )
    self.driver.send_command.assert_awaited_once_with("Vprocess LightControl")

  async def test_start_led_rejects_bad_camera(self):
    with self.assertRaises(ValueError):
      await self.vision.start_led("left")  # type: ignore[arg-type]

  async def test_start_led_vision_server_without_engine_raises(self):
    """use_server='vision' needs a connected engine; without one it raises rather than relaying."""
    with self.assertRaises(RuntimeError):
      await self.vision.start_led(use_server="vision")  # this backend has no vision_driver


class TestVisionBackendOrchestrations(unittest.IsolatedAsyncioTestCase):
  """The vision orchestrations compose the wire primitives over the driver transport. Mocking the
  driver (not the backend methods) exercises the real primitive path through to the wire."""

  def setUp(self):
    self.driver = MagicMock()
    self.driver.send_command = AsyncMock(return_value="")
    self.driver.request_vision_tool_property = AsyncMock(return_value="")
    self.driver._set_vision_tool_property = AsyncMock(return_value="")
    self.vision = PreciseFlexVisionBackend(self.driver)

  async def test_save_image_toggles_acquire_mode_around_process(self):
    # "front" selects the acq1/Camera1 tool+process and toggles ACQUIRE_AND_SAVE around the run.
    await self.vision.save_image("front", acquire_prefix="cap", acquire_path="Images")
    self.assertEqual(
      [c.args for c in self.driver._set_vision_tool_property.await_args_list],
      [
        ("acq1", "acquiremode", "ACQUIRE_AND_SAVE"),
        ("acq1", "acquirepath", "Images"),
        ("acq1", "acquireprefix", "cap"),
        ("acq1", "acquiremode", "NORMAL_ACQUIRE"),  # restored after the run, in the finally
      ],
    )
    self.driver.send_command.assert_awaited_once_with("Vprocess Camera1")

  async def test_save_image_bottom_selects_acq2_camera2(self):
    # "bottom" routes to the second acquire tool/process (acq2/Camera2).
    await self.vision.save_image("bottom")
    self.assertEqual(
      [c.args for c in self.driver._set_vision_tool_property.await_args_list],
      [
        ("acq2", "acquiremode", "ACQUIRE_AND_SAVE"),
        ("acq2", "acquiremode", "NORMAL_ACQUIRE"),
      ],
    )
    self.driver.send_command.assert_awaited_once_with("Vprocess Camera2")

  async def test_save_image_rejects_unknown_camera(self):
    # Only front/bottom (or 1/2) are valid camera selectors.
    with self.assertRaises(ValueError):
      await self.vision.save_image("sideways")  # type: ignore[arg-type]

  async def test_read_barcode_runs_process_then_reads_result(self):
    self.driver.send_command = AsyncMock(side_effect=["0 1", " Code128 ABC123"])
    value = await self.vision.read_barcode("Camera1", "barcode_read1", 1)
    self.assertEqual(
      [c.args[0] for c in self.driver.send_command.await_args_list],
      ["Vprocess Camera1", "VresultInfoString barcode_read1 1"],
    )
    self.assertEqual(value, "Code128 ABC123")

  async def test_request_camera_count_uses_controller_primitive(self):
    self.driver.request_vision_tool_property = AsyncMock(return_value="2")
    self.assertEqual(await self.vision.request_camera_count(), 2)
    self.driver.request_vision_tool_property.assert_awaited_once_with("System", "CameraCount")

  async def test_stop_led_drives_bank_brightness_zero_then_runs_process(self):
    """stop_led is start_led at brightness 0 - same bank/process, brightness forced off."""
    await self.vision.stop_led("bottom")
    self.assertEqual(
      [c.args for c in self.driver._set_vision_tool_property.await_args_list],
      [("led", "Bank", "2"), ("led", "Brightness", "0")],
    )
    self.driver.send_command.assert_awaited_once_with("Vprocess LightControl")

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

  async def test_capture_image_triggers_skips_nonmatching_and_decodes(self):
    # The backend triggers cameraacquire, skips non-image and other-camera records off the engine
    # stream, then decodes the matching frame. "bottom" resolves to engine camera 2.
    jpeg = b"\xff\xd8\xff\xe0frame\xff\xd9"
    engine = MagicMock()
    engine._set_property = AsyncMock()
    engine.read_next_record = AsyncMock(
      side_effect=[
        ("VisionResults[led]", b"..."),  # non-image record - skipped
        ("Primary Image [1]", b"other"),  # other camera - skipped
        ("Primary Image [2]", jpeg),  # the wanted frame
      ]
    )
    vision = PreciseFlexVisionBackend(self.driver, vision_driver=engine)
    with patch(
      "pylabrobot.brooks.precise_flex.vision_backend.decode_jpeg",
      side_effect=lambda d: ("decoded", d),
    ) as dec:
      out = await vision.capture_image("bottom")
    engine._set_property.assert_awaited_once_with("system.cameraacquire", 2)
    dec.assert_called_once_with(jpeg)
    self.assertEqual(out, ("decoded", jpeg))

  async def test_capture_image_raises_when_stream_ends_without_frame(self):
    # read_next_record returns None at the stream end before the wanted frame - a clear error, not None.
    engine = MagicMock()
    engine._set_property = AsyncMock()
    engine.read_next_record = AsyncMock(return_value=None)
    vision = PreciseFlexVisionBackend(self.driver, vision_driver=engine)
    with self.assertRaises(RuntimeError):
      await vision.capture_image(1)

  async def test_capture_image_raises_without_engine_configured(self):
    # Calling a vision-engine method with no engine wired up is unsupported - raise, don't return None.
    with self.assertRaises(RuntimeError):
      await self.vision.capture_image(1)  # no vision_driver on self.vision


class TestPreciseFlex400VisionExposure(unittest.IsolatedAsyncioTestCase):
  """PreciseFlex400.setup asks the driver to connect vision iff the arm discovered a vision module
  and skip_vision is not set, then exposes driver.vision as self.vision."""

  def _device(self) -> PreciseFlex400:
    dev = PreciseFlex400(host="localhost", closed_gripper_position=500.0)
    dev._capabilities = []  # skip the real arm _on_setup (no I/O in this unit test)
    return dev

  async def test_vision_connected_and_exposed_when_module_present(self):
    dev = self._device()
    built = PreciseFlexVisionBackend(dev.driver)  # what driver.setup_vision would have built

    async def fake_setup_vision(host):
      dev.driver.vision = built

    with (
      patch.object(dev.driver, "setup", AsyncMock()),
      patch.object(dev, "_has_vision_module", return_value=True),
      patch.object(
        dev.driver, "setup_vision", AsyncMock(side_effect=fake_setup_vision)
      ) as setup_vision,
    ):
      await dev.setup()
    setup_vision.assert_awaited_once_with(dev._vision_host)
    self.assertIs(dev.vision, built)

  async def test_vision_skipped_with_skip_vision_flag(self):
    dev = self._device()
    with (
      patch.object(dev.driver, "setup", AsyncMock()),
      patch.object(dev, "_has_vision_module", return_value=True),
      patch.object(dev.driver, "setup_vision", AsyncMock()) as setup_vision,
    ):
      await dev.setup(skip_vision=True)
    setup_vision.assert_not_awaited()
    self.assertIsNone(dev.vision)

  async def test_no_vision_when_module_absent(self):
    dev = self._device()
    with (
      patch.object(dev.driver, "setup", AsyncMock()),
      patch.object(dev, "_has_vision_module", return_value=False),
      patch.object(dev.driver, "setup_vision", AsyncMock()) as setup_vision,
    ):
      await dev.setup()
    setup_vision.assert_not_awaited()
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
    built = PreciseFlexVisionBackend(dev.driver)  # what driver.setup_vision would have built

    async def fake_setup_vision(host):
      dev.driver.vision = built

    with (
      patch.object(dev.driver, "setup", AsyncMock()),
      patch.object(dev, "_has_vision_module", return_value=True),
      patch.object(dev.driver, "setup_vision", AsyncMock(side_effect=fake_setup_vision)),
    ):
      await dev.setup()
    self.assertIs(dev.vision, built)
    skipped = self._device()
    with (
      patch.object(skipped.driver, "setup", AsyncMock()),
      patch.object(skipped, "_has_vision_module", return_value=True),
      patch.object(skipped.driver, "setup_vision", AsyncMock()) as setup_vision,
    ):
      await skipped.setup(skip_vision=True)
    setup_vision.assert_not_awaited()
    self.assertIsNone(skipped.vision)


def _backend_with_engine() -> "tuple[PreciseFlexVisionBackend, MagicMock]":
  """A backend wired to a real PreciseVisionDriver whose property socket is mocked, returning the
  backend and the socket so tests can assert the :1450 command bytes and stub replies."""
  prop = MagicMock()
  prop.write = AsyncMock()
  prop.readline = AsyncMock(return_value=b"0\r\n")
  engine = PreciseVisionDriver("127.0.0.1")
  engine.io_property = prop  # type: ignore[assignment]
  return PreciseFlexVisionBackend(MagicMock(), vision_driver=engine), prop


class TestVisionEngineCapabilities(unittest.IsolatedAsyncioTestCase):
  """Backend capability methods over a real PreciseVision engine driver with a mocked property socket."""

  def setUp(self):
    self.vision, self.prop = _backend_with_engine()

  async def test_set_camera_setting_resolves_alias_writes_then_applies(self):
    """set_camera_setting resolves the front/bottom alias to acq<N>, writes the knob, then applies it."""
    await self.vision.set_camera_setting("bottom", "brightness", 4)
    self.assertEqual(
      [c.args[0] for c in self.prop.write.await_args_list],
      [b"property set acq2.brightness 4\r\n", b"property set system.runtool acq2\r\n"],
    )

  async def test_set_barcode_symbologies_enables_each_stored(self):
    """Each symbology is written 'true' and stored (apply=False, no runtool) for the next barcode run."""
    await self.vision.set_barcode_symbologies("barcode_read1", ["code128", "qrcode"])
    self.assertEqual(
      [c.args[0] for c in self.prop.write.await_args_list],
      [
        b"property set barcode_read1.code128 true\r\n",
        b"property set barcode_read1.qrcode true\r\n",
      ],
    )

  async def test_run_vision_tool_sends_runtool(self):
    """The internal apply primitive issues exactly `property set system.runtool <tool>`."""
    await self.vision._run_vision_tool("acq1")
    self.prop.write.assert_awaited_once_with(b"property set system.runtool acq1\r\n")

  async def test_start_led_vision_server_writes_led_props_then_runtool(self):
    """use_server='vision' writes led.bank/brightness/delay straight to the engine, then runtool led."""
    await self.vision.start_led("bottom", brightness=80, delay=5, use_server="vision")
    self.assertEqual(
      [c.args[0] for c in self.prop.write.await_args_list],
      [
        b"property set led.bank 2\r\n",
        b"property set led.brightness 80\r\n",
        b"property set led.delay 5\r\n",
        b"property set system.runtool led\r\n",
      ],
    )

  async def test_request_camera_width_sends_index_and_parses_int(self):
    """request_camera_width passes the camera index and returns an int."""
    self.prop.readline = AsyncMock(return_value=b"0 2592\r\n")
    self.assertEqual(await self.vision.request_camera_width(1), 2592)
    self.prop.write.assert_awaited_once_with(b"property get system.cameraframewidth 1\r\n")

  async def test_request_vision_tool_properties_splits_list(self):
    """request_vision_tool_properties parses the engine's name list into a list of strings."""
    self.prop.readline = AsyncMock(return_value=b"0 brightness hue gain\r\n")
    self.assertEqual(
      await self.vision.request_vision_tool_properties("acq1"), ["brightness", "hue", "gain"]
    )

  async def test_request_projects_splits_comma_list(self):
    """request_projects parses the comma-separated project list."""
    self.prop.readline = AsyncMock(return_value=b"0 arucos_cam1,VisionTest,vision_project\r\n")
    self.assertEqual(
      await self.vision.request_projects(), ["arucos_cam1", "VisionTest", "vision_project"]
    )

  async def test_request_is_licensed_parses_bool(self):
    """request_is_licensed maps the engine's True/False string to a bool."""
    self.prop.readline = AsyncMock(return_value=b"0 True\r\n")
    self.assertTrue(await self.vision.request_is_licensed())

  async def test_enumerate_project_splits_both_list_formats(self):
    """enumerate_project parses the space- and comma-separated process/tool lists."""
    self.prop.readline = AsyncMock(side_effect=[b"0 Camera1, Camera2\r\n", b"0 acq1 acq2 led\r\n"])
    self.assertEqual(
      await self.vision.enumerate_project(),
      {"processes": ["Camera1", "Camera2"], "vision_tools": ["acq1", "acq2", "led"]},
    )

  async def test_engine_methods_raise_without_engine(self):
    """Engine-dependent methods raise a clear error when no engine was configured."""
    no_engine = PreciseFlexVisionBackend(MagicMock())
    with self.assertRaises(RuntimeError):
      await no_engine._run_vision_tool("acq1")


# --- Real engine replies captured from our PF400 rig (PreciseVision 5.3.3.0). ------------------
# Ground truth, not hand-written mocks: refresh from a new capture if the device changes.
REAL_TOOLTYPES = (
  "ObjectFinder Classifier BarcodeRead Acquire ArcFitter ClearGrip ComputedLine ComputeIntersection "
  "ComputePointOnLine EdgeFinder SharpnessDetector FindBlob FindMid FixedFrame ImageProcess "
  "FiducialLocator LightControl LineFitter PixelWindow PixelWindowColor PointFinder SensorWindow"
)
REAL_LISTTOOLS = (
  "acq1 acq2 aruco1 aruco2 barcode_read1 barcode_read2 led sharpness_detector1 sharpness_detector2"
)
REAL_ACQUIREMODE_INFO = "Type[AcquireModeEnum] EnumValues[NORMAL_ACQUIRE ACQUIRE_AND_SAVE PLAY_FROM_DISK SAVE_ONLY CLEAR_BUFFER]"


class TestBackendCapturedEngineReplies(unittest.IsolatedAsyncioTestCase):
  """Backend engine reads driven by REAL captured replies - adaptive ground truth, not hand-mocks."""

  def setUp(self):
    self.vision, self.prop = _backend_with_engine()

  async def test_tooltypes_reply_yields_full_palette(self):
    """The captured system.tooltypes reply parses to all 22 tool types, incl. known members."""
    self.prop.readline = AsyncMock(return_value=b"0 " + REAL_TOOLTYPES.encode() + b"\r\n")
    types = await self.vision.request_vision_tool_types()
    self.assertEqual(len(types), 22)
    self.assertIn("FiducialLocator", types)
    self.assertIn("Acquire", types)

  async def test_listtools_reply_yields_visiontest_instances(self):
    """The captured system.listtools reply parses to the 9 VisionTest tool instances."""
    self.prop.readline = AsyncMock(return_value=b"0 " + REAL_LISTTOOLS.encode() + b"\r\n")
    self.assertEqual(await self.vision.request_vision_tools(), REAL_LISTTOOLS.split())

  async def test_toolpropertyinfo_reply_returned_verbatim(self):
    """The captured toolpropertyinfo reply (Type[...] EnumValues[...]) is returned to the caller."""
    self.prop.readline = AsyncMock(return_value=b"0 " + REAL_ACQUIREMODE_INFO.encode() + b"\r\n")
    info = await self.vision.request_vision_tool_property_info("acq1", "acquiremode")
    self.assertEqual(info, REAL_ACQUIREMODE_INFO)
    self.assertIn("EnumValues[NORMAL_ACQUIRE ACQUIRE_AND_SAVE", info or "")


class TestVisionConfigurationDiscovery(unittest.IsolatedAsyncioTestCase):
  """discover_configuration builds and caches a capability snapshot from the engine reads."""

  @staticmethod
  def _engine(*, tools, types, props, cameras, palette, projects, active, processes):
    """A MagicMock engine whose ``request_property`` answers the discovery reads from a name->reply map -
    the boundary discover_configuration now talks to (every read goes through the engine driver's
    ``request_property``)."""
    replies = {
      "system.listtools": " ".join(tools),
      "system.cameracount": str(cameras),
      "system.engineversion": "5.3.3.0",
      "system.islicensed": "True",
      "system.tooltypes": " ".join(palette),
      "system.listprojects": ",".join(projects),
      "system.projectname": active,
      "system.listprocesses": " ".join(processes),
    }
    for t in tools:
      replies[f"system.tooltype {t}"] = types[t]
      replies[f"system.toolproperties {t}"] = " ".join(props)
    for cam in range(1, cameras + 1):
      replies[f"system.cameraname {cam}"] = f"Cam{cam}"
      replies[f"system.cameratype {cam}"] = "DirectShow"
      replies[f"system.cameraframewidth {cam}"] = "2592"
      replies[f"system.cameraframeheight {cam}"] = "1944"
      replies[f"system.cameraresolutions {cam}"] = "640x480"
    e = MagicMock()
    # discovery issues only request_property(<name>) reads; map each name back to the reply table
    e.request_property = AsyncMock(side_effect=lambda name: replies.get(name))
    return e

  def _simple_engine(self):
    return self._engine(
      tools=["acq1", "aruco1"],
      types={"acq1": "Acquire", "aruco1": "FiducialLocator"},
      props=["brightness", "hue"],
      cameras=1,
      palette=["Acquire", "FiducialLocator", "BarcodeRead"],
      projects=["VisionTest", "vision_project"],
      active="VisionTest",
      processes=["Camera1"],
    )

  async def test_discover_builds_and_caches(self):
    """Discovery populates the typed snapshot (tools with type+props, cameras, palette) and caches it."""
    vision = PreciseFlexVisionBackend(MagicMock())
    vision.vision_driver = self._simple_engine()  # type: ignore[assignment]
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
    vision.vision_driver = self._simple_engine()  # type: ignore[assignment]
    await vision.discover_configuration()
    snapshot = vision.configuration.to_dict()
    self.assertEqual(snapshot["vision_version"], "5.3.3.0")
    vision_tools = snapshot["vision_tools"]
    assert isinstance(vision_tools, dict)
    self.assertEqual(vision_tools["aruco1"]["type"], "FiducialLocator")

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
    e = self._engine(
      tools=list(real_types),
      types=real_types,
      props=["brightness", "hue", "exposure"],
      cameras=2,
      palette=palette,
      projects=["arucos_cam1", "arucos_cam2", "VisionTest", "vision_project"],
      active="VisionTest",
      processes=["Camera1", "Camera2", "LightControl"],
    )
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
    driver = MagicMock()
    driver.send_command = AsyncMock(return_value="0 1")
    vision = PreciseFlexVisionBackend(driver)
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
    driver = MagicMock()
    driver.send_command = AsyncMock(return_value="0 1")
    vision = PreciseFlexVisionBackend(driver)
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


def _controller_with_io() -> "tuple[PreciseFlexDriver, MagicMock]":
  """A real controller driver whose socket is mocked, returning the driver and the socket so tests can
  assert the controller's VToolProperty wire bytes and stub replies."""
  io = MagicMock()
  io.write = AsyncMock()
  io.readline = AsyncMock(return_value=b"0\r\n")
  driver = PreciseFlexDriver(host="127.0.0.1")
  driver.io = io  # type: ignore[assignment]
  return driver, io


class TestControllerVisionPrimitives(unittest.IsolatedAsyncioTestCase):
  """The controller's VToolProperty relay primitives on PreciseFlexDriver, asserting their wire bytes.

  These cover the read bare-value / negative-raises / 3-token-write behaviour that used to live on the
  backend's ``vtool_property``; the backend now just delegates to these (see TestVisionWirePrimitives).
  """

  def setUp(self):
    self.driver, self.io = _controller_with_io()

  async def test_set_vision_tool_property_writes_three_token_command(self):
    """A write emits ``VToolProperty <tool> <prop> <value>`` and parses the normal ``0`` reply."""
    await self.driver._set_vision_tool_property("acq1", "acquiremode", "ACQUIRE_AND_SAVE")
    self.io.write.assert_awaited_once_with(b"VToolProperty acq1 acquiremode ACQUIRE_AND_SAVE\n")

  async def test_request_vision_tool_property_reads_bare_value(self):
    """A read emits the 2-token form and returns the raw bare reply (no ``<code>`` prefix)."""
    self.io.readline = AsyncMock(return_value=b"2\n")
    self.assertEqual(await self.driver.request_vision_tool_property("System", "CameraCount"), "2")
    self.io.write.assert_awaited_once_with(b"VToolProperty System CameraCount\n")

  async def test_request_vision_tool_property_raises_on_error_code(self):
    """A bare negative reply is a vision error code, not a value, so it raises."""
    self.io.readline = AsyncMock(return_value=b"-4016\n")
    with self.assertRaises(PreciseFlexError):
      await self.driver.request_vision_tool_property("System", "Info")
