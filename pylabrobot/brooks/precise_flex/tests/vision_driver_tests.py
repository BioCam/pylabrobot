import unittest
from unittest.mock import AsyncMock, MagicMock

from pylabrobot.brooks.precise_flex.vision_driver import (
  PreciseVisionDriver,
  _drain_named_image,
  parse_engine_reply,
)

# A realistic engine image header: binary preamble (length etc.) + the result name, then the JPEG.
_HDR = b"\x01\x11\x00\x00\x00\x00\x00\x00"


def _framed(camera: int, payload: bytes = b"img") -> bytes:
  """One engine image result, as on the wire: binary header + name + JPEG (FFD8…FFD9)."""
  header = _HDR + f"Primary Image [{camera}]".encode()
  jpeg = b"\xff\xd8\xff\xe0" + payload + b"\xff\xd9"
  return header + jpeg


class TestEngineFraming(unittest.TestCase):
  def test_parse_engine_reply_success_and_error(self):
    self.assertEqual(parse_engine_reply("0 5.3.3.0"), "5.3.3.0")
    self.assertEqual(parse_engine_reply("0"), "")  # success with empty value
    self.assertIsNone(parse_engine_reply("-4017 some error"))

  def test_drain_named_image_extracts_and_consumes_complete_frame(self):
    buf = bytearray(_framed(1, b"abc"))
    framed = _drain_named_image(buf)
    assert framed is not None
    header, jpeg = framed
    self.assertIn(b"Primary Image [1]", header)
    self.assertTrue(jpeg.startswith(b"\xff\xd8\xff") and jpeg.endswith(b"\xff\xd9"))
    self.assertEqual(buf, bytearray())  # consumed

  def test_drain_named_image_none_until_complete(self):
    buf = bytearray(_HDR + b"Primary Image [1]" + b"\xff\xd8\xff" + b"partial")  # no EOI yet
    self.assertIsNone(_drain_named_image(buf))


class TestPreciseVisionDriver(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    # Configure the two engine sockets via MagicMock-typed locals, then attach them to the driver
    # (the only type-checker exceptions are the two attribute swaps).
    self.prop = MagicMock()
    self.prop.write = AsyncMock()
    self.prop.readline = AsyncMock(return_value=b"0\r\n")
    self.img = MagicMock()
    self.driver = PreciseVisionDriver("127.0.0.1")
    self.driver.io_property = self.prop  # type: ignore[assignment]
    self.driver.io_image = self.img  # type: ignore[assignment]

  async def test_query_parses_success_value(self):
    self.prop.readline = AsyncMock(return_value=b"0 5.3.3.0\r\n")
    self.assertEqual(await self.driver.query("property get system.engineversion"), "5.3.3.0")
    self.prop.write.assert_awaited_once_with(b"property get system.engineversion\r\n")

  async def test_request_camera_count(self):
    self.prop.readline = AsyncMock(return_value=b"0 2\r\n")
    self.assertEqual(await self.driver.request_camera_count(), 2)

  async def test_enumerate_project_splits_both_list_formats(self):
    self.prop.readline = AsyncMock(side_effect=[b"0 Camera1, Camera2\r\n", b"0 acq1 acq2 led\r\n"])
    out = await self.driver.enumerate_project()
    self.assertEqual(
      out, {"processes": ["Camera1", "Camera2"], "vision_tools": ["acq1", "acq2", "led"]}
    )

  async def test_request_camera_image_triggers_cameraacquire_and_returns_frame(self):
    self.img.read = AsyncMock(side_effect=[_framed(1, b"jpegbytes"), b""])
    out = await self.driver.request_camera_image(1)
    self.prop.write.assert_awaited_once_with(b"property set system.cameraacquire 1\r\n")
    self.assertEqual(out, b"\xff\xd8\xff\xe0jpegbytes\xff\xd9")

  async def test_request_camera_image_skips_other_camera_then_matches(self):
    self.img.read = AsyncMock(side_effect=[_framed(2, b"other"), _framed(1, b"mine"), b""])
    self.assertEqual(await self.driver.request_camera_image(1), b"\xff\xd8\xff\xe0mine\xff\xd9")

  async def test_request_camera_image_none_on_timeout(self):
    self.img.read = AsyncMock(side_effect=TimeoutError)
    self.assertIsNone(await self.driver.request_camera_image(1))

  async def test_run_vision_tool_sends_runtool(self):
    """run_vision_tool issues exactly `property set system.runtool <tool>`."""
    await self.driver.run_vision_tool("acq1")
    self.prop.write.assert_awaited_once_with(b"property set system.runtool acq1\r\n")

  async def test_set_vision_tool_property_writes_then_applies(self):
    """set_vision_tool_property writes the value, then runs the tool (two commands) by default."""
    await self.driver.set_vision_tool_property("acq1", "brightness", 2)
    self.assertEqual(
      [c.args[0] for c in self.prop.write.await_args_list],
      [b"property set acq1.brightness 2\r\n", b"property set system.runtool acq1\r\n"],
    )

  async def test_set_vision_tool_property_apply_false_only_writes(self):
    """apply=False stores the value without running the tool (a single command)."""
    await self.driver.set_vision_tool_property("acq1", "brightness", 2, apply=False)
    self.prop.write.assert_awaited_once_with(b"property set acq1.brightness 2\r\n")

  async def test_request_vision_tool_properties_splits_list(self):
    """request_vision_tool_properties parses the engine's name list into a list of strings."""
    self.prop.readline = AsyncMock(return_value=b"0 brightness hue gain\r\n")
    self.assertEqual(
      await self.driver.request_vision_tool_properties("acq1"), ["brightness", "hue", "gain"]
    )

  async def test_request_projects_splits_comma_list(self):
    """request_projects parses the comma-separated project list."""
    self.prop.readline = AsyncMock(return_value=b"0 arucos_cam1,VisionTest,vision_project\r\n")
    self.assertEqual(
      await self.driver.request_projects(), ["arucos_cam1", "VisionTest", "vision_project"]
    )

  async def test_request_is_licensed_parses_bool(self):
    """request_is_licensed maps the engine's True/False string to a bool."""
    self.prop.readline = AsyncMock(return_value=b"0 True\r\n")
    self.assertTrue(await self.driver.request_is_licensed())
    self.prop.readline = AsyncMock(return_value=b"0 False\r\n")
    self.assertFalse(await self.driver.request_is_licensed())

  async def test_request_camera_width_sends_index_and_parses_int(self):
    """request_camera_width passes the camera index and returns an int."""
    self.prop.readline = AsyncMock(return_value=b"0 2592\r\n")
    self.assertEqual(await self.driver.request_camera_width(1), 2592)
    self.prop.write.assert_awaited_once_with(b"property get system.cameraframewidth 1\r\n")


# --- Real engine replies captured from our PF400 rig (PreciseVision 5.3.3.0). ------------------
# Ground truth, not hand-written mocks: refresh from a new capture if the device changes and the
# tests below adapt to whatever the hardware actually returns.
REAL_TOOLTYPES = (
  "ObjectFinder Classifier BarcodeRead Acquire ArcFitter ClearGrip ComputedLine ComputeIntersection "
  "ComputePointOnLine EdgeFinder SharpnessDetector FindBlob FindMid FixedFrame ImageProcess "
  "FiducialLocator LightControl LineFitter PixelWindow PixelWindowColor PointFinder SensorWindow"
)
REAL_LISTTOOLS = (
  "acq1 acq2 aruco1 aruco2 barcode_read1 barcode_read2 led sharpness_detector1 sharpness_detector2"
)
REAL_ACQUIREMODE_INFO = "Type[AcquireModeEnum] EnumValues[NORMAL_ACQUIRE ACQUIRE_AND_SAVE PLAY_FROM_DISK SAVE_ONLY CLEAR_BUFFER]"


class TestCapturedEngineReplies(unittest.IsolatedAsyncioTestCase):
  """Readers driven by REAL captured engine replies - adaptive ground truth, not hand-mocks."""

  def setUp(self):
    self.prop = MagicMock()
    self.prop.write = AsyncMock()
    self.prop.readline = AsyncMock(return_value=b"0\r\n")
    self.driver = PreciseVisionDriver("127.0.0.1")
    self.driver.io_property = self.prop  # type: ignore[assignment]

  async def test_tooltypes_reply_yields_full_palette(self):
    """The captured system.tooltypes reply parses to all 22 tool types, incl. known members."""
    self.prop.readline = AsyncMock(return_value=b"0 " + REAL_TOOLTYPES.encode() + b"\r\n")
    types = await self.driver.request_vision_tool_types()
    self.assertEqual(len(types), 22)
    self.assertIn("ObjectFinder", types)
    self.assertIn("FiducialLocator", types)
    self.assertIn("Acquire", types)

  async def test_listtools_reply_yields_visiontest_instances(self):
    """The captured system.listtools reply parses to the 9 VisionTest tool instances."""
    self.prop.readline = AsyncMock(return_value=b"0 " + REAL_LISTTOOLS.encode() + b"\r\n")
    self.assertEqual(await self.driver.request_vision_tools(), REAL_LISTTOOLS.split())

  async def test_toolpropertyinfo_reply_returned_verbatim(self):
    """The captured toolpropertyinfo reply (Type[...] EnumValues[...]) is returned to the caller."""
    self.prop.readline = AsyncMock(return_value=b"0 " + REAL_ACQUIREMODE_INFO.encode() + b"\r\n")
    info = await self.driver.request_vision_tool_property_info("acq1", "acquiremode")
    self.assertEqual(info, REAL_ACQUIREMODE_INFO)
    self.assertIn("EnumValues[NORMAL_ACQUIRE ACQUIRE_AND_SAVE", info)
