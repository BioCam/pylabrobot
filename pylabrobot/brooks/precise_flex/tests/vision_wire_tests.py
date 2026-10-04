"""What every vision method sends, on the controller and on both PreciseVision engine connections.

A fake network answers at the socket, by port, so the test holds whichever class owns a connection:
the controller on :10100, the engine's property protocol on :1450 and its image stream on :1500.
"""

import unittest
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Type
from unittest.mock import AsyncMock, patch

from pylabrobot.brooks.precise_flex import PreciseFlex
from pylabrobot.brooks.precise_flex.driver.features.vision import (
  PreciseFlexVision,
  StereoParameters,
)
from pylabrobot.io.socket import Socket

from .wire_tests import _REPLIES

try:
  from PIL import Image as _PILImage
except ImportError:
  _PILImage = None  # type: ignore[assignment]

_CONTROLLER_PORT, _ENGINE_PORT, _IMAGE_PORT = 10100, 1450, 1500
_LINK = {_CONTROLLER_PORT: "controller", _ENGINE_PORT: "vision", _IMAGE_PORT: "image"}

# Controller replies for the vision relay; VToolProperty reads answer the bare value.
_CONTROLLER_REPLIES: Dict[str, str] = {
  **_REPLIES,
  "VToolProperty System CameraCount": "2",
  "VresultInfoString barcode_read1 1": "0 Code128 HELLO",
  "StereoParam 1 1": "0 Locate locator 150 0.5 4 2 3 63 2 1000",
  "StereoLocate 1 1": "0 400 100 150 10 90 180",
}

_ENGINE_REPLIES: Dict[str, str] = {
  "property get system.engineversion": "0 4.1.0",
  "property get system.islicensed": "0 True",
  "property get system.listprojects": "0 ProjA,ProjB",
  "property get system.projectname": "0 ProjA",
  "property get system.listprocesses": "0 Camera1,Camera2,LightControl,Barcode,Locate",
  "property get system.listtools": "0 acq1 acq2 led barcode_read1 locator",
  "property get system.tooltypes": "0 Acquire BarcodeRead LightControl FiducialLocator",
  "property get system.tooltype acq1": "0 Acquire",
  "property get system.tooltype acq2": "0 Acquire",
  "property get system.tooltype led": "0 LightControl",
  "property get system.tooltype barcode_read1": "0 BarcodeRead",
  "property get system.tooltype locator": "0 FiducialLocator",
  "property get system.toolproperties acq1": "0 exposure gain",
  "property get system.toolproperties acq2": "0 exposure gain",
  "property get system.toolproperties led": "0 bank brightness delay",
  "property get system.toolproperties barcode_read1": "0 code128 qrcode",
  "property get system.toolproperties locator": "0 marker",
  "property get system.cameracount": "0 2",
  "property get system.cameraname 1": "0 Front",
  "property get system.cameraname 2": "0 Bottom",
  "property get system.cameratype 1": "0 DirectShow",
  "property get system.cameratype 2": "0 DirectShow",
  "property get system.cameraframewidth 1": "0 1280",
  "property get system.cameraframewidth 2": "0 1280",
  "property get system.cameraframeheight 1": "0 960",
  "property get system.cameraframeheight 2": "0 960",
  "property get system.cameraresolutions 1": "0 640x480,1280x960",
  "property get system.cameraresolutions 2": "0 640x480,1280x960",
  "property get acq1.exposure": "0 20",
  "property get system.toolpropertyinfo acq1 exposure": "0 int 0 100",
}


def _record(name: str, data: bytes) -> bytes:
  """One result record as the engine frames it on :1500."""
  name_bytes = name.encode("ascii")
  header = bytes([0x01, len(name_bytes), 0, 0, 0]) + len(data).to_bytes(4, "little") + bytes(7)
  return header + name_bytes + data


def _jpeg() -> bytes:
  """A 2x2 JPEG frame."""
  import io

  assert _PILImage is not None
  out = io.BytesIO()
  _PILImage.new("RGB", (2, 2), (10, 20, 30)).save(out, format="JPEG")
  return out.getvalue()


class _FakeNetwork:
  """Answers every socket by port and records each line written, tagged with its link."""

  def __init__(self) -> None:
    self.sent: List[str] = []
    self.image_chunks: List[bytes] = []
    # Pushed onto the image stream when a camera acquire is triggered, as the engine does.
    self.frames_on_acquire: List[bytes] = []
    self._pending: Dict[int, List[str]] = {}

  def install(self, test: unittest.TestCase) -> None:
    network = self

    async def setup(sock: Socket) -> None:
      network.sent.append(f"{_LINK[sock._port]}: <open>")

    async def stop(sock: Socket) -> None:
      network.sent.append(f"{_LINK[sock._port]}: <close>")

    async def write(sock: Socket, data: bytes, timeout: Optional[float] = None) -> None:
      line = data.decode().strip()
      network.sent.append(f"{_LINK[sock._port]}: {line}")
      network._pending.setdefault(sock._port, []).append(line)
      if "system.cameraacquire" in line:
        network.image_chunks.extend(network.frames_on_acquire)

    async def readline(sock: Socket, timeout: Optional[float] = None) -> bytes:
      line = network._pending[sock._port].pop(0)
      replies = _ENGINE_REPLIES if sock._port == _ENGINE_PORT else _CONTROLLER_REPLIES
      return (replies.get(line, "0") + "\r\n").encode()

    async def read(sock: Socket, num_bytes: int = 128, timeout: Optional[float] = None) -> bytes:
      network.sent.append(f"{_LINK[sock._port]}: <read>")
      return network.image_chunks.pop(0) if network.image_chunks else b""

    for name, fn in (
      ("setup", setup),
      ("stop", stop),
      ("write", write),
      ("readline", readline),
      ("read", read),
    ):
      p = patch.object(Socket, name, fn)
      p.start()
      test.addCleanup(p.stop)


def _vision(arm: PreciseFlex) -> PreciseFlexVision:
  """The vision capability of an arm set up with its engine."""
  assert arm.vision is not None
  return arm.vision


_Case = Tuple[str, Callable[[PreciseFlex], Awaitable[Any]], List[str], Optional[Type[Exception]]]

# (name, call, every line sent tagged with its link, exception raised or None), on an arm set up
# with its vision engine.
_CASES: List[_Case] = [
  (
    "request_vision_tool_property",
    lambda arm: _vision(arm).request_vision_tool_property("System", "CameraCount"),
    [
      "controller: VToolProperty System CameraCount",
    ],
    None,
  ),
  (
    "request_camera_count",
    lambda arm: _vision(arm).request_camera_count(),
    [
      "controller: VToolProperty System CameraCount",
    ],
    None,
  ),
  (
    "request_vision_version",
    lambda arm: _vision(arm).request_vision_version(),
    [
      "vision: property get system.engineversion",
    ],
    None,
  ),
  (
    "request_is_licensed",
    lambda arm: _vision(arm).request_is_licensed(),
    [
      "vision: property get system.islicensed",
    ],
    None,
  ),
  (
    "request_projects",
    lambda arm: _vision(arm).request_projects(),
    [
      "vision: property get system.listprojects",
    ],
    None,
  ),
  (
    "request_project_name",
    lambda arm: _vision(arm).request_project_name(),
    [
      "vision: property get system.projectname",
    ],
    None,
  ),
  (
    "request_processes",
    lambda arm: _vision(arm).request_processes(),
    [
      "vision: property get system.listprocesses",
    ],
    None,
  ),
  (
    "request_vision_tools",
    lambda arm: _vision(arm).request_vision_tools(),
    [
      "vision: property get system.listtools",
    ],
    None,
  ),
  (
    "enumerate_project",
    lambda arm: _vision(arm).enumerate_project(),
    [
      "vision: property get system.listprocesses",
      "vision: property get system.listtools",
    ],
    None,
  ),
  (
    "discover_configuration",
    lambda arm: _vision(arm).discover_configuration(),
    [
      "vision: property get system.listtools",
      "vision: property get system.tooltype acq1",
      "vision: property get system.toolproperties acq1",
      "vision: property get system.tooltype acq2",
      "vision: property get system.toolproperties acq2",
      "vision: property get system.tooltype led",
      "vision: property get system.toolproperties led",
      "vision: property get system.tooltype barcode_read1",
      "vision: property get system.toolproperties barcode_read1",
      "vision: property get system.tooltype locator",
      "vision: property get system.toolproperties locator",
      "vision: property get system.cameracount",
      "vision: property get system.cameraname 1",
      "vision: property get system.cameratype 1",
      "vision: property get system.cameraframewidth 1",
      "vision: property get system.cameraframeheight 1",
      "vision: property get system.cameraresolutions 1",
      "vision: property get system.cameraname 2",
      "vision: property get system.cameratype 2",
      "vision: property get system.cameraframewidth 2",
      "vision: property get system.cameraframeheight 2",
      "vision: property get system.cameraresolutions 2",
      "vision: property get system.engineversion",
      "vision: property get system.islicensed",
      "vision: property get system.tooltypes",
      "vision: property get system.listprojects",
      "vision: property get system.projectname",
      "vision: property get system.listprocesses",
    ],
    None,
  ),
  (
    "request_camera_name_front",
    lambda arm: _vision(arm).request_camera_name(),
    [
      "vision: property get system.cameraname 1",
    ],
    None,
  ),
  (
    "request_camera_name_bottom",
    lambda arm: _vision(arm).request_camera_name("bottom"),
    [
      "vision: property get system.cameraname 2",
    ],
    None,
  ),
  (
    "request_camera_type",
    lambda arm: _vision(arm).request_camera_type(),
    [
      "vision: property get system.cameratype 1",
    ],
    None,
  ),
  (
    "request_camera_width",
    lambda arm: _vision(arm).request_camera_width(),
    [
      "vision: property get system.cameraframewidth 1",
    ],
    None,
  ),
  (
    "request_camera_height",
    lambda arm: _vision(arm).request_camera_height(),
    [
      "vision: property get system.cameraframeheight 1",
    ],
    None,
  ),
  (
    "request_camera_resolutions",
    lambda arm: _vision(arm).request_camera_resolutions(),
    [
      "vision: property get system.cameraresolutions 1",
    ],
    None,
  ),
  (
    "request_vision_tool_property_value",
    lambda arm: _vision(arm).request_vision_tool_property_value("acq1", "exposure"),
    [
      "vision: property get acq1.exposure",
    ],
    None,
  ),
  (
    "request_vision_tool_properties",
    lambda arm: _vision(arm).request_vision_tool_properties("acq1"),
    [
      "vision: property get system.toolproperties acq1",
    ],
    None,
  ),
  (
    "request_vision_tool_property_info",
    lambda arm: _vision(arm).request_vision_tool_property_info("acq1", "exposure"),
    [
      "vision: property get system.toolpropertyinfo acq1 exposure",
    ],
    None,
  ),
  (
    "request_vision_tool_type",
    lambda arm: _vision(arm).request_vision_tool_type("acq1"),
    [
      "vision: property get system.tooltype acq1",
    ],
    None,
  ),
  (
    "request_vision_tool_types",
    lambda arm: _vision(arm).request_vision_tool_types(),
    [
      "vision: property get system.tooltypes",
    ],
    None,
  ),
  (
    "start_led_controller",
    lambda arm: _vision(arm).start_led("front", 80, delay=5),
    [
      "controller: VToolProperty led Bank 1",
      "controller: VToolProperty led Brightness 80",
      "controller: VToolProperty led Delay 5",
      "controller: Vprocess LightControl",
    ],
    None,
  ),
  (
    "start_led_vision",
    lambda arm: _vision(arm).start_led("bottom", 60, delay=5, use_server="vision"),
    [
      "vision: property set led.bank 2",
      "vision: property set led.brightness 60",
      "vision: property set led.delay 5",
      "vision: property set system.runtool led",
    ],
    None,
  ),
  (
    "stop_led_controller",
    lambda arm: _vision(arm).stop_led(),
    [
      "controller: VToolProperty led Bank 1",
      "controller: VToolProperty led Brightness 0",
      "controller: Vprocess LightControl",
    ],
    None,
  ),
  (
    "stop_led_vision",
    lambda arm: _vision(arm).stop_led("bottom", use_server="vision"),
    [
      "vision: property set led.bank 2",
      "vision: property set led.brightness 0",
      "vision: property set system.runtool led",
    ],
    None,
  ),
  (
    "capture_image",
    lambda arm: _vision(arm).capture_image("front"),
    [
      "image: <read>",
      "image: <read>",
      "vision: property set system.cameraacquire 1",
      "image: <read>",
      "image: <read>",
      "image: <read>",
    ],
    None,
  ),
  (
    "save_image",
    lambda arm: _vision(arm).save_image("bottom", acquire_prefix="p", acquire_path="/rd"),
    [
      "controller: VToolProperty acq2 acquiremode ACQUIRE_AND_SAVE",
      "controller: VToolProperty acq2 acquirepath /rd",
      "controller: VToolProperty acq2 acquireprefix p",
      "controller: Vprocess Camera2",
      "controller: VToolProperty acq2 acquiremode NORMAL_ACQUIRE",
    ],
    None,
  ),
  (
    "set_camera_setting",
    lambda arm: _vision(arm)._set_camera_setting("front", "exposure", 30),
    [
      "vision: property set acq1.exposure 30",
      "vision: property set system.runtool acq1",
    ],
    None,
  ),
  (
    "set_barcode_symbologies",
    lambda arm: _vision(arm).set_barcode_symbologies("barcode_read1", ["code128", "qrcode"]),
    [
      "vision: property set barcode_read1.code128 true",
      "vision: property set barcode_read1.qrcode true",
    ],
    None,
  ),
  (
    "read_barcode",
    lambda arm: _vision(arm).read_barcode("Barcode"),
    [
      "controller: Vprocess Barcode",
      "controller: VresultInfoString barcode_read1 1",
    ],
    None,
  ),
  (
    "request_stereo_parameters",
    lambda arm: _vision(arm).request_stereo_parameters(),
    [
      "controller: StereoParam 1 1",
    ],
    None,
  ),
  (
    "set_stereo_parameters",
    lambda arm: _vision(arm).set_stereo_parameters(
      StereoParameters.from_reply("Locate locator 150 0.5 4 2 3 63 2 1000")
    ),
    [
      "controller: StereoParam 1 1 Locate locator 150.0 0.5 4 2 3 63.0 2.0 1000",
    ],
    None,
  ),
  (
    "locate_target",
    lambda arm: _vision(arm).locate_target(),
    [
      "controller: StereoLocate 1 1",
    ],
    None,
  ),
]

_SETUP: List[str] = [
  "controller: <open>",
  "controller: mode 0",
  "controller: hp 1 20",
  "controller: attach 1",
  "controller: home",
  "controller: freemode -1",
  "controller: pd 16078",
  "controller: pd 16077",
  "controller: pd 2003",
  "controller: pd 2002",
  "controller: version",
  "controller: pd 2700",
  "controller: pd 2702",
  "controller: pd 2704",
  "controller: pd 2705",
  "controller: pd 2706",
  "controller: pd 16050",
  "controller: pd 16051",
  "controller: pd 100",
  "controller: pd 101",
  "controller: pd 102",
  "controller: pd 103",
  "controller: pd 110",
  "controller: pd 116",
  "controller: pd 2000",
  "controller: pd 2004",
  "controller: pd 16076",
  "controller: pd 16075",
  "controller: pd 2701",
  "controller: pd 2703",
  "controller: sysState",
  "controller: pd 2800",
  "controller: wherej",
  "controller: wherej",
  "controller: wherej",
  "vision: <open>",
  "image: <open>",
  "vision: property get system.listtools",
  "vision: property get system.tooltype acq1",
  "vision: property get system.toolproperties acq1",
  "vision: property get system.tooltype acq2",
  "vision: property get system.toolproperties acq2",
  "vision: property get system.tooltype led",
  "vision: property get system.toolproperties led",
  "vision: property get system.tooltype barcode_read1",
  "vision: property get system.toolproperties barcode_read1",
  "vision: property get system.tooltype locator",
  "vision: property get system.toolproperties locator",
  "vision: property get system.cameracount",
  "vision: property get system.cameraname 1",
  "vision: property get system.cameratype 1",
  "vision: property get system.cameraframewidth 1",
  "vision: property get system.cameraframeheight 1",
  "vision: property get system.cameraresolutions 1",
  "vision: property get system.cameraname 2",
  "vision: property get system.cameratype 2",
  "vision: property get system.cameraframewidth 2",
  "vision: property get system.cameraframeheight 2",
  "vision: property get system.cameraresolutions 2",
  "vision: property get system.engineversion",
  "vision: property get system.islicensed",
  "vision: property get system.tooltypes",
  "vision: property get system.listprojects",
  "vision: property get system.projectname",
  "vision: property get system.listprocesses",
]

_STOP: List[str] = [
  "controller: attach 0",
  "controller: hp 0",
  "controller: exit",
  "image: <close>",
  "vision: <close>",
  "controller: <close>",
]


class TestPreciseFlexVisionWire(unittest.IsolatedAsyncioTestCase):
  """Each vision method sends exactly what it sends today, on the link it sends it on."""

  def setUp(self) -> None:
    sleep = patch("pylabrobot.brooks.precise_flex.driver.master.asyncio.sleep", new=AsyncMock())
    sleep.start()
    self.addCleanup(sleep.stop)
    self.network = _FakeNetwork()
    self.network.install(self)

  async def _arm(self) -> PreciseFlex:
    arm = PreciseFlex(
      host="pf400",
      gripper_length=162.0,
      gripper_z_offset=0.0,
      closed_gripper_position=80.0,
      vision_host="engine",
    )
    await arm.setup()
    return arm

  async def test_setup_with_vision(self):
    await self._arm()
    self.assertEqual(self.network.sent, _SETUP)

  async def test_stop_closes_the_engine(self):
    arm = await self._arm()
    self.network.sent.clear()
    await arm.stop()
    self.assertEqual(self.network.sent, _STOP)

  async def test_every_vision_method(self):
    for name, call, expected, error in _CASES:
      with self.subTest(name):
        if name == "capture_image" and _PILImage is None:
          continue
        arm = await self._arm()
        self.network.sent.clear()
        if name == "capture_image":
          self.network.image_chunks = [_record("Primary Image [1]", b"stale")]  # left by a tool run
          self.network.frames_on_acquire = [
            _record("VisionResults[led]", b"x"),
            _record("Primary Image [2]", _jpeg()),
            _record("Primary Image [1]", _jpeg()),
          ]
        if error is None:
          await call(arm)
        else:
          with self.assertRaises(error):
            await call(arm)
        self.assertEqual(self.network.sent, expected)


if __name__ == "__main__":
  unittest.main()
