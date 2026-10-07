import asyncio
import io
import struct
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from pylabrobot.brooks.precise_flex import PreciseFlexDriver
from pylabrobot.brooks.precise_flex.driver.errors import PreciseFlexError, PreciseFlexVisionError
from pylabrobot.brooks.precise_flex.driver.features import vision
from pylabrobot.brooks.precise_flex.driver.features.vision import decode_jpeg
from pylabrobot.brooks.precise_flex.driver.master import _drain_named_record
from pylabrobot.events import EventBus, use_event_bus


def _arm() -> PreciseFlexDriver:
  """A driver whose engine connections the test attaches as mocks."""
  return PreciseFlexDriver(
    host="127.0.0.1", gripper_length=162.0, gripper_z_offset=0.0, closed_gripper_position=500.0
  )


def _record(name: str, data: bytes) -> bytes:
  """One :1500 result record on the wire: the engine's fixed 16-byte header, then the name, then data.

  Header: ``01 | name_len (u8) | 00 00 00 | data_len (u32 LE) | seven 00 padding bytes``.
  """
  header = bytes([0x01, len(name)]) + b"\x00\x00\x00" + struct.pack("<I", len(data)) + b"\x00" * 7
  return header + name.encode("ascii") + data


def _framed(camera: int, jpeg: bytes = b"\xff\xd8\xff\xe0img\xff\xd9") -> bytes:
  """A ``Primary Image [camera]`` record carrying ``jpeg`` as its data."""
  return _record(f"Primary Image [{camera}]", jpeg)


class TestEnginePropertyPrimitives(unittest.IsolatedAsyncioTestCase):
  """The engine ``property get/set`` read/write primitives over a mocked :1450 property socket."""

  def setUp(self):
    self.prop = MagicMock()
    self.prop.write = AsyncMock()
    self.prop.readline = AsyncMock(return_value=b"0\r\n")
    self.engine = _arm()
    self.engine._vision_server_io = self.prop  # type: ignore[assignment]

  async def test_request_property_builds_get_and_returns_value(self):
    self.prop.readline = AsyncMock(return_value=b"0 5.3.3.0\r\n")
    self.assertEqual(
      await self.engine.request_vision_server_property("system.engineversion"), "5.3.3.0"
    )
    self.prop.write.assert_awaited_once_with(b"property get system.engineversion\r\n")

  async def test_request_property_raises_vision_error_with_code_on_negative(self):
    """A negative reply surfaces as a coded PreciseFlexVisionError (a -40xx code), not a silent None."""
    self.prop.readline = AsyncMock(return_value=b"-4017 some error\r\n")
    with self.assertRaises(PreciseFlexVisionError) as ctx:
      await self.engine.request_vision_server_property("bogus.name")
    self.assertEqual(ctx.exception.replycode, -4017)
    self.assertIsInstance(ctx.exception, PreciseFlexError)  # still caught by the base type

  async def test_set_property_builds_set(self):
    # A bare `0` is success with an empty value.
    self.assertEqual(await self.engine._set_vision_server_property("system.runtool", "acq1"), "")
    self.prop.write.assert_awaited_once_with(b"property set system.runtool acq1\r\n")

  async def test_set_property_dot_joined_tool_property_writes_one_token_key(self):
    """A tool property is addressed as the dotted ``<tool>.<property>`` key (one token on the wire)."""
    await self.engine._set_vision_server_property("acq1.brightness", 4)
    self.prop.write.assert_awaited_once_with(b"property set acq1.brightness 4\r\n")


class TestEngineFraming(unittest.TestCase):
  def test_drain_named_record_extracts_and_consumes_complete_record(self):
    jpeg = b"\xff\xd8\xff\xe0abc\xff\xd9"
    buf = bytearray(_framed(1, jpeg))
    record = _drain_named_record(buf)
    assert record is not None
    name, data = record
    self.assertEqual(name, "Primary Image [1]")
    self.assertEqual(data, jpeg)  # exactly data_len bytes, by the announced length (no FFD9 scan)
    self.assertEqual(buf, bytearray())  # consumed

  def test_drain_named_record_none_until_complete(self):
    # The header announces a longer data_len than has arrived, so the record is not yet drainable.
    buf = bytearray(_framed(1, b"\xff\xd8\xff\xe0abc\xff\xd9"))[:-3]  # truncated mid-data
    self.assertIsNone(_drain_named_record(buf))

  def test_drain_named_record_skips_non_image_record(self):
    # The stream interleaves non-image records (tool results); they frame identically and come back by
    # name so capture_image can discard them.
    buf = bytearray(_record("VisionResults[led]", b"ToolName led\r\nResultCount 0\r\n"))
    record = _drain_named_record(buf)
    assert record is not None
    name, _ = record
    self.assertEqual(name, "VisionResults[led]")
    self.assertEqual(buf, bytearray())

  def test_drain_named_record_raises_on_desync(self):
    # A record not starting with 0x01 means the stream lost alignment; fail loud, not silently.
    with self.assertRaises(ValueError):
      _drain_named_record(bytearray(b"\x99" + b"\x00" * 20))

  def test_decode_jpeg_requires_pillow_and_numpy(self):
    # Without the optional imaging deps the decoder raises a clear install error, not AttributeError.
    with patch.object(vision, "np", None), patch.object(vision, "PILImage", None):
      with self.assertRaises(ImportError):
        decode_jpeg(b"\xff\xd8\xff\xe0jpeg\xff\xd9")

  def test_decode_jpeg_returns_rgb_uint8_array(self):
    # End-to-end decode (skipped when Pillow/numpy absent): a red frame decodes height-first,
    # 3-channel uint8, with the red channel dominant - i.e. RGB order, not BGR.
    if vision.PILImage is None or vision.np is None:
      self.skipTest("Pillow/numpy not installed")
    buf = io.BytesIO()
    vision.PILImage.new("RGB", (4, 3), (200, 0, 0)).save(buf, format="JPEG")
    arr = decode_jpeg(buf.getvalue())
    self.assertEqual(arr.shape, (3, 4, 3))  # height x width x channels
    self.assertEqual(arr.dtype, vision.np.uint8)
    self.assertGreater(arr[..., 0].mean(), arr[..., 2].mean())  # red > blue == RGB ordering


class TestDriverVisionServer(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    # Configure the two engine sockets via MagicMock-typed locals, then attach them to the driver
    # (the only type-checker exceptions are the two attribute swaps).
    self.prop = MagicMock()
    self.prop.write = AsyncMock()
    self.prop.readline = AsyncMock(return_value=b"0\r\n")
    self.img = MagicMock()
    self.driver = _arm()
    self.driver._vision_server_io = self.prop  # type: ignore[assignment]
    self.driver._vision_image_io = self.img  # type: ignore[assignment]

  async def test_send_command_writes_line_and_parses_value(self):
    """To the vision server, `send_command` ends the line CRLF and returns the success value."""
    self.prop.readline = AsyncMock(return_value=b"0 5.3.3.0\r\n")
    self.assertEqual(
      await self.driver.send_command("property get system.engineversion", use_server="vision"),
      "5.3.3.0",
    )
    self.prop.write.assert_awaited_once_with(b"property get system.engineversion\r\n")

  async def test_a_vision_server_command_emits_the_firmware_command_events(self):
    self.driver._vision_host = "192.168.0.200"
    events: list = []
    event_bus = EventBus()
    event_bus.subscribe(events.append)
    with use_event_bus(event_bus):
      await self.driver.send_command("property get system.engineversion", use_server="vision")
    self.assertEqual(
      [event.name for event in events],
      ["precise_flex.firmware_command.started", "precise_flex.firmware_command.completed"],
    )
    self.assertEqual(events[0].data["device"]["host"], "192.168.0.200")
    self.assertEqual(events[0].data["device"]["port"], 1450)

  async def test_a_server_that_is_neither_is_refused(self):
    with self.assertRaisesRegex(ValueError, "use_server"):
      await self.driver.send_command("nop", use_server="engine")  # type: ignore[arg-type]

  async def test_concurrent_commands_do_not_interleave(self):
    """Two concurrent commands each keep their write paired with their own reply."""
    events: list = []

    async def write(data: bytes) -> None:
      events.append("w")
      await asyncio.sleep(0)

    async def readline() -> bytes:
      events.append("r")
      await asyncio.sleep(0)
      return b"0\r\n"

    self.prop.write, self.prop.readline = write, readline
    await asyncio.gather(
      self.driver.send_command("A", use_server="vision"),
      self.driver.send_command("B", use_server="vision"),
    )
    self.assertEqual(events, ["w", "r", "w", "r"])

  async def test_concurrent_record_reads_take_records_in_call_order(self):
    """Two concurrent readers each take a whole record, the first caller the first record."""
    first, second = _framed(1), _framed(2)
    chunks = iter([first[:10], first[10:], second[:10], second[10:]])

    async def read(n: int, timeout: float) -> bytes:
      await asyncio.sleep(0)
      return next(chunks)

    self.img.read = read
    a, b = await asyncio.gather(
      self.driver.read_next_vision_server_record(), self.driver.read_next_vision_server_record()
    )
    assert a is not None and b is not None
    self.assertEqual((a[0], b[0]), ("Primary Image [1]", "Primary Image [2]"))

  async def test_read_next_record_returns_buffered_record(self):
    # The next complete record is framed off the stream by its announced length and returned as-is.
    jpeg = b"\xff\xd8\xff\xe0jpegbytes\xff\xd9"
    self.img.read = AsyncMock(side_effect=[_framed(1, jpeg), b""])
    self.assertEqual(
      await self.driver.read_next_vision_server_record(), ("Primary Image [1]", jpeg)
    )

  async def test_read_next_record_drains_buffered_records_in_order(self):
    # One socket read can carry several records; each call returns the next without re-reading.
    two = _framed(2, b"\xff\xd8\xff\xe0a\xff\xd9") + _framed(1, b"\xff\xd8\xff\xe0b\xff\xd9")
    self.img.read = AsyncMock(side_effect=[two, b""])
    first = await self.driver.read_next_vision_server_record()
    second = await self.driver.read_next_vision_server_record()
    assert first is not None and second is not None
    self.assertEqual((first[0], second[0]), ("Primary Image [2]", "Primary Image [1]"))
    self.img.read.assert_awaited_once()  # both records came from the one read

  async def test_read_next_record_returns_none_on_stream_end(self):
    # An empty read means the stream closed; signal it with None rather than blocking or raising.
    self.img.read = AsyncMock(return_value=b"")
    self.assertIsNone(await self.driver.read_next_vision_server_record())

  async def test_read_next_record_retains_partial_record_across_timeout(self):
    # A read that times out mid-record leaves the partial bytes buffered, so the next call completes
    # the record instead of starting mid-stream (the held-socket desync guard).
    whole = _framed(1, b"\xff\xd8\xff\xe0data\xff\xd9")
    self.img.read = AsyncMock(side_effect=[whole[:20], TimeoutError, whole[20:]])
    with self.assertRaises(TimeoutError):
      await self.driver.read_next_vision_server_record()
    recovered = await self.driver.read_next_vision_server_record()
    assert recovered is not None
    self.assertEqual(recovered[0], "Primary Image [1]")

  async def test_read_next_record_propagates_timeout(self):
    # A read timeout surfaces as TimeoutError for the caller (capture_image) to contextualise.
    self.img.read = AsyncMock(side_effect=TimeoutError)
    with self.assertRaises(TimeoutError):
      await self.driver.read_next_vision_server_record()
