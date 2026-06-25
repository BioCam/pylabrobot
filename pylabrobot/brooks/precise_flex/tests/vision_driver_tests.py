import io
import struct
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from pylabrobot.brooks.precise_flex import vision_driver
from pylabrobot.brooks.precise_flex.vision_driver import (
  PreciseVisionDriver,
  _drain_named_record,
  decode_jpeg,
  parse_engine_reply,
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


class TestEngineFraming(unittest.TestCase):
  def test_parse_engine_reply_success_and_error(self):
    self.assertEqual(parse_engine_reply("0 5.3.3.0"), "5.3.3.0")
    self.assertEqual(parse_engine_reply("0"), "")  # success with empty value
    self.assertIsNone(parse_engine_reply("-4017 some error"))

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
    with patch.object(vision_driver, "np", None), patch.object(vision_driver, "PILImage", None):
      with self.assertRaises(ImportError):
        decode_jpeg(b"\xff\xd8\xff\xe0jpeg\xff\xd9")

  def test_decode_jpeg_returns_rgb_uint8_array(self):
    # End-to-end decode (skipped when Pillow/numpy absent): a red frame decodes height-first,
    # 3-channel uint8, with the red channel dominant - i.e. RGB order, not BGR.
    if vision_driver.PILImage is None or vision_driver.np is None:
      self.skipTest("Pillow/numpy not installed")
    buf = io.BytesIO()
    vision_driver.PILImage.new("RGB", (4, 3), (200, 0, 0)).save(buf, format="JPEG")
    arr = decode_jpeg(buf.getvalue())
    self.assertEqual(arr.shape, (3, 4, 3))  # height x width x channels
    self.assertEqual(arr.dtype, vision_driver.np.uint8)
    self.assertGreater(arr[..., 0].mean(), arr[..., 2].mean())  # red > blue == RGB ordering


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

  async def test_read_next_record_returns_buffered_record(self):
    # The next complete record is framed off the stream by its announced length and returned as-is.
    jpeg = b"\xff\xd8\xff\xe0jpegbytes\xff\xd9"
    self.img.read = AsyncMock(side_effect=[_framed(1, jpeg), b""])
    self.assertEqual(await self.driver.read_next_record(), ("Primary Image [1]", jpeg))

  async def test_read_next_record_drains_buffered_records_in_order(self):
    # One socket read can carry several records; each call returns the next without re-reading.
    two = _framed(2, b"\xff\xd8\xff\xe0a\xff\xd9") + _framed(1, b"\xff\xd8\xff\xe0b\xff\xd9")
    self.img.read = AsyncMock(side_effect=[two, b""])
    first = await self.driver.read_next_record()
    second = await self.driver.read_next_record()
    assert first is not None and second is not None
    self.assertEqual((first[0], second[0]), ("Primary Image [2]", "Primary Image [1]"))
    self.img.read.assert_awaited_once()  # both records came from the one read

  async def test_read_next_record_returns_none_on_stream_end(self):
    # An empty read means the stream closed; signal it with None rather than blocking or raising.
    self.img.read = AsyncMock(return_value=b"")
    self.assertIsNone(await self.driver.read_next_record())

  async def test_read_next_record_retains_partial_record_across_timeout(self):
    # A read that times out mid-record leaves the partial bytes buffered, so the next call completes
    # the record instead of starting mid-stream (the held-socket desync guard).
    whole = _framed(1, b"\xff\xd8\xff\xe0data\xff\xd9")
    self.img.read = AsyncMock(side_effect=[whole[:20], TimeoutError, whole[20:]])
    with self.assertRaises(TimeoutError):
      await self.driver.read_next_record()
    recovered = await self.driver.read_next_record()
    assert recovered is not None
    self.assertEqual(recovered[0], "Primary Image [1]")

  async def test_read_next_record_propagates_timeout(self):
    # A read timeout surfaces as TimeoutError for the caller (capture_image) to contextualise.
    self.img.read = AsyncMock(side_effect=TimeoutError)
    with self.assertRaises(TimeoutError):
      await self.driver.read_next_record()
