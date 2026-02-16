# mypy: disable-error-code = attr-defined

import struct
import unittest
import unittest.mock

from pylabrobot.plate_reading.bmg_labtech.clario_star_backend import (
  ChecksumError,
  CLARIOstarBackend,
  FrameError,
  ShakerType,
  StartCorner,
  StatusFlag,
  _frame,
  _parse_status,
  _scan_mode_byte,
  _shaker_bytes,
  _unframe,
)
from pylabrobot.resources import Cor_96_wellplate_360ul_Fb


# ---------------------------------------------------------------------------
# PR 2: Protocol framing
# ---------------------------------------------------------------------------


class TestFrame(unittest.TestCase):
  """Test _frame() and _unframe() against the Go TestInit vector."""

  def test_frame_init_command(self):
    """Verify _frame() of the init payload produces the Go TestInit expected bytes."""
    payload = b"\x01\x00\x00\x10\x02\x00"
    expected = bytes([0x02, 0x00, 0x0D, 0x0C, 0x01, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x2E, 0x0D])
    self.assertEqual(_frame(payload), expected)

  def test_frame_status_command(self):
    """Verify _frame() of the status command payload."""
    payload = b"\x80\x00"
    framed = _frame(payload)
    self.assertEqual(framed[0], 0x02)  # STX
    self.assertEqual(framed[-1], 0x0D)  # CR
    size = int.from_bytes(framed[1:3], "big")
    self.assertEqual(size, len(payload) + 7)
    self.assertEqual(framed[3], 0x0C)  # NP

  def test_unframe_round_trip(self):
    """Frame then unframe recovers original payload."""
    payload = b"\x01\x02\x03\x04\x05"
    self.assertEqual(_unframe(_frame(payload)), payload)

  def test_unframe_init_response(self):
    """Unframe the Go TestInit expected frame."""
    framed = bytes([0x02, 0x00, 0x0D, 0x0C, 0x01, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x2E, 0x0D])
    self.assertEqual(_unframe(framed), b"\x01\x00\x00\x10\x02\x00")

  def test_unframe_bad_stx(self):
    payload = b"\x01\x02\x03"
    framed = bytearray(_frame(payload))
    framed[0] = 0xFF
    with self.assertRaises(FrameError):
      _unframe(bytes(framed))

  def test_unframe_bad_cr(self):
    payload = b"\x01\x02\x03"
    framed = bytearray(_frame(payload))
    framed[-1] = 0xFF
    with self.assertRaises(FrameError):
      _unframe(bytes(framed))

  def test_unframe_bad_checksum(self):
    payload = b"\x01\x02\x03"
    framed = bytearray(_frame(payload))
    framed[-2] ^= 0xFF  # corrupt checksum
    with self.assertRaises(ChecksumError):
      _unframe(bytes(framed))

  def test_unframe_too_short(self):
    with self.assertRaises(FrameError):
      _unframe(b"\x02\x00\x07")


# ---------------------------------------------------------------------------
# PR 1: Status flags
# ---------------------------------------------------------------------------


class TestParseStatus(unittest.TestCase):
  """Test _parse_status() flag extraction."""

  def test_busy_and_valid(self):
    """Byte 1 = 0x25 means BUSY (bit 5) + VALID (bit 0)."""
    # From Go TestInit response: status bytes [0x01, 0x25, 0x00, 0x27, 0x00]
    flags = _parse_status(bytes([0x01, 0x25, 0x00, 0x27, 0x00]))
    self.assertTrue(flags["valid"])
    self.assertTrue(flags["busy"])
    self.assertTrue(flags["initialized"])
    self.assertTrue(flags["drawer_open"])
    self.assertTrue(flags["plate_detected"])
    self.assertTrue(flags["z_probed"])
    self.assertFalse(flags["standby"])
    self.assertFalse(flags["running"])
    self.assertFalse(flags["unread_data"])
    self.assertFalse(flags["lid_open"])

  def test_valid_not_busy(self):
    """Byte 1 = 0x05 means VALID (bit 0) only, not BUSY."""
    flags = _parse_status(bytes([0x00, 0x05, 0x00, 0x00, 0x00]))
    self.assertTrue(flags["valid"])
    self.assertFalse(flags["busy"])

  def test_empty(self):
    """All zero bytes → all flags False."""
    flags = _parse_status(bytes([0x00, 0x00, 0x00, 0x00, 0x00]))
    self.assertTrue(all(v is False for v in flags.values()))
    self.assertEqual(len(flags), len(StatusFlag))

  def test_all_flags(self):
    """Set all bits to verify all flags are True."""
    flags = _parse_status(bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
    self.assertTrue(all(v is True for v in flags.values()))
    self.assertEqual(len(flags), len(StatusFlag))

  def test_filter_cover(self):
    """Byte 4 bit 6 → FILTER_COVER_OPEN."""
    flags = _parse_status(bytes([0x00, 0x00, 0x00, 0x00, 0x40]))
    self.assertTrue(flags["filter_cover_open"])
    # All other flags should be False
    self.assertEqual(sum(v for v in flags.values()), 1)

  def test_short_bytes(self):
    """Fewer than 5 bytes should not crash; missing bytes default to False."""
    flags = _parse_status(bytes([0x00, 0x21]))
    self.assertTrue(flags["valid"])
    self.assertTrue(flags["busy"])
    # Flags from missing bytes should be False, not absent
    self.assertFalse(flags["initialized"])
    self.assertEqual(len(flags), len(StatusFlag))


# ---------------------------------------------------------------------------
# PR 6: Shaker support
# ---------------------------------------------------------------------------


class TestShakerBytes(unittest.TestCase):
  def test_no_shake(self):
    self.assertEqual(_shaker_bytes(duration_s=0), b"\x00\x00\x00\x00")

  def test_orbital_300rpm_10s(self):
    result = _shaker_bytes(ShakerType.ORBITAL, speed_rpm=300, duration_s=10)
    # byte 0: (1<<4) | 0 = 0x10
    # byte 1: 300/100 - 1 = 2
    # bytes 2-3: 10 as uint16 BE = 0x000A
    self.assertEqual(result, bytes([0x10, 0x02, 0x00, 0x0A]))

  def test_linear_500rpm_60s(self):
    result = _shaker_bytes(ShakerType.LINEAR, speed_rpm=500, duration_s=60)
    self.assertEqual(result, bytes([0x11, 0x04, 0x00, 0x3C]))

  def test_meander_300rpm(self):
    result = _shaker_bytes(ShakerType.MEANDER, speed_rpm=300, duration_s=5)
    self.assertEqual(result, bytes([0x13, 0x02, 0x00, 0x05]))

  def test_meander_too_fast(self):
    with self.assertRaises(ValueError):
      _shaker_bytes(ShakerType.MEANDER, speed_rpm=400, duration_s=5)

  def test_invalid_speed_too_low(self):
    with self.assertRaises(ValueError):
      _shaker_bytes(ShakerType.ORBITAL, speed_rpm=50, duration_s=5)

  def test_invalid_speed_not_multiple(self):
    with self.assertRaises(ValueError):
      _shaker_bytes(ShakerType.ORBITAL, speed_rpm=150, duration_s=5)


# ---------------------------------------------------------------------------
# PR 7: Scan mode
# ---------------------------------------------------------------------------


class TestScanModeByte(unittest.TestCase):
  def test_defaults_top_left(self):
    """TOP_LEFT, bidirectional, horizontal, no flying → 0x12."""
    # bit 1 always set (0x02), corner TOP_LEFT=1 shifted left 4 (0x10) → 0x12
    self.assertEqual(_scan_mode_byte(), 0x12)

  def test_top_right(self):
    self.assertEqual(
      _scan_mode_byte(start_corner=StartCorner.TOP_RIGHT),
      (0b0011 << 4) | 0x02,  # 0x32
    )

  def test_bottom_left(self):
    self.assertEqual(
      _scan_mode_byte(start_corner=StartCorner.BOTTOM_LEFT),
      (0b0101 << 4) | 0x02,  # 0x52
    )

  def test_bottom_right(self):
    self.assertEqual(
      _scan_mode_byte(start_corner=StartCorner.BOTTOM_RIGHT),
      (0b0111 << 4) | 0x02,  # 0x72
    )

  def test_unidirectional(self):
    result = _scan_mode_byte(unidirectional=True)
    self.assertTrue(result & 0x80)  # bit 7 set

  def test_vertical(self):
    result = _scan_mode_byte(vertical=True)
    self.assertTrue(result & 0x08)  # bit 3 set

  def test_flying_mode(self):
    result = _scan_mode_byte(flying_mode=True)
    self.assertTrue(result & 0x04)  # bit 2 set

  def test_all_flags(self):
    result = _scan_mode_byte(
      start_corner=StartCorner.BOTTOM_RIGHT,
      unidirectional=True,
      vertical=True,
      flying_mode=True,
    )
    # 0x80 | 0x70 | 0x08 | 0x04 | 0x02 = 0xFE
    self.assertEqual(result, 0xFE)


# ---------------------------------------------------------------------------
# PR 3: Plate bytes and well selection
# ---------------------------------------------------------------------------


class TestPlateBytes(unittest.TestCase):
  def setUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")

  def test_plate_bytes_length(self):
    """Full-plate encoding should be 63 bytes (1 cmd + 12 geometry + 2 counts + 48 mask)."""
    result = self.backend._plate_bytes(self.plate)
    self.assertEqual(len(result), 63)

  def test_plate_bytes_prefix(self):
    """First byte is 0x04 command prefix."""
    result = self.backend._plate_bytes(self.plate)
    self.assertEqual(result[0], 0x04)

  def test_plate_bytes_geometry(self):
    """Verify geometry encoding for Cor_96_wellplate_360ul_Fb."""
    result = self.backend._plate_bytes(self.plate)

    # plate_length = 127.76 → 12776 → 0x31E8
    self.assertEqual(result[1:3], (12776).to_bytes(2, "big"))
    # plate_width = 85.48 → 8548 → 0x2164
    self.assertEqual(result[3:5], (8548).to_bytes(2, "big"))

  def test_plate_bytes_col_row_counts(self):
    """Cols and rows should be 12 and 8."""
    result = self.backend._plate_bytes(self.plate)
    self.assertEqual(result[13], 12)  # cols
    self.assertEqual(result[14], 8)  # rows

  def test_all_wells_mask(self):
    """All-wells mask: first 12 bytes 0xFF, remaining 36 bytes 0x00."""
    result = self.backend._plate_bytes(self.plate)
    mask = result[15:]  # 48-byte mask
    self.assertEqual(len(mask), 48)
    self.assertEqual(mask[:12], b"\xff" * 12)
    self.assertEqual(mask[12:], b"\x00" * 36)

  def test_partial_wells_mask_go_vector(self):
    """Verify partial well mask matches Go TestSetWells: wells {0, 13, 26, 39}."""
    all_items = self.plate.get_all_items()
    selected = [all_items[0], all_items[13], all_items[26], all_items[39]]
    result = self.backend._plate_bytes(self.plate, wells=selected)
    mask = result[15:]
    # Go TestSetWells expected first 5 bytes: [0x80, 0x04, 0x00, 0x20, 0x01]
    self.assertEqual(mask[0], 0x80)
    self.assertEqual(mask[1], 0x04)
    self.assertEqual(mask[2], 0x00)
    self.assertEqual(mask[3], 0x20)
    self.assertEqual(mask[4], 0x01)
    # Remaining bytes should be zero
    self.assertEqual(mask[5:], b"\x00" * 43)

  def test_single_well(self):
    """Selecting only well 0 → byte 0 = 0x80, rest zero."""
    all_items = self.plate.get_all_items()
    result = self.backend._plate_bytes(self.plate, wells=[all_items[0]])
    mask = result[15:]
    self.assertEqual(mask[0], 0x80)
    self.assertEqual(mask[1:], b"\x00" * 47)


class TestPlateBytesWithScan(unittest.TestCase):
  def setUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")

  def test_length(self):
    """_plate_bytes_with_scan returns 64 bytes (63 plate + 1 scan)."""
    result = self.backend._plate_bytes_with_scan(self.plate)
    self.assertEqual(len(result), 64)

  def test_scan_byte_appended(self):
    """Last byte is the scan mode byte."""
    result = self.backend._plate_bytes_with_scan(self.plate)
    self.assertEqual(result[-1], _scan_mode_byte())  # default = 0x12


class TestWellToIndex(unittest.TestCase):
  def setUp(self):
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")

  def test_first_well(self):
    well = self.plate.get_all_items()[0]
    self.assertEqual(CLARIOstarBackend._well_to_index(self.plate, well), 0)

  def test_last_well(self):
    well = self.plate.get_all_items()[-1]
    self.assertEqual(CLARIOstarBackend._well_to_index(self.plate, well), 95)

  def test_unknown_well_raises(self):
    other_plate = Cor_96_wellplate_360ul_Fb(name="other")
    well = other_plate.get_all_items()[0]
    with self.assertRaises(ValueError):
      CLARIOstarBackend._well_to_index(self.plate, well)


# ---------------------------------------------------------------------------
# PR 4: Fluorescence response parsing
# ---------------------------------------------------------------------------


class TestParseFluorescenceResponse(unittest.TestCase):
  """Test against Go flUnmarshalData test vector."""

  FL_RESPONSE_PAYLOAD = bytes(
    [
      0x02,
      0x05,
      0x06,
      0x26,
      0x00,
      0x00,
      0x21,
      0x00,
      0x03,
      0x00,
      0x03,
      0x00,
      0x03,
      0xF7,
      0xA0,
      0x01,
      0x00,
      0x01,
      0x00,
      0x03,
      0x01,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x01,
      0x01,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
      0x08,
      0x71,
      0x00,
      0x01,
      0x07,
      0xA2,
      0x00,
      0x01,
      0x09,
      0x5F,
      0x00,
    ]
  )

  def test_values(self):
    """Go test expects values [67697, 67490, 67935]."""
    values, _, _ = CLARIOstarBackend._parse_fluorescence_response(self.FL_RESPONSE_PAYLOAD)
    self.assertEqual(values, [67697, 67490, 67935])

  def test_overflow(self):
    """Go test expects overflow = 260000."""
    _, _, overflow = CLARIOstarBackend._parse_fluorescence_response(self.FL_RESPONSE_PAYLOAD)
    self.assertEqual(overflow, 260000)

  def test_count(self):
    """3 wells → 3 values."""
    values, _, _ = CLARIOstarBackend._parse_fluorescence_response(self.FL_RESPONSE_PAYLOAD)
    self.assertEqual(len(values), 3)

  def test_bad_schema_byte(self):
    """Wrong schema byte should raise."""
    bad = bytearray(self.FL_RESPONSE_PAYLOAD)
    bad[6] = 0x29  # abs schema, not fl
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_fluorescence_response(bytes(bad))

  def test_too_short(self):
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_fluorescence_response(b"\x00" * 10)


# ---------------------------------------------------------------------------
# PR 5: Absorbance response parsing
# ---------------------------------------------------------------------------


class TestParseAbsorbanceResponse(unittest.TestCase):
  """Test with a synthetic absorbance response."""

  def _build_abs_response(
    self,
    num_wells: int,
    num_wavelengths: int,
    samples: list,
    refs: list,
    chromats: list,
    ref_chan_hi: int,
    ref_chan_lo: int,
    temperature_raw: int = 250,
  ) -> bytes:
    """Build a synthetic unframed absorbance response payload."""
    payload = bytearray(36)
    payload[6] = 0x29  # schema
    payload[16:18] = num_wavelengths.to_bytes(2, "big")
    payload[20:22] = num_wells.to_bytes(2, "big")
    payload[23:25] = temperature_raw.to_bytes(2, "big")

    # Sample values: wells * wavelengths uint32s
    for v in samples:
      payload += struct.pack(">I", v)
    # Reference values: wells uint32s
    for v in refs:
      payload += struct.pack(">I", v)
    # Chromatic references: wavelengths pairs of (hi, lo) uint32s
    for hi, lo in chromats:
      payload += struct.pack(">I", hi)
      payload += struct.pack(">I", lo)
    # Reference channel hi/lo
    payload += struct.pack(">I", ref_chan_hi)
    payload += struct.pack(">I", ref_chan_lo)

    return bytes(payload)

  def test_simple_single_wavelength(self):
    """2 wells, 1 wavelength, known transmission values."""
    resp = self._build_abs_response(
      num_wells=2,
      num_wavelengths=1,
      samples=[50000, 60000],  # well0/wl0, well1/wl0
      refs=[100000, 100000],
      chromats=[(100000, 0)],
      ref_chan_hi=200000,
      ref_chan_lo=0,
    )
    transmission, temp, _ = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=1)

    self.assertAlmostEqual(temp, 25.0)
    self.assertEqual(len(transmission), 2)
    # wref = (100000 - 0) / (200000 - 0) = 0.5
    # trans[0][0] = ((50000 - 0) / (100000 - 0)) / 0.5 * 100 = 100.0
    # trans[1][0] = ((60000 - 0) / (100000 - 0)) / 0.5 * 100 = 120.0
    self.assertAlmostEqual(transmission[0][0], 100.0)
    self.assertAlmostEqual(transmission[1][0], 120.0)

  def test_multi_wavelength(self):
    """2 wells, 2 wavelengths."""
    # Data layout: samples = [w0_wl0, w1_wl0, w0_wl1, w1_wl1]
    # (wells inner, wavelengths outer — vals[i + j * wells])
    resp = self._build_abs_response(
      num_wells=2,
      num_wavelengths=2,
      samples=[40000, 50000, 60000, 70000],
      refs=[100000, 100000],
      chromats=[(100000, 0), (100000, 0)],
      ref_chan_hi=200000,
      ref_chan_lo=0,
    )
    transmission, temp, _ = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=2)

    self.assertEqual(len(transmission), 2)
    self.assertEqual(len(transmission[0]), 2)
    # wref = 0.5 for both wells
    # trans[0][0] = (40000/100000) / 0.5 * 100 = 80.0
    # trans[0][1] = (60000/100000) / 0.5 * 100 = 120.0
    # trans[1][0] = (50000/100000) / 0.5 * 100 = 100.0
    # trans[1][1] = (70000/100000) / 0.5 * 100 = 140.0
    self.assertAlmostEqual(transmission[0][0], 80.0)
    self.assertAlmostEqual(transmission[0][1], 120.0)
    self.assertAlmostEqual(transmission[1][0], 100.0)
    self.assertAlmostEqual(transmission[1][1], 140.0)

  def test_temperature(self):
    resp = self._build_abs_response(
      num_wells=1,
      num_wavelengths=1,
      samples=[50000],
      refs=[100000],
      chromats=[(100000, 0)],
      ref_chan_hi=200000,
      ref_chan_lo=0,
      temperature_raw=372,
    )
    _, temp, _ = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=1)
    self.assertAlmostEqual(temp, 37.2)

  def test_bad_schema_byte(self):
    resp = bytearray(40)
    resp[6] = 0x21  # wrong schema
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_absorbance_response(bytes(resp), num_wavelengths=1)

  def test_too_short(self):
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_absorbance_response(b"\x00" * 10, num_wavelengths=1)

  def test_zero_ref_no_crash(self):
    """Division by zero in reference should produce 0, not crash."""
    resp = self._build_abs_response(
      num_wells=1,
      num_wavelengths=1,
      samples=[50000],
      refs=[100000],
      chromats=[(100000, 0)],
      ref_chan_hi=0,  # hi == lo → wref = 0
      ref_chan_lo=0,
    )
    transmission, _, _ = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=1)
    self.assertEqual(transmission[0][0], 0)

  def test_raw_values_returned(self):
    """Raw dict contains the unprocessed detector counts and calibration data."""
    resp = self._build_abs_response(
      num_wells=2,
      num_wavelengths=1,
      samples=[50000, 60000],
      refs=[100000, 110000],
      chromats=[(100000, 5000)],
      ref_chan_hi=200000,
      ref_chan_lo=1000,
    )
    _, _, raw = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=1)

    self.assertEqual(raw["samples"], [50000.0, 60000.0])
    self.assertEqual(raw["references"], [100000.0, 110000.0])
    self.assertEqual(raw["chromatic_cal"], [(100000.0, 5000.0)])
    self.assertEqual(raw["reference_cal"], (200000.0, 1000.0))


# ---------------------------------------------------------------------------
# Integration tests with mocked FTDI IO
# ---------------------------------------------------------------------------


class TestCLARIOstarSend(unittest.IsolatedAsyncioTestCase):
  """Test send() and related methods with mocked FTDI."""

  async def asyncSetUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.backend.io = unittest.mock.MagicMock()
    self.backend.io.setup = unittest.mock.AsyncMock()
    self.backend.io.stop = unittest.mock.AsyncMock()
    self.backend.io.write = unittest.mock.AsyncMock()
    self.backend.io.read = unittest.mock.AsyncMock()
    self.backend.io.set_baudrate = unittest.mock.AsyncMock()
    self.backend.io.set_line_property = unittest.mock.AsyncMock()
    self.backend.io.set_latency_timer = unittest.mock.AsyncMock()
    self.backend.io.poll_modem_status = unittest.mock.AsyncMock()

  async def test_send_frames_and_writes(self):
    """send() should frame the payload and write it."""
    # Build a valid response for read_resp to return
    response_payload = b"\x80\x00\x05\x00\x00"
    response = _frame(response_payload)

    self.backend.io.write.return_value = 9  # len(_frame(b"\x80\x00"))
    self.backend.io.read.side_effect = [response, b""]

    result = await self.backend.send(b"\x80\x00")
    self.assertEqual(result, response)

    # Verify the written data is the framed payload
    written = self.backend.io.write.call_args[0][0]
    self.assertEqual(written, _frame(b"\x80\x00"))

  async def test_request_command_status_payload(self):
    """_request_command_status sends the correct payload."""
    response = _frame(b"\x80\x00\x05\x00\x00")
    self.backend.io.write.return_value = len(_frame(b"\x80\x00"))
    self.backend.io.read.side_effect = [response, b""]

    await self.backend._request_command_status()
    written = self.backend.io.write.call_args[0][0]
    self.assertEqual(written, _frame(b"\x80\x00"))

  async def test_request_machine_status_parses_flags(self):
    """request_machine_status() should return parsed status flags."""
    # Build a response where byte 1 of unframed payload has VALID (bit 0) set
    status_payload = b"\x00\x01\x00\x00\x00"  # only VALID flag
    response = _frame(status_payload)
    self.backend.io.write.return_value = len(_frame(b"\x80\x00"))
    self.backend.io.read.side_effect = [response, b""]

    flags = await self.backend.request_machine_status()
    self.assertTrue(flags["valid"])
    self.assertFalse(flags["busy"])


class TestCLARIOstarInitialize(unittest.IsolatedAsyncioTestCase):
  """Test initialize() sends the correct init payload."""

  async def asyncSetUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.backend.timeout = 150
    self.backend.io = unittest.mock.MagicMock()
    self.backend.io.write = unittest.mock.AsyncMock()
    self.backend.io.read = unittest.mock.AsyncMock()

  async def test_initialize_payload(self):
    """initialize() sends the init payload and polls for ready."""
    init_response = _frame(b"\x01\x00\x00\x10\x02\x00")
    # Status response: VALID only (not BUSY) → ready
    ready_response = _frame(b"\x00\x01\x00\x00\x00")

    call_count = 0

    async def mock_read(n):
      nonlocal call_count
      call_count += 1
      # First send() → init response
      if call_count == 1:
        return init_response
      # Second send() → ready status
      if call_count == 2:
        return ready_response
      return b""

    self.backend.io.write.side_effect = lambda d: len(d)
    self.backend.io.read.side_effect = mock_read

    await self.backend.initialize()

    # First write should be the framed init command
    first_write = self.backend.io.write.call_args_list[0][0][0]
    expected_init = _frame(b"\x01\x00\x00\x10\x02\x00")
    self.assertEqual(first_write, expected_init)


if __name__ == "__main__":
  unittest.main()
