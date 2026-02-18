# mypy: disable-error-code = attr-defined

import struct
import unittest
import unittest.mock

from pylabrobot.plate_reading.bmg_labtech.clariostar_backend import (
  ChecksumError,
  CLARIOstarBackend,
  CLARIOstarConfig,
  FrameError,
  _parse_usage_counters,
  ShakerType,
  StartCorner,
  StatusFlag,
  _frame,
  _parse_status,
  _scan_mode_byte,
  _shaker_bytes,
  _unframe,
  dump_eeprom,
)
from pylabrobot.plate_reading.bmg_labtech.clariostar_simulator import CLARIOstarSimulatorBackend
from pylabrobot.resources import Cor_96_wellplate_360ul_Fb


# ---------------------------------------------------------------------------
# PR 2: Protocol framing
# ---------------------------------------------------------------------------


def _make_response_frame(payload: bytes) -> bytes:
  """Build a 2-byte-checksum frame (response format) for _unframe tests."""
  size = len(payload) + 7
  buf = bytearray([0x02]) + size.to_bytes(2, "big") + b"\x0c" + payload
  cs = sum(buf) & 0xFFFF
  buf += cs.to_bytes(2, "big")
  buf += b"\x0d"
  return bytes(buf)


class TestFrame(unittest.TestCase):
  """Test _frame() (2-byte CS default, 1-byte CS for temperature) and _unframe()."""

  def test_frame_init_command(self):
    """Verify _frame() of the init payload produces the Go reference expected bytes."""
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

  def test_frame_round_trip(self):
    """Frame (2-byte CS) then unframe recovers original payload."""
    payload = b"\x01\x02\x03\x04\x05"
    self.assertEqual(_unframe(_frame(payload)), payload)

  def test_frame_temperature_37c(self):
    """Verify 1-byte CS frame of the temperature 37°C command matches OEM software capture."""
    payload = b"\x06\x01\x72\x00\x00"
    # OEM: 02 00 0B 0C 06 01 72 00 00 92 0D
    expected = bytes([0x02, 0x00, 0x0B, 0x0C, 0x06, 0x01, 0x72, 0x00, 0x00, 0x92, 0x0D])
    self.assertEqual(_frame(payload, single_byte_checksum=True), expected)

  def test_frame_temperature_monitor(self):
    """Verify 1-byte CS frame of the temperature monitor-only command matches OEM software capture."""
    payload = b"\x06\x00\x01\x00\x00"
    # OEM: 02 00 0B 0C 06 00 01 00 00 20 0D
    expected = bytes([0x02, 0x00, 0x0B, 0x0C, 0x06, 0x00, 0x01, 0x00, 0x00, 0x20, 0x0D])
    self.assertEqual(_frame(payload, single_byte_checksum=True), expected)

  def test_frame_temperature_off(self):
    """Verify 1-byte CS frame of the temperature off command matches OEM software capture."""
    payload = b"\x06\x00\x00\x00\x00"
    # OEM: 02 00 0B 0C 06 00 00 00 00 1F 0D
    expected = bytes([0x02, 0x00, 0x0B, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x0D])
    self.assertEqual(_frame(payload, single_byte_checksum=True), expected)

  def test_unframe_init_response(self):
    """Unframe a response with 2-byte checksum (instrument response format)."""
    framed = _make_response_frame(b"\x01\x00\x00\x10\x02\x00")
    self.assertEqual(_unframe(framed), b"\x01\x00\x00\x10\x02\x00")

  def test_unframe_bad_stx(self):
    framed = bytearray(_make_response_frame(b"\x01\x02\x03"))
    framed[0] = 0xFF
    with self.assertRaises(FrameError):
      _unframe(bytes(framed))

  def test_unframe_bad_cr(self):
    framed = bytearray(_make_response_frame(b"\x01\x02\x03"))
    framed[-1] = 0xFF
    with self.assertRaises(FrameError):
      _unframe(bytes(framed))

  def test_unframe_bad_checksum(self):
    framed = bytearray(_make_response_frame(b"\x01\x02\x03"))
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


class TestComputeScanOrder(unittest.TestCase):
  def setUp(self):
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    self.all_wells = self.plate.get_all_items()

  def _well_at(self, row: int, col: int):
    """Get the well at (row, col) from the plate."""
    return self.plate.get_item(f"{chr(65 + row)}{col + 1}")

  def test_full_plate_top_left_horizontal_unidirectional(self):
    """Default absorbance settings: row-major A1→A12, B1→B12, ..., H1→H12."""
    order = CLARIOstarBackend._compute_scan_order(
      self.plate, self.all_wells,
      start_corner=StartCorner.TOP_LEFT, unidirectional=True, vertical=False,
    )
    self.assertEqual(len(order), 96)
    # First row: A1-A12
    self.assertEqual(order[0], (0, 0))   # A1
    self.assertEqual(order[11], (0, 11)) # A12
    # Second row: B1-B12
    self.assertEqual(order[12], (1, 0))  # B1
    # Last: H12
    self.assertEqual(order[95], (7, 11))

  def test_full_plate_top_left_horizontal_bidirectional(self):
    """Snake: A1→A12, B12→B1, C1→C12, ..."""
    order = CLARIOstarBackend._compute_scan_order(
      self.plate, self.all_wells,
      start_corner=StartCorner.TOP_LEFT, unidirectional=False, vertical=False,
    )
    self.assertEqual(len(order), 96)
    # Row 0 (even): left to right
    self.assertEqual(order[0], (0, 0))
    self.assertEqual(order[11], (0, 11))
    # Row 1 (odd): right to left
    self.assertEqual(order[12], (1, 11))
    self.assertEqual(order[23], (1, 0))
    # Row 2 (even): left to right again
    self.assertEqual(order[24], (2, 0))

  def test_full_plate_bottom_right_vertical_unidirectional(self):
    """Start bottom-right, scan columns bottom-to-top, column-by-column right-to-left."""
    order = CLARIOstarBackend._compute_scan_order(
      self.plate, self.all_wells,
      start_corner=StartCorner.BOTTOM_RIGHT, unidirectional=True, vertical=True,
    )
    self.assertEqual(len(order), 96)
    # First column (rightmost=11), bottom-to-top: H12, G12, ..., A12
    self.assertEqual(order[0], (7, 11))  # H12
    self.assertEqual(order[1], (6, 11))  # G12
    self.assertEqual(order[7], (0, 11))  # A12
    # Second column (10): H11, G11, ..., A11
    self.assertEqual(order[8], (7, 10))  # H11

  def test_partial_wells_filtered_correctly(self):
    """Only selected wells appear in scan order, in traversal sequence."""
    # Select column 1 (all 8 rows)
    col1_wells = [self._well_at(r, 0) for r in range(8)]
    order = CLARIOstarBackend._compute_scan_order(
      self.plate, col1_wells,
      start_corner=StartCorner.TOP_LEFT, unidirectional=True, vertical=False,
    )
    # Row-major scan but only col 0 selected: A1, B1, C1, ..., H1
    self.assertEqual(len(order), 8)
    for i in range(8):
      self.assertEqual(order[i], (i, 0))

  def test_partial_wells_two_columns_row_major(self):
    """Partial: columns 1-2, row-major scan → A1,A2,B1,B2,...,H1,H2."""
    wells = []
    for r in range(8):
      for c in range(2):
        wells.append(self._well_at(r, c))
    order = CLARIOstarBackend._compute_scan_order(
      self.plate, wells,
      start_corner=StartCorner.TOP_LEFT, unidirectional=True, vertical=False,
    )
    self.assertEqual(len(order), 16)
    # Row 0: A1, A2
    self.assertEqual(order[0], (0, 0))
    self.assertEqual(order[1], (0, 1))
    # Row 1: B1, B2
    self.assertEqual(order[2], (1, 0))
    self.assertEqual(order[3], (1, 1))
    # Last: H2
    self.assertEqual(order[15], (7, 1))

  def test_partial_wells_snake_reverses_correctly(self):
    """Partial with bidirectional: even rows L→R, odd rows R→L."""
    wells = []
    for r in range(3):
      for c in range(3):
        wells.append(self._well_at(r, c))
    order = CLARIOstarBackend._compute_scan_order(
      self.plate, wells,
      start_corner=StartCorner.TOP_LEFT, unidirectional=False, vertical=False,
    )
    self.assertEqual(len(order), 9)
    # Row 0: (0,0), (0,1), (0,2)
    self.assertEqual(order[0], (0, 0))
    self.assertEqual(order[1], (0, 1))
    self.assertEqual(order[2], (0, 2))
    # Row 1 reversed: (1,2), (1,1), (1,0)
    self.assertEqual(order[3], (1, 2))
    self.assertEqual(order[4], (1, 1))
    self.assertEqual(order[5], (1, 0))
    # Row 2: (2,0), (2,1), (2,2)
    self.assertEqual(order[6], (2, 0))


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
    """Build a synthetic unframed absorbance response payload.

    The firmware response has 4 data groups (chromatic 1, 2, 3, reference)
    followed by 4 calibration pairs. Groups 1-2 (chromatic 2, 3) are filled
    with zeros in tests. Calibration values are raw detector counts (no encoding).
    """
    payload = bytearray(36)
    payload[6] = 0x29  # schema
    payload[18:20] = num_wavelengths.to_bytes(2, "big")
    payload[20:22] = num_wells.to_bytes(2, "big")
    payload[23:25] = temperature_raw.to_bytes(2, "big")

    # Group 0: chromatic 1 = sample detector counts (wells * wavelengths)
    for v in samples:
      payload += struct.pack(">I", v)
    # Group 1: chromatic 2 (dummy zeros in tests)
    payload += b"\x00" * (num_wells * 4)
    # Group 2: chromatic 3 (dummy zeros in tests)
    payload += b"\x00" * (num_wells * 4)
    # Group 3: reference detector counts
    for v in refs:
      payload += struct.pack(">I", v)
    # Calibration: 4 pairs of (hi, lo) raw uint32 BE — chromat1, chromat2, chromat3, ref
    for hi, lo in chromats:
      payload += struct.pack(">I", hi)
      payload += struct.pack(">I", lo)
    # Pad remaining chromatic pairs to always have 3 total
    for _ in range(3 - len(chromats)):
      payload += struct.pack(">I", 0)
      payload += struct.pack(">I", 0)
    # Reference calibration pair
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
      ref_chan_hi=100000,
      ref_chan_lo=0,
    )
    transmission, temp, _ = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=1)

    self.assertAlmostEqual(temp, 25.0)
    self.assertEqual(len(transmission), 2)
    # T = ((sample - c_lo) / (c_hi - c_lo)) * ((r_hi - r_lo) / (ref - r_lo)) * 100
    # With c_lo=0, r_lo=0, r_hi=ref: T = (sample/c_hi) * 1.0 * 100
    # trans[0][0] = 50000 / 100000 * 100 = 50.0
    # trans[1][0] = 60000 / 100000 * 100 = 60.0
    self.assertAlmostEqual(transmission[0][0], 50.0)
    self.assertAlmostEqual(transmission[1][0], 60.0)

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
      ref_chan_hi=100000,
      ref_chan_lo=0,
    )
    transmission, temp, _ = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=2)

    self.assertEqual(len(transmission), 2)
    self.assertEqual(len(transmission[0]), 2)
    # T = (sample/c_hi) * (r_hi/ref) * 100, with c_lo=r_lo=0, r_hi=ref
    # trans[0][0] = 40000 / 100000 * 100 = 40.0
    # trans[0][1] = 60000 / 100000 * 100 = 60.0
    # trans[1][0] = 50000 / 100000 * 100 = 50.0
    # trans[1][1] = 70000 / 100000 * 100 = 70.0
    self.assertAlmostEqual(transmission[0][0], 40.0)
    self.assertAlmostEqual(transmission[0][1], 60.0)
    self.assertAlmostEqual(transmission[1][0], 50.0)
    self.assertAlmostEqual(transmission[1][1], 70.0)

  def test_temperature(self):
    resp = self._build_abs_response(
      num_wells=1,
      num_wavelengths=1,
      samples=[50000],
      refs=[100000],
      chromats=[(100000, 0)],
      ref_chan_hi=100000,
      ref_chan_lo=0,
      temperature_raw=372,
    )
    _, temp, _ = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=1)
    self.assertAlmostEqual(temp, 37.2)

  def test_schema_high_bit_accepted(self):
    """0xa9 (0x29 | 0x80) should be accepted and read temperature from offset 34."""
    resp = self._build_abs_response(
      num_wells=1, num_wavelengths=1,
      samples=[50000], refs=[100000],
      chromats=[(100000, 0)], ref_chan_hi=100000, ref_chan_lo=0,
    )
    resp = bytearray(resp)
    resp[6] = 0xA9
    # Place temperature at offset 34 (the high-bit layout)
    resp[34:36] = (363).to_bytes(2, "big")  # 36.3 °C
    transmission, temp, _ = CLARIOstarBackend._parse_absorbance_response(bytes(resp), num_wavelengths=1)
    self.assertEqual(len(transmission), 1)
    self.assertAlmostEqual(temp, 36.3)

  def test_schema_high_bit_incubation_off_fallback(self):
    """0xa9 with offset 34 = 0 (incubation just turned off) should fall back to offset 23."""
    resp = self._build_abs_response(
      num_wells=1, num_wavelengths=1,
      samples=[50000], refs=[100000],
      chromats=[(100000, 0)], ref_chan_hi=100000, ref_chan_lo=0,
      temperature_raw=260,  # 26.0 °C at offset 23
    )
    resp = bytearray(resp)
    resp[6] = 0xA9
    # offset 34 stays 0 (default from bytearray) — incubation off
    transmission, temp, _ = CLARIOstarBackend._parse_absorbance_response(bytes(resp), num_wavelengths=1)
    self.assertAlmostEqual(temp, 26.0)

  def test_schema_high_bit_both_offsets_implausible(self):
    """0xa9 with both offsets ~0 (post-incubation) returns None for temperature."""
    resp = self._build_abs_response(
      num_wells=1, num_wavelengths=1,
      samples=[50000], refs=[100000],
      chromats=[(100000, 0)], ref_chan_hi=100000, ref_chan_lo=0,
      temperature_raw=1,  # 0.1 °C at offset 23 — firmware noise
    )
    resp = bytearray(resp)
    resp[6] = 0xA9
    # offset 34 stays 0 — firmware noise
    transmission, temp, _ = CLARIOstarBackend._parse_absorbance_response(bytes(resp), num_wavelengths=1)
    self.assertIsNone(temp)

  def test_bad_schema_byte(self):
    resp = bytearray(40)
    resp[6] = 0x21  # wrong schema
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_absorbance_response(bytes(resp), num_wavelengths=1)

  def test_too_short(self):
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_absorbance_response(b"\x00" * 10, num_wavelengths=1)

  def test_zero_chromat_hi_no_crash(self):
    """Division by zero in chromat_hi should produce 0, not crash."""
    resp = self._build_abs_response(
      num_wells=1,
      num_wavelengths=1,
      samples=[50000],
      refs=[100000],
      chromats=[(0, 0)],  # chromat_hi = 0 → T% = 0
      ref_chan_hi=100000,
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
      ref_chan_hi=100000,
      ref_chan_lo=1000,
    )
    _, _, raw = CLARIOstarBackend._parse_absorbance_response(resp, num_wavelengths=1)

    self.assertEqual(raw["samples"], [50000.0, 60000.0])
    self.assertEqual(raw["references"], [100000.0, 110000.0])
    self.assertEqual(raw["chromatic_cal"], [(100000.0, 5000.0)])
    self.assertEqual(raw["reference_cal"], (100000.0, 1000.0))


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
    # Build a valid response (2-byte CS, instrument format)
    response = _make_response_frame(b"\x80\x00\x05\x00\x00")

    self.backend.io.write.return_value = len(_frame(b"\x80\x00"))
    self.backend.io.read.side_effect = [response, b""]

    result = await self.backend.send(b"\x80\x00")
    self.assertEqual(result, response)

    # Verify the written data is the framed payload (1-byte CS, outgoing format)
    written = self.backend.io.write.call_args[0][0]
    self.assertEqual(written, _frame(b"\x80\x00"))

  async def test_request_command_status_payload(self):
    """_request_command_status sends the correct payload."""
    response = _make_response_frame(b"\x80\x00\x05\x00\x00")
    self.backend.io.write.return_value = len(_frame(b"\x80\x00"))
    self.backend.io.read.side_effect = [response, b""]

    await self.backend._request_command_status()
    written = self.backend.io.write.call_args[0][0]
    self.assertEqual(written, _frame(b"\x80\x00"))

  async def test_request_machine_status_parses_flags(self):
    """request_machine_status() should return parsed status flags."""
    # Build a response where byte 1 of unframed payload has VALID (bit 0) set
    status_payload = b"\x00\x01\x00\x00\x00"  # only VALID flag
    response = _make_response_frame(status_payload)
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
    init_response = _make_response_frame(b"\x01\x00\x00\x10\x02\x00")
    # Status response: VALID only (not BUSY) → ready
    ready_response = _make_response_frame(b"\x00\x01\x00\x00\x00")

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


# ---------------------------------------------------------------------------
# EEPROM parsing and CLARIOstarConfig
# ---------------------------------------------------------------------------

# Real EEPROM payload captured from CLARIOstar Plus (serial 430-2621).
# This is the unframed 264-byte payload from command 0x05 0x07.
_REAL_EEPROM_PAYLOAD = bytes([
  0x07, 0x05, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x01, 0x01, 0x01, 0x01, 0x00,
  0x00, 0x01, 0x00, 0xee, 0x02, 0x00, 0x00, 0x0f, 0x00, 0xb0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x03, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0xdc, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0xf4, 0x01, 0x08, 0x03, 0xa7, 0x04, 0x08, 0x07, 0x60, 0x09, 0xda, 0x08, 0xac, 0x0d, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x02, 0x98,
  0x06, 0xae, 0x01, 0x3d, 0x0a, 0x46, 0x05, 0xee, 0x01, 0xfb, 0xff, 0x70, 0x0c, 0x00, 0x00, 0x00,
  0x00, 0xa4, 0x00, 0x58, 0xff, 0x8e, 0x03, 0xf2, 0x04, 0x60, 0xff, 0x55, 0x11, 0xfe, 0x0b, 0x55,
  0x11, 0x8f, 0x1a, 0x17, 0x02, 0x98, 0x06, 0x5a, 0xff, 0x97, 0x06, 0x68, 0x04, 0x26, 0x03, 0xbc,
  0x14, 0xb8, 0x04, 0x08, 0x07, 0x91, 0x00, 0x90, 0x01, 0x46, 0x32, 0x28, 0x46, 0x0a, 0x00, 0x46,
  0x07, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x03, 0xd4, 0x06, 0x28,
  0x00, 0x2c, 0x01, 0x90, 0x01, 0x46, 0x00, 0x1e, 0x00, 0x00, 0x14, 0x11, 0x00, 0x12, 0x09, 0xac,
  0x0d, 0x60, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Real firmware info payload captured from the same unit (command 0x05 0x09).
_REAL_FIRMWARE_PAYLOAD = bytes([
  0x0a, 0x05, 0x00, 0x24, 0x00, 0x00, 0x05, 0x46,
  0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x20, 0x32,
  0x30, 0x32, 0x30, 0x00, 0x31, 0x31, 0x3a, 0x35,
  0x31, 0x3a, 0x32, 0x31, 0x00, 0x00, 0x01, 0x00,
])


class TestCLARIOstarConfig(unittest.TestCase):
  """Test CLARIOstarConfig dataclass and parse_eeprom."""

  def test_defaults(self):
    """Default config should have empty/false values."""
    cfg = CLARIOstarConfig()
    self.assertEqual(cfg.serial_number, "")
    self.assertEqual(cfg.firmware_version, "")
    self.assertFalse(cfg.has_pump1)
    self.assertEqual(cfg.monochromator_range, (0, 0))
    self.assertEqual(cfg.machine_type_code, 0)

  def test_parse_eeprom_empty_payload(self):
    """Parsing a minimal framed response returns defaults without crashing."""
    framed = _make_response_frame(b"\x00" * 20)
    cfg = CLARIOstarConfig.parse_eeprom(framed)
    self.assertIsInstance(cfg, CLARIOstarConfig)
    self.assertEqual(cfg.machine_type_code, 0)

  def test_parse_eeprom_too_short(self):
    """Payload shorter than 15 bytes returns defaults."""
    cfg = CLARIOstarConfig.parse_eeprom(b"\x07\x05\x00\x24")
    self.assertEqual(cfg.machine_type_code, 0)
    self.assertFalse(cfg.has_absorbance)

  def test_parse_real_eeprom(self):
    """Parse the real EEPROM capture from CLARIOstar Plus 430-2621."""
    framed = _make_response_frame(_REAL_EEPROM_PAYLOAD)
    cfg = CLARIOstarConfig.parse_eeprom(framed)

    self.assertEqual(cfg.machine_type_code, 0x0024)
    self.assertEqual(cfg.model_name, "CLARIOstar Plus")
    self.assertTrue(cfg.has_absorbance)
    self.assertTrue(cfg.has_fluorescence)
    self.assertTrue(cfg.has_luminescence)
    self.assertTrue(cfg.has_alpha_technology)
    self.assertEqual(cfg.monochromator_range, (220, 1000))
    self.assertEqual(cfg.num_filter_slots, 11)

  def test_parse_eeprom_unframed_fallback(self):
    """If the input is not a valid frame, parse_eeprom treats it as raw payload."""
    cfg = CLARIOstarConfig.parse_eeprom(_REAL_EEPROM_PAYLOAD)
    self.assertEqual(cfg.machine_type_code, 0x0024)
    self.assertTrue(cfg.has_absorbance)

  def test_parse_eeprom_unknown_type_code(self):
    """Unknown machine type code produces a descriptive model name."""
    payload = bytearray(_REAL_EEPROM_PAYLOAD)
    payload[2] = 0x00
    payload[3] = 0xFF  # type 0x00FF — unknown
    cfg = CLARIOstarConfig.parse_eeprom(bytes(payload))
    self.assertEqual(cfg.machine_type_code, 0x00FF)
    self.assertIn("Unknown", cfg.model_name)
    self.assertEqual(cfg.monochromator_range, (0, 0))

  def test_parse_eeprom_capability_flags_false(self):
    """Zeroed capability bytes should produce False."""
    payload = bytearray(_REAL_EEPROM_PAYLOAD)
    payload[11] = 0
    payload[12] = 0
    payload[13] = 0
    payload[14] = 0
    cfg = CLARIOstarConfig.parse_eeprom(bytes(payload))
    self.assertFalse(cfg.has_absorbance)
    self.assertFalse(cfg.has_fluorescence)
    self.assertFalse(cfg.has_luminescence)
    self.assertFalse(cfg.has_alpha_technology)


class TestParseFirmwareInfo(unittest.TestCase):
  """Test CLARIOstarConfig.parse_firmware_info against real hardware capture."""

  def test_parse_real_firmware(self):
    """Parse the real firmware info capture from 430-2621."""
    framed = _make_response_frame(_REAL_FIRMWARE_PAYLOAD)
    cfg = CLARIOstarConfig.parse_firmware_info(framed)

    self.assertEqual(cfg.firmware_version, "1.35")
    self.assertEqual(cfg.firmware_build_timestamp, "Nov 20 2020 11:51:21")

  def test_parse_firmware_unframed(self):
    """Unframed payload also works."""
    cfg = CLARIOstarConfig.parse_firmware_info(_REAL_FIRMWARE_PAYLOAD)
    self.assertEqual(cfg.firmware_version, "1.35")
    self.assertIn("Nov 20 2020", cfg.firmware_build_timestamp)

  def test_parse_firmware_too_short(self):
    """Short payload returns defaults."""
    cfg = CLARIOstarConfig.parse_firmware_info(b"\x0a\x05\x00\x24\x00\x00")
    self.assertEqual(cfg.firmware_version, "")
    self.assertEqual(cfg.firmware_build_timestamp, "")

  def test_firmware_version_encoding(self):
    """Verify the version × 1000 encoding: 0x0546 = 1350 → '1.35'."""
    payload = bytearray(_REAL_FIRMWARE_PAYLOAD)
    # Change version to 0x0514 = 1300 → should give "1.30"
    payload[6] = 0x05
    payload[7] = 0x14
    cfg = CLARIOstarConfig.parse_firmware_info(bytes(payload))
    self.assertEqual(cfg.firmware_version, "1.30")

    # Change to 0x07D0 = 2000 → "2.00"
    payload[6] = 0x07
    payload[7] = 0xD0
    cfg = CLARIOstarConfig.parse_firmware_info(bytes(payload))
    self.assertEqual(cfg.firmware_version, "2.00")


# Real usage counter payload captured from the same unit (command 0x05 0x21).
_REAL_COUNTER_PAYLOAD = bytes([
  0x21, 0x05, 0x00, 0x24, 0x00, 0x00,  # header
  0x00, 0x1b, 0xa5, 0x20,  # flashes = 1,811,744
  0x00, 0x00, 0x06, 0x44,  # testruns = 1,604
  0x00, 0x00, 0x04, 0x7c,  # wells_raw = 1,148  (×100 = 114,800)
  0x00, 0x00, 0x03, 0x6e,  # well_movements_raw = 878  (×100 = 87,800)
  0x00, 0x02, 0x4c, 0xbf,  # active_time_s = 150,719
  0x00, 0x00, 0x12, 0xb0,  # shake_time_s = 4,784
  0x00, 0x00, 0x00, 0x0a,  # pump1_usage = 10
  0x00, 0x00, 0x00, 0x0a,  # pump2_usage = 10
  0x00, 0x00, 0x00, 0x0a,  # alpha_time = 10
  0x00,                     # trailing byte
])


class TestParseUsageCounters(unittest.TestCase):
  """Test _parse_usage_counters against real hardware capture."""

  def test_parse_real_counters(self):
    """Parse the real counter capture from 430-2621."""
    framed = _make_response_frame(_REAL_COUNTER_PAYLOAD)
    c = _parse_usage_counters(framed)

    self.assertEqual(c["flashes"], 1_811_744)
    self.assertEqual(c["testruns"], 1_604)
    self.assertEqual(c["wells"], 114_800)
    self.assertEqual(c["well_movements"], 87_800)
    self.assertEqual(c["active_time_s"], 150_719)
    self.assertEqual(c["shake_time_s"], 4_784)
    self.assertEqual(c["pump1_usage"], 10)
    self.assertEqual(c["pump2_usage"], 10)
    self.assertEqual(c["alpha_time"], 10)

  def test_parse_unframed(self):
    """Unframed payload also works."""
    c = _parse_usage_counters(_REAL_COUNTER_PAYLOAD)
    self.assertEqual(c["flashes"], 1_811_744)
    self.assertEqual(c["shake_time_s"], 4_784)

  def test_parse_too_short(self):
    """Short payload returns empty dict."""
    c = _parse_usage_counters(b"\x21\x05\x00\x24\x00\x00")
    self.assertEqual(c, {})


class TestDumpEeprom(unittest.TestCase):
  """Test the dump_eeprom() pretty-printer."""

  def test_dump_framed(self):
    """dump_eeprom on a framed response produces hex + ASCII output."""
    payload = b"\x48\x65\x6c\x6c\x6f"  # "Hello"
    framed = _make_response_frame(payload)
    output = dump_eeprom(framed)
    self.assertIn("Raw length:", output)
    self.assertIn("Payload length: 5", output)
    self.assertIn("Hello", output)

  def test_dump_unframed(self):
    """dump_eeprom on unframed data falls back gracefully."""
    raw = b"\x01\x02\x03\x41\x42\x43"  # last 3 = "ABC"
    output = dump_eeprom(raw)
    self.assertIn("ABC", output)

  def test_dump_nonprintable_replaced(self):
    """Non-printable bytes show as '.' in ASCII column."""
    payload = bytes(range(16))
    framed = _make_response_frame(payload)
    output = dump_eeprom(framed)
    # Bytes 0-31 are non-printable, should be dots
    self.assertIn(".", output)

  def test_dump_real_eeprom(self):
    """dump_eeprom produces the expected length annotation for real data."""
    framed = _make_response_frame(_REAL_EEPROM_PAYLOAD)
    output = dump_eeprom(framed)
    self.assertIn("Payload length: 264", output)


class TestCLARIOstarBackendEepromMethods(unittest.TestCase):
  """Test get_machine_config and dump_eeprom_str on the real backend class."""

  def setUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.backend._eeprom_data = None
    self.backend._firmware_data = None
    self.backend.io = unittest.mock.MagicMock()
    self.backend.io.serial = None
    self.backend.io.device_id = None

  def test_get_machine_config_none_before_setup(self):
    """get_machine_config returns None if EEPROM data hasn't been read."""
    self.assertIsNone(self.backend.get_machine_config())

  def test_get_machine_config_eeprom_only(self):
    """get_machine_config works with only EEPROM data (no firmware info)."""
    self.backend._eeprom_data = _make_response_frame(_REAL_EEPROM_PAYLOAD)
    cfg = self.backend.get_machine_config()
    self.assertIsInstance(cfg, CLARIOstarConfig)
    self.assertEqual(cfg.machine_type_code, 0x0024)
    self.assertTrue(cfg.has_absorbance)
    # Firmware fields should be empty without firmware data
    self.assertEqual(cfg.firmware_version, "")

  def test_get_machine_config_with_firmware(self):
    """get_machine_config merges EEPROM and firmware data."""
    self.backend._eeprom_data = _make_response_frame(_REAL_EEPROM_PAYLOAD)
    self.backend._firmware_data = _make_response_frame(_REAL_FIRMWARE_PAYLOAD)
    cfg = self.backend.get_machine_config()
    self.assertEqual(cfg.model_name, "CLARIOstar Plus")
    self.assertEqual(cfg.firmware_version, "1.35")
    self.assertIn("Nov 20 2020", cfg.firmware_build_timestamp)
    self.assertTrue(cfg.has_luminescence)

  def test_dump_eeprom_str_none_before_setup(self):
    """dump_eeprom_str returns None if EEPROM data hasn't been read."""
    self.assertIsNone(self.backend.dump_eeprom_str())

  def test_dump_eeprom_str_returns_string(self):
    """dump_eeprom_str returns a formatted string when EEPROM data is present."""
    self.backend._eeprom_data = _make_response_frame(b"test_payload")
    result = self.backend.dump_eeprom_str()
    self.assertIsInstance(result, str)
    self.assertIn("Raw length:", result)


class TestSimulatorConfig(unittest.TestCase):
  """Test CLARIOstarSimulatorBackend config methods."""

  def test_get_machine_config(self):
    """Simulator returns a populated CLARIOstarConfig."""
    sim = CLARIOstarSimulatorBackend()
    cfg = sim.get_machine_config()
    self.assertIsInstance(cfg, CLARIOstarConfig)
    self.assertEqual(cfg.serial_number, "SIM-0000")
    self.assertEqual(cfg.firmware_version, "1.35")
    self.assertTrue(cfg.has_absorbance)
    self.assertTrue(cfg.has_fluorescence)
    self.assertTrue(cfg.has_luminescence)
    self.assertFalse(cfg.has_pump1)
    self.assertEqual(cfg.monochromator_range, (220, 1000))
    self.assertEqual(cfg.machine_type_code, 0x0024)

  def test_dump_eeprom_str_is_none(self):
    """Simulator has no EEPROM data to dump."""
    sim = CLARIOstarSimulatorBackend()
    self.assertIsNone(sim.dump_eeprom_str())

  def test_get_eeprom_data_is_none(self):
    """Simulator returns None for raw EEPROM data."""
    sim = CLARIOstarSimulatorBackend()
    self.assertIsNone(sim.get_eeprom_data())


class TestSimulatorUsageCounters(unittest.IsolatedAsyncioTestCase):
  """Test CLARIOstarSimulatorBackend usage counter methods."""

  async def test_request_usage_counters(self):
    """Simulator returns zeroed usage counters."""
    sim = CLARIOstarSimulatorBackend()
    c = await sim.request_usage_counters()
    self.assertIsInstance(c, dict)
    self.assertEqual(c["flashes"], 0)
    self.assertEqual(c["wells"], 0)


if __name__ == "__main__":
  unittest.main()
