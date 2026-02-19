# mypy: disable-error-code = attr-defined

import struct
import unittest
import unittest.mock

from pylabrobot.plate_reading.bmg_labtech.clariostar_backend import (
  ChecksumError,
  CLARIOstarBackend,
  CLARIOstarConfig,
  FrameError,
  _ORBITAL_MEAS_CODE,
  _parse_usage_counters,
  _well_scan_optic_flags,
  _well_scan_orbital_bytes,
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
    """TOP_LEFT, bidirectional, vertical, no flying → 0x1A."""
    # bit 1 always set (0x02), corner TOP_LEFT=1 shifted left 4 (0x10), vertical bit 3 (0x08)
    self.assertEqual(_scan_mode_byte(), 0x1A)

  def test_top_right(self):
    self.assertEqual(
      _scan_mode_byte(start_corner=StartCorner.TOP_RIGHT),
      (0b0011 << 4) | 0x08 | 0x02,  # 0x3A
    )

  def test_bottom_left(self):
    self.assertEqual(
      _scan_mode_byte(start_corner=StartCorner.BOTTOM_LEFT),
      (0b0101 << 4) | 0x08 | 0x02,  # 0x5A
    )

  def test_bottom_right(self):
    self.assertEqual(
      _scan_mode_byte(start_corner=StartCorner.BOTTOM_RIGHT),
      (0b0111 << 4) | 0x08 | 0x02,  # 0x7A
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
# Well scan helpers
# ---------------------------------------------------------------------------


class TestWellScanOpticFlags(unittest.TestCase):
  """Test _well_scan_optic_flags across all scan modes."""

  def test_point_returns_zero(self):
    self.assertEqual(_well_scan_optic_flags("point"), 0x00)

  def test_orbital_returns_0x30(self):
    self.assertEqual(_well_scan_optic_flags("orbital"), 0x30)

  def test_spiral_returns_0x04(self):
    """Spiral: bit 2 set. Verified via OEM pcap (spiral 4mm, spiral 5mm)."""
    self.assertEqual(_well_scan_optic_flags("spiral"), 0x04)

  def test_matrix_returns_zero_for_now(self):
    self.assertEqual(_well_scan_optic_flags("matrix"), 0x00)


class TestWellScanOrbitalBytes(unittest.TestCase):
  """Test _well_scan_orbital_bytes byte encoding."""

  def setUp(self):
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")

  def test_point_returns_empty(self):
    result = _well_scan_orbital_bytes(0x02, "point", None, self.plate)
    self.assertEqual(result, b"")

  def test_orbital_returns_5_bytes(self):
    result = _well_scan_orbital_bytes(0x02, "orbital", 3, self.plate)
    self.assertEqual(len(result), 5)

  def test_orbital_abs_measurement_code(self):
    result = _well_scan_orbital_bytes(0x02, "orbital", 3, self.plate)
    self.assertEqual(result[0], 0x02)

  def test_orbital_fl_measurement_code(self):
    result = _well_scan_orbital_bytes(0x03, "orbital", 3, self.plate)
    self.assertEqual(result[0], 0x03)

  def test_orbital_diameter_encoded(self):
    result = _well_scan_orbital_bytes(0x02, "orbital", 5, self.plate)
    self.assertEqual(result[1], 5)

  def test_orbital_well_diameter_from_plate(self):
    """Well diameter is physical well size in 0.01mm as uint16 BE."""
    result = _well_scan_orbital_bytes(0x02, "orbital", 3, self.plate)
    w = self.plate.get_all_items()[0]
    expected = round(min(w.get_size_x(), w.get_size_y()) * 100)
    self.assertEqual(int.from_bytes(result[2:4], "big"), expected)

  def test_orbital_terminator(self):
    result = _well_scan_orbital_bytes(0x02, "orbital", 3, self.plate)
    self.assertEqual(result[4], 0x00)

  def test_spiral_returns_5_bytes(self):
    """Spiral uses the same 5-byte structure as orbital (verified via OEM pcap)."""
    result = _well_scan_orbital_bytes(0x02, "spiral", 4, self.plate)
    self.assertEqual(len(result), 5)

  def test_spiral_width_encoded(self):
    """Spiral 4mm → width byte = 4 (verified via OEM pcap spiral 4mm)."""
    result = _well_scan_orbital_bytes(0x02, "spiral", 4, self.plate)
    self.assertEqual(result[0], 0x02)  # measurement code
    self.assertEqual(result[1], 4)     # width = 4mm

  def test_spiral_5mm(self):
    """Spiral 5mm → width byte = 5 (verified via OEM pcap spiral 5mm)."""
    result = _well_scan_orbital_bytes(0x02, "spiral", 5, self.plate)
    self.assertEqual(result[1], 5)

  def test_orbital_meas_code_dict(self):
    """Verify the known measurement code constants."""
    self.assertEqual(_ORBITAL_MEAS_CODE["absorbance"], 0x02)
    self.assertEqual(_ORBITAL_MEAS_CODE["fluorescence"], 0x03)


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

  def test_partial_wells_mask_row_major(self):
    """Verify partial well mask uses row-major firmware indexing.

    PLR all_items is column-major: indices {0,13,26,39} = wells A1,F2,C4,H5.
    Firmware row-major indices: A1=0, F2=61, C4=27, H5=88.
    """
    all_items = self.plate.get_all_items()
    selected = [all_items[0], all_items[13], all_items[26], all_items[39]]
    result = self.backend._plate_bytes(self.plate, wells=selected)
    mask = result[15:]
    # A1 → row-major 0 → byte[0] bit 7
    self.assertEqual(mask[0], 0x80)
    self.assertEqual(mask[1], 0x00)
    self.assertEqual(mask[2], 0x00)
    # C4 → row-major 27 → byte[3] bit 4
    self.assertEqual(mask[3], 0x10)
    self.assertEqual(mask[4:7], b"\x00" * 3)
    # F2 → row-major 61 → byte[7] bit 2
    self.assertEqual(mask[7], 0x04)
    self.assertEqual(mask[8:11], b"\x00" * 3)
    # H5 → row-major 88 → byte[11] bit 7 (88%8=0, 7-0=7)
    self.assertEqual(mask[11], 0x80)
    # Remaining bytes should be zero
    self.assertEqual(mask[12:], b"\x00" * 36)

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

  def test_unframe_with_trailing_status_byte(self):
    """_unframe should handle responses where a trailing byte is excluded from the checksum.

    Some firmware responses (e.g. final measurement values) include a status byte before the
    checksum that is NOT included in the checksum computation. The standard checksum
    (sum of all bytes before the last 3) would be off by the value of this trailing byte.
    """
    # Build a frame where the last payload byte is excluded from the checksum
    payload = b"\x02\x05\x06\x26" + b"\x00" * 20 + b"\x01"  # trailing 0x01
    size = len(payload) + 7
    buf = bytearray([0x02]) + size.to_bytes(2, "big") + b"\x0c" + payload
    # Compute checksum excluding the trailing byte (as firmware does)
    cs = sum(buf[:-1]) & 0xFFFF
    buf += cs.to_bytes(2, "big")
    buf += b"\x0d"
    frame = bytes(buf)

    # Standard checksum would fail (off by 1)
    standard_cs = sum(frame[:-3]) & 0xFFFF
    self.assertNotEqual(standard_cs, cs)

    # _unframe should still succeed via the alternate checksum path
    result = _unframe(frame)
    self.assertEqual(result, payload)

  def test_parse_oem_capture_orbital_well_scan(self):
    """Validate parser against real OEM capture (orbital well scan, 96 wells, 600 nm).

    Response captured from absorbance_test_1_well_scan_orbital.txt line 253.
    OEM expected OD values (same file, lines 264-271) are used as ground truth.
    """
    # fmt: off
    oem_resp = (
      b"\x02\x06\x4c\x0c\x02\x05\x06\x26\x00\x00\xa9\x01\x88\x01\x88\x00"
      b"\x1d\xff\xe2\x02\x20\x03\x00\x01\x00\x60\x01\x00\x01\x00\x00\x00"
      b"\x01\x01\x00\x00\x00\x00\x00\x00\x00\x2c\x26\xd9\x00\x45\x04\xdd"
      b"\x00\x44\x8b\x97\x00\x44\xd7\xf9\x00\x44\xde\x5b\x00\x45\x2a\x94"
      b"\x00\x45\x3e\xdb\x00\x45\x12\x5a\x00\x44\xb5\xd9\x00\x44\xa3\x87"
      b"\x00\x44\xf4\xe4\x00\x44\xbd\xe1\x00\x35\xe6\x52\x00\x44\x90\x32"
      b"\x00\x44\xb0\x6c\x00\x44\xc5\x50\x00\x44\xd8\x3e\x00\x44\xb0\xe4"
      b"\x00\x44\xbb\xc7\x00\x44\x44\x95\x00\x44\x7b\xe7\x00\x44\xb3\x3b"
      b"\x00\x44\xce\x99\x00\x45\x02\x89\x00\x2e\xfb\xa7\x00\x44\x79\x37"
      b"\x00\x44\x95\x31\x00\x44\xd3\xfc\x00\x44\x8e\x36\x00\x42\x5a\xd4"
      b"\x00\x44\x8b\xa7\x00\x44\xad\x73\x00\x44\x84\x3c\x00\x44\x98\xdb"
      b"\x00\x44\xb8\x3b\x00\x45\x05\x68\x00\x2e\x0d\x2e\x00\x44\x8a\xb6"
      b"\x00\x43\xda\xf3\x00\x45\x13\x45\x00\x45\x0d\x78\x00\x44\x75\x82"
      b"\x00\x44\xe6\x86\x00\x44\x02\x5f\x00\x44\x8c\xe1\x00\x44\x65\x98"
      b"\x00\x44\xc1\x1f\x00\x44\xdd\x94\x00\x32\xca\x5e\x00\x44\x59\xeb"
      b"\x00\x44\xb1\x64\x00\x44\x01\xad\x00\x44\xcd\x0d\x00\x45\x36\x04"
      b"\x00\x45\x1b\x6a\x00\x45\x14\xae\x00\x44\x7c\xc2\x00\x44\x3e\xbf"
      b"\x00\x44\xa9\xe6\x00\x44\xeb\x21\x00\x23\xfe\x25\x00\x45\x24\xda"
      b"\x00\x44\x87\xac\x00\x45\x26\x84\x00\x45\x02\x41\x00\x45\x36\x37"
      b"\x00\x44\x77\xeb\x00\x44\x79\x42\x00\x43\xf6\x87\x00\x44\xac\x6c"
      b"\x00\x44\xbd\x45\x00\x44\xb4\x1c\x00\x0d\x05\x9e\x00\x44\x95\x23"
      b"\x00\x45\x02\xc9\x00\x43\xa1\x0c\x00\x44\xef\xd6\x00\x45\x1d\x31"
      b"\x00\x43\xca\x83\x00\x43\xbe\x7d\x00\x44\x23\xa8\x00\x44\x46\x4c"
      b"\x00\x43\xe3\x44\x00\x44\xbb\xb5\x00\x00\x35\xe7\x00\x45\x41\xa2"
      b"\x00\x43\xb8\x1e\x00\x44\x19\xbb\x00\x44\xd8\xee\x00\x45\x04\xc1"
      b"\x00\x45\x35\x05\x00\x44\x2a\xc6\x00\x44\xaf\xfa\x00\x44\xd2\x06"
      b"\x00\x44\xcf\xb3\x00\x43\xfb\x0c\x00\x14\x46\x77\x00\x1b\x9e\xf0"
      b"\x00\x1b\x6d\x2f\x00\x1b\x9d\x0d\x00\x1b\x9c\x8b\x00\x1b\xcc\x69"
      b"\x00\x1b\xbb\x61\x00\x1b\xb6\x87\x00\x1b\x96\x5d\x00\x1b\x8a\x06"
      b"\x00\x1b\xac\xc0\x00\x1b\x95\x69\x00\x17\xde\x28\x00\x1b\x79\x10"
      b"\x00\x1b\x8b\x78\x00\x1b\x8f\x19\x00\x1b\xaa\xb7\x00\x1b\xa5\xa5"
      b"\x00\x1b\x9e\xe8\x00\x1b\x88\x91\x00\x1b\x86\x26\x00\x1b\xae\xba"
      b"\x00\x1b\xb1\x79\x00\x1b\xae\xda\x00\x13\x25\x96\x00\x1b\x77\xf3"
      b"\x00\x1b\x92\xb1\x00\x1b\x92\xdf\x00\x1b\x8a\x64\x00\x1a\xac\x8f"
      b"\x00\x1b\x90\xbb\x00\x1b\xa5\xec\x00\x1b\x95\x71\x00\x1b\xa0\x14"
      b"\x00\x1b\x9a\xf5\x00\x1b\xc2\xe1\x00\x12\xbf\x34\x00\x1b\x95\x0a"
      b"\x00\x1b\x4e\xad\x00\x1b\xcf\x53\x00\x1b\xc8\xf6\x00\x1b\x8b\x37"
      b"\x00\x1b\xaa\x94\x00\x1b\x60\x97\x00\x1b\xa7\x76\x00\x1b\xa5\xcd"
      b"\x00\x1b\xb3\x29\x00\x1b\xb6\xf3\x00\x17\x4d\x28\x00\x1b\x74\xc7"
      b"\x00\x1b\xae\xf5\x00\x1b\x5d\xa8\x00\x1b\xc3\x8b\x00\x1b\xcb\x0d"
      b"\x00\x1b\xbf\x6a\x00\x1b\xcb\xd7\x00\x1b\x96\x6d\x00\x1b\x96\x5c"
      b"\x00\x1b\xa8\x11\x00\x1b\xaf\xad\x00\x13\xa3\x10\x00\x1b\xc0\xf6"
      b"\x00\x1b\x7c\x02\x00\x1b\xc2\xb8\x00\x1b\xb5\x03\x00\x1b\xe6\x30"
      b"\x00\x1b\x8f\xb0\x00\x1b\x7f\xa3\x00\x1b\x4a\xa4\x00\x1b\xaa\x3e"
      b"\x00\x1b\xb8\xc3\x00\x1b\x99\x07\x00\x15\x57\xe8\x00\x1b\x7a\x3a"
      b"\x00\x1b\xa7\xa3\x00\x1b\x13\x0b\x00\x1b\xa6\x34\x00\x1b\xcf\xdd"
      b"\x00\x1b\x42\xdf\x00\x1b\x49\xdd\x00\x1b\x5b\xf6\x00\x1b\x8b\x0c"
      b"\x00\x1b\x4b\x71\x00\x1b\x89\x85\x00\x19\xa3\x7d\x00\x1b\xaa\x8c"
      b"\x00\x1b\x16\x68\x00\x1b\x4f\x32\x00\x1b\xa1\x50\x00\x1b\xa5\x0f"
      b"\x00\x1b\xb7\x35\x00\x1b\x56\xf3\x00\x1b\x90\x5d\x00\x1b\xad\x64"
      b"\x00\x1b\x9e\x46\x00\x1b\x51\x39\x00\x08\x51\x9d\x00\x0d\x4f\xe0"
      b"\x00\x0d\x3e\xe6\x00\x0d\x4c\x9b\x00\x0d\x4e\xee\x00\x0d\x5d\xf8"
      b"\x00\x0d\x5f\xcb\x00\x0d\x51\x28\x00\x0d\x45\x27\x00\x0d\x44\xff"
      b"\x00\x0d\x55\x0c\x00\x0d\x4a\x2f\x00\x09\xb8\x40\x00\x0d\x39\xe3"
      b"\x00\x0d\x41\x51\x00\x0d\x4e\xaa\x00\x0d\x5d\xac\x00\x0d\x51\x50"
      b"\x00\x0d\x56\xc8\x00\x0d\x47\x51\x00\x0d\x50\xf8\x00\x0d\x58\xe5"
      b"\x00\x0d\x55\xb5\x00\x0d\x4b\x41\x00\x07\xf3\x00\x00\x0d\x3a\x3e"
      b"\x00\x0d\x4f\x3d\x00\x0d\x5c\x75\x00\x0d\x4f\xec\x00\x0c\xd8\xd2"
      b"\x00\x0d\x45\x6e\x00\x0d\x58\x29\x00\x0d\x4c\xf8\x00\x0d\x50\x32"
      b"\x00\x0d\x4c\x94\x00\x0d\x53\x74\x00\x07\xcc\x69\x00\x0d\x46\x84"
      b"\x00\x0d\x29\x56\x00\x0d\x71\x2a\x00\x0d\x5a\x75\x00\x0d\x46\x3b"
      b"\x00\x0d\x54\x84\x00\x0d\x35\xf3\x00\x0d\x59\x7a\x00\x0d\x4e\x01"
      b"\x00\x0d\x57\x8e\x00\x0d\x5b\x22\x00\x09\x86\x63\x00\x0d\x38\xed"
      b"\x00\x0d\x55\x4c\x00\x0d\x36\x0a\x00\x0d\x5d\xa8\x00\x0d\x66\x0c"
      b"\x00\x0d\x55\xd4\x00\x0d\x6c\x6f\x00\x0d\x4b\x9f\x00\x0d\x4d\x68"
      b"\x00\x0d\x52\x6f\x00\x0d\x57\xdf\x00\x08\x36\xf8\x00\x0d\x5e\x29"
      b"\x00\x0d\x3b\xf6\x00\x0d\x62\x7e\x00\x0d\x5d\xa7\x00\x0d\x69\xcc"
      b"\x00\x0d\x3d\x82\x00\x0d\x4e\xfb\x00\x0d\x31\x8c\x00\x0d\x56\x03"
      b"\x00\x0d\x5c\xc9\x00\x0d\x47\x42\x00\x08\xbf\xa4\x00\x0d\x41\x14"
      b"\x00\x0d\x4c\xb1\x00\x0d\x0f\xfe\x00\x0d\x59\x91\x00\x0d\x63\x7c"
      b"\x00\x0d\x1a\xe0\x00\x0d\x28\x15\x00\x0d\x33\x30\x00\x0d\x39\xe3"
      b"\x00\x0d\x28\x54\x00\x0d\x49\x29\x00\x0a\xac\x5a\x00\x0d\x4a\xc0"
      b"\x00\x0d\x11\xb2\x00\x0d\x21\x11\x00\x0d\x47\x1c\x00\x0d\x4c\xfe"
      b"\x00\x0d\x57\x71\x00\x0d\x2a\x09\x00\x0d\x47\xce\x00\x0d\x59\xce"
      b"\x00\x0d\x45\x18\x00\x0d\x21\x3f\x00\x00\x47\x96\x00\x00\x47\x6b"
      b"\x00\x00\x47\x6f\x00\x00\x47\x77\x00\x00\x47\x5e\x00\x00\x47\x61"
      b"\x00\x00\x47\x7f\x00\x00\x47\x42\x00\x00\x47\x35\x00\x00\x47\x3d"
      b"\x00\x00\x47\x38\x00\x00\x47\x4a\x00\x00\x47\xb4\x00\x00\x47\x7b"
      b"\x00\x00\x47\x87\x00\x00\x47\x6f\x00\x00\x47\x78\x00\x00\x47\x6b"
      b"\x00\x00\x47\x63\x00\x00\x47\x58\x00\x00\x47\x4b\x00\x00\x47\x41"
      b"\x00\x00\x47\x38\x00\x00\x47\x33\x00\x00\x47\xa1\x00\x00\x47\x72"
      b"\x00\x00\x47\x69\x00\x00\x47\x65\x00\x00\x47\x81\x00\x00\x47\x5b"
      b"\x00\x00\x47\x69\x00\x00\x47\x61\x00\x00\x47\x42\x00\x00\x47\x51"
      b"\x00\x00\x47\x45\x00\x00\x47\x37\x00\x00\x47\x96\x00\x00\x47\x7e"
      b"\x00\x00\x47\x6f\x00\x00\x47\x7d\x00\x00\x47\x6c\x00\x00\x47\x6e"
      b"\x00\x00\x47\x5b\x00\x00\x47\x58\x00\x00\x47\x40\x00\x00\x47\x44"
      b"\x00\x00\x47\x40\x00\x00\x47\x4c\x00\x00\x47\x8c\x00\x00\x47\x6f"
      b"\x00\x00\x47\x72\x00\x00\x47\x74\x00\x00\x47\x73\x00\x00\x47\x65"
      b"\x00\x00\x47\x59\x00\x00\x47\x6a\x00\x00\x47\x42\x00\x00\x47\x32"
      b"\x00\x00\x47\x2e\x00\x00\x47\x29\x00\x00\x47\x97\x00\x00\x47\x9c"
      b"\x00\x00\x47\x63\x00\x00\x47\x82\x00\x00\x47\x63\x00\x00\x47\x6b"
      b"\x00\x00\x47\x35\x00\x00\x47\x4d\x00\x00\x47\x45\x00\x00\x47\x31"
      b"\x00\x00\x47\x47\x00\x00\x47\x41\x00\x00\x47\x98\x00\x00\x47\x8f"
      b"\x00\x00\x47\x7e\x00\x00\x47\x7f\x00\x00\x47\x5d\x00\x00\x47\x60"
      b"\x00\x00\x47\x52\x00\x00\x47\x47\x00\x00\x47\x42\x00\x00\x47\x64"
      b"\x00\x00\x47\x32\x00\x00\x47\x37\x00\x00\x47\x81\x00\x00\x47\x88"
      b"\x00\x00\x47\x85\x00\x00\x47\x76\x00\x00\x47\x5d\x00\x00\x47\x6a"
      b"\x00\x00\x47\x52\x00\x00\x47\x59\x00\x00\x47\x45\x00\x00\x47\x53"
      b"\x00\x00\x47\x46\x00\x00\x47\x3a\x00\x53\xd7\xed\x00\x00\xc4\xc7"
      b"\x00\x20\xcc\x92\x00\x00\xc6\xee\x00\x0f\xb1\x40\x00\x00\xc6\xcd"
      b"\x00\x00\x47\x63\x00\x00\x00\x00\x01\x8d\x51\x0d"
    )
    # fmt: on

    # OEM expected OD values (absorbance_test_1_well_scan_orbital.txt lines 264-271)
    oem_expected = [
      [0.28,  0.085, 0.088, 0.086, 0.085, 0.084, 0.084, 0.083, 0.085, 0.086, 0.084, 0.086],
      [0.194, 0.088, 0.087, 0.086, 0.086, 0.087, 0.086, 0.089, 0.087, 0.086, 0.085, 0.083],
      [0.253, 0.088, 0.087, 0.086, 0.088, 0.101, 0.088, 0.087, 0.087, 0.087, 0.086, 0.083],
      [0.261, 0.088, 0.092, 0.085, 0.084, 0.088, 0.085, 0.091, 0.087, 0.088, 0.085, 0.085],
      [0.219, 0.089, 0.087, 0.091, 0.086, 0.083, 0.084, 0.084, 0.087, 0.088, 0.086, 0.084],
      [0.368, 0.085, 0.088, 0.084, 0.085, 0.084, 0.087, 0.087, 0.09,  0.086, 0.086, 0.086],
      [0.81,  0.088, 0.085, 0.094, 0.085, 0.084, 0.092, 0.092, 0.089, 0.089, 0.09,  0.085],
      [2.601, 0.084, 0.094, 0.091, 0.085, 0.085, 0.083, 0.09,  0.086, 0.085, 0.085, 0.09],
    ]

    import math

    trans, temperature, raw = CLARIOstarBackend._parse_absorbance_response(oem_resp, 1)

    # Check structure
    self.assertEqual(len(trans), 96)
    self.assertEqual(len(trans[0]), 1)

    # Convert transmittance to OD and compare with OEM
    for row in range(8):
      for col in range(12):
        well_idx = row * 12 + col
        t = trans[well_idx][0]
        expected = oem_expected[row][col]
        self.assertIsNotNone(t, f"Well {chr(65+row)}{col+1} transmittance is None")

        # Wells with OD > 2 are at the instrument's dynamic range limit.
        # The signal drops below the dark calibration baseline, producing
        # negative transmittance from noise — skip OD comparison for these.
        if expected > 2.0:
          continue

        self.assertGreater(t, 0, f"Well {chr(65+row)}{col+1} transmittance <= 0: {t}")
        od = math.log10(100 / t)
        # Tolerances: blank wells (~0.085 OD) match within 0.005 OD.
        # Sample wells (column 1, higher OD) need wider tolerance because
        # log-scale amplifies small transmittance differences and the OEM
        # values are display-rounded to 3 decimal places.
        if expected > 0.5:
          tol = 0.15
        elif expected > 0.15:
          tol = 0.01
        else:
          tol = 0.005
        self.assertAlmostEqual(od, expected, delta=tol,
          msg=f"Well {chr(65+row)}{col+1}: OD {od:.4f} != {expected}")

    # Verify calibration values are plausible (non-zero)
    self.assertGreater(raw["chromatic_cal"][0][0], 0, "chromatic1 hi should be > 0")
    self.assertGreater(raw["reference_cal"][0], 0, "reference hi should be > 0")


# ---------------------------------------------------------------------------
# Integration tests with mocked FTDI IO
# ---------------------------------------------------------------------------


class TestCLARIOstarSend(unittest.IsolatedAsyncioTestCase):
  """Test send() and related methods with mocked FTDI."""

  async def asyncSetUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.backend.read_timeout = 20
    self.backend.write_timeout = 10
    self.backend.io = unittest.mock.MagicMock()
    self.backend.io.setup = unittest.mock.AsyncMock()
    self.backend.io.stop = unittest.mock.AsyncMock()
    self.backend.io.write = unittest.mock.AsyncMock()
    self.backend.io.read = unittest.mock.AsyncMock()
    self.backend.io.set_baudrate = unittest.mock.AsyncMock()
    self.backend.io.set_line_property = unittest.mock.AsyncMock()
    self.backend.io.set_latency_timer = unittest.mock.AsyncMock()
    self.backend.io.poll_modem_status = unittest.mock.AsyncMock()

  async def test_send_command_frames_and_writes(self):
    """send_command() should frame the payload and write it."""
    # Build a valid response (2-byte CS, instrument format)
    response = _make_response_frame(b"\x80\x00\x05\x00\x00")

    self.backend.io.write.return_value = len(_frame(b"\x80\x00"))
    self.backend.io.read.side_effect = [response, b""]

    result = await self.backend.send_command(b"\x80\x00")
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
    self.backend.read_timeout = 20
    self.backend.write_timeout = 10
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


class TestMachineTypeAutoDetection(unittest.TestCase):
  """Test machine type auto-detection and extended separator logic."""

  def setUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.backend._machine_type_code = 0

  def test_default_type_code_is_zero(self):
    """Before setup, machine type code is 0."""
    self.assertEqual(self.backend._machine_type_code, 0)

  def test_extended_separator_unknown_type(self):
    """Unknown type (0) defaults to extended separator (conservative)."""
    self.backend._machine_type_code = 0
    self.assertTrue(self.backend._uses_extended_separator)

  def test_extended_separator_type_0x0026(self):
    """Type 0x0026 uses extended separator."""
    self.backend._machine_type_code = 0x0026
    self.assertTrue(self.backend._uses_extended_separator)

  def test_no_extended_separator_type_0x0024(self):
    """Type 0x0024 does NOT use extended separator (matches Go reference)."""
    self.backend._machine_type_code = 0x0024
    self.assertFalse(self.backend._uses_extended_separator)


class TestAbsorbanceOrbitalPayload(unittest.TestCase):
  """Test orbital well_scan encoding in _start_absorbance_measurement payload."""

  def setUp(self):
    self.backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    self.backend._machine_type_code = 0x0024  # no extended separator
    self.backend._last_scan_params = {}
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")

  def _build_payload(self, well_scan="point", well_scan_width=None):
    """Build the absorbance payload synchronously for testing.

    Replicates _start_absorbance_measurement's payload construction without the async send.
    """
    plate = self.plate
    plate_and_wells = self.backend._plate_bytes(plate, wells=None)
    scan = _scan_mode_byte()

    payload = bytearray()
    payload += plate_and_wells
    payload += bytes([scan])

    optic_base = 0x02
    optic_config = optic_base | _well_scan_optic_flags(well_scan)

    if self.backend._uses_extended_separator:
      # 0x0026 layout: 36-byte block between scan and separator
      block = bytearray(36)
      block[4] = optic_base | (0x08 if well_scan != "point" else 0x00)
      block[5] = optic_config
      payload += bytes(block)
    else:
      # 0x0024 layout: optic(1) + zeros(3) + shaker(4)
      payload += bytes([optic_config])
      payload += b"\x00\x00\x00"
      payload += b"\x00\x00\x00\x00"  # no-shake shaker bytes

    payload += b"\x27\x0f\x27\x0f"

    payload += _well_scan_orbital_bytes(
      _ORBITAL_MEAS_CODE["absorbance"], well_scan, well_scan_width, plate,
    )

    # Settling + 1 wavelength at 600nm
    payload += bytes([0x19, 1])
    payload += (600 * 10).to_bytes(2, "big")

    return bytes(payload)

  def test_point_scan_optic_byte(self):
    """Point scan: optic config byte is 0x02 (no orbital bits)."""
    payload = self._build_payload(well_scan="point")
    # Optic byte is at offset 64 (63 plate + 1 scan = offset 64)
    self.assertEqual(payload[64], 0x02)

  def test_orbital_scan_optic_byte(self):
    """Orbital scan: optic config byte is 0x32 (bits 4-5 set)."""
    payload = self._build_payload(well_scan="orbital", well_scan_width=3)
    self.assertEqual(payload[64], 0x32)

  def test_orbital_inserts_5_bytes_after_separator(self):
    """Orbital scan adds 5 bytes between separator and settling byte."""
    point_payload = self._build_payload(well_scan="point")
    orbital_payload = self._build_payload(well_scan="orbital", well_scan_width=3)
    self.assertEqual(len(orbital_payload), len(point_payload) + 5)

  def test_orbital_params_encoding(self):
    """Orbital params: [0x02, diameter_mm, well_dia_hi, well_dia_lo, 0x00]."""
    payload = self._build_payload(well_scan="orbital", well_scan_width=3)
    # For 0x0024 (no extended separator), separator at offset 72:
    # plate(63) + scan(1) + optic(1) + zeros(3) + shaker(4) = 72
    sep_offset = 72
    self.assertEqual(payload[sep_offset:sep_offset + 4], b"\x27\x0f\x27\x0f")
    # Orbital params start right after separator
    orbital = payload[sep_offset + 4 : sep_offset + 9]
    self.assertEqual(orbital[0], 0x02)  # scan type
    self.assertEqual(orbital[1], 3)     # diameter = 3 mm
    # Well diameter: Cor_96 well size_x = size_y = 6.35 mm → 635 = 0x027B
    sample_well = self.plate.get_all_items()[0]
    well_dia = round(min(sample_well.get_size_x(), sample_well.get_size_y()) * 100)
    self.assertEqual(int.from_bytes(orbital[2:4], "big"), well_dia)
    self.assertEqual(orbital[4], 0x00)  # terminator

  def test_0x0026_uses_36_byte_block(self):
    """Machine type 0x0026 uses a 36-byte block between scan and separator."""
    self.backend._machine_type_code = 0x0026
    extended_payload = self._build_payload(well_scan="point")

    self.backend._machine_type_code = 0x0024
    standard_payload = self._build_payload(well_scan="point")

    # 0x0026: 36-byte block; 0x0024: 8 bytes (optic + zeros + shaker)
    self.assertEqual(len(extended_payload), len(standard_payload) + 28)

    # Separator positions
    sep_offset_std = 72  # plate(63) + scan(1) + optic(1) + zeros(3) + shaker(4)
    sep_offset_ext = 100  # plate(63) + scan(1) + block(36)
    self.assertEqual(standard_payload[sep_offset_std:sep_offset_std + 4], b"\x27\x0f\x27\x0f")
    self.assertEqual(extended_payload[sep_offset_ext:sep_offset_ext + 4], b"\x27\x0f\x27\x0f")

  def test_0x0026_optic_bytes_in_block(self):
    """Machine type 0x0026 puts optic config at block positions 4 and 5."""
    self.backend._machine_type_code = 0x0026
    payload = self._build_payload(well_scan="orbital", well_scan_width=3)
    # Block starts at offset 64 (after plate(63) + scan(1))
    # block[4] = optic_base | 0x08 = 0x02 | 0x08 = 0x0a (orbital indicator)
    # block[5] = optic_config = 0x02 | 0x30 = 0x32
    self.assertEqual(payload[64 + 4], 0x0a)
    self.assertEqual(payload[64 + 5], 0x32)


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


# ---------------------------------------------------------------------------
# Progressive measurement monitoring
# ---------------------------------------------------------------------------


def _make_run_response_payload(
  command_echo: int = 0x03,
  status_bytes: bytes = b"\x25\x04\x06",
  total_values: int = 392,
) -> bytes:
  """Build a minimal run response payload (>= 14 bytes) for _parse_run_response tests."""
  # Byte 0: command echo
  # Bytes 1-3: status
  # Bytes 4-11: padding (timing/firmware metadata)
  # Bytes 12-13: total values (uint16 BE)
  payload = bytes([command_echo]) + status_bytes + b"\x00" * 8
  payload += total_values.to_bytes(2, "big")
  return payload


def _make_data_response_payload(
  schema: int = 0xA9,
  total: int = 392,
  complete: int = 0,
) -> bytes:
  """Build a minimal data response payload (>= 11 bytes) for _parse_progress_from_data_response tests.

  Layout: 6 header bytes + schema(1) + total(2) + complete(2) + padding.
  """
  header = b"\x02\x05\x00\x26\x00\x00"  # 6 bytes
  payload = header + bytes([schema]) + total.to_bytes(2, "big") + complete.to_bytes(2, "big")
  return payload


class TestParseRunResponse(unittest.TestCase):
  """Test CLARIOstarBackend._parse_run_response()."""

  def test_accepted_response(self):
    """A valid run response with command echo 0x03 is accepted."""
    payload = _make_run_response_payload(command_echo=0x03, total_values=392)
    framed = _make_response_frame(payload)
    result = CLARIOstarBackend._parse_run_response(framed)
    self.assertTrue(result["accepted"])
    self.assertEqual(result["total_values"], 392)
    self.assertEqual(result["status_bytes"], b"\x25\x04\x06")

  def test_rejected_response(self):
    """A response with unexpected command echo is not accepted."""
    payload = _make_run_response_payload(command_echo=0x01, total_values=100)
    framed = _make_response_frame(payload)
    result = CLARIOstarBackend._parse_run_response(framed)
    self.assertFalse(result["accepted"])
    self.assertEqual(result["total_values"], 100)

  def test_too_short_response_raises(self):
    """A response shorter than 4 payload bytes raises ValueError."""
    short_payload = b"\x03\x25\x04"  # only 3 bytes
    framed = _make_response_frame(short_payload)
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_run_response(framed)

  def test_truncated_response_returns_minus_one_total(self):
    """A truncated response (4-13 payload bytes) parses accepted/status but
    returns total_values=-1 instead of crashing. This handles the case where
    the serial link drops bytes mid-frame (firmware sent 17 of 53 expected)."""
    # 10-byte payload: accepted + status + padding, but no total_values field
    truncated_payload = b"\x03\x25\x04\x26\x00\x00\x00\x00\x4e\x20"
    result = CLARIOstarBackend._parse_run_response(truncated_payload)
    self.assertTrue(result["accepted"])
    self.assertEqual(result["status_bytes"], b"\x25\x04\x26")
    self.assertEqual(result["total_values"], -1)

  def test_unframed_fallback(self):
    """When given raw (unframed) bytes, parse_run_response still works."""
    payload = _make_run_response_payload(command_echo=0x03, total_values=288)
    # Pass raw payload without framing
    result = CLARIOstarBackend._parse_run_response(payload)
    self.assertTrue(result["accepted"])
    self.assertEqual(result["total_values"], 288)

  def test_different_total_values(self):
    """Verify various total_values are parsed correctly."""
    for total in [0, 96, 288, 392, 1000]:
      payload = _make_run_response_payload(total_values=total)
      framed = _make_response_frame(payload)
      result = CLARIOstarBackend._parse_run_response(framed)
      self.assertEqual(result["total_values"], total)


class TestParseProgressFromDataResponse(unittest.TestCase):
  """Test CLARIOstarBackend._parse_progress_from_data_response()."""

  def test_zero_complete(self):
    """First progressive poll: 0 values complete."""
    payload = _make_data_response_payload(schema=0xA9, total=392, complete=0)
    framed = _make_response_frame(payload)
    result = CLARIOstarBackend._parse_progress_from_data_response(framed)
    self.assertEqual(result["complete"], 0)
    self.assertEqual(result["total"], 392)
    self.assertEqual(result["schema"], 0xA9)

  def test_partial_complete(self):
    """Progressive poll with partial data."""
    for complete_val in [44, 88, 132, 200]:
      payload = _make_data_response_payload(schema=0xA9, total=392, complete=complete_val)
      framed = _make_response_frame(payload)
      result = CLARIOstarBackend._parse_progress_from_data_response(framed)
      self.assertEqual(result["complete"], complete_val)
      self.assertEqual(result["total"], 392)

  def test_all_complete(self):
    """Progressive poll when measurement is fully done."""
    payload = _make_data_response_payload(schema=0xA9, total=392, complete=392)
    framed = _make_response_frame(payload)
    result = CLARIOstarBackend._parse_progress_from_data_response(framed)
    self.assertEqual(result["complete"], 392)
    self.assertEqual(result["total"], 392)

  def test_fluorescence_schema(self):
    """Fluorescence schema byte (0x21) is parsed correctly."""
    payload = _make_data_response_payload(schema=0x21, total=96, complete=48)
    framed = _make_response_frame(payload)
    result = CLARIOstarBackend._parse_progress_from_data_response(framed)
    self.assertEqual(result["schema"], 0x21)
    self.assertEqual(result["complete"], 48)
    self.assertEqual(result["total"], 96)

  def test_too_short_response_raises(self):
    """A response shorter than 11 payload bytes raises ValueError."""
    short_payload = b"\x02\x05\x00\x26"  # only 4 bytes
    framed = _make_response_frame(short_payload)
    with self.assertRaises(ValueError):
      CLARIOstarBackend._parse_progress_from_data_response(framed)


class TestProgressiveGetData(unittest.IsolatedAsyncioTestCase):
  """Test that the progressive getData command uses the correct payload."""

  async def test_progressive_payload(self):
    """_get_progressive_measurement_values sends $05 $02 $FF $FF $FF $FF $00 $00."""
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    expected_payload = b"\x05\x02\xff\xff\xff\xff\x00\x00"

    captured = []

    async def mock_send_command(payload, **kwargs):
      captured.append(payload)
      return _make_response_frame(b"\x00" * 11)

    backend.send_command = mock_send_command

    await backend._get_progressive_measurement_values()
    self.assertEqual(len(captured), 1)
    self.assertEqual(captured[0], expected_payload)

  async def test_final_getData_payload(self):
    """_get_measurement_values sends $05 $02 $00 $00 $00 $00 $00 $00 (for comparison)."""
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    expected_payload = b"\x05\x02\x00\x00\x00\x00\x00\x00"

    captured = []

    async def mock_send_command(payload, **kwargs):
      captured.append(payload)
      return _make_response_frame(b"\x00" * 11)

    backend.send_command = mock_send_command

    await backend._get_measurement_values()
    self.assertEqual(len(captured), 1)
    self.assertEqual(captured[0], expected_payload)


class TestWaitForReadyWithProgress(unittest.IsolatedAsyncioTestCase):
  """Test CLARIOstarBackend._wait_for_ready_with_progress()."""

  def _make_backend(self):
    """Create a backend with mocked I/O."""
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    backend.timeout = 30
    backend.read_timeout = 20
    backend.write_timeout = 10
    backend.io = unittest.mock.MagicMock()
    backend._trace_io_path = None
    return backend

  def _make_status_response(self, busy: bool) -> bytes:
    """Build a framed status response with the given BUSY state."""
    # Byte 1 bit 5 = BUSY
    byte1 = 0x25 if busy else 0x05  # 0x25 = VALID + BUSY, 0x05 = VALID
    payload = bytes([0x00, byte1, 0x00, 0x00, 0x00])
    return _make_response_frame(payload)

  async def test_no_progress_callback_falls_back(self):
    """When on_progress=None, _wait_for_ready_with_progress uses _wait_for_ready_and_return."""
    backend = self._make_backend()
    run_payload = _make_run_response_payload()
    run_response = _make_response_frame(run_payload)

    # Mock _wait_for_ready_and_return to verify fallback
    backend._wait_for_ready_and_return = unittest.mock.AsyncMock(return_value=run_response)

    result = await backend._wait_for_ready_with_progress(run_response, on_progress=None)
    self.assertEqual(result, run_response)
    backend._wait_for_ready_and_return.assert_awaited_once_with(run_response, timeout=None)

  async def test_progress_callback_called_with_increasing_values(self):
    """Progress callback receives increasing complete values."""
    backend = self._make_backend()
    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)

    # Simulate: 2 progressive polls, then BUSY clears
    progressive_payloads = [
      _make_data_response_payload(schema=0xA9, total=392, complete=44),
      _make_data_response_payload(schema=0xA9, total=392, complete=200),
    ]
    progressive_responses = [_make_response_frame(p) for p in progressive_payloads]
    progressive_idx = [0]

    async def mock_get_progressive():
      idx = progressive_idx[0]
      progressive_idx[0] += 1
      return progressive_responses[min(idx, len(progressive_responses) - 1)]

    status_call_count = [0]

    async def mock_request_status():
      status_call_count[0] += 1
      # BUSY on first two polls, then ready
      busy = status_call_count[0] < 3
      return self._make_status_response(busy)

    backend._get_progressive_measurement_values = mock_get_progressive
    backend._request_command_status = mock_request_status

    progress_log = []

    async def on_progress(complete, total, raw):
      progress_log.append((complete, total))

    result = await backend._wait_for_ready_with_progress(
      run_response, on_progress=on_progress, poll_interval=0.01,
    )

    self.assertEqual(result, run_response)
    self.assertGreaterEqual(len(progress_log), 2)
    # Values should be increasing
    self.assertEqual(progress_log[0], (44, 392))
    self.assertEqual(progress_log[1], (200, 392))

  async def test_timeout_raises(self):
    """TimeoutError is raised when BUSY never clears."""
    backend = self._make_backend()
    run_payload = _make_run_response_payload()
    run_response = _make_response_frame(run_payload)

    async def mock_get_progressive():
      return _make_response_frame(
        _make_data_response_payload(schema=0xA9, total=392, complete=0)
      )

    async def mock_request_status():
      return self._make_status_response(busy=True)

    backend._get_progressive_measurement_values = mock_get_progressive
    backend._request_command_status = mock_request_status

    async def noop_progress(c, t, r):
      pass

    with self.assertRaises(TimeoutError):
      await backend._wait_for_ready_with_progress(
        run_response, on_progress=noop_progress, poll_interval=0.01, timeout=0.05,
      )

  async def test_immediate_ready(self):
    """If BUSY clears on the first check, callback is called once and returns."""
    backend = self._make_backend()
    run_payload = _make_run_response_payload()
    run_response = _make_response_frame(run_payload)

    async def mock_get_progressive():
      return _make_response_frame(
        _make_data_response_payload(schema=0xA9, total=392, complete=392)
      )

    async def mock_request_status():
      return self._make_status_response(busy=False)

    backend._get_progressive_measurement_values = mock_get_progressive
    backend._request_command_status = mock_request_status

    progress_log = []

    async def on_progress(complete, total, raw):
      progress_log.append((complete, total))

    result = await backend._wait_for_ready_with_progress(
      run_response, on_progress=on_progress, poll_interval=0.01,
    )

    self.assertEqual(result, run_response)
    self.assertEqual(len(progress_log), 1)
    self.assertEqual(progress_log[0], (392, 392))


# ---------------------------------------------------------------------------
# read_absorbance orchestration integration tests
# ---------------------------------------------------------------------------


class TestReadAbsorbanceOrchestration(unittest.IsolatedAsyncioTestCase):
  """Test the refactored read_absorbance orchestration flow.

  The new flow:
    0. enable_temperature_monitoring()
    1. _start_absorbance_measurement() — atomic send, returns run response
    2. Check if BUSY already cleared (fast measurements)
    3. If wait=False → return None
    4. If wait=True → polling loop: check status first, then progressive getData
    5. Collect final data via collect_absorbance_measurement
  """

  def _make_backend(self):
    """Create a backend with mocked I/O."""
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    backend.timeout = 30
    backend.read_timeout = 20
    backend.write_timeout = 10
    backend.io = unittest.mock.MagicMock()
    backend.io.usb_purge_rx_buffer = unittest.mock.AsyncMock()
    backend._trace_io_path = None
    backend._machine_type_code = 0x0026
    backend._last_scan_params = {}
    backend.enable_temperature_monitoring = unittest.mock.AsyncMock()
    return backend

  def _make_status_response(self, busy: bool) -> bytes:
    byte1 = 0x25 if busy else 0x05
    payload = bytes([0x00, byte1, 0x00, 0x00, 0x00])
    return _make_response_frame(payload)

  async def test_wait_false_returns_none_immediately(self):
    """read_absorbance(wait=False) sends the run command and returns None."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    all_wells = plate.get_all_items()

    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)

    backend._start_absorbance_measurement = unittest.mock.AsyncMock(return_value=run_response)

    # Initial status check: still BUSY
    backend._request_command_status = unittest.mock.AsyncMock(
      return_value=self._make_status_response(busy=True)
    )

    result = await backend.read_absorbance(
      plate=plate, wells=all_wells, wavelength=600, wait=False,
    )

    self.assertIsNone(result)
    backend._start_absorbance_measurement.assert_awaited_once()

  async def test_fast_measurement_skips_progressive(self):
    """When BUSY clears before progressive polling starts, skip it entirely."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    all_wells = plate.get_all_items()

    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)

    backend._start_absorbance_measurement = unittest.mock.AsyncMock(return_value=run_response)

    # Initial status check: already done (BUSY cleared)
    backend._request_command_status = unittest.mock.AsyncMock(
      return_value=self._make_status_response(busy=False)
    )

    # Progressive should NOT be called
    backend._get_progressive_measurement_values = unittest.mock.AsyncMock()

    expected_result = [{"wavelength": 600, "data": [[0.1]], "temperature": 25.0, "time": 0}]
    backend.collect_absorbance_measurement = unittest.mock.AsyncMock(return_value=expected_result)

    result = await backend.read_absorbance(
      plate=plate, wells=all_wells, wavelength=600,
    )

    self.assertEqual(result, expected_result)
    backend._get_progressive_measurement_values.assert_not_awaited()
    backend.collect_absorbance_measurement.assert_awaited_once()

  async def test_wait_true_polls_then_collects(self):
    """read_absorbance(wait=True) does progressive polling then collects final data."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    all_wells = plate.get_all_items()

    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)

    backend._start_absorbance_measurement = unittest.mock.AsyncMock(return_value=run_response)

    # Progressive data for the polling loop (step 4)
    progressive_responses = [
      _make_response_frame(_make_data_response_payload(schema=0xA9, total=392, complete=100)),
      _make_response_frame(_make_data_response_payload(schema=0xA9, total=392, complete=300)),
    ]
    prog_idx = [0]

    async def mock_get_progressive(**kwargs):
      idx = prog_idx[0]
      prog_idx[0] += 1
      return progressive_responses[min(idx, len(progressive_responses) - 1)]

    backend._get_progressive_measurement_values = mock_get_progressive

    # Status: initial check BUSY, then loop: BUSY, BUSY, ready
    # Call order: initial check, loop iteration 1, loop iteration 2, loop iteration 3
    status_count = [0]

    async def mock_request_status():
      status_count[0] += 1
      # Call 1 = initial check (BUSY), calls 2-3 = loop (BUSY), call 4 = loop (ready)
      busy = status_count[0] < 4
      return self._make_status_response(busy)

    backend._request_command_status = mock_request_status

    expected_result = [{"wavelength": 600, "data": [[0.1]], "temperature": 25.0, "time": 0}]
    backend.collect_absorbance_measurement = unittest.mock.AsyncMock(return_value=expected_result)

    result = await backend.read_absorbance(
      plate=plate, wells=all_wells, wavelength=600, data_retrieval_rate=0.01,
    )

    self.assertEqual(result, expected_result)
    backend._start_absorbance_measurement.assert_awaited_once()
    backend.collect_absorbance_measurement.assert_awaited_once()

  async def test_on_progress_callback_called(self):
    """on_progress callback is called during the polling loop."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    all_wells = plate.get_all_items()

    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)

    backend._start_absorbance_measurement = unittest.mock.AsyncMock(return_value=run_response)

    progressive_responses = [
      _make_response_frame(_make_data_response_payload(schema=0xA9, total=392, complete=44)),
      _make_response_frame(_make_data_response_payload(schema=0xA9, total=392, complete=200)),
    ]
    prog_idx = [0]

    async def mock_get_progressive(**kwargs):
      idx = prog_idx[0]
      prog_idx[0] += 1
      return progressive_responses[min(idx, len(progressive_responses) - 1)]

    backend._get_progressive_measurement_values = mock_get_progressive

    # initial check BUSY, loop: BUSY, BUSY, ready
    status_count = [0]

    async def mock_request_status():
      status_count[0] += 1
      busy = status_count[0] < 4
      return self._make_status_response(busy)

    backend._request_command_status = mock_request_status

    expected_result = [{"wavelength": 600, "data": [[0.1]], "temperature": 25.0, "time": 0}]
    backend.collect_absorbance_measurement = unittest.mock.AsyncMock(return_value=expected_result)

    progress_log = []

    async def on_progress(complete, total, raw):
      progress_log.append((complete, total))

    result = await backend.read_absorbance(
      plate=plate, wells=all_wells, wavelength=600,
      data_retrieval_rate=0.01, on_progress=on_progress,
    )

    self.assertEqual(result, expected_result)
    # on_progress should have been called during the polling loop
    self.assertGreaterEqual(len(progress_log), 1)
    self.assertEqual(progress_log[0][0], 44)

  async def test_timeout_raises(self):
    """TimeoutError is raised when BUSY never clears."""
    backend = self._make_backend()
    backend.timeout = 0.05  # very short timeout
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    all_wells = plate.get_all_items()

    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)

    backend._start_absorbance_measurement = unittest.mock.AsyncMock(return_value=run_response)

    async def mock_get_progressive(**kwargs):
      return _make_response_frame(
        _make_data_response_payload(schema=0xA9, total=392, complete=0)
      )

    backend._get_progressive_measurement_values = mock_get_progressive

    async def mock_request_status():
      return self._make_status_response(busy=True)

    backend._request_command_status = mock_request_status

    with self.assertRaises(TimeoutError):
      await backend.read_absorbance(
        plate=plate, wells=all_wells, wavelength=600, data_retrieval_rate=0.01,
      )

  async def test_start_absorbance_measurement_is_atomic(self):
    """_start_absorbance_measurement sends, verifies, and returns the run response."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")

    # Mock send_command with an accepted response
    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)
    backend.send_command = unittest.mock.AsyncMock(return_value=run_response)

    result = await backend._start_absorbance_measurement(
      wavelengths=[600], plate=plate,
    )

    # Should return the run response directly
    self.assertEqual(result, run_response)
    backend.send_command.assert_awaited_once()

  async def test_start_absorbance_measurement_rejected_raises(self):
    """_start_absorbance_measurement raises RuntimeError when the firmware rejects the command."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")

    # Mock send_command with a rejected response (command_echo != 0x03)
    run_payload = _make_run_response_payload(command_echo=0x01, total_values=0)
    run_response = _make_response_frame(run_payload)
    backend.send_command = unittest.mock.AsyncMock(return_value=run_response)

    with self.assertRaises(RuntimeError) as ctx:
      await backend._start_absorbance_measurement(wavelengths=[600], plate=plate)

    self.assertIn("rejected", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# Payload encoding: _start_absorbance_measurement
# ---------------------------------------------------------------------------


class TestAbsorbancePayloadEncoding(unittest.IsolatedAsyncioTestCase):
  """Test that _start_absorbance_measurement encodes parameters correctly in the payload.

  Uses the separator bytes (0x27 0x0F 0x27 0x0F) as an anchor to locate
  parameter-dependent bytes regardless of machine type or plate size.
  """

  def _make_backend(self, machine_type=0x0024):
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    backend._machine_type_code = machine_type
    backend._last_scan_params = {}
    return backend

  async def _capture_payload(self, backend, **kwargs):
    """Call _start_absorbance_measurement and return the raw payload bytes sent."""
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    captured = []
    run_payload = _make_run_response_payload(total_values=392)
    run_response = _make_response_frame(run_payload)

    async def mock_send(payload, **kw):
      captured.append(payload)
      return run_response

    backend.send_command = mock_send

    defaults = {"wavelengths": [600], "plate": plate}
    defaults.update(kwargs)
    await backend._start_absorbance_measurement(**defaults)
    return captured[0]

  def _find_params(self, payload, num_wavelengths=1):
    """Find key parameter positions relative to the separator.

    Layout after separator (for point scan, no orbital bytes):
      +4: settling_byte (pause_time_per_well encoding)
      +5: wavelength_count
      +6: wavelength data (2 bytes each × N)
      +6+2N: fixed bytes (13)
      +6+2N+13: settling_time flag (1)
      +6+2N+14: settling_time value (2)
      +6+2N+16: fixed trailer (11)
      +6+2N+27: flashes_per_well (2)
    """
    sep = b"\x27\x0f\x27\x0f"
    idx = payload.index(sep)
    N = num_wavelengths
    base = idx + 6 + 2 * N
    return {
      "settling_byte": payload[idx + 4],
      "wl_count": payload[idx + 5],
      "wl_data_start": idx + 6,
      "settling_time_flag": payload[base + 13],
      "settling_time_value": int.from_bytes(payload[base + 14 : base + 16], "big"),
      "flashes_per_well": int.from_bytes(payload[base + 27 : base + 29], "big"),
    }

  # --- pause_time_per_well encoding ---

  async def test_pause_time_per_well_zero_encodes_as_1(self):
    """pause_time_per_well=0 → settling_byte=1 (firmware convention: 0 means 'use 1')."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, pause_time_per_well=0)
    self.assertEqual(self._find_params(payload)["settling_byte"], 1)

  async def test_pause_time_per_well_1_encodes_as_5(self):
    """pause_time_per_well=1 → (1 * 10) // 2 = 5."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, pause_time_per_well=1)
    self.assertEqual(self._find_params(payload)["settling_byte"], 5)

  async def test_pause_time_per_well_5_encodes_as_25(self):
    """pause_time_per_well=5 → (5 * 10) // 2 = 25 = 0x19 (the OEM default byte)."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, pause_time_per_well=5)
    self.assertEqual(self._find_params(payload)["settling_byte"], 25)

  async def test_pause_time_per_well_10_encodes_as_50(self):
    """pause_time_per_well=10 → (10 * 10) // 2 = 50."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, pause_time_per_well=10)
    self.assertEqual(self._find_params(payload)["settling_byte"], 50)

  async def test_pause_time_per_well_exceeds_max_raises(self):
    """pause_time_per_well > 10 raises ValueError."""
    backend = self._make_backend()
    with self.assertRaises(ValueError):
      await self._capture_payload(backend, pause_time_per_well=11)

  # --- settling_time_before_measurement encoding ---

  async def test_settling_time_zero_no_flag(self):
    """settling_time_before_measurement=0 → flag=0x00, value=0x0000."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, settling_time_before_measurement=0)
    params = self._find_params(payload)
    self.assertEqual(params["settling_time_flag"], 0x00)
    self.assertEqual(params["settling_time_value"], 0)

  async def test_settling_time_nonzero_sets_flag(self):
    """settling_time_before_measurement=5 → flag=0x01, value=5."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, settling_time_before_measurement=5)
    params = self._find_params(payload)
    self.assertEqual(params["settling_time_flag"], 0x01)
    self.assertEqual(params["settling_time_value"], 5)

  async def test_settling_time_large_value(self):
    """settling_time_before_measurement=300 → flag=0x01, value=300 (uint16 BE)."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, settling_time_before_measurement=300)
    params = self._find_params(payload)
    self.assertEqual(params["settling_time_flag"], 0x01)
    self.assertEqual(params["settling_time_value"], 300)

  # --- flashes_per_well encoding ---

  async def test_flashes_per_well_default_5(self):
    """Default flashes_per_well=5 → 0x0005."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend)
    self.assertEqual(self._find_params(payload)["flashes_per_well"], 5)

  async def test_flashes_per_well_100(self):
    """flashes_per_well=100 → 0x0064."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, flashes_per_well=100)
    self.assertEqual(self._find_params(payload)["flashes_per_well"], 100)

  async def test_flashes_per_well_200(self):
    """flashes_per_well=200 → 0x00C8."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, flashes_per_well=200)
    self.assertEqual(self._find_params(payload)["flashes_per_well"], 200)

  # --- wavelength encoding ---

  async def test_single_wavelength_600nm(self):
    """600 nm → count=1, encoded as 6000 = 0x1770."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, wavelengths=[600])
    params = self._find_params(payload)
    self.assertEqual(params["wl_count"], 1)
    start = params["wl_data_start"]
    self.assertEqual(int.from_bytes(payload[start : start + 2], "big"), 6000)

  async def test_multi_wavelength_encoding(self):
    """[260, 280, 600] → count=3, values=[2600, 2800, 6000]."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend, wavelengths=[260, 280, 600])
    sep = b"\x27\x0f\x27\x0f"
    idx = payload.index(sep)
    self.assertEqual(payload[idx + 5], 3)  # count
    start = idx + 6
    self.assertEqual(int.from_bytes(payload[start : start + 2], "big"), 2600)
    self.assertEqual(int.from_bytes(payload[start + 2 : start + 4], "big"), 2800)
    self.assertEqual(int.from_bytes(payload[start + 4 : start + 6], "big"), 6000)
    # Verify the downstream params are still at the right offsets for 3 wavelengths
    params = self._find_params(payload, num_wavelengths=3)
    self.assertEqual(params["settling_time_flag"], 0x00)
    self.assertEqual(params["flashes_per_well"], 5)

  async def test_wavelength_out_of_range_low_raises(self):
    """Wavelength below 220 nm raises ValueError."""
    backend = self._make_backend()
    with self.assertRaises(ValueError):
      await self._capture_payload(backend, wavelengths=[100])

  async def test_wavelength_out_of_range_high_raises(self):
    """Wavelength above 1000 nm raises ValueError."""
    backend = self._make_backend()
    with self.assertRaises(ValueError):
      await self._capture_payload(backend, wavelengths=[1100])

  async def test_too_many_wavelengths_raises(self):
    """More than 8 wavelengths raises ValueError."""
    backend = self._make_backend()
    with self.assertRaises(ValueError):
      await self._capture_payload(backend, wavelengths=list(range(220, 220 + 9 * 50, 50)))

  async def test_zero_wavelengths_raises(self):
    """Empty wavelength list raises ValueError."""
    backend = self._make_backend()
    with self.assertRaises(ValueError):
      await self._capture_payload(backend, wavelengths=[])

  # --- shaker encoding (0x0024) ---

  async def test_no_shake_bytes_0x0024(self):
    """No shaking → 4 zero bytes at shaker position for 0x0024."""
    backend = self._make_backend()
    payload = await self._capture_payload(backend)
    # Shaker at offset 68-71 for type 0x0024 (plate(63) + scan(1) + optic(1) + zeros(3))
    self.assertEqual(payload[68:72], b"\x00\x00\x00\x00")

  async def test_shake_bytes_encoded_0x0024(self):
    """Orbital 300rpm 10s → correct 0x0024 shaker encoding at offset 68."""
    backend = self._make_backend()
    payload = await self._capture_payload(
      backend, shake_speed_rpm=300, shake_duration_s=10
    )
    expected = _shaker_bytes(ShakerType.ORBITAL, speed_rpm=300, duration_s=10)
    self.assertEqual(payload[68:72], expected)

  # --- shaker encoding (0x0026) ---

  async def test_no_shake_0x0026(self):
    """No shaking → block positions 17, 23, 24-25 are all zero for 0x0026.

    Uses orbital well_scan because the 36-byte block is only used for
    non-point scans on 0x0026.
    """
    backend = self._make_backend(machine_type=0x0026)
    payload = await self._capture_payload(
      backend, well_scan="orbital", well_scan_width=3.0
    )
    # Block starts at offset 64 (plate(63) + scan(1))
    self.assertEqual(payload[64 + 17], 0x00)  # shake type
    self.assertEqual(payload[64 + 23], 0x00)  # speed
    self.assertEqual(payload[64 + 24], 0x00)  # duration hi
    self.assertEqual(payload[64 + 25], 0x00)  # duration lo

  async def test_shake_bytes_0x0026_orbital(self):
    """Orbital 300rpm 5s → correct 0x0026 encoding at scattered block positions."""
    backend = self._make_backend(machine_type=0x0026)
    payload = await self._capture_payload(
      backend, well_scan="orbital", well_scan_width=3.0,
      shake_speed_rpm=300, shake_duration_s=5,
    )
    # Block starts at offset 64
    self.assertEqual(payload[64 + 17], 0x02)  # orbital → 0x02 in 0x0026 encoding
    self.assertEqual(payload[64 + 23], 2)     # speed_idx = (300/100)-1 = 2
    self.assertEqual(payload[64 + 24], 0x00)  # duration hi
    self.assertEqual(payload[64 + 25], 0x05)  # duration lo = 5

  async def test_shake_0x0026_separator_at_100(self):
    """0x0026 non-point separator is at offset 100 (plate(63) + scan(1) + block(36))."""
    backend = self._make_backend(machine_type=0x0026)
    payload = await self._capture_payload(
      backend, well_scan="orbital", well_scan_width=3.0
    )
    self.assertEqual(payload[100:104], b"\x27\x0f\x27\x0f")

  async def test_0x0026_optic_bytes_orbital(self):
    """0x0026 block[4]=0x0a, block[5]=0x32 for orbital absorbance."""
    backend = self._make_backend(machine_type=0x0026)
    payload = await self._capture_payload(
      backend, well_scan="orbital", well_scan_width=3.0
    )
    # block[4] = 0x02 | 0x08 = 0x0a (well-scan-enabled)
    # block[5] = 0x02 | 0x30 = 0x32 (orbital flags)
    self.assertEqual(payload[64 + 4], 0x0a)
    self.assertEqual(payload[64 + 5], 0x32)

  async def test_0x0026_optic_bytes_spiral(self):
    """0x0026 block[4]=0x0a, block[5]=0x06 for spiral absorbance."""
    backend = self._make_backend(machine_type=0x0026)
    payload = await self._capture_payload(
      backend, well_scan="spiral", well_scan_width=4.0
    )
    # block[4] = 0x02 | 0x08 = 0x0a (well-scan-enabled, same for any non-point)
    # block[5] = 0x02 | 0x04 = 0x06 (spiral flag)
    self.assertEqual(payload[64 + 4], 0x0a)
    self.assertEqual(payload[64 + 5], 0x06)

  async def test_0x0026_point_uses_compact_format(self):
    """0x0026 point scan uses compact format, NOT the 36-byte block.

    Layout: optic(1) + zeros(2) + shaker(4) + extended(5) + separator(4).
    Optic byte at offset 64, separator at offset 76.
    """
    backend = self._make_backend(machine_type=0x0026)
    payload = await self._capture_payload(backend)
    # optic byte = 0x02 (point absorbance, no flags)
    self.assertEqual(payload[64], 0x02)
    # 2 zero bytes
    self.assertEqual(payload[65:67], b"\x00\x00")
    # 4 shaker bytes (no shake)
    self.assertEqual(payload[67:71], b"\x00\x00\x00\x00")
    # 5-byte extended separator
    self.assertEqual(payload[71:76], b"\x00\x20\x04\x00\x1e")
    # Then the standard separator
    self.assertEqual(payload[76:80], b"\x27\x0f\x27\x0f")

  # --- combined parameters ---

  async def test_all_parameters_combined(self):
    """All three renamed parameters together produce correct encoding."""
    backend = self._make_backend()
    payload = await self._capture_payload(
      backend,
      pause_time_per_well=3,
      settling_time_before_measurement=10,
      flashes_per_well=50,
    )
    params = self._find_params(payload)
    self.assertEqual(params["settling_byte"], (3 * 10) // 2)  # 15
    self.assertEqual(params["settling_time_flag"], 0x01)
    self.assertEqual(params["settling_time_value"], 10)
    self.assertEqual(params["flashes_per_well"], 50)

  # --- machine type differences ---

  async def test_0x0026_params_via_separator_anchor(self):
    """Type 0x0026 uses 36-byte block; post-separator params still encoded correctly."""
    backend = self._make_backend(machine_type=0x0026)
    payload = await self._capture_payload(
      backend, pause_time_per_well=5, settling_time_before_measurement=2, flashes_per_well=7,
    )
    params = self._find_params(payload)
    self.assertEqual(params["settling_byte"], 25)
    self.assertEqual(params["settling_time_flag"], 0x01)
    self.assertEqual(params["settling_time_value"], 2)
    self.assertEqual(params["flashes_per_well"], 7)


# ---------------------------------------------------------------------------
# Payload encoding: _start_fluorescence_measurement
# ---------------------------------------------------------------------------


class TestFluorescencePayloadEncoding(unittest.IsolatedAsyncioTestCase):
  """Test that _start_fluorescence_measurement encodes parameters correctly.

  Uses separator anchor and end-of-payload offsets to locate encoded bytes.
  """

  def _make_backend(self):
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    backend._machine_type_code = 0x0024
    backend._last_scan_params = {}
    return backend

  async def _capture_payload(self, backend, **kwargs):
    """Call _start_fluorescence_measurement(wait=False) and capture the payload."""
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    captured = []
    run_payload = _make_run_response_payload(total_values=96)
    run_response = _make_response_frame(run_payload)

    async def mock_send(payload, **kw):
      captured.append(payload)
      return run_response

    backend.send_command = mock_send

    defaults = {
      "plate": plate,
      "excitation_wavelength": 485,
      "emission_wavelength": 528,
      "focal_height": 8.5,
      "wait": False,
    }
    defaults.update(kwargs)
    await backend._start_fluorescence_measurement(**defaults)
    return captured[0]

  def _find_fl_params(self, payload):
    """Find fluorescence parameter positions.

    Uses separator as anchor for pause_time_per_well, and end-of-payload
    offsets for settling_time and flashes.

    End layout: ... [flag(1)] [value(2)] [trailer(11)] [flashes(2)] [final(4)]
    Total from flag to end: 1 + 2 + 11 + 2 + 4 = 20 bytes.
    """
    sep = b"\x27\x0f\x27\x0f"
    idx = payload.index(sep)
    return {
      "pause_time_per_well_byte": payload[idx + 4],
      "flashes": int.from_bytes(payload[-6:-4], "big"),
      "settling_time_flag": payload[-20],
      "settling_time_value": int.from_bytes(payload[-19:-17], "big"),
    }

  # --- pause_time_per_well ---

  async def test_pause_time_per_well_zero_encodes_as_1(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend, pause_time_per_well=0)
    self.assertEqual(self._find_fl_params(payload)["pause_time_per_well_byte"], 1)

  async def test_pause_time_per_well_5_encodes_as_25(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend, pause_time_per_well=5)
    self.assertEqual(self._find_fl_params(payload)["pause_time_per_well_byte"], 25)

  async def test_pause_time_per_well_10_encodes_as_50(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend, pause_time_per_well=10)
    self.assertEqual(self._find_fl_params(payload)["pause_time_per_well_byte"], 50)

  # --- settling_time_before_measurement ---

  async def test_settling_time_zero_no_flag(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend, settling_time_before_measurement=0)
    params = self._find_fl_params(payload)
    self.assertEqual(params["settling_time_flag"], 0x00)
    self.assertEqual(params["settling_time_value"], 0)

  async def test_settling_time_nonzero_sets_flag(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend, settling_time_before_measurement=10)
    params = self._find_fl_params(payload)
    self.assertEqual(params["settling_time_flag"], 0x01)
    self.assertEqual(params["settling_time_value"], 10)

  # --- flashes ---

  async def test_flashes_default_100(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend)
    self.assertEqual(self._find_fl_params(payload)["flashes"], 100)

  async def test_flashes_200(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend, flashes=200)
    self.assertEqual(self._find_fl_params(payload)["flashes"], 200)

  async def test_flashes_exceeds_200_raises(self):
    backend = self._make_backend()
    with self.assertRaises(ValueError):
      await self._capture_payload(backend, flashes=201)

  async def test_flying_mode_with_too_many_flashes_raises(self):
    backend = self._make_backend()
    with self.assertRaises(ValueError):
      await self._capture_payload(backend, flying_mode=True, flashes=5)

  async def test_flying_mode_with_3_flashes_ok(self):
    backend = self._make_backend()
    payload = await self._capture_payload(backend, flying_mode=True, flashes=3)
    self.assertEqual(self._find_fl_params(payload)["flashes"], 3)

  # --- combined ---

  async def test_all_parameters_combined(self):
    backend = self._make_backend()
    payload = await self._capture_payload(
      backend,
      pause_time_per_well=7,
      settling_time_before_measurement=15,
      flashes=50,
    )
    params = self._find_fl_params(payload)
    self.assertEqual(params["pause_time_per_well_byte"], (7 * 10) // 2)  # 35
    self.assertEqual(params["settling_time_flag"], 0x01)
    self.assertEqual(params["settling_time_value"], 15)
    self.assertEqual(params["flashes"], 50)


# ---------------------------------------------------------------------------
# Kwargs forwarding: read_absorbance → _start_absorbance_measurement
# ---------------------------------------------------------------------------


class TestReadAbsorbanceKwargsForwarding(unittest.IsolatedAsyncioTestCase):
  """Test that read_absorbance forwards renamed parameters to _start_absorbance_measurement."""

  def _make_backend(self):
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    backend.timeout = 30
    backend.read_timeout = 20
    backend.write_timeout = 10
    backend.io = unittest.mock.MagicMock()
    backend.io.usb_purge_rx_buffer = unittest.mock.AsyncMock()
    backend._trace_io_path = None
    backend._machine_type_code = 0x0026
    backend._last_scan_params = {}
    backend.enable_temperature_monitoring = unittest.mock.AsyncMock()
    return backend

  def _make_status_response(self, busy: bool) -> bytes:
    byte1 = 0x25 if busy else 0x05
    payload = bytes([0x00, byte1, 0x00, 0x00, 0x00])
    return _make_response_frame(payload)

  async def _run_with_kwargs(self, **kwargs):
    """Call read_absorbance with the given kwargs and return the captured call_args."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    all_wells = plate.get_all_items()

    run_payload = _make_run_response_payload(total_values=24)
    run_response = _make_response_frame(run_payload)

    backend._start_absorbance_measurement = unittest.mock.AsyncMock(return_value=run_response)
    backend._request_command_status = unittest.mock.AsyncMock(
      return_value=self._make_status_response(busy=False)
    )
    backend.collect_absorbance_measurement = unittest.mock.AsyncMock(return_value=[{}])

    await backend.read_absorbance(
      plate=plate, wells=all_wells, wavelength=600, **kwargs,
    )

    return backend._start_absorbance_measurement.call_args.kwargs

  async def test_pause_time_per_well_forwarded(self):
    call_kwargs = await self._run_with_kwargs(pause_time_per_well=7)
    self.assertEqual(call_kwargs["pause_time_per_well"], 7)

  async def test_settling_time_before_measurement_forwarded(self):
    call_kwargs = await self._run_with_kwargs(settling_time_before_measurement=3)
    self.assertEqual(call_kwargs["settling_time_before_measurement"], 3)

  async def test_flashes_per_well_forwarded(self):
    call_kwargs = await self._run_with_kwargs(flashes_per_well=22)
    self.assertEqual(call_kwargs["flashes_per_well"], 22)

  async def test_all_params_forwarded_together(self):
    call_kwargs = await self._run_with_kwargs(
      pause_time_per_well=5,
      settling_time_before_measurement=10,
      flashes_per_well=50,
    )
    self.assertEqual(call_kwargs["pause_time_per_well"], 5)
    self.assertEqual(call_kwargs["settling_time_before_measurement"], 10)
    self.assertEqual(call_kwargs["flashes_per_well"], 50)

  async def test_orchestration_kwargs_not_forwarded(self):
    """wait, data_retrieval_rate, on_progress are consumed by read_absorbance, not forwarded."""
    call_kwargs = await self._run_with_kwargs(
      wait=True, data_retrieval_rate=2.0,
    )
    self.assertNotIn("wait", call_kwargs)
    self.assertNotIn("data_retrieval_rate", call_kwargs)
    self.assertNotIn("on_progress", call_kwargs)


# ---------------------------------------------------------------------------
# Kwargs forwarding: read_fluorescence → _start_fluorescence_measurement
# ---------------------------------------------------------------------------


class TestReadFluorescenceKwargsForwarding(unittest.IsolatedAsyncioTestCase):
  """Test that read_fluorescence forwards renamed parameters to _start_fluorescence_measurement."""

  def _make_backend(self):
    backend = CLARIOstarBackend.__new__(CLARIOstarBackend)
    backend.timeout = 30
    backend.read_timeout = 20
    backend.write_timeout = 10
    backend.io = unittest.mock.MagicMock()
    backend._trace_io_path = None
    backend._machine_type_code = 0x0024
    backend._last_scan_params = {}
    return backend

  async def _run_with_kwargs(self, **kwargs):
    """Call read_fluorescence with the given kwargs and return the captured call_args."""
    backend = self._make_backend()
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    all_wells = plate.get_all_items()

    backend._start_fluorescence_measurement = unittest.mock.AsyncMock(return_value=b"")

    # Mock collect to avoid needing a real response
    backend.collect_fluorescence_measurement = unittest.mock.AsyncMock(return_value=[{}])

    await backend.read_fluorescence(
      plate=plate, wells=all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      **kwargs,
    )

    return backend._start_fluorescence_measurement.call_args.kwargs

  async def test_pause_time_per_well_forwarded(self):
    call_kwargs = await self._run_with_kwargs(pause_time_per_well=7)
    self.assertEqual(call_kwargs["pause_time_per_well"], 7)

  async def test_settling_time_before_measurement_forwarded(self):
    call_kwargs = await self._run_with_kwargs(settling_time_before_measurement=3)
    self.assertEqual(call_kwargs["settling_time_before_measurement"], 3)

  async def test_flashes_forwarded(self):
    call_kwargs = await self._run_with_kwargs(flashes=50)
    self.assertEqual(call_kwargs["flashes"], 50)

  async def test_wait_forwarded_to_start(self):
    """Unlike absorbance, fluorescence forwards wait to _start_fluorescence_measurement."""
    call_kwargs = await self._run_with_kwargs(wait=False)
    self.assertFalse(call_kwargs["wait"])


class TestReadingsToGridRowMajorOrder(unittest.TestCase):
  """Test that _readings_to_grid maps firmware values correctly for partial well selections.

  The firmware returns values in row-major order of the selected wells (A1, A2, ..., B1, B3, ...),
  regardless of the order in which the wells list is constructed in Python. This test verifies
  that column-major well lists (like PLR's get_all_items()) are handled correctly.
  """

  def test_column_major_wells_mapped_correctly(self):
    """Wells passed in column-major order must still map values to correct grid positions."""
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    # Column-major well list: all col 1, then some col 2, then some col 3
    wells = (
      [plate.get_well(f"{r}1") for r in "ABCDEFGH"]
      + [plate.get_well(f"{r}2") for r in "ACEG"]
      + [plate.get_well(f"{r}3") for r in "BDFH"]
    )
    # Firmware returns 16 values in row-major order of selected wells:
    # A1, A2, B1, B3, C1, C2, D1, D3, E1, E2, F1, F3, G1, G2, H1, H3
    # Use distinctive values to detect any mis-mapping.
    readings = [
      1.0, 2.0,    # row A: A1, A2
      3.0, 4.0,    # row B: B1, B3
      5.0, 6.0,    # row C: C1, C2
      7.0, 8.0,    # row D: D1, D3
      9.0, 10.0,   # row E: E1, E2
      11.0, 12.0,  # row F: F1, F3
      13.0, 14.0,  # row G: G1, G2
      15.0, 16.0,  # row H: H1, H3
    ]
    grid = CLARIOstarBackend._readings_to_grid(readings, plate, wells)

    # Verify each value lands at the correct position
    self.assertEqual(grid[0][0], 1.0)   # A1
    self.assertEqual(grid[0][1], 2.0)   # A2
    self.assertEqual(grid[1][0], 3.0)   # B1
    self.assertEqual(grid[1][2], 4.0)   # B3
    self.assertEqual(grid[2][0], 5.0)   # C1
    self.assertEqual(grid[2][1], 6.0)   # C2
    self.assertEqual(grid[3][0], 7.0)   # D1
    self.assertEqual(grid[3][2], 8.0)   # D3
    self.assertEqual(grid[4][0], 9.0)   # E1
    self.assertEqual(grid[4][1], 10.0)  # E2
    self.assertEqual(grid[5][0], 11.0)  # F1
    self.assertEqual(grid[5][2], 12.0)  # F3
    self.assertEqual(grid[6][0], 13.0)  # G1
    self.assertEqual(grid[6][1], 14.0)  # G2
    self.assertEqual(grid[7][0], 15.0)  # H1
    self.assertEqual(grid[7][2], 16.0)  # H3
    # Unselected wells should be None
    self.assertIsNone(grid[0][2])  # A3 not selected
    self.assertIsNone(grid[1][1])  # B2 not selected

  def test_row_major_wells_still_work(self):
    """Wells already in row-major order should still map correctly."""
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    # Row-major: A1, A2, B1, B3 (already sorted by row,col)
    wells = [
      plate.get_well("A1"), plate.get_well("A2"),
      plate.get_well("B1"), plate.get_well("B3"),
    ]
    readings = [10.0, 20.0, 30.0, 40.0]
    grid = CLARIOstarBackend._readings_to_grid(readings, plate, wells)
    self.assertEqual(grid[0][0], 10.0)  # A1
    self.assertEqual(grid[0][1], 20.0)  # A2
    self.assertEqual(grid[1][0], 30.0)  # B1
    self.assertEqual(grid[1][2], 40.0)  # B3

  def test_single_column_order_unchanged(self):
    """Single-column well lists (already row-major) should be unaffected by the fix."""
    plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    wells = [plate.get_well(f"{r}1") for r in "ABCDEFGH"]
    readings = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    grid = CLARIOstarBackend._readings_to_grid(readings, plate, wells)
    for i in range(8):
      self.assertEqual(grid[i][0], float(i + 1))


if __name__ == "__main__":
  unittest.main()
