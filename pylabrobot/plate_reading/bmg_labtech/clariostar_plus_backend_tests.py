"""Tests for CLARIOstarPlusBackend.

Verifies that initialize, open, and close produce exactly the byte sequences
observed in pcap captures from real CLARIOstar Plus hardware.
Phase 4 adds absorbance measurement tests verified against pcap ground truth.
"""

import asyncio
import math
import unittest
import warnings
from typing import Dict, List

from pylabrobot.io.io import IOBase
from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import (
  _REFERENCE_BLOCK,
  _SEPARATOR,
  _TRAILER,
  CONFIRMED_FIRMWARE_VERSIONS,
  CLARIOstarPlusBackend,
  _extract_payload,
  _validate_frame,
  _wrap_payload,
)
from pylabrobot.resources.corning.plates import Cor_96_wellplate_360ul_Fb

# ---------------------------------------------------------------------------
# Pcap ground truth -- commands (verified against pcap captures)
#
# name → (payload bytes, expected wire frame).
# Adding an entry here automatically generates a frame-match test AND
# provides the single source of truth for all test classes via COMMANDS[name].
# ---------------------------------------------------------------------------

COMMANDS: Dict[str, tuple] = {
  # CF.INITIALIZE(0x01) + Cmd.INIT(0x00) + b"\x00\x10\x02\x00"
  "initialize": (
    b"\x01\x00\x00\x10\x02\x00",
    bytes.fromhex("02000e0c01000010020000002f0d"),
  ),
  # CF.TRAY(0x03) + Cmd.TRAY_OPEN(0x01) + b"\x00\x00\x00\x00"
  "open": (
    b"\x03\x01\x00\x00\x00\x00",
    bytes.fromhex("02000e0c0301000000000000200d"),
  ),
  # CF.TRAY(0x03) + Cmd.TRAY_CLOSE(0x00) + b"\x00\x00\x00\x00"
  "close": (
    b"\x03\x00\x00\x00\x00\x00",
    bytes.fromhex("02000e0c03000000000000001f0d"),
  ),
  # STATUS_QUERY (0x80), no command byte.
  "status": (
    b"\x80",
    bytes.fromhex("0200090c800000970d"),
  ),
  # CF.TEMPERATURE(0x06), no command byte. K01 pcap ground truth.
  "temp_off": (
    b"\x06\x00\x00",
    bytes.fromhex("02000b0c060000 00001f0d".replace(" ", "")),
  ),
  "temp_monitor": (
    b"\x06\x00\x01",
    bytes.fromhex("02000b0c060001 0000200d".replace(" ", "")),
  ),
  "temp_set_30c": (
    b"\x06\x01\x2c",
    bytes.fromhex("02000b0c06012c 00004c0d".replace(" ", "")),
  ),
  # CF.REQUEST(0x05) + Cmd.DATA(0x02) — standard variant. Pcap: A01 final frame.
  "get_data_standard": (
    b"\x05\x02\x00\x00\x00\x00\x00",
    bytes.fromhex("02000f0c050200000000000000240d"),
  ),
  # CF.REQUEST(0x05) + Cmd.DATA(0x02) — progressive variant. Pcap: A01 mid-measurement.
  "get_data_progressive": (
    b"\x05\x02\xff\xff\xff\xff\x00",
    bytes.fromhex("02000f0c0502ffffffff000004200d"),
  ),
  # CF.REQUEST(0x05) + Cmd.READ_ORDER(0x1D). Pcap: all measurement captures.
  "read_order": (
    b"\x05\x1d\x00\x00\x00\x00\x00",
    bytes.fromhex("02000f0c051d000000000000003f0d"),
  ),
}

# Generic command acknowledgement -- shared by all command tests.
ACK = _wrap_payload(b"\x00")

# ---------------------------------------------------------------------------
# Shared status response frames (pcap ground truth)
#
# Full wire frames (STX | size | 0x0C | payload | checksum | CR).
# Payload byte map (16 bytes):
#   0: response_type (0x01 = status)
#   1: status_flags (0x05 = not busy, 0x25 = busy)
#   3: device_state (0x20 = initialized, 0x21 = init+drawer_open,
#                    0x22 = init+plate_detected)
#   11-14: temperature sensors (big-endian)
#   15: byte15 (0xC0 typical)
# ---------------------------------------------------------------------------

# Initialized, not busy, drawer closed
STATUS_IDLE = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")
# Initialized, not busy, drawer open
STATUS_DRAWER_OPEN = bytes.fromhex("0200180c010500210000000000000000000000c000010d0d")
# Initialized, not busy, plate detected
STATUS_PLATE = bytes.fromhex("0200180c010500220000000000000000000000c000010e0d")
# Busy + initialized
STATUS_BUSY = bytes.fromhex("0200180c012500200000000000000000000000c000012c0d")


# ---------------------------------------------------------------------------
# Mock FTDI
# ---------------------------------------------------------------------------


class MockFTDI(IOBase):
  """Minimal FTDI mock that records writes and plays back queued responses.

  Delivers one queued frame per ``_read_frame`` invocation:
    - First ``read()`` after a ``write()`` or after an empty-read boundary
      delivers the next queued frame.
    - Subsequent ``read()`` calls return empty bytes, signalling end-of-frame
      to ``_read_frame`` and resetting the gate for the next frame.

  This supports both the normal one-frame-per-write pattern and the
  REQUEST status-then-data pattern where ``send_command`` calls
  ``_read_frame`` twice without an intervening ``write()``.
  """

  def __init__(self) -> None:
    self.written: List[bytes] = []
    self._responses: List[bytes] = []
    self._ready = False  # True = next read() may deliver a frame
    self.device_id: str = ""
    self.stop_called: bool = False

  def queue_response(self, *frames: bytes) -> None:
    """Queue one or more complete frames to return on subsequent reads."""
    self._responses.extend(frames)

  # -- FTDI interface methods used by the backend --

  async def setup(self) -> None:
    pass

  async def set_baudrate(self, baud: int) -> None:
    pass

  async def set_line_property(self, bits: int, stop: int, parity: int) -> None:
    pass

  async def set_latency_timer(self, ms: int) -> None:
    pass

  async def stop(self) -> None:
    self.stop_called = True

  async def write(self, data: bytes) -> int:
    self.written.append(bytes(data))
    self._ready = True
    return len(data)

  async def read(self, n: int) -> bytes:
    if self._ready and self._responses:
      self._ready = False
      return self._responses.pop(0)
    # Empty read = end-of-frame boundary. Re-arm for next _read_frame call.
    self._ready = True
    return b""


def _make_backend() -> CLARIOstarPlusBackend:
  """Create a backend with a MockFTDI injected (bypasses real USB)."""
  backend = CLARIOstarPlusBackend.__new__(CLARIOstarPlusBackend)
  backend.io = MockFTDI()  # type: ignore[assignment]
  backend.read_timeout = 5
  backend.configuration = {
    "serial_number": "",
    "firmware_version": "",
    "firmware_build_timestamp": "",
    "model_name": "",
    "machine_type_code": 0,
    "max_temperature": 45,
    "has_absorbance": False,
    "has_fluorescence": False,
    "has_luminescence": False,
    "has_alpha_technology": False,
    "excitation_monochromator_max_nm": 0,
    "emission_monochromator_max_nm": 0,
    "excitation_filter_slots": 0,
    "dichroic_filter_slots": 0,
    "emission_filter_slots": 0,
  }
  backend._target_temperature = None
  return backend


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFrameUtilities(unittest.TestCase):
  """Verify the frame wrap / validate / extract round-trip."""

  def test_round_trip(self):
    payload = COMMANDS["initialize"][0]
    frame = _wrap_payload(payload)
    _validate_frame(frame)
    self.assertEqual(_extract_payload(frame), payload)


# Auto-generate a frame-match test for every COMMANDS entry.
def _make_frame_test(name, payload, expected_frame):
  def test(self):
    frame = _wrap_payload(payload)
    self.assertEqual(
      frame,
      expected_frame,
      f"frame mismatch for {name!r}: got {frame.hex()}, expected {expected_frame.hex()}",
    )

  test.__doc__ = f"_wrap_payload must match pcap ground truth for {name!r}"
  return test


for _name, (_payload, _frame) in COMMANDS.items():
  setattr(
    TestFrameUtilities,
    f"test_{_name}_frame_matches_ground_truth",
    _make_frame_test(_name, _payload, _frame),
  )
del _name, _payload, _frame


class TestInitialize(unittest.TestCase):
  """Pcap ground truth for initialize command and its status response."""

  def test_initialize_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, STATUS_IDLE)
    asyncio.run(backend.initialize())

    self.assertEqual(mock.written[0], COMMANDS["initialize"][1])

  def test_initialize_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, STATUS_IDLE)
    asyncio.run(backend.initialize())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], COMMANDS["status"][1])


class TestOpen(unittest.TestCase):
  """Pcap ground truth for drawer-open command and its status response."""

  def test_open_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, STATUS_DRAWER_OPEN)
    asyncio.run(backend.open())

    self.assertEqual(mock.written[0], COMMANDS["open"][1])

  def test_open_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, STATUS_DRAWER_OPEN)
    asyncio.run(backend.open())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], COMMANDS["status"][1])


class TestClose(unittest.TestCase):
  """Pcap ground truth for drawer-close command and its status response."""

  def test_close_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, STATUS_IDLE)
    asyncio.run(backend.close())

    self.assertEqual(mock.written[0], COMMANDS["close"][1])

  def test_close_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, STATUS_IDLE)
    asyncio.run(backend.close())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], COMMANDS["status"][1])


class TestStatusPollResilience(unittest.TestCase):
  """Verify that _wait_until_machine_ready survives partial/corrupt frames."""

  # Corrupt status -- correct size field (16 bytes) but bad checksum.
  # _read_frame completes normally; _validate_frame raises ChecksumError.
  CORRUPT = bytes.fromhex("0200100c0115000000c90000dead000d")

  def test_recovers_from_partial_frame(self):
    """A truncated status response should be retried, not crash."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.CORRUPT, STATUS_IDLE)
    asyncio.run(backend.initialize())

    # Should have written: init command, status poll (failed), status poll (success)
    self.assertEqual(len(mock.written), 3)
    self.assertEqual(mock.written[0], COMMANDS["initialize"][1])
    self.assertEqual(mock.written[1], COMMANDS["status"][1])
    self.assertEqual(mock.written[2], COMMANDS["status"][1])

  def test_recovers_from_empty_frame(self):
    """An empty response should be retried."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, b"", STATUS_DRAWER_OPEN)
    asyncio.run(backend.open())

    self.assertEqual(mock.written[0], COMMANDS["open"][1])


class TestStatusParsing(unittest.TestCase):
  def test_initialized_flag(self):
    # byte 3, bit 5 = 0x20
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x20\x00")
    self.assertTrue(flags["initialized"])
    self.assertFalse(flags["busy"])
    self.assertFalse(flags["drawer_open"])

  def test_busy_flag(self):
    # byte 1, bit 5 = 0x20
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x20\x00\x00\x00")
    self.assertTrue(flags["busy"])
    self.assertFalse(flags["initialized"])

  def test_drawer_open_flag(self):
    # byte 3, bit 0 = 0x01
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x01\x00")
    self.assertTrue(flags["drawer_open"])
    self.assertFalse(flags["initialized"])

  def test_plate_detected_flag(self):
    # byte 3, bit 1 = 0x02
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x02\x00")
    self.assertTrue(flags["plate_detected"])

  def test_reading_wells_flag(self):
    # byte 3, bit 3 = 0x08
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x08\x00")
    self.assertTrue(flags["reading_wells"])
    self.assertFalse(flags["initialized"])

  def test_reading_wells_with_busy_and_initialized(self):
    # Real pcap pattern: busy (byte 1: 0x20) + initialized + reading_wells (byte 3: 0x28)
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x20\x00\x28\x00")
    self.assertTrue(flags["busy"])
    self.assertTrue(flags["initialized"])
    self.assertTrue(flags["reading_wells"])
    self.assertFalse(flags["drawer_open"])

  def test_combined_flags(self):
    # initialized + drawer_open + plate_detected = byte 3: 0x20 | 0x01 | 0x02 = 0x23
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x23\x00")
    self.assertTrue(flags["initialized"])
    self.assertTrue(flags["drawer_open"])
    self.assertTrue(flags["plate_detected"])
    self.assertFalse(flags["busy"])
    self.assertFalse(flags["reading_wells"])

  def test_valid_flag(self):
    # byte 1, bit 0 = 0x01
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x01\x00\x00\x00")
    self.assertTrue(flags["valid"])
    self.assertFalse(flags["busy"])

  def test_lid_open_flag(self):
    # byte 3, bit 6 = 0x40
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x40\x00")
    self.assertTrue(flags["lid_open"])
    self.assertFalse(flags["initialized"])

  def test_z_probed_flag(self):
    # byte 3, bit 2 = 0x04
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x04\x00")
    self.assertTrue(flags["z_probed"])
    self.assertFalse(flags["drawer_open"])

  def test_filter_cover_open_flag(self):
    # byte 4, bit 6 = 0x40
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x00\x40")
    self.assertTrue(flags["filter_cover_open"])
    self.assertFalse(flags["busy"])

  def test_standby_flag(self):
    # byte 0, bit 1 = 0x02
    flags = CLARIOstarPlusBackend._parse_status(b"\x02\x00\x00\x00\x00")
    self.assertTrue(flags["standby"])
    self.assertFalse(flags["busy"])

  def test_running_flag(self):
    # byte 1, bit 4 = 0x10
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x10\x00\x00\x00")
    self.assertTrue(flags["running"])
    self.assertFalse(flags["busy"])

  def test_unread_data_flag(self):
    # byte 2, bit 0 = 0x01
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x01\x00\x00")
    self.assertTrue(flags["unread_data"])
    self.assertFalse(flags["busy"])

  def test_all_flags_present_in_result(self):
    """All 12 status flags must appear as keys in the parsed dict."""
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x00\x00")
    expected_keys = {
      "standby",
      "valid",
      "busy",
      "running",
      "unread_data",
      "lid_open",
      "initialized",
      "reading_wells",
      "z_probed",
      "plate_detected",
      "drawer_open",
      "filter_cover_open",
    }
    self.assertEqual(set(flags.keys()), expected_keys)

  def test_all_flags_set(self):
    """All 12 flags True when every relevant bit is set."""
    # byte 0: bit 1 (standby)
    # byte 1: bits 5,4,0 (busy, running, valid)
    # byte 2: bit 0 (unread_data)
    # byte 3: bits 6,5,3,2,1,0 (lid_open, initialized, reading_wells, z_probed, plate_detected, drawer_open)
    # byte 4: bit 6 (filter_cover_open)
    flags = CLARIOstarPlusBackend._parse_status(b"\x02\x31\x01\x6f\x40")
    for name, value in flags.items():
      self.assertTrue(value, f"{name} should be True")


class TestUsageCounters(unittest.TestCase):
  """Verify request_usage_counters parses a synthetic 43-byte response."""

  def test_parses_usage_counters(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # Build a 43-byte payload:
    #   bytes 0-5: echo/header (don't care for parsing)
    #   bytes 6-41: nine uint32 BE fields
    #   byte 42: trailing padding
    payload = bytearray(43)
    # flashes = 1000 at offset 6
    payload[6:10] = (1000).to_bytes(4, "big")
    # testruns = 50 at offset 10
    payload[10:14] = (50).to_bytes(4, "big")
    # wells = 200 at offset 14 (firmware stores /100, so 200 → 20000)
    payload[14:18] = (200).to_bytes(4, "big")
    # well_movements = 300 at offset 18 (firmware stores /100, so 300 → 30000)
    payload[18:22] = (300).to_bytes(4, "big")
    # active_time_s = 86400 at offset 22
    payload[22:26] = (86400).to_bytes(4, "big")
    # shake_time_s = 3600 at offset 26
    payload[26:30] = (3600).to_bytes(4, "big")
    # pump1_usage = 42 at offset 30
    payload[30:34] = (42).to_bytes(4, "big")
    # pump2_usage = 7 at offset 34
    payload[34:38] = (7).to_bytes(4, "big")
    # alpha_time = 999 at offset 38
    payload[38:42] = (999).to_bytes(4, "big")

    response_frame = _wrap_payload(bytes(payload))
    mock.queue_response(response_frame)

    counters = asyncio.run(backend.request_usage_counters())

    self.assertEqual(counters["flashes"], 1000)
    self.assertEqual(counters["testruns"], 50)
    self.assertEqual(counters["wells"], 20000)
    self.assertEqual(counters["well_movements"], 30000)
    self.assertEqual(counters["active_time_s"], 86400)
    self.assertEqual(counters["shake_time_s"], 3600)
    self.assertEqual(counters["pump1_usage"], 42)
    self.assertEqual(counters["pump2_usage"], 7)
    self.assertEqual(counters["alpha_time"], 999)


class TestConvenienceStatusQueries(unittest.TestCase):
  """Verify sense_plate_present, is_ready, and sense_drawer_open delegate to status."""

  def test_sense_drawer_open_true(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(STATUS_DRAWER_OPEN)
    self.assertTrue(asyncio.run(backend.sense_drawer_open()))

  def test_sense_drawer_open_false(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(STATUS_IDLE)  # drawer closed = same as idle
    self.assertFalse(asyncio.run(backend.sense_drawer_open()))

  def test_sense_plate_present_true(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(STATUS_PLATE)
    self.assertTrue(asyncio.run(backend.sense_plate_present()))

  def test_sense_plate_present_false(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(STATUS_IDLE)
    self.assertFalse(asyncio.run(backend.sense_plate_present()))

  def test_is_ready_false_when_busy(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(STATUS_BUSY)
    self.assertFalse(asyncio.run(backend.is_ready()))

  def test_is_ready_true_when_idle(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(STATUS_IDLE)
    self.assertTrue(asyncio.run(backend.is_ready()))


# ---------------------------------------------------------------------------
# Real hardware captures (from CLARIOstar Plus)
#
# Stored as complete wire frames (STX | size | 0x0C | payload | checksum | CR)
# so tests exercise _validate_frame + _extract_payload on fixed bytes rather
# than re-wrapping payloads with _wrap_payload (which would mask framing bugs).
# ---------------------------------------------------------------------------

# 271-byte wire frame for EEPROM response (command 0x05 0x07, 263-byte payload).
# Source: real capture from CLARIOstar Plus (2026-02-24), verified identical
# across two reads in the same session.
# Byte map: see request_eeprom_data() docstring in clariostar_plus_backend.py.
_REAL_EEPROM_FRAME = bytes.fromhex(  # noqa: E501
  "02010f0c070500240000000100000a0101010100000100ee0200000f00e2030000000000000304000001000001020000000000000000000032000000000000000000000000000000000000000074006f0000000000000065000000dc050000000000000000f4010803a70408076009da08ac0d0000000000000000000000000000000000000000000000000100000001010000000000000001010000000000000012029806ae013d0a4605ee01fbff700c00000000a40058ff8e03f20460ff5511fe0b55118f1a170298065aff970668042603bc14b804080791009001463228460a0046071e0000000000000000002103d40628002c01900146001e00001411001209ac0d6009000000000020260d"
)

# 39-byte wire frame for firmware info response (command 0x05 0x09, 31-byte payload).
# Source: real capture from CLARIOstar Plus (2026-02-24).
# Payload byte map:
#   0:     response_type (0x0a = subcommand 0x09 + 1)
#   1:     status_flags (0x05 = not busy, standby)
#   2-3:   machine type code (0x0024)
#   4-5:   unknown (0x0000)
#   6-7:   firmware version x 1000 (0x0546 = 1350 → "1.35")
#   8-19:  build date "Nov 20 2020\0"
#   20-27: build time "11:51:21\0"
#   28-30: unknown
_REAL_FIRMWARE_FRAME = bytes.fromhex(
  "0200270c0a050024000005464e6f7620323020323032300031313a35313a32310000010004ec0d"
)


class TestFirmwareInfoParsing(unittest.TestCase):
  """Verify firmware info parsing with real hardware capture data."""

  def test_parse_real_firmware(self):
    """Parse the real 32-byte firmware payload via mock backend."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_REAL_FIRMWARE_FRAME)

    fw = asyncio.run(backend.request_firmware_info())
    self.assertEqual(fw["firmware_version"], "1.35")
    self.assertEqual(fw["firmware_build_timestamp"], "Nov 20 2020 11:51:21")

  def test_parse_firmware_too_short(self):
    """Payload shorter than 28 bytes returns empty defaults."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_wrap_payload(b"\x0a\x05\x00\x24\x00\x00"))

    fw = asyncio.run(backend.request_firmware_info())
    self.assertEqual(fw["firmware_version"], "")
    self.assertEqual(fw["firmware_build_timestamp"], "")

  def test_stores_into_configuration(self):
    """request_firmware_info result merges into configuration via update()."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_REAL_FIRMWARE_FRAME)

    fw = asyncio.run(backend.request_firmware_info())
    backend.configuration.update(fw)

    self.assertEqual(backend.configuration["firmware_version"], "1.35")
    self.assertEqual(backend.configuration["firmware_build_timestamp"], "Nov 20 2020 11:51:21")


class TestEepromParsing(unittest.TestCase):
  """Verify EEPROM parsing with real hardware capture data."""

  def test_parse_real_eeprom(self):
    """Parse the real 263-byte EEPROM payload."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_REAL_EEPROM_FRAME)

    eeprom = asyncio.run(backend.request_eeprom_data())

    self.assertEqual(eeprom["machine_type_code"], 0x0024)
    self.assertEqual(eeprom["model_name"], "CLARIOstar Plus")
    self.assertTrue(eeprom["has_absorbance"])
    self.assertTrue(eeprom["has_fluorescence"])
    self.assertTrue(eeprom["has_luminescence"])
    self.assertTrue(eeprom["has_alpha_technology"])
    self.assertEqual(eeprom["excitation_monochromator_max_nm"], 750)
    self.assertEqual(eeprom["emission_monochromator_max_nm"], 994)
    self.assertEqual(eeprom["dichroic_filter_slots"], 3)
    self.assertEqual(eeprom["excitation_filter_slots"], 4)
    self.assertEqual(eeprom["emission_filter_slots"], 4)

  def test_parse_eeprom_too_short(self):
    """Payload shorter than 15 bytes returns defaults."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_wrap_payload(b"\x07\x05\x00\x24"))

    eeprom = asyncio.run(backend.request_eeprom_data())

    self.assertEqual(eeprom["machine_type_code"], 0)
    self.assertFalse(eeprom["has_absorbance"])
    self.assertEqual(eeprom["excitation_monochromator_max_nm"], 0)

  def test_parse_eeprom_short_skips_optics(self):
    """Payload with 15-34 bytes parses detection flags but not optics."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # 20 bytes: enough for detection flags (bytes 11-14) but not optics (bytes 19+)
    payload = _extract_payload(_REAL_EEPROM_FRAME)[:20]
    mock.queue_response(_wrap_payload(payload))

    eeprom = asyncio.run(backend.request_eeprom_data())

    self.assertEqual(eeprom["machine_type_code"], 0x0024)
    self.assertTrue(eeprom["has_absorbance"])
    self.assertEqual(eeprom["excitation_monochromator_max_nm"], 0)
    self.assertEqual(eeprom["dichroic_filter_slots"], 0)

  def test_stores_into_configuration(self):
    """request_eeprom_data result merges into configuration via update()."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_REAL_EEPROM_FRAME)

    eeprom = asyncio.run(backend.request_eeprom_data())
    backend.configuration.update(eeprom)

    self.assertEqual(backend.configuration["excitation_monochromator_max_nm"], 750)
    self.assertEqual(backend.configuration["emission_monochromator_max_nm"], 994)
    self.assertEqual(backend.configuration["model_name"], "CLARIOstar Plus")

  def test_unknown_machine_type(self):
    """Unknown machine type code produces a descriptive model name."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # Change bytes 2-3 from 0x0024 to 0x00FF
    payload = bytearray(_extract_payload(_REAL_EEPROM_FRAME))
    payload[2:4] = b"\x00\xff"
    mock.queue_response(_wrap_payload(bytes(payload)))

    eeprom = asyncio.run(backend.request_eeprom_data())

    self.assertEqual(eeprom["machine_type_code"], 0x00FF)
    self.assertIn("0x00ff", eeprom["model_name"])


class TestAvailableDetectionModes(unittest.TestCase):
  """Verify request_available_detection_modes fetches EEPROM and derives modes."""

  def test_all_modes(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_REAL_EEPROM_FRAME)
    modes = asyncio.run(backend.request_available_detection_modes())
    self.assertEqual(
      modes,
      ["absorbance", "absorbance_spectrum", "fluorescence", "luminescence", "alpha_technology"],
    )

  def test_partial_modes(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # Build EEPROM payload with absorbance + luminescence but no fluorescence/alpha.
    payload = bytearray(_extract_payload(_REAL_EEPROM_FRAME))
    payload[12] = 0x00  # has_fluorescence = False
    payload[14] = 0x00  # has_alpha_technology = False
    mock.queue_response(_wrap_payload(bytes(payload)))
    modes = asyncio.run(backend.request_available_detection_modes())
    self.assertEqual(modes, ["absorbance", "absorbance_spectrum", "luminescence"])

  def test_no_eeprom(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # Short payload → all detection flags default to False.
    mock.queue_response(_wrap_payload(b"\x07\x05\x00\x24"))
    modes = asyncio.run(backend.request_available_detection_modes())
    self.assertEqual(modes, [])


class TestTemperature(unittest.TestCase):
  """Verify temperature commands use standard framing (K01 pcap ground truth)."""

  def test_stop_control_downgrades_to_monitor(self):
    """stop_temperature_control sends MONITOR (0x0001), not OFF."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK)
    asyncio.run(backend.stop_temperature_control())

    self.assertEqual(mock.written[0], COMMANDS["temp_monitor"][1])

  def test_stop_monitoring_sends_off(self):
    """_stop_temperature_monitoring sends OFF (0x0000)."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK)
    asyncio.run(backend._stop_temperature_monitoring())

    self.assertEqual(mock.written[0], COMMANDS["temp_off"][1])

  def test_monitor_sends_correct_frame(self):
    """_start_temperature_monitoring sends MONITOR unconditionally."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK)
    asyncio.run(backend._start_temperature_monitoring())

    self.assertEqual(len(mock.written), 1)
    self.assertEqual(mock.written[0], COMMANDS["temp_monitor"][1])

  def test_start_set_30c(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # measure_temperature inside start_temperature_control:
    #   1. _request_temperature_monitoring_on -> status poll (sensors inactive)
    #   2. _start_temperature_monitoring -> sends MONITOR -> ack
    #   3. measure loop -> status with temps (22°C room temp)
    # Then the SET command itself -> ack.
    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(220, 225),  # measure_temperature poll
      ACK,  # SET command ack
    )
    asyncio.run(backend.start_temperature_control(temperature=30.0))

    self.assertEqual(mock.written[-1], COMMANDS["temp_set_30c"][1])

  def test_start_set_37c(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(220, 225),  # measure_temperature poll
      ACK,  # SET command ack
    )
    asyncio.run(backend.start_temperature_control(temperature=37.0))

    # 37.0°C = 370 = 0x0172
    expected = _wrap_payload(b"\x06\x01\x72")
    self.assertEqual(mock.written[-1], expected)

  def test_start_set_25c(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(220, 225),  # measure_temperature poll
      ACK,  # SET command ack
    )
    asyncio.run(backend.start_temperature_control(temperature=25.0))

    # 25.0°C = 250 = 0x00FA
    expected = _wrap_payload(b"\x06\x00\xfa")
    self.assertEqual(mock.written[-1], expected)

  def test_start_rejects_above_max(self):
    backend = _make_backend()
    with self.assertRaises(ValueError):
      asyncio.run(backend.start_temperature_control(temperature=50.0))

  @staticmethod
  def _make_temp_response(bottom_raw: int, top_raw: int, byte15: int = 0xC0) -> bytes:
    """Build a standard framed response with temperature at payload bytes 11-14."""
    payload = bytearray(16)
    payload[11:13] = bottom_raw.to_bytes(2, "big")
    payload[13:15] = top_raw.to_bytes(2, "big")
    payload[15] = byte15
    return _wrap_payload(bytes(payload))

  def test_measure_temperature_bottom(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # measure_temperature flow:
    #   1. _request_temperature_monitoring_on() -> status poll (sensors inactive)
    #   2. _start_temperature_monitoring() -> sends MONITOR -> ack
    #   3. measure_temperature poll -> status(populated)
    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor command ack
      self._make_temp_response(370, 375),  # measure_temperature poll
    )
    temp = asyncio.run(backend.measure_temperature(sensor="bottom"))
    self.assertAlmostEqual(temp, 37.0)
    self.assertEqual(mock.written[0], COMMANDS["status"][1])
    self.assertEqual(mock.written[1], COMMANDS["temp_monitor"][1])
    self.assertEqual(mock.written[2], COMMANDS["status"][1])

  def test_measure_temperature_top(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(370, 375),  # measure_temperature poll
    )
    temp = asyncio.run(backend.measure_temperature(sensor="top"))
    self.assertAlmostEqual(temp, 37.5)

  def test_measure_temperature_mean(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(370, 375),  # measure_temperature poll
    )
    temp = asyncio.run(backend.measure_temperature(sensor="mean"))
    self.assertAlmostEqual(temp, 37.2)  # round((37.0 + 37.5) / 2, 1)

  def test_measure_temperature_sensors_already_active(self):
    """When sensors are already reporting (e.g. heating active), no monitor cmd is sent."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # _request_temperature_monitoring_on -> True -> skip _start_temperature_monitoring.
    # measure_temperature poll -> gets temps -> returns.
    mock.queue_response(
      self._make_temp_response(300, 305),  # monitoring check (sensors active)
      self._make_temp_response(300, 305),  # measure_temperature poll
    )
    temp = asyncio.run(backend.measure_temperature(sensor="bottom"))
    self.assertAlmostEqual(temp, 30.0)
    # Two status polls, no monitor command sent.
    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[0], COMMANDS["status"][1])
    self.assertEqual(mock.written[1], COMMANDS["status"][1])

  def test_measure_temperature_retries_until_populated(self):
    """Sensor takes time to populate after monitor command."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # measure_temperature flow:
    #   1. _request_temperature_monitoring_on() -> status poll (inactive)
    #   2. _start_temperature_monitoring() -> sends MONITOR -> ack
    #   3. measure loop: status(zeros still) -> status(populated)
    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(0, 0),  # still not ready
      self._make_temp_response(291, 296),  # populated
    )
    temp = asyncio.run(backend.measure_temperature(sensor="bottom"))
    self.assertAlmostEqual(temp, 29.1)

  def test_status_temperature_none_when_inactive(self):
    """request_machine_status returns None temperatures when monitoring is off."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(self._make_temp_response(0, 0))
    status = asyncio.run(backend.request_machine_status())
    self.assertIsNone(status["temperature_bottom"])
    self.assertIsNone(status["temperature_top"])

  def test_status_dict_has_no_heating_active(self):
    """Status dict must not contain a heating_active key."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self._make_temp_response(228, 232))
    status = asyncio.run(backend.request_machine_status())
    self.assertNotIn("heating_active", status)

  def test_get_target_temperature_none_at_boot(self):
    """Before any temperature command, get_target_temperature returns None."""
    backend = _make_backend()
    self.assertIsNone(backend.get_target_temperature())

  def test_get_target_temperature_after_set(self):
    """After start_temperature_control(37.0), get_target_temperature returns 37.0."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(220, 225),  # measure_temperature poll
      ACK,  # SET command ack
    )
    asyncio.run(backend.start_temperature_control(37.0))
    self.assertEqual(backend.get_target_temperature(), 37.0)

  def test_get_target_temperature_none_after_stop_control(self):
    """After stop_temperature_control, get_target_temperature returns None."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(
      self._make_temp_response(0, 0),  # measure_temperature monitoring check
      ACK,  # monitor ack
      self._make_temp_response(220, 225),  # measure_temperature poll
      ACK,  # SET ack
      ACK,  # stop_temperature_control (MONITOR) ack
    )
    asyncio.run(backend.start_temperature_control(37.0))
    asyncio.run(backend.stop_temperature_control())
    self.assertIsNone(backend.get_target_temperature())


# ---------------------------------------------------------------------------
# Phase 4: Absorbance measurement tests
# ---------------------------------------------------------------------------

# Ground truth hex from pcap CSV (raw_command_hex_captured).
# These are FULL wire frames including STX, size, header, checksum, CR.
_GT_HEX = {
  "A01": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000008a02000000000000000000000000000000000000000000000000000000000000270f270f0501177000000064232826ca0000006400000000020000000000010000000100050001000013780d",
  "A02": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000008a32000000000000000000000000000000000000000000000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000014480d",
  "A03": "0200900c0431e82164059e04642c4a1d000c08008008008008008008008008000000000000000000000000000000000000000000000000000000000000000000000000008a02000000000000000000000000000000000000000000000000000000000000270f270f0501177000000064232826ca0000006400000000020000000000010000000100050001000009a40d",
  "A05": "0200900c0431e82164059e04642c4a1d000c08008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a02000000000000000000000000000000000000000000000000000000000000270f270f0501177000000064232826ca0000006400000000020000000000010000000100050001000008040d",
  "A07": "0200900c0431e82164059e04642c4a1d000c0800fc0fc0fc0fc0fc0fc0fc0fc00000000000000000000000000000000000000000000000000000000000000000000000008a02000000000000000000000000000000000000000000000000000000000000270f270f0501177000000064232826ca000000640000000002000000000001000000010005000100000eb00d",
  "A08": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000000000000000000000000000000000000000000270f270f02030292000101177000000064232826ca000000640000000002000000000001000000010007000100000dca0d",
  "B01": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000008a06000000000000000000000000000000000000000000000000000000000000270f270f02040292000101177000000064232826ca00000064000000000200000000000100000001000f0001000014210d",
  "B02": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000008a06000000000000000000000000000000000000000000000000000000000000270f270f02030292000101177000000064232826ca00000064000000000200000000000100000001000f0001000014200d",
  "C01": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000002a02000000000000000000000000000000000000000000000000000000000000270f270f0101177000000064232826ca0000006400000000020000000000010000000100010001000013100d",
  "C02": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000004a02000000000000000000000000000000000000000000000000000000000000270f270f0101177000000064232826ca0000006400000000020000000000010000000100010001000013300d",
  "C03": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000006a02000000000000000000000000000000000000000000000000000000000000270f270f0101177000000064232826ca0000006400000000020000000000010000000100010001000013500d",
  "C04": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000008a02000000000000000000000000000000000000000000000000000000000000270f270f0101177000000064232826ca0000006400000000020000000000010000000100010001000013700d",
  "C05": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000202000000000000000000000000000000000000000000000000000000000000270f270f0101177000000064232826ca0000006400000000020000000000010000000100010001000012e80d",
  "D01": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a02000000000000000000000000000000000000000000000000000000000000270f270f0101119400000064232826ca00000064000000000200000000000100000001000100010000130e0d",
  "D02": "0200920c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a02000000000000000000000000000000000000000000000000000000000000270f270f01021194177000000064232826ca0000006400000000020000000000010000000100010001000013980d",
  "D03": "0200940c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a02000000000000000000000000000000000000000000000000000000000000270f270f01031194177019c800000064232826ca00000064000000000200000000000100000001000100010000147c0d",
  "F01": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000002000500000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000013d10d",
  "F04": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000202000500000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000013d30d",
  "F02": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000004000500000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000013d30d",
  "F03": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000002000a00000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000013d60d",
  "F05": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000102000500000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000013d20d",
  "F06": "0200950c0431e82164059e04642c4a1d000c08008008008008008008008008000000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000002000500000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000009fd0d",
  # G-series: shake + settling time variations
  "G01": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000002000500000000000000000000270f270f020302920019011770000000642328 26ca0000006400000000020000000000010000000100070001000013e50d".replace(
    " ", ""
  ),
  "G02": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000002000000000002000500000000000000000000270f270f02030292000501177000000064232826ca0000006400000000020000000000010000000100070001000013d10d",
}


def _make_plate():
  """Create a Cor_96_wellplate_360ul_Fb plate for testing."""
  return Cor_96_wellplate_360ul_Fb("test_plate")


def _build_synthetic_response(
  num_wells: int = 96,
  num_wavelengths: int = 1,
  schema: int = 0xA9,
  sample_values: List[int] = None,
  ref_values: List[int] = None,
  cal_pairs: List[tuple] = None,
) -> bytes:
  """Build a synthetic absorbance response payload.

  Uses a simplified layout with all WL samples in group0 (unlike real hardware
  which uses wl_resp=1 and extra groups for additional WLs). The dynamic group
  detection in _parse_absorbance_response handles both layouts correctly.
  Real device behavior is validated by test_pcap_D02/D03 ground truth tests.

  Structure:
    Header (36 bytes) + Group0 (sample × WLs) + Group1 (chrom2) + Group2 (chrom3)
    + Group3 (ref) + Calibration (32 bytes)
  """
  if sample_values is None:
    sample_values = [3_000_000] * (num_wells * num_wavelengths)
  if ref_values is None:
    ref_values = [1_300_000] * num_wells
  if cal_pairs is None:
    cal_pairs = [
      (3_932_985, 596217),  # chromatic 1 (sample)
      (1_537_345, 594949),  # chromatic 2
      (733_492, 594217),  # chromatic 3
      (18317, 0),  # reference
    ]

  num_groups = num_wavelengths + 3  # WL sample groups + chrom2 + chrom3 + reference
  total_values = num_wells * num_groups + num_groups * 2  # groups × wells + cal pairs × 2
  header = bytearray(36)
  header[0] = 0x02  # response_type (echoes DATA subcommand)
  header[1] = 0x05  # status_flags (not busy, standby)
  header[6] = schema
  header[7:9] = total_values.to_bytes(2, "big")
  header[9:11] = total_values.to_bytes(2, "big")  # values_written = expected (complete)
  header[18:20] = num_wavelengths.to_bytes(2, "big")
  header[20:22] = num_wells.to_bytes(2, "big")

  payload = bytearray(header)
  for v in sample_values:
    payload.extend(v.to_bytes(4, "big"))
  for _ in range(num_wells):
    payload.extend((1_300_000).to_bytes(4, "big"))
  for _ in range(num_wells):
    payload.extend((600_000).to_bytes(4, "big"))
  for v in ref_values:
    payload.extend(v.to_bytes(4, "big"))
  for hi, lo in cal_pairs:
    payload.extend(hi.to_bytes(4, "big"))
    payload.extend(lo.to_bytes(4, "big"))

  return bytes(payload)


# ===========================================================================
# Common Reading Preparations
# ===========================================================================
# Test order follows backend method order:
#   _plate_field → _scan_direction_byte → _pre_separator_block →
#   _well_scan_field → _map_readings_to_plate_grid → _request_measurement_data →
#   _measurement_progress


class TestPlateField(unittest.TestCase):
  """Verify _plate_field well mask encoding against pcap ground truth."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()

  def test_all_96_wells_mask(self):
    """All 96 wells → first 12 bytes = 0xFF, rest = 0x00."""
    wells = self.plate.get_all_items()
    field = self.backend._plate_field(self.plate, wells)
    mask = field[15:63]
    self.assertEqual(mask[:12], b"\xff" * 12)
    self.assertEqual(mask[12:], b"\x00" * 36)

  def test_single_well_A1_mask(self):
    """Well A1 only → first byte = 0x80, rest = 0x00."""
    wells = [self.plate.get_item("A1")]
    field = self.backend._plate_field(self.plate, wells)
    mask = field[15:63]
    self.assertEqual(mask[0], 0x80)
    self.assertEqual(mask[1:], b"\x00" * 47)

  def test_column1_mask(self):
    """Column 1 (A1,B1,...,H1) → matches pcap 80 08 00 80 08 00 80 08 00 80 08 00."""
    wells = self.plate.get_items("A1:H1")
    field = self.backend._plate_field(self.plate, wells)
    mask = field[15:63]
    expected_mask_start = bytes.fromhex("800800800800800800800800")
    self.assertEqual(mask[:12], expected_mask_start)
    self.assertEqual(mask[12:], b"\x00" * 36)

  def test_plate_geometry_bytes(self):
    """Verify plate geometry encoding (sizes and well positions)."""
    wells = self.plate.get_all_items()
    field = self.backend._plate_field(self.plate, wells)
    self.assertEqual(len(field), 63)
    # Plate dimensions match PLR plate definition
    plate_len = int.from_bytes(field[0:2], "big")
    plate_wid = int.from_bytes(field[2:4], "big")
    self.assertEqual(plate_len, 12776)  # 127.76mm * 100
    self.assertEqual(plate_wid, 8548)  # 85.48mm * 100
    self.assertEqual(field[12], 12)  # columns
    self.assertEqual(field[13], 8)  # rows
    self.assertEqual(field[14], 0x00)  # extra byte


class TestScanDirectionByte(unittest.TestCase):
  """Verify _scan_direction_byte against all 6 known pcap values."""

  def test_uni_tl_vert(self):
    self.assertEqual(CLARIOstarPlusBackend._scan_direction_byte(True, True, "TL"), 0x8A)

  def test_bidi_tl_vert(self):
    self.assertEqual(CLARIOstarPlusBackend._scan_direction_byte(False, True, "TL"), 0x0A)

  def test_tr(self):
    self.assertEqual(CLARIOstarPlusBackend._scan_direction_byte(False, True, "TR"), 0x2A)

  def test_bl(self):
    self.assertEqual(CLARIOstarPlusBackend._scan_direction_byte(False, True, "BL"), 0x4A)

  def test_br(self):
    self.assertEqual(CLARIOstarPlusBackend._scan_direction_byte(False, True, "BR"), 0x6A)

  def test_horizontal(self):
    self.assertEqual(CLARIOstarPlusBackend._scan_direction_byte(False, False, "TL"), 0x02)


class TestPreSeparatorBlock(unittest.TestCase):
  """Verify _pre_separator_block for different scan and shake modes."""

  ABS = CLARIOstarPlusBackend.Modality.ABSORBANCE
  POINT = CLARIOstarPlusBackend.WellScanMode.POINT
  ORBITAL = CLARIOstarPlusBackend.WellScanMode.ORBITAL
  SPIRAL = CLARIOstarPlusBackend.WellScanMode.SPIRAL

  def test_point_no_shake(self):
    block = CLARIOstarPlusBackend._pre_separator_block(self.ABS, self.POINT)
    self.assertEqual(len(block), 31)
    self.assertEqual(block[0], 0x02)  # ABSORBANCE | POINT
    self.assertEqual(block[12], 0x00)  # no shaking

  def test_orbital_no_shake(self):
    block = CLARIOstarPlusBackend._pre_separator_block(self.ABS, self.ORBITAL)
    self.assertEqual(len(block), 31)
    self.assertEqual(block[0], 0x32)  # ABSORBANCE | ORBITAL

  def test_spiral_no_shake(self):
    block = CLARIOstarPlusBackend._pre_separator_block(self.ABS, self.SPIRAL)
    self.assertEqual(len(block), 31)
    self.assertEqual(block[0], 0x06)  # ABSORBANCE | SPIRAL

  def test_orbital_with_orbital_shake(self):
    block = CLARIOstarPlusBackend._pre_separator_block(
      self.ABS, self.ORBITAL, shake_mode="orbital", shake_speed_rpm=300, shake_duration_s=5
    )
    self.assertEqual(block[0], 0x32)
    self.assertEqual(block[12], 0x02)  # mixer_action
    self.assertEqual(block[17], 0x00)  # shake_pattern: orbital
    self.assertEqual(block[18], 0x02)  # speed_idx: (300/100)-1 = 2
    self.assertEqual(int.from_bytes(block[20:22], "little"), 5)  # duration 5s

  def test_linear_shake(self):
    block = CLARIOstarPlusBackend._pre_separator_block(
      self.ABS, self.ORBITAL, shake_mode="linear", shake_speed_rpm=300, shake_duration_s=5
    )
    self.assertEqual(block[17], 0x01)  # shake_pattern: linear

  def test_double_orbital_shake(self):
    block = CLARIOstarPlusBackend._pre_separator_block(
      self.ABS, self.ORBITAL, shake_mode="double_orbital", shake_speed_rpm=300, shake_duration_s=5
    )
    self.assertEqual(block[17], 0x02)  # shake_pattern: double_orbital


class TestWellScanField(unittest.TestCase):
  """Verify _well_scan_field for point vs orbital/spiral."""

  ABS = CLARIOstarPlusBackend.Modality.ABSORBANCE
  POINT = CLARIOstarPlusBackend.WellScanMode.POINT
  ORBITAL = CLARIOstarPlusBackend.WellScanMode.ORBITAL
  SPIRAL = CLARIOstarPlusBackend.WellScanMode.SPIRAL

  def test_point_returns_empty(self):
    result = CLARIOstarPlusBackend._well_scan_field(self.POINT, self.ABS, 3, 686)
    self.assertEqual(result, b"")

  def test_orbital_returns_5_bytes(self):
    result = CLARIOstarPlusBackend._well_scan_field(self.ORBITAL, self.ABS, 3, 686)
    self.assertEqual(len(result), 5)
    self.assertEqual(result[0], 0x02)  # Modality.ABSORBANCE
    self.assertEqual(result[1], 3)  # scan diameter
    self.assertEqual(int.from_bytes(result[2:4], "big"), 686)  # well diameter
    self.assertEqual(result[4], 0x00)

  def test_spiral_returns_5_bytes(self):
    result = CLARIOstarPlusBackend._well_scan_field(self.SPIRAL, self.ABS, 4, 686)
    self.assertEqual(len(result), 5)
    self.assertEqual(result[1], 4)  # scan diameter


class TestReadingsToGrid(unittest.TestCase):
  """Verify _map_readings_to_plate_grid for all-well and partial-well cases."""

  def setUp(self):
    self.plate = _make_plate()

  def test_all_wells_reshape(self):
    """96 readings → 8×12 grid, row-major."""
    wells = self.plate.get_all_items()
    readings = list(range(96))
    grid = CLARIOstarPlusBackend._map_readings_to_plate_grid(readings, wells, self.plate)

    self.assertEqual(len(grid), 8)
    self.assertEqual(len(grid[0]), 12)
    # Row 0 (A): values 0-11
    self.assertEqual(grid[0], list(range(12)))
    # Row 7 (H): values 84-95
    self.assertEqual(grid[7], list(range(84, 96)))

  def test_partial_wells_none_fill(self):
    """Partial wells: only measured wells filled, rest None."""
    wells = [self.plate.get_item("A1")]
    readings = [0.5]
    grid = CLARIOstarPlusBackend._map_readings_to_plate_grid(readings, wells, self.plate)

    self.assertEqual(grid[0][0], 0.5)
    self.assertIsNone(grid[0][1])
    self.assertIsNone(grid[1][0])


class TestMeasurementData(unittest.TestCase):
  """Verify _request_measurement_data and _measurement_progress."""

  def test_request_measurement_data_progressive_payload(self):
    """Progressive variant sends ff ff ff ff 00 payload."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    resp_payload = bytes(36)
    mock.queue_response(_wrap_payload(resp_payload))

    asyncio.run(backend._request_measurement_data(progressive=True))

    sent = mock.written[0]
    inner = _extract_payload(sent)
    # Inner: 0x05 (REQUEST) + 0x02 (DATA) + ff ff ff ff 00
    self.assertEqual(inner[0], 0x05)
    self.assertEqual(inner[1], 0x02)
    self.assertEqual(inner[2:7], b"\xff\xff\xff\xff\x00")

  def test_request_measurement_data_standard_payload(self):
    """Standard variant sends 05 02 00 00 00 00 00 (7 bytes, matching pcap)."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    resp_payload = bytes(36)
    mock.queue_response(_wrap_payload(resp_payload))

    asyncio.run(backend._request_measurement_data(progressive=False))

    sent = mock.written[0]
    inner = _extract_payload(sent)
    self.assertEqual(inner, b"\x05\x02\x00\x00\x00\x00\x00")  # 7 bytes total

  def test_measurement_progress_parsing(self):
    """_measurement_progress extracts (values_written, values_expected) from header."""
    payload = bytearray(36)
    payload[7:9] = (392).to_bytes(2, "big")  # values_expected
    payload[9:11] = (148).to_bytes(2, "big")  # values_written

    written, expected = CLARIOstarPlusBackend._measurement_progress(bytes(payload))
    self.assertEqual(expected, 392)
    self.assertEqual(written, 148)

  def test_measurement_progress_pcap_ground_truth(self):
    """Verify _measurement_progress against real pcap A01 progressive response header.

    Source: A01_all_point_frames.txt — first progressive DATA response.
    values_expected=392 (96 wells × 4 + 8), values_written=0 (measurement just started).
    """
    # First 36 bytes of the progressive response inner payload from pcap
    pcap_header = bytes.fromhex(
      "0225042e0000a901880000001dffe2022003000100600100010000000101000000000000"
    )
    written, expected = CLARIOstarPlusBackend._measurement_progress(pcap_header)
    self.assertEqual(expected, 392)  # 96 × 4 + 8
    self.assertEqual(written, 0)  # measurement just started

  def test_measurement_progress_too_short_raises(self):
    """_measurement_progress raises FrameError on short payloads."""
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    with self.assertRaises(FrameError):
      CLARIOstarPlusBackend._measurement_progress(bytes(10))


# ===========================================================================
# Feature: Absorbance Measurement
# ===========================================================================
# Test order follows backend method order:
#   _build_absorbance_payload → _parse_absorbance_response →
#   request_absorbance_results → read_absorbance


class TestBuildAbsorbancePayload(unittest.TestCase):
  """Verify _build_absorbance_payload against pcap ground truth.

  The plate geometry bytes (well centers) differ from pcap (~0.08mm) because PLR
  uses different well offsets than OEM MARS. We compare all other bytes exactly.
  """

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def _get_gt_inner(self, key: str) -> bytes:
    """Extract inner payload (no STX/size/header/checksum/CR) from ground truth hex."""
    frame = bytes.fromhex(_GT_HEX[key])
    return frame[4:-4]  # skip STX(1)+size(2)+header(1) and checksum(3)+CR(1)

  def _compare_payload(self, payload: bytes, gt_key: str, msg: str = ""):
    """Compare payload against ground truth, skipping known PLR-vs-OEM differences.

    The ground truth inner payload starts with the 0x04 command family byte
    (added by send_command), so we prepend it to the payload for comparison.

    Skips:
    - Bytes 1-12 of full frame: plate geometry (A1 center differs ~0.08mm)
    - Well scan field diameter bytes (PLR: 6.86mm → 0x02AE, OEM: 6.58mm → 0x0292)
    All other bytes must match exactly.
    """
    gt = self._get_gt_inner(gt_key)
    # Prepend the 0x04 command family byte that send_command would add
    full = bytes([0x04]) + payload
    self.assertEqual(
      len(full), len(gt), f"{msg} length mismatch: got {len(full)}, expected {len(gt)}"
    )
    # Byte 0 (0x04 command family)
    self.assertEqual(full[0], gt[0], f"{msg} byte 0 (command family)")
    # Skip bytes 1-12 (plate geometry — PLR offsets differ from OEM)
    # Bytes 13-14: cols/rows
    self.assertEqual(full[13], gt[13], f"{msg} byte 13 (cols)")
    self.assertEqual(full[14], gt[14], f"{msg} byte 14 (rows)")
    self.assertEqual(full[15], gt[15], f"{msg} byte 15 (extra)")
    # Bytes 16-63: well mask
    self.assertEqual(full[16:64], gt[16:64], f"{msg} well mask mismatch")
    # Bytes 64 onward: compare byte-by-byte, skipping well diameter in scan field.
    # Find separator position to locate well scan field.
    sep = b"\x27\x0f\x27\x0f"
    sep_idx = full.index(sep, 64)
    # Before separator (scan byte + pre-separator block): exact match
    self.assertEqual(full[64 : sep_idx + 4], gt[64 : sep_idx + 4], f"{msg} scan+presep mismatch")
    # After separator: if non-point scan, skip well diameter at wsf[2:4]
    after_sep_p = full[sep_idx + 4 :]
    after_sep_g = gt[sep_idx + 4 :]
    if len(after_sep_p) != len(after_sep_g):
      self.fail(f"{msg} post-sep length mismatch: {len(after_sep_p)} vs {len(after_sep_g)}")
    # Check if well scan field is present (non-point: first byte is 0x02 measurement code)
    if len(after_sep_p) > 5 and after_sep_p[0] == 0x02 and after_sep_g[0] == 0x02:
      # Well scan field: byte 0 (meas code), byte 1 (diameter), bytes 2-3 (well diam), byte 4
      self.assertEqual(after_sep_p[0], after_sep_g[0], f"{msg} wsf meas code")
      self.assertEqual(after_sep_p[1], after_sep_g[1], f"{msg} wsf scan diameter")
      # Skip bytes 2-3 (well diameter — PLR uses 686 vs OEM 658)
      self.assertEqual(after_sep_p[4], after_sep_g[4], f"{msg} wsf terminator")
      # Rest after well scan field
      self.assertEqual(after_sep_p[5:], after_sep_g[5:], f"{msg} post-wsf mismatch")
    else:
      # Point mode: no well scan field, compare everything
      self.assertEqual(after_sep_p, after_sep_g, f"{msg} post-sep mismatch")

  def test_A01_point_all96_600nm(self):
    """A01: point, all 96 wells, 600nm, 5 flashes, uni/vert/TL."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=5,
      well_scan="point",
      unidirectional=True,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "A01", "A01")

  def test_A05_point_A1_only(self):
    """A05: point, single well A1."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_absorbance_payload(
      self.plate,
      wells,
      [600],
      flashes=5,
      well_scan="point",
      unidirectional=True,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "A05", "A05")

  def test_A03_point_col1(self):
    """A03: point, column 1 only (8 wells)."""
    wells = self.plate.get_items("A1:H1")
    payload = self.backend._build_absorbance_payload(
      self.plate,
      wells,
      [600],
      flashes=5,
      well_scan="point",
      unidirectional=True,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "A03", "A03")

  def test_A02_orbital_all96(self):
    """A02: orbital, all 96 wells, 600nm, 7 flashes."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=True,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "A02", "A02")

  def test_A07_cols16_point(self):
    """A07: point, columns 1-6 (48 wells), 600nm, 5 flashes."""
    wells = self.plate.get_items("A1:H6")
    payload = self.backend._build_absorbance_payload(
      self.plate,
      wells,
      [600],
      flashes=5,
      well_scan="point",
      unidirectional=True,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "A07", "A07")

  def test_A08_rows_AD_orbital(self):
    """A08: orbital, rows A-D (48 wells), 600nm, 7 flashes, bidi/vert/TL."""
    wells = self.plate.get_items("A1:D12")
    payload = self.backend._build_absorbance_payload(
      self.plate,
      wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      pause_time=0x01,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "A08", "A08")

  def test_B01_spiral_4mm(self):
    """B01: spiral 4mm, all 96, 600nm, 15 flashes."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=15,
      well_scan="spiral",
      scan_diameter_mm=4,
      unidirectional=True,
      vertical=True,
      corner="TL",
      pause_time=0x01,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "B01", "B01")

  def test_B02_spiral_3mm(self):
    """B02: spiral 3mm, all 96, 600nm, 15 flashes."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=15,
      well_scan="spiral",
      scan_diameter_mm=3,
      unidirectional=True,
      vertical=True,
      corner="TL",
      pause_time=0x01,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "B02", "B02")

  def test_C01_corner_TR(self):
    """C01: point, corner TR."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=1,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TR",
      pause_time=0x01,
    )
    self._compare_payload(payload, "C01", "C01")

  def test_C02_corner_BL(self):
    """C02: point, corner BL."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=1,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="BL",
      pause_time=0x01,
    )
    self._compare_payload(payload, "C02", "C02")

  def test_C03_corner_BR(self):
    """C03: point, corner BR."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=1,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="BR",
      pause_time=0x01,
    )
    self._compare_payload(payload, "C03", "C03")

  def test_C04_unidirectional(self):
    """C04: point, unidirectional (same as TL uni but with 1 flash)."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=1,
      well_scan="point",
      unidirectional=True,
      vertical=True,
      corner="TL",
      pause_time=0x01,
    )
    self._compare_payload(payload, "C04", "C04")

  def test_C05_horizontal(self):
    """C05: point, horizontal (not vertical)."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=1,
      well_scan="point",
      unidirectional=False,
      vertical=False,
      corner="TL",
      pause_time=0x01,
    )
    self._compare_payload(payload, "C05", "C05")

  def test_D01_450nm(self):
    """D01: single 450nm."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [450],
      flashes=1,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TL",
      pause_time=0x01,
    )
    self._compare_payload(payload, "D01", "D01")

  def test_D02_dual_wavelength(self):
    """D02: dual 450+600nm → 137 payload bytes (138 on wire with cmd byte)."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [450, 600],
      flashes=1,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TL",
      pause_time=0x01,
    )
    self.assertEqual(len(payload), 137)
    self._compare_payload(payload, "D02", "D02")

  def test_D03_triple_wavelength(self):
    """D03: triple 450+600+660nm → 139 payload bytes (140 on wire with cmd byte)."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [450, 600, 660],
      flashes=1,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TL",
      pause_time=0x01,
    )
    self.assertEqual(len(payload), 139)
    self._compare_payload(payload, "D03", "D03")

  def test_F01_orbital_shake(self):
    """F01: orbital, orbital shake 300rpm 5s."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="orbital",
      shake_speed_rpm=300,
      shake_duration_s=5,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "F01", "F01")

  def test_F02_orbital_500_5(self):
    """F02: orbital, orbital shake 500rpm 5s."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="orbital",
      shake_speed_rpm=500,
      shake_duration_s=5,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "F02", "F02")

  def test_F03_orbital_300_10(self):
    """F03: orbital, orbital shake 300rpm 10s."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="orbital",
      shake_speed_rpm=300,
      shake_duration_s=10,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "F03", "F03")

  def test_F04_double_orbital_shake(self):
    """F04: orbital, double-orbital shake 300rpm 5s."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="double_orbital",
      shake_speed_rpm=300,
      shake_duration_s=5,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "F04", "F04")

  def test_F05_linear_shake(self):
    """F05: orbital, linear shake 300rpm 5s."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="linear",
      shake_speed_rpm=300,
      shake_duration_s=5,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "F05", "F05")

  def test_F06_col1_orbital_shake(self):
    """F06: orbital, column 1 only (8 wells), orbital shake 300rpm 5s."""
    wells = [self.plate.get_item(f"{row}1") for row in "ABCDEFGH"]
    payload = self.backend._build_absorbance_payload(
      self.plate,
      wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="orbital",
      shake_speed_rpm=300,
      shake_duration_s=5,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "F06", "F06")

  def test_G01_orbital_shake_settle05(self):
    """G01: orbital shake 300rpm 5s, settling 0.5s (OEM encodes as pause_time=0x19)."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="orbital",
      shake_speed_rpm=300,
      shake_duration_s=5,
      pause_time=0x19,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "G01", "G01")

  def test_G02_orbital_shake_settle10(self):
    """G02: orbital shake 300rpm 5s, settling 1.0s (wire-identical to F01)."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=7,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
      shake_mode="orbital",
      shake_speed_rpm=300,
      shake_duration_s=5,
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "G02", "G02")

  def test_separator_always_present(self):
    """Separator 0x270f270f appears in every payload."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=5,
    )
    sep_offset = payload.index(_SEPARATOR)  # raises ValueError if missing
    self.assertEqual(payload[sep_offset : sep_offset + 4], _SEPARATOR)

  def test_reference_block_always_present(self):
    """Reference block appears in every payload."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=5,
    )
    self.assertIn(_REFERENCE_BLOCK, payload)

  def test_trailer_always_present(self):
    """Trailer appears in every payload."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=5,
    )
    self.assertIn(_TRAILER, payload)

  def test_wavelength_encoding(self):
    """Wavelengths are encoded as nm*10 u16 BE."""
    payload = self.backend._build_absorbance_payload(
      self.plate,
      self.all_wells,
      [600],
      flashes=5,
    )
    # Find separator, wavelength data is after it (+well_scan_field+pause+num_wl)
    sep_idx = payload.index(_SEPARATOR)
    # For point: sep(4) + wsf(0) + pause(1) + num_wl(1) = sep_idx+6
    wl_offset = sep_idx + 4 + 1 + 1
    wl_raw = int.from_bytes(payload[wl_offset : wl_offset + 2], "big")
    self.assertEqual(wl_raw, 6000)  # 600nm * 10


class TestParseAbsorbanceResponse(unittest.TestCase):
  """Verify _parse_absorbance_response with synthetic data matching A01 structure."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()

  def test_basic_od_computation(self):
    """OD = -log10((sample/c_hi) * (r_hi/ref)) produces plausible values."""
    wells = self.plate.get_all_items()
    sample_val = 3_000_000
    ref_val = 1_300_000
    c_hi = 3_932_985
    r_hi = 18317

    resp = _build_synthetic_response(
      num_wells=96,
      num_wavelengths=1,
      sample_values=[sample_val] * 96,
      ref_values=[ref_val] * 96,
      cal_pairs=[(c_hi, 0), (0, 0), (0, 0), (r_hi, 0)],
    )

    results = self.backend._parse_absorbance_response(resp, self.plate, wells, [600])
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 600)
    self.assertIsNotNone(results[0]["data"])

    # Verify OD computation
    t = (sample_val / c_hi) * (r_hi / ref_val)
    expected_od = -math.log10(t)
    actual_od = results[0]["data"][0][0]  # Well A1
    self.assertAlmostEqual(actual_od, expected_od, places=6)

  def test_grid_mapping_all_96(self):
    """96 values map to 8×12 grid."""
    wells = self.plate.get_all_items()
    resp = _build_synthetic_response(num_wells=96)
    results = self.backend._parse_absorbance_response(resp, self.plate, wells, [600])

    data = results[0]["data"]
    self.assertEqual(len(data), 8)
    self.assertEqual(len(data[0]), 12)
    for row in data:
      for val in row:
        self.assertIsNotNone(val)
        self.assertIsInstance(val, float)

  def test_dual_wavelength(self):
    """Two wavelengths produce two result dicts."""
    wells = self.plate.get_all_items()
    resp = _build_synthetic_response(
      num_wells=96,
      num_wavelengths=2,
      sample_values=[3_000_000] * 192,  # 96 * 2
    )
    results = self.backend._parse_absorbance_response(resp, self.plate, wells, [450, 600])

    self.assertEqual(len(results), 2)
    self.assertEqual(results[0]["wavelength"], 450)
    self.assertEqual(results[1]["wavelength"], 600)

  def test_temperature_extraction_schema_a9(self):
    """Schema 0xA9: temperature at payload bytes 34-36."""
    wells = self.plate.get_all_items()
    resp_bytes = bytearray(_build_synthetic_response())
    # Set temperature at offset 34-35: 25.5°C = 255
    resp_bytes[34:36] = (255).to_bytes(2, "big")
    results = self.backend._parse_absorbance_response(bytes(resp_bytes), self.plate, wells, [600])
    self.assertAlmostEqual(results[0]["temperature"], 25.5)

  def test_temperature_extraction_schema_29(self):
    """Schema 0x29: temperature at payload bytes 23-25."""
    wells = self.plate.get_all_items()
    resp_bytes = bytearray(_build_synthetic_response(schema=0x29))
    # Set temperature at offset 23-24: 30.0°C = 300
    resp_bytes[23:25] = (300).to_bytes(2, "big")
    results = self.backend._parse_absorbance_response(bytes(resp_bytes), self.plate, wells, [600])
    self.assertAlmostEqual(results[0]["temperature"], 30.0)

  def test_too_short_response_raises(self):
    """Payload shorter than 36 bytes raises FrameError."""
    wells = self.plate.get_all_items()
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    for length in (0, 10, 35):
      with self.assertRaises(FrameError, msg=f"payload of {length} bytes should raise"):
        self.backend._parse_absorbance_response(bytes(length), self.plate, wells, [600])

  def test_transmittance_report(self):
    """report='transmittance' returns T% = (sample/c_hi)*(r_hi/ref)*100."""
    wells = self.plate.get_all_items()
    sample_val = 3_000_000
    ref_val = 1_300_000
    c_hi = 3_932_985
    r_hi = 18317

    resp = _build_synthetic_response(
      num_wells=96,
      num_wavelengths=1,
      sample_values=[sample_val] * 96,
      ref_values=[ref_val] * 96,
      cal_pairs=[(c_hi, 0), (0, 0), (0, 0), (r_hi, 0)],
    )

    results = self.backend._parse_absorbance_response(
      resp, self.plate, wells, [600], report="transmittance"
    )
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 600)

    # Verify transmittance computation
    t_pct = (sample_val / c_hi) * (r_hi / ref_val) * 100
    actual = results[0]["data"][0][0]
    self.assertAlmostEqual(actual, t_pct, places=6)

  def test_raw_report(self):
    """report='raw' returns unprocessed detector counts + calibration metadata."""
    wells = self.plate.get_all_items()
    sample_val = 3_000_000
    ref_val = 1_300_000
    c_hi = 3_932_985
    r_hi = 18317

    resp = _build_synthetic_response(
      num_wells=96,
      num_wavelengths=1,
      sample_values=[sample_val] * 96,
      ref_values=[ref_val] * 96,
      cal_pairs=[(c_hi, 0), (0, 0), (0, 0), (r_hi, 0)],
    )

    results = self.backend._parse_absorbance_response(resp, self.plate, wells, [600], report="raw")
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 600)

    # Data grid should contain raw sample counts (as floats)
    actual = results[0]["data"][0][0]
    self.assertAlmostEqual(actual, float(sample_val))

    # Extra keys present in raw mode
    self.assertIn("references", results[0])
    self.assertIn("chromatic_cal", results[0])
    self.assertIn("reference_cal", results[0])
    self.assertEqual(results[0]["chromatic_cal"], (c_hi, 0))
    self.assertEqual(results[0]["reference_cal"], (r_hi, 0))
    self.assertEqual(len(results[0]["references"]), 96)
    self.assertEqual(results[0]["references"][0], ref_val)

  def test_od_transmittance_relationship(self):
    """OD and transmittance are consistent: OD = log10(100 / T%)."""
    wells = self.plate.get_all_items()
    sample_val = 3_000_000
    ref_val = 1_300_000
    c_hi = 3_932_985
    r_hi = 18317

    resp = _build_synthetic_response(
      num_wells=96,
      num_wavelengths=1,
      sample_values=[sample_val] * 96,
      ref_values=[ref_val] * 96,
      cal_pairs=[(c_hi, 0), (0, 0), (0, 0), (r_hi, 0)],
    )

    od_results = self.backend._parse_absorbance_response(
      resp, self.plate, wells, [600], report="optical_density"
    )
    trans_results = self.backend._parse_absorbance_response(
      resp, self.plate, wells, [600], report="transmittance"
    )

    od_val = od_results[0]["data"][0][0]
    t_pct = trans_results[0]["data"][0][0]
    # OD = -log10(T) = -log10(T%/100) = log10(100/T%)
    self.assertAlmostEqual(od_val, math.log10(100 / t_pct), places=6)

  def test_pcap_A05_single_well_ground_truth(self):
    """Verify OD against real pcap A05 capture (single well A1, 600nm, point scan).

    Source: A05_A1_point_frames.txt — final standard DATA response (84-byte payload).
    Expected OD ≈ 0.0771 (blank/clear well).
    """
    # Inner payload from pcap A05 final standard DATA response (wire[4:-4])
    payload = bytes.fromhex(
      "020506260000a9000c000c001dffe2022003000100010100010000000101"
      "00000000000000326c950013c73b0008a5a3000047d1003bda6600008d"
      "10001760d700008d3b000b303e00008c0a0000476300000000"
    )

    wells_a1 = [self.plate.get_well("A1")]
    results = self.backend._parse_absorbance_response(payload, self.plate, wells_a1, [600])

    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 600)

    od_a1 = results[0]["data"][0][0]
    # T = (sample / c_hi) * (r_hi / ref)
    #   = (3304597 / 3922534) * (18275 / 18385) ≈ 0.8374
    # OD = -log10(0.8374) ≈ 0.0771
    self.assertAlmostEqual(od_a1, 0.0771, places=3)

  def test_pcap_A03_col1_dilution_ground_truth(self):
    """Verify OD against real pcap A03 capture (col 1, 8 wells, 600nm, point scan).

    Source: A03_col1_point_frames.txt — final standard DATA response (196-byte payload).
    Column 1 contains a dilution series: A1 blank (OD ~0.08) through H1 dense (OD ~2.8).
    """
    # Inner payload from pcap A03 final standard DATA response (wire[4:-4])
    payload = bytes.fromhex(
      "020506260000a900280028001dffe2022003000100080100010000000101"
      "00000000000000321a740021b78100176887000b112a0002c8c50000b524"
      "00003b5f000017fe0013acbe00132d3c001378170013891d001366930013"
      "77d8001393d100133816000899e900084714000879bf00086a4200086b70"
      "00086fa300086f4400085f74000047be000047bd000047ae000047940000"
      "47780000478e000047a800004798003bf595000090140017b4c500008f83"
      "000b3dc500008daa0000479000000000"
    )

    wells_col1 = [self.plate.get_well(f"{r}1") for r in "ABCDEFGH"]
    results = self.backend._parse_absorbance_response(payload, self.plate, wells_col1, [600])

    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 600)

    # Expected OD values for column 1 dilution series (from pcap computation)
    expected_ods = [0.079, 0.251, 0.409, 0.734, 1.333, 1.928, 2.413, 2.806]
    data = results[0]["data"]
    for row_idx, expected_od in enumerate(expected_ods):
      actual_od = data[row_idx][0]
      self.assertAlmostEqual(
        actual_od,
        expected_od,
        places=2,
        msg=f"Well {chr(65 + row_idx)}1: expected OD {expected_od:.3f}, got {actual_od:.3f}",
      )

  def test_pcap_D02_dual_wavelength_ground_truth(self):
    """Verify dual-WL OD against real pcap D02 capture (col 1, 8 wells, 450+600nm).

    Source: D02_dual_frames.txt — final standard DATA response.
    On real hardware, header bytes [18:20] (wl_resp) is always 1. The second
    wavelength data appears as an extra group after group0, detected dynamically
    from the payload size. Layout: group0(WL1) + WL2 + chrom2 + chrom3 + ref,
    with 5 calibration pairs.
    """
    # 8-well dual-WL payload built from real D02 pcap A1-H1 values
    payload = bytes.fromhex(
      "020500000000a90032003200000000000000000100080000000000000000"
      "000000000000000cb0f2000c274b000d12e6000cd8b0000c19a2000c8efb"
      "000c4dee000c2f740009dd6a0006546b0004a3f200024d8900008db80000"
      "2dec00000bac000005410003e5d60003be890003cbf80003daac0003c196"
      "0003ce320003d0b90003ef010001aee200019a2e0001a34d0001a96a0001"
      "9f700001a6940001a4940001b6ec000047a70000478600004743000047740000"
      "4786000047b2000047b5000047770010152800002186000be9c4000022c0"
      "0004a8ea000022640002385d000022b70000472900000000"
    )

    wells_col1 = [self.plate.get_well(f"{r}1") for r in "ABCDEFGH"]
    results = self.backend._parse_absorbance_response(payload, self.plate, wells_col1, [450, 600])

    self.assertEqual(len(results), 2)
    self.assertEqual(results[0]["wavelength"], 450)
    self.assertEqual(results[1]["wavelength"], 600)

    # 450nm: dilution series is invisible (no absorption at 450nm for this sample)
    expected_450 = [0.106, 0.124, 0.091, 0.099, 0.126, 0.111, 0.120, 0.122]
    data_450 = results[0]["data"]
    for row_idx, expected_od in enumerate(expected_450):
      self.assertAlmostEqual(
        data_450[row_idx][0],
        expected_od,
        places=2,
        msg=f"450nm {chr(65 + row_idx)}1: expected {expected_od:.3f}",
      )

    # 600nm: dilution series clearly visible
    expected_600 = [0.085, 0.277, 0.410, 0.716, 1.335, 1.826, 2.421, 2.766]
    data_600 = results[1]["data"]
    for row_idx, expected_od in enumerate(expected_600):
      self.assertAlmostEqual(
        data_600[row_idx][0],
        expected_od,
        places=2,
        msg=f"600nm {chr(65 + row_idx)}1: expected {expected_od:.3f}",
      )

  def test_pcap_D03_triple_wavelength_ground_truth(self):
    """Verify triple-WL OD against real pcap D03 capture (col 1, 8 wells, 450+600+660nm).

    Source: D03_triple_frames.txt — final standard DATA response.
    Layout: group0(WL1) + WL2 + WL3 + chrom2 + chrom3 + ref, with 6 cal pairs.
    """
    # 8-well triple-WL payload built from real D03 pcap A1-H1 values
    payload = bytes.fromhex(
      "020500000000a9003c003c00000000000000000100080000000000000000"
      "000000000000000c9b93000c3d1b000d0724000cd3b2000c37e1000c8651"
      "000c5ce5000c38b70009cf6b000664000004af4200024d77000090e60000"
      "2c6500000d14000004900006d2480005906a0004e2070003950f0001e712"
      "00011a9d0000915c0000596b0003de8e0003c2e50003d2f80003da350003"
      "c2fe0003cbfa0003cc020003ea860001abfd00019b0a0001a8930001a7bb"
      "0001a0210001a2b60001a3c20001b507000047490000477a0000475c0000"
      "477a0000476a0000479e0000479f000047730010073d00002255000bea80"
      "0000228a000823f7000022940004a71500002324000238f6000023b60000"
      "46f900000000"
    )

    wells_col1 = [self.plate.get_well(f"{r}1") for r in "ABCDEFGH"]
    results = self.backend._parse_absorbance_response(
      payload, self.plate, wells_col1, [450, 600, 660]
    )

    self.assertEqual(len(results), 3)
    self.assertEqual(results[0]["wavelength"], 450)
    self.assertEqual(results[1]["wavelength"], 600)
    self.assertEqual(results[2]["wavelength"], 660)

    # Expected ODs from pcap computation
    expected_450 = [0.106, 0.120, 0.092, 0.100, 0.121, 0.111, 0.117, 0.121]
    expected_600 = [0.086, 0.274, 0.408, 0.717, 1.326, 1.841, 2.372, 2.828]
    expected_660 = [0.079, 0.168, 0.224, 0.360, 0.634, 0.872, 1.160, 1.370]

    for wl_idx, (wl_nm, expected) in enumerate(
      [(450, expected_450), (600, expected_600), (660, expected_660)]
    ):
      data = results[wl_idx]["data"]
      for row_idx, expected_od in enumerate(expected):
        self.assertAlmostEqual(
          data[row_idx][0],
          expected_od,
          places=2,
          msg=f"{wl_nm}nm {chr(65 + row_idx)}1: expected {expected_od:.3f}",
        )


class TestReadAbsorbanceIntegration(unittest.TestCase):
  """Integration test: full read_absorbance and request_absorbance_results flow."""

  def test_read_absorbance_flow(self):
    """Verify read_absorbance sends measurement, polls, retrieves data, and returns results."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    data_frame = _wrap_payload(_build_synthetic_response())

    # Queue: run ack, progressive data (complete), final standard data
    mock.queue_response(
      ACK,  # measurement run ack
      data_frame,  # progressive _request_measurement_data → values_written == expected
      data_frame,  # final standard _request_measurement_data
    )

    results = asyncio.run(backend.read_absorbance(plate, wells, wavelength=600))

    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 600)
    self.assertIsNotNone(results[0]["data"])
    # All values should be floats (grid shape already tested in test_grid_mapping_all_96)
    for row in results[0]["data"]:
      for val in row:
        self.assertIsNotNone(val)
        self.assertIsInstance(val, float)

  def test_read_absorbance_sends_via_send_command(self):
    """Verify measurement command goes through send_command(RUN) with 0x04 command family."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    data_frame = _wrap_payload(_build_synthetic_response(num_wells=1, schema=0x29))
    mock.queue_response(ACK, data_frame, data_frame)

    asyncio.run(backend.read_absorbance(plate, wells, wavelength=600))

    # First write is the measurement frame via send_command(RUN)
    first_frame = mock.written[0]
    _validate_frame(first_frame)
    inner = _extract_payload(first_frame)
    self.assertEqual(inner[0], 0x04)  # CommandFamily.RUN

  def test_read_absorbance_wait_false_returns_empty_list(self):
    """wait=False sends RUN only and returns empty list immediately."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    # Only the RUN ack is needed — no data retrieval
    mock.queue_response(ACK)

    result = asyncio.run(backend.read_absorbance(plate, wells, wavelength=600, wait=False))

    self.assertEqual(result, [])
    # Exactly one frame sent (the RUN command)
    self.assertEqual(len(mock.written), 1)
    inner = _extract_payload(mock.written[0])
    self.assertEqual(inner[0], 0x04)  # CommandFamily.RUN

  def test_incremental_polling_multiple_rounds(self):
    """Incremental polling loops until values_written >= values_expected."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    # Build data response helper
    def _make_data_response(values_written: int, values_expected: int) -> bytes:
      data_payload = bytearray(36 + 4 * 4 + 32)  # header + 1well*4groups + cal
      data_payload[0] = 0x02
      data_payload[1] = 0x05
      data_payload[6] = 0x29
      data_payload[7:9] = values_expected.to_bytes(2, "big")
      data_payload[9:11] = values_written.to_bytes(2, "big")
      data_payload[18:20] = (1).to_bytes(2, "big")
      data_payload[20:22] = (1).to_bytes(2, "big")
      # Fill with nonzero to avoid div by zero
      for i in range(36, len(data_payload)):
        data_payload[i] = 0x01
      return _wrap_payload(bytes(data_payload))

    expected = 4  # 1 well × 4 groups
    incomplete = _make_data_response(values_written=0, values_expected=expected)
    halfway = _make_data_response(values_written=2, values_expected=expected)
    complete = _make_data_response(values_written=expected, values_expected=expected)

    mock.queue_response(
      ACK,  # RUN ack
      incomplete,  # progressive poll 1: 0/4
      STATUS_IDLE,  # interleaved status
      halfway,  # progressive poll 2: 2/4
      STATUS_IDLE,  # interleaved status
      complete,  # progressive poll 3: 4/4 → break
      complete,  # final standard request
    )

    results = asyncio.run(backend.read_absorbance(plate, wells, wavelength=600))
    self.assertIsNotNone(results)
    self.assertEqual(len(results), 1)

  def test_request_absorbance_results(self):
    """request_absorbance_results retrieves and parses data in one call."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    mock.queue_response(_wrap_payload(_build_synthetic_response()))

    results = asyncio.run(backend.request_absorbance_results(plate, wells, [600]))

    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 600)
    self.assertIsNotNone(results[0]["data"])
    self.assertIsInstance(results[0]["data"][0][0], float)

    # Verify it sent the standard (non-progressive) payload (7 bytes, matching pcap)
    inner = _extract_payload(mock.written[0])
    self.assertEqual(inner, b"\x05\x02\x00\x00\x00\x00\x00")


# ---------------------------------------------------------------------------
# Firmware version warning tests
# ---------------------------------------------------------------------------


def _make_firmware_frame(version_x1000: int) -> bytes:
  """Build a firmware info response frame with the given version (×1000).

  Uses a real firmware frame as a template, replacing only the version bytes.
  """
  payload = bytearray(_extract_payload(_REAL_FIRMWARE_FRAME))
  payload[6:8] = version_x1000.to_bytes(2, "big")
  return _wrap_payload(bytes(payload))


def _setup_backend_with_firmware(version_x1000: int) -> CLARIOstarPlusBackend:
  """Run setup() with a mock that returns the given firmware version.

  Queues the minimum responses needed for the full setup() sequence:
    1. ACK for initialize() command
    2. STATUS_IDLE for _wait_until_machine_ready (not busy → exit)
    3. STATUS_IDLE for poll-flush loop (payload[3]!=0x04 → break)
    4. _REAL_EEPROM_FRAME for request_eeprom_data()
    5. firmware frame for request_firmware_info()
  """
  backend = _make_backend()
  mock: MockFTDI = backend.io  # type: ignore[assignment]
  mock.queue_response(
    ACK,
    STATUS_IDLE,
    STATUS_IDLE,
    _REAL_EEPROM_FRAME,
    _make_firmware_frame(version_x1000),
  )
  return backend


class TestFirmwareVersionWarning(unittest.TestCase):
  """Verify that setup() warns on unrecognized firmware versions."""

  def test_confirmed_version_no_warning(self):
    """Known firmware version (1.35) should not produce a warning."""
    backend = _setup_backend_with_firmware(1350)
    with warnings.catch_warnings(record=True) as w:
      warnings.simplefilter("always")
      asyncio.run(backend.setup())
    fw_warnings = [x for x in w if "firmware" in str(x.message).lower()]
    self.assertEqual(fw_warnings, [])

  def test_unknown_version_warns(self):
    """Unrecognized firmware version should produce a UserWarning."""
    backend = _setup_backend_with_firmware(2000)  # "2.00"
    with warnings.catch_warnings(record=True) as w:
      warnings.simplefilter("always")
      asyncio.run(backend.setup())
    fw_warnings = [x for x in w if "firmware" in str(x.message).lower()]
    self.assertEqual(len(fw_warnings), 1)
    self.assertIn("2.00", str(fw_warnings[0].message))
    self.assertIn("1.35", str(fw_warnings[0].message))

  def test_confirmed_versions_has_known_entry(self):
    """Sanity: the constant contains the version we verified in pcap."""
    self.assertIn("1.35", CONFIRMED_FIRMWARE_VERSIONS)
    self.assertEqual(CONFIRMED_FIRMWARE_VERSIONS["1.35"], 2020)


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------


class TestInputValidation(unittest.TestCase):
  """Verify that invalid inputs raise ValueError at the public API boundary."""

  # -- __init__ --

  def test_init_invalid_read_timeout(self):
    with self.assertRaises(ValueError):
      CLARIOstarPlusBackend(read_timeout=0)
    with self.assertRaises(ValueError):
      CLARIOstarPlusBackend(read_timeout=-1)

  def test_init_invalid_max_temperature(self):
    with self.assertRaises(ValueError):
      CLARIOstarPlusBackend(max_temperature=0)
    with self.assertRaises(ValueError):
      CLARIOstarPlusBackend(max_temperature=-5)
    with self.assertRaises(ValueError):
      CLARIOstarPlusBackend(max_temperature=66)

  # -- measure_temperature --

  def test_measure_temperature_invalid_sensor(self):
    backend = _make_backend()
    with self.assertRaises(ValueError):
      asyncio.run(backend.measure_temperature(sensor="left"))

  # -- read_absorbance --

  def _call_absorbance(self, **overrides):
    """Call read_absorbance with valid defaults, overriding specific params."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    defaults = dict(
      plate=plate,
      wells=wells,
      wavelength=600,
      wait=False,
    )
    defaults.update(overrides)
    return asyncio.run(backend.read_absorbance(**defaults))

  def test_read_absorbance_no_wavelength(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(wavelength=0)

  def test_read_absorbance_invalid_wavelength_count(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(wavelengths=[])
    with self.assertRaises(ValueError):
      self._call_absorbance(wavelengths=[400] * 9)

  def test_read_absorbance_invalid_wavelength_range(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(wavelength=219)
    with self.assertRaises(ValueError):
      self._call_absorbance(wavelength=1001)

  def test_read_absorbance_invalid_flashes(self):
    # point mode: 1-200
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="point", flashes=0)
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="point", flashes=201)
    # orbital mode: 1-44
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="orbital", flashes=45)
    # spiral mode: 1-127
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="spiral", flashes=128)

  def test_read_absorbance_invalid_well_scan(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="zigzag")

  def test_read_absorbance_matrix_not_implemented(self):
    with self.assertRaises(NotImplementedError):
      self._call_absorbance(well_scan="matrix")

  def test_read_absorbance_invalid_scan_diameter(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="orbital", scan_diameter_mm=0)
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="spiral", scan_diameter_mm=7)

  def test_read_absorbance_invalid_corner(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(corner="XX")

  def test_read_absorbance_invalid_report(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(report="absorbance")

  def test_read_absorbance_invalid_shake_mode(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(shake_mode="vibrate")

  def test_read_absorbance_invalid_shake_speed(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(
        shake_mode="orbital", shake_speed_rpm=0, shake_duration_s=5, settling_time_s=0
      )
    with self.assertRaises(ValueError):
      self._call_absorbance(
        shake_mode="orbital", shake_speed_rpm=150, shake_duration_s=5, settling_time_s=0
      )
    with self.assertRaises(ValueError):  # 800 exceeds 700 max
      self._call_absorbance(
        shake_mode="orbital", shake_speed_rpm=800, shake_duration_s=5, settling_time_s=0
      )

  def test_read_absorbance_invalid_shake_duration(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(
        shake_mode="orbital", shake_speed_rpm=300, shake_duration_s=0, settling_time_s=0
      )
    with self.assertRaises(ValueError):
      self._call_absorbance(
        shake_mode="linear", shake_speed_rpm=300, shake_duration_s=-1, settling_time_s=0
      )

  def test_read_absorbance_invalid_settling_time(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(
        shake_mode="orbital", shake_speed_rpm=300, shake_duration_s=5, settling_time_s=-1
      )
    with self.assertRaises(ValueError):
      self._call_absorbance(
        shake_mode="orbital", shake_speed_rpm=300, shake_duration_s=5, settling_time_s=2
      )

  def test_read_absorbance_shake_requires_speed(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(shake_mode="orbital", shake_duration_s=5, settling_time_s=0)

  def test_read_absorbance_shake_requires_duration(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(shake_mode="orbital", shake_speed_rpm=300, settling_time_s=0)

  def test_read_absorbance_shake_requires_settling(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(shake_mode="orbital", shake_speed_rpm=300, shake_duration_s=5)

  def test_read_absorbance_shake_params_without_mode(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(shake_speed_rpm=300)
    with self.assertRaises(ValueError):
      self._call_absorbance(shake_duration_s=5)
    with self.assertRaises(ValueError):
      self._call_absorbance(settling_time_s=0.5)

  def test_read_absorbance_invalid_read_timeout(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(read_timeout=0)
    with self.assertRaises(ValueError):
      self._call_absorbance(read_timeout=-5)

  def test_read_absorbance_neither_wavelength_nor_wavelengths(self):
    with self.assertRaises(ValueError):
      self._call_absorbance(wavelength=0, wavelengths=None)


# ---------------------------------------------------------------------------
# Stop method tests
# ---------------------------------------------------------------------------


class TestStop(unittest.TestCase):
  """Verify stop() lifecycle teardown behavior."""

  def test_stop_calls_io_stop(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # Status: not monitoring, drawer closed, no plate
    mock.queue_response(
      _wrap_payload(b"\x00" * 16),  # _request_temperature_monitoring_on -> inactive
      STATUS_IDLE,  # sense_drawer_open -> closed
      STATUS_IDLE,  # sense_plate_present -> no plate
    )
    asyncio.run(backend.stop())
    self.assertTrue(mock.stop_called, "io.stop() should have been called")

  def test_stop_closes_drawer_if_open(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(
      _wrap_payload(b"\x00" * 16),  # temp monitoring check -> inactive
      STATUS_DRAWER_OPEN,  # sense_drawer_open -> True
      ACK,  # close() command ack
      STATUS_IDLE,  # close() wait poll
      STATUS_IDLE,  # sense_plate_present -> no plate
    )
    asyncio.run(backend.stop())
    # Verify close command was sent
    close_frames = [w for w in mock.written if w == COMMANDS["close"][1]]
    self.assertEqual(len(close_frames), 1)

  def test_stop_stops_temperature_monitoring(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # Temperature monitoring is active (non-zero temps)
    temp_active = bytearray(16)
    temp_active[11:13] = (250).to_bytes(2, "big")
    temp_active[13:15] = (255).to_bytes(2, "big")
    mock.queue_response(
      _wrap_payload(bytes(temp_active)),  # monitoring check -> active
      ACK,  # _stop_temperature_monitoring -> OFF ack
      STATUS_IDLE,  # sense_drawer_open -> closed
      STATUS_IDLE,  # sense_plate_present -> no plate
    )
    asyncio.run(backend.stop())
    # Verify temp_off was sent
    off_frames = [w for w in mock.written if w == COMMANDS["temp_off"][1]]
    self.assertEqual(len(off_frames), 1)

  def test_stop_raises_when_plate_present(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(
      _wrap_payload(b"\x00" * 16),  # temp check -> inactive
      STATUS_IDLE,  # sense_drawer_open -> closed
      STATUS_PLATE,  # sense_plate_present -> True
      ACK,  # open() ack (reopens drawer)
      STATUS_DRAWER_OPEN,  # open() wait poll
    )
    with self.assertRaises(RuntimeError):
      asyncio.run(backend.stop())

  def test_stop_accept_plate_skips_check(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(
      _wrap_payload(b"\x00" * 16),  # temp check -> inactive
      STATUS_IDLE,  # sense_drawer_open -> closed
      # No plate check — skipped
    )
    asyncio.run(backend.stop(accept_plate_left_in_device=True))
    # Should not raise


# ---------------------------------------------------------------------------
# Frame validation error case tests
# ---------------------------------------------------------------------------


class TestValidateFrame(unittest.TestCase):
  """Verify _validate_frame raises on each error condition."""

  def test_too_short(self):
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    with self.assertRaises(FrameError):
      _validate_frame(b"\x02\x00\x09")

  def test_wrong_stx(self):
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    # Build valid frame then corrupt STX
    frame = bytearray(_wrap_payload(b"\x80"))
    frame[0] = 0xFF
    with self.assertRaises(FrameError):
      _validate_frame(bytes(frame))

  def test_wrong_cr(self):
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    frame = bytearray(_wrap_payload(b"\x80"))
    frame[-1] = 0xFF
    with self.assertRaises(FrameError):
      _validate_frame(bytes(frame))

  def test_wrong_header(self):
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    frame = bytearray(_wrap_payload(b"\x80"))
    frame[3] = 0xFF
    with self.assertRaises(FrameError):
      _validate_frame(bytes(frame))

  def test_size_mismatch(self):
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    frame = bytearray(_wrap_payload(b"\x80"))
    # Corrupt size field to claim a larger size
    frame[1:3] = (255).to_bytes(2, "big")
    with self.assertRaises(FrameError):
      _validate_frame(bytes(frame))

  def test_checksum_mismatch(self):
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import (
      ChecksumError,
    )

    frame = bytearray(_wrap_payload(b"\x80"))
    # Corrupt a checksum byte
    frame[-2] ^= 0xFF
    with self.assertRaises(ChecksumError):
      _validate_frame(bytes(frame))


# ---------------------------------------------------------------------------
# Timeout tests
# ---------------------------------------------------------------------------


class TestTimeouts(unittest.TestCase):
  """Verify timeout behavior for polling and measurement."""

  def test_wait_until_ready_timeout(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # Queue more busy responses than the 0.01s timeout can consume; each poll
    # takes ~0ms in-process so 100 is more than enough to outlast the timeout.
    for _ in range(100):
      mock.queue_response(STATUS_BUSY)
    with self.assertRaises(TimeoutError):
      asyncio.run(backend._wait_until_machine_ready(read_timeout=0.01))

  def test_read_absorbance_timeout(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    # Build an incomplete data response (values_written=0, values_expected=392)
    incomplete = bytearray(36)
    incomplete[0] = 0x02
    incomplete[1] = 0x05
    incomplete[6] = 0xA9
    incomplete[7:9] = (392).to_bytes(2, "big")  # expected
    incomplete[9:11] = (0).to_bytes(2, "big")  # written
    incomplete[18:20] = (1).to_bytes(2, "big")
    incomplete[20:22] = (96).to_bytes(2, "big")
    incomplete_frame = _wrap_payload(bytes(incomplete))

    # Queue: RUN ack, then more incomplete progressive responses + interleaved
    # status polls than the 0.05s timeout can consume (each pair is ~instant
    # in-process, so 100 pairs is more than enough to outlast the timeout).
    mock.queue_response(ACK)
    for _ in range(100):
      mock.queue_response(incomplete_frame, STATUS_BUSY)

    with self.assertRaises(TimeoutError):
      asyncio.run(backend.read_absorbance(plate, wells, wavelength=600, read_timeout=0.05))


# ---------------------------------------------------------------------------
# send_command validation tests
# ---------------------------------------------------------------------------


class TestSendCommandValidation(unittest.TestCase):
  """Verify send_command raises on invalid command family/command combinations."""

  def test_no_command_family_rejects_command(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK)
    with self.assertRaises(ValueError):
      asyncio.run(
        backend.send_command(
          command_family=backend.CommandFamily.STATUS,
          command=0x00,
        )
      )

  def test_command_family_requires_command(self):
    backend = _make_backend()
    with self.assertRaises(ValueError):
      asyncio.run(
        backend.send_command(
          command_family=backend.CommandFamily.REQUEST,
        )
      )

  def test_invalid_command_for_family(self):
    backend = _make_backend()
    with self.assertRaises(ValueError):
      asyncio.run(
        backend.send_command(
          command_family=backend.CommandFamily.REQUEST,
          command=0xFF,
        )
      )


# ---------------------------------------------------------------------------
# Convenience status query additional tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# request_machine_status retries validation
# ---------------------------------------------------------------------------


class TestStatusRetries(unittest.TestCase):
  """Verify request_machine_status validates retries parameter."""

  def test_retries_zero_raises(self):
    backend = _make_backend()
    with self.assertRaises(ValueError):
      asyncio.run(backend.request_machine_status(retries=0))

  def test_retries_negative_raises(self):
    backend = _make_backend()
    with self.assertRaises(ValueError):
      asyncio.run(backend.request_machine_status(retries=-1))


if __name__ == "__main__":
  unittest.main()
