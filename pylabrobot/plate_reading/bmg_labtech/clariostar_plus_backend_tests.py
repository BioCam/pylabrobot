"""Tests for CLARIOstarPlusBackend — Phase 1 commands.

Verifies that initialize, open, and close produce exactly the byte sequences
observed in pcap captures from real CLARIOstar Plus hardware.
"""

import asyncio
import unittest
from typing import Dict, List

from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import (
  CLARIOstarPlusBackend,
  _extract_payload,
  _validate_frame,
  _wrap_payload,
)


# ---------------------------------------------------------------------------
# Pcap ground truth — commands (verified against pcap captures)
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
  # CF.STATUS(0x80), no command byte
  "status": (
    b"\x80",
    bytes.fromhex("0200090c800000970d"),
  ),
}

# Generic command acknowledgement — shared by all command tests.
ACK = _wrap_payload(b"\x00")


# ---------------------------------------------------------------------------
# Mock FTDI
# ---------------------------------------------------------------------------


class MockFTDI:
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
    pass

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
  backend.io = MockFTDI()
  backend.read_timeout = 5
  backend.configuration = {
    "serial_number": "",
    "firmware_version": "",
    "firmware_build_timestamp": "",
    "model_name": "",
    "machine_type_code": 0,
    "monochromator_range": (0, 0),
    "num_filter_slots": 0,
    "has_absorbance": False,
    "has_fluorescence": False,
    "has_luminescence": False,
    "has_alpha_technology": False,
  }
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
    self.assertEqual(frame, expected_frame,
      f"frame mismatch for {name!r}: got {frame.hex()}, expected {expected_frame.hex()}")
  test.__doc__ = f"_wrap_payload must match pcap ground truth for {name!r}"
  return test

for _name, (_payload, _frame) in COMMANDS.items():
  setattr(TestFrameUtilities, f"test_{_name}_frame_matches_ground_truth",
          _make_frame_test(_name, _payload, _frame))
del _name, _payload, _frame


class TestInitialize(unittest.TestCase):
  """Pcap ground truth for initialize command and its status response."""

  # Pcap response: ready + initialized (byte 5=0x05, byte 7=0x20)
  STATUS_READY = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")

  def test_initialize_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.STATUS_READY)
    asyncio.run(backend.initialize())

    self.assertEqual(mock.written[0], COMMANDS["initialize"][1])

  def test_initialize_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.STATUS_READY)
    asyncio.run(backend.initialize())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], COMMANDS["status"][1])


class TestOpen(unittest.TestCase):
  """Pcap ground truth for drawer-open command and its status response."""

  # Pcap response: ready + initialized + drawer_open (byte 5=0x05, byte 7=0x21)
  STATUS_READY = bytes.fromhex("0200180c010500210000000000000000000000c000010d0d")

  def test_open_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.STATUS_READY)
    asyncio.run(backend.open())

    self.assertEqual(mock.written[0], COMMANDS["open"][1])

  def test_open_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.STATUS_READY)
    asyncio.run(backend.open())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], COMMANDS["status"][1])


class TestClose(unittest.TestCase):
  """Pcap ground truth for drawer-close command and its status response."""

  # Pcap response: ready + initialized, drawer closed (byte 5=0x05, byte 7=0x20)
  STATUS_READY = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")

  def test_close_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.STATUS_READY)
    asyncio.run(backend.close())

    self.assertEqual(mock.written[0], COMMANDS["close"][1])

  def test_close_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.STATUS_READY)
    asyncio.run(backend.close())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], COMMANDS["status"][1])


class TestStatusPollResilience(unittest.TestCase):
  """Verify that _poll_until_ready survives partial/corrupt frames."""

  # Corrupt status — correct size field (16 bytes) but bad checksum.
  # _read_frame completes normally; _validate_frame raises ChecksumError.
  CORRUPT = bytes.fromhex("0200100c0115000000c90000dead000d")

  # Valid status responses for recovery
  STATUS_INITIALIZED = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")
  STATUS_DRAWER_OPEN = bytes.fromhex("0200180c010500210000000000000000000000c000010d0d")

  def test_recovers_from_partial_frame(self):
    """A truncated status response should be retried, not crash."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.CORRUPT, self.STATUS_INITIALIZED)
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

    mock.queue_response(ACK, b"", self.STATUS_DRAWER_OPEN)
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

  def test_combined_flags(self):
    # initialized + drawer_open + plate_detected = byte 3: 0x20 | 0x01 | 0x02 = 0x23
    flags = CLARIOstarPlusBackend._parse_status(b"\x00\x00\x00\x23\x00")
    self.assertTrue(flags["initialized"])
    self.assertTrue(flags["drawer_open"])
    self.assertTrue(flags["plate_detected"])
    self.assertFalse(flags["busy"])


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
  """Verify request_plate_detected and request_busy delegate to status."""

  # initialized + plate_detected (byte 3: 0x22)
  STATUS_PLATE = bytes.fromhex("0200180c010500220000000000000000000000c000010e0d")
  # busy + initialized (payload byte 1: 0x25 = 0x05 | 0x20)
  STATUS_BUSY = bytes.fromhex("0200180c012500200000000000000000000000c000012c0d")
  # idle (all zero status bytes)
  STATUS_IDLE = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")

  def test_request_plate_detected_true(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_PLATE)
    self.assertTrue(asyncio.run(backend.request_plate_detected()))

  def test_request_busy_true(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_BUSY)
    self.assertTrue(asyncio.run(backend.request_busy()))

  def test_request_busy_false(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_IDLE)
    self.assertFalse(asyncio.run(backend.request_busy()))


# ---------------------------------------------------------------------------
# Real hardware capture — firmware info (from CLARIOstar Plus 430-2621)
# ---------------------------------------------------------------------------

# 32-byte unframed payload for command 0x05 0x09.
# Byte map:
#   0:     subcommand echo (0x0a = 0x09 + 1)
#   1:     command family echo (0x05)
#   2-3:   machine type code (0x0024)
#   4-5:   unknown (0x0000)
#   6-7:   firmware version × 1000 (0x0546 = 1350 → "1.35")
#   8-19:  build date "Nov 20 2020\0"
#   20-27: build time "11:51:21\0"
#   28-31: unknown
_REAL_FIRMWARE_PAYLOAD = bytes([
  0x0a, 0x05, 0x00, 0x24, 0x00, 0x00, 0x05, 0x46,
  0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x20, 0x32,
  0x30, 0x32, 0x30, 0x00, 0x31, 0x31, 0x3a, 0x35,
  0x31, 0x3a, 0x32, 0x31, 0x00, 0x00, 0x01, 0x00,
])


class TestFirmwareInfoParsing(unittest.TestCase):
  """Verify firmware info parsing with real hardware capture data."""

  def test_parse_real_firmware(self):
    """Parse the real 32-byte firmware payload from 430-2621 via mock backend."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(_wrap_payload(_REAL_FIRMWARE_PAYLOAD))

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
    mock.queue_response(_wrap_payload(_REAL_FIRMWARE_PAYLOAD))

    fw = asyncio.run(backend.request_firmware_info())
    backend.configuration.update(fw)

    self.assertEqual(backend.configuration["firmware_version"], "1.35")
    self.assertEqual(backend.configuration["firmware_build_timestamp"], "Nov 20 2020 11:51:21")


class TestAvailableDetectionModes(unittest.TestCase):
  """Verify request_available_detection_modes derives modes from configuration."""

  def test_all_modes(self):
    backend = _make_backend()
    backend.configuration.update({
      "has_absorbance": True,
      "has_fluorescence": True,
      "has_luminescence": True,
      "has_alpha_technology": True,
    })
    modes = backend.request_available_detection_modes()
    self.assertEqual(modes, ["absorbance", "fluorescence", "luminescence", "alpha_technology"])

  def test_partial_modes(self):
    backend = _make_backend()
    backend.configuration.update({
      "has_absorbance": True,
      "has_fluorescence": False,
      "has_luminescence": True,
      "has_alpha_technology": False,
    })
    modes = backend.request_available_detection_modes()
    self.assertEqual(modes, ["absorbance", "luminescence"])

  def test_no_eeprom(self):
    backend = _make_backend()
    modes = backend.request_available_detection_modes()
    self.assertEqual(modes, [])


if __name__ == "__main__":
  unittest.main()
