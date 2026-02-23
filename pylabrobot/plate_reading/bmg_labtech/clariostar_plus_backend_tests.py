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

  Each entry in the response queue is returned as a single chunk on the
  first ``read()`` call within a ``_read_frame`` invocation. Subsequent
  ``read()`` calls (before the next ``write()``) return empty bytes so that
  ``_read_frame`` sees the chunk as a complete (or truncated) frame and
  returns it without mixing in the next queued response.
  """

  def __init__(self) -> None:
    self.written: List[bytes] = []
    self._responses: List[bytes] = []
    self._delivered_since_write = False

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
    self._delivered_since_write = False
    return len(data)

  async def read(self, n: int) -> bytes:
    if not self._delivered_since_write and self._responses:
      self._delivered_since_write = True
      return self._responses.pop(0)
    return b""


def _make_backend() -> CLARIOstarPlusBackend:
  """Create a backend with a MockFTDI injected (bypasses real USB)."""
  backend = CLARIOstarPlusBackend.__new__(CLARIOstarPlusBackend)
  backend.io = MockFTDI()
  backend.timeout = 5
  backend.read_timeout = 1
  backend._eeprom_data = None
  backend._firmware_data = None
  backend._machine_type_code = 0
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

  # Truncated status (17 of 24 bytes)
  TRUNCATED = bytes.fromhex("0200180c011500000000c900000000000d")

  # Valid status responses for recovery
  STATUS_INITIALIZED = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")
  STATUS_DRAWER_OPEN = bytes.fromhex("0200180c010500210000000000000000000000c000010d0d")

  def test_recovers_from_partial_frame(self):
    """A truncated status response should be retried, not crash."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK, self.TRUNCATED, self.STATUS_INITIALIZED)
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


if __name__ == "__main__":
  unittest.main()
