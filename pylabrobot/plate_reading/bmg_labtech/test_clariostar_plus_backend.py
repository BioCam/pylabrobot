"""Tests for CLARIOstarPlusBackend — Phase 1 commands.

Verifies that initialize, open, and close produce exactly the byte sequences
observed in pcap captures from real CLARIOstar Plus hardware.
"""

import asyncio
import unittest
from typing import List

from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import (
  CLARIOstarPlusBackend,
  _extract_payload,
  _validate_frame,
  _wrap_payload,
)


# ---------------------------------------------------------------------------
# Ground truth frames (verified against pcap captures)
# ---------------------------------------------------------------------------

# initialize: CG.INITIALIZE(0x01) + Cmd.INIT_DEFAULT(0x00) + b"\x00\x10\x02\x00"
GROUND_TRUTH_INITIALIZE = bytes.fromhex("02000e0c01000010020000002f0d")

# open (drawer out): CG.TRAY(0x03) + Cmd.TRAY_OPEN(0x01) + b"\x00\x00\x00\x00\x00"
GROUND_TRUTH_OPEN = bytes.fromhex("02000f0c030100000000000000210d")

# close (drawer in): CG.TRAY(0x03) + Cmd.TRAY_CLOSE(0x00) + b"\x00\x00\x00\x00\x00"
GROUND_TRUTH_CLOSE = bytes.fromhex("02000f0c030000000000000000200d")

# status query: CG.STATUS(0x80), no command byte
GROUND_TRUTH_STATUS = bytes.fromhex("0200090c800000970d")


# ---------------------------------------------------------------------------
# Mock response frames (what the device sends back)
# ---------------------------------------------------------------------------

# Generic command acknowledgement (minimal valid frame)
_ACK = _wrap_payload(b"\x00")

# Status: initialized=True (byte 3 bit 5), not busy
_STATUS_INITIALIZED = _wrap_payload(b"\x00\x00\x00\x20\x00")

# Status: initialized + drawer_open (byte 3 = 0x21), not busy
_STATUS_DRAWER_OPEN = _wrap_payload(b"\x00\x00\x00\x21\x00")

# Status: initialized, drawer closed, not busy
_STATUS_DRAWER_CLOSED = _wrap_payload(b"\x00\x00\x00\x20\x00")


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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFrameUtilities(unittest.TestCase):
  """Verify the frame wrap / validate / extract round-trip."""

  def test_round_trip(self):
    payload = b"\x01\x00\x00\x10\x02\x00"
    frame = _wrap_payload(payload)
    _validate_frame(frame)
    self.assertEqual(_extract_payload(frame), payload)

  def test_initialize_frame_matches_ground_truth(self):
    """The raw frame for an initialize command must match the pcap ground truth."""
    frame = _wrap_payload(b"\x01\x00\x00\x10\x02\x00")
    self.assertEqual(frame, GROUND_TRUTH_INITIALIZE)

  def test_open_frame_matches_ground_truth(self):
    frame = _wrap_payload(b"\x03\x01\x00\x00\x00\x00\x00")
    self.assertEqual(frame, GROUND_TRUTH_OPEN)

  def test_close_frame_matches_ground_truth(self):
    frame = _wrap_payload(b"\x03\x00\x00\x00\x00\x00\x00")
    self.assertEqual(frame, GROUND_TRUTH_CLOSE)

  def test_status_frame_matches_ground_truth(self):
    frame = _wrap_payload(b"\x80")
    self.assertEqual(frame, GROUND_TRUTH_STATUS)


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


class TestInitialize(unittest.TestCase):

  def test_initialize_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # Queue: command ack, then status response (initialized, not busy)
    mock.queue_response(_ACK, _STATUS_INITIALIZED)

    asyncio.run(backend.initialize())

    # First write is the initialize command
    self.assertEqual(mock.written[0], GROUND_TRUTH_INITIALIZE)

  def test_initialize_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(_ACK, _STATUS_INITIALIZED)

    asyncio.run(backend.initialize())

    # Second write is the status poll
    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], GROUND_TRUTH_STATUS)


class TestOpen(unittest.TestCase):

  def test_open_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(_ACK, _STATUS_DRAWER_OPEN)

    asyncio.run(backend.open())

    self.assertEqual(mock.written[0], GROUND_TRUTH_OPEN)

  def test_open_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(_ACK, _STATUS_DRAWER_OPEN)

    asyncio.run(backend.open())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], GROUND_TRUTH_STATUS)


class TestClose(unittest.TestCase):

  def test_close_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(_ACK, _STATUS_DRAWER_CLOSED)

    asyncio.run(backend.close())

    self.assertEqual(mock.written[0], GROUND_TRUTH_CLOSE)

  def test_close_then_polls_status(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(_ACK, _STATUS_DRAWER_CLOSED)

    asyncio.run(backend.close())

    self.assertEqual(len(mock.written), 2)
    self.assertEqual(mock.written[1], GROUND_TRUTH_STATUS)


class TestStatusPollResilience(unittest.TestCase):
  """Verify that _wait_for_ready_and_return survives partial/corrupt frames."""

  def test_recovers_from_partial_frame(self):
    """A truncated status response should be retried, not crash."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # Command ack, then a truncated frame (17 of 24 bytes — the real bug),
    # then a valid status response on the retry.
    truncated = bytes.fromhex("0200180c011500000000c900000000000d")
    mock.queue_response(_ACK, truncated, _STATUS_INITIALIZED)

    asyncio.run(backend.initialize())

    # Should have written: init command, status poll (failed), status poll (success)
    self.assertEqual(len(mock.written), 3)
    self.assertEqual(mock.written[0], GROUND_TRUTH_INITIALIZE)
    self.assertEqual(mock.written[1], GROUND_TRUTH_STATUS)
    self.assertEqual(mock.written[2], GROUND_TRUTH_STATUS)

  def test_recovers_from_empty_frame(self):
    """An empty response should be retried."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # Command ack, then empty bytes (simulating total read timeout),
    # then valid status.
    mock.queue_response(_ACK, b"", _STATUS_DRAWER_OPEN)

    asyncio.run(backend.open())

    self.assertEqual(mock.written[0], GROUND_TRUTH_OPEN)


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
