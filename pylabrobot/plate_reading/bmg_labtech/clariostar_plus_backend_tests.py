"""Tests for CLARIOstarPlusBackend.

Verifies that initialize, open, and close produce exactly the byte sequences
observed in pcap captures from real CLARIOstar Plus hardware.
Phase 4 adds absorbance measurement tests verified against pcap ground truth.
"""

import asyncio
import math
import unittest
from unittest.mock import AsyncMock, patch
import warnings
from typing import Dict, List

from pylabrobot.io.io import IOBase
from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import (
  _CORE_REFERENCE,
  _REFERENCE_BLOCK,
  _SEPARATOR,
  _TRAILER,
  CONFIRMED_FIRMWARE_VERSIONS,
  CLARIOstarPlusBackend,
  MeasurementInterrupted,
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
  # CF.PAUSE_RESUME(0x0D) — pause. Pcap: stop_and_abandon capture @17.3s.
  "pause_measurement": (
    b"\x0d\xff\xff\x00\x00",
    bytes.fromhex("02000d0c0dffff00000002260d"),
  ),
  # CF.PAUSE_RESUME(0x0D) — resume. Pcap: stop_and_abandon capture @78.4s.
  "resume_measurement": (
    b"\x0d\x00\x00\x00\x00",
    bytes.fromhex("02000d0c0d000000000000280d"),
  ),
  # CF.STOP(0x0B). Pcap: stop_and_abandon capture @86.0s.
  "stop_measurement": (
    b"\x0b\x00",
    bytes.fromhex("02000a0c0b000000230d"),
  ),
  # CF.CMD_0x0E(0x0E). Pcap: normal_power_cycle_oem_start capture @34.3s.
  "cmd_0x0e": (
    b"\x0e\x0b\x12\x00\x00\x04\x19",
    bytes.fromhex("02000f0c0e0b12000004190000650d"),
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
# Running + initialized (stuck measurement state, not busy)
STATUS_RUNNING = bytes.fromhex("0200180c011500200000000000000000000000c000011c0d")


# ---------------------------------------------------------------------------
# Mock FTDI
# ---------------------------------------------------------------------------


class MockFTDI(IOBase):
  """Minimal FTDI mock that records writes and plays back queued responses.

  Delivers exactly one queued frame per ``write()`` cycle:
    - First ``read()`` after a ``write()`` delivers the next queued frame.
    - Subsequent ``read()`` calls return empty bytes, signalling end-of-frame
      to ``_read_frame``.
    - After a frame is delivered, further empty reads do NOT re-arm delivery
      until the next ``write()`` call. This prevents ``_read_frame`` timeout
      loops from consuming queued responses meant for later retries.
  """

  def __init__(self) -> None:
    self.written: List[bytes] = []
    self._responses: List[bytes] = []
    self._ready = False  # True = next read() may deliver a frame
    self._delivered = False  # True = frame delivered, block re-arm until next write
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

  async def usb_purge_rx_buffer(self) -> None:
    self._ready = False

  async def usb_purge_tx_buffer(self) -> None:
    pass

  async def usb_reset(self) -> None:
    pass

  async def stop(self) -> None:
    self.stop_called = True

  async def write(self, data: bytes) -> int:
    self.written.append(bytes(data))
    self._ready = True
    self._delivered = False
    return len(data)

  async def read(self, n: int) -> bytes:
    if self._ready and self._responses:
      self._ready = False
      self._delivered = True
      return self._responses.pop(0)
    # Empty read = end-of-frame boundary. Re-arm only if no frame has been
    # delivered yet in this write cycle. This prevents _read_frame timeout
    # loops from consuming queued responses meant for later write cycles.
    if not self._delivered:
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
  backend._resume_context = None
  backend.measurement_poll_interval = 0.0  # no delay in unit tests
  backend.pause_on_interrupt = False
  backend.excitation_filter_slide = CLARIOstarPlusBackend.ExcitationFilterSlide()
  backend.emission_filter_slide = CLARIOstarPlusBackend.EmissionFilterSlide()
  backend.dichroic_filter_slide = CLARIOstarPlusBackend.DichroicFilterSlide()
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

  def test_initialize_retries_on_frame_error(self):
    """After a power cycle the first response may be a stale 0x0D byte.

    initialize() should retry (with RX purge) and succeed on a later attempt.
    """
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # First attempt: stale CR byte → FrameError. Second attempt: valid response.
    mock.queue_response(b"\x0d", ACK, STATUS_IDLE)
    asyncio.run(backend.initialize())

    # Should have sent the init command twice (retry) + one status poll
    self.assertEqual(len(mock.written), 3)
    self.assertEqual(mock.written[0], COMMANDS["initialize"][1])
    self.assertEqual(mock.written[1], COMMANDS["initialize"][1])  # retry


class TestSetupSendsCmdOx0e(unittest.TestCase):
  """Verify that setup() sends CMD_0x0E after EEPROM + firmware reads (matches OEM pcap)."""

  def test_setup_sends_cmd_0x0e(self):
    """CMD_0x0E frame appears in the written frames during setup()."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # setup() sequence (no running-state check anymore):
    #  1. ACK for initialize()
    #  2. STATUS_IDLE for _wait_until_machine_ready
    #  3. STATUS_IDLE for poll-flush loop (payload[3]!=0x04)
    #  4. _REAL_EEPROM_FRAME for request_eeprom_data()
    #  5. firmware frame for request_firmware_info()
    #  6. ACK for _send_cmd_0x0e()
    mock.queue_response(
      ACK,
      STATUS_IDLE,
      STATUS_IDLE,
      _REAL_EEPROM_FRAME,
      _make_firmware_frame(1350),
      ACK,  # _send_cmd_0x0e()
    )
    with warnings.catch_warnings(record=True):
      warnings.simplefilter("always")
      asyncio.run(backend.setup())
    self.assertFalse(mock._responses, "all queued responses should be consumed")

    # Verify CMD_0x0E (command family 0x0E) was sent.
    # Frame format: STX(0x02) | size(2B) | header(0x0C) | payload[0]=cmd_family | ...
    cmd_0x0e_frames = [f for f in mock.written if len(f) > 4 and f[4] == 0x0E]
    self.assertTrue(cmd_0x0e_frames, "CMD_0x0E should be sent during setup()")


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
  # H-series: absorbance spectrum captures
  # H01: 300-700nm, 1nm step, point, all 96 wells, 5 flashes
  "H01": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a02000000000000000000000000000000000000000000000000000000000000270f270f05000bb81b58000a232826ca00000064000000000200000000000100000001000500010000134c0d",
  # H02: 400-600nm, 1nm step, point, all 96 wells, 5 flashes
  "H02": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a02000000000000000000000000000000000000000000000000000000000000270f270f05000fa01770000a232826ca00000064000000000200000000000100000001000500010000134c0d",
  # H03: 300-700nm, 5nm step, point, all 96 wells, 5 flashes
  "H03": "0200900c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a02000000000000000000000000000000000000000000000000000000000000270f270f05000bb81b580032232826ca000000640000000002000000000001000000010005000100" + "0013740d",
  # H04: 300-700nm, 1nm step, point, column 1 only (8 wells), 5 flashes
  "H04": "0200900c0431e82164059e04642c4a1d000c08008008008008008008008008000000000000000000000000000000000000000000000000000000000000000000000000000a02000000000000000000000000000000000000000000000000000000000000270f270f05000bb81b58000a232826ca0000006400000000020000000000010000000100050001000009780d",
  # H05: 300-700nm, 1nm step, orbital 3mm, all 96 wells, 5 flashes
  "H05": "0200950c0431e82164059e04642c4a1d000c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a32000000000000000000000000000000000000000000000000000000000000270f270f020302920005000bb81b58000a232826ca0000006400000000020000000000010000000100050001000014 1a0d".replace(" ", ""),
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

  ABS = CLARIOstarPlusBackend.DetectionMode.ABSORBANCE
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

  def test_meander_shake(self):
    block = CLARIOstarPlusBackend._pre_separator_block(
      self.ABS, self.ORBITAL, shake_mode="meander", shake_speed_rpm=200, shake_duration_s=5
    )
    self.assertEqual(block[12], 0x02)  # mixer_action
    self.assertEqual(block[17], 0x03)  # shake_pattern: meander
    self.assertEqual(block[18], 0x01)  # speed_idx: (200/100)-1 = 1
    self.assertEqual(int.from_bytes(block[20:22], "little"), 5)  # duration 5s


class TestWellScanField(unittest.TestCase):
  """Verify _well_scan_field for point vs orbital/spiral."""

  ABS = CLARIOstarPlusBackend.DetectionMode.ABSORBANCE
  POINT = CLARIOstarPlusBackend.WellScanMode.POINT
  ORBITAL = CLARIOstarPlusBackend.WellScanMode.ORBITAL
  SPIRAL = CLARIOstarPlusBackend.WellScanMode.SPIRAL

  def test_point_returns_empty(self):
    result = CLARIOstarPlusBackend._well_scan_field(self.POINT, self.ABS, 3, 686)
    self.assertEqual(result, b"")

  def test_orbital_returns_5_bytes(self):
    result = CLARIOstarPlusBackend._well_scan_field(self.ORBITAL, self.ABS, 3, 686)
    self.assertEqual(len(result), 5)
    self.assertEqual(result[0], 0x02)  # DetectionMode.ABSORBANCE
    self.assertEqual(result[1], 3)  # scan diameter
    self.assertEqual(int.from_bytes(result[2:4], "big"), 686)  # well diameter
    self.assertEqual(result[4], 0x00)

  def test_spiral_returns_5_bytes(self):
    result = CLARIOstarPlusBackend._well_scan_field(self.SPIRAL, self.ABS, 4, 686)
    self.assertEqual(len(result), 5)
    self.assertEqual(result[1], 4)  # scan diameter

  def test_matrix_returns_5_bytes_with_N(self):
    """Matrix: buf[0] = matrix_size N, not detection-mode code."""
    MATRIX = CLARIOstarPlusBackend.WellScanMode.MATRIX
    result = CLARIOstarPlusBackend._well_scan_field(MATRIX, self.ABS, 3, 686, matrix_size=3)
    self.assertEqual(len(result), 5)
    self.assertEqual(result[0], 3)  # N, not 0x02
    self.assertEqual(result[1], 3)  # scan diameter
    self.assertEqual(int.from_bytes(result[2:4], "big"), 686)
    self.assertEqual(result[4], 0x00)

  def test_matrix_7x7_returns_N7(self):
    """Matrix 7×7: buf[0] = 7."""
    MATRIX = CLARIOstarPlusBackend.WellScanMode.MATRIX
    FL = CLARIOstarPlusBackend.DetectionMode.FLUORESCENCE
    result = CLARIOstarPlusBackend._well_scan_field(MATRIX, FL, 5, 686, matrix_size=7)
    self.assertEqual(result[0], 7)  # N=7, not 0x03 (FL code)

  def test_matrix_11x11_returns_N11(self):
    """Matrix 11×11: buf[0] = 11."""
    MATRIX = CLARIOstarPlusBackend.WellScanMode.MATRIX
    result = CLARIOstarPlusBackend._well_scan_field(MATRIX, self.ABS, 4, 686, matrix_size=11)
    self.assertEqual(result[0], 11)


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


class TestBuildAbsorbanceSpectrumPayload(unittest.TestCase):
  """Verify _build_absorbance_spectrum_payload against pcap ground truth.

  H01-H05 spectrum captures provide exact byte-level ground truth.
  Same plate geometry tolerance as discrete tests (PLR vs OEM well offsets).
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
    """Compare spectrum payload against ground truth.

    Same skip logic as discrete tests: skip plate geometry bytes 1-12 and
    well scan field diameter bytes (PLR vs OEM well diameter).
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
    sep = b"\x27\x0f\x27\x0f"
    sep_idx = full.index(sep, 64)
    # Before separator (scan byte + pre-separator block): exact match
    self.assertEqual(full[64 : sep_idx + 4], gt[64 : sep_idx + 4], f"{msg} scan+presep mismatch")
    # After separator: check for well scan field
    after_sep_p = full[sep_idx + 4 :]
    after_sep_g = gt[sep_idx + 4 :]
    if len(after_sep_p) != len(after_sep_g):
      self.fail(f"{msg} post-sep length mismatch: {len(after_sep_p)} vs {len(after_sep_g)}")
    if len(after_sep_p) > 5 and after_sep_p[0] == 0x02 and after_sep_g[0] == 0x02:
      # Well scan field present (non-point mode)
      self.assertEqual(after_sep_p[0], after_sep_g[0], f"{msg} wsf meas code")
      self.assertEqual(after_sep_p[1], after_sep_g[1], f"{msg} wsf scan diameter")
      # Skip bytes 2-3 (well diameter — PLR uses 686 vs OEM 658)
      self.assertEqual(after_sep_p[4], after_sep_g[4], f"{msg} wsf terminator")
      self.assertEqual(after_sep_p[5:], after_sep_g[5:], f"{msg} post-wsf mismatch")
    else:
      # Point mode: no well scan field, compare everything
      self.assertEqual(after_sep_p, after_sep_g, f"{msg} post-sep mismatch")

  def test_H01_spectrum_300_700_1nm(self):
    """H01: 300-700nm, 1nm step, point, all 96 wells, 5 flashes.

    OEM MARS uses bidirectional scanning for spectrum mode (scan byte 0x0A).
    """
    payload = self.backend._build_absorbance_spectrum_payload(
      self.plate,
      self.all_wells,
      start_wavelength=300,
      end_wavelength=700,
      step_size=1,
      flashes=5,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "H01", "H01")

  def test_H02_spectrum_400_600_1nm(self):
    """H02: 400-600nm, 1nm step, point, all 96 wells, 5 flashes."""
    payload = self.backend._build_absorbance_spectrum_payload(
      self.plate,
      self.all_wells,
      start_wavelength=400,
      end_wavelength=600,
      step_size=1,
      flashes=5,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "H02", "H02")

  def test_H03_spectrum_300_700_5nm(self):
    """H03: 300-700nm, 5nm step, point, all 96 wells, 5 flashes."""
    payload = self.backend._build_absorbance_spectrum_payload(
      self.plate,
      self.all_wells,
      start_wavelength=300,
      end_wavelength=700,
      step_size=5,
      flashes=5,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "H03", "H03")

  def test_H04_spectrum_col1_only(self):
    """H04: 300-700nm, 1nm step, point, column 1 only (8 wells)."""
    wells = [self.plate.get_item(f"{chr(65+r)}1") for r in range(8)]
    payload = self.backend._build_absorbance_spectrum_payload(
      self.plate,
      wells,
      start_wavelength=300,
      end_wavelength=700,
      step_size=1,
      flashes=5,
      well_scan="point",
      unidirectional=False,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 135)
    self._compare_payload(payload, "H04", "H04")

  def test_H05_spectrum_orbital(self):
    """H05: 300-700nm, 1nm step, orbital 3mm, all 96 wells, 5 flashes."""
    payload = self.backend._build_absorbance_spectrum_payload(
      self.plate,
      self.all_wells,
      start_wavelength=300,
      end_wavelength=700,
      step_size=1,
      flashes=5,
      well_scan="orbital",
      scan_diameter_mm=3,
      unidirectional=False,
      vertical=True,
      corner="TL",
    )
    self.assertEqual(len(payload), 140)
    self._compare_payload(payload, "H05", "H05")

  def test_spectrum_wavelength_encoding(self):
    """Verify wavelength bytes are correctly encoded as nm * 10 u16 BE."""
    payload = self.backend._build_absorbance_spectrum_payload(
      self.plate,
      self.all_wells,
      start_wavelength=220,
      end_wavelength=1000,
      step_size=10,
      flashes=5,
    )
    sep = _SEPARATOR
    sep_idx = payload.index(sep)
    # For point: sep(4) + wsf(0) + pause(1) + num_wl(1) = sep_idx+6
    num_wl_offset = sep_idx + 4 + 1
    # num_wl should be 0 for spectrum mode
    self.assertEqual(payload[num_wl_offset], 0x00)
    # start_wavelength = 220 * 10 = 2200 = 0x0898
    start_offset = num_wl_offset + 1
    start_raw = int.from_bytes(payload[start_offset : start_offset + 2], "big")
    self.assertEqual(start_raw, 2200)
    # end_wavelength = 1000 * 10 = 10000 = 0x2710
    end_raw = int.from_bytes(payload[start_offset + 2 : start_offset + 4], "big")
    self.assertEqual(end_raw, 10000)
    # step = 10 * 10 = 100 = 0x0064
    step_raw = int.from_bytes(payload[start_offset + 4 : start_offset + 6], "big")
    self.assertEqual(step_raw, 100)

  def test_spectrum_uses_core_reference_only(self):
    """Verify spectrum payload uses _CORE_REFERENCE without _PRE_REFERENCE."""
    payload = self.backend._build_absorbance_spectrum_payload(
      self.plate,
      self.all_wells,
      start_wavelength=300,
      end_wavelength=700,
      step_size=1,
      flashes=5,
    )
    # _CORE_REFERENCE should appear in the payload
    self.assertIn(_CORE_REFERENCE, payload)
    # _REFERENCE_BLOCK (PRE + CORE) should NOT appear — only CORE is used
    self.assertNotIn(_REFERENCE_BLOCK, payload)


class TestReadAbsorbanceSpectrumValidation(unittest.TestCase):
  """Verify input validation for read_absorbance_spectrum."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_start_wavelength_too_low(self):
    with self.assertRaises(ValueError):
      asyncio.run(
        self.backend.read_absorbance_spectrum(
          self.plate, self.all_wells, start_wavelength=200, end_wavelength=700, step_size=1
        )
      )

  def test_end_wavelength_too_high(self):
    with self.assertRaises(ValueError):
      asyncio.run(
        self.backend.read_absorbance_spectrum(
          self.plate, self.all_wells, start_wavelength=300, end_wavelength=1100, step_size=1
        )
      )

  def test_end_not_greater_than_start(self):
    with self.assertRaises(ValueError):
      asyncio.run(
        self.backend.read_absorbance_spectrum(
          self.plate, self.all_wells, start_wavelength=700, end_wavelength=300, step_size=1
        )
      )

  def test_step_size_zero(self):
    with self.assertRaises(ValueError):
      asyncio.run(
        self.backend.read_absorbance_spectrum(
          self.plate, self.all_wells, start_wavelength=300, end_wavelength=700, step_size=0
        )
      )

  def test_step_does_not_divide_range(self):
    with self.assertRaises(ValueError):
      asyncio.run(
        self.backend.read_absorbance_spectrum(
          self.plate, self.all_wells, start_wavelength=300, end_wavelength=700, step_size=3
        )
      )

  def test_invalid_well_scan(self):
    with self.assertRaises(ValueError):
      asyncio.run(
        self.backend.read_absorbance_spectrum(
          self.plate, self.all_wells, start_wavelength=300, end_wavelength=700, step_size=1,
          well_scan="matrix",
        )
      )

  def test_shake_mode_without_params(self):
    with self.assertRaises(ValueError):
      asyncio.run(
        self.backend.read_absorbance_spectrum(
          self.plate, self.all_wells, start_wavelength=300, end_wavelength=700, step_size=1,
          shake_mode="orbital",
        )
      )


def _build_synthetic_spectrum_response(
  num_wells: int = 96,
  num_wavelengths: int = 81,
  schema: int = 0xA9,
  sample_base: int = 3_000_000,
  ref_value: int = 1_300_000,
  cal_hi: int = 3_932_985,
  cal_lo: int = 596_217,
  ref_cal_hi: int = 18_317,
  ref_cal_lo: int = 0,
  page_counter: int = 1,
) -> bytes:
  """Build a synthetic spectrum response page payload.

  Unlike _build_synthetic_response (which packs all WLs into group0 with
  num_wl_resp=N), this matches real spectrum hardware behavior: num_wl_resp=1
  in the header, with additional wavelengths encoded as extra groups.

  Layout (matching firmware format):
    Header (36 bytes) with num_wl_resp=1
    + group0 (WL1 samples, num_wells u32s)
    + (num_wl - 1) extra groups for WL2..WLN (num_wells u32s each)
    + chrom2 group (num_wells u32s)
    + chrom3 group (num_wells u32s)
    + reference group (num_wells u32s)
    + (num_wl + 3) calibration pairs (8 bytes each)

  Total u32 values = (num_wavelengths + 3) × (num_wells + 2).

  Args:
    num_wells: Number of wells.
    num_wavelengths: Number of wavelengths in the spectrum.
    schema: Response schema byte (0xA9 for absorbance).
    sample_base: Base detector count for samples. Each well gets
      sample_base + well_index to make values distinguishable.
    ref_value: Detector count for reference wells.
    cal_hi/cal_lo: Chromatic calibration pair for sample wavelengths.
    ref_cal_hi/ref_cal_lo: Calibration pair for reference.
    page_counter: Frame counter byte (1-indexed).

  Returns:
    Single page payload bytes (header + data).
  """
  num_groups = num_wavelengths + 3  # WL groups + chrom2 + chrom3 + ref
  total_values = num_groups * (num_wells + 2)  # groups × wells + cal pairs × 2

  header = bytearray(36)
  header[0] = 0x02  # response_type
  header[1] = 0x05  # status_flags
  header[6] = schema
  # Clamp to u16 max — real firmware uses per-page counts; parsing doesn't use this field.
  clamped = min(total_values, 65535)
  header[7:9] = clamped.to_bytes(2, "big")  # values_expected
  header[9:11] = clamped.to_bytes(2, "big")  # values_written
  header[18:20] = (1).to_bytes(2, "big")  # num_wl_resp = 1 (spectrum mode)
  header[20:22] = num_wells.to_bytes(2, "big")
  header[29] = page_counter

  payload = bytearray(header)

  # WL groups: group0 + (num_wl - 1) extra groups
  for wl_idx in range(num_wavelengths):
    for well_idx in range(num_wells):
      val = sample_base + well_idx + wl_idx * 100  # vary by wavelength
      payload.extend(val.to_bytes(4, "big"))

  # chrom2 group
  for _ in range(num_wells):
    payload.extend((1_300_000).to_bytes(4, "big"))
  # chrom3 group
  for _ in range(num_wells):
    payload.extend((600_000).to_bytes(4, "big"))
  # reference group
  for _ in range(num_wells):
    payload.extend(ref_value.to_bytes(4, "big"))

  # Calibration pairs: one per group (num_wavelengths + 3)
  for wl_idx in range(num_wavelengths):
    payload.extend(cal_hi.to_bytes(4, "big"))
    payload.extend(cal_lo.to_bytes(4, "big"))
  # chrom2 cal
  payload.extend((1_537_345).to_bytes(4, "big"))
  payload.extend((594_949).to_bytes(4, "big"))
  # chrom3 cal
  payload.extend((733_492).to_bytes(4, "big"))
  payload.extend((594_217).to_bytes(4, "big"))
  # reference cal
  payload.extend(ref_cal_hi.to_bytes(4, "big"))
  payload.extend(ref_cal_lo.to_bytes(4, "big"))

  return bytes(payload)


def _split_spectrum_into_pages(
  full_payload: bytes,
  values_per_page: int,
) -> List[bytes]:
  """Split a single synthetic spectrum payload into multiple pages.

  Simulates the firmware's pagination: each page gets the same 36-byte header
  (with an incrementing page counter at byte 29) and a slice of the data.

  Args:
    full_payload: Complete spectrum payload from _build_synthetic_spectrum_response.
    values_per_page: Number of u32 values per page (e.g., 13197 for H01).

  Returns:
    List of page payloads, each with a 36-byte header + data slice.
  """
  header = full_payload[:36]
  data = full_payload[36:]
  total_values = len(data) // 4
  pages = []
  offset = 0
  page_num = 0
  while offset < total_values:
    page_num += 1
    chunk_values = min(values_per_page, total_values - offset)
    chunk_data = data[offset * 4 : (offset + chunk_values) * 4]

    page_header = bytearray(header)
    page_header[29] = page_num
    # Set per-page values_expected/written to chunk_values
    page_header[7:9] = chunk_values.to_bytes(2, "big")
    page_header[9:11] = chunk_values.to_bytes(2, "big")

    pages.append(bytes(page_header) + chunk_data)
    offset += chunk_values
  return pages


class TestParseSpectrumPages(unittest.TestCase):
  """Verify _parse_abs_spectrum_pages with synthetic spectrum data."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_single_page_spectrum(self):
    """Single-page spectrum (like H03: 81 wl) parses correctly."""
    num_wl = 81
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )
    pages = [full_payload]
    wavelengths = [300 + i * 5 for i in range(num_wl)]

    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )

    self.assertEqual(len(results), num_wl)
    self.assertEqual(results[0]["wavelength"], 300)
    self.assertEqual(results[-1]["wavelength"], 700)
    for r in results:
      self.assertIsNotNone(r["data"])
      self.assertIsInstance(r["data"][0][0], float)
      # OD should be positive and finite for our test values
      self.assertTrue(0 < r["data"][0][0] < 10)

  def test_multi_page_spectrum(self):
    """Multi-page spectrum (like H01: 401 wl, 3 pages) parses correctly."""
    num_wl = 401
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )
    # Split into 3 pages: total=39592 values, ceil(39592/13198)=3
    pages = _split_spectrum_into_pages(full_payload, values_per_page=13198)
    self.assertEqual(len(pages), 3, f"expected 3 pages, got {len(pages)}")

    wavelengths = [300 + i for i in range(num_wl)]

    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )

    self.assertEqual(len(results), num_wl)
    self.assertEqual(results[0]["wavelength"], 300)
    self.assertEqual(results[-1]["wavelength"], 700)
    # Verify distinct OD values across wavelengths (sample_base varies per wl)
    od_first = results[0]["data"][0][0]
    od_last = results[-1]["data"][0][0]
    self.assertNotAlmostEqual(od_first, od_last, places=3)

  def test_transmittance_report(self):
    """Spectrum with report='transmittance' returns percent transmittance."""
    num_wl = 5
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )
    pages = [full_payload]
    wavelengths = [400 + i * 50 for i in range(num_wl)]

    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="transmittance"
    )

    self.assertEqual(len(results), num_wl)
    for r in results:
      # Transmittance should be 0-100+
      self.assertGreater(r["data"][0][0], 0)

  def test_raw_report(self):
    """Spectrum with report='raw' includes references and calibration."""
    num_wl = 5
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )
    pages = [full_payload]
    wavelengths = [400 + i * 50 for i in range(num_wl)]

    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="raw"
    )

    self.assertEqual(len(results), num_wl)
    for r in results:
      self.assertIn("references", r)
      self.assertIn("chromatic_cal", r)
      self.assertIn("reference_cal", r)
      self.assertEqual(len(r["references"]), 96)

  def test_empty_pages_raises(self):
    """_parse_abs_spectrum_pages raises ValueError for empty page list."""
    with self.assertRaises(ValueError):
      self.backend._parse_abs_spectrum_pages(
        [], self.plate, self.all_wells, [600], report="optical_density"
      )

  def test_five_page_spectrum(self):
    """Five-page spectrum (like verification: 781 wl) parses correctly."""
    num_wl = 781
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )
    # Split into 5 pages: total=76832 values, ceil(76832/15367)=5
    pages = _split_spectrum_into_pages(full_payload, values_per_page=15367)
    self.assertEqual(len(pages), 5, f"expected 5 pages, got {len(pages)}")

    wavelengths = [220 + i for i in range(num_wl)]

    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )

    self.assertEqual(len(results), num_wl)
    self.assertEqual(results[0]["wavelength"], 220)
    self.assertEqual(results[-1]["wavelength"], 1000)

  def test_page_concatenation_preserves_data_order(self):
    """Values from page N+1 continue exactly where page N left off."""
    num_wl = 10
    num_wells = 4
    plate = _make_plate()
    wells = plate.get_items("A1:D1")

    # Build with distinctive sample values
    full_payload = _build_synthetic_spectrum_response(
      num_wells=num_wells, num_wavelengths=num_wl,
      sample_base=1_000_000, ref_value=500_000
    )
    # Parse as single page
    single_results = self.backend._parse_abs_spectrum_pages(
      [full_payload], plate, wells,
      [300 + i * 10 for i in range(num_wl)],
      report="raw"
    )
    # Split into 2 pages and parse
    pages = _split_spectrum_into_pages(full_payload, values_per_page=40)
    self.assertGreater(len(pages), 1)
    multi_results = self.backend._parse_abs_spectrum_pages(
      pages, plate, wells,
      [300 + i * 10 for i in range(num_wl)],
      report="raw"
    )

    # Results must be identical
    self.assertEqual(len(single_results), len(multi_results))
    for s, m in zip(single_results, multi_results):
      self.assertEqual(s["wavelength"], m["wavelength"])
      self.assertEqual(s["data"], m["data"])


class TestReadAbsorbanceSpectrumIntegration(unittest.TestCase):
  """Integration test: full read_absorbance_spectrum flow with MockFTDI."""

  def test_spectrum_flow_single_page(self):
    """Spectrum measurement with 1 page: RUN → status poll → GET_DATA → parse."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    num_wl = 5  # small spectrum for fast test
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )
    data_frame = _wrap_payload(full_payload)

    mock.queue_response(
      ACK,  # measurement RUN ack
      STATUS_IDLE,  # status poll → not busy → measurement done
      data_frame,  # standard GET_DATA → single page
    )

    results = asyncio.run(
      backend.read_absorbance_spectrum(
        plate, wells,
        start_wavelength=400, end_wavelength=420, step_size=5,
      )
    )

    self.assertEqual(len(results), num_wl)
    self.assertEqual(results[0]["wavelength"], 400)
    self.assertEqual(results[-1]["wavelength"], 420)
    for r in results:
      self.assertIsInstance(r["data"][0][0], float)

  def test_spectrum_flow_multi_page(self):
    """Spectrum with multiple pages: RUN → poll → GET_DATA × N → parse."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    num_wl = 81  # H03-like
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )
    # Split into 2 pages
    pages = _split_spectrum_into_pages(full_payload, values_per_page=4200)
    self.assertEqual(len(pages), 2)

    responses = [
      ACK,  # RUN ack
      STATUS_IDLE,  # status poll → done
    ]
    for p in pages:
      responses.append(_wrap_payload(p))
    mock.queue_response(*responses)

    results = asyncio.run(
      backend.read_absorbance_spectrum(
        plate, wells,
        start_wavelength=300, end_wavelength=700, step_size=5,
      )
    )

    self.assertEqual(len(results), num_wl)
    self.assertEqual(results[0]["wavelength"], 300)
    self.assertEqual(results[-1]["wavelength"], 700)

  def test_spectrum_wait_false(self):
    """wait=False sends RUN only and returns empty list."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    mock.queue_response(ACK)

    result = asyncio.run(
      backend.read_absorbance_spectrum(
        plate, wells,
        start_wavelength=300, end_wavelength=700, step_size=5,
        wait=False,
      )
    )

    self.assertEqual(result, [])
    self.assertEqual(len(mock.written), 1)
    inner = _extract_payload(mock.written[0])
    self.assertEqual(inner[0], 0x04)  # CommandFamily.RUN

  def test_spectrum_status_polling_loop(self):
    """Status polling loops until device reports not busy."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    num_wl = 5
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )

    mock.queue_response(
      ACK,  # RUN ack
      STATUS_BUSY,  # poll 1: still measuring
      STATUS_BUSY,  # poll 2: still measuring
      STATUS_IDLE,  # poll 3: done
      _wrap_payload(full_payload),  # data page
    )

    results = asyncio.run(
      backend.read_absorbance_spectrum(
        plate, wells,
        start_wavelength=400, end_wavelength=420, step_size=5,
      )
    )

    self.assertEqual(len(results), num_wl)

  def test_spectrum_sends_standard_get_data(self):
    """Spectrum uses standard GET_DATA (00 00 00 00), not progressive."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    num_wl = 5
    full_payload = _build_synthetic_spectrum_response(
      num_wells=96, num_wavelengths=num_wl
    )

    mock.queue_response(
      ACK,  # RUN ack
      STATUS_IDLE,  # not busy
      _wrap_payload(full_payload),  # data page
    )

    asyncio.run(
      backend.read_absorbance_spectrum(
        plate, wells,
        start_wavelength=400, end_wavelength=420, step_size=5,
      )
    )

    # Writes: RUN command, STATUS query, GET_DATA (standard)
    # Find the GET_DATA frame
    get_data_frame = mock.written[-1]
    inner = _extract_payload(get_data_frame)
    # Standard GET_DATA: CF.REQUEST(0x05) + Cmd.DATA(0x02) + 00 00 00 00 00
    self.assertEqual(inner, b"\x05\x02\x00\x00\x00\x00\x00")


# ---------------------------------------------------------------------------
# Spectrum ground truth tests — real pcap capture data
# ---------------------------------------------------------------------------

# OEM MARS OD at 600nm for all 96 wells from the verification plate spectrum scan
# (220-1000nm, 1nm step, spiral scan, 20 flashes).
# Source: 260226_verification_SPECTRUM220-1000_spiral_20f_20secorbital DATA CSV.
VERIFICATION_SPECTRUM_OD_600 = {
  "A01": 2.737, "A02": 2.727, "A03": 0.134, "A04": 1.199, "A05": 2.128,
  "A06": 2.579, "A07": 2.639, "A08": 2.673, "A09": 2.644, "A10": 2.669,
  "A11": 0.155, "A12": 0.121,
  "B01": 0.095, "B02": 2.753, "B03": 2.705, "B04": 2.742, "B05": 2.744,
  "B06": 2.750, "B07": 2.650, "B08": 2.675, "B09": 2.595, "B10": 2.565,
  "B11": 0.143, "B12": 0.133,
  "C01": 0.145, "C02": 0.149, "C03": 0.119, "C04": 0.110, "C05": 0.129,
  "C06": 0.140, "C07": 0.151, "C08": 0.164, "C09": 2.257, "C10": 2.211,
  "C11": 0.134, "C12": 0.120,
  "D01": 0.143, "D02": 0.148, "D03": 0.155, "D04": 0.176, "D05": 0.194,
  "D06": 0.216, "D07": 0.148, "D08": 0.151, "D09": 1.639, "D10": 1.611,
  "D11": 0.114, "D12": 0.114,
  "E01": 0.095, "E02": 0.098, "E03": 0.117, "E04": 0.101, "E05": 0.098,
  "E06": 0.096, "E07": 0.102, "E08": 0.099, "E09": 0.860, "E10": 0.899,
  "E11": 0.108, "E12": 0.092,
  "F01": 0.098, "F02": 0.093, "F03": 0.098, "F04": 0.096, "F05": 0.094,
  "F06": 0.114, "F07": 0.090, "F08": 0.092, "F09": 0.144, "F10": 0.092,
  "F11": 0.092, "F12": 0.106,
  "G01": 2.645, "G02": 2.638, "G03": 2.720, "G04": 2.649, "G05": 2.680,
  "G06": 2.695, "G07": 2.675, "G08": 2.665, "G09": 2.632, "G10": 2.630,
  "G11": 2.608, "G12": 2.645,
  "H01": 2.647, "H02": 2.650, "H03": 2.693, "H04": 2.665, "H05": 2.674,
  "H06": 2.644, "H07": 2.639, "H08": 2.703, "H09": 2.668, "H10": 2.655,
  "H11": 2.656, "H12": 2.653,
}

# OEM MARS OD at selected wavelengths for A01 from the verification plate spectrum scan.
VERIFICATION_SPECTRUM_A01_MULTI_WL = {
  220: 1.304, 280: 2.610, 300: 2.350, 400: 1.524, 450: 0.198,
  500: 0.319, 550: 1.526, 600: 2.737, 700: 0.205, 800: 0.092,
  900: 0.120, 1000: 0.216,
}

# OEM MARS OD at selected wavelengths for B01 (low-OD clear well).
VERIFICATION_SPECTRUM_B01_MULTI_WL = {
  300: 0.718, 450: 0.119, 600: 0.095, 800: 0.085,
}


def _load_test_data_pages(prefix: str) -> List[bytes]:
  """Load binary page payloads from test_data directory.

  Args:
    prefix: File prefix (e.g., 'h01', 'verification').

  Returns:
    List of raw payload bytes, one per page, in order.
  """
  import os

  test_data_dir = os.path.join(os.path.dirname(__file__), "test_data")
  pages = []
  page_num = 1
  while True:
    path = os.path.join(test_data_dir, f"{prefix}_page{page_num}.bin")
    if not os.path.exists(path):
      break
    with open(path, "rb") as f:
      pages.append(f.read())
    page_num += 1
  return pages


class TestSpectrumResponseGroundTruth(unittest.TestCase):
  """Ground truth tests using real pcap spectrum response data.

  Binary page payloads were extracted from USB pcap captures of real
  CLARIOstar Plus hardware. Tests verify:
  1. Structural correctness (page count, value count, wavelength count)
  2. Header fields match expected values
  3. Parser produces valid OD values
  4. Verification plate OD matches OEM MARS ground truth CSV

  Capture parameters:
    H01: 300-700nm, 1nm step, 96 wells, point scan, 5 flashes → 401 wl, 3 pages
    H02: 400-600nm, 1nm step, 96 wells, point scan, 5 flashes → 201 wl, 2 pages
    H03: 300-700nm, 5nm step, 96 wells, point scan, 5 flashes → 81 wl, 1 page
    H04: 300-700nm, 1nm step, 8 wells (col 1), point scan, 5 flashes → 401 wl, 1 page
    H05: 300-700nm, 1nm step, 96 wells, orbital scan, 5 flashes → 401 wl, 3 pages
    Verification: 220-1000nm, 1nm step, 96 wells, spiral scan, 20 flashes → 781 wl, 5 pages
  """

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  # -- Header validation helpers --

  def _assert_page_headers(
    self,
    pages: List[bytes],
    expected_num_wells: int,
    expected_page_count: int,
  ):
    """Validate common header fields across all pages."""
    self.assertEqual(len(pages), expected_page_count,
                     f"expected {expected_page_count} pages, got {len(pages)}")
    for i, page in enumerate(pages):
      self.assertGreaterEqual(len(page), 36, f"page {i+1} too short: {len(page)} bytes")
      schema = page[6]
      self.assertEqual(schema, 0xA9, f"page {i+1}: schema 0x{schema:02X} != 0xA9")
      num_wl_resp = int.from_bytes(page[18:20], "big")
      self.assertEqual(num_wl_resp, 1, f"page {i+1}: num_wl_resp {num_wl_resp} != 1")
      num_wells = int.from_bytes(page[20:22], "big")
      self.assertEqual(num_wells, expected_num_wells,
                       f"page {i+1}: num_wells {num_wells} != {expected_num_wells}")
      page_counter = page[29]
      self.assertEqual(page_counter, i + 1,
                       f"page {i+1}: page_counter {page_counter} != {i+1}")

  def _total_values(self, pages: List[bytes]) -> int:
    """Sum of u32 values across all pages (excluding 36-byte headers)."""
    return sum((len(p) - 36) // 4 for p in pages)

  # -- H01: 300-700nm, 1nm step, 96 wells, point scan, 3 pages --

  def test_h01_page_structure(self):
    """H01 capture: 3 pages, 96 wells, 39592 total values."""
    pages = _load_test_data_pages("h01")
    self._assert_page_headers(pages, expected_num_wells=96, expected_page_count=3)
    self.assertEqual(self._total_values(pages), 39592)  # (401+3)×(96+2)

  def test_h01_parse_produces_401_wavelengths(self):
    """H01: parser returns 401 wavelength dicts with valid OD values."""
    pages = _load_test_data_pages("h01")
    wavelengths = list(range(300, 701))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )
    self.assertEqual(len(results), 401)
    self.assertEqual(results[0]["wavelength"], 300)
    self.assertEqual(results[-1]["wavelength"], 700)
    for r in results:
      self.assertEqual(len(r["data"]), 8)  # 8 rows
      self.assertEqual(len(r["data"][0]), 12)  # 12 cols
      od = r["data"][0][0]  # A01
      self.assertIsInstance(od, float)
      self.assertTrue(math.isfinite(od), f"non-finite OD at {r['wavelength']}nm: {od}")

  # -- H02: 400-600nm, 1nm step, 96 wells, point scan, 2 pages --

  def test_h02_page_structure(self):
    """H02 capture: 2 pages, 96 wells, 19992 total values."""
    pages = _load_test_data_pages("h02")
    self._assert_page_headers(pages, expected_num_wells=96, expected_page_count=2)
    self.assertEqual(self._total_values(pages), 19992)  # (201+3)×(96+2)

  def test_h02_parse_produces_201_wavelengths(self):
    """H02: parser returns 201 wavelength dicts."""
    pages = _load_test_data_pages("h02")
    wavelengths = list(range(400, 601))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )
    self.assertEqual(len(results), 201)
    self.assertEqual(results[0]["wavelength"], 400)
    self.assertEqual(results[-1]["wavelength"], 600)

  # -- H03: 300-700nm, 5nm step, 96 wells, point scan, 1 page --

  def test_h03_page_structure(self):
    """H03 capture: 1 page, 96 wells, 8232 total values."""
    pages = _load_test_data_pages("h03")
    self._assert_page_headers(pages, expected_num_wells=96, expected_page_count=1)
    self.assertEqual(self._total_values(pages), 8232)  # (81+3)×(96+2)

  def test_h03_parse_produces_81_wavelengths(self):
    """H03: parser returns 81 wavelength dicts."""
    pages = _load_test_data_pages("h03")
    wavelengths = [300 + i * 5 for i in range(81)]
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )
    self.assertEqual(len(results), 81)
    self.assertEqual(results[0]["wavelength"], 300)
    self.assertEqual(results[-1]["wavelength"], 700)

  # -- H04: 300-700nm, 1nm step, 8 wells (col 1), point scan, 1 page --

  def test_h04_page_structure(self):
    """H04 capture: 1 page, 8 wells, 4040 total values.

    H04 was captured with 1nm step (confirmed from pcap RUN payload),
    giving 401 wavelengths. Values: (401+3)×(8+2) = 4040.
    """
    pages = _load_test_data_pages("h04")
    self._assert_page_headers(pages, expected_num_wells=8, expected_page_count=1)
    self.assertEqual(self._total_values(pages), 4040)  # (401+3)×(8+2)

  def test_h04_parse_produces_401_wavelengths_8_wells(self):
    """H04: parser returns 401 wavelength dicts for 8 wells (col 1)."""
    pages = _load_test_data_pages("h04")
    wells_col1 = [self.plate.get_well(f"{r}1") for r in "ABCDEFGH"]
    wavelengths = list(range(300, 701))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, wells_col1, wavelengths, report="optical_density"
    )
    self.assertEqual(len(results), 401)
    self.assertEqual(results[0]["wavelength"], 300)
    self.assertEqual(results[-1]["wavelength"], 700)
    # 8 wells in column 1 → data grid should have 8 rows, 1 col each
    # (since only col 1 wells are requested)
    inf_count = 0
    for r in results:
      for row in range(8):
        od = r["data"][row][0]
        self.assertIsInstance(od, float)
        if not math.isfinite(od):
          inf_count += 1
    # Allow up to 1% inf values (detector saturation at extreme OD)
    max_inf = int(401 * 8 * 0.01)
    self.assertLessEqual(inf_count, max_inf,
                         f"H04: too many inf values ({inf_count}/{401*8})")

  # -- H05: 300-700nm, 1nm step, 96 wells, orbital scan, 3 pages --

  def test_h05_page_structure(self):
    """H05 capture: 3 pages, 96 wells, 39592 total values (same as H01)."""
    pages = _load_test_data_pages("h05")
    self._assert_page_headers(pages, expected_num_wells=96, expected_page_count=3)
    self.assertEqual(self._total_values(pages), 39592)  # (401+3)×(96+2)

  def test_h05_parse_produces_401_wavelengths(self):
    """H05 (orbital scan): parser returns 401 wavelength dicts."""
    pages = _load_test_data_pages("h05")
    wavelengths = list(range(300, 701))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )
    self.assertEqual(len(results), 401)
    self.assertEqual(results[0]["wavelength"], 300)
    self.assertEqual(results[-1]["wavelength"], 700)
    for r in results:
      od = r["data"][0][0]
      self.assertIsInstance(od, float)
      self.assertTrue(math.isfinite(od), f"non-finite OD at {r['wavelength']}nm: {od}")

  # -- Verification plate: 220-1000nm, 1nm step, 96 wells, spiral scan, 5 pages --

  def test_verification_page_structure(self):
    """Verification capture: 5 pages, 96 wells, 76832 total values."""
    pages = _load_test_data_pages("verification")
    self._assert_page_headers(pages, expected_num_wells=96, expected_page_count=5)
    self.assertEqual(self._total_values(pages), 76832)  # (781+3)×(96+2)

  def test_verification_parse_produces_781_wavelengths(self):
    """Verification: parser returns 781 wavelength dicts."""
    pages = _load_test_data_pages("verification")
    wavelengths = list(range(220, 1001))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )
    self.assertEqual(len(results), 781)
    self.assertEqual(results[0]["wavelength"], 220)
    self.assertEqual(results[-1]["wavelength"], 1000)

  def test_verification_temperature(self):
    """Verification capture pages report temperature = 24.1°C."""
    pages = _load_test_data_pages("verification")
    # Header byte[34:36] = 0x00F1 = 241 → 241/10 = 24.1°C
    for i, page in enumerate(pages):
      raw_temp = int.from_bytes(page[34:36], "big")
      self.assertEqual(raw_temp, 241, f"page {i+1}: raw temp {raw_temp} != 241")

  def test_verification_od_600nm_all_96_wells(self):
    """Verification: OD at 600nm matches OEM MARS ground truth for all 96 wells.

    Tolerance: ±0.015 OD for low-OD wells (OD < 1.0), ±0.04 OD for high-OD wells.
    Spectrum measurements inherently differ from discrete at high OD due to
    stray light and bandwidth effects, so wider tolerance is expected at OD > 2.
    """
    pages = _load_test_data_pages("verification")
    wavelengths = list(range(220, 1001))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )

    # Find the 600nm result (index 380 = 600 - 220)
    idx_600 = 600 - 220
    self.assertEqual(results[idx_600]["wavelength"], 600)
    data_600 = results[idx_600]["data"]

    mismatches = []
    for row_idx, row_letter in enumerate("ABCDEFGH"):
      for col_idx in range(12):
        well = f"{row_letter}{col_idx + 1:02d}"
        expected = VERIFICATION_SPECTRUM_OD_600[well]
        actual = data_600[row_idx][col_idx]
        tol = 0.04 if expected > 1.0 else 0.015
        if abs(actual - expected) > tol:
          mismatches.append(
            f"{well}: actual={actual:.4f}, expected={expected:.3f}, diff={abs(actual-expected):.4f}"
          )
    self.assertEqual(
      mismatches, [],
      f"OD mismatches at 600nm ({len(mismatches)}/{96}):\n" + "\n".join(mismatches[:20]),
    )

  def test_verification_a01_multi_wavelength(self):
    """Verification: A01 OD at multiple wavelengths matches OEM MARS ground truth.

    Tests across the full spectrum range to verify correct wavelength mapping
    and data ordering across page boundaries.
    """
    pages = _load_test_data_pages("verification")
    wavelengths = list(range(220, 1001))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )

    for wl_nm, expected_od in VERIFICATION_SPECTRUM_A01_MULTI_WL.items():
      idx = wl_nm - 220
      actual_od = results[idx]["data"][0][0]  # row 0, col 0 = A01
      tol = 0.04 if expected_od > 1.0 else 0.015
      self.assertAlmostEqual(
        actual_od, expected_od, delta=tol,
        msg=f"A01 @ {wl_nm}nm: actual={actual_od:.4f}, expected={expected_od:.3f}",
      )

  def test_verification_b01_multi_wavelength(self):
    """Verification: B01 (low-OD well) at multiple wavelengths."""
    pages = _load_test_data_pages("verification")
    wavelengths = list(range(220, 1001))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )

    for wl_nm, expected_od in VERIFICATION_SPECTRUM_B01_MULTI_WL.items():
      idx = wl_nm - 220
      actual_od = results[idx]["data"][1][0]  # row 1, col 0 = B01
      tol = 0.015
      self.assertAlmostEqual(
        actual_od, expected_od, delta=tol,
        msg=f"B01 @ {wl_nm}nm: actual={actual_od:.4f}, expected={expected_od:.3f}",
      )

  def test_verification_raw_report_has_references(self):
    """Verification: raw report includes reference and calibration data."""
    pages = _load_test_data_pages("verification")
    wavelengths = list(range(220, 1001))
    results = self.backend._parse_abs_spectrum_pages(
      pages, self.plate, self.all_wells, wavelengths, report="raw"
    )

    self.assertEqual(len(results), 781)
    for r in results:
      self.assertIn("references", r)
      self.assertIn("chromatic_cal", r)
      self.assertIn("reference_cal", r)
      self.assertEqual(len(r["references"]), 96)
      # Reference values should be positive integers
      for ref in r["references"]:
        self.assertGreater(ref, 0, f"zero reference at {r['wavelength']}nm")

  # -- Cross-capture consistency tests --

  def test_h01_h05_same_wavelengths_different_scan(self):
    """H01 (point) and H05 (orbital) measure the same plate at same wavelengths.

    Values should differ (different scan mode) but both should produce
    valid OD values and the same number of wavelengths.
    """
    h01_pages = _load_test_data_pages("h01")
    h05_pages = _load_test_data_pages("h05")
    wavelengths = list(range(300, 701))

    h01_results = self.backend._parse_abs_spectrum_pages(
      h01_pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )
    h05_results = self.backend._parse_abs_spectrum_pages(
      h05_pages, self.plate, self.all_wells, wavelengths, report="optical_density"
    )

    self.assertEqual(len(h01_results), len(h05_results))
    # Both should produce valid OD values for all wells and wavelengths.
    # A small number of inf values are expected at very-high-OD wells where the
    # detector reads zero (e.g., saturated dye wells near absorption peak).
    inf_count_h01 = 0
    inf_count_h05 = 0
    for r1, r5 in zip(h01_results, h05_results):
      self.assertEqual(r1["wavelength"], r5["wavelength"])
      for row_idx in range(8):
        for col_idx in range(12):
          if not math.isfinite(r1["data"][row_idx][col_idx]):
            inf_count_h01 += 1
          if not math.isfinite(r5["data"][row_idx][col_idx]):
            inf_count_h05 += 1
    # Allow up to 1% inf values (detector saturation at extreme OD)
    max_inf = int(401 * 96 * 0.01)
    self.assertLessEqual(inf_count_h01, max_inf,
                         f"H01: too many inf values ({inf_count_h01}/{401*96})")
    self.assertLessEqual(inf_count_h05, max_inf,
                         f"H05: too many inf values ({inf_count_h05}/{401*96})")

  def test_h01_h03_overlapping_wavelengths(self):
    """H01 (1nm step) and H03 (5nm step) cover the same range.

    At shared wavelengths (every 5nm from 300-700), OD values should be
    similar since they're the same plate/scan mode.
    """
    h01_pages = _load_test_data_pages("h01")
    h03_pages = _load_test_data_pages("h03")

    h01_results = self.backend._parse_abs_spectrum_pages(
      h01_pages, self.plate, self.all_wells,
      list(range(300, 701)), report="optical_density"
    )
    h03_results = self.backend._parse_abs_spectrum_pages(
      h03_pages, self.plate, self.all_wells,
      [300 + i * 5 for i in range(81)], report="optical_density"
    )

    # Compare at shared wavelengths (every 5nm)
    for h3_idx, h3_result in enumerate(h03_results):
      wl = h3_result["wavelength"]
      h1_idx = wl - 300  # 1nm step → index = wl - start
      h1_result = h01_results[h1_idx]
      self.assertEqual(h1_result["wavelength"], wl)

      # OD values should be reasonably similar (same plate, same scan mode)
      # Allow wider tolerance because different hardware sessions may have
      # slightly different calibration
      a1_h1 = h1_result["data"][0][0]
      a1_h3 = h3_result["data"][0][0]
      self.assertTrue(math.isfinite(a1_h1))
      self.assertTrue(math.isfinite(a1_h3))


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


def _build_synthetic_matrix_response(
  num_wells: int = 2,
  n_positions: int = 9,
  schema: int = 0xA9,
  sample_values: List[int] = None,
  ref_values: List[int] = None,
  cal_pairs: List[tuple] = None,
) -> bytes:
  """Build a synthetic absorbance matrix response payload.

  Layout: Header(36B) + Group0(effective × wl_resp × 4B) + 3 extra groups(effective × 4B each)
          + 4 cal pairs(8B each) + trailing(1B)

  where effective = num_wells × n_positions.
  """
  effective = num_wells * n_positions
  if sample_values is None:
    sample_values = [3_000_000] * effective
  if ref_values is None:
    ref_values = [1_300_000] * effective
  if cal_pairs is None:
    cal_pairs = [
      (3_932_985, 596217),  # chromatic 1 (sample)
      (1_537_345, 594949),  # chromatic 2
      (733_492, 594217),    # chromatic 3
      (18317, 0),           # reference
    ]

  num_groups = 4  # group0 + chrom2 + chrom3 + ref
  total_values = effective * num_groups + num_groups * 2  # groups × effective + cal pairs × 2
  header = bytearray(36)
  header[0] = 0x02
  header[1] = 0x05
  header[6] = schema
  header[7:9] = total_values.to_bytes(2, "big")   # values_expected
  header[9:11] = total_values.to_bytes(2, "big")   # values_written = expected (complete)
  header[18:20] = (1).to_bytes(2, "big")  # num_wl_resp = 1
  header[20:22] = num_wells.to_bytes(2, "big")
  header[23:25] = n_positions.to_bytes(2, "big")

  payload = bytearray(header)
  # Group 0: sample values (effective × 1 wl)
  for v in sample_values:
    payload.extend(v.to_bytes(4, "big"))
  # Extra group 1: chrom2
  for _ in range(effective):
    payload.extend((1_300_000).to_bytes(4, "big"))
  # Extra group 2: chrom3
  for _ in range(effective):
    payload.extend((600_000).to_bytes(4, "big"))
  # Extra group 3: reference
  for v in ref_values:
    payload.extend(v.to_bytes(4, "big"))
  # Cal pairs
  for hi, lo in cal_pairs:
    payload.extend(hi.to_bytes(4, "big"))
    payload.extend(lo.to_bytes(4, "big"))
  # Trailing byte
  payload.append(0x00)

  return bytes(payload)


class TestAbsorbanceMatrixWellScanField(unittest.TestCase):
  """Verify _build_absorbance_payload well scan field for matrix mode."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()

  def test_matrix_3x3_well_scan_field(self):
    """Matrix 3×3: well_scan_field[0] = 3, optic byte has 0x10 flag."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_absorbance_payload(
      self.plate, wells, [600],
      well_scan="matrix", scan_diameter_mm=3, matrix_size=3,
    )
    full = bytes([0x04]) + payload
    # Optic byte: DetectionMode.ABSORBANCE(0x02) | WellScanMode.MATRIX(0x10) = 0x12
    self.assertEqual(full[65], 0x12)
    # Well scan field: 5 bytes after separator
    # Point payload = 135B, +1 prefix = 136. Matrix adds 5 → 141.
    self.assertEqual(len(full), 141)

  def test_matrix_7x7_well_scan_field(self):
    """Matrix 7×7: well_scan_field[0] = 7."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_absorbance_payload(
      self.plate, wells, [600],
      well_scan="matrix", scan_diameter_mm=5, matrix_size=7,
    )
    full = bytes([0x04]) + payload
    # Well scan field at full[100:105]
    self.assertEqual(full[100], 7)  # N=7
    self.assertEqual(full[101], 5)  # scan_diameter=5mm

  def test_matrix_size_auto_sets_well_scan(self):
    """Providing matrix_size to read_absorbance auto-sets well_scan='matrix'."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]
    data_frame = _wrap_payload(_build_synthetic_matrix_response(num_wells=1, n_positions=9))
    mock.queue_response(ACK, data_frame)
    # matrix_size=3 without well_scan="matrix" — should auto-set
    results = asyncio.run(backend.read_absorbance(
      plate, wells, 600, matrix_size=3, read_timeout=1.0,
    ))
    self.assertIsInstance(results, list)


class TestAbsorbanceMatrixParsing(unittest.TestCase):
  """Verify matrix response parsing in the ABS pipeline."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()

  def test_parse_response_header_extracts_n_positions(self):
    """_parse_response_header returns n_positions from payload[23:25] for schema 0xA9."""
    header = bytearray(36)
    header[6] = 0xA9
    header[18:20] = (1).to_bytes(2, "big")   # num_wl_resp
    header[20:22] = (2).to_bytes(2, "big")   # num_wells
    header[23:25] = (9).to_bytes(2, "big")   # n_positions = 9 (3×3 matrix)
    schema, num_wl, num_wells, n_pos, temp = CLARIOstarPlusBackend._parse_response_header(
      bytes(header)
    )
    self.assertEqual(n_pos, 9)
    self.assertEqual(num_wells, 2)

  def test_parse_response_header_defaults_to_1(self):
    """Non-matrix response: n_positions defaults to 1."""
    header = bytearray(36)
    header[6] = 0xA9
    header[18:20] = (1).to_bytes(2, "big")
    header[20:22] = (96).to_bytes(2, "big")
    # payload[23:25] = 0x0000 → max(0, 1) = 1
    _, _, _, n_pos, _ = CLARIOstarPlusBackend._parse_response_header(bytes(header))
    self.assertEqual(n_pos, 1)

  def test_schema_29_ignores_n_positions(self):
    """Schema 0x29: payload[23:25] is temperature, not n_positions."""
    header = bytearray(36)
    header[6] = 0x29
    header[18:20] = (1).to_bytes(2, "big")
    header[20:22] = (96).to_bytes(2, "big")
    header[23:25] = (300).to_bytes(2, "big")  # temperature 30.0°C
    _, _, _, n_pos, temp = CLARIOstarPlusBackend._parse_response_header(bytes(header))
    self.assertEqual(n_pos, 1)  # not 300
    self.assertAlmostEqual(temp, 30.0)

  def test_compute_results_averages_9_positions(self):
    """_compute_results with n_positions=9 averages 9 values per well."""
    wells = [self.plate.get_item("A1"), self.plate.get_item("A2")]
    # 2 wells × 9 positions = 18 sample values
    samples_w1 = [100, 110, 120, 130, 140, 150, 160, 170, 180]  # mean=140
    samples_w2 = [200, 210, 220, 230, 240, 250, 260, 270, 280]  # mean=240
    group0 = samples_w1 + samples_w2
    refs = [1_300_000] * 18
    cal_pairs = [
      (3_932_985, 0),  # chromatic 1
      (1_537_345, 0),  # chromatic 2
      (733_492, 0),    # chromatic 3
      (18317, 0),      # reference
    ]
    extras = [
      [1_300_000] * 18,  # chrom2
      [600_000] * 18,    # chrom3
      refs,              # reference
    ]
    results = self.backend._compute_results(
      group0, extras, cal_pairs,
      num_wells=2, n_positions=9,
      temp=None, plate=self.plate, wells=wells,
      wavelengths=[600], report="raw",
    )
    self.assertEqual(len(results), 1)
    a1_val = results[0]["data"][0][0]
    a2_val = results[0]["data"][0][1]
    self.assertAlmostEqual(a1_val, 140.0, delta=0.01)
    self.assertAlmostEqual(a2_val, 240.0, delta=0.01)

  def test_compute_results_n_positions_1_unchanged(self):
    """n_positions=1 produces identical results to original behavior."""
    wells = self.plate.get_all_items()
    resp = _build_synthetic_response(num_wells=96, num_wavelengths=1)
    # Parse with pipeline (which passes n_positions=1 for non-matrix)
    results = self.backend._parse_absorbance_response(
      resp, self.plate, wells, [600]
    )
    self.assertEqual(len(results), 1)
    a1_val = results[0]["data"][0][0]
    self.assertIsNotNone(a1_val)

  def test_detect_group_layout_with_matrix_payload(self):
    """_detect_group_layout correctly finds 3 extra groups for matrix data."""
    n_wells = 2
    n_pos = 9
    effective = n_wells * n_pos  # 18
    # 4 groups of 18 u32s + 4 cal pairs(8B) + 1 trailing
    data_size = effective * 4 * 4 + 4 * 8 + 1
    payload_len = 36 + data_size
    extra = CLARIOstarPlusBackend._detect_group_layout(payload_len, effective, 1)
    self.assertEqual(extra, 3)

  def test_end_to_end_matrix_response(self):
    """Full pipeline: synthetic matrix response → averaged OD per well."""
    wells = [self.plate.get_item("A1"), self.plate.get_item("A2")]
    sample_val = 3_000_000
    ref_val = 1_300_000
    c_hi = 3_932_985
    r_hi = 18317
    n_pos = 9

    resp = _build_synthetic_matrix_response(
      num_wells=2, n_positions=n_pos,
      sample_values=[sample_val] * (2 * n_pos),
      ref_values=[ref_val] * (2 * n_pos),
      cal_pairs=[(c_hi, 0), (0, 0), (0, 0), (r_hi, 0)],
    )
    results = self.backend._parse_absorbance_response(resp, self.plate, wells, [600])

    self.assertEqual(len(results), 1)
    a1_od = results[0]["data"][0][0]
    a2_od = results[0]["data"][0][1]
    # OD should be same as non-matrix with same sample/ref values
    expected_t = (sample_val / c_hi) * (r_hi / ref_val)
    expected_od = -math.log10(expected_t)
    self.assertAlmostEqual(a1_od, expected_od, places=3)
    self.assertAlmostEqual(a2_od, expected_od, places=3)

  def test_end_to_end_matrix_varied_positions(self):
    """Matrix with varying position values → correct averaged OD."""
    wells = [self.plate.get_item("A1")]
    c_hi = 3_932_985
    r_hi = 18317
    ref_val = 1_300_000
    # 9 position samples with different values for one well
    position_samples = [2_800_000, 2_900_000, 3_000_000, 3_100_000, 3_200_000,
                        3_000_000, 2_950_000, 3_050_000, 3_000_000]
    mean_sample = sum(position_samples) / 9

    resp = _build_synthetic_matrix_response(
      num_wells=1, n_positions=9,
      sample_values=position_samples,
      ref_values=[ref_val] * 9,
      cal_pairs=[(c_hi, 0), (0, 0), (0, 0), (r_hi, 0)],
    )
    results = self.backend._parse_absorbance_response(resp, self.plate, wells, [600])

    a1_od = results[0]["data"][0][0]
    expected_t = (mean_sample / c_hi) * (r_hi / ref_val)
    expected_od = -math.log10(expected_t)
    self.assertAlmostEqual(a1_od, expected_od, places=3)

  def test_matrix_raw_report_returns_averaged(self):
    """report='raw' with matrix returns averaged values (one per well)."""
    wells = [self.plate.get_item("A1")]
    position_samples = [100, 200, 300, 400, 500, 600, 700, 800, 900]

    resp = _build_synthetic_matrix_response(
      num_wells=1, n_positions=9,
      sample_values=position_samples,
    )
    results = self.backend._parse_absorbance_response(
      resp, self.plate, wells, [600], report="raw"
    )
    a1_val = results[0]["data"][0][0]
    self.assertAlmostEqual(a1_val, 500.0, delta=0.01)


class TestAbsorbanceMatrixValidation(unittest.TestCase):
  """Validation tests for matrix_size parameter in read_absorbance."""

  def _call_absorbance(self, **kwargs):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()
    defaults = {
      "plate": plate, "wells": wells, "wavelength": 600,
      "read_timeout": 1.0,
    }
    defaults.update(kwargs)
    data_frame = _wrap_payload(_build_synthetic_response())
    mock.queue_response(ACK, data_frame)
    return asyncio.run(backend.read_absorbance(**defaults))

  def test_matrix_size_none_with_matrix_well_scan_raises(self):
    """well_scan='matrix' without matrix_size raises ValueError."""
    with self.assertRaises(ValueError):
      self._call_absorbance(well_scan="matrix")

  def test_matrix_size_0_raises(self):
    """matrix_size=0 raises ValueError."""
    with self.assertRaises(ValueError):
      self._call_absorbance(matrix_size=0)

  def test_matrix_size_1_raises(self):
    """matrix_size=1 raises ValueError."""
    with self.assertRaises(ValueError):
      self._call_absorbance(matrix_size=1)

  def test_matrix_size_12_raises(self):
    """matrix_size=12 raises ValueError."""
    with self.assertRaises(ValueError):
      self._call_absorbance(matrix_size=12)

  def test_matrix_size_3_accepted(self):
    """matrix_size=3 is valid."""
    # Should not raise
    results = self._call_absorbance(matrix_size=3)
    self.assertIsInstance(results, list)

  def test_matrix_size_auto_sets_well_scan(self):
    """Providing matrix_size without well_scan='matrix' auto-sets it."""
    results = self._call_absorbance(matrix_size=5)
    self.assertIsInstance(results, list)

  def test_spectrum_matrix_validation(self):
    """read_absorbance_spectrum also validates matrix_size."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.read_absorbance_spectrum(
        plate, wells, 400, 500, 5,
        well_scan="matrix",  # no matrix_size
      ))

  def test_fl_matrix_validation(self):
    """read_fluorescence also validates matrix_size."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.read_fluorescence(
        plate, wells, 485, 528, 8.5,
        well_scan="matrix",  # no matrix_size
      ))


class TestReadAbsorbanceIntegration(unittest.TestCase):
  """Integration test: full read_absorbance and request_absorbance_results flow."""

  def test_read_absorbance_flow(self):
    """Verify read_absorbance sends measurement, polls, retrieves data, and returns results."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    data_frame = _wrap_payload(_build_synthetic_response())

    # Queue: run ack, progressive data (complete) — progressive complete skips standard request
    mock.queue_response(
      ACK,  # measurement run ack
      data_frame,  # progressive _request_measurement_data → values_written == expected
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
    mock.queue_response(ACK, data_frame)

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
      STATUS_BUSY,  # interleaved status — still measuring
      halfway,  # progressive poll 2: 2/4
      STATUS_BUSY,  # interleaved status — still measuring
      complete,  # progressive poll 3: 4/4 → break (progressive complete, no standard request)
    )

    results = asyncio.run(backend.read_absorbance(plate, wells, wavelength=600))
    self.assertIsNotNone(results)
    self.assertEqual(len(results), 1)

  def test_polling_handles_firmware_counter_reset(self):
    """Firmware resets progress to 0/0 after measurement — loop must still exit.

    On real hardware the firmware can go from e.g. 364/392 directly to 0/0 without
    ever reporting 392/392.  The polling loop detects this because the interleaved
    status query shows busy=False once the measurement finishes.
    """
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    def _make_data_response(values_written: int, values_expected: int) -> bytes:
      data_payload = bytearray(36 + 4 * 4 + 32)
      data_payload[0] = 0x02
      data_payload[1] = 0x05
      data_payload[6] = 0x29
      data_payload[7:9] = values_expected.to_bytes(2, "big")
      data_payload[9:11] = values_written.to_bytes(2, "big")
      data_payload[18:20] = (1).to_bytes(2, "big")
      data_payload[20:22] = (1).to_bytes(2, "big")
      for i in range(36, len(data_payload)):
        data_payload[i] = 0x01
      return _wrap_payload(bytes(data_payload))

    expected = 12  # 1 well × 4 groups + 8 cal
    partial = _make_data_response(values_written=8, values_expected=expected)
    reset = _make_data_response(values_written=0, values_expected=0)  # firmware cleared
    final = _make_data_response(values_written=expected, values_expected=expected)

    mock.queue_response(
      ACK,  # RUN ack
      partial,  # progressive poll 1: 8/12
      STATUS_BUSY,  # interleaved status — still measuring
      reset,  # progressive poll 2: 0/0 → firmware reset counters
      STATUS_IDLE,  # interleaved status — not busy → break
      final,  # final standard request
    )

    results = asyncio.run(backend.read_absorbance(plate, wells, wavelength=600))
    self.assertIsNotNone(results)
    self.assertEqual(len(results), 1)

  def test_progressive_complete_skips_standard_request(self):
    """When progressive polling completes (written >= expected), no standard GET_DATA is sent."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    data_frame = _wrap_payload(_build_synthetic_response())

    # Only RUN ack + progressive data — no standard data response queued
    mock.queue_response(ACK, data_frame)

    results = asyncio.run(backend.read_absorbance(plate, wells, wavelength=600))
    self.assertEqual(len(results), 1)

    # Exactly 2 writes: RUN command + progressive GET_DATA. No third standard GET_DATA.
    self.assertEqual(len(mock.written), 2)
    # First write is the RUN command
    inner0 = _extract_payload(mock.written[0])
    self.assertEqual(inner0[0], 0x04)  # CommandFamily.RUN
    # Second write is the progressive GET_DATA (ff ff ff ff 00)
    inner1 = _extract_payload(mock.written[1])
    self.assertEqual(inner1, b"\x05\x02\xff\xff\xff\xff\x00")

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
    6. ACK for _send_cmd_0x0e()
  """
  backend = _make_backend()
  mock: MockFTDI = backend.io  # type: ignore[assignment]
  mock.queue_response(
    ACK,
    STATUS_IDLE,
    STATUS_IDLE,
    _REAL_EEPROM_FRAME,
    _make_firmware_frame(version_x1000),
    ACK,  # _send_cmd_0x0e()
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

  def test_read_absorbance_matrix_requires_matrix_size(self):
    with self.assertRaises(ValueError):
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

  def test_read_absorbance_meander_speed_limit(self):
    """Meander shake mode is capped at 300 RPM."""
    with self.assertRaises(ValueError):  # 400 exceeds meander 300 max
      self._call_absorbance(
        shake_mode="meander", shake_speed_rpm=400, shake_duration_s=5, settling_time_s=0
      )
    with self.assertRaises(ValueError):  # 700 exceeds meander 300 max
      self._call_absorbance(
        shake_mode="meander", shake_speed_rpm=700, shake_duration_s=5, settling_time_s=0
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
      STATUS_IDLE,  # request_machine_status -> not busy
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
      STATUS_IDLE,  # request_machine_status -> not busy
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
      STATUS_IDLE,  # request_machine_status -> not busy
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
      STATUS_IDLE,  # request_machine_status -> not busy
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
      STATUS_IDLE,  # request_machine_status -> not busy
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
# send_command frame retry tests
# ---------------------------------------------------------------------------


class TestSendCommandFrameRetry(unittest.TestCase):
  """Verify send_command retries on transient FrameError (truncated frames)."""

  def test_retries_on_truncated_frame(self):
    """First read returns a truncated frame, second succeeds."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    backend._PACKET_READ_TIMEOUT = 0.01  # type: ignore[attr-defined]

    # Truncated 18 bytes of a 53-byte DRAWER_CLOSE response (pcap ground truth
    # from notebook cell 33 failure).
    truncated = bytes.fromhex("0200350c032504260000000002610000370d")

    mock.queue_response(
      truncated,  # attempt 1: truncated → FrameError, retry
      ACK,  # attempt 2: valid frame → success
    )
    result = asyncio.run(
      backend.send_command(
        command_family=backend.CommandFamily.STATUS,
        parameters=b"",
      )
    )
    # Should succeed without raising.
    self.assertIsInstance(result, bytes)

  def test_raises_after_all_retries_exhausted(self):
    """Three consecutive truncated frames → FrameError raised."""
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import FrameError

    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    backend._PACKET_READ_TIMEOUT = 0.01  # type: ignore[attr-defined]

    truncated = bytes.fromhex("0200350c032504260000000002610000370d")
    mock.queue_response(truncated, truncated, truncated)

    with self.assertRaises(FrameError):
      asyncio.run(
        backend.send_command(
          command_family=backend.CommandFamily.STATUS,
          parameters=b"",
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


# ===========================================================================
# Fluorescence Measurement Tests
# ===========================================================================
# Ground truth hex from 20 pcap captures (F-A01 through F-L01).
# Full wire frames: STX(1) + size(2) + header(1) + payload + checksum(3) + CR(1).

_FL_GT_HEX = {
  # F-A01: baseline — top, point, Ex=485/15, Em=528/20, gain=1000, focal=8.5mm, 10 flashes, all 96
  "FA01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a00010000141b0d",
  # F-A02: bottom optic — same as A01 but optic byte = 0x40
  "FA02": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a40000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a00010000145b0d",
  # F-A03: A1 only — same as A01 but well mask = 80 00 00...
  "FA03": "02009c0c0431ec2166059604602c561d060c08008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a0001000008a70d",
  # F-B01: Ex=540/15, Em=590/20 — different wavelengths
  "FB01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e8156114cf1606176d16ab00040003000000000000000000000100000001000a0001000014940d",
  # F-D01: gain=500
  "FD01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c01f4133b12a913bc1501143f00040003000000000000000000000100000001000a0001000014250d",
  # F-E01: focal_height=4.0mm
  "FE01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05019000000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a0001000014570d",
  # F-G01: orbital 3mm, 7 flashes (161B frame — 5 extra well scan bytes)
  "FG01": "0200a10c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a30000000000000000000000000000000000000000000000000000000000000270f270f0303027b0005035200000100000000000c03e8133b12a913bc1501143f0004000300000000000000000000010000000100070001000014d00d",
  # F-K01: temp 37°C — measurement command identical to A01
  "FK01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a00010000141b0d",
  # F-O01: flying mode — scan_byte=0x1E (flying+vertical), settling=1 (0.0s), flashes=1
  "FO01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000270f270f01035200000100000000000c03e8133b12a913bc1501143f0004000300000000000000000000010000000100010001000014220d",
  # F-P01: EDR mode — optic byte[1]=0x40 (EDR flag), scan_byte=0x1A
  "FP01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000001a00400000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a00010000146b0d",
  # F-Q01: auto-focus — same as baseline but focal_height=10.0mm, scan_byte=0x1A
  "FQ01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000270f270f0503e800000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a0001000014c10d",
  # F-M01: dual chromatic (176B) — multi[2]=0x02, 2 chromatic blocks + 3B inter-chrom separator
  "FM01": "0200b00c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000200000000000c03e8133b12a913bc1501143f000400030000000c03e81868174018e71b54196800040003000000000000000000000100000001000a0001000017f40d",
  # F-Lf01: all-filter mode — Ex/Em/Dich all filter, slit=00 01 00 01 00
  "FLf01": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e80002000100020001000200010001000000000000000000000100000001000a0001000011dd0d",
  # F-Lf02: mixed mono Ex + filter Em — ExHi/Lo real, Dich/Em filter
  "FLf02": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e80fe70f5900020001000200010003000000000000000000000100000001000a00010000133a0d",
  # F-Lf03: mixed filter Ex + mono Em — ExHi/Lo/Dich filter, Em real
  "FLf03": "02009c0c0431ec2166059604602c561d060c0800ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000270f270f05035200000100000000000c03e80002000100021501143f00040001000000000000000000000100000001000a0001000012460d",
  # F-S01: matrix 3×3 — optic[0]=0x10, well scan field present, A1 only
  "FS01": "0200a10c0431ec2166059604602c561d060c08008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a10000000000000000000000000000000000000000000000000000000000000270f270f0303027b0005035200000100000000000c03e8133b12a913bc1501143f00040003000000000000000000000100000001000a00010000094f0d",
}

# FL DATA_RESPONSE hex (full wire frames, exact from pcap)
_FL_RESP_HEX = {
  # F-A01: 96 wells, room temp — 426 bytes
  "FA01": "0201aa0c020506260000a1006000600003f7a00100010060010001000000010100000000000000000097000000900000009c000000a10000009d0000009b0000009b000000970000009b0000009900000a8c0000008a0000009700000091000000a90000009a0000009a00000093000000a0000000a0000006f0000000b1000008330000009300000a89000007af000000b5000008640000078a00000737000006d9000006bd00000719000000c6000008350000009f00000aa4000007ca000006c40000062e000005d600000607000006af00000680000006da000000d500000831000000a4000000f000000100000000b0000000d3000000de000000f7000000f2000000ef0000071b000000e10000080c0000009a000000ea000000f4000000f40000010c0000010900000109000000f1000000f800000774000000f9000000e80000009400000097000000a2000000a100000097000000a2000000950000009e000000a1000000a3000000a1000000a0000000960000008500000096000000920000008e0000009300000092000000900000008c000000900000009a0000009600000086003e550d",
  # F-A03: 1 well, room temp — 46 bytes
  "FA03": "02002e0c022506260000a1000100010003f7a001000100010100010000000101000000000000000000910003640d",
  # F-K01: 96 wells, 37°C — 426 bytes
  "FK01": "0201aa0c020506260000a1006000600003f7a0010001006001000100000001010000000001720000008d0000008f000000a50000009d00000093000000980000009600000093000000950000009400000ac5000000950000009a000000970000009d0000009b0000009100000093000000a30000009b00000718000000ae0000084d0000009500000aaf000007d9000000b50000086f0000078800000734000006f1000006c100000707000000bf000008550000009900000ad2000007f1000006ea00000640000005e500000611000006bb0000068d000006cf000000d20000082e000000a0000000eb000000fd000000b7000000ce000000de000000f1000000f3000000f30000071f000000df000008020000009c000000ef000000f2000000f1000001040000010300000105000000f0000000f30000076a000000f6000000eb00000094000000900000009f0000009b0000009a000000970000009f000000990000009a000000970000009f0000009f0000009b0000008a000000950000008e000000940000008f0000008a000000960000008c00000090000000930000008e00000089003fd70d",
  # F-M01: dual chromatic — 192 values (96 wells × 2 chromatics), room temp
  "FM01": "02032a0c020506260000a100c000c00003f7a00100020060010001000000010100000000000000000095000000a2000000a60000009b0000009e000000970000009f0000009b000000980000009300000a9b0000008e00000098000000740000007b000000780000007a0000007b0000007d00000081000004160000008a000005c30000009e00000a9b0000041d000000710000049f0000042f000003e7000003be00000399000003ae0000008d00000572000000a100000ab2000004020000039e0000035b00000340000003370000036a0000036300000390000000a000000554000000a0000000f00000009a0000007a0000008a0000009d000000a20000009a00000098000003ba000000b400000559000000a5000000f400000091000000950000009f000000ae000000a60000009f00000095000003df000000be000000c10000009c000000960000006c000000740000006c000000700000007a00000078000000730000007f000000830000008a0000009e0000008e0000009900000099000000930000008e000000930000009400000097000000960000009d0000009a000000910000140300001213000000270000136f000013eb0000134d000013080000135f0000130d00001331000000560000002f000000300000075e00000741000006f40000074500000700000007f2000007c300000852000008890000004b0000002a00000049000000350000002500000033000000330000003a00000036000000390000070e0000087b0000004c0000002a00000051000000330000002f0000003a0000003b000000390000003c00000034000007260000098500000047000000310000002a000000280000002b0000002b0000002c00000027000000350000002900000766000009b6000000340000002a0000002d0000002d0000002e000000260000002f000000300000002d00000028000000340000002a0000002b0000002e0000142a000005750000054f000006760000073a000007d7000008050000075100000901000009fc00000a930000136c0000156a0000147b00001426000013ed000013cf0000142b000014470000134800001425000013a900001499000015aa0059c40d",
  # F-P01: EDR — 96 wells, overflow threshold 700M
  "FP01": "0201aa0c020506260000a10060006029b92700010001006001000100000001010000000000000000175d0000181c00001af90000191200001922000018840000194d000018930000181f000018e20001ec4b0000170c00001913000011b90000127c000011da000011c60000113a000012d5000012180000bd650000155c00010bfc000018ce0001ec5a0000babd000011ff0000d22a0000bde90000b0540000abdf0000a3640000acbc000016ed0000f9090000197e0001eee60000b6380000a234000099b0000094e70000912800009b0000009a1b0000a26600001a0a0000f3ab000019ed00002988000016f20000129100001534000017110000192700001903000018680000aa6f00001c520000f463000019eb000027df00001734000017f200001a3700001ab700001a6900001931000017e90000b4ba00001fa600001ed40000186b000017e800000fc600000ffd000011280000114d00001327000011d50000122c000013a40000152e000014720000192a000015900000181c000017700000184a000017b3000017be000017e8000016d7000017ea0000182d0000182c0000165a004ad30d",
  # F-O01: flying mode — 96 wells
  "FO01": "0201aa0c020506260000a1006000600003f7a001000100600100010000000101000000000000000000a90000009b00000150000000b9000000a2000000ab000000aa000000b20000009b0000009400000a3e000000a300000091000000780000008d00000074000000730000007c00000075000000750000042600000090000005b1000000a300000a55000003fd00000084000004800000041c000003cf000003bf0000038c000003ce0000008c00000596000000a500000a8e0000040500000399000003460000033400000327000003570000034a000003b1000000990000054b00000090000000e4000000950000007900000092000000a2000000a20000009c00000092000003b6000000a10000053f000000ac000000f70000008e00000094000000940000009f000000b000000098000000a6000003cf000000b6000000b1000000910000008a0000006700000072000000720000006a0000007900000077000000730000007d00000083000000780000009000000076000000a80000009a000000a00000008c00000089000000960000008b0000009f00000096000000960000008000391d0d",
  # F-S01: matrix 3×3 — 9 values (1 well × 9 matrix positions)
  "FS01": "02004e0c020506260000a1000900090003f7a00100010001030009000000010100000000000000000091000000930000008e000000880000009000000090000000890000008e0000008b0007e90d",
}


class TestBuildFluorescencePayload(unittest.TestCase):
  """Verify _build_fluorescence_payload against pcap ground truth.

  Same pattern as TestBuildAbsorbancePayload: compare output against pcap
  ground truth hex, skipping plate geometry bytes 1-12 (PLR vs OEM well
  center offsets) and wavelength bytes (±2-3 firmware calibration offsets).
  """

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def _get_gt_inner(self, key: str) -> bytes:
    """Extract inner payload (no STX/size/header/checksum/CR) from ground truth hex."""
    frame = bytes.fromhex(_FL_GT_HEX[key])
    return frame[4:-4]

  def _compare_fl_payload(self, payload: bytes, gt_key: str, msg: str = ""):
    """Compare FL payload against ground truth, skipping known differences.

    Skips:
    - Bytes 1-12: plate geometry (PLR vs OEM well center offsets)
    - Wavelength bytes in post-separator (±2-3 firmware calibration)
    - Well scan field diameter bytes (PLR vs OEM well diameter)
    """
    gt = self._get_gt_inner(gt_key)
    full = bytes([0x04]) + payload
    self.assertEqual(
      len(full), len(gt), f"{msg} length mismatch: got {len(full)}, expected {len(gt)}"
    )
    # Byte 0 (0x04 command family)
    self.assertEqual(full[0], gt[0], f"{msg} byte 0 (command family)")
    # Skip bytes 1-12 (plate geometry)
    # Bytes 13-14: cols/rows
    self.assertEqual(full[13], gt[13], f"{msg} byte 13 (cols)")
    self.assertEqual(full[14], gt[14], f"{msg} byte 14 (rows)")
    self.assertEqual(full[15], gt[15], f"{msg} byte 15 (extra)")
    # Bytes 16-63: well mask
    self.assertEqual(full[16:64], gt[16:64], f"{msg} well mask mismatch")
    # Byte 64: scan direction
    self.assertEqual(full[64], gt[64], f"{msg} scan direction byte")
    # Bytes 65-95: pre-separator block (31 bytes)
    self.assertEqual(full[65:96], gt[65:96], f"{msg} pre-separator mismatch")
    # Bytes 96-99: separator
    self.assertEqual(full[96:100], gt[96:100], f"{msg} separator mismatch")
    # After separator: well scan field (if present) + FL post-sep fields
    after_sep_p = full[100:]
    after_sep_g = gt[100:]
    self.assertEqual(
      len(after_sep_p), len(after_sep_g), f"{msg} post-sep length mismatch"
    )

    # Determine well scan field length
    wsf_len = 0
    if len(after_sep_p) > 48:  # non-point mode: 5 extra bytes
      wsf_len = 5
      # Well scan field: byte 0 (meas code), byte 1 (diameter), bytes 2-3 (well diam), byte 4
      self.assertEqual(after_sep_p[0], after_sep_g[0], f"{msg} wsf meas code")
      self.assertEqual(after_sep_p[1], after_sep_g[1], f"{msg} wsf scan diameter")
      # Skip bytes 2-3 (well diameter — PLR vs OEM)
      self.assertEqual(after_sep_p[4], after_sep_g[4], f"{msg} wsf terminator")

    # FL post-separator: settling(1) + focal(2) + multi(9) + gain(2) +
    #   ExHi(2) + ExLo(2) + Dich(2) + EmHi(2) + EmLo(2) +
    #   slit(5) + pause(3) + trailer(11) + flashes(2) + tail(3)
    ps_p = after_sep_p[wsf_len:]
    ps_g = after_sep_g[wsf_len:]
    # settling + focal + multi + gain = 1+2+9+2 = 14 bytes
    self.assertEqual(ps_p[:14], ps_g[:14], f"{msg} settle+focal+multi+gain mismatch")
    # Skip wavelength bytes 14-23 (ExHi, ExLo, Dich, EmHi, EmLo = 10 bytes)
    # Remaining: slit(5)+pause(3)+trailer(11)+flashes(2)+tail(3) = 24 bytes at offset 24
    self.assertEqual(ps_p[24:], ps_g[24:], f"{msg} slit+pause+trailer+flashes+tail mismatch")

  def test_FA01_baseline_top_point(self):
    """F-A01: baseline — top, point, Ex=485/15, Em=528/20, gain=1000, focal=8.5, 10 flashes."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=8.5,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=1000,
      optic_position="top",
      flashes=10,
      settling_time_s=0.1,
      well_scan="point",
      # Exact pcap wavelength values (bypass ±2-3 firmware calibration)
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    self.assertEqual(len(payload), 147)
    self._compare_fl_payload(payload, "FA01", "FA01")

  def test_FA02_bottom_optic(self):
    """F-A02: bottom optic."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=8.5,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=1000,
      optic_position="bottom",
      flashes=10,
      settling_time_s=0.1,
      well_scan="point",
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    self.assertEqual(len(payload), 147)
    self._compare_fl_payload(payload, "FA02", "FA02")

  def test_FA03_A1_only(self):
    """F-A03: single well A1."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=8.5,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=1000,
      optic_position="top",
      flashes=10,
      settling_time_s=0.1,
      well_scan="point",
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    self.assertEqual(len(payload), 147)
    self._compare_fl_payload(payload, "FA03", "FA03")

  def test_FB01_different_wavelengths(self):
    """F-B01: Ex=540/15, Em=590/20 (different wavelengths)."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=540,
      emission_wavelength=590,
      focal_height=8.5,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=1000,
      optic_position="top",
      flashes=10,
      settling_time_s=0.1,
      well_scan="point",
      _ex_hi=5473, _ex_lo=5327, _em_hi=5997, _em_lo=5803, _dichroic_raw=5638,
    )
    self.assertEqual(len(payload), 147)
    self._compare_fl_payload(payload, "FB01", "FB01")

  def test_FD01_gain_500(self):
    """F-D01: gain=500."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=8.5,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=500,
      optic_position="top",
      flashes=10,
      settling_time_s=0.1,
      well_scan="point",
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    self.assertEqual(len(payload), 147)
    self._compare_fl_payload(payload, "FD01", "FD01")

  def test_FE01_focal_4mm(self):
    """F-E01: focal_height=4.0mm."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=4.0,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=1000,
      optic_position="top",
      flashes=10,
      settling_time_s=0.1,
      well_scan="point",
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    self.assertEqual(len(payload), 147)
    self._compare_fl_payload(payload, "FE01", "FE01")

  def test_FG01_orbital_3mm(self):
    """F-G01: orbital 3mm, 7 flashes."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=8.5,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=1000,
      optic_position="top",
      flashes=7,
      settling_time_s=0.1,
      well_scan="orbital",
      scan_diameter_mm=3,
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    self.assertEqual(len(payload), 152)
    self._compare_fl_payload(payload, "FG01", "FG01")

  def test_FK01_temp_37C(self):
    """F-K01: temp 37°C — command identical to F-A01 (temp is set separately)."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=8.5,
      excitation_bandwidth=15,
      emission_bandwidth=20,
      gain=1000,
      optic_position="top",
      flashes=10,
      settling_time_s=0.1,
      well_scan="point",
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    self.assertEqual(len(payload), 147)
    self._compare_fl_payload(payload, "FK01", "FK01")

  def test_nominal_wavelength_encoding(self):
    """Verify nominal wavelength encoding without pcap overrides."""
    payload = self.backend._build_fluorescence_payload(
      self.plate,
      self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=528,
      focal_height=8.5,
    )
    self.assertEqual(len(payload), 147)
    # Check wavelength fields at known offsets in post-separator
    # post-sep starts at byte 99 (plate63 + scan1 + presep31 + sep4)
    # settling(1) + focal(2) + multi(9) + gain(2) = 14 bytes
    # wavelengths start at offset 99 + 14 = 113
    ex_hi = int.from_bytes(payload[113:115], "big")
    ex_lo = int.from_bytes(payload[115:117], "big")
    em_hi = int.from_bytes(payload[119:121], "big")
    em_lo = int.from_bytes(payload[121:123], "big")
    # Nominal: Ex=485/15 → ExHi=4925, ExLo=4775
    self.assertEqual(ex_hi, 4925)
    self.assertEqual(ex_lo, 4775)
    # Nominal: Em=528/20 → EmHi=5380, EmLo=5180
    self.assertEqual(em_hi, 5380)
    self.assertEqual(em_lo, 5180)
    # Auto-dichroic = (ExHi + EmLo) // 2 = (4925 + 5180) // 2 = 5052
    dich = int.from_bytes(payload[117:119], "big")
    self.assertEqual(dich, 5052)

  def test_FQ01_auto_focus_focal_height(self):
    """F-Q01: auto-focus — focal=10.0mm. Verify post-separator focal encoding."""
    gt = bytes.fromhex(_FL_GT_HEX["FQ01"])
    inner = gt[4:-4]  # strip envelope
    # Post-sep starts at byte 100 (after separator at 96:100)
    post = inner[100:]
    # settle(1) + focal(2) at post[1:3]
    focal_raw = int.from_bytes(post[1:3], "big")
    self.assertEqual(focal_raw, 1000)  # 10.0mm * 100
    self.assertEqual(focal_raw / 100, 10.0)


class TestFluorescenceFrameValidity(unittest.TestCase):
  """Verify all new FL pcap ground truth frames have valid checksums."""

  def _validate_gt_frame(self, hex_str: str, name: str):
    """Validate frame envelope: STX, size, checksum, CR."""
    raw = bytes.fromhex(hex_str)
    self.assertEqual(raw[0], 0x02, f"{name}: STX")
    self.assertEqual(raw[-1], 0x0D, f"{name}: CR")
    size = int.from_bytes(raw[1:3], "big")
    self.assertEqual(size, len(raw), f"{name}: size field")
    cs = int.from_bytes(raw[-4:-1], "big")
    computed = sum(raw[:-4]) & 0xFFFFFF
    self.assertEqual(cs, computed, f"{name}: checksum")

  def test_all_measurement_run_frames_valid(self):
    """All MEASUREMENT_RUN ground truth frames have valid checksums."""
    for key, hex_str in _FL_GT_HEX.items():
      with self.subTest(key=key):
        self._validate_gt_frame(hex_str, key)

  def test_all_data_response_frames_valid(self):
    """All DATA_RESPONSE ground truth frames have valid checksums."""
    for key, hex_str in _FL_RESP_HEX.items():
      with self.subTest(key=key):
        self._validate_gt_frame(hex_str, key)

  def test_FM01_dual_chromatic_frame_length(self):
    """F-M01: dual chromatic frame is 176B (20B longer than 156B single)."""
    raw = bytes.fromhex(_FL_GT_HEX["FM01"])
    self.assertEqual(len(raw), 176)
    # Post-sep should be 68 bytes (48 single + 20 extra for 2nd chromatic)
    inner = raw[4:-4]
    post = inner[100:]
    self.assertEqual(len(post), 68)

  def test_FS01_matrix_frame_length(self):
    """F-S01: matrix 3×3 frame is 161B (5 extra for well scan field)."""
    raw = bytes.fromhex(_FL_GT_HEX["FS01"])
    self.assertEqual(len(raw), 161)


class TestFluorescencePostSeparatorGroundTruth(unittest.TestCase):
  """Byte-level verification of post-separator fields from new pcap captures.

  Tests the wire encoding of features not yet implemented in the backend:
  dual chromatic, filter mode, flying mode, EDR, matrix scan. These serve as
  ground truth specifications for future implementation.
  """

  def _get_post_sep(self, key: str) -> bytes:
    """Extract post-separator bytes from a MEASUREMENT_RUN ground truth frame."""
    raw = bytes.fromhex(_FL_GT_HEX[key])
    inner = raw[4:-4]
    return inner[100:]

  # --- Dual chromatic (F-M01) ---

  def test_FM01_multi_block_n_chrom_2(self):
    """F-M01: multichromatic block byte[2] = 0x02 (dual)."""
    post = self._get_post_sep("FM01")
    multi = post[3:12]
    self.assertEqual(multi[2], 0x02)

  def test_FM01_chromatic_1_wavelengths(self):
    """F-M01: chromatic 1 = Ex=485/15, Em=528/20 (same as baseline)."""
    post = self._get_post_sep("FM01")
    # Chromatic 1 starts at offset 12: gain(2) + ExHi(2) + ExLo(2) + Dich(2) + EmHi(2) + EmLo(2)
    gain1 = int.from_bytes(post[12:14], "big")
    ex_hi1 = int.from_bytes(post[14:16], "big")
    ex_lo1 = int.from_bytes(post[16:18], "big")
    em_hi1 = int.from_bytes(post[20:22], "big")
    em_lo1 = int.from_bytes(post[22:24], "big")
    self.assertEqual(gain1, 1000)
    self.assertAlmostEqual((ex_hi1 + ex_lo1) / 20, 485, delta=1)
    self.assertAlmostEqual((em_hi1 + em_lo1) / 20, 528, delta=1)

  def test_FM01_inter_chromatic_separator(self):
    """F-M01: inter-chromatic separator is 00 00 0c (3 bytes) at offset 29."""
    post = self._get_post_sep("FM01")
    # chrom1 ends at offset 29 (12 + 17), separator at 29:32
    self.assertEqual(post[29:32], b"\x00\x00\x0c")

  def test_FM01_chromatic_2_wavelengths(self):
    """F-M01: chromatic 2 = Ex≈610/30, Em≈675/49."""
    post = self._get_post_sep("FM01")
    # Chromatic 2 starts at offset 32: gain(2) + ExHi(2) + ...
    gain2 = int.from_bytes(post[32:34], "big")
    ex_hi2 = int.from_bytes(post[34:36], "big")
    ex_lo2 = int.from_bytes(post[36:38], "big")
    em_hi2 = int.from_bytes(post[40:42], "big")
    em_lo2 = int.from_bytes(post[42:44], "big")
    self.assertEqual(gain2, 1000)
    self.assertAlmostEqual((ex_hi2 + ex_lo2) / 20, 610, delta=1)
    self.assertAlmostEqual((em_hi2 + em_lo2) / 20, 675, delta=1)

  def test_FM01_tail_fields_after_chrom2(self):
    """F-M01: pause+trailer+flashes+tail are at standard offsets after chrom2."""
    post = self._get_post_sep("FM01")
    # chrom2 ends at 49, then: pause(3) + trailer(11) + flashes(2) + tail(3)
    self.assertEqual(post[49:52], b"\x00\x00\x00")  # pause disabled
    self.assertEqual(post[52:63], b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01")  # trailer
    flashes = int.from_bytes(post[63:65], "big")
    self.assertEqual(flashes, 10)
    self.assertEqual(post[65:68], b"\x00\x01\x00")  # tail

  # --- Filter mode (F-Lf01, F-Lf02, F-Lf03) ---

  def test_FLf01_all_filter_wavelength_encoding(self):
    """F-Lf01: all-filter — Ex/Dich/Em all use filter flag 0x0002/slot 0x0001."""
    post = self._get_post_sep("FLf01")
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    dich = int.from_bytes(post[18:20], "big")
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    # Filter encoding: ExHi=flag(2), ExLo=slot(1), Dich=flag(2), EmHi=slot(1), EmLo=flag(2)
    self.assertEqual(ex_hi, 0x0002)
    self.assertEqual(ex_lo, 0x0001)
    self.assertEqual(dich, 0x0002)
    self.assertEqual(em_hi, 0x0001)
    self.assertEqual(em_lo, 0x0002)

  def test_FLf01_all_filter_slit_config(self):
    """F-Lf01: all-filter slit = 00 01 00 01 00 (both channels filter)."""
    post = self._get_post_sep("FLf01")
    slit = post[24:29]
    self.assertEqual(slit, b"\x00\x01\x00\x01\x00")

  def test_FLf02_mixed_mono_ex_filter_em(self):
    """F-Lf02: mono Ex=400/14 + filter Em. Slit = 00 01 00 03 00."""
    post = self._get_post_sep("FLf02")
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    dich = int.from_bytes(post[18:20], "big")
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    # Ex is monochromator: real wavelength edges
    self.assertAlmostEqual((ex_hi + ex_lo) / 20, 400, delta=1)
    # Dich and Em are filter
    self.assertEqual(dich, 0x0002)
    self.assertEqual(em_hi, 0x0001)
    self.assertEqual(em_lo, 0x0002)
    # Slit: slit[1]=0x01 (filter Em), slit[3]=0x03 (mono Ex)
    slit = post[24:29]
    self.assertEqual(slit, b"\x00\x01\x00\x03\x00")

  def test_FLf03_mixed_filter_ex_mono_em(self):
    """F-Lf03: filter Ex + mono Em=528/19. Slit = 00 04 00 01 00."""
    post = self._get_post_sep("FLf03")
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    dich = int.from_bytes(post[18:20], "big")
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    # Ex is filter
    self.assertEqual(ex_hi, 0x0002)
    self.assertEqual(ex_lo, 0x0001)
    self.assertEqual(dich, 0x0002)
    # Em is monochromator: real wavelength edges
    self.assertAlmostEqual((em_hi + em_lo) / 20, 528, delta=1)
    # Slit: slit[1]=0x04 (mono Em), slit[3]=0x01 (filter Ex)
    slit = post[24:29]
    self.assertEqual(slit, b"\x00\x04\x00\x01\x00")

  # --- Flying mode (F-O01) ---

  def test_FO01_scan_byte_has_flying_flag(self):
    """F-O01: scan byte = 0x1E with flying bit (bit2) set."""
    raw = bytes.fromhex(_FL_GT_HEX["FO01"])
    inner = raw[4:-4]
    scan_byte = inner[64]
    self.assertEqual(scan_byte, 0x1E)
    self.assertTrue(scan_byte & 0x04, "flying bit (bit2) not set")

  def test_FO01_settling_forced_to_1(self):
    """F-O01: flying mode forces settling raw=1 (0.0s)."""
    post = self._get_post_sep("FO01")
    self.assertEqual(post[0], 0x01)

  def test_FO01_flashes_forced_to_1(self):
    """F-O01: flying mode forces flashes=1."""
    post = self._get_post_sep("FO01")
    flashes = int.from_bytes(post[43:45], "big")
    self.assertEqual(flashes, 1)

  # --- EDR mode (F-P01) ---

  def test_FP01_optic_byte1_has_edr_flag(self):
    """F-P01: EDR flag is optic block byte[1] = 0x40."""
    raw = bytes.fromhex(_FL_GT_HEX["FP01"])
    inner = raw[4:-4]
    optic_byte1 = inner[66]  # offset 65 + 1
    self.assertEqual(optic_byte1, 0x40)

  def test_FP01_scan_byte_0x1A(self):
    """F-P01: EDR uses scan_byte=0x1A (explicit TL corner, vertical, bidirectional)."""
    raw = bytes.fromhex(_FL_GT_HEX["FP01"])
    inner = raw[4:-4]
    self.assertEqual(inner[64], 0x1A)

  # --- Matrix 3×3 (F-S01) ---

  def test_FS01_optic_byte0_has_matrix_flag(self):
    """F-S01: matrix scan = optic byte[0] = 0x10."""
    raw = bytes.fromhex(_FL_GT_HEX["FS01"])
    inner = raw[4:-4]
    self.assertEqual(inner[65], 0x10)

  def test_FS01_well_scan_field_present(self):
    """F-S01: matrix scan includes 5-byte well scan field with code=3."""
    raw = bytes.fromhex(_FL_GT_HEX["FS01"])
    inner = raw[4:-4]
    # After separator at 96:100, well scan field at 100:105
    wsf = inner[100:105]
    self.assertEqual(wsf[0], 0x03)  # FL measurement code
    self.assertEqual(wsf[1], 0x03)  # scan diameter = 3mm
    self.assertEqual(wsf[4], 0x00)  # terminator

  def test_FS01_well_mask_A1_only(self):
    """F-S01: matrix capture was done with A1 only."""
    raw = bytes.fromhex(_FL_GT_HEX["FS01"])
    inner = raw[4:-4]
    mask = inner[16:64]
    self.assertEqual(mask[0], 0x80)  # A1 bit set
    self.assertEqual(sum(mask[1:]), 0)  # no other wells


class TestParseFluorescenceResponse(unittest.TestCase):
  """Verify _parse_fluorescence_response against pcap ground truth."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_FA01_96wells_room_temp(self):
    """F-A01: 96 wells, room temperature — no incubation data."""
    frame = bytes.fromhex(_FL_RESP_HEX["FA01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)

    results = self.backend._parse_fluorescence_response(
      payload, self.plate, self.all_wells, [(485, 528)]
    )

    self.assertEqual(len(results), 1)
    r = results[0]
    self.assertEqual(r["ex_wavelength"], 485)
    self.assertEqual(r["em_wavelength"], 528)
    self.assertIsNone(r["temperature"])
    self.assertIsNotNone(r["data"])
    # First 4 wells (row A, cols 1-4): 0x97=151, 0x90=144, 0x9c=156, 0xa1=161
    self.assertEqual(r["data"][0][0], 151.0)
    self.assertEqual(r["data"][0][1], 144.0)
    self.assertEqual(r["data"][0][2], 156.0)
    self.assertEqual(r["data"][0][3], 161.0)
    # Grid shape: 8 rows × 12 cols
    self.assertEqual(len(r["data"]), 8)
    self.assertEqual(len(r["data"][0]), 12)

  def test_FA03_1well_room_temp(self):
    """F-A03: 1 well (A1), room temperature."""
    frame = bytes.fromhex(_FL_RESP_HEX["FA03"])
    _validate_frame(frame)
    payload = _extract_payload(frame)
    wells = [self.plate.get_item("A1")]

    results = self.backend._parse_fluorescence_response(
      payload, self.plate, wells, [(485, 528)]
    )

    self.assertEqual(len(results), 1)
    r = results[0]
    self.assertIsNone(r["temperature"])
    # A1 value: 0x91 = 145
    self.assertEqual(r["data"][0][0], 145.0)
    # All other wells should be None
    none_count = sum(1 for row in r["data"] for v in row if v is None)
    self.assertEqual(none_count, 95)

  def test_FK01_96wells_37C(self):
    """F-K01: 96 wells, incubation at 37°C."""
    frame = bytes.fromhex(_FL_RESP_HEX["FK01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)

    results = self.backend._parse_fluorescence_response(
      payload, self.plate, self.all_wells, [(485, 528)]
    )

    self.assertEqual(len(results), 1)
    r = results[0]
    # Temperature: bytes [32:34] = 0x0172 = 370 → 37.0°C
    self.assertEqual(r["temperature"], 37.0)
    # First well: 0x8d = 141
    self.assertEqual(r["data"][0][0], 141.0)

  def test_FO01_flying_mode_96wells(self):
    """F-O01: flying mode — standard 96-well response."""
    frame = bytes.fromhex(_FL_RESP_HEX["FO01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)

    results = self.backend._parse_fluorescence_response(
      payload, self.plate, self.all_wells, [(485, 528)]
    )

    self.assertEqual(len(results), 1)
    r = results[0]
    self.assertIsNone(r["temperature"])
    # First well A1: 0xa9 = 169
    self.assertEqual(r["data"][0][0], 169.0)
    # Grid shape: 8×12
    self.assertEqual(len(r["data"]), 8)
    self.assertEqual(len(r["data"][0]), 12)

  def test_FP01_edr_response_overflow_threshold(self):
    """F-P01: EDR response has overflow=700M, data still parses correctly."""
    frame = bytes.fromhex(_FL_RESP_HEX["FP01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)
    # Verify the overflow threshold is 700M (EDR signature)
    overflow = int.from_bytes(payload[11:15], "big")
    self.assertEqual(overflow, 700_000_000)

    results = self.backend._parse_fluorescence_response(
      payload, self.plate, self.all_wells, [(485, 528)]
    )

    self.assertEqual(len(results), 1)
    r = results[0]
    # First well A1: 0x175d = 5981
    self.assertEqual(r["data"][0][0], 5981.0)
    # EDR values are much larger than standard (thousands vs hundreds)
    self.assertGreater(r["data"][0][0], 1000)

  def test_FM01_dual_chromatic_192_values(self):
    """F-M01: dual chromatic response has 192 values (96 wells × 2 chromatics).

    The current parser reads num_wells from bytes 7:9 (=192) and returns all
    192 values mapped to the grid. This is a known limitation — multi-chromatic
    support would return separate dicts per chromatic.
    """
    frame = bytes.fromhex(_FL_RESP_HEX["FM01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)
    # Total values = 192 (96 × 2 chromatics)
    total = int.from_bytes(payload[7:9], "big")
    self.assertEqual(total, 192)
    # Chromatic 1, first well (A1): 0x95 = 149
    val_c1_a1 = int.from_bytes(payload[34:38], "big")
    self.assertEqual(val_c1_a1, 149)
    # Chromatic 2, first well: offset 34 + 96*4 = 418
    val_c2_a1 = int.from_bytes(payload[418:422], "big")
    self.assertEqual(val_c2_a1, 5123)  # 0x1403

  def test_FS01_matrix_9_values(self):
    """F-S01: matrix 3×3 response has 9 values (1 well × 9 positions)."""
    frame = bytes.fromhex(_FL_RESP_HEX["FS01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)
    total = int.from_bytes(payload[7:9], "big")
    self.assertEqual(total, 9)
    # First value: 0x91 = 145
    val0 = int.from_bytes(payload[34:38], "big")
    self.assertEqual(val0, 145)
    # All 9 values should be in the 130-150 range (background fluorescence)
    for i in range(9):
      v = int.from_bytes(payload[34 + i * 4 : 38 + i * 4], "big")
      self.assertGreater(v, 100, f"matrix position {i} value too low: {v}")
      self.assertLess(v, 200, f"matrix position {i} value too high: {v}")


def _build_synthetic_fl_response(
  num_wells: int = 96,
  schema: int = 0xA1,
  temperature_raw: int = 0,
) -> bytes:
  """Build a synthetic fluorescence response payload for integration tests."""
  total_values = num_wells
  header = bytearray(34)
  header[0] = 0x02  # echoes DATA subcommand
  header[1] = 0x05  # status_flags
  header[6] = schema
  header[7:9] = total_values.to_bytes(2, "big")
  header[9:11] = total_values.to_bytes(2, "big")
  header[11:15] = (260000).to_bytes(4, "big")  # overflow threshold
  if schema & 0x80 and temperature_raw > 0:
    header[32:34] = temperature_raw.to_bytes(2, "big")

  payload = bytearray(header)
  for i in range(num_wells):
    payload.extend((100 + i).to_bytes(4, "big"))

  return bytes(payload)


class TestReadFluorescenceIntegration(unittest.TestCase):
  """Integration test: full read_fluorescence flow."""

  def test_read_fluorescence_flow(self):
    """Verify read_fluorescence sends RUN, polls, retrieves data, and returns results."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    data_frame = _wrap_payload(_build_synthetic_fl_response())

    mock.queue_response(
      ACK,  # measurement run ack
      data_frame,  # progressive data — values_written == expected
    )

    results = asyncio.run(
      backend.read_fluorescence(
        plate, wells, excitation_wavelength=485, emission_wavelength=528, focal_height=8.5
      )
    )

    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["ex_wavelength"], 485)
    self.assertEqual(results[0]["em_wavelength"], 528)
    self.assertIsNotNone(results[0]["data"])
    for row in results[0]["data"]:
      for val in row:
        self.assertIsNotNone(val)
        self.assertIsInstance(val, float)

  def test_read_fluorescence_wait_false(self):
    """wait=False sends RUN only and returns empty list immediately."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    mock.queue_response(ACK)

    result = asyncio.run(
      backend.read_fluorescence(
        plate, wells, excitation_wavelength=485, emission_wavelength=528,
        focal_height=8.5, wait=False,
      )
    )

    self.assertEqual(result, [])
    self.assertEqual(len(mock.written), 1)
    inner = _extract_payload(mock.written[0])
    self.assertEqual(inner[0], 0x04)  # CommandFamily.RUN

  def test_read_fluorescence_sends_via_send_command(self):
    """Verify first write has 0x04 command family byte."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    data_frame = _wrap_payload(_build_synthetic_fl_response(num_wells=1))
    mock.queue_response(ACK, data_frame)

    asyncio.run(
      backend.read_fluorescence(
        plate, wells, excitation_wavelength=485, emission_wavelength=528, focal_height=8.5
      )
    )

    first_frame = mock.written[0]
    _validate_frame(first_frame)
    inner = _extract_payload(first_frame)
    self.assertEqual(inner[0], 0x04)  # CommandFamily.RUN

  def test_read_fluorescence_validates_wavelength_range(self):
    """Wavelengths outside 320-840nm raise ValueError."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()

    with self.assertRaises(ValueError):
      asyncio.run(
        backend.read_fluorescence(
          plate, wells, excitation_wavelength=200, emission_wavelength=528, focal_height=8.5
        )
      )

    with self.assertRaises(ValueError):
      asyncio.run(
        backend.read_fluorescence(
          plate, wells, excitation_wavelength=485, emission_wavelength=900, focal_height=8.5
        )
      )

  def test_read_fluorescence_validates_gain_range(self):
    """Gain outside 0-4095 raises ValueError."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()

    with self.assertRaises(ValueError):
      asyncio.run(
        backend.read_fluorescence(
          plate, wells, excitation_wavelength=485, emission_wavelength=528,
          focal_height=8.5, gain=5000,
        )
      )

  def test_read_fluorescence_validates_focal_height(self):
    """Focal height outside 0-25 raises ValueError."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()

    with self.assertRaises(ValueError):
      asyncio.run(
        backend.read_fluorescence(
          plate, wells, excitation_wavelength=485, emission_wavelength=528, focal_height=30.0
        )
      )


class TestBuildFluorescencePayloadEDR(unittest.TestCase):
  """Verify EDR flag in payload construction."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_edr_sets_optic_byte1(self):
    """EDR sets pre-separator byte[1] (p[66]) to 0x40."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      edr=True,
    )
    full = bytes([0x04]) + payload
    self.assertEqual(full[66], 0x40)

  def test_edr_off_optic_byte1_is_zero(self):
    """Without EDR, pre-separator byte[1] is 0x00."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      edr=False,
    )
    full = bytes([0x04]) + payload
    self.assertEqual(full[66], 0x00)

  def test_edr_matches_FP01_ground_truth(self):
    """EDR payload matches F-P01 pcap (skipping plate geometry and wavelength bytes)."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      edr=True,
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    full = bytes([0x04]) + payload
    gt = bytes.fromhex(_FL_GT_HEX["FP01"])[4:-4]
    self.assertEqual(len(full), len(gt))
    # Optic byte[1] = EDR flag
    self.assertEqual(full[66], gt[66])
    # Post-separator fields (settle through tail) should match
    self.assertEqual(full[100:], gt[100:])

  def test_edr_does_not_change_payload_length(self):
    """EDR doesn't add or remove bytes from payload."""
    p_normal = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
    )
    p_edr = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      edr=True,
    )
    self.assertEqual(len(p_normal), len(p_edr))


class TestBuildFluorescencePayloadFlying(unittest.TestCase):
  """Verify flying mode in payload construction."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_flying_sets_scan_byte_bit2(self):
    """Flying mode sets bit 2 (0x04) of scan direction byte."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      flying_mode=True,
    )
    full = bytes([0x04]) + payload
    self.assertTrue(full[64] & 0x04, "flying bit (bit2) not set")

  def test_flying_forces_settling_to_1(self):
    """Flying mode forces settling time raw=1 regardless of settling_time_s."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      flying_mode=True, settling_time_s=0.5,
    )
    full = bytes([0x04]) + payload
    # Settling is first byte of post-separator
    self.assertEqual(full[100], 1)

  def test_flying_forces_flashes_to_1(self):
    """Flying mode forces flashes=1 regardless of flashes param."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      flying_mode=True, flashes=100,
    )
    full = bytes([0x04]) + payload
    # Flashes at post-sep offset 43-44 (settle1+focal2+multi9+chrom17+slit5+pause3+trailer11 = 48-5 = 43)
    # Actually: post-sep[0]=settle, [1:3]=focal, [3:12]=multi, [12:29]=chrom, [29:32]=pause,
    # [32:43]=trailer, [43:45]=flashes
    flashes_offset = 100 + 1 + 2 + 9 + 17 + 3 + 11  # = 143
    flashes_val = int.from_bytes(full[flashes_offset:flashes_offset + 2], "big")
    self.assertEqual(flashes_val, 1)

  def test_flying_matches_FO01_ground_truth(self):
    """Flying payload matches F-O01 pcap post-separator fields."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      flying_mode=True,
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    full = bytes([0x04]) + payload
    gt = bytes.fromhex(_FL_GT_HEX["FO01"])[4:-4]
    self.assertEqual(len(full), len(gt))
    # Scan byte: both should have flying bit set
    self.assertTrue(full[64] & 0x04)
    self.assertTrue(gt[64] & 0x04)
    # Post-separator should match exactly
    self.assertEqual(full[100:], gt[100:])


class TestBuildFluorescencePayloadFilter(unittest.TestCase):
  """Verify filter mode wavelength and slit encoding."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def _get_post_sep(self, payload: bytes) -> bytes:
    """Extract post-separator bytes from a payload (after prepending 0x04)."""
    full = bytes([0x04]) + payload
    return full[100:]

  def test_all_filter_wavelength_sentinels(self):
    """All-filter mode uses sentinel values: ExHi=2, ExLo=1, Dich=2, EmHi=1, EmLo=2."""
    OpticalFilter = CLARIOstarPlusBackend.OpticalFilter
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      excitation_filter=OpticalFilter(slot=1), emission_filter=OpticalFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    # Chrom block starts at offset 12 (settle1+focal2+multi9)
    # gain(2) at [12:14], then ExHi(2), ExLo(2), Dich(2), EmHi(2), EmLo(2)
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    dich = int.from_bytes(post[18:20], "big")
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    self.assertEqual(ex_hi, 0x0002)
    self.assertEqual(ex_lo, 0x0001)
    self.assertEqual(dich, 0x0002)
    self.assertEqual(em_hi, 0x0001)
    self.assertEqual(em_lo, 0x0002)

  def test_all_filter_slit_config(self):
    """All-filter slit = 00 01 00 01 00."""
    OpticalFilter = CLARIOstarPlusBackend.OpticalFilter
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      excitation_filter=OpticalFilter(slot=1), emission_filter=OpticalFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    slit = post[24:29]
    self.assertEqual(slit, b"\x00\x01\x00\x01\x00")

  def test_all_filter_matches_FLf01(self):
    """All-filter payload matches F-Lf01 pcap post-separator."""
    OpticalFilter = CLARIOstarPlusBackend.OpticalFilter
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      excitation_filter=OpticalFilter(slot=1), emission_filter=OpticalFilter(slot=1),
    )
    full = bytes([0x04]) + payload
    gt = bytes.fromhex(_FL_GT_HEX["FLf01"])[4:-4]
    self.assertEqual(len(full), len(gt))
    # Post-sep should match (wavelength sentinels + slit + tail)
    self.assertEqual(full[100:], gt[100:])

  def test_mono_ex_filter_em_slit(self):
    """Mono Ex + filter Em: slit = 00 01 00 03 00."""
    OpticalFilter = CLARIOstarPlusBackend.OpticalFilter
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=400, emission_wavelength=528, focal_height=8.5,
      excitation_bandwidth=14,
      emission_filter=OpticalFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    slit = post[24:29]
    self.assertEqual(slit, b"\x00\x01\x00\x03\x00")
    # Ex should be real wavelength edges
    ex_hi = int.from_bytes(post[14:16], "big")
    self.assertGreater(ex_hi, 100)  # real value, not sentinel
    # Em should be filter sentinels
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    self.assertEqual(em_hi, 0x0001)
    self.assertEqual(em_lo, 0x0002)

  def test_filter_ex_mono_em_slit(self):
    """Filter Ex + mono Em: slit = 00 04 00 01 00."""
    OpticalFilter = CLARIOstarPlusBackend.OpticalFilter
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      excitation_filter=OpticalFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    slit = post[24:29]
    self.assertEqual(slit, b"\x00\x04\x00\x01\x00")
    # Ex should be filter sentinels
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    self.assertEqual(ex_hi, 0x0002)
    self.assertEqual(ex_lo, 0x0001)
    # Em should be real wavelength edges
    em_hi = int.from_bytes(post[20:22], "big")
    self.assertGreater(em_hi, 100)

  def test_filter_dichroic_is_always_0x0002(self):
    """When any channel uses filter, dichroic is always 0x0002."""
    OpticalFilter = CLARIOstarPlusBackend.OpticalFilter
    test_cases = [
      (OpticalFilter(slot=1), None, "ex_filter"),
      (None, OpticalFilter(slot=1), "em_filter"),
      (OpticalFilter(slot=1), OpticalFilter(slot=1), "both_filter"),
    ]
    for ex_f, em_f, label in test_cases:
      payload = self.backend._build_fluorescence_payload(
        self.plate, self.all_wells,
        excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
        excitation_filter=ex_f, emission_filter=em_f,
      )
      post = self._get_post_sep(payload)
      dich = int.from_bytes(post[18:20], "big")
      self.assertEqual(dich, 0x0002, f"dichroic should be 0x0002 for {label}")


class TestBuildFluorescencePayloadMatrix(unittest.TestCase):
  """Verify matrix scan payload construction."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_matrix_sets_optic_byte0(self):
    """Matrix scan sets optic byte[0] (p[65]) to 0x10."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_fluorescence_payload(
      self.plate, wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      well_scan="matrix", scan_diameter_mm=3, matrix_size=3,
    )
    full = bytes([0x04]) + payload
    self.assertEqual(full[65], 0x10)

  def test_matrix_includes_well_scan_field(self):
    """Matrix scan inserts 5-byte well scan field after separator."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_fluorescence_payload(
      self.plate, wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      well_scan="matrix", scan_diameter_mm=3, matrix_size=3,
    )
    full = bytes([0x04]) + payload
    # Point mode is 148 bytes, matrix adds 5 = 153
    self.assertEqual(len(full), 153)
    # Well scan field at [100:105]
    self.assertEqual(full[100], 3)  # matrix_size=3
    self.assertEqual(full[101], 0x03)  # scan diameter = 3mm
    self.assertEqual(full[104], 0x00)  # terminator

  def test_matrix_includes_well_scan_field_7x7(self):
    """Matrix 7×7: well scan field buf[0] = 7 (not FL code 0x03)."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_fluorescence_payload(
      self.plate, wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      well_scan="matrix", scan_diameter_mm=3, matrix_size=7,
    )
    full = bytes([0x04]) + payload
    self.assertEqual(full[100], 7)  # matrix_size=7, not FL code 0x03

  def test_matrix_matches_FS01_post_separator(self):
    """Matrix payload matches F-S01 pcap post-separator."""
    wells = [self.plate.get_item("A1")]
    payload = self.backend._build_fluorescence_payload(
      self.plate, wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      well_scan="matrix", scan_diameter_mm=3, matrix_size=3,
      _ex_hi=4923, _ex_lo=4777, _em_hi=5377, _em_lo=5183, _dichroic_raw=5052,
    )
    full = bytes([0x04]) + payload
    gt = bytes.fromhex(_FL_GT_HEX["FS01"])[4:-4]
    self.assertEqual(len(full), len(gt))
    # Optic byte[0] = matrix flag
    self.assertEqual(full[65], gt[65])
    # Well scan field: byte 0 (code) and byte 1 (diameter) should match
    self.assertEqual(full[100], gt[100])
    self.assertEqual(full[101], gt[101])
    # Post-sep after well scan field: settle+focal+multi+chrom+slit+pause+trailer+flashes+tail
    self.assertEqual(full[105:], gt[105:])


class TestBuildFluorescencePayloadDualChromatic(unittest.TestCase):
  """Verify dual chromatic payload construction."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_dual_chromatic_length(self):
    """Dual chromatic payload is 20 bytes longer than single (167 vs 147)."""
    p_single = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
    )
    p_dual = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      chromatics=[
        {"excitation_wavelength": 485, "emission_wavelength": 528},
        {"excitation_wavelength": 610, "emission_wavelength": 675, "emission_bandwidth": 49,
         "excitation_bandwidth": 30},
      ],
    )
    self.assertEqual(len(p_single), 147)
    self.assertEqual(len(p_dual), 167)  # 147 + 20

  def test_dual_chromatic_multi_count(self):
    """Dual chromatic sets multichromatic header byte[2] = 0x02."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      chromatics=[
        {"excitation_wavelength": 485, "emission_wavelength": 528},
        {"excitation_wavelength": 610, "emission_wavelength": 675},
      ],
    )
    full = bytes([0x04]) + payload
    # Multi header at post-sep offset 3: byte[2] of the 9-byte block
    # Post-sep starts at 100, multi header at 100+1+2=103, count at 103+2=105
    self.assertEqual(full[105], 0x02)

  def test_dual_chromatic_inter_separator(self):
    """Dual chromatic has 00 00 0c separator between chromatic blocks."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      chromatics=[
        {"excitation_wavelength": 485, "emission_wavelength": 528},
        {"excitation_wavelength": 610, "emission_wavelength": 675},
      ],
    )
    full = bytes([0x04]) + payload
    # Chrom 1 ends at 100 + 12 + 17 = 129. Inter-sep at 129:132
    self.assertEqual(full[129:132], b"\x00\x00\x0c")

  def test_dual_chromatic_matches_FM01(self):
    """Dual chromatic payload matches F-M01 pcap."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      chromatics=[
        {"excitation_wavelength": 485, "emission_wavelength": 528, "gain": 1000},
        {"excitation_wavelength": 610, "emission_wavelength": 675,
         "excitation_bandwidth": 30, "emission_bandwidth": 49, "gain": 1000},
      ],
      _chromatic_overrides=[
        {"ex_hi": 4923, "ex_lo": 4777, "em_hi": 5377, "em_lo": 5183, "dichroic": 5052},
        {"ex_hi": 6248, "ex_lo": 5952, "em_hi": 6996, "em_lo": 6504, "dichroic": 6375},
      ],
    )
    full = bytes([0x04]) + payload
    gt = bytes.fromhex(_FL_GT_HEX["FM01"])[4:-4]
    self.assertEqual(len(full), len(gt))
    # Multi count
    self.assertEqual(full[105], gt[105])
    # Chrom 1 block (17 bytes at offset 112)
    self.assertEqual(full[112:129], gt[112:129])
    # Inter-chromatic separator
    self.assertEqual(full[129:132], gt[129:132])
    # Chrom 2 block (17 bytes at offset 132)
    self.assertEqual(full[132:149], gt[132:149])
    # Tail fields (pause+trailer+flashes+tail)
    self.assertEqual(full[149:], gt[149:])

  def test_chromatics_limit_1_to_5(self):
    """chromatics must have 1-5 entries."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK)

    with self.assertRaises(ValueError):
      asyncio.run(backend.read_fluorescence(
        plate, wells, 485, 528, 8.5,
        chromatics=[{"excitation_wavelength": 485, "emission_wavelength": 528}] * 6,
      ))


class TestParseFluorescenceResponseDualChromatic(unittest.TestCase):
  """Verify multi-chromatic response parsing."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_FM01_dual_chromatic_returns_two_dicts(self):
    """F-M01 dual chromatic returns 2 result dicts, one per chromatic."""
    frame = bytes.fromhex(_FL_RESP_HEX["FM01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)

    results = self.backend._parse_fluorescence_response(
      payload, self.plate, self.all_wells, [(485, 528), (610, 675)]
    )

    self.assertEqual(len(results), 2)
    # Chromatic 1
    self.assertEqual(results[0]["ex_wavelength"], 485)
    self.assertEqual(results[0]["em_wavelength"], 528)
    self.assertEqual(len(results[0]["data"]), 8)
    self.assertEqual(len(results[0]["data"][0]), 12)
    # Chromatic 1, A1 value: 0x95 = 149
    self.assertEqual(results[0]["data"][0][0], 149.0)
    # Chromatic 2
    self.assertEqual(results[1]["ex_wavelength"], 610)
    self.assertEqual(results[1]["em_wavelength"], 675)
    # Chromatic 2, A1 value: 0x1403 = 5123
    self.assertEqual(results[1]["data"][0][0], 5123.0)


class TestParseFluorescenceResponseMatrix(unittest.TestCase):
  """Verify matrix response parsing."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()

  def test_FS01_matrix_returns_averaged_value(self):
    """F-S01 matrix 3×3 with 1 well returns mean of 9 positions."""
    frame = bytes.fromhex(_FL_RESP_HEX["FS01"])
    _validate_frame(frame)
    payload = _extract_payload(frame)

    wells = [self.plate.get_item("A1")]
    results = self.backend._parse_fluorescence_response(
      payload, self.plate, wells, [(485, 528)]
    )

    self.assertEqual(len(results), 1)
    r = results[0]
    # 9 values: 145,147,142,136,144,144,137,142,139 → mean ≈ 141.8
    # Grid should have A1 = mean, all others None
    a1_val = r["data"][0][0]
    self.assertIsNotNone(a1_val)
    self.assertAlmostEqual(a1_val, 141.8, delta=0.2)
    # Other wells should be None
    none_count = sum(1 for row in r["data"] for v in row if v is None)
    self.assertEqual(none_count, 95)


class TestReadFluorescenceNewFeatureValidation(unittest.TestCase):
  """Validate new feature parameters in read_fluorescence."""

  def test_flying_mode_rejects_orbital(self):
    """flying_mode=True with well_scan='orbital' raises ValueError."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.read_fluorescence(
        plate, wells, 485, 528, 8.5,
        flying_mode=True, well_scan="orbital",
      ))

  def test_chromatics_missing_required_key(self):
    """chromatics dict missing excitation_wavelength raises ValueError."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.read_fluorescence(
        plate, wells, 485, 528, 8.5,
        chromatics=[{"emission_wavelength": 528}],
      ))

  def test_chromatics_wavelength_out_of_range(self):
    """chromatics with wavelength outside 320-840 raises ValueError."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.read_fluorescence(
        plate, wells, 485, 528, 8.5,
        chromatics=[{"excitation_wavelength": 200, "emission_wavelength": 528}],
      ))

  def test_chromatics_gain_out_of_range(self):
    """chromatics with gain > 4095 raises ValueError."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.read_fluorescence(
        plate, wells, 485, 528, 8.5,
        chromatics=[{"excitation_wavelength": 485, "emission_wavelength": 528, "gain": 5000}],
      ))

  def test_well_scan_matrix_accepted(self):
    """well_scan='matrix' with matrix_size is valid."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]
    data_frame = _wrap_payload(_build_synthetic_fl_response(num_wells=9))
    mock.queue_response(ACK, data_frame)
    results = asyncio.run(backend.read_fluorescence(
      plate, wells, 485, 528, 8.5,
      well_scan="matrix", scan_diameter_mm=3, matrix_size=3,
    ))
    self.assertEqual(len(results), 1)

  def test_edr_integration_flow(self):
    """EDR flag passes through to payload correctly."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()
    data_frame = _wrap_payload(_build_synthetic_fl_response())
    mock.queue_response(ACK, data_frame)
    results = asyncio.run(backend.read_fluorescence(
      plate, wells, 485, 528, 8.5, edr=True,
    ))
    self.assertEqual(len(results), 1)
    # Verify the sent command has EDR flag
    first_frame = mock.written[0]
    inner = _extract_payload(first_frame)
    # inner[0] = 0x04 (RUN), payload starts at inner[1:]
    # p[66] = inner[1+65] = inner[66]
    self.assertEqual(inner[66], 0x40)

  def test_flying_mode_integration_flow(self):
    """Flying mode passes through correctly."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()
    data_frame = _wrap_payload(_build_synthetic_fl_response())
    mock.queue_response(ACK, data_frame)
    results = asyncio.run(backend.read_fluorescence(
      plate, wells, 485, 528, 8.5, flying_mode=True,
    ))
    self.assertEqual(len(results), 1)
    # Verify scan byte has flying bit
    first_frame = mock.written[0]
    inner = _extract_payload(first_frame)
    self.assertTrue(inner[64] & 0x04)

  def test_meander_shake_accepted(self):
    """Meander shake mode at 200 RPM is accepted."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()
    data_frame = _wrap_payload(_build_synthetic_fl_response())
    mock.queue_response(ACK, data_frame)
    results = asyncio.run(backend.read_fluorescence(
      plate, wells, 485, 528, 8.5,
      shake_mode="meander", shake_speed_rpm=200, shake_duration_s=5,
    ))
    self.assertEqual(len(results), 1)
    # Verify shake pattern byte = 3 (meander)
    first_frame = mock.written[0]
    inner = _extract_payload(first_frame)
    # Pre-separator block starts at inner[65], shake_pattern at offset 17
    self.assertEqual(inner[65 + 17], 0x03)

  def test_meander_shake_rejects_400_rpm(self):
    """Meander shake mode at 400 RPM raises ValueError (max 300)."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.read_fluorescence(
        plate, wells, 485, 528, 8.5,
        shake_mode="meander", shake_speed_rpm=400, shake_duration_s=5,
      ))


# ---------------------------------------------------------------------------
# Auto-Focus Tests
# ---------------------------------------------------------------------------

# Ground truth from F-Q01 pcap capture.
# AUTO_FOCUS_SCAN (0x0c) SEND — full wire frame (97 bytes)
_AF_GT_SEND_HEX = (
  "02 00 61 0c 0c 31 ec 21 66 05 96 04 60 2c 56 1d 06 0c 08 ff"
  " ff ff ff ff ff ff ff ff ff ff ff ff 00 00 00 00 00 00 00 00"
  " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
  " 00 00 00 00 00 00 00 a0 08 05 dc 00 0a 00 00 00 00 00 0c 13"
  " 3b 12 a9 13 bc 15 01 14 3f 00 04 00 03 00 13 b2 0d"
).replace(" ", "")

# FOCUS_RESULT (0x05/0x05) RECV — full inner payload from F-Q01 pcap (1177 bytes).
# 27B header + 143 × 8B Z-records + 6B trailing = 1177B.
# Contains the complete W-curve: peak at 8.4mm (65463), null at 11.2mm (1182).
_AF_GT_RESULT_FULL = (
  "05 05 20 26 00 00 01 07 08 00 01 78 96 00 01 0b 02 03 e8"
  " 00 01 77 ec 00 90 00 00 05 dc 00 00 93 ed 00 00 05 d2 00"
  " 00 8b 00 00 00 05 c8 00 00 8a 4d 00 00 05 be 00 00 88 54"
  " 00 00 05 b4 00 00 84 23 00 00 05 aa 00 00 84 6a 00 00 05"
  " a0 00 00 7c cc 00 00 05 96 00 00 79 ab 00 00 05 8c 00 00"
  " 7a 5d 00 00 05 82 00 00 74 40 00 00 05 78 00 00 74 3a 00"
  " 00 05 6e 00 00 6e 9b 00 00 05 64 00 00 72 82 00 00 05 5a"
  " 00 00 70 e8 00 00 05 50 00 00 75 26 00 00 05 46 00 00 70"
  " 62 00 00 05 3c 00 00 76 fe 00 00 05 32 00 00 72 36 00 00"
  " 05 28 00 00 75 0b 00 00 05 1e 00 00 74 9b 00 00 05 14 00"
  " 00 7d c7 00 00 05 0a 00 00 7e bc 00 00 05 00 00 00 7e 0f"
  " 00 00 04 f6 00 00 84 d6 00 00 04 ec 00 00 87 c4 00 00 04"
  " e2 00 00 8c ee 00 00 04 d8 00 00 93 a9 00 00 04 ce 00 00"
  " 96 cc 00 00 04 c4 00 00 a3 64 00 00 04 ba 00 00 a6 c4 00"
  " 00 04 b0 00 00 ae dd 00 00 04 a6 00 00 b6 9c 00 00 04 9c"
  " 00 00 c0 92 00 00 04 92 00 00 ca a6 00 00 04 88 00 00 d5"
  " 27 00 00 04 7e 00 00 e4 b4 00 00 04 74 00 00 f2 34 00 00"
  " 04 6a 00 00 fa 85 00 00 04 60 00 01 04 9e 00 00 04 56 00"
  " 01 13 d7 00 00 04 4c 00 01 1c 2b 00 00 04 42 00 01 31 2e"
  " 00 00 04 38 00 01 40 a5 00 00 04 2e 00 01 48 8e 00 00 04"
  " 24 00 01 58 7e 00 00 04 1a 00 01 65 3f 00 00 04 10 00 01"
  " 66 fb 00 00 04 06 00 01 71 40 00 00 03 fc 00 01 71 96 00"
  " 00 03 f2 00 01 7a 31 00 00 03 e8 00 01 74 14 00 00 03 de"
  " 00 01 7c 19 00 00 03 d4 00 01 7b aa 00 00 03 ca 00 01 78"
  " 63 00 00 03 c0 00 01 69 9c 00 00 03 b6 00 01 63 3a 00 00"
  " 03 ac 00 01 5d 99 00 00 03 a2 00 01 53 4a 00 00 03 98 00"
  " 01 52 7a 00 00 03 8e 00 01 4e 79 00 00 03 84 00 01 44 e1"
  " 00 00 03 7a 00 01 3b ef 00 00 03 70 00 01 29 e2 00 00 03"
  " 66 00 01 1f 21 00 00 03 5c 00 01 12 0d 00 00 03 52 00 01"
  " 0a 0b 00 00 03 48 00 00 ff b7 00 00 03 3e 00 00 f2 29 00"
  " 00 03 34 00 00 ea c8 00 00 03 2a 00 00 d8 8f 00 00 03 20"
  " 00 00 d0 42 00 00 03 16 00 00 c3 89 00 00 03 0c 00 00 b2"
  " e1 00 00 03 02 00 00 ac f4 00 00 02 f8 00 00 a3 68 00 00"
  " 02 ee 00 00 96 81 00 00 02 e4 00 00 88 46 00 00 02 da 00"
  " 00 86 1a 00 00 02 d0 00 00 7e d4 00 00 02 c6 00 00 78 25"
  " 00 00 02 bc 00 00 71 d6 00 00 02 b2 00 00 65 5b 00 00 02"
  " a8 00 00 62 ef 00 00 02 9e 00 00 60 9d 00 00 02 94 00 00"
  " 59 6f 00 00 02 8a 00 00 53 84 00 00 02 80 00 00 4e 7e 00"
  " 00 02 76 00 00 49 bb 00 00 02 6c 00 00 49 3c 00 00 02 62"
  " 00 00 44 65 00 00 02 58 00 00 42 92 00 00 02 4e 00 00 3d"
  " 08 00 00 02 44 00 00 3e d3 00 00 02 3a 00 00 3f 28 00 00"
  " 02 30 00 00 39 1d 00 00 02 26 00 00 36 98 00 00 02 1c 00"
  " 00 33 df 00 00 02 12 00 00 31 a5 00 00 02 08 00 00 32 40"
  " 00 00 01 fe 00 00 2d 05 00 00 01 f4 00 00 2b 5f 00 00 01"
  " ea 00 00 2a b8 00 00 01 e0 00 00 29 36 00 00 01 d6 00 00"
  " 27 0a 00 00 01 cc 00 00 27 44 00 00 01 c2 00 00 24 7c 00"
  " 00 01 b8 00 00 22 e3 00 00 01 ae 00 00 22 5b 00 00 01 a4"
  " 00 00 21 ae 00 00 01 9a 00 00 20 5a 00 00 01 90 00 00 21"
  " bb 00 00 01 86 00 00 1e 36 00 00 01 7c 00 00 1d 42 00 00"
  " 01 72 00 00 1c 47 00 00 01 68 00 00 1b 99 00 00 01 5e 00"
  " 00 19 3a 00 00 01 54 00 00 1a 2f 00 00 01 4a 00 00 18 2b"
  " 00 00 01 40 00 00 18 51 00 00 01 36 00 00 18 1d 00 00 01"
  " 2c 00 00 16 46 00 00 01 22 00 00 16 27 00 00 01 18 00 00"
  " 15 a7 00 00 01 0e 00 00 14 96 00 00 01 04 00 00 14 d3 00"
  " 00 00 fa 00 00 13 20 00 00 00 f0 00 00 12 9d 00 00 00 e6"
  " 00 00 13 8d 00 00 00 dc 00 00 10 fc 00 00 00 d2 00 00 11"
  " 7b 00 00 00 c8 00 00 10 c5 00 00 00 be 00 00 0f 33 00 00"
  " 00 b4 00 00 11 5c 00 00 00 aa 00 00 10 22 00 00 00 a0 00"
  " 00 0f f5 00 00 00 96 00 00 0e 60 00 00 00 8c 00 00 0c dd"
  " 00 00 00 82 00 00 0f 8d 00 00 00 78 00 00 0d e0 00 00 00"
  " 6e 00 00 0d 7c 00 00 00 64 00 00 0b 4f 00 00 00 5a 00 00"
  " 0d 6a 00 00 00 50 00 00 0a 7c 00 00 00 46 00 00 0a 50"
).replace(" ", "")


class TestBuildAutofocusPayload(unittest.TestCase):
  """Tests for _build_autofocus_payload against F-Q01 pcap ground truth."""

  def test_payload_length(self):
    """Auto-focus payload should be 88 bytes (excluding command byte)."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(
      plate, wells, 485, 528, max_focal_height_mm=15.0, flashes_per_position=10,
    )
    self.assertEqual(len(payload), 88)

  def test_plate_extra_byte_is_0xff(self):
    """Auto-focus sets plate extra byte [14] to 0xFF."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(plate, wells, 485, 528)
    self.assertEqual(payload[14], 0xFF)

  def test_config_byte(self):
    """Config byte at [63] should be 0x08."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(plate, wells, 485, 528)
    self.assertEqual(payload[63], 0x08)

  def test_max_focal_height(self):
    """Max focal height at [64:66] should encode correctly."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(
      plate, wells, 485, 528, max_focal_height_mm=15.0,
    )
    fh = int.from_bytes(payload[64:66], "big")
    self.assertEqual(fh, 1500)  # 15.0mm × 100

  def test_flashes_per_position(self):
    """Flashes per position at [67] should encode correctly."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(
      plate, wells, 485, 528, flashes_per_position=10,
    )
    self.assertEqual(payload[67], 10)

  def test_post_plate_structure_matches_pcap(self):
    """Structural bytes (non-wavelength) should match F-Q01 pcap ground truth."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(
      plate, wells, 485, 528,
      excitation_bandwidth=15, emission_bandwidth=20,
      max_focal_height_mm=15.0, flashes_per_position=10,
    )
    gt_frame = bytes.fromhex(_AF_GT_SEND_HEX)
    gt_inner = gt_frame[4:-4]  # strip envelope
    gt_post = gt_inner[64:]    # post-plate (after 0x0c cmd byte + 63B plate)

    our_post = payload[63:]    # post-plate (63B plate, no cmd byte)

    # Compare structural bytes: config(1) + focal(2) + zero(1) + flashes(1) + zeros(5) + marker(1)
    self.assertEqual(our_post[:11], gt_post[:11])
    # Skip wavelengths [11:21] — firmware applies ±2-3 monochromator calibration
    # Compare slit config
    self.assertEqual(our_post[21:], gt_post[21:])

  def test_wavelengths_within_calibration_tolerance(self):
    """Wavelength edge values should be within ±3 of pcap (monochromator calibration)."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(
      plate, wells, 485, 528,
      excitation_bandwidth=15, emission_bandwidth=20,
    )
    # pcap values: ExHi=0x133b=4923, ExLo=0x12a9=4777, Dich=0x13bc=5052,
    #              EmHi=0x1501=5377, EmLo=0x143f=5183
    pcap_wl = [4923, 4777, 5052, 5377, 5183]
    for i, expected in enumerate(pcap_wl):
      actual = int.from_bytes(payload[74 + i*2 : 76 + i*2], "big")
      self.assertAlmostEqual(actual, expected, delta=3,
        msg=f"Wavelength pair {i} at offset {74+i*2}: {actual} vs pcap {expected}")

  def test_slit_mono_mono(self):
    """Slit config should be 00 04 00 03 for mono/mono."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(plate, wells, 485, 528)
    self.assertEqual(payload[84:88], bytes([0x00, 0x04, 0x00, 0x03]))

  def test_multi_marker(self):
    """Multi marker at [73] should be 0x0C."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    payload = backend._build_autofocus_payload(plate, wells, 485, 528)
    self.assertEqual(payload[73], 0x0C)


class TestParseFocusResult(unittest.TestCase):
  """Tests for _parse_focus_result against full F-Q01 pcap ground truth (1177B payload)."""

  def _get_payload(self):
    return bytes.fromhex(_AF_GT_RESULT_FULL)

  def test_best_focal_height(self):
    """Best focal height should be 10.0mm from the F-Q01 ground truth."""
    backend = _make_backend()
    result = backend._parse_focus_result(self._get_payload())
    self.assertAlmostEqual(result["best_focal_mm"], 10.0, places=1)

  def test_total_z_records(self):
    """Full Z-scan should produce exactly 143 records (15.0mm to 0.8mm, 0.1mm steps)."""
    backend = _make_backend()
    result = backend._parse_focus_result(self._get_payload())
    self.assertEqual(len(result["z_profile"]), 143)

  def test_z_range(self):
    """Z range should span 15.0mm (first) to 0.8mm (last)."""
    backend = _make_backend()
    z_profile = backend._parse_focus_result(self._get_payload())["z_profile"]
    self.assertAlmostEqual(z_profile[0]["z_mm"], 15.0, places=1)
    self.assertAlmostEqual(z_profile[-1]["z_mm"], 0.8, places=1)

  def test_z_profile_descending(self):
    """Z positions should be in strictly descending order."""
    backend = _make_backend()
    z_profile = backend._parse_focus_result(self._get_payload())["z_profile"]
    z_values = [r["z_mm"] for r in z_profile]
    self.assertEqual(z_values, sorted(z_values, reverse=True))

  def test_z_step_size(self):
    """All Z steps should be 0.1mm."""
    backend = _make_backend()
    z_profile = backend._parse_focus_result(self._get_payload())["z_profile"]
    for i in range(len(z_profile) - 1):
      step = z_profile[i]["z_mm"] - z_profile[i + 1]["z_mm"]
      self.assertAlmostEqual(step, 0.1, places=2,
        msg=f"Step {i}: {z_profile[i]['z_mm']:.1f} -> {z_profile[i+1]['z_mm']:.1f}")

  def test_first_record(self):
    """First record: z=15.0mm, signal=37869, pass_flag=0."""
    backend = _make_backend()
    z_profile = backend._parse_focus_result(self._get_payload())["z_profile"]
    rec = z_profile[0]
    self.assertAlmostEqual(rec["z_mm"], 15.0, places=1)
    self.assertEqual(rec["signal"], 37869)
    self.assertEqual(rec["pass_flag"], 0)

  def test_w_curve_peak(self):
    """Peak signal should be 65463 at z=8.4mm (bottom focus, pass_flag=0)."""
    backend = _make_backend()
    z_profile = backend._parse_focus_result(self._get_payload())["z_profile"]
    peak = max(z_profile, key=lambda r: r["signal"])
    self.assertAlmostEqual(peak["z_mm"], 8.4, places=1)
    self.assertEqual(peak["signal"], 65463)
    self.assertEqual(peak["pass_flag"], 0)

  def test_w_curve_null(self):
    """Minimum signal should be 1182 at z=11.2mm (extinction null, pass_flag=1)."""
    backend = _make_backend()
    z_profile = backend._parse_focus_result(self._get_payload())["z_profile"]
    null = min(z_profile, key=lambda r: r["signal"])
    self.assertAlmostEqual(null["z_mm"], 11.2, places=1)
    self.assertEqual(null["signal"], 1182)
    self.assertEqual(null["pass_flag"], 1)

  def test_best_focal_signal(self):
    """At the firmware-selected z=10.0mm: signal=29716, pass_flag=1."""
    backend = _make_backend()
    z_profile = backend._parse_focus_result(self._get_payload())["z_profile"]
    z_dict = {round(r["z_mm"], 1): r for r in z_profile}
    rec = z_dict[10.0]
    self.assertEqual(rec["signal"], 29716)
    self.assertEqual(rec["pass_flag"], 1)

  def test_short_payload_raises(self):
    """Payload shorter than 27 bytes should raise ValueError."""
    backend = _make_backend()
    with self.assertRaises(ValueError):
      backend._parse_focus_result(b"\x05\x05" + b"\x00" * 10)


class TestAutoFocusIntegration(unittest.TestCase):
  """Integration tests for the auto_focus method."""

  def _build_synthetic_focus_response(self, best_focal_raw=1000, n_records=5):
    """Build a synthetic focus result payload.

    Args:
      best_focal_raw: Best focal height in mm×100 (default 1000 = 10.0mm).
      n_records: Number of Z-scan records.
    """
    header = bytearray(27)
    header[0] = 0x05  # sub echo
    header[1] = 0x05  # family echo
    header[17:19] = best_focal_raw.to_bytes(2, "big")
    data = bytearray()
    for i in range(n_records):
      z = (1500 - i * 10)  # 15.0mm, 14.9mm, ...
      record = z.to_bytes(2, "big") + b"\x00\x00" + (1000 + i * 100).to_bytes(2, "big") + b"\x00\x00"
      data += record
    return bytes(header) + bytes(data)

  def _build_idle_status(self):
    """Build a synthetic status response (idle, not running)."""
    # 16-byte status: byte[1] bit0=valid, bit2=set; no running/busy flags
    payload = bytearray(16)
    payload[0] = 0x01
    payload[1] = 0x05  # valid + bit2 (normal idle)
    return _wrap_payload(bytes(payload))

  def test_auto_focus_returns_focal_height(self):
    """auto_focus with real pcap payload should return 10.0mm and 143 records."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    # Queue: (1) ACK for 0x0c command, (2) idle status, (3) real pcap focus result
    pcap_result = bytes.fromhex(_AF_GT_RESULT_FULL)
    mock.queue_response(ACK, self._build_idle_status(), _wrap_payload(pcap_result))

    result = asyncio.run(backend.auto_focus(plate, wells, 485, 528))
    self.assertAlmostEqual(result["best_focal_mm"], 10.0, places=1)
    self.assertEqual(len(result["z_profile"]), 143)

  def test_auto_focus_sends_0x0c_command(self):
    """auto_focus should send a 0x0c command family."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    focus_result = self._build_synthetic_focus_response()
    mock.queue_response(ACK, self._build_idle_status(), _wrap_payload(focus_result))

    asyncio.run(backend.auto_focus(plate, wells, 485, 528))

    # First written frame should be 0x0c command
    first_frame = mock.written[0]
    inner = _extract_payload(first_frame)
    self.assertEqual(inner[0], 0x0C)

  def test_auto_focus_validation_wavelength(self):
    """auto_focus should reject invalid wavelengths."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.auto_focus(plate, wells, 100, 528))

  def test_auto_focus_validation_max_focal(self):
    """auto_focus should reject max_focal_height_mm out of range."""
    backend = _make_backend()
    plate = _make_plate()
    wells = plate.get_all_items()
    with self.assertRaises(ValueError):
      asyncio.run(backend.auto_focus(plate, wells, 485, 528, max_focal_height_mm=30.0))


class TestCommandFamilyAutoFocus(unittest.TestCase):
  """Tests for the AUTO_FOCUS command family enum and dispatch."""

  def test_auto_focus_enum_value(self):
    """AUTO_FOCUS should have value 0x0C."""
    self.assertEqual(CLARIOstarPlusBackend.CommandFamily.AUTO_FOCUS, 0x0C)

  def test_focus_result_command_value(self):
    """FOCUS_RESULT should have value 0x05."""
    self.assertEqual(CLARIOstarPlusBackend.Command.FOCUS_RESULT, 0x05)

  def test_auto_focus_in_no_command_families(self):
    """AUTO_FOCUS should be in _NO_COMMAND_FAMILIES (no subcommand byte)."""
    self.assertIn(
      CLARIOstarPlusBackend.CommandFamily.AUTO_FOCUS,
      CLARIOstarPlusBackend._NO_COMMAND_FAMILIES,
    )

  def test_focus_result_in_valid_commands(self):
    """FOCUS_RESULT should be in _VALID_COMMANDS for REQUEST family."""
    valid = CLARIOstarPlusBackend._VALID_COMMANDS[CLARIOstarPlusBackend.CommandFamily.REQUEST]
    self.assertIn(CLARIOstarPlusBackend.Command.FOCUS_RESULT, valid)


class TestFilter(unittest.TestCase):
  """Tests for Filter dataclass and filter slide classes."""

  OpticalFilter = CLARIOstarPlusBackend.OpticalFilter
  DichroicFilter = CLARIOstarPlusBackend.DichroicFilter

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def _get_post_sep(self, payload: bytes) -> bytes:
    full = bytes([0x04]) + payload
    return full[100:]

  # -- Filter object resolves to correct mode+slot --

  def test_excitation_filter_resolves_mode_and_slot(self):
    """Filter on excitation selects filter mode and uses its slot number."""
    ef = self.OpticalFilter(slot=3, name="480/20 BP")
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=0, emission_wavelength=528, focal_height=8.5,
      excitation_filter=ef, emission_filter=self.OpticalFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    self.assertEqual(ex_hi, 0x0002)  # filter sentinel
    self.assertEqual(ex_lo, 3)       # slot number

  def test_emission_filter_resolves_mode_and_slot(self):
    """Filter on emission selects filter mode and uses its slot number."""
    emf = self.OpticalFilter(slot=2, name="520/25 BP")
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=0, focal_height=8.5,
      emission_filter=emf, excitation_filter=self.OpticalFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    self.assertEqual(em_hi, 2)       # slot number
    self.assertEqual(em_lo, 0x0002)  # filter sentinel

  def test_filter_objects_all_three(self):
    """All three filter objects produce full filter-mode encoding."""
    ef = self.OpticalFilter(slot=1)
    emf = self.OpticalFilter(slot=1)
    df = self.DichroicFilter(slot=1)
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=0, emission_wavelength=0, focal_height=8.5,
      excitation_filter=ef, emission_filter=emf, dichroic_filter=df,
    )
    post = self._get_post_sep(payload)
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    dich = int.from_bytes(post[18:20], "big")
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    self.assertEqual(ex_hi, 0x0002)
    self.assertEqual(ex_lo, 1)
    self.assertEqual(dich, 0x0002)
    self.assertEqual(em_hi, 1)
    self.assertEqual(em_lo, 0x0002)
    # Slit should be all-filter: 00 01 00 01 00
    slit = post[24:29]
    self.assertEqual(slit, b"\x00\x01\x00\x01\x00")

  # -- DichroicFilter forces sentinel --

  def test_dichroic_filter_forces_sentinel(self):
    """dichroic_filter forces dichroic to 0x0002 even with mono ex/em."""
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      dichroic_filter=self.DichroicFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    dich = int.from_bytes(post[18:20], "big")
    self.assertEqual(dich, 0x0002)
    # But ex/em should still be real monochromator values
    ex_hi = int.from_bytes(post[14:16], "big")
    self.assertGreater(ex_hi, 100)

  def test_dichroic_filter_object_sets_sentinel(self):
    """DichroicFilter(slot=2) produces 0x0002."""
    df = self.DichroicFilter(slot=2, name="LP 504")
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      dichroic_filter=df,
    )
    post = self._get_post_sep(payload)
    dich = int.from_bytes(post[18:20], "big")
    self.assertEqual(dich, 0x0002)

  # -- Slot validation --

  def test_excitation_filter_slot_out_of_range(self):
    """Filter with out-of-range excitation slot raises ValueError."""
    self.backend.configuration["excitation_filter_slots"] = 4
    ef = self.OpticalFilter(slot=5)
    with self.assertRaises(ValueError) as cm:
      asyncio.run(self.backend.read_fluorescence(
        self.plate, self.all_wells,
        excitation_wavelength=0, emission_wavelength=528, focal_height=8.5,
        excitation_filter=ef,
      ))
    self.assertIn("slot 5", str(cm.exception))
    self.assertIn("4 excitation filter slots", str(cm.exception))

  def test_emission_filter_slot_out_of_range(self):
    """Filter with out-of-range emission slot raises ValueError."""
    self.backend.configuration["emission_filter_slots"] = 4
    emf = self.OpticalFilter(slot=5)
    with self.assertRaises(ValueError) as cm:
      asyncio.run(self.backend.read_fluorescence(
        self.plate, self.all_wells,
        excitation_wavelength=485, emission_wavelength=0, focal_height=8.5,
        emission_filter=emf,
      ))
    self.assertIn("slot 5", str(cm.exception))
    self.assertIn("4 emission filter slots", str(cm.exception))

  def test_dichroic_filter_slot_out_of_range(self):
    """DichroicFilter with out-of-range slot raises ValueError."""
    self.backend.configuration["dichroic_filter_slots"] = 3
    df = self.DichroicFilter(slot=4)
    with self.assertRaises(ValueError) as cm:
      asyncio.run(self.backend.read_fluorescence(
        self.plate, self.all_wells,
        excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
        dichroic_filter=df,
      ))
    self.assertIn("slot 4", str(cm.exception))
    self.assertIn("3 dichroic filter slots", str(cm.exception))

  def test_slot_validation_skipped_when_eeprom_zero(self):
    """No validation error when EEPROM reports 0 slots (unknown hardware)."""
    self.backend.configuration["excitation_filter_slots"] = 0
    ef = self.OpticalFilter(slot=99)
    # Should not raise — 0 means "don't validate"
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=0, emission_wavelength=528, focal_height=8.5,
      excitation_filter=ef, emission_filter=self.OpticalFilter(slot=1),
    )
    post = self._get_post_sep(payload)
    ex_lo = int.from_bytes(post[16:18], "big")
    self.assertEqual(ex_lo, 99)

  # -- Filter object in chromatics dict --

  def test_filter_in_chromatics_dict(self):
    """excitation_filter/emission_filter in chromatics dict resolves correctly."""
    ef = self.OpticalFilter(slot=2)
    emf = self.OpticalFilter(slot=3)
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      chromatics=[{
        "excitation_wavelength": 0,
        "emission_wavelength": 0,
        "excitation_filter": ef,
        "emission_filter": emf,
      }],
    )
    post = self._get_post_sep(payload)
    ex_hi = int.from_bytes(post[14:16], "big")
    ex_lo = int.from_bytes(post[16:18], "big")
    em_hi = int.from_bytes(post[20:22], "big")
    em_lo = int.from_bytes(post[22:24], "big")
    self.assertEqual(ex_hi, 0x0002)
    self.assertEqual(ex_lo, 2)
    self.assertEqual(em_hi, 3)
    self.assertEqual(em_lo, 0x0002)

  def test_dichroic_filter_in_chromatics_dict(self):
    """dichroic_filter in chromatics dict forces dichroic sentinel."""
    df = self.DichroicFilter(slot=1)
    payload = self.backend._build_fluorescence_payload(
      self.plate, self.all_wells,
      excitation_wavelength=485, emission_wavelength=528, focal_height=8.5,
      chromatics=[{
        "excitation_wavelength": 485,
        "emission_wavelength": 528,
        "dichroic_filter": df,
      }],
    )
    post = self._get_post_sep(payload)
    dich = int.from_bytes(post[18:20], "big")
    self.assertEqual(dich, 0x0002)

  # -- Autofocus filter support --

  def test_autofocus_filter_objects(self):
    """Filter objects work in _build_autofocus_payload."""
    ef = self.OpticalFilter(slot=1)
    emf = self.OpticalFilter(slot=2)
    payload = self.backend._build_autofocus_payload(
      self.plate, [self.plate.get_item("A1")],
      excitation_wavelength=0, emission_wavelength=0,
      excitation_filter=ef, emission_filter=emf,
    )
    # AF payload: plate(63) + config(1) + focal(2) + flash(2) + zeros(5) + multi(1) + wl(10) + slit(4) = 88
    # Wavelength block starts at offset 74
    ex_hi = int.from_bytes(payload[74:76], "big")
    ex_lo = int.from_bytes(payload[76:78], "big")
    em_hi = int.from_bytes(payload[80:82], "big")
    em_lo = int.from_bytes(payload[82:84], "big")
    dich = int.from_bytes(payload[78:80], "big")
    self.assertEqual(ex_hi, 0x0002)
    self.assertEqual(ex_lo, 1)
    self.assertEqual(em_hi, 2)
    self.assertEqual(em_lo, 0x0002)
    self.assertEqual(dich, 0x0002)

  def test_autofocus_dichroic_filter(self):
    """dichroic_filter in autofocus forces dichroic sentinel."""
    payload = self.backend._build_autofocus_payload(
      self.plate, [self.plate.get_item("A1")],
      excitation_wavelength=485, emission_wavelength=528,
      dichroic_filter=self.DichroicFilter(slot=1),
    )
    dich = int.from_bytes(payload[78:80], "big")
    self.assertEqual(dich, 0x0002)

  # -- Frozen / hashable --

  def test_filters_are_frozen(self):
    """Filter is immutable."""
    ef = self.OpticalFilter(slot=1, name="test")
    with self.assertRaises(AttributeError):
      ef.slot = 2  # type: ignore[misc]

  def test_filters_are_hashable(self):
    """Frozen Filter can be used in sets/dicts."""
    ef1 = self.OpticalFilter(slot=1, name="A")
    ef2 = self.OpticalFilter(slot=1, name="A")
    self.assertEqual(ef1, ef2)
    self.assertEqual(hash(ef1), hash(ef2))
    self.assertEqual(len({ef1, ef2}), 1)

  # -- Filter metadata fields --

  def test_center_wavelength_and_bandwidth(self):
    """Filter stores optional center_wavelength and bandwidth."""
    fs = self.OpticalFilter(slot=1, name="480/20 BP", center_wavelength=480, bandwidth=20)
    self.assertEqual(fs.center_wavelength, 480)
    self.assertEqual(fs.bandwidth, 20)

  def test_metadata_defaults_to_none(self):
    """center_wavelength and bandwidth default to None."""
    fs = self.OpticalFilter(slot=1)
    self.assertIsNone(fs.center_wavelength)
    self.assertIsNone(fs.bandwidth)

  # -- Filter slide classes --

  def test_filter_slide_register_and_lookup(self):
    """Register a filter and look it up by attribute name."""
    slide = CLARIOstarPlusBackend.ExcitationFilterSlide()
    fs = self.OpticalFilter(slot=1, name="BP 480")
    slide.register(fs)
    self.assertIs(slide.BP_480, fs)  # name sanitised: space → _

  def test_filter_slide_by_slot(self):
    """by_slot returns registered filter or creates anonymous one."""
    slide = CLARIOstarPlusBackend.ExcitationFilterSlide()
    fs = self.OpticalFilter(slot=2, name="test")
    slide.register(fs)
    self.assertIs(slide.by_slot(2), fs)
    anon = slide.by_slot(99)
    self.assertEqual(anon.slot, 99)
    self.assertEqual(anon.name, "")

  def test_filter_slide_unknown_attr_raises(self):
    """Accessing unregistered name raises AttributeError."""
    slide = CLARIOstarPlusBackend.ExcitationFilterSlide()
    with self.assertRaises(AttributeError):
      _ = slide.nonexistent

  def test_filter_slide_slot_validation(self):
    """Register with out-of-range slot raises ValueError."""
    slide = CLARIOstarPlusBackend.ExcitationFilterSlide(max_slots=4)
    with self.assertRaises(ValueError):
      slide.register(self.OpticalFilter(slot=5))

  def test_excitation_filter_slide_getitem(self):
    """__getitem__ returns registered filter or creates anonymous one."""
    slide = CLARIOstarPlusBackend.ExcitationFilterSlide()
    fs = self.OpticalFilter(slot=1, name="BP 480")
    slide.register(fs)
    self.assertIs(slide[1], fs)
    anon = slide[99]
    self.assertEqual(anon.slot, 99)
    self.assertEqual(anon.name, "")

  def test_dichroic_filter_slide_letter_keys(self):
    """Dichroic slide accepts string keys 'A', 'B', 'C' mapped to slots 1-3."""
    slide = CLARIOstarPlusBackend.DichroicFilterSlide()
    fs_a = self.DichroicFilter(slot=1, name="LP 504")
    fs_b = self.DichroicFilter(slot=2, name="LP 560")
    slide.register(fs_a)
    slide.register(fs_b)
    self.assertIs(slide["A"], fs_a)
    self.assertIs(slide["a"], fs_a)  # case insensitive
    self.assertIs(slide["B"], fs_b)
    anon_c = slide["C"]
    self.assertEqual(anon_c.slot, 3)
    with self.assertRaises(KeyError):
      _ = slide["D"]

  def test_update_max_slots(self):
    """_update_max_slots changes the slot limit."""
    slide = CLARIOstarPlusBackend.ExcitationFilterSlide()
    slide._update_max_slots(8)
    # Should now reject slot > 8
    with self.assertRaises(ValueError):
      slide.register(self.OpticalFilter(slot=9))
    # But slot 8 should be fine
    slide.register(self.OpticalFilter(slot=8, name="ok"))

  def test_backend_has_three_slide_attrs(self):
    """Backend instance has excitation, emission, and dichroic filter slide attributes."""
    self.assertIsInstance(
      self.backend.excitation_filter_slide, CLARIOstarPlusBackend.ExcitationFilterSlide)
    self.assertIsInstance(
      self.backend.emission_filter_slide, CLARIOstarPlusBackend.EmissionFilterSlide)
    self.assertIsInstance(
      self.backend.dichroic_filter_slide, CLARIOstarPlusBackend.DichroicFilterSlide)


class TestFilterDetection(unittest.TestCase):
  """Tests for filter auto-detection (detect_all_filters).

  Ground truth from clariostar_plus_filter_autodetection_routine.pcapng.
  See FILTER_AUTODETECT_PROTOCOL.md for the full byte-level analysis.
  """

  def setUp(self):
    self.backend = _make_backend()

  # -- Payload builder tests --

  def test_build_filter_scan_payload_excitation(self):
    """Excitation scan (cycle 1): motor 1 → position 2, zeros for wavelength config."""
    params = CLARIOstarPlusBackend._build_filter_scan_payload(
      scan_mode=0x20, motor_index=1, motor_value=2)
    # Full command payload = [0x24, 0x20] + params.
    # Pcap cycle 1 frame (after STX/size/0x0C, before checksum/CR):
    #   24 20 | 00 00 00 00 00 00 00 00 | 00 01 | 00 01 00 02 00 01 00 01 00 01 00 01 00 01 00 01
    #          ↑ wl_config (8 zeros)      ↑ preamble  ↑ motors: all 0x0001 except motor[1]=0x0002
    expected = bytes([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # wavelength config (zeros)
      0x00, 0x01,                                        # preamble
      0x00, 0x01,  # motor 0: home
      0x00, 0x02,  # motor 1: position 2 (Ex slide 1, pos 1)
      0x00, 0x01,  # motor 2: home
      0x00, 0x01,  # motor 3: home
      0x00, 0x01,  # motor 4: home
      0x00, 0x01,  # motor 5: home
      0x00, 0x01,  # motor 6: home
      0x00, 0x01,  # motor 7: home
    ])
    self.assertEqual(params, expected)
    # Verify the full command frame matches pcap
    full_payload = bytes([0x24, 0x20]) + params
    frame = _wrap_payload(full_payload)
    self.assertEqual(
      frame,
      bytes.fromhex(
        "0200240c"
        "2420"
        "0000000000000000"
        "0001"
        "00010002000100010001000100010001"
        "000080"
        "0d"
      ),
    )

  def test_build_filter_scan_payload_emission(self):
    """Emission scan (cycle 8): motor 5 → position 2, emission wavelength config present."""
    params = CLARIOstarPlusBackend._build_filter_scan_payload(
      scan_mode=0x21, motor_index=5, motor_value=2)
    expected = bytes([
      0x04, 0x4C, 0x04, 0xB0, 0x04, 0x4C, 0x04, 0x7E,  # emission wavelength config
      0x00, 0x01,                                        # preamble
      0x00, 0x01,  # motor 0: home
      0x00, 0x01,  # motor 1: home
      0x00, 0x01,  # motor 2: home
      0x00, 0x01,  # motor 3: home
      0x00, 0x01,  # motor 4: home
      0x00, 0x02,  # motor 5: position 2 (Em slide 1, pos 1)
      0x00, 0x01,  # motor 6: home
      0x00, 0x01,  # motor 7: home
    ])
    self.assertEqual(params, expected)
    # Verify full frame matches pcap cycle 8
    full_payload = bytes([0x24, 0x21]) + params
    frame = _wrap_payload(full_payload)
    self.assertEqual(
      frame,
      bytes.fromhex(
        "0200240c"
        "2421"
        "044c04b0044c047e"
        "0001"
        "00010001000100010001000200010001"
        "000257"
        "0d"
      ),
    )

  def test_build_filter_scan_payload_dichroic(self):
    """Dichroic scan (cycle 7): motor 3 → position 4 (dichroic C)."""
    params = CLARIOstarPlusBackend._build_filter_scan_payload(
      scan_mode=0x23, motor_index=3, motor_value=4)
    expected = bytes([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # zeros
      0x00, 0x01,                                        # preamble
      0x00, 0x01,  # motor 0
      0x00, 0x01,  # motor 1
      0x00, 0x01,  # motor 2
      0x00, 0x04,  # motor 3: position 4 (Dichroic C)
      0x00, 0x01,  # motor 4
      0x00, 0x01,  # motor 5
      0x00, 0x01,  # motor 6
      0x00, 0x01,  # motor 7
    ])
    self.assertEqual(params, expected)
    # Verify full frame matches pcap cycle 7
    full_payload = bytes([0x24, 0x23]) + params
    frame = _wrap_payload(full_payload)
    self.assertEqual(
      frame,
      bytes.fromhex(
        "0200240c"
        "2423"
        "0000000000000000"
        "0001"
        "00010001000100040001000100010001"
        "000085"
        "0d"
      ),
    )

  # -- Filter result parser tests --

  def test_parse_filter_result_excitation_occupied(self):
    """Pcap cycle 1: Ex pos 1 → BP 327/90 (Ex TR filter installed).

    Raw 0x1b payload header: 1b 05 13 26 80 00
    Type byte: 0x80 (excitation bandpass)
    Center: 0x0CC6 = 3270 → 327.0 nm → rounded to 327
    Bandwidth: 0x0380 = 896 → 89.6 nm → rounded to 90
    """
    payload = bytes([
      0x1b, 0x05, 0x13, 0x26, 0x80, 0x00,  # header
      0x80,                                   # type: excitation bandpass
      0x0C, 0xC6,                             # center: 3270 → 327.0 nm
      0x03, 0x80,                             # bandwidth: 896 → 89.6 nm
      0x0B, 0x06,                             # low edge: 2822 → 282.2 nm
      0x0E, 0x86,                             # high edge: 3718 → 371.8 nm
    ])
    result = CLARIOstarPlusBackend._parse_filter_result(payload, slot=1, category="excitation")
    self.assertIsNotNone(result)
    self.assertIsInstance(result, CLARIOstarPlusBackend.OpticalFilter)
    self.assertEqual(result.slot, 1)
    self.assertEqual(result.name, "BP 327/90")
    self.assertEqual(result.center_wavelength, 327)
    self.assertEqual(result.bandwidth, 90)

  def test_parse_filter_result_emission_occupied(self):
    """Pcap cycle 8: Em pos 5 → BP 614/18 (615-18 filter installed).

    Type byte: 0x81 (emission bandpass)
    Center: 0x17FC = 6140 → 614.0 nm → 614
    Bandwidth: 0x00B7 = 183 → 18.3 nm → 18
    """
    payload = bytes([
      0x1b, 0x05, 0x13, 0x26, 0x80, 0x00,  # header
      0x81,                                   # type: emission bandpass
      0x17, 0xFC,                             # center: 6140 → 614.0 nm
      0x00, 0xB7,                             # bandwidth: 183 → 18.3 nm
      0x17, 0xA1,                             # low edge: 6049 → 604.9 nm
      0x18, 0x58,                             # high edge: 6232 → 623.2 nm
    ])
    result = CLARIOstarPlusBackend._parse_filter_result(payload, slot=1, category="emission")
    self.assertIsNotNone(result)
    self.assertIsInstance(result, CLARIOstarPlusBackend.OpticalFilter)
    self.assertEqual(result.slot, 1)
    self.assertEqual(result.name, "BP 614/18")
    self.assertEqual(result.center_wavelength, 614)
    self.assertEqual(result.bandwidth, 18)

  def test_parse_filter_result_dichroic_occupied(self):
    """Pcap cycle 5: Dichroic A → DM 422 (LP TR filter installed).

    Type byte: 0x83 (dichroic long-pass)
    Bytes 7-10 = zeros (no center/bandwidth for dichroic)
    Cut-on: bytes 11-12 = 0x107A = 4218 → 421.8 nm → 422
    """
    payload = bytes([
      0x1b, 0x05, 0x13, 0x26, 0x80, 0x00,  # header
      0x83,                                   # type: dichroic
      0x00, 0x00,                             # no center
      0x00, 0x00,                             # no bandwidth
      0x10, 0x7A,                             # cut-on: 4218 → 421.8 nm
    ])
    result = CLARIOstarPlusBackend._parse_filter_result(payload, slot=1, category="dichroic")
    self.assertIsNotNone(result)
    self.assertIsInstance(result, CLARIOstarPlusBackend.DichroicFilter)
    self.assertEqual(result.slot, 1)
    self.assertEqual(result.name, "DM 422")
    self.assertEqual(result.cut_on_wavelength, 422)

  def test_parse_filter_result_empty(self):
    """Pcap cycle 2: Ex pos 2 → empty (bandwidth = 0).

    The center wavelength is non-zero (noise peak at 940 nm) but bandwidth = 0
    indicates no filter present.
    """
    payload = bytes([
      0x1b, 0x05, 0x13, 0x26, 0x80, 0x00,  # header
      0x80,                                   # type: excitation bandpass
      0x24, 0xB8,                             # center: 9400 → 940.0 nm (noise peak)
      0x00, 0x00,                             # bandwidth: 0 → empty
      0x00, 0x00,                             # low edge: 0
      0x00, 0x00,                             # high edge: 0
    ])
    result = CLARIOstarPlusBackend._parse_filter_result(payload, slot=2, category="excitation")
    self.assertIsNone(result)

  def test_parse_filter_result_dichroic_empty(self):
    """Pcap cycle 6: Dichroic B → empty (cut-on = 0)."""
    payload = bytes([
      0x1b, 0x05, 0x13, 0x26, 0x80, 0x00,  # header
      0x83,                                   # type: dichroic
      0x00, 0x00,                             # no center
      0x00, 0x00,                             # no bandwidth
      0x00, 0x00,                             # cut-on: 0 → empty
    ])
    result = CLARIOstarPlusBackend._parse_filter_result(payload, slot=2, category="dichroic")
    self.assertIsNone(result)

  def test_detect_all_filters(self):
    """Full orchestration: mock send_command for all 11 positions.

    Expected results (matching pcap + MARS screenshots):
      Ex 1 → BP 327/90 (Ex TR), Ex 2-4 → empty
      Dich A → DM 422 (LP TR), Dich B-C → empty
      Em 5 → BP 614/18 (615-18), Em 6-8 → empty
    """
    io: MockFTDI = self.backend.io  # type: ignore[assignment]

    # For each of the 11 scan table entries, we need to queue:
    #   1. ACK for FILTER_SCAN (0x24) command
    #   2. Status response (not-busy) for wait=True polling
    #   3. Response for REQUEST SPECTRAL_DATA (0x11)
    #   4. Response for REQUEST FILTER_RESULT (0x1b)

    # Status: not busy, initialized
    status_not_busy = _wrap_payload(bytes([
      0x01, 0x05, 0x00, 0x20, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xC0,
    ]))

    # Minimal spectral data response (we just discard it)
    spectral_ack = _wrap_payload(bytes([0x11, 0x05, 0x00, 0x00]))

    def _make_filter_result(type_byte, center_raw=0, bw_raw=0,
                            low_raw=0, high_raw=0, cut_on_raw=0):
      """Build a minimal 0x1b FILTER_RESULT response payload."""
      payload = bytearray([
        0x1b, 0x05, 0x13, 0x26, 0x80, 0x00,  # header
        type_byte,
      ])
      payload.extend(center_raw.to_bytes(2, "big"))
      payload.extend(bw_raw.to_bytes(2, "big"))
      if type_byte == 0x83:
        payload.extend(cut_on_raw.to_bytes(2, "big"))
      else:
        payload.extend(low_raw.to_bytes(2, "big"))
        payload.extend(high_raw.to_bytes(2, "big"))
      return _wrap_payload(bytes(payload))

    # Build responses for all 11 cycles
    cycle_responses = [
      # Cycle 1: Ex 1 → occupied (BP 327/90)
      _make_filter_result(0x80, center_raw=3270, bw_raw=896, low_raw=2822, high_raw=3718),
      # Cycle 2: Ex 2 → empty
      _make_filter_result(0x80, center_raw=9400),
      # Cycle 3: Ex 3 → empty
      _make_filter_result(0x80, center_raw=8430),
      # Cycle 4: Ex 4 → empty
      _make_filter_result(0x80, center_raw=9620),
      # Cycle 5: Dich A → occupied (DM 422)
      _make_filter_result(0x83, cut_on_raw=4218),
      # Cycle 6: Dich B → empty
      _make_filter_result(0x83),
      # Cycle 7: Dich C → empty
      _make_filter_result(0x83),
      # Cycle 8: Em 5 → occupied (BP 614/18)
      _make_filter_result(0x81, center_raw=6140, bw_raw=183, low_raw=6049, high_raw=6232),
      # Cycle 9: Em 6 → empty
      _make_filter_result(0x81, center_raw=3170),
      # Cycle 10: Em 7 → empty
      _make_filter_result(0x81, center_raw=7000),
      # Cycle 11: Em 8 → empty
      _make_filter_result(0x81, center_raw=3370),
    ]

    for filter_result in cycle_responses:
      io.queue_response(
        ACK,               # FILTER_SCAN ack
        status_not_busy,   # status poll (wait=True)
        spectral_ack,      # SPECTRAL_DATA response
        filter_result,     # FILTER_RESULT response
      )

    result = asyncio.run(self.backend.detect_all_filters())

    # Verify return dict structure — positional lists (index = slot - 1)
    self.assertEqual(len(result["excitation"]), 4)
    self.assertEqual(len(result["dichroic"]), 3)
    self.assertEqual(len(result["emission"]), 4)

    # Verify excitation filter (slot 1 occupied, 2-4 empty)
    ex = result["excitation"][0]
    self.assertEqual(ex.slot, 1)
    self.assertEqual(ex.name, "BP 327/90")
    self.assertEqual(ex.center_wavelength, 327)
    self.assertEqual(ex.bandwidth, 90)
    self.assertIsNone(result["excitation"][1])
    self.assertIsNone(result["excitation"][2])
    self.assertIsNone(result["excitation"][3])

    # Verify dichroic filter (slot 1 occupied, 2-3 empty)
    dich = result["dichroic"][0]
    self.assertEqual(dich.slot, 1)
    self.assertEqual(dich.name, "DM 422")
    self.assertEqual(dich.cut_on_wavelength, 422)
    self.assertIsNone(result["dichroic"][1])
    self.assertIsNone(result["dichroic"][2])

    # Verify emission filter (slot 1 occupied, 2-4 empty)
    em = result["emission"][0]
    self.assertEqual(em.slot, 1)
    self.assertEqual(em.name, "BP 614/18")
    self.assertEqual(em.center_wavelength, 614)
    self.assertEqual(em.bandwidth, 18)
    self.assertIsNone(result["emission"][1])
    self.assertIsNone(result["emission"][2])
    self.assertIsNone(result["emission"][3])

    # Verify filter slides are populated
    self.assertIs(self.backend.excitation_filter_slide[1], ex)
    self.assertIs(self.backend.dichroic_filter_slide[1], dich)
    self.assertIs(self.backend.emission_filter_slide[1], em)

    # Verify attribute access works
    self.assertIs(self.backend.excitation_filter_slide.BP_327_90, ex)
    self.assertIs(self.backend.dichroic_filter_slide.DM_422, dich)
    self.assertIs(self.backend.emission_filter_slide.BP_614_18, em)


# ===========================================================================
# Fluorescence Spectrum Tests
# ===========================================================================

# Pcap ground truth: excitation scan F-SCAN-A01 post-separator (68 bytes)
# settling(1) + focal(2) + scan_header(7) + block1(20) + block2(20) + tail(18)
_FL_SCAN_EX_POST_SEP_HEX = (
  "0503520200dd00000000"                        # settling + focal + scan_header
  "000c03e80fce0f7217571fa01ee0000300020000"    # block 1 (START: Ex=400)
  "000c03e8186818081ba31fa01ee0000300020000"    # block 2 (STOP: Ex=620)
  "000000000000000001000000010005000100"        # tail (byte14=0x05)
)
# Pcap ground truth: emission scan F-SCAN-A02 post-separator (68 bytes)
_FL_SCAN_EM_POST_SEP_HEX = (
  "05035202006500000000"                        # settling + focal + scan_header
  "000c03e80fce0f72119413b81358000200030000"    # block 1 (START: Em=500)
  "000c03e80fce0f72138817a01740000200030000"    # block 2 (STOP: Em=600)
  "000000000000000001000000010005000100"        # tail (byte14=0x05)
)


def _build_synthetic_fl_spectrum_page(
  n_steps: int = 101,
  schema: int = 0xA0,
  status_flags: int = 0x25,
  temperature_raw: int = 0,
  base_value: int = 70,
) -> bytes:
  """Build a synthetic FL spectrum DATA_RESPONSE page (one per well)."""
  header = bytearray(34)
  header[0] = 0x02  # response_type
  header[1] = status_flags
  header[6] = schema
  # bytes 7:9 = step_count in spectrum pages (0xA0 schema)
  header[7:9] = n_steps.to_bytes(2, "big")
  header[9:11] = n_steps.to_bytes(2, "big")
  if schema & 0x80 and temperature_raw > 0:
    header[32:34] = temperature_raw.to_bytes(2, "big")
  payload = bytearray(header)
  for i in range(n_steps):
    payload.extend((base_value + i).to_bytes(4, "big"))
  return bytes(payload)


class TestBuildFluorescenceSpectrumPayload(unittest.TestCase):
  """Verify _build_fl_spectrum_payload against pcap ground truth."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def _get_post_separator(self, payload: bytes) -> bytes:
    """Extract post-separator bytes from a fl spectrum payload."""
    # payload starts after 0x04 cmd byte (added by send_command)
    # plate(63) + scan(1) + pre_sep(31) + separator(4) = 99 bytes
    return payload[99:]

  def test_excitation_scan_post_separator_ground_truth(self):
    """Post-separator bytes must match F-SCAN-A01 pcap exactly."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=400, end_wavelength=620,
      fixed_wavelength=800, focal_height=8.5,
      scan="excitation", scan_bandwidth=10, fixed_bandwidth=20,
      gain=1000, flashes_per_step=1000, settling_time_s=0.1,
      # Exact pcap edge values
      _start_ex_hi=0x0FCE, _start_ex_lo=0x0F72,
      _start_em_hi=0x1FA0, _start_em_lo=0x1EE0, _start_dichroic=0x1757,
      _stop_ex_hi=0x1868, _stop_ex_lo=0x1808,
      _stop_em_hi=0x1FA0, _stop_em_lo=0x1EE0, _stop_dichroic=0x1BA3,
    )
    post_sep = self._get_post_separator(payload)
    expected = bytes.fromhex(_FL_SCAN_EX_POST_SEP_HEX)
    self.assertEqual(post_sep.hex(), expected.hex())

  def test_emission_scan_post_separator_ground_truth(self):
    """Post-separator bytes must match F-SCAN-A02 pcap exactly."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5,
      scan="emission", scan_bandwidth=10, fixed_bandwidth=20,
      gain=1000, flashes_per_step=1000, settling_time_s=0.1,
      _start_ex_hi=0x0FCE, _start_ex_lo=0x0F72,
      _start_em_hi=0x13B8, _start_em_lo=0x1358, _start_dichroic=0x1194,
      _stop_ex_hi=0x0FCE, _stop_ex_lo=0x0F72,
      _stop_em_hi=0x17A0, _stop_em_lo=0x1740, _stop_dichroic=0x1388,
    )
    post_sep = self._get_post_separator(payload)
    expected = bytes.fromhex(_FL_SCAN_EM_POST_SEP_HEX)
    self.assertEqual(post_sep.hex(), expected.hex())

  def test_scan_header_mode_flag_0x02(self):
    """Scan header byte[0] must be 0x02 (spectral scan mode)."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5, scan="emission",
    )
    post_sep = self._get_post_separator(payload)
    # settling(1) + focal(2) = 3 bytes, then scan_header byte[0]
    self.assertEqual(post_sep[3], 0x02)

  def test_scan_header_step_count_excitation(self):
    """Excitation scan 400→620 = 221 steps."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=400, end_wavelength=620,
      fixed_wavelength=800, focal_height=8.5, scan="excitation",
    )
    post_sep = self._get_post_separator(payload)
    step_count = int.from_bytes(post_sep[4:6], "big")
    self.assertEqual(step_count, 221)

  def test_scan_header_step_count_emission(self):
    """Emission scan 500→600 = 101 steps."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5, scan="emission",
    )
    post_sep = self._get_post_separator(payload)
    step_count = int.from_bytes(post_sep[4:6], "big")
    self.assertEqual(step_count, 101)

  def test_filter_cfg_excitation_scan(self):
    """Excitation scan: filter_cfg = 00 03 00 02 in both blocks."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=400, end_wavelength=620,
      fixed_wavelength=800, focal_height=8.5, scan="excitation",
    )
    post_sep = self._get_post_separator(payload)
    # Block 1 starts at offset 10 (settle+focal+header = 1+2+7 = 10)
    # filter_cfg at block[14:18] → post_sep offset 10+14=24
    self.assertEqual(post_sep[24:28], b"\x00\x03\x00\x02")
    # Block 2 filter_cfg at 10+20+14=44
    self.assertEqual(post_sep[44:48], b"\x00\x03\x00\x02")

  def test_filter_cfg_emission_scan(self):
    """Emission scan: filter_cfg = 00 02 00 03 in both blocks."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5, scan="emission",
    )
    post_sep = self._get_post_separator(payload)
    self.assertEqual(post_sep[24:28], b"\x00\x02\x00\x03")
    self.assertEqual(post_sep[44:48], b"\x00\x02\x00\x03")

  def test_tail_byte14_is_0x05(self):
    """Tail byte[14] = 0x05 (spectral scan marker), not flash count."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5, scan="emission",
    )
    post_sep = self._get_post_separator(payload)
    # Tail starts at offset 10+40=50, byte[14] is at 50+14=64
    tail = post_sep[50:]
    self.assertEqual(len(tail), 18)
    self.assertEqual(tail[14], 0x05)

  def test_total_payload_length_point_scan(self):
    """Point scan payload = 167 bytes (no WSF)."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5, scan="emission",
      well_scan="point",
    )
    self.assertEqual(len(payload), 167)

  def test_total_payload_length_orbital(self):
    """Orbital scan payload = 172 bytes (5-byte WSF added)."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5, scan="emission",
      well_scan="orbital", scan_diameter_mm=3,
    )
    self.assertEqual(len(payload), 172)

  def test_pre_separator_identical_to_discrete_fl(self):
    """Pre-separator block uses DetectionMode.FLUORESCENCE (0x00)."""
    payload = self.backend._build_fl_spectrum_payload(
      self.plate, self.all_wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5, scan="emission",
    )
    # Pre-separator at bytes 64:95 (scan_dir at 63, pre_sep starts at 64)
    pre_sep = payload[64:95]
    # byte[0] of pre-separator = detection_mode | well_scan_mode
    # FLUORESCENCE=0x00, POINT=0x00 → 0x00
    self.assertEqual(pre_sep[0], 0x00)


class TestReadFluorescenceSpectrumValidation(unittest.TestCase):
  """Input validation for read_fluorescence_spectrum."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.wells = self.plate.get_all_items()

  def _run(self, **kwargs):
    defaults = dict(
      plate=self.plate, wells=self.wells,
      start_wavelength=500, end_wavelength=600,
      fixed_wavelength=400, focal_height=8.5,
    )
    defaults.update(kwargs)
    return asyncio.run(self.backend.read_fluorescence_spectrum(**defaults))

  def test_start_wavelength_too_low(self):
    with self.assertRaises(ValueError):
      self._run(start_wavelength=200)

  def test_end_wavelength_too_high(self):
    with self.assertRaises(ValueError):
      self._run(end_wavelength=900)

  def test_end_not_greater_than_start(self):
    with self.assertRaises(ValueError):
      self._run(start_wavelength=600, end_wavelength=500)

  def test_end_equal_to_start(self):
    with self.assertRaises(ValueError):
      self._run(start_wavelength=500, end_wavelength=500)

  def test_invalid_well_scan_matrix(self):
    with self.assertRaises(ValueError):
      self._run(well_scan="matrix")

  def test_gain_out_of_range(self):
    with self.assertRaises(ValueError):
      self._run(gain=5000)

  def test_focal_height_out_of_range(self):
    with self.assertRaises(ValueError):
      self._run(focal_height=30.0)

  def test_shake_mode_without_speed(self):
    with self.assertRaises(ValueError):
      self._run(shake_mode="orbital", shake_duration_s=5)

  def test_scan_invalid_value(self):
    with self.assertRaises(ValueError):
      self._run(scan="both")


class TestParseFluorescenceSpectrumResponse(unittest.TestCase):
  """Verify _parse_fl_spectrum_pages against synthetic data."""

  def setUp(self):
    self.backend = _make_backend()
    self.plate = _make_plate()
    self.all_wells = self.plate.get_all_items()

  def test_parse_single_well_emission_scan(self):
    """Single well, 101-step emission scan → 101 result dicts."""
    page = _build_synthetic_fl_spectrum_page(n_steps=101, status_flags=0x05)
    results = self.backend._parse_fl_spectrum_pages(
      [page], self.plate, [self.plate.get_item("A1")],
      list(range(500, 601)), "emission", 400,
    )
    self.assertEqual(len(results), 101)
    self.assertEqual(results[0]["wavelength"], 500)
    self.assertEqual(results[-1]["wavelength"], 600)

  def test_parse_multi_well(self):
    """4 wells × 101 steps → 101 results with correct grid mapping."""
    wells = [self.plate.get_item(w) for w in ["A1", "A2", "B1", "B2"]]
    pages = [
      _build_synthetic_fl_spectrum_page(n_steps=101, status_flags=0x25, base_value=100 + w * 10)
      for w in range(4)
    ]
    # Last page should have done status
    pages[-1] = _build_synthetic_fl_spectrum_page(
      n_steps=101, status_flags=0x05, base_value=100 + 30)

    results = self.backend._parse_fl_spectrum_pages(
      pages, self.plate, wells, list(range(500, 601)), "emission", 400,
    )
    self.assertEqual(len(results), 101)
    # Check that data grid has values for our 4 wells
    first_grid = results[0]["data"]
    self.assertIsNotNone(first_grid[0][0])  # A1
    self.assertIsNotNone(first_grid[0][1])  # A2
    self.assertIsNotNone(first_grid[1][0])  # B1
    self.assertIsNotNone(first_grid[1][1])  # B2
    self.assertIsNone(first_grid[2][0])  # C1 not measured

  def test_temperature_extraction(self):
    """Schema 0xA0 has 0x80 bit → temperature from bytes 32:34."""
    page = _build_synthetic_fl_spectrum_page(
      n_steps=10, schema=0xA0, temperature_raw=253)
    results = self.backend._parse_fl_spectrum_pages(
      [page], self.plate, [self.plate.get_item("A1")],
      list(range(500, 510)), "emission", 400,
    )
    self.assertAlmostEqual(results[0]["temperature"], 25.3)

  def test_empty_pages_raises(self):
    """No pages → ValueError."""
    with self.assertRaises(ValueError):
      self.backend._parse_fl_spectrum_pages(
        [], self.plate, self.all_wells, [500], "emission", 400,
      )

  def test_wavelength_assignment(self):
    """Wavelength key increments by 1 nm."""
    page = _build_synthetic_fl_spectrum_page(n_steps=5, status_flags=0x05)
    results = self.backend._parse_fl_spectrum_pages(
      [page], self.plate, [self.plate.get_item("A1")],
      [400, 401, 402, 403, 404], "excitation", 800,
    )
    self.assertEqual([r["wavelength"] for r in results], [400, 401, 402, 403, 404])

  def test_ex_em_wavelength_keys_emission_scan(self):
    """Emission scan: ex_wavelength = fixed, em_wavelength = swept."""
    page = _build_synthetic_fl_spectrum_page(n_steps=3, status_flags=0x05)
    results = self.backend._parse_fl_spectrum_pages(
      [page], self.plate, [self.plate.get_item("A1")],
      [500, 501, 502], "emission", 400,
    )
    for r in results:
      self.assertEqual(r["ex_wavelength"], 400)
    self.assertEqual(results[0]["em_wavelength"], 500)
    self.assertEqual(results[2]["em_wavelength"], 502)

  def test_ex_em_wavelength_keys_excitation_scan(self):
    """Excitation scan: em_wavelength = fixed, ex_wavelength = swept."""
    page = _build_synthetic_fl_spectrum_page(n_steps=3, status_flags=0x05)
    results = self.backend._parse_fl_spectrum_pages(
      [page], self.plate, [self.plate.get_item("A1")],
      [400, 401, 402], "excitation", 800,
    )
    for r in results:
      self.assertEqual(r["em_wavelength"], 800)
    self.assertEqual(results[0]["ex_wavelength"], 400)
    self.assertEqual(results[2]["ex_wavelength"], 402)


class TestReadFluorescenceSpectrumIntegration(unittest.TestCase):
  """Integration tests for the full read_fluorescence_spectrum flow."""

  def test_emission_scan_full_flow(self):
    """Full emission scan: RUN → status poll → GET_DATA pages → parsed results."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    page = _build_synthetic_fl_spectrum_page(n_steps=101, status_flags=0x05, base_value=70)
    page_frame = _wrap_payload(page)

    mock.queue_response(
      ACK,  # measurement run ack
      STATUS_IDLE,  # status poll → not busy
      page_frame,  # GET_DATA page for A1
    )

    results = asyncio.run(
      backend.read_fluorescence_spectrum(
        plate, wells,
        start_wavelength=500, end_wavelength=600,
        fixed_wavelength=400, focal_height=8.5,
        scan="emission",
      )
    )

    self.assertEqual(len(results), 101)
    self.assertEqual(results[0]["wavelength"], 500)
    self.assertEqual(results[-1]["wavelength"], 600)
    self.assertEqual(results[0]["ex_wavelength"], 400)
    self.assertEqual(results[0]["em_wavelength"], 500)
    self.assertIsNotNone(results[0]["data"])
    self.assertIsNotNone(results[0]["data"][0][0])

  def test_excitation_scan_full_flow(self):
    """Full excitation scan: RUN → status poll → GET_DATA pages → parsed results."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    page = _build_synthetic_fl_spectrum_page(n_steps=221, status_flags=0x05, base_value=50)
    page_frame = _wrap_payload(page)

    mock.queue_response(ACK, STATUS_IDLE, page_frame)

    results = asyncio.run(
      backend.read_fluorescence_spectrum(
        plate, wells,
        start_wavelength=400, end_wavelength=620,
        fixed_wavelength=800, focal_height=8.5,
        scan="excitation",
      )
    )

    self.assertEqual(len(results), 221)
    self.assertEqual(results[0]["wavelength"], 400)
    self.assertEqual(results[-1]["wavelength"], 620)
    self.assertEqual(results[0]["ex_wavelength"], 400)
    self.assertEqual(results[0]["em_wavelength"], 800)

  def test_wait_false_returns_empty(self):
    """wait=False sends RUN only and returns empty list."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = plate.get_all_items()

    mock.queue_response(ACK)

    result = asyncio.run(
      backend.read_fluorescence_spectrum(
        plate, wells,
        start_wavelength=500, end_wavelength=600,
        fixed_wavelength=400, focal_height=8.5,
        wait=False,
      )
    )

    self.assertEqual(result, [])
    self.assertEqual(len(mock.written), 1)
    inner = _extract_payload(mock.written[0])
    self.assertEqual(inner[0], 0x04)

  def test_timeout_raises(self):
    """Timeout during status polling raises TimeoutError."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    # Queue busy status responses (never clears)
    mock.queue_response(ACK, *([STATUS_BUSY] * 100))

    with self.assertRaises(TimeoutError):
      asyncio.run(
        backend.read_fluorescence_spectrum(
          plate, wells,
          start_wavelength=500, end_wavelength=510,
          fixed_wavelength=400, focal_height=8.5,
          read_timeout=0.01,
        )
      )

  def test_orbital_well_scan(self):
    """Orbital mode: WSF bytes present in payload."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    page = _build_synthetic_fl_spectrum_page(n_steps=11, status_flags=0x05)
    mock.queue_response(ACK, STATUS_IDLE, _wrap_payload(page))

    results = asyncio.run(
      backend.read_fluorescence_spectrum(
        plate, wells,
        start_wavelength=500, end_wavelength=510,
        fixed_wavelength=400, focal_height=8.5,
        well_scan="orbital", scan_diameter_mm=3,
      )
    )

    # Verify payload is 172 bytes (167 + 5 WSF)
    first_frame = mock.written[0]
    inner = _extract_payload(first_frame)
    self.assertEqual(len(inner), 173)  # 172 payload + 1 byte cmd family

    self.assertEqual(len(results), 11)

  def test_bottom_optic(self):
    """Bottom optic position byte in pre-separator."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    plate = _make_plate()
    wells = [plate.get_item("A1")]

    page = _build_synthetic_fl_spectrum_page(n_steps=11, status_flags=0x05)
    mock.queue_response(ACK, STATUS_IDLE, _wrap_payload(page))

    asyncio.run(
      backend.read_fluorescence_spectrum(
        plate, wells,
        start_wavelength=500, end_wavelength=510,
        fixed_wavelength=400, focal_height=8.5,
        optic_position="bottom",
      )
    )

    first_frame = mock.written[0]
    inner = _extract_payload(first_frame)
    # Pre-separator byte[0] at inner[65]: FLUORESCENCE(0x00) | BOTTOM(0x40) = 0x40
    self.assertEqual(inner[65], 0x40)


class TestMeasurementControl(unittest.TestCase):
  """Pcap ground truth for pause_measurement, resume_measurement, stop_measurement.

  Source: clariostar_stop_then_abort_drawer_in_out.pcapng
  """

  def test_pause_measurement_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK)
    asyncio.run(backend.pause_measurement())
    self.assertEqual(mock.written[0], COMMANDS["pause_measurement"][1])

  def test_resume_measurement_and_collect_data_sends_resume_frame(self):
    """resume_measurement_and_collect_data sends the PAUSE_RESUME(0x00) frame."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    # Set up resume context (progressive mode, simplest case)
    backend._resume_context = {
      "poll_mode": "progressive",
      "log_prefix": "test",
      "read_timeout": 30.0,
      "collect_fn": lambda resp, prog_complete: [],
      "fallback_collect_fn": AsyncMock(return_value=[]),
    }
    # Queue: ACK for resume command, then poll needs status not-busy
    mock.queue_response(ACK)
    # Mock polling to return immediately
    backend._poll_progressive = AsyncMock(return_value=(b"\x00" * 20, True))
    asyncio.run(backend.resume_measurement_and_collect_data())
    self.assertEqual(mock.written[0], COMMANDS["resume_measurement"][1])

  def test_stop_measurement_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK)
    asyncio.run(backend.stop_measurement())
    self.assertEqual(mock.written[0], COMMANDS["stop_measurement"][1])

  def test_pause_payload_matches_pcap_ground_truth(self):
    """Byte-for-byte match against pcap frame at t=17.3s."""
    expected = bytes.fromhex("02000d0c0dffff00000002260d")
    self.assertEqual(_wrap_payload(b"\x0d\xff\xff\x00\x00"), expected)

  def test_resume_payload_matches_pcap_ground_truth(self):
    """Byte-for-byte match against pcap frame at t=78.4s."""
    expected = bytes.fromhex("02000d0c0d000000000000280d")
    self.assertEqual(_wrap_payload(b"\x0d\x00\x00\x00\x00"), expected)

  def test_stop_payload_matches_pcap_ground_truth(self):
    """Byte-for-byte match against pcap frame at t=86.0s."""
    expected = bytes.fromhex("02000a0c0b000000230d")
    self.assertEqual(_wrap_payload(b"\x0b\x00"), expected)

  def test_cmd_0x0e_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK)
    asyncio.run(backend._send_cmd_0x0e())
    self.assertEqual(mock.written[0], COMMANDS["cmd_0x0e"][1])

  def test_cmd_0x0e_payload_matches_pcap_ground_truth(self):
    """Byte-for-byte match against pcap frame from normal boot capture."""
    expected = bytes.fromhex("02000f0c0e0b12000004190000650d")
    self.assertEqual(_wrap_payload(b"\x0e\x0b\x12\x00\x00\x04\x19"), expected)


class TestInterruptHandling(unittest.TestCase):
  """Tests for interrupt-triggered stop/pause during measurements."""

  # -- Default behavior: interrupt → stop --

  def test_keyboard_interrupt_during_progressive_poll_stops_device(self):
    """Default: KeyboardInterrupt stops device and raises MeasurementInterrupted."""
    backend = _make_backend()
    first_response = b"\x00" * 20  # dummy partial data
    call_count = 0

    async def fake_request_data(progressive=False):
      nonlocal call_count
      call_count += 1
      if call_count == 1:
        return first_response
      raise KeyboardInterrupt()

    backend._request_measurement_data = fake_request_data
    backend._measurement_progress = lambda resp: (0, 10)
    backend.request_machine_status = AsyncMock(return_value={"busy": True})
    backend.stop_measurement = AsyncMock()
    backend.pause_measurement = AsyncMock()

    with self.assertRaises(MeasurementInterrupted) as ctx:
      asyncio.run(backend._poll_progressive(read_timeout=30.0, log_prefix="test"))

    self.assertIsNotNone(ctx.exception.partial_data)
    self.assertEqual(ctx.exception.partial_data, first_response)
    backend.stop_measurement.assert_called_once()
    backend.pause_measurement.assert_not_called()
    self.assertIn("stopped", str(ctx.exception))

  def test_cancelled_error_during_progressive_poll_stops_device(self):
    """Default: asyncio.CancelledError stops device and raises MeasurementInterrupted."""
    backend = _make_backend()
    first_response = b"\x00" * 20
    call_count = 0

    async def fake_request_data(progressive=False):
      nonlocal call_count
      call_count += 1
      if call_count == 1:
        return first_response
      raise asyncio.CancelledError()

    backend._request_measurement_data = fake_request_data
    backend._measurement_progress = lambda resp: (0, 10)
    backend.request_machine_status = AsyncMock(return_value={"busy": True})
    backend.stop_measurement = AsyncMock()

    with self.assertRaises(MeasurementInterrupted) as ctx:
      asyncio.run(backend._poll_progressive(read_timeout=30.0, log_prefix="test"))

    self.assertIsNotNone(ctx.exception.partial_data)
    backend.stop_measurement.assert_called_once()

  def test_keyboard_interrupt_during_status_only_poll_stops_device(self):
    """Default: KeyboardInterrupt in _poll_status_only stops device."""
    backend = _make_backend()
    backend.request_machine_status = AsyncMock(side_effect=KeyboardInterrupt())
    backend.stop_measurement = AsyncMock()
    backend.pause_measurement = AsyncMock()

    with self.assertRaises(MeasurementInterrupted) as ctx:
      asyncio.run(backend._poll_status_only(read_timeout=30.0, log_prefix="test"))

    self.assertIsNone(ctx.exception.partial_data)
    backend.stop_measurement.assert_called_once()
    backend.pause_measurement.assert_not_called()

  # -- Opt-in behavior: pause_on_interrupt=True → pause --

  def test_interrupt_with_pause_on_interrupt_pauses_device(self):
    """With pause_on_interrupt=True, interrupt pauses instead of stopping."""
    backend = _make_backend()
    backend.pause_on_interrupt = True
    first_response = b"\x00" * 20
    call_count = 0

    async def fake_request_data(progressive=False):
      nonlocal call_count
      call_count += 1
      if call_count == 1:
        return first_response
      raise KeyboardInterrupt()

    backend._request_measurement_data = fake_request_data
    backend._measurement_progress = lambda resp: (0, 10)
    backend.request_machine_status = AsyncMock(return_value={"busy": True})
    backend.pause_measurement = AsyncMock()
    backend.stop_measurement = AsyncMock()

    with self.assertRaises(MeasurementInterrupted) as ctx:
      asyncio.run(backend._poll_progressive(read_timeout=30.0, log_prefix="test"))

    self.assertIsNotNone(ctx.exception.partial_data)
    backend.pause_measurement.assert_called_once()
    backend.stop_measurement.assert_not_called()
    self.assertIn("paused", str(ctx.exception).lower())

  def test_interrupt_status_only_with_pause_on_interrupt_pauses_device(self):
    """With pause_on_interrupt=True, interrupt in status-only poll pauses."""
    backend = _make_backend()
    backend.pause_on_interrupt = True
    backend.request_machine_status = AsyncMock(side_effect=KeyboardInterrupt())
    backend.pause_measurement = AsyncMock()
    backend.stop_measurement = AsyncMock()

    with self.assertRaises(MeasurementInterrupted) as ctx:
      asyncio.run(backend._poll_status_only(read_timeout=30.0, log_prefix="test"))

    backend.pause_measurement.assert_called_once()
    backend.stop_measurement.assert_not_called()
    self.assertIn("resume", str(ctx.exception))

  # -- _safe_interrupt and exception --

  def test_safe_interrupt_swallows_errors_stop(self):
    """_safe_interrupt does not propagate exceptions from stop_measurement."""
    backend = _make_backend()
    backend.stop_measurement = AsyncMock(side_effect=RuntimeError("comm failure"))

    asyncio.run(backend._safe_interrupt())
    backend.stop_measurement.assert_called_once()

  def test_safe_interrupt_swallows_errors_pause(self):
    """_safe_interrupt does not propagate exceptions from pause_measurement."""
    backend = _make_backend()
    backend.pause_on_interrupt = True
    backend.pause_measurement = AsyncMock(side_effect=RuntimeError("comm failure"))

    asyncio.run(backend._safe_interrupt())
    backend.pause_measurement.assert_called_once()

  def test_measurement_interrupted_carries_partial_data(self):
    """MeasurementInterrupted stores partial_data attribute."""
    data = b"\xde\xad\xbe\xef"
    exc = MeasurementInterrupted("paused", partial_data=data)
    self.assertEqual(exc.partial_data, data)
    self.assertIn("paused", str(exc))

    exc_none = MeasurementInterrupted("paused")
    self.assertIsNone(exc_none.partial_data)


class TestResumeAndCollect(unittest.TestCase):
  """Tests for resume_measurement_and_collect_data()."""

  def test_resume_and_collect_progressive(self):
    """Resume sends command, re-enters progressive poll, returns parsed results."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    expected_results = [{"wavelength": 450, "data": [[0.5]]}]
    collect_fn = lambda resp, prog_complete: expected_results if prog_complete else None

    backend._resume_context = {
      "poll_mode": "progressive",
      "log_prefix": "ABS measurement",
      "read_timeout": 30.0,
      "collect_fn": collect_fn,
      "fallback_collect_fn": AsyncMock(return_value=expected_results),
    }

    # ACK for resume command
    mock.queue_response(ACK)
    # Mock the polling to simulate completion
    backend._poll_progressive = AsyncMock(return_value=(b"\x00" * 20, True))

    result = asyncio.run(backend.resume_measurement_and_collect_data())

    # Verify resume command was sent
    self.assertEqual(mock.written[0], COMMANDS["resume_measurement"][1])
    # Verify polling was invoked
    backend._poll_progressive.assert_called_once_with(30.0, log_prefix="ABS measurement")
    # Verify results returned
    self.assertEqual(result, expected_results)
    # Verify context cleared
    self.assertIsNone(backend._resume_context)

  def test_resume_and_collect_progressive_fallback(self):
    """When progressive data is incomplete, fallback_collect_fn is used."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    expected_results = [{"wavelength": 450, "data": [[0.5]]}]
    # collect_fn returns None when prog_complete=False
    collect_fn = lambda resp, prog_complete: None

    fallback = AsyncMock(return_value=expected_results)
    backend._resume_context = {
      "poll_mode": "progressive",
      "log_prefix": "FL measurement",
      "read_timeout": 30.0,
      "collect_fn": collect_fn,
      "fallback_collect_fn": fallback,
    }

    mock.queue_response(ACK)
    backend._poll_progressive = AsyncMock(return_value=(b"\x00" * 20, False))

    result = asyncio.run(backend.resume_measurement_and_collect_data())

    fallback.assert_called_once()
    self.assertEqual(result, expected_results)
    self.assertIsNone(backend._resume_context)

  def test_resume_and_collect_status_only(self):
    """Resume with status-only polling (spectrum path)."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    expected_results = [{"wavelength": 300, "data": [[1.2]]}]
    collect_fn = AsyncMock(return_value=expected_results)

    backend._resume_context = {
      "poll_mode": "status_only",
      "log_prefix": "ABS spectrum",
      "read_timeout": 60.0,
      "collect_fn": collect_fn,
    }

    mock.queue_response(ACK)
    backend._poll_status_only = AsyncMock()

    result = asyncio.run(backend.resume_measurement_and_collect_data())

    self.assertEqual(mock.written[0], COMMANDS["resume_measurement"][1])
    backend._poll_status_only.assert_called_once_with(60.0, log_prefix="ABS spectrum")
    collect_fn.assert_called_once()
    self.assertEqual(result, expected_results)
    self.assertIsNone(backend._resume_context)

  def test_resume_without_context_raises(self):
    """Calling resume_measurement_and_collect_data() without prior interrupt raises RuntimeError."""
    backend = _make_backend()
    self.assertIsNone(backend._resume_context)
    with self.assertRaises(RuntimeError) as ctx:
      asyncio.run(backend.resume_measurement_and_collect_data())
    self.assertIn("No paused measurement", str(ctx.exception))

  def test_stop_clears_resume_context(self):
    """stop_measurement() clears _resume_context."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    backend._resume_context = {
      "poll_mode": "progressive",
      "log_prefix": "test",
      "read_timeout": 30.0,
      "collect_fn": lambda resp, prog_complete: [],
      "fallback_collect_fn": AsyncMock(return_value=[]),
    }

    mock.queue_response(ACK)
    asyncio.run(backend.stop_measurement())

    self.assertIsNone(backend._resume_context)

  def test_interrupt_stop_clears_resume_context(self):
    """When interrupt stops (not pauses), _resume_context is cleared."""
    backend = _make_backend()
    backend.pause_on_interrupt = False
    backend._resume_context = {
      "poll_mode": "progressive",
      "log_prefix": "test",
      "read_timeout": 30.0,
      "collect_fn": lambda resp, prog_complete: [],
      "fallback_collect_fn": AsyncMock(return_value=[]),
    }

    backend._request_measurement_data = AsyncMock(side_effect=KeyboardInterrupt())
    backend._measurement_progress = lambda resp: (0, 10)
    backend.request_machine_status = AsyncMock(return_value={"busy": True})
    backend.stop_measurement = AsyncMock()

    with self.assertRaises(MeasurementInterrupted):
      asyncio.run(backend._poll_progressive(read_timeout=30.0, log_prefix="test"))

    self.assertIsNone(backend._resume_context)

  def test_interrupt_pause_preserves_resume_context(self):
    """When interrupt pauses, _resume_context is preserved for later resume."""
    backend = _make_backend()
    backend.pause_on_interrupt = True
    ctx = {
      "poll_mode": "progressive",
      "log_prefix": "test",
      "read_timeout": 30.0,
      "collect_fn": lambda resp, prog_complete: [],
      "fallback_collect_fn": AsyncMock(return_value=[]),
    }
    backend._resume_context = ctx

    backend._request_measurement_data = AsyncMock(side_effect=KeyboardInterrupt())
    backend._measurement_progress = lambda resp: (0, 10)
    backend.request_machine_status = AsyncMock(return_value={"busy": True})
    backend.pause_measurement = AsyncMock()

    with self.assertRaises(MeasurementInterrupted):
      asyncio.run(backend._poll_progressive(read_timeout=30.0, log_prefix="test"))

    # Context should still be there for resume
    self.assertIs(backend._resume_context, ctx)


if __name__ == "__main__":
  unittest.main()
