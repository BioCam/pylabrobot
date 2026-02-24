"""Tests for CLARIOstarPlusBackend.

Verifies that initialize, open, and close produce exactly the byte sequences
observed in pcap captures from real CLARIOstar Plus hardware.
"""

import asyncio
import unittest
from typing import Dict, List

from pylabrobot.io.io import IOBase
from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import (
  CLARIOstarPlusBackend,
  _extract_payload,
  _validate_frame,
  _wrap_payload,
)

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
}

# Generic command acknowledgement -- shared by all command tests.
ACK = _wrap_payload(b"\x00")


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
  backend._heating_active = False
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
  """Verify that _wait_until_machine_ready survives partial/corrupt frames."""

  # Corrupt status -- correct size field (16 bytes) but bad checksum.
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
  """Verify sense_plate_present and request_busy delegate to status."""

  # initialized + plate_detected (byte 3: 0x22)
  STATUS_PLATE = bytes.fromhex("0200180c010500220000000000000000000000c000010e0d")
  # busy + initialized (payload byte 1: 0x25 = 0x05 | 0x20)
  STATUS_BUSY = bytes.fromhex("0200180c012500200000000000000000000000c000012c0d")
  # idle (all zero status bytes)
  STATUS_IDLE = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")

  # initialized + drawer_open (byte 3: 0x21)
  STATUS_DRAWER_OPEN = bytes.fromhex("0200180c010500210000000000000000000000c000010d0d")
  # initialized, drawer closed (byte 3: 0x20)
  STATUS_DRAWER_CLOSED = bytes.fromhex("0200180c010500200000000000000000000000c000010c0d")

  def test_sense_drawer_open_true(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_DRAWER_OPEN)
    self.assertTrue(asyncio.run(backend.sense_drawer_open()))

  def test_sense_drawer_open_false(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_DRAWER_CLOSED)
    self.assertFalse(asyncio.run(backend.sense_drawer_open()))

  def test_sense_plate_present_true(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_PLATE)
    self.assertTrue(asyncio.run(backend.sense_plate_present()))

  def test_is_ready_false_when_busy(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_BUSY)
    self.assertFalse(asyncio.run(backend.is_ready()))

  def test_is_ready_true_when_idle(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(self.STATUS_IDLE)
    self.assertTrue(asyncio.run(backend.is_ready()))


# ---------------------------------------------------------------------------
# Real hardware captures (from CLARIOstar Plus 430-2621)
#
# Stored as complete wire frames (STX | size | 0x0C | payload | checksum | CR)
# so tests exercise _validate_frame + _extract_payload on fixed bytes rather
# than re-wrapping payloads with _wrap_payload (which would mask framing bugs).
# ---------------------------------------------------------------------------

# 272-byte wire frame for EEPROM response (command 0x05 0x07, 264-byte payload).
# Byte map: see request_eeprom_data() docstring in clariostar_plus_backend.py.
_REAL_EEPROM_FRAME = bytes.fromhex(
  "0201100c070500240000000100000a0101010100000100ee0200000f00b003000000000000030400"
  "0001000001020000000000000000000032000000000000000000000000000000000000000074006f"
  "0000000000000065000000dc050000000000000000f4010803a70408076009da08ac0d0000000000"
  "000000000000000000000000000000000000000100000001010000000000000001010000000000000"
  "012029806ae013d0a4605ee01fbff700c00000000a40058ff8e03f20460ff5511fe0b55118f1a1702"
  "98065aff970668042603bc14b804080791009001463228460a0046071e0000000000000000002103d"
  "40628002c01900146001e00001411001209ac0d60090000000000001ff50d"
)

# 40-byte wire frame for firmware info response (command 0x05 0x09, 32-byte payload).
# Payload byte map:
#   0:     subcommand echo (0x0a = 0x09 + 1)
#   1:     command family echo (0x05)
#   2-3:   machine type code (0x0024)
#   4-5:   unknown (0x0000)
#   6-7:   firmware version x 1000 (0x0546 = 1350 → "1.35")
#   8-19:  build date "Nov 20 2020\0"
#   20-27: build time "11:51:21\0"
#   28-31: unknown
_REAL_FIRMWARE_FRAME = bytes.fromhex(
  "0200280c0a050024000005464e6f7620323020323032300031313a35313a3231000001000004ed0d"
)


class TestFirmwareInfoParsing(unittest.TestCase):
  """Verify firmware info parsing with real hardware capture data."""

  def test_parse_real_firmware(self):
    """Parse the real 32-byte firmware payload from 430-2621 via mock backend."""
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
    """Parse the real 264-byte EEPROM payload from 430-2621."""
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
    self.assertEqual(eeprom["emission_monochromator_max_nm"], 944)
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
    self.assertEqual(backend.configuration["emission_monochromator_max_nm"], 944)
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
    """stop_temperature_monitoring sends OFF (0x0000)."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK)
    asyncio.run(backend.stop_temperature_monitoring())

    self.assertEqual(mock.written[0], COMMANDS["temp_off"][1])

  def test_monitor_sends_correct_frame(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # Status poll (sensors inactive) -> monitor command ack.
    mock.queue_response(TestTemperature._make_temp_response(0, 0), ACK)
    asyncio.run(backend.start_temperature_monitoring())

    self.assertEqual(mock.written[0], COMMANDS["status"][1])
    self.assertEqual(mock.written[1], COMMANDS["temp_monitor"][1])

  def test_monitor_skips_when_sensors_already_reporting(self):
    """start_temperature_monitoring skips if sensors are already populated."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(TestTemperature._make_temp_response(300, 305))
    asyncio.run(backend.start_temperature_monitoring())

    # Only one status poll, no monitor command.
    self.assertEqual(len(mock.written), 1)
    self.assertEqual(mock.written[0], COMMANDS["status"][1])

  def test_start_set_30c(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK)
    asyncio.run(backend.start_temperature_control(target_celsius=30.0))

    self.assertEqual(mock.written[0], COMMANDS["temp_set_30c"][1])

  def test_start_set_37c(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK)
    asyncio.run(backend.start_temperature_control(target_celsius=37.0))

    # 37.0°C = 370 = 0x0172
    expected = _wrap_payload(b"\x06\x01\x72")
    self.assertEqual(mock.written[0], expected)

  def test_start_set_25c(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(ACK)
    asyncio.run(backend.start_temperature_control(target_celsius=25.0))

    # 25.0°C = 250 = 0x00FA
    expected = _wrap_payload(b"\x06\x00\xfa")
    self.assertEqual(mock.written[0], expected)

  def test_start_rejects_above_max(self):
    backend = _make_backend()
    with self.assertRaises(ValueError):
      asyncio.run(backend.start_temperature_control(target_celsius=50.0))

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

    # start_temperature_monitoring: status(zeros) -> monitor_ack
    # measure_temperature poll: status(populated).
    mock.queue_response(
      self._make_temp_response(0, 0),  # start_temperature_monitoring poll
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
      self._make_temp_response(0, 0),
      ACK,
      self._make_temp_response(370, 375),
    )
    temp = asyncio.run(backend.measure_temperature(sensor="top"))
    self.assertAlmostEqual(temp, 37.5)

  def test_measure_temperature_mean(self):
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    mock.queue_response(
      self._make_temp_response(0, 0),
      ACK,
      self._make_temp_response(370, 375),
    )
    temp = asyncio.run(backend.measure_temperature(sensor="mean"))
    self.assertAlmostEqual(temp, 37.2)  # round((37.0 + 37.5) / 2, 1)

  def test_measure_temperature_sensors_already_active(self):
    """When sensors are already reporting (e.g. heating active), no monitor cmd is sent."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]

    # start_temperature_monitoring polls status -> sees temps -> returns early.
    # measure_temperature polls status -> gets temps -> returns.
    mock.queue_response(
      self._make_temp_response(300, 305),  # start_temperature_monitoring poll
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

    # start_temperature_monitoring: status(zeros) -> monitor_ack
    # measure_temperature: status(zeros still) -> status(populated).
    mock.queue_response(
      self._make_temp_response(0, 0),  # start_temperature_monitoring poll
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

  def test_request_temperature_control_on_after_set(self):
    """After start_temperature_control, request_temperature_control_on returns True."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK)  # SET command ack
    asyncio.run(backend.start_temperature_control(30.0))
    self.assertTrue(asyncio.run(backend.request_temperature_control_on()))

  def test_request_temperature_control_on_false_at_boot(self):
    """Before any temperature command, request_temperature_control_on returns False."""
    backend = _make_backend()
    self.assertFalse(asyncio.run(backend.request_temperature_control_on()))

  def test_request_temperature_control_on_false_after_stop_control(self):
    """After stop_temperature_control, request_temperature_control_on returns False."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK, ACK)  # SET ack, MONITOR ack
    asyncio.run(backend.start_temperature_control(30.0))
    asyncio.run(backend.stop_temperature_control())
    self.assertFalse(asyncio.run(backend.request_temperature_control_on()))

  def test_request_temperature_control_on_false_after_stop_monitoring(self):
    """After stop_temperature_monitoring, request_temperature_control_on returns False."""
    backend = _make_backend()
    mock: MockFTDI = backend.io  # type: ignore[assignment]
    mock.queue_response(ACK, ACK)  # SET ack, OFF ack
    asyncio.run(backend.start_temperature_control(30.0))
    asyncio.run(backend.stop_temperature_monitoring())
    self.assertFalse(asyncio.run(backend.request_temperature_control_on()))


if __name__ == "__main__":
  unittest.main()
