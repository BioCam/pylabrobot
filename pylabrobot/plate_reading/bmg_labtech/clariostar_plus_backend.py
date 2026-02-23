"""CLARIOstar Plus plate reader backend - Phase 1 (core lifecycle).

Supports: initialize, open/close drawer, status polling, EEPROM/firmware
identification, machine type auto-detection.
Measurement commands (absorbance, fluorescence, luminescence) are stubbed
for later phases.
"""

import asyncio
import dataclasses
import enum
import logging
import time
from typing import Dict, List, Optional, Tuple

from pylabrobot.io.ftdi import FTDI
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well

from ..backend import PlateReaderBackend

logger = logging.getLogger("pylabrobot")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FrameError(Exception):
  """Raised when a response frame is malformed."""


class ChecksumError(FrameError):
  """Raised when the frame checksum does not match."""


# ---------------------------------------------------------------------------
# Wire-protocol framing
# ---------------------------------------------------------------------------
#
# Frame format (8-byte overhead):
#   STX (1) | size (2 BE) | 0x0C (1) | payload (n) | checksum (3 BE) | CR (1)
#
# Checksum = sum(frame[:-4]) & 0xFFFFFF
# Verified against 6,780 pcap frames with zero failures.

_FRAME_OVERHEAD = 8  # STX + size(2) + header(1) + checksum(3) + CR(1)


def _wrap_payload(payload: bytes) -> bytes:
  """Build a complete frame from a payload."""
  frame_size = len(payload) + _FRAME_OVERHEAD
  frame = bytearray()
  frame.append(0x02)                           # STX
  frame.extend(frame_size.to_bytes(2, "big"))   # size
  frame.append(0x0C)                            # header
  frame.extend(payload)                         # payload
  checksum = sum(frame) & 0xFFFFFF
  frame.extend(checksum.to_bytes(3, "big"))     # checksum
  frame.append(0x0D)                            # CR
  return bytes(frame)


def _validate_frame(data: bytes) -> None:
  """Validate frame structure and checksum integrity.

  Checks STX/CR delimiters, header byte, size field consistency,
  and 24-bit checksum. Raises on first failure; does not extract
  or return any data.

  Raises:
    FrameError: If STX, CR, header, or size field are wrong.
    ChecksumError: If the checksum does not match.
  """
  if len(data) < _FRAME_OVERHEAD:
    raise FrameError(f"Response too short ({len(data)} bytes)")
  if data[0] != 0x02:
    raise FrameError(f"Expected STX (0x02), got 0x{data[0]:02x}")
  if data[-1] != 0x0D:
    raise FrameError(f"Expected CR (0x0d), got 0x{data[-1]:02x}")
  if data[3] != 0x0C:
    raise FrameError(f"Expected header (0x0c) at byte 3, got 0x{data[3]:02x}")

  received_size = int.from_bytes(data[1:3], "big")
  if received_size != len(data):
    raise FrameError(f"Size field says {received_size}, got {len(data)} bytes")

  received_cs = int.from_bytes(data[-4:-1], "big")
  computed_cs = sum(data[:-4]) & 0xFFFFFF
  if computed_cs != received_cs:
    raise ChecksumError(
      f"Checksum mismatch: computed 0x{computed_cs:06x}, received 0x{received_cs:06x}"
    )


def _extract_payload(data: bytes) -> bytes:
  """Extract the payload from a validated frame.

  Returns the bytes between the 4-byte header (STX + size + header byte)
  and the 4-byte trailer (checksum + CR). Caller must validate first
  via ``_validate_frame``.
  """
  return data[4:-4]


# Backward-compat alias
_frame = _wrap_payload


# ---------------------------------------------------------------------------
# Response-parsing flow
# ---------------------------------------------------------------------------
#
# Commands with wait=True follow a two-phase path:
#
#   Phase A (once): send_command → _wrap_payload → _write_frame → _read_frame
#                   → _validate_frame → _extract_payload
#
#   Phase B (loop): _wait_until_machine_ready → request_machine_status
#                   → flags["busy"] check → return or retry
#
# _read_frame terminates on: short FTDI read (<25 bytes) ending in 0x0D,
# guarded by the size field to avoid false termination on mid-payload 0x0D.
#
# Pre-cached _STATUS_FRAME avoids per-poll frame construction.
# .hex() in I/O methods guarded by isEnabledFor() to skip eager string allocation.
#
# ~37 ms/poll. Open ≈ 4.3 s, close ≈ 8 s, dominated by physical motor speed.
#

# ---------------------------------------------------------------------------
# Device configuration
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class CLARIOstarPlusConfig:
  """Machine configuration parsed from CLARIOstar EEPROM (``0x05 0x07``)
  and firmware info (``0x05 0x09``) responses.

  Byte map (confirmed via hardware capture on CLARIOstar Plus, serial 430-2621):

  **EEPROM response (``0x05 0x07``, 264-byte payload):**

  ======  ======  ===================================================
  Offset  Size    Field
  ======  ======  ===================================================
  0       1       Subcommand echo (``0x07``)
  1       1       Command family echo (``0x05``)
  2-3     2       Machine type code (uint16 BE, ``0x0024``/``0x0026``)
  4-5     2       Unknown (always ``0x0000``)
  6-10    5       Unknown
  11      1       has_absorbance (bool)
  12      1       has_fluorescence (bool)
  13      1       has_luminescence (bool)
  14      1       has_alpha_technology (bool)
  ======  ======  ===================================================

  **Firmware info response (``0x05 0x09``, 32-byte unframed payload):**

  ======  ======  ===================================================
  Offset  Size    Field
  ======  ======  ===================================================
  0       1       Subcommand echo (``0x0a`` = cmd + 1)
  1       1       Command family echo (``0x05``)
  2-3     2       Machine type code (uint16 BE, same as EEPROM)
  4-5     2       Unknown (always ``0x0000``)
  6-7     2       Firmware version × 1000 (uint16 BE, e.g. ``0x0546`` = 1.35)
  8-19    12      Build date, null-terminated ASCII (e.g. ``"Nov 20 2020"``)
  20-27   8       Build time, null-terminated ASCII (e.g. ``"11:51:21"``)
  28-31   4       Unknown
  ======  ======  ===================================================

  Date and time are merged into ``firmware_build_timestamp``.
  """

  # Model type code -> (name, monochromator_range, num_filter_slots)
  _MODEL_LOOKUP: Dict[int, Tuple[str, Tuple[int, int], int]] = dataclasses.field(
    default_factory=dict, init=False, repr=False, compare=False,
  )

  serial_number: str = ""
  firmware_version: str = ""
  firmware_build_timestamp: str = ""
  model_name: str = ""
  machine_type_code: int = 0
  has_absorbance: bool = False
  has_fluorescence: bool = False
  has_luminescence: bool = False
  has_alpha_technology: bool = False
  monochromator_range: Tuple[int, int] = (0, 0)
  num_filter_slots: int = 0

  @staticmethod
  def _extract_cstring(data: bytes, start: int, max_len: int) -> str:
    """Extract a null-terminated ASCII string from a byte buffer."""
    end = start
    while end < start + max_len and end < len(data) and data[end] != 0:
      end += 1
    return data[start:end].decode("ascii", errors="replace")

  @staticmethod
  def parse_eeprom(raw: bytes) -> "CLARIOstarPlusConfig":
    """Parse a raw EEPROM response payload into a CLARIOstarPlusConfig."""
    try:
      _validate_frame(raw)
      payload = _extract_payload(raw)
    except FrameError:
      payload = raw

    # Known machine type codes.
    #
    # CLARIOstar Plus (post-2019) replaced the original CLARIOstar. Both share
    # the dual LVF Monochromator + filter + UV/Vis spectrometer architecture.
    # The Plus adds rapid full-plate autofocus, newer PMT options (far-red),
    # and Voyager control software. EDR (Enhanced Dynamic Range) was introduced
    # after 2024 and is NOT present on all CLARIOstar Plus units.
    #
    # 0x0024: verified on CLARIOstar Plus hardware (serial 430-2621, 220-1000 nm).
    # 0x0026: from vibed code, unverified on real hardware.
    model_lookup: Dict[int, Tuple[str, Tuple[int, int], int]] = {
      0x0024: ("CLARIOstar Plus", (220, 1000), 11),
      0x0026: ("CLARIOstar Plus", (220, 1000), 11),
    }

    config = CLARIOstarPlusConfig()

    if len(payload) < 15:
      return config

    config.machine_type_code = int.from_bytes(payload[2:4], "big")

    model_info = model_lookup.get(config.machine_type_code)
    if model_info is not None:
      config.model_name, config.monochromator_range, config.num_filter_slots = model_info
    else:
      config.model_name = f"Unknown BMG reader (type 0x{config.machine_type_code:04x})"

    config.has_absorbance = bool(payload[11])
    config.has_fluorescence = bool(payload[12])
    config.has_luminescence = bool(payload[13])
    config.has_alpha_technology = bool(payload[14])

    return config

  @staticmethod
  def parse_firmware_info(raw: bytes) -> "CLARIOstarPlusConfig":
    """Parse a raw firmware info response payload. Typically merged into an existing config."""
    try:
      _validate_frame(raw)
      payload = _extract_payload(raw)
    except FrameError:
      payload = raw

    config = CLARIOstarPlusConfig()

    if len(payload) < 28:
      return config

    version_raw = int.from_bytes(payload[6:8], "big")
    config.firmware_version = f"{version_raw / 1000:.2f}"

    build_date = CLARIOstarPlusConfig._extract_cstring(payload, 8, 12)
    build_time = CLARIOstarPlusConfig._extract_cstring(payload, 20, 8)
    config.firmware_build_timestamp = f"{build_date} {build_time}".strip()

    return config


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class CLARIOstarPlusBackend(PlateReaderBackend):
  """BMG CLARIOstar Plus plate reader backend.

  Phase 1: initialize, open/close drawer, status polling, device identification.
  Measurement commands will be added in later phases after hardware validation.
  """

  # -- Command enums (CLARIOstar-specific) ----------------------------------

  class CommandFamily(enum.IntEnum):
    """Command group byte (payload byte 0)."""
    INITIALIZE  = 0x01
    TRAY        = 0x03
    RUN         = 0x04
    REQUEST     = 0x05
    TEMPERATURE = 0x06
    POLL        = 0x08
    STATUS      = 0x80
    HW_STATUS   = 0x81

  class Command:
    """Command byte constants (payload byte 1).

    Grouped by CommandFamily. Values are plain ints rather than IntEnum because
    multiple groups reuse the same byte value (e.g. INIT, TRAY_CLOSE, and POLL
    are all 0x00) and IntEnum would silently alias them.
    """
    # INITIALIZE
    INIT               = 0x00
    # TRAY
    TRAY_CLOSE         = 0x00
    TRAY_OPEN          = 0x01
    # RUN
    MEASUREMENT        = 0x31
    # REQUEST
    DATA               = 0x02
    EEPROM             = 0x07
    FIRMWARE_INFO      = 0x09
    FOCUS_HEIGHT       = 0x0F
    READ_ORDER         = 0x1D
    USAGE_COUNTERS     = 0x21
    # POLL
    POLL               = 0x00

  # Validation tables built after enum definitions are available.
  # Populated in _build_command_tables() below.
  _VALID_COMMANDS: Dict  # CommandFamily -> set[Command]
  _NO_COMMAND_FAMILIES: set  # CommandFamilys that take no command byte

  # -- Status flags (CLARIOstar-specific bit positions) ---------------------

  # (flag_name, byte_index_in_5-byte_status, bitmask)
  _STATUS_FLAGS = [
    ("standby",        0, 1 << 1),
    ("busy",           1, 1 << 5),
    ("running",        1, 1 << 4),
    ("unread_data",    2, 1),
    ("initialized",    3, 1 << 5),
    ("drawer_open",    3, 1),
    ("plate_detected", 3, 1 << 1),
  ]

  @staticmethod
  def _parse_status(status_bytes: bytes) -> Dict[str, bool]:
    """Parse the 5-byte status field into a dict of flag names to booleans."""
    flags: Dict[str, bool] = {}
    for name, byte_idx, mask in CLARIOstarPlusBackend._STATUS_FLAGS:
      if byte_idx < len(status_bytes):
        flags[name] = bool(status_bytes[byte_idx] & mask)
      else:
        flags[name] = False
    return flags

  # === Constructor ===

  def __init__(
    self,
    device_id: Optional[str] = None,
    timeout: float = 150,
    read_timeout: float = 2,
  ):
    self.io = FTDI(device_id=device_id, vid=0x0403, pid=0xBB68)
    self.timeout = timeout
    self.read_timeout = read_timeout
    self._eeprom_data: Optional[bytes] = None
    self._firmware_version: str = ""
    self._firmware_build_timestamp: str = ""
    self._machine_type_code: int = 0

  # === Life cycle ===

  async def setup(self):
    """Configure FTDI serial link (125 kBaud, 8N1), initialize the reader, and read EEPROM/firmware."""
    await self.io.setup()
    await self.io.set_baudrate(125000)
    await self.io.set_line_property(8, 0, 0)  # 8N1
    await self.io.set_latency_timer(2)

    await self.initialize()
    await self.request_eeprom_data()

    fw = await self.request_firmware_info()
    self._firmware_version = fw["firmware_version"]
    self._firmware_build_timestamp = fw["firmware_build_timestamp"]

    # Auto-detect machine type and log device identity + detection capabilities.
    config = self.request_machine_configuration()
    if config is not None:
      self._machine_type_code = config.machine_type_code
      modes = [m for m, flag in [
        ("absorbance", config.has_absorbance),
        ("fluorescence", config.has_fluorescence),
        ("luminescence", config.has_luminescence),
        ("alpha_technology", config.has_alpha_technology),
      ] if flag]
      logger.info(
        "%s (0x%04x) fw %s (%s) — detection: %s",
        config.model_name, self._machine_type_code,
        config.firmware_version or "?",
        config.firmware_build_timestamp or "unknown build",
        ", ".join(modes) if modes else "none",
      )

  async def stop(self):
    """Close the FTDI connection. Requires a new ``setup()`` call to use the reader again."""
    await self.io.stop()

  # === Low-level I/O ===

  async def _write_frame(self, frame: bytes) -> None:
    """Write a complete frame to the serial port."""
    n = await self.io.write(frame)
    if n != len(frame):
      raise IOError(f"Short write: sent {n} of {len(frame)} bytes")
    if logger.isEnabledFor(logging.DEBUG):
      logger.debug("sent %d bytes: %s", len(frame), frame.hex())

  async def _read_frame(self, timeout: Optional[float] = None) -> bytes:
    """Read a complete frame from the serial port.

    A short FTDI read (< 25 bytes) ending in 0x0D means the chip has delivered
    everything it has and the frame is complete. The size field (bytes 1-2) is
    used as a safeguard against false termination on mid-payload 0x0D bytes.

    The timeout is purely a fallback; it should never be the normal exit path.
    """
    if timeout is None:
      timeout = self.read_timeout

    d = b""
    expected_size = None
    end_byte_found = False
    t = time.time()

    while True:
      last_read = await self.io.read(25)
      if len(last_read) > 0:
        d += last_read
        end_byte_found = d[-1] == 0x0D

        # Parse size field once we have the header.
        if expected_size is None and len(d) >= 3 and d[0] == 0x02:
          expected_size = int.from_bytes(d[1:3], "big")

        # Fast path: short FTDI read ending in CR → frame complete,
        # but only if we have enough bytes to satisfy the size field.
        # 0x0D can appear inside payloads, so a short read ending in CR
        # is not sufficient on its own when we know the frame is longer.
        if len(last_read) < 25 and end_byte_found:
          if expected_size is None or len(d) >= expected_size:
            break

        # Size-based completion: all expected bytes received.
        if expected_size is not None and len(d) >= expected_size:
          break
      else:
        # Empty read after we already saw CR → done.
        if end_byte_found:
          break

        if time.time() - t > timeout:
          logger.warning("timed out reading response")
          break

        await asyncio.sleep(0.0001)

    if d and logger.isEnabledFor(logging.INFO):
      logger.info("read %d bytes: %s", len(d), d.hex())

    return d

  # Keep old name as alias for backward compatibility
  async def read_resp(self, timeout=None) -> bytes:
    """Backward-compat alias for ``_read_frame``."""
    return await self._read_frame(timeout=timeout)

  # Pre-cached STATUS_QUERY frame; avoids rebuilding on every poll.
  _STATUS_FRAME = _wrap_payload(b"\x80")

  async def send_command(
    self,
    command_family: "CLARIOstarPlusBackend.CommandFamily",
    command: Optional[int] = None,
    *,
    payload: bytes = b"",
    read_timeout: Optional[float] = None,
    wait: bool = False,
    poll_interval: float = 0.0,
  ) -> bytes:
    """Build a frame, send it, and return the validated response payload.

    Steps:
      1. Validate command_family / command against _VALID_COMMANDS tables
      2. Assemble payload bytes: ``[group, cmd] + payload``
      3. _wrap_payload  → full frame (STX + size + 0x0C + data + checksum + CR)
      4. _write_frame   → io.write
      5. _read_frame    → io.read (fast-path: short read ending in 0x0D + size check)
      6. _validate_frame → verify STX, CR, 0x0C, size field, 24-bit checksum
      7. _extract_payload → strip framing, return inner bytes
      8. If wait=True   → _wait_until_machine_ready (status loop until not busy)

    Args:
      command_family: Command group byte (payload byte 0).
      command: Command byte (payload byte 1). Required for all groups
        except STATUS and HW_STATUS.
      payload: Additional parameter bytes after command_family and command.
      read_timeout: Seconds to wait for the response frame. Defaults to
        ``self.read_timeout``.
      wait: If True, poll status after the initial response until the device
        is no longer busy. Used by commands that trigger physical actions
        (initialize, open, close, etc.).
      poll_interval: Seconds to sleep between status polls when *wait* is True.
        Default 0.0 (no sleep, paced by I/O roundtrip alone, ~37 ms/poll).
        OEM software uses ~0.25 s between polls (observed in pcap). We default
        to 0 because the total wall time is dominated by physical motor speed
        (~4.3 s open, ~8 s close) regardless of poll frequency, and faster
        polling minimises detection latency when the motor finishes.

    Returns:
      Validated response payload (frame overhead stripped).

    Raises:
      ValueError: If *command* is missing, unexpected, or not valid for the group.
      FrameError: If the response frame structure is invalid.
      ChecksumError: If the response checksum does not match.
      TimeoutError: If no response is received within *read_timeout*, or if
        *wait* is True and the device stays busy beyond ``self.timeout``.
    """
    CG = self.CommandFamily
    if command_family in self._NO_COMMAND_FAMILIES:
      if command is not None:
        raise ValueError(f"{CG(command_family).name} does not accept a command")
      data = bytes([command_family]) + payload
    else:
      if command is None:
        raise ValueError(f"{CG(command_family).name} requires a command")
      valid = self._VALID_COMMANDS.get(command_family, set())
      if command not in valid:
        raise ValueError(
          f"command 0x{command:02x} is not valid for {CG(command_family).name}")
      data = bytes([command_family, command]) + payload

    frame = _wrap_payload(data)
    await self._write_frame(frame)
    resp = await self._read_frame(timeout=read_timeout)
    _validate_frame(resp)
    ret = _extract_payload(resp)

    if wait:
      await self._wait_until_machine_ready(poll_interval=poll_interval)

      # REQUEST commands (0x05): the initial response is a status frame.
      # The actual data frame arrives after the device finishes processing
      # (i.e. after _wait_until_machine_ready returns). Read it now.
      if command_family == self.CommandFamily.REQUEST:
        resp = await self._read_frame(timeout=read_timeout)
        _validate_frame(resp)
        ret = _extract_payload(resp)

    return ret

  # === Status ===

  async def request_machine_status(self) -> Dict[str, bool]:
    """Query device status and return parsed flags.

    Bypasses ``send_command`` because ``send_command(wait=True)`` calls
    ``_wait_until_machine_ready``, which calls this method. Routing through
    ``send_command`` would create infinite recursion.
    """
    await self._write_frame(self._STATUS_FRAME)
    resp = await self._read_frame()
    _validate_frame(resp)
    payload = _extract_payload(resp)
    return self._parse_status(payload[:5])

  async def _wait_until_machine_ready(self, timeout=None, poll_interval: float = 0.05):
    """Poll ``request_machine_status`` until the device is no longer busy.

    Args:
      timeout: Max seconds to wait. Defaults to ``self.timeout``.
      poll_interval: Seconds to sleep between polls. Default 0.05 s.
        OEM software uses ~0.25 s (12 polls over 4.3 s for open).
    """
    if timeout is None:
      timeout = self.timeout
    t = time.time()
    while time.time() - t < timeout:
      try:
        flags = await self.request_machine_status()
      except FrameError as e:
        logger.warning("status poll: bad frame (%s), retrying", e)
        continue

      logger.info("status: %s", flags)

      if not flags["busy"]:
        return

      if poll_interval > 0:
        await asyncio.sleep(poll_interval)

    elapsed = time.time() - t
    raise TimeoutError(
      f"Plate reader still busy after {elapsed:.1f}s (timeout={timeout}s). "
      f"Increase timeout via CLARIOstarPlusBackend(timeout=...) for long-running operations."
    )

  # === Device info ===

  async def request_eeprom_data(self):
    """Fetch the 264-byte EEPROM payload (command ``0x05 0x07``) and cache it for ``request_machine_configuration``."""
    self._eeprom_data = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.EEPROM,
      payload=b"\x00\x00\x00\x00\x00\x00",
      wait=True,
    )
    logger.info(
      "EEPROM: %d bytes, head=%s",
      len(self._eeprom_data), self._eeprom_data[:16].hex() if len(self._eeprom_data) >= 16 else self._eeprom_data.hex(),
    )
    return self._eeprom_data

  async def request_firmware_info(self) -> Dict[str, str]:
    """Request firmware version and build date/time (command ``0x05 0x09``).

    Returns:
      Dict with ``firmware_version`` (e.g. ``"1.35"``) and
      ``firmware_build_timestamp`` (e.g. ``"Nov 20 2020 11:51:21"``).
      Values are empty strings if the response is too short to parse.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.FIRMWARE_INFO,
      payload=b"\x00\x00\x00\x00\x00\x00",
      wait=True,
    )

    version = ""
    timestamp = ""
    if len(payload) >= 28:
      version_raw = int.from_bytes(payload[6:8], "big")
      version = f"{version_raw / 1000:.2f}"
      build_date = CLARIOstarPlusConfig._extract_cstring(payload, 8, 12)
      build_time = CLARIOstarPlusConfig._extract_cstring(payload, 20, 8)
      timestamp = f"{build_date} {build_time}".strip()
    else:
      logger.warning(
        "Firmware info payload too short (%d bytes, need 28): %s",
        len(payload), payload.hex(),
      )

    return {"firmware_version": version, "firmware_build_timestamp": timestamp}

  def request_machine_configuration(self) -> Optional[CLARIOstarPlusConfig]:
    """Parse and return the machine configuration from stored EEPROM and firmware data.

    Returns None if EEPROM data has not been read yet (i.e. setup() not called).
    """
    if self._eeprom_data is None:
      return None
    config = CLARIOstarPlusConfig.parse_eeprom(self._eeprom_data)

    config.firmware_version = self._firmware_version
    config.firmware_build_timestamp = self._firmware_build_timestamp

    if hasattr(self.io, "serial") and self.io.serial:
      config.serial_number = self.io.serial
    elif hasattr(self.io, "device_id") and self.io.device_id:
      config.serial_number = self.io.device_id

    return config

  def request_available_detection_modes(self) -> List[str]:
    """Return the list of detection modes available on this device.

    Derived from the EEPROM capability flags read during ``setup()``.
    Returns an empty list if EEPROM data has not been read yet.
    """
    config = self.request_machine_configuration()
    if config is None:
      return []
    return [mode for mode, flag in [
      ("absorbance", config.has_absorbance),
      ("fluorescence", config.has_fluorescence),
      ("luminescence", config.has_luminescence),
      ("alpha_technology", config.has_alpha_technology),
    ] if flag]

  # === Convenience status queries ===

  async def request_plate_detected(self) -> bool:
    """Return True if a plate is currently detected in the drawer."""
    return (await self.request_machine_status())["plate_detected"]

  async def request_busy(self) -> bool:
    """Return True if the device is currently busy."""
    return (await self.request_machine_status())["busy"]

  # === Usage counters ===

  async def request_usage_counters(self) -> Dict[str, int]:
    """Fetch lifetime usage counters (command ``0x05 0x21``).

    Returns a dict with keys: flashes, testruns, wells, well_movements,
    active_time_s, shake_time_s, pump1_usage, pump2_usage, alpha_time.
    ``wells`` and ``well_movements`` are stored /100 in firmware and
    multiplied back here.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.USAGE_COUNTERS,
      payload=b"\x00\x00\x00\x00\x00\x00",
      wait=True,
    )

    def _u32(off: int) -> int:
      return int.from_bytes(payload[off:off + 4], "big")

    return {
      "flashes": _u32(6),
      "testruns": _u32(10),
      "wells": _u32(14) * 100,
      "well_movements": _u32(18) * 100,
      "active_time_s": _u32(22),
      "shake_time_s": _u32(26),
      "pump1_usage": _u32(30),
      "pump2_usage": _u32(34),
      "alpha_time": _u32(38),
    }

  # === Commands (Phase 1) ===

  async def initialize(self, wait: bool = True, poll_interval: float = 0.0):
    """Send the hardware init sequence and poll until the device is no longer busy."""
    return await self.send_command(
      command_family=self.CommandFamily.INITIALIZE,
      command=self.Command.INIT,
      payload=b"\x00\x10\x02\x00",
      wait=wait,
      poll_interval=poll_interval,
    )

  async def open(self, wait: bool = True, poll_interval: float = 0.1):
    """Extend the plate drawer. Motor takes ~4.3 s (from pcap)."""
    return await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_OPEN,
      payload=b"\x00\x00\x00\x00",
      wait=wait,
      poll_interval=poll_interval,
    )

  async def close(
    self, plate: Optional[Plate] = None, wait: bool = True, poll_interval: float = 0.1,
  ):
    """Retract the plate drawer. Motor takes ~8 s (from pcap)."""
    return await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_CLOSE,
      payload=b"\x00\x00\x00\x00",
      wait=wait,
      poll_interval=poll_interval,
    )

  # === Measurement stubs (Phase 4+) ===

  async def read_absorbance(
    self, plate: Plate, wells: List[Well], wavelength: int
  ) -> List[Dict]:
    raise NotImplementedError("Absorbance not yet implemented for CLARIOstar Plus.")

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
  ) -> List[Dict]:
    raise NotImplementedError("Fluorescence not yet implemented for CLARIOstar Plus.")

  async def read_luminescence(
    self, plate: Plate, wells: List[Well], focal_height: float
  ) -> List[Dict]:
    raise NotImplementedError("Luminescence not yet implemented for CLARIOstar Plus.")


# Build command validation tables now that the nested classes exist.
CG = CLARIOstarPlusBackend.CommandFamily
Cmd = CLARIOstarPlusBackend.Command
CLARIOstarPlusBackend._VALID_COMMANDS = {
  CG.INITIALIZE: {Cmd.INIT},
  CG.TRAY:       {Cmd.TRAY_CLOSE, Cmd.TRAY_OPEN},
  CG.RUN:        {Cmd.MEASUREMENT},
  CG.REQUEST:    {Cmd.DATA, Cmd.EEPROM, Cmd.FIRMWARE_INFO,
                  Cmd.FOCUS_HEIGHT, Cmd.READ_ORDER, Cmd.USAGE_COUNTERS},
  CG.POLL:       {Cmd.POLL},
}
CLARIOstarPlusBackend._NO_COMMAND_FAMILIES = {CG.STATUS, CG.HW_STATUS}
del CG, Cmd
