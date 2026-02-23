"""CLARIOstar Plus plate reader backend — Phase 1 (core lifecycle).

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

  **Firmware info response (``0x05 0x09``, 32-byte payload):**

  ======  ======  ===================================================
  Offset  Size    Field
  ======  ======  ===================================================
  6-7     2       Firmware version x1000 (uint16 BE)
  8-19    12      Build date, null-terminated ASCII
  20-27   8       Build time, null-terminated ASCII
  ======  ======  ===================================================
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

    model_lookup: Dict[int, Tuple[str, Tuple[int, int], int]] = {
      0x0024: ("CLARIOstar", (320, 900), 11),
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

  class CommandGroup(enum.IntEnum):
    """Command group byte (payload byte 0)."""
    INITIALIZE  = 0x01
    TRAY        = 0x03
    RUN         = 0x04
    REQUEST     = 0x05
    TEMPERATURE = 0x06
    POLL        = 0x08
    STATUS      = 0x80
    HW_STATUS   = 0x81

  class Command(enum.IntEnum):
    """Command byte (payload byte 1)."""
    # INITIALIZE
    INIT_DEFAULT          = 0x00
    # TRAY
    TRAY_CLOSE            = 0x00
    TRAY_OPEN             = 0x01
    # RUN
    RUN_MEASUREMENT       = 0x31
    # REQUEST
    REQUEST_MEASUREMENT   = 0x02
    REQUEST_EEPROM        = 0x07
    REQUEST_FIRMWARE_INFO = 0x09
    REQUEST_FOCUS_HEIGHT  = 0x0F
    REQUEST_READ_ORDER    = 0x1D
    REQUEST_USAGE_COUNTERS = 0x21
    # POLL
    POLL_DEFAULT          = 0x00

  # Validation tables built after enum definitions are available.
  # Populated in _build_command_tables() below.
  _VALID_COMMANDS: Dict  # CommandGroup -> set[Command]
  _NO_COMMAND_GROUPS: set  # CommandGroups that take no command byte

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
    read_timeout: float = 20,
  ):
    self.io = FTDI(device_id=device_id, vid=0x0403, pid=0xBB68)
    self.timeout = timeout
    self.read_timeout = read_timeout
    self._eeprom_data: Optional[bytes] = None
    self._firmware_data: Optional[bytes] = None
    self._machine_type_code: int = 0

  # === Life cycle ===

  async def setup(self):
    await self.io.setup()
    await self.io.set_baudrate(125000)
    await self.io.set_line_property(8, 0, 0)  # 8N1
    await self.io.set_latency_timer(2)

    await self.initialize()
    await self.request_eeprom_data()
    await self.request_firmware_info()

    # Auto-detect machine type from EEPROM for payload format selection.
    config = self.get_machine_config()
    if config is not None:
      self._machine_type_code = config.machine_type_code
      logger.info(
        "Detected machine type 0x%04x (%s), extended_separator=%s",
        self._machine_type_code, config.model_name, self._uses_extended_separator,
      )

  async def stop(self):
    await self.io.stop()

  @property
  def _uses_extended_separator(self) -> bool:
    """Whether this machine uses the 0x0026-style extended pre-separator block.

    Machine type 0x0026 has a 36-byte block between the scan-mode byte and
    the ``$27 $0F $27 $0F`` separator (containing optic config, shaker data
    at scattered offsets, and padding).  Type 0x0024 (Go reference) uses a
    compact 8-byte layout (optic + zeros + shaker) before the separator.

    Defaults to True (0x0026 layout) when the machine type is unknown so
    that existing setups that haven't called ``setup()`` keep working.
    """
    return self._machine_type_code != 0x0024

  # === Low-level I/O ===

  async def _write_frame(self, frame: bytes) -> None:
    """Write a complete frame to the serial port."""
    n = await self.io.write(frame)
    if n != len(frame):
      raise IOError(f"Short write: sent {n} of {len(frame)} bytes")
    logger.debug("sent %d bytes: %s", len(frame), frame.hex())

  async def _read_frame(self, timeout: Optional[float] = None) -> bytes:
    """Read a complete frame from the serial port.

    Reads bytes until the full frame indicated by the size field is received,
    or until the timeout expires.
    """
    if timeout is None:
      timeout = self.read_timeout

    d = b""
    expected_size = None
    t = time.time()

    while True:
      last_read = await self.io.read(25)
      if len(last_read) > 0:
        d += last_read

        if expected_size is None and len(d) >= 3 and d[0] == 0x02:
          expected_size = int.from_bytes(d[1:3], "big")
          t = time.time()

        if expected_size is not None and len(d) >= expected_size:
          break
      else:
        if expected_size is not None and len(d) >= expected_size:
          break

        if expected_size is None and len(d) > 0 and d[-1] == 0x0D:
          break

        if time.time() - t > timeout:
          logger.warning("timed out reading response")
          break

        await asyncio.sleep(0.0001)

    if d:
      logger.info("read complete response: %d bytes, %s", len(d), d.hex())

    return d

  # Keep old name as alias for backward compatibility
  async def read_resp(self, timeout=None) -> bytes:
    return await self._read_frame(timeout=timeout)

  async def send_command(
    self,
    command_group: "CLARIOstarPlusBackend.CommandGroup",
    command: "Optional[CLARIOstarPlusBackend.Command]" = None,
    *,
    payload: bytes = b"",
    read_timeout: Optional[float] = None,
  ) -> bytes:
    """Build a frame, send it, and return the validated response payload.

    Args:
      command_group: Command group byte (payload byte 0).
      command: Command byte (payload byte 1). Required for all groups
        except STATUS and HW_STATUS.
      payload: Additional parameter bytes after command_group and command.
      read_timeout: Seconds to wait for the response frame. Defaults to
        ``self.read_timeout``.

    Returns:
      Validated response payload (frame overhead stripped).

    Raises:
      ValueError: If *command* is missing, unexpected, or not valid for the group.
      FrameError: If the response frame structure is invalid.
      ChecksumError: If the response checksum does not match.
      TimeoutError: If no response is received within *read_timeout*.
    """
    CG = self.CommandGroup
    if command_group in self._NO_COMMAND_GROUPS:
      if command is not None:
        raise ValueError(f"{CG(command_group).name} does not accept a command")
      data = bytes([command_group]) + payload
    else:
      if command is None:
        raise ValueError(f"{CG(command_group).name} requires a command")
      valid = self._VALID_COMMANDS.get(command_group, set())
      if command not in valid:
        raise ValueError(
          f"{self.Command(command).name} is not valid for {CG(command_group).name}")
      data = bytes([command_group, command]) + payload

    frame = _wrap_payload(data)
    await self._write_frame(frame)
    resp = await self._read_frame(timeout=read_timeout)
    _validate_frame(resp)
    return _extract_payload(resp)

  # === Status ===

  async def _request_command_status(self) -> bytes:
    return await self.send_command(self.CommandGroup.STATUS)

  def _parse_status_response(self, payload: bytes) -> Dict[str, bool]:
    """Extract and parse status flags from an unframed status response payload."""
    if len(payload) >= 5:
      return self._parse_status(payload[:5])
    return {name: False for name, _, _ in self._STATUS_FLAGS}

  async def request_machine_status(self) -> Dict[str, bool]:
    """Request the current status flags from the plate reader."""
    response = await self._request_command_status()
    return self._parse_status_response(response)

  async def _wait_for_ready_and_return(self, ret, timeout=None):
    """Wait for the plate reader to be ready (BUSY flag cleared) and return the response."""
    if timeout is None:
      timeout = self.timeout
    last_status_hex = None
    t = time.time()
    while time.time() - t < timeout:
      await asyncio.sleep(0.1)

      command_status = await self._request_command_status()

      status_hex = command_status.hex()
      if status_hex != last_status_hex:
        last_status_hex = status_hex
        flags = self._parse_status_response(command_status)
        logger.info("status: %s", {k: v for k, v in flags.items() if v})
        if not flags["busy"]:
          return ret

    elapsed = time.time() - t
    raise TimeoutError(
      f"Plate reader still busy after {elapsed:.1f}s (timeout={timeout}s). "
      f"Increase timeout via CLARIOstarPlusBackend(timeout=...) for long-running operations."
    )

  # === Device info ===

  async def request_eeprom_data(self):
    eeprom_response = await self.send_command(
      self.CommandGroup.REQUEST, self.Command.REQUEST_EEPROM,
      payload=b"\x00\x00\x00\x00\x00\x00")
    self._eeprom_data = eeprom_response
    return await self._wait_for_ready_and_return(eeprom_response)

  async def request_firmware_info(self):
    """Request firmware version and build date/time (command ``0x05 0x09``)."""
    resp = await self.send_command(
      self.CommandGroup.REQUEST, self.Command.REQUEST_FIRMWARE_INFO,
      payload=b"\x00\x00\x00\x00\x00\x00")
    self._firmware_data = resp
    return await self._wait_for_ready_and_return(resp)

  def get_machine_config(self) -> Optional[CLARIOstarPlusConfig]:
    """Parse and return the machine configuration from stored EEPROM and firmware data.

    Returns None if EEPROM data has not been read yet (i.e. setup() not called).
    """
    if self._eeprom_data is None:
      return None
    config = CLARIOstarPlusConfig.parse_eeprom(self._eeprom_data)

    if self._firmware_data is not None:
      fw = CLARIOstarPlusConfig.parse_firmware_info(self._firmware_data)
      config.firmware_version = fw.firmware_version
      config.firmware_build_timestamp = fw.firmware_build_timestamp

    if hasattr(self.io, "serial") and self.io.serial:
      config.serial_number = self.io.serial
    elif hasattr(self.io, "device_id") and self.io.device_id:
      config.serial_number = self.io.device_id

    return config

  # === Commands (Phase 1) ===

  async def initialize(self):
    command_response = await self.send_command(
      self.CommandGroup.INITIALIZE, self.Command.INIT_DEFAULT,
      payload=b"\x00\x10\x02\x00")
    return await self._wait_for_ready_and_return(command_response)

  async def open(self):
    open_response = await self.send_command(
      self.CommandGroup.TRAY, self.Command.TRAY_OPEN,
      payload=b"\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(open_response)

  async def close(self, plate: Optional[Plate] = None):
    close_response = await self.send_command(
      self.CommandGroup.TRAY, self.Command.TRAY_CLOSE,
      payload=b"\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(close_response)

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


# Build command validation tables now that the nested enums exist.
CG = CLARIOstarPlusBackend.CommandGroup
Cmd = CLARIOstarPlusBackend.Command
CLARIOstarPlusBackend._VALID_COMMANDS = {
  CG.INITIALIZE: {Cmd.INIT_DEFAULT},
  CG.TRAY:       {Cmd.TRAY_CLOSE, Cmd.TRAY_OPEN},
  CG.RUN:        {Cmd.RUN_MEASUREMENT},
  CG.REQUEST:    {Cmd.REQUEST_MEASUREMENT, Cmd.REQUEST_EEPROM,
                  Cmd.REQUEST_FIRMWARE_INFO, Cmd.REQUEST_FOCUS_HEIGHT,
                  Cmd.REQUEST_READ_ORDER, Cmd.REQUEST_USAGE_COUNTERS},
  CG.POLL:       {Cmd.POLL_DEFAULT},
}
CLARIOstarPlusBackend._NO_COMMAND_GROUPS = {CG.STATUS, CG.HW_STATUS}
del CG, Cmd
