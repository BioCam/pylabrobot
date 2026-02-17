import asyncio
import dataclasses
import enum
import logging
import math
import struct
import sys
import time
import warnings
from typing import Dict, List, Literal, Optional, Tuple, Union

from pylabrobot import utils
from pylabrobot.io.ftdi import FTDI
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well

from ..backend import PlateReaderBackend

if sys.version_info >= (3, 8):
  from typing import Literal
else:
  from typing_extensions import Literal

logger = logging.getLogger("pylabrobot")


class StatusFlag(enum.Enum):
  """Named status flags parsed from the CLARIOstar 5-byte status field."""

  STANDBY = "standby"
  VALID = "valid"
  BUSY = "busy"
  RUNNING = "running"
  UNREAD_DATA = "unread_data"
  INITIALIZED = "initialized"
  LID_OPEN = "lid_open"
  OPEN = "drawer_open"
  PLATE_DETECTED = "plate_detected"
  Z_PROBED = "z_probed"
  ACTIVE = "active"
  FILTER_COVER_OPEN = "filter_cover_open"


# (byte_index_in_status, bitmask) — status field is bytes 0-4 of the unframed payload
_STATUS_DEFS: List[Tuple[StatusFlag, int, int]] = [
  (StatusFlag.STANDBY, 0, 1 << 1),
  (StatusFlag.VALID, 1, 1 << 0),
  (StatusFlag.BUSY, 1, 1 << 5),
  (StatusFlag.RUNNING, 1, 1 << 4),
  (StatusFlag.UNREAD_DATA, 2, 1),
  (StatusFlag.INITIALIZED, 3, 1 << 5),
  (StatusFlag.LID_OPEN, 3, 1 << 6),
  (StatusFlag.OPEN, 3, 1),
  (StatusFlag.PLATE_DETECTED, 3, 1 << 1),
  (StatusFlag.Z_PROBED, 3, 1 << 2),
  (StatusFlag.ACTIVE, 3, 1 << 3),
  (StatusFlag.FILTER_COVER_OPEN, 4, 1 << 6),
]


def _parse_status(status_bytes: bytes) -> Dict[str, bool]:
  """Parse 5 status bytes into a dict mapping every flag name to True/False.

  Args:
    status_bytes: The 5-byte status field from the unframed response payload.
  """
  flags: Dict[str, bool] = {}
  for flag, byte_idx, mask in _STATUS_DEFS:
    if byte_idx < len(status_bytes):
      flags[flag.value] = bool(status_bytes[byte_idx] & mask)
    else:
      flags[flag.value] = False
  return flags


class ShakerType(enum.IntEnum):
  """Shaker movement types."""

  ORBITAL = 0
  LINEAR = 1
  DOUBLE_ORBITAL = 2
  MEANDER = 3


def _shaker_bytes(
  shake_type: ShakerType = ShakerType.ORBITAL,
  speed_rpm: int = 0,
  duration_s: int = 0,
) -> bytes:
  """Encode shaker configuration into 4 bytes.

  Args:
    shake_type: The type of shaking motion.
    speed_rpm: Shaking speed in RPM (100-700 in steps of 100). Meander limited to 300 max.
    duration_s: Duration in seconds. 0 = no shaking.
  """
  if duration_s == 0:
    return b"\x00\x00\x00\x00"
  if shake_type == ShakerType.MEANDER and speed_rpm > 300:
    raise ValueError("Meander shake cannot exceed 300 RPM")
  if speed_rpm < 100 or speed_rpm > 700 or speed_rpm % 100 != 0:
    raise ValueError("Speed must be 100-700 RPM in steps of 100")
  speed_idx = speed_rpm // 100 - 1
  return bytes([(1 << 4) | int(shake_type), speed_idx]) + duration_s.to_bytes(2, "big")


class StartCorner(enum.IntEnum):
  """Which corner to begin measurements from."""

  TOP_LEFT = 0b0001
  TOP_RIGHT = 0b0011
  BOTTOM_LEFT = 0b0101
  BOTTOM_RIGHT = 0b0111


def _scan_mode_byte(
  start_corner: StartCorner = StartCorner.TOP_LEFT,
  unidirectional: bool = False,
  vertical: bool = False,
  flying_mode: bool = False,
) -> int:
  """Encode the scan mode into a single byte.

  Bit layout: | uni(7) | corner(6:4) | vert(3) | flying(2) | always_set(1) | 0 |
  """
  d = 0
  if unidirectional:
    d |= 1 << 7
  d |= (int(start_corner) << 4) & 0x70
  if vertical:
    d |= 1 << 3
  if flying_mode:
    d |= 1 << 2
  d |= 1 << 1  # always set
  return d


class FrameError(Exception):
  """Raised when a response frame is malformed."""


class ChecksumError(FrameError):
  """Raised when a response frame checksum is invalid."""


def _frame(payload: bytes, single_byte_checksum: bool = False) -> bytes:
  """Frame a payload according to the BMG serial protocol.

  Args:
    payload: The command payload bytes.
    single_byte_checksum: If True, use 1-byte checksum (size = payload + 6).
      Required for temperature commands (0x06) per OEM software captures. If False
      (default), use 2-byte checksum (size = payload + 7), which works for
      all other commands (init, status, open, close, measurements).
  """
  if single_byte_checksum:
    size = len(payload) + 6
    buf = bytearray([0x02]) + size.to_bytes(2, "big") + b"\x0c" + payload
    checksum = sum(buf) & 0xFF
    buf += bytes([checksum])
  else:
    size = len(payload) + 7
    buf = bytearray([0x02]) + size.to_bytes(2, "big") + b"\x0c" + payload
    checksum = sum(buf) & 0xFFFF
    buf += checksum.to_bytes(2, "big")
  buf += b"\x0d"
  return bytes(buf)


def _unframe(data: bytes) -> bytes:
  """Validate and strip framing from a response, returning the payload.

  Raises FrameError/ChecksumError on malformed responses.
  """
  if len(data) < 7:
    raise FrameError(f"Response too short ({len(data)} bytes)")
  if data[0] != 0x02:
    raise FrameError(f"Expected STX (0x02), got 0x{data[0]:02x}")
  if data[-1] != 0x0D:
    raise FrameError(f"Expected CR (0x0d), got 0x{data[-1]:02x}")

  # Validate checksum: sum of all bytes except the last 3 (checksum + CR)
  expected_cs = sum(data[:-3]) & 0xFFFF
  actual_cs = int.from_bytes(data[-3:-1], "big")
  if expected_cs != actual_cs:
    raise ChecksumError(f"Checksum mismatch: expected 0x{expected_cs:04x}, got 0x{actual_cs:04x}")

  # Return payload (strip STX + size + NP header and checksum + CR trailer)
  return data[4:-3]


# Model type code → (name, monochromator_range, num_filter_slots)
# Only one model confirmed so far; others will be added as hardware data is captured.
_MODEL_LOOKUP: Dict[int, Tuple[str, Tuple[int, int], int]] = {
  0x0024: ("CLARIOstar Plus", (220, 1000), 11),  # UV/Vis 220-1000nm, 11 filter slots
}


@dataclasses.dataclass
class CLARIOstarConfig:
  """Machine configuration parsed from CLARIOstar EEPROM (``0x05 0x07``)
  and firmware info (``0x05 0x09``) responses.

  Byte map (confirmed via hardware capture on CLARIOstar Plus, serial 430-2621):

  **EEPROM response (``0x05 0x07``, 264-byte payload):**

  ======  ======  ===================================================
  Offset  Size    Field
  ======  ======  ===================================================
  0       1       Subcommand echo (``0x07``)
  1       1       Command family echo (``0x05``)
  2-3     2       Machine type code (uint16 BE, ``0x0024`` = CLARIOstar Plus)
  4-5     2       Unknown (always ``0x0000``)
  6-10    5       Unknown
  11      1       has_absorbance (bool)
  12      1       has_fluorescence (bool)
  13      1       has_luminescence (bool)
  14      1       has_alpha_technology (bool)
  15-16   2       Unknown
  17      1       Unknown flag (``0x01`` on test unit)
  18-19   2       Unknown (``0x00EE = 238``)
  20-95   76      Unknown (sparse — contains ``0x32`` at offset 0x34)
  96-107  12      Dense 16-bit values (0x60-0x6B), likely usage counters
  108+    ...     Calibration / config data (not yet mapped)
  ======  ======  ===================================================

  **Firmware info response (``0x05 0x09``, 32-byte payload):**

  ======  ======  ===================================================
  Offset  Size    Field
  ======  ======  ===================================================
  0-5     6       Header (schema + family + type code)
  6-7     2       Firmware version × 1000 (uint16 BE, e.g. ``0x0546`` = 1.35)
  8-19    12      Build date, null-terminated (e.g. ``"Nov 20 2020"``)
  20-27   8       Build time, null-terminated (e.g. ``"11:51:21"``)
  28-31   4       Unknown

  Date and time are merged into ``firmware_build_timestamp``.
  ======  ======  ===================================================
  """

  serial_number: str = ""
  firmware_version: str = ""
  firmware_build_timestamp: str = ""
  model_name: str = ""
  machine_type_code: int = 0
  has_absorbance: bool = False
  has_fluorescence: bool = False
  has_luminescence: bool = False
  has_alpha_technology: bool = False
  has_pump1: bool = False
  has_pump2: bool = False
  has_stacker: bool = False
  monochromator_range: Tuple[int, int] = (0, 0)  # (min_nm, max_nm)
  num_filter_slots: int = 0

  @staticmethod
  def parse_eeprom(raw: bytes) -> "CLARIOstarConfig":
    """Parse a raw framed EEPROM response (``0x05 0x07``) into a CLARIOstarConfig.

    Extracts confirmed fields from the 264-byte payload. Fields whose offsets
    are not yet known (pump/stacker presence) remain at their defaults.
    """
    try:
      payload = _unframe(raw)
    except FrameError:
      payload = raw

    config = CLARIOstarConfig()

    if len(payload) < 15:
      return config

    # Bytes 2-3: machine type code (uint16 BE)
    config.machine_type_code = int.from_bytes(payload[2:4], "big")

    # Look up model-dependent defaults from the type code
    model_info = _MODEL_LOOKUP.get(config.machine_type_code)
    if model_info is not None:
      config.model_name, config.monochromator_range, config.num_filter_slots = model_info
    else:
      config.model_name = f"Unknown BMG reader (type 0x{config.machine_type_code:04x})"

    # Bytes 11-14: reading technology capability flags
    config.has_absorbance = bool(payload[11])
    config.has_fluorescence = bool(payload[12])
    config.has_luminescence = bool(payload[13])
    config.has_alpha_technology = bool(payload[14])

    # Pump/stacker offsets are NOT yet identified — they are False on the only
    # test unit (430-2621) so every non-zero byte in the EEPROM represents
    # something that IS present. A second unit with pumps/stacker is needed
    # to identify those offsets.

    return config

  @staticmethod
  def parse_firmware_info(raw: bytes) -> "CLARIOstarConfig":
    """Parse a raw framed firmware info response (``0x05 0x09``) and return
    a CLARIOstarConfig populated with firmware fields only.

    Typically merged into an existing config via ``_merge_firmware_info()``.
    """
    try:
      payload = _unframe(raw)
    except FrameError:
      payload = raw

    config = CLARIOstarConfig()

    if len(payload) < 28:
      return config

    # Bytes 6-7: firmware version encoded as version × 1000 (uint16 BE)
    # Example: 0x0546 = 1350 → version "1.35"
    version_raw = int.from_bytes(payload[6:8], "big")
    config.firmware_version = f"{version_raw / 1000:.2f}"

    # Bytes 8-19: null-terminated build date, bytes 20-27: null-terminated build time
    build_date = _extract_cstring(payload, 8, 12)
    build_time = _extract_cstring(payload, 20, 8)
    config.firmware_build_timestamp = f"{build_date} {build_time}".strip()

    return config


def _parse_usage_counters(raw: bytes) -> Dict[str, int]:
  """Parse a counter response (``0x05 0x21``, 43-byte payload) into a dict.

  Wells and well movements are stored ÷100 in firmware; returned ×100 here.
  """
  try:
    payload = _unframe(raw)
  except FrameError:
    payload = raw

  if len(payload) < 42:
    return {}

  return {
    "flashes": int.from_bytes(payload[6:10], "big"),
    "testruns": int.from_bytes(payload[10:14], "big"),
    "wells": int.from_bytes(payload[14:18], "big") * 100,
    "well_movements": int.from_bytes(payload[18:22], "big") * 100,
    "active_time_s": int.from_bytes(payload[22:26], "big"),
    "shake_time_s": int.from_bytes(payload[26:30], "big"),
    "pump1_usage": int.from_bytes(payload[30:34], "big"),
    "pump2_usage": int.from_bytes(payload[34:38], "big"),
    "alpha_time": int.from_bytes(payload[38:42], "big"),
  }


def _extract_cstring(data: bytes, start: int, max_len: int) -> str:
  """Extract a null-terminated ASCII string from a byte buffer."""
  end = start
  while end < start + max_len and end < len(data) and data[end] != 0:
    end += 1
  return data[start:end].decode("ascii", errors="replace")


def dump_eeprom(raw: bytes) -> str:
  """Pretty-print an EEPROM response in hex + ASCII for reverse-engineering.

  Works on both framed (raw from the wire) and unframed payloads.

  Returns a multi-line string with:
    - Raw and payload lengths
    - Hex dump (16 bytes per line with offset)
    - ASCII interpretation (non-printable bytes shown as '.')
  """
  try:
    payload = _unframe(raw)
  except FrameError:
    payload = raw

  lines = []
  lines.append(f"Raw length: {len(raw)}, Payload length: {len(payload)}")
  lines.append("")

  # Hex + ASCII dump of the unframed payload
  lines.append("Offset  | Hex                                              | ASCII")
  lines.append("--------+--------------------------------------------------+-----------------")
  for i in range(0, len(payload), 16):
    chunk = payload[i : i + 16]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    lines.append(f"{i:06x}  | {hex_part:<48s} | {ascii_part}")

  return "\n".join(lines)


class CLARIOstarBackend(PlateReaderBackend):
  """A plate reader backend for the CLARIOstar.

  Implements luminescence, absorbance, and fluorescence reads with structured
  protocol framing, status flag parsing, partial well selection, shaker control,
  and configurable scan modes.
  """

  def __init__(self, device_id: Optional[str] = None, timeout: int = 150):
    self.io = FTDI(device_id=device_id, vid=0x0403, pid=0xBB68)
    self.timeout = timeout
    self._eeprom_data: Optional[bytes] = None
    self._firmware_data: Optional[bytes] = None
    self._incubation_target: float = 0.0

  async def setup(self):
    await self.io.setup()
    await self.io.set_baudrate(125000)
    await self.io.set_line_property(8, 0, 0)  # 8N1
    await self.io.set_latency_timer(2)

    await self.initialize()
    await self.request_eeprom_data()
    await self.request_firmware_info()

  async def stop(self):
    await self.io.stop()

  async def get_stat(self):
    stat = await self.io.poll_modem_status()
    return hex(stat)

  async def read_resp(self, timeout=20) -> bytes:
    """Read a response from the plate reader. If the timeout is reached, return the data that has
    been read so far."""

    d = b""
    last_read = b""
    end_byte_found = False
    t = time.time()

    # Commands are terminated with 0x0d, but this value may also occur as a part of the response.
    # Therefore, we read until we read a 0x0d, but if that's the last byte we read in a full packet,
    # we keep reading for at least one more cycle. We only check the timeout if the last read was
    # unsuccessful (i.e. keep reading if we are still getting data).
    while True:
      last_read = await self.io.read(25)  # 25 is max length observed in pcap
      if len(last_read) > 0:
        d += last_read
        end_byte_found = d[-1] == 0x0D
        if (
          len(last_read) < 25 and end_byte_found
        ):  # if we read less than 25 bytes, we're at the end
          break
      else:
        # If we didn't read any data, check if the last read ended in an end byte. If so, done
        if end_byte_found:
          break

        # Check if we've timed out.
        if time.time() - t > timeout:
          logger.warning("timed out reading response")
          break

        # If we read data, we don't wait and immediately try to read more.
        await asyncio.sleep(0.0001)

    logger.debug("read %s", d.hex())

    return d

  async def send(
    self,
    payload: Union[bytearray, bytes],
    read_timeout=20,
    single_byte_checksum: bool = False,
  ) -> bytes:
    """Frame a payload and send it to the plate reader, returning the raw response."""

    cmd = _frame(payload, single_byte_checksum=single_byte_checksum)

    logger.debug("sending %s", cmd.hex())

    w = await self.io.write(cmd)

    logger.debug("wrote %s bytes", w)

    assert w == len(cmd)

    resp = await self.read_resp(timeout=read_timeout)
    return resp

  # --- Status ---

  def _parse_status_response(self, response: bytes) -> Dict[str, bool]:
    """Extract and parse status flags from a framed status response.

    The unframed payload starts with a schema byte, then 5 status bytes at positions 0-4.
    For the status command, the unframed payload is the status data itself.
    """
    try:
      payload = _unframe(response)
    except FrameError:
      logger.warning("Could not unframe status response: %s", response.hex())
      # Fall back to extracting bytes 4-9 from the raw framed response
      if len(response) >= 9:
        return _parse_status(response[4:9])
      return {flag.value: False for flag in StatusFlag}
    # The first byte of the payload is a schema/command byte, then status bytes follow
    if len(payload) >= 5:
      return _parse_status(payload[:5])
    return {flag.value: False for flag in StatusFlag}

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
        logger.debug("status changed: %s flags=%s", status_hex, flags)
        if not flags["busy"]:
          return ret

    elapsed = time.time() - t
    raise TimeoutError(
      f"Plate reader still busy after {elapsed:.1f}s (timeout={timeout}s). "
      f"Increase timeout via CLARIOstarBackend(timeout=...) for long-running operations."
    )

  async def request_machine_status(self) -> Dict[str, bool]:
    """Request the current status flags from the plate reader."""
    response = await self._request_command_status()
    return self._parse_status_response(response)

  def _parse_temperature_from_status(self, response: bytes) -> Tuple[float, float]:
    """Extract two incubator heating plate temperatures from a status response.

    The incubator heats from both below and above the microplate.

    The status response payload contains temperature at bytes 11-14:
      - Bytes 11-12: bottom heating plate (below the microplate), uint16 BE, ÷10 for °C
      - Bytes 13-14: top heating plate (above the microplate), uint16 BE, ÷10 for °C

    Both read 0 when temperature monitoring is inactive.

    Reference: CLARIOstar ActiveX/DDE Manual (0430N0003I), Section 2, Temp1/Temp2.

    Returns:
      (bottom_plate_celsius, top_plate_celsius)
    """
    try:
      payload = _unframe(response)
    except FrameError:
      payload = response[4:] if len(response) > 4 else response
    if len(payload) >= 15:
      t1 = int.from_bytes(payload[11:13], "big") / 10.0
      t2 = int.from_bytes(payload[13:15], "big") / 10.0
      return (t1, t2)
    return (0.0, 0.0)

  async def request_drawer_open(self) -> bool:
    """Request whether the drawer is currently open."""
    return (await self.request_machine_status())["drawer_open"]

  async def request_plate_detected(self) -> bool:
    """Request whether a plate is detected in the drawer."""
    return (await self.request_machine_status())["plate_detected"]

  async def request_busy(self) -> bool:
    """Request whether the machine is currently executing a command."""
    return (await self.request_machine_status())["busy"]

  async def request_initialization_status(self) -> bool:
    """Request whether the instrument has been initialized."""
    return (await self.request_machine_status())["initialized"]

  async def _request_command_status(self) -> bytes:
    return await self.send(b"\x80\x00")

  # --- Temperature ---

  _MAX_TEMPERATURE: float = 45.0

  async def start_temperature_control(self, temperature: float) -> None:
    """Start active temperature control (incubation).

    This immediately activates the heater and begins regulating to the target.
    The CLARIOstar has no active cooling — it can only heat above ambient.

    Args:
      temperature: Target temperature in °C (0–45). Pass 0 to switch off the
        incubator and temperature monitoring.

    Raises:
      ValueError: If temperature is outside the 0–45 °C range.
    """
    if not 0 <= temperature <= self._MAX_TEMPERATURE:
      raise ValueError(
        f"Temperature must be between 0 and {self._MAX_TEMPERATURE} °C, got {temperature}."
      )

    if temperature > 0:
      current = await self.measure_temperature(sensor="bottom")
      if temperature < current:
        warnings.warn(
          f"Target {temperature} °C is below the current bottom plate temperature "
          f"({current} °C). The CLARIOstar has no active cooling and will not reach "
          f"this target unless the ambient temperature drops.",
          stacklevel=2,
        )

    self._incubation_target = temperature
    temp_raw = round(temperature * 10)
    payload = b"\x06" + temp_raw.to_bytes(2, "big") + b"\x00\x00"
    await self.send(payload, single_byte_checksum=True)

  async def stop_temperature_control(self) -> None:
    """Switch off the incubator and temperature monitoring."""
    await self.start_temperature_control(0.0)

  async def measure_temperature(
    self,
    sensor: Literal["mean", "bottom", "top"] = "bottom",
  ) -> float:
    """Activate temperature monitoring and return the current incubator temperature.

    The incubator heats from both below and above the microplate. The top plate
    targets setpoint + 0.5 °C to prevent condensation on the plate seal.

    If incubation is active (target > 0), re-sends the incubation command to
    keep heating while refreshing the sensor readings. Otherwise sends the
    "monitor only" command (no heating).

    Args:
      sensor: Which heating plate sensor to read. "bottom" (below the microplate,
        tracks the setpoint), "top" (above the microplate, ~0.5 °C above setpoint),
        or "mean" (average of both).

    Returns:
      Temperature in °C.
    """
    if self._incubation_target > 0:
      # Re-send the current incubation command so we don't cancel heating
      temp_raw = round(self._incubation_target * 10)
      await self.send(b"\x06" + temp_raw.to_bytes(2, "big") + b"\x00\x00",
                      single_byte_checksum=True)
    else:
      # Activate monitoring without incubation
      await self.send(b"\x06\x00\x01\x00\x00", single_byte_checksum=True)
    await asyncio.sleep(0.5)
    response = await self._request_command_status()
    bottom, top = self._parse_temperature_from_status(response)

    sensor_mapping = {
      "bottom": [bottom],
      "top": [top],
      "mean": [bottom, top],
    }
    vals = sensor_mapping[sensor]
    return round(sum(vals) / len(vals), 2)

  async def initialize(self):
    command_response = await self.send(b"\x01\x00\x00\x10\x02\x00")
    return await self._wait_for_ready_and_return(command_response)

  async def request_eeprom_data(self):
    eeprom_response = await self.send(b"\x05\x07\x00\x00\x00\x00\x00\x00")
    self._eeprom_data = eeprom_response
    return await self._wait_for_ready_and_return(eeprom_response)

  async def request_firmware_info(self):
    """Request firmware version and build date/time (command ``0x05 0x09``)."""
    resp = await self.send(b"\x05\x09\x00\x00\x00\x00\x00\x00")
    self._firmware_data = resp
    return await self._wait_for_ready_and_return(resp)

  async def request_usage_counters(self) -> Dict[str, int]:
    """Request lifetime usage counters (command ``0x05 0x21``).

    Each call queries the instrument for current values (not cached).
    """
    resp = await self.send(b"\x05\x21\x00\x00\x00\x00\x00\x00")
    await self._wait_for_ready_and_return(resp)
    return _parse_usage_counters(resp)

  def get_eeprom_data(self) -> Optional[bytes]:
    """Return the raw EEPROM response captured during setup, or None if not yet read."""
    return self._eeprom_data

  def get_firmware_data(self) -> Optional[bytes]:
    """Return the raw firmware info response captured during setup, or None if not yet read."""
    return self._firmware_data

  def get_machine_config(self) -> Optional[CLARIOstarConfig]:
    """Parse and return the machine configuration from stored EEPROM and firmware data.

    Combines fields from the EEPROM response (``0x05 0x07``) and firmware info
    response (``0x05 0x09``). The serial number is read from the FTDI chip.

    Returns None if EEPROM data has not been read yet (i.e. setup() not called).
    """
    if self._eeprom_data is None:
      return None
    config = CLARIOstarConfig.parse_eeprom(self._eeprom_data)

    # Merge firmware info if available
    if self._firmware_data is not None:
      fw = CLARIOstarConfig.parse_firmware_info(self._firmware_data)
      config.firmware_version = fw.firmware_version
      config.firmware_build_timestamp = fw.firmware_build_timestamp

    # Serial number comes from the FTDI chip, not the EEPROM
    if hasattr(self.io, "serial") and self.io.serial:
      config.serial_number = self.io.serial
    elif hasattr(self.io, "device_id") and self.io.device_id:
      config.serial_number = self.io.device_id

    return config

  def dump_eeprom_str(self) -> Optional[str]:
    """Pretty-print the stored EEPROM data for reverse-engineering.

    Returns None if EEPROM data has not been read yet.
    """
    if self._eeprom_data is None:
      return None
    return dump_eeprom(self._eeprom_data)

  async def open(self):
    open_response = await self.send(b"\x03\x01\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(open_response)

  async def close(self, plate: Optional[Plate] = None):
    close_response = await self.send(b"\x03\x00\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(close_response)

  async def _mp_and_focus_height_value(self):
    mp_and_focus_height_value_response = await self.send(b"\x05\x0f\x00\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(mp_and_focus_height_value_response)

  def _plate_bytes(self, plate: Plate, wells: Optional[List[Well]] = None) -> bytes:
    """Encode the plate geometry and well selection into the binary format the CLARIOstar expects.

    The 0x04 command prefix is included. Returns a 63-byte sequence:
    command(1) + plate dimensions(12) + col/row counts(2) + 384-bit well mask(48).

    Args:
      plate: The plate resource.
      wells: Optional list of wells to read. If None, all wells are read.
    """

    def float_to_bytes(f: float) -> bytes:
      return round(f * 100).to_bytes(2, byteorder="big")

    plate_length = plate.get_absolute_size_x()
    plate_width = plate.get_absolute_size_y()

    well_0 = plate.get_well(0)
    assert well_0.location is not None, "Well 0 must be assigned to a plate"
    plate_x1 = well_0.location.x + well_0.center().x
    plate_y1 = plate_width - (well_0.location.y + well_0.center().y)
    plate_xn = plate_length - plate_x1
    plate_yn = plate_width - plate_y1

    plate_cols = plate.num_items_x
    plate_rows = plate.num_items_y

    if wells is None or set(wells) == set(plate.get_all_items()):
      # All wells: set first num_items bits
      all_bits = ([1] * plate.num_items) + ([0] * (384 - plate.num_items))
      well_mask_int: int = sum(b << i for i, b in enumerate(all_bits[::-1]))
      wells_bytes = well_mask_int.to_bytes(48, "big")
    else:
      # Selective wells: encode specific well indices into the bitmask
      mask = bytearray(48)
      for well in wells:
        idx = self._well_to_index(plate, well)
        mask[idx // 8] |= 1 << (7 - idx % 8)
      wells_bytes = bytes(mask)

    return (
      b"\x04"
      + float_to_bytes(plate_length)
      + float_to_bytes(plate_width)
      + float_to_bytes(plate_x1)
      + float_to_bytes(plate_y1)
      + float_to_bytes(plate_xn)
      + float_to_bytes(plate_yn)
      + plate_cols.to_bytes(1, byteorder="big")
      + plate_rows.to_bytes(1, byteorder="big")
      + wells_bytes
    )

  @staticmethod
  def _well_to_index(plate: Plate, well: Well) -> int:
    """Convert a well to its row-major index in the plate."""
    for idx, w in enumerate(plate.get_all_items()):
      if w is well:
        return idx
    raise ValueError(f"Well {well.name} not found in plate {plate.name}")

  def _plate_bytes_with_scan(
    self,
    plate: Plate,
    wells: Optional[List[Well]] = None,
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = False,
    vertical: bool = False,
    flying_mode: bool = False,
  ) -> bytes:
    """Encode plate geometry + well selection + scan mode byte.

    This corresponds to Go `plateBytes()` which includes the 0x04 prefix, geometry, wells,
    and scan mode byte. Returns 64 bytes total.
    """
    pb = self._plate_bytes(plate, wells)
    scan = _scan_mode_byte(start_corner, unidirectional, vertical, flying_mode)
    return pb + bytes([scan])

  # --- Run commands ---

  async def _run_luminescence(
    self,
    focal_height: float,
    plate: Plate,
    wells: Optional[List[Well]] = None,
    shake_type: ShakerType = ShakerType.ORBITAL,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = False,
    vertical: bool = False,
    wait: bool = True,
  ):
    """Run a plate reader luminescence run."""

    assert 0 <= focal_height <= 25, "focal height must be between 0 and 25 mm"

    focal_height_data = int(focal_height * 100).to_bytes(2, byteorder="big")
    plate_and_wells = self._plate_bytes(plate, wells)
    scan = _scan_mode_byte(start_corner, unidirectional, vertical, flying_mode=False)

    shaker = (
      _shaker_bytes(shake_type, shake_speed_rpm, shake_duration_s)
      if shake_duration_s > 0
      else b"\x00\x00\x00\x00"
    )

    # Payload structure preserved from working capture:
    # plate(63) + scan(1) + optic_etc(3) + shaker(4) + fixed(5) + separator(4) + ...
    payload = (
      plate_and_wells
      + bytes([scan])
      + b"\x01\x00\x00"
      + shaker
      + b"\x00\x20\x04\x00\x1e\x27\x0f\x27\x0f\x01"
      + focal_height_data
      + b"\x00\x00\x01\x00\x00\x0e\x10\x00\x01\x00\x01\x00"
      + b"\x01\x00\x01\x00\x01\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x01"
      + b"\x00\x00\x00\x01\x00\x64\x00\x20\x00\x00"
    )
    run_response = await self.send(payload)
    if wait:
      return await self._wait_for_ready_and_return(run_response)
    return run_response

  async def _run_absorbance(
    self,
    wavelengths: List[int],
    plate: Plate,
    wells: Optional[List[Well]] = None,
    flashes: int = 22,
    settling_time: int = 0,
    shake_type: ShakerType = ShakerType.ORBITAL,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    pause_time: int = 0,
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = True,
    vertical: bool = False,
    wait: bool = True,
  ):
    """Run a plate reader absorbance run.

    Args:
      wavelengths: List of wavelengths in nm (1-8 wavelengths, 200-1000 nm each).
      flashes: Number of flashes per well (0-200).
      settling_time: Settling time in deciseconds (0-10).
    """
    if not 1 <= len(wavelengths) <= 8:
      raise ValueError("Must specify 1-8 wavelengths")
    if settling_time > 10:
      raise ValueError("Settling time must be 0-10 deciseconds")
    for w in wavelengths:
      if not 220 <= w <= 1000:
        raise ValueError(f"Wavelength {w} nm out of range (220-1000)")

    plate_and_wells = self._plate_bytes(plate, wells)
    scan = _scan_mode_byte(start_corner, unidirectional, vertical, flying_mode=False)

    shaker = (
      _shaker_bytes(shake_type, shake_speed_rpm, shake_duration_s)
      if shake_duration_s > 0
      else b"\x00\x00\x00\x00"
    )

    # Payload structure preserved from working capture + Go reference for wavelength encoding:
    # plate(63) + scan(1) + optic_etc(3) + shaker(4) + fixed(5) + separator(4) + ...
    payload = bytearray()
    payload += plate_and_wells
    payload += bytes([scan])
    # Absorbance optic mode + zeros
    payload += b"\x02\x00\x00"
    payload += shaker
    payload += b"\x00\x20\x04\x00\x1e\x27\x0f\x27\x0f"
    # Settling + wavelength count + wavelength data (per Go absDiscreteBytes)
    payload += bytes([0x19, len(wavelengths)])
    for w in wavelengths:
      payload += (w * 10).to_bytes(2, "big")
    # Fixed bytes
    payload += b"\x00\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00\x64\x00"
    # Pause time
    if pause_time != 0:
      payload += b"\x01"
    else:
      payload += b"\x00"
    payload += pause_time.to_bytes(2, "big")
    # Fixed trailer
    payload += b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01"
    payload += flashes.to_bytes(2, "big")
    payload += b"\x00\x01\x00\x00"

    run_response = await self.send(bytes(payload))
    if wait:
      return await self._wait_for_ready_and_return(run_response)
    return run_response

  async def _run_fluorescence(
    self,
    plate: Plate,
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    wells: Optional[List[Well]] = None,
    gain: int = 1000,
    ex_bandwidth: int = 20,
    em_bandwidth: int = 40,
    dichroic: Optional[int] = None,
    flashes: int = 100,
    settling_time: int = 0,
    bottom_optic: bool = False,
    shake_type: ShakerType = ShakerType.ORBITAL,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    pause_time: int = 0,
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = False,
    vertical: bool = False,
    flying_mode: bool = False,
    wait: bool = True,
  ):
    """Run a plate reader fluorescence run.

    Args:
      excitation_wavelength: Excitation center wavelength in nm.
      emission_wavelength: Emission center wavelength in nm.
      focal_height: Focal height in mm (0-25).
      gain: Detector gain.
      ex_bandwidth: Excitation bandwidth in nm.
      em_bandwidth: Emission bandwidth in nm.
      dichroic: Dichroic wavelength * 10. Auto-calculated if not provided.
      flashes: Number of flashes per well (0-200).
      settling_time: Settling time in deciseconds (0-10).
      bottom_optic: Use bottom optic instead of top.
    """
    if flashes > 200:
      raise ValueError("Flashes per well must be <= 200")
    if flying_mode and flashes > 3:
      raise ValueError("Cannot do more than 3 flashes in flying mode")

    if dichroic is None:
      dichroic = (excitation_wavelength + emission_wavelength) * 5

    focal_height_encoded = int(focal_height * 100)

    plate_and_wells = self._plate_bytes(plate, wells)
    scan = _scan_mode_byte(start_corner, unidirectional, vertical, flying_mode)

    shaker = (
      _shaker_bytes(shake_type, shake_speed_rpm, shake_duration_s)
      if shake_duration_s > 0
      else b"\x00\x00\x00\x00"
    )

    payload = bytearray()
    payload += plate_and_wells
    payload += bytes([scan])

    # Optic/mode byte
    d = 0
    if bottom_optic:
      d |= 1 << 6
    payload += bytes([d])

    # Always-zero bytes
    payload += b"\x00\x00\x00"

    payload += shaker

    # Unknown separator
    payload += b"\x27\x0f\x27\x0f"

    # Settling time
    if settling_time == 0:
      payload += bytes([1])
    else:
      payload += bytes([(settling_time * 10) // 2])

    # Focal height
    payload += focal_height_encoded.to_bytes(2, "big")

    # Multichromatic config (single chromat)
    payload += b"\x00\x00\x01\x00\x00\x00\x00\x00\x0c"

    # Gain
    payload += gain.to_bytes(2, "big")

    # Excitation high/low (center * 10 +/- bandwidth)
    ex_high = excitation_wavelength * 10 + ex_bandwidth
    ex_low = excitation_wavelength * 10 - ex_bandwidth
    payload += ex_high.to_bytes(2, "big")
    payload += ex_low.to_bytes(2, "big")

    # Dichroic
    payload += dichroic.to_bytes(2, "big")

    # Emission high/low
    em_high = emission_wavelength * 10 + em_bandwidth
    em_low = emission_wavelength * 10 - em_bandwidth
    payload += em_high.to_bytes(2, "big")
    payload += em_low.to_bytes(2, "big")

    # Unknown fixed bytes (slit config?)
    payload += b"\x00\x04\x00\x03\x00"

    # Pause time
    if pause_time != 0:
      payload += b"\x01"
    else:
      payload += b"\x00"
    payload += pause_time.to_bytes(2, "big")

    # Fixed trailer
    payload += b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01"

    # Flashes
    payload += flashes.to_bytes(2, "big")
    payload += b"\x00\x4b\x00\x00"

    run_response = await self.send(bytes(payload))
    if wait:
      return await self._wait_for_ready_and_return(run_response)
    return run_response

  async def _read_order_values(self):
    return await self.send(b"\x05\x1d\x00\x00\x00\x00\x00\x00")

  async def _status_hw(self):
    status_hw_response = await self.send(b"\x81\x00")
    return await self._wait_for_ready_and_return(status_hw_response)

  async def _get_measurement_values(self):
    return await self.send(b"\x05\x02\x00\x00\x00\x00\x00\x00")

  @staticmethod
  def _parse_absorbance_response(
    resp: bytes, num_wavelengths: int
  ) -> Tuple[List[List[float]], float, Dict]:
    """Parse an absorbance measurement response using fixed offsets per the Go reference.

    Returns (transmission_per_well_per_wavelength, temperature_celsius, raw).

    ``transmission[well_idx][wavelength_idx]`` = percent transmission.

    ``raw`` is a dict with the unprocessed detector counts::

        {
          "samples": [float, ...],        # wells*wavelengths raw counts
          "references": [float, ...],      # per-well reference counts
          "chromatic_cal": [(hi, lo), ...], # per-wavelength calibration bounds
          "reference_cal": (hi, lo),        # reference channel calibration bounds
        }

    **Why the subtraction ``ref[well] - ref_cal_lo``?**  The ``lo`` value is
    subtracted as a baseline offset before normalization — this is a standard
    pattern in spectrophotometry (often the detector dark current or electronic
    zero, but the exact physical meaning on the CLARIOstar has not been confirmed).
    ``ref_cal_hi`` is the upper bound, so dividing by ``(hi - lo)`` maps the
    signal onto a 0–1 scale.  The same logic applies to ``chromat_lo``/
    ``chromat_hi`` on the sample channel.
    """
    try:
      payload = _unframe(resp)
    except FrameError:
      payload = resp

    if len(payload) < 36:
      raise ValueError(f"Absorbance response too short ({len(payload)} bytes)")

    if payload[6] != 0x29:
      raise ValueError(f"Incorrect schema byte for abs data: 0x{payload[6]:02x}, expected 0x29")

    wavelengths_in_resp = int.from_bytes(payload[16:18], "big")
    wells = int.from_bytes(payload[20:22], "big")
    temp_raw = int.from_bytes(payload[23:25], "big")
    temperature = temp_raw / 10.0

    # Raw sample values: wells * wavelengths uint32s starting at byte 36
    offset = 36
    vals = []
    for _ in range(wells * wavelengths_in_resp):
      vals.append(float(struct.unpack(">I", payload[offset : offset + 4])[0]))
      offset += 4

    # Reference values: wells uint32s
    ref = []
    for _ in range(wells):
      ref.append(float(struct.unpack(">I", payload[offset : offset + 4])[0]))
      offset += 4

    # Chromatic reference hi/lo pairs: wavelengths pairs of uint32
    chromats = []
    for _ in range(wavelengths_in_resp):
      hi = float(struct.unpack(">I", payload[offset : offset + 4])[0])
      lo = float(struct.unpack(">I", payload[offset + 4 : offset + 8])[0])
      chromats.append((hi, lo))
      offset += 8

    # Reference channel hi/lo
    ref_chan_hi = float(struct.unpack(">I", payload[offset : offset + 4])[0])
    ref_chan_lo = float(struct.unpack(">I", payload[offset + 4 : offset + 8])[0])

    raw: Dict = {
      "samples": list(vals),
      "references": list(ref),
      "chromatic_cal": list(chromats),
      "reference_cal": (ref_chan_hi, ref_chan_lo),
    }

    # Calculate transmission per well per wavelength (matching Go formula)
    transmission: List[List[float]] = []
    for i in range(wells):
      wref = (
        (ref[i] - ref_chan_lo) / (ref_chan_hi - ref_chan_lo) if ref_chan_hi != ref_chan_lo else 0
      )
      well_trans = []
      for j in range(wavelengths_in_resp):
        c_hi, c_lo = chromats[j]
        value = (vals[i + j * wells] - c_lo) / (c_hi - c_lo) if c_hi != c_lo else 0
        well_trans.append(value / wref * 100 if wref != 0 else 0)
      transmission.append(well_trans)

    return transmission, temperature, raw

  @staticmethod
  def _parse_fluorescence_response(resp: bytes) -> Tuple[List[int], float, int]:
    """Parse a fluorescence measurement response using fixed offsets per the Go reference.

    Returns (values, temperature_celsius, overflow_value).
    """
    try:
      payload = _unframe(resp)
    except FrameError:
      payload = resp

    if len(payload) < 34:
      raise ValueError(f"Fluorescence response too short ({len(payload)} bytes)")

    if payload[6] != 0x21:
      raise ValueError(f"Incorrect schema byte for fl data: 0x{payload[6]:02x}, expected 0x21")

    complete = int.from_bytes(payload[9:11], "big")
    overflow = struct.unpack(">I", payload[11:15])[0]
    temp_raw = int.from_bytes(payload[25:27], "big")
    temperature = temp_raw / 10.0

    values = []
    offset = 34
    for _ in range(complete):
      if offset + 4 > len(payload):
        raise ValueError("Expected fluorescence data, but response truncated")
      values.append(struct.unpack(">I", payload[offset : offset + 4])[0])
      offset += 4

    return values, temperature, overflow

  # --- Grid mapping ---

  @staticmethod
  def _readings_to_grid(
    readings: List[Optional[float]],
    plate: Plate,
    wells: List[Well],
  ) -> List[List[Optional[float]]]:
    """Map a flat list of per-well readings onto a 2D plate grid.

    Readings must be in the same order as ``wells``. Wells not in the
    selection are filled with None.
    """
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())
    if all_wells:
      return utils.reshape_2d(readings, (plate.num_items_y, plate.num_items_x))

    grid: List[Optional[float]] = [None] * plate.num_items
    all_items = plate.get_all_items()
    for reading, well in zip(readings, wells):
      idx = all_items.index(well)
      grid[idx] = reading
    return utils.reshape_2d(grid, (plate.num_items_y, plate.num_items_x))

  # --- Public read methods ---

  async def read_luminescence(
    self, plate: Plate, wells: List[Well], focal_height: float = 13, **backend_kwargs
  ) -> Optional[List[Dict]]:
    """Read luminescence values from the plate reader.

    Supports partial well selection. Unread wells are filled with None.

    Args:
      plate: The plate resource.
      wells: List of wells to read.
      focal_height: Focal height in mm.
      **backend_kwargs: Additional keyword arguments:
        shake_type, shake_speed_rpm, shake_duration_s: shaker config.
        start_corner, unidirectional, vertical: scan config.
        wait: bool - if False, start measurement and return None immediately.
          Use ``collect_luminescence_measurement`` to retrieve results later.
    """
    wait = backend_kwargs.pop("wait", True)
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())

    await self._mp_and_focus_height_value()

    await self._run_luminescence(
      focal_height=focal_height,
      plate=plate,
      wells=None if all_wells else wells,
      wait=wait,
      **backend_kwargs,
    )

    if not wait:
      return None

    return await self.collect_luminescence_measurement(plate=plate, wells=wells)

  async def collect_luminescence_measurement(
    self,
    plate: Plate,
    wells: List[Well],
  ) -> List[Dict]:
    """Retrieve and parse luminescence data after a measurement has completed.

    Call this after ``read_luminescence(..., wait=False)`` once ``unread_data`` is True in ``request_machine_status()``.
    """
    await self._read_order_values()
    await self._status_hw()
    vals = await self._get_measurement_values()

    num_read = len(wells)
    fl_values, temperature, overflow = self._parse_fluorescence_response(vals)
    readings = [float(v) for v in fl_values[:num_read]]

    return [
      {
        "data": self._readings_to_grid(readings, plate, wells),
        "temperature": temperature,
        "time": time.time(),
      }
    ]

  async def read_absorbance(
    self,
    plate: Plate,
    wells: List[Well],
    wavelength: int,
    report: Literal["OD", "transmittance", "raw"] = "OD",
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    """Read absorbance values from the device.

    Args:
      wavelength: wavelength to read absorbance at, in nanometers.
      report: whether to report absorbance as optical depth (OD) or transmittance.
      **backend_kwargs: Additional keyword arguments:
        wavelengths: List[int] - multiple wavelengths (overrides `wavelength`).
        flashes: int - number of flashes per well.
        settling_time: int - settling time in deciseconds.
        shake_type, shake_speed_rpm, shake_duration_s: shaker config.
        start_corner, unidirectional, vertical: scan config.
        wait: bool - if False, start measurement and return None immediately.
          Use ``collect_absorbance_measurement`` to retrieve results later.
    """
    wait = backend_kwargs.pop("wait", True)
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())

    # Support multi-wavelength via backend_kwargs
    wavelengths = backend_kwargs.pop("wavelengths", [wavelength])
    if isinstance(wavelengths, int):
      wavelengths = [wavelengths]

    await self._mp_and_focus_height_value()

    await self._run_absorbance(
      wavelengths=wavelengths,
      plate=plate,
      wells=None if all_wells else wells,
      wait=wait,
      **backend_kwargs,
    )

    if not wait:
      return None

    return await self.collect_absorbance_measurement(
      plate=plate, wells=wells, wavelengths=wavelengths, report=report,
    )

  async def collect_absorbance_measurement(
    self,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["OD", "transmittance", "raw"] = "OD",
  ) -> List[Dict]:
    """Retrieve and parse absorbance data after a measurement has completed.

    Call this after ``read_absorbance(..., wait=False)`` once ``unread_data`` is True in ``request_machine_status()``.
    """
    await self._read_order_values()
    await self._status_hw()
    vals = await self._get_measurement_values()

    num_wells = len(wells)
    transmission_data, temperature, raw = self._parse_absorbance_response(vals, len(wavelengths))

    # --- raw mode: return detector counts + calibration directly ---
    if report == "raw":
      results = []
      for wl_idx, wl in enumerate(wavelengths):
        raw_for_wl: List[Optional[float]] = []
        for well_idx in range(num_wells):
          flat_idx = well_idx + wl_idx * num_wells
          raw_for_wl.append(
            raw["samples"][flat_idx] if flat_idx < len(raw["samples"]) else None
          )

        results.append({
          "wavelength": wl,
          "data": self._readings_to_grid(raw_for_wl, plate, wells),
          "references": raw["references"],
          "chromatic_cal": raw["chromatic_cal"][wl_idx],
          "reference_cal": raw["reference_cal"],
          "temperature": temperature,
          "time": time.time(),
        })
      return results

    # --- OD / transmittance modes ---
    results = []
    for wl_idx, wl in enumerate(wavelengths):
      trans_for_wl: List[Optional[float]] = []
      for well_idx in range(num_wells):
        if well_idx < len(transmission_data):
          t = (
            transmission_data[well_idx][wl_idx]
            if wl_idx < len(transmission_data[well_idx])
            else None
          )
        else:
          t = None
        trans_for_wl.append(t)

      if report == "OD":
        final_vals: List[Optional[float]] = [
          math.log10(100 / t) if t is not None and t > 0 else None
          for t in trans_for_wl
        ]
      elif report == "transmittance":
        final_vals = trans_for_wl
      else:
        raise ValueError(f"Invalid report type: {report}")

      results.append(
        {
          "wavelength": wl,
          "data": self._readings_to_grid(final_vals, plate, wells),
          "temperature": temperature,
          "time": time.time(),
        }
      )

    return results

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    """Read fluorescence values from the plate reader.

    Args:
      excitation_wavelength: Excitation center wavelength in nm.
      emission_wavelength: Emission center wavelength in nm.
      focal_height: Focal height in mm.
      **backend_kwargs: Additional keyword arguments:
        gain: int - detector gain.
        ex_bandwidth: int - excitation bandwidth in nm.
        em_bandwidth: int - emission bandwidth in nm.
        dichroic: int - dichroic wavelength * 10.
        flashes: int - number of flashes per well.
        settling_time: int - settling time in deciseconds.
        bottom_optic: bool - use bottom optic.
        shake_type, shake_speed_rpm, shake_duration_s: shaker config.
        start_corner, unidirectional, vertical, flying_mode: scan config.
        wait: bool - if False, start measurement and return None immediately.
          Use ``collect_fluorescence_measurement`` to retrieve results later.
    """
    wait = backend_kwargs.pop("wait", True)
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())

    await self._mp_and_focus_height_value()

    await self._run_fluorescence(
      plate=plate,
      excitation_wavelength=excitation_wavelength,
      emission_wavelength=emission_wavelength,
      focal_height=focal_height,
      wells=None if all_wells else wells,
      wait=wait,
      **backend_kwargs,
    )

    if not wait:
      return None

    return await self.collect_fluorescence_measurement(
      plate=plate, wells=wells,
      excitation_wavelength=excitation_wavelength,
      emission_wavelength=emission_wavelength,
    )

  async def collect_fluorescence_measurement(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
  ) -> List[Dict]:
    """Retrieve and parse fluorescence data after a measurement has completed.

    Call this after ``read_fluorescence(..., wait=False)`` once ``unread_data`` is True in ``request_machine_status()``.
    """
    await self._read_order_values()
    await self._status_hw()
    vals = await self._get_measurement_values()

    num_read = len(wells)
    fl_values, temperature, overflow = self._parse_fluorescence_response(vals)

    readings = [float(v) for v in fl_values[:num_read]]

    return [
      {
        "ex_wavelength": excitation_wavelength,
        "em_wavelength": emission_wavelength,
        "data": self._readings_to_grid(readings, plate, wells),
        "temperature": temperature,
        "time": time.time(),
      }
    ]


# Deprecated alias with warning # TODO: remove mid May 2025 (giving people 1 month to update)
# https://github.com/PyLabRobot/pylabrobot/issues/466


class CLARIOStar:
  def __init__(self, *args, **kwargs):
    raise RuntimeError("`CLARIOStar` is deprecated. Please use `CLARIOStarBackend` instead.")


class CLARIOStarBackend:
  def __init__(self, *args, **kwargs):
    raise RuntimeError(
      "`CLARIOStarBackend` (capital 'S') is deprecated. Please use `CLARIOstarBackend` instead."
    )
