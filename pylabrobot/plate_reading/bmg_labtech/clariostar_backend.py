import asyncio
import dataclasses
import enum
import logging
import math
import struct
import sys
import time
import warnings
from typing import Awaitable, Callable, Dict, List, Literal, Optional, Tuple, Union

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


# # # Error handling # # #


class FrameError(Exception):
  """Raised when a response frame is malformed."""


class ChecksumError(FrameError):
  """Raised when a response frame checksum is invalid."""


# # # Wire-protocol primitives # # #


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

  # Validate checksum: sum of all bytes except the last 3 (checksum + CR).
  # Some firmware responses (e.g. measurement values) include a trailing status
  # byte before the checksum that is NOT included in the checksum computation.
  # Try the standard formula first, then fall back to excluding data[-4].
  expected_cs = sum(data[:-3]) & 0xFFFF
  actual_cs = int.from_bytes(data[-3:-1], "big")
  if expected_cs != actual_cs:
    expected_cs_alt = sum(data[:-4]) & 0xFFFF
    if expected_cs_alt != actual_cs:
      raise ChecksumError(
        f"Checksum mismatch: expected 0x{expected_cs:04x} (or 0x{expected_cs_alt:04x} "
        f"excluding trailing byte), got 0x{actual_cs:04x}"
      )

  # Return payload (strip STX + size + NP header and checksum + CR trailer)
  return data[4:-3]


# # # Command families # # #
#
# All CLARIOstar commands are framed as [STX, size_hi, size_lo, 0x0C, payload, checksum, CR].
# The first byte of the payload identifies the command family. The 0x05 family uses a
# second byte as the subcommand. Measurement runs are the exception — their payload starts
# with plate data (0x04 prefix from _plate_bytes) and the firmware distinguishes them by
# structure/length rather than a family byte.
#
# Sources: Go reference implementation, OEM software USB pcap captures, ActiveX/DDE manual.


@dataclasses.dataclass(frozen=True)
class _CommandDef:
  """Definition of a single CLARIOstar command or subcommand."""
  name: str
  payload: bytes
  single_byte_checksum: bool = False
  description: str = ""


# Registry of known command families and their subcommands.
# Keyed by (family_byte, subcommand_byte) — subcommand is 0x00 for families
# that don't use subcommands.
COMMAND_REGISTRY: Dict[Tuple[int, int], _CommandDef] = {
  # 0x01 — Initialize
  (0x01, 0x00): _CommandDef(
    name="initialize",
    payload=b"\x01\x00\x00\x10\x02\x00",
    description="Instrument initialization",
  ),

  # 0x03 — Drawer
  (0x03, 0x01): _CommandDef(
    name="drawer_open",
    payload=b"\x03\x01\x00\x00\x00\x00\x00",
    description="Open the plate drawer",
  ),
  (0x03, 0x00): _CommandDef(
    name="drawer_close",
    payload=b"\x03\x00\x00\x00\x00\x00\x00",
    description="Close the plate drawer",
  ),

  # 0x05 — Data / Query (second byte = subcommand)
  (0x05, 0x02): _CommandDef(
    name="get_data",
    payload=b"\x05\x02\x00\x00\x00\x00\x00\x00",
    description="Retrieve measurement data (final). Progressive variant uses FF FF FF FF at bytes 2-5.",
  ),
  (0x05, 0x07): _CommandDef(
    name="eeprom_read",
    payload=b"\x05\x07\x00\x00\x00\x00\x00\x00",
    description="Read EEPROM / machine configuration",
  ),
  (0x05, 0x09): _CommandDef(
    name="firmware_info",
    payload=b"\x05\x09\x00\x00\x00\x00\x00\x00",
    description="Read firmware version and build date",
  ),
  (0x05, 0x0F): _CommandDef(
    name="focus_height",
    payload=b"\x05\x0f\x00\x00\x00\x00\x00\x00",
    description="Read/set microplate and focus height value",
  ),
  (0x05, 0x1D): _CommandDef(
    name="read_order",
    payload=b"\x05\x1d\x00\x00\x00\x00\x00\x00",
    description="Read well measurement order",
  ),
  (0x05, 0x21): _CommandDef(
    name="usage_counters",
    payload=b"\x05\x21\x00\x00\x00\x00\x00\x00",
    description="Read lifetime usage counters (flashes, wells, shake time, etc.)",
  ),

  # 0x06 — Temperature (1-byte checksum, unique among families)
  (0x06, 0x00): _CommandDef(
    name="temperature_off",
    payload=b"\x06\x00\x00\x00\x00",
    single_byte_checksum=True,
    description="Turn off incubator and temperature monitoring",
  ),
  (0x06, 0x01): _CommandDef(
    name="temperature_monitor",
    payload=b"\x06\x00\x01\x00\x00",
    single_byte_checksum=True,
    description="Enable temperature sensor monitoring without heating",
  ),
  # Note: temperature_set is dynamic (target encoded in bytes 1-2), not a fixed payload.

  # 0x80 — Status
  (0x80, 0x00): _CommandDef(
    name="command_status",
    payload=b"\x80\x00",
    description="Query command/machine status flags",
  ),

  # 0x81 — Hardware status
  (0x81, 0x00): _CommandDef(
    name="hardware_status",
    payload=b"\x81\x00",
    description="Query hardware status",
  ),
}


# # # Byte utilities # # #


def _extract_cstring(data: bytes, start: int, max_len: int) -> str:
  """Extract a null-terminated ASCII string from a byte buffer."""
  end = start
  while end < start + max_len and end < len(data) and data[end] != 0:
    end += 1
  return data[start:end].decode("ascii", errors="replace")


# # # Status flags # # #


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


# # # Shaker # # #


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


# # # Scan mode # # #


class StartCorner(enum.IntEnum):
  """Which corner to begin measurements from."""

  TOP_LEFT = 0b0001
  TOP_RIGHT = 0b0011
  BOTTOM_LEFT = 0b0101
  BOTTOM_RIGHT = 0b0111


def _scan_mode_byte(
  start_corner: StartCorner = StartCorner.TOP_LEFT,
  unidirectional: bool = False,
  vertical: bool = True,
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


# # # Well scan mode # # #


# Measurement-type codes for the first byte of the 5-byte orbital scan block.
# Absorbance confirmed via OEM pcap; fluorescence from Go fl.go.
_ORBITAL_MEAS_CODE: Dict[str, int] = {
  "absorbance": 0x02,
  "fluorescence": 0x03,
  # luminescence: not yet confirmed via OEM capture
}


def _well_scan_optic_flags(well_scan: Literal["point", "orbital", "spiral", "matrix"]) -> int:
  """Return the optic-config flag bits for the given well scan mode.

  Point scan returns ``0x00`` (no extra flags).
  Orbital scan returns ``0x30`` (bits 4 and 5 = orbital averaging enable).

  These bits are OR'd into the per-measurement optic config byte, which sits
  right after the scan mode byte in the command payload.  The bit layout is
  consistent across absorbance (Go ``abs.go:79``), fluorescence (Go ``fl.go:96-98``),
  and presumably luminescence.
  """
  if well_scan == "orbital":
    return 0x30
  # point / spiral / matrix: no orbital flags (spiral/matrix TBD)
  return 0x00


def _well_scan_orbital_bytes(
  measurement_code: int,
  well_scan: Literal["point", "orbital", "spiral", "matrix"],
  well_scan_width: Optional[float],
  plate: "Plate",
) -> bytes:
  """Build the orbital scan parameter block to insert after the ``$27 $0F`` separator.

  Returns 5 bytes for orbital mode, empty ``bytes`` for point mode.

  The 5-byte structure (verified via OEM pcap for absorbance, Go ``fl.go``
  for fluorescence)::

    [measurement_code, diameter_mm, well_dia_hi, well_dia_lo, 0x00]

  - *measurement_code*: ``0x02`` for absorbance, ``0x03`` for fluorescence.
  - *diameter_mm*: orbital diameter in integer mm (``well_scan_width``).
  - *well_dia*: physical well diameter in 0.01 mm as uint16 BE
    (matches Go ``Plate.WellDia`` which is "mm × 100").
  - ``0x00``: terminator.

  For point scan the firmware expects *no* extra bytes between the separator
  and the measurement-specific data (settling byte, wavelength list, etc.).
  """
  if well_scan != "orbital" or well_scan_width is None:
    return b""
  sample_well = plate.get_all_items()[0]
  well_dia_mm = min(sample_well.get_size_x(), sample_well.get_size_y())
  well_dia_hundredths = round(well_dia_mm * 100)
  return (
    bytes([measurement_code, round(well_scan_width)])
    + well_dia_hundredths.to_bytes(2, "big")
    + b"\x00"
  )


# # # Model lookup # # #


# Model type code → (name, monochromator_range, num_filter_slots)
# Only one model confirmed so far; others will be added as hardware data is captured.
_MODEL_LOOKUP: Dict[int, Tuple[str, Tuple[int, int], int]] = {
  0x0024: ("CLARIOstar Plus", (220, 1000), 11),  # UV/Vis 220-1000nm, 11 filter slots
  0x0026: ("CLARIOstar Plus", (220, 1000), 11),  # Alternate type code (serial 430-2621)
}


# # # Device configuration # # #


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
  2-3     2       Machine type code (uint16 BE, ``0x0024``/``0x0026`` = CLARIOstar Plus)
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


# # # Diagnostic helpers # # #


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


  # === Constructor ===

  def __init__(self, device_id: Optional[str] = None, timeout: int = 150,
               read_timeout: float = 20, write_timeout: float = 10,
               trace_io: Optional[str] = "clariostar_io_trace.log"):
    import os
    self.io = FTDI(device_id=device_id, vid=0x0403, pid=0xBB68)
    self.timeout = timeout
    self.read_timeout = read_timeout
    self.write_timeout = write_timeout
    self._eeprom_data: Optional[bytes] = None
    self._firmware_data: Optional[bytes] = None
    self._incubation_target: float = 0.0
    self._last_scan_params: Dict = {}
    self._machine_type_code: int = 0
    self._trace_io_path: Optional[str] = os.path.abspath(trace_io) if trace_io else None

  # === Life cycle ===
  
  async def setup(self):
    if self._trace_io_path:
      import datetime
      with open(self._trace_io_path, "a") as f:
        f.write(f"\n{'='*80}\nSession started at {datetime.datetime.now()}\n{'='*80}\n")

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
    """Whether this machine uses 5 extra bytes before the ``$27 $0F`` separator.

    Machine type 0x0026 requires ``$00 $20 $04 $00 $1E`` between the shaker bytes
    and the ``$27 $0F $27 $0F`` separator in absorbance and luminescence payloads.
    Type 0x0024 (Go reference) does not include these bytes.

    Defaults to True (extended) when the machine type is unknown (not yet detected)
    so that existing setups that haven't called ``setup()`` keep working.
    """
    return self._machine_type_code != 0x0024

  # === Low-level I/O ===

  def _trace(self, direction: str, data: bytes):
    """Append a timestamped hex trace line to the trace file (if enabled)."""
    if getattr(self, "_trace_io_path", None) is None:
      return
    import datetime
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with open(self._trace_io_path, "a") as f:
      f.write(f"{ts} {direction} ({len(data):>5d} B): {data.hex(' ')}\n")

  async def read_resp(self, timeout=None) -> bytes:
    """Read a response from the plate reader. If the timeout is reached, return the data that has
    been read so far."""

    if timeout is None:
      timeout = self.read_timeout

    d = b""
    expected_size = None
    t = time.time()

    # All CLARIOstar frames start with [0x02, SIZE_HI, SIZE_LO, 0x0C, ...] where
    # the 2-byte size field gives the total frame length. Once we have ≥3 bytes we
    # can extract the expected size and read until we have exactly that many bytes.
    # This avoids stopping early on embedded 0x0D bytes inside the payload.
    #
    # Fallback: if the size field can't be extracted (e.g., non-standard response)
    # or no more data arrives, stop when we see 0x0D at the end of a stalled read.
    while True:
      last_read = await self.io.read(25)  # 25 is max length observed so far
      if len(last_read) > 0:
        d += last_read

        # Extract expected frame size once we have the header.
        # Reset the timeout: the firmware is responding, so give it a fresh
        # window to deliver the remaining bytes.  Without this, a long initial
        # silence (transient firmware delay) eats the timeout budget and we
        # return a truncated frame even though bytes are still arriving.
        if expected_size is None and len(d) >= 3 and d[0] == 0x02:
          expected_size = int.from_bytes(d[1:3], "big")
          t = time.time()

        if expected_size is not None and len(d) >= expected_size:
          break
      else:
        # No data received — check if we already have a complete frame
        if expected_size is not None and len(d) >= expected_size:
          break

        # Fallback: if data stream stalled and last byte is 0x0D, treat as
        # complete — but ONLY when we don't have a known expected_size that
        # we haven't reached yet.  When expected_size is known, an embedded
        # 0x0D is just a payload byte; the FTDI chip may need a few ms to
        # flush the remaining bytes (latency timer = 2 ms).
        if expected_size is None and len(d) > 0 and d[-1] == 0x0D:
          break

        # Check if we've timed out.
        if time.time() - t > timeout:
          logger.warning("timed out reading response")
          break

        await asyncio.sleep(0.0001)

    if d:
      logger.info("read complete response: %d bytes, %s", len(d), d.hex())
    self._trace("RECV", d)

    return d

  async def send_command(
    self,
    payload: Union[bytearray, bytes],
    read_timeout=None,
    single_byte_checksum: bool = False,
  ) -> bytes:
    """Frame a payload and send it to the plate reader, returning the raw response.

    If the response is truncated (size field indicates a larger frame than received
    and the checksum does not validate), retries once after draining the buffer.
    This handles transient firmware delays where the first response of a session
    arrives partially within the read timeout window.
    """

    cmd = _frame(payload, single_byte_checksum=single_byte_checksum)
    self._trace("SEND", cmd)

    w = await self.io.write(cmd)
    assert w == len(cmd)

    resp = await self.read_resp(timeout=read_timeout)

    # Detect truncated response: size field says N bytes but we got fewer,
    # and the checksum doesn't validate (meaning the frame is incomplete).
    if len(resp) >= 7 and resp[0] == 0x02:
      expected_size = int.from_bytes(resp[1:3], "big")
      if len(resp) < expected_size:
        cs_ok = (
          resp[-1] == 0x0D
          and (sum(resp[:-3]) & 0xFFFF) == int.from_bytes(resp[-3:-1], "big")
        )
        if not cs_ok:
          logger.warning(
            "Truncated response (%d/%d bytes), retrying after drain...",
            len(resp), expected_size,
          )
          await asyncio.sleep(1.0)
          await self._drain_buffer()
          w = await self.io.write(cmd)
          assert w == len(cmd)
          resp = await self.read_resp(timeout=read_timeout)

    return resp

  async def _drain_buffer(self):
    """Drain any stale data from the FTDI receive buffer.

    The firmware sends unsolicited "confirmation" responses during and after
    measurement runs.  These pile up in the FTDI receive buffer and, if not
    cleared, cause subsequent ``read_resp`` calls to return the *wrong*
    response (response desync).  Call this before a sequence of send/read
    pairs that depend on getting the correct response for each command.
    """
    await self.io.usb_purge_rx_buffer()
    logger.debug("Drained FTDI RX buffer")

  async def get_stat(self):
    stat = await self.io.poll_modem_status()
    return hex(stat)

  # === Public high-level API ===

  # # # Querying Machine State # # #

  async def _request_command_status(self) -> bytes:
    return await self.send_command(b"\x80\x00")

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
        logger.info("status: %s", {k: v for k, v in flags.items() if v})
        if not flags["busy"]:
          return ret

    elapsed = time.time() - t
    raise TimeoutError(
      f"Plate reader still busy after {elapsed:.1f}s (timeout={timeout}s). "
      f"Increase timeout via CLARIOstarBackend(timeout=...) for long-running operations."
    )

  async def _wait_for_ready_with_progress(
    self,
    run_response: bytes,
    on_progress: Optional[Callable[[int, int, Optional[bytes]], Awaitable[None]]] = None,
    poll_interval: float = 3.0,
    timeout: Optional[float] = None,
  ) -> bytes:
    """Wait for measurement to complete, optionally reporting progress.

    This is the OEM-style progress-aware replacement for the blind status
    polling in ``_wait_for_ready_and_return``.

    Args:
      run_response: The initial response from the run command.
      on_progress: Async callback ``(complete, total, raw_response)`` called
        each time progressive data is fetched. If None, falls back to
        existing ``_wait_for_ready_and_return`` behavior (status polling
        every 100ms with no progressive data).
      poll_interval: Seconds between progressive data fetches (OEM uses ~3s).
      timeout: Override default timeout in seconds.

    Returns:
      The run_response (for compatibility with existing callers).
    """
    # Validate the run response
    try:
      run_info = self._parse_run_response(run_response)
      logger.info(
        "Run command %s: total_values=%d, status=%s",
        "accepted" if run_info["accepted"] else "REJECTED",
        run_info["total_values"],
        run_info["status_bytes"].hex(),
      )
    except ValueError as e:
      logger.warning("Could not parse run response: %s", e)

    # If no progress callback, fall back to the original blind polling
    if on_progress is None:
      return await self._wait_for_ready_and_return(run_response, timeout=timeout)

    if timeout is None:
      timeout = self.timeout

    t = time.time()
    while time.time() - t < timeout:
      await asyncio.sleep(poll_interval)

      # Fetch progressive data
      try:
        progressive_resp = await self._get_progressive_measurement_values()
        progress = self._parse_progress_from_data_response(progressive_resp)
        logger.info(
          "Progressive poll: %d/%d values (schema=0x%02x)",
          progress["complete"], progress["total"], progress["schema"],
        )
        await on_progress(progress["complete"], progress["total"], progressive_resp)
      except (ValueError, FrameError) as e:
        logger.warning("Progressive poll failed: %s", e)

      # Check if BUSY has cleared
      command_status = await self._request_command_status()
      flags = self._parse_status_response(command_status)
      logger.info("status: %s", {k: v for k, v in flags.items() if v})
      if not flags["busy"]:
        return run_response

    elapsed = time.time() - t
    raise TimeoutError(
      f"Plate reader still busy after {elapsed:.1f}s (timeout={timeout}s). "
      f"Increase timeout via CLARIOstarBackend(timeout=...) for long-running operations."
    )

  async def request_machine_status(self) -> Dict[str, bool]:
    """Request the current status flags from the plate reader."""
    response = await self._request_command_status()
    return self._parse_status_response(response)

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

  # # # Device info # # #

  async def request_eeprom_data(self):
    eeprom_response = await self.send_command(b"\x05\x07\x00\x00\x00\x00\x00\x00")
    self._eeprom_data = eeprom_response
    return await self._wait_for_ready_and_return(eeprom_response)

  async def request_firmware_info(self):
    """Request firmware version and build date/time (command ``0x05 0x09``)."""
    resp = await self.send_command(b"\x05\x09\x00\x00\x00\x00\x00\x00")
    self._firmware_data = resp
    return await self._wait_for_ready_and_return(resp)

  async def request_usage_counters(self) -> Dict[str, int]:
    """Request lifetime usage counters (command ``0x05 0x21``).

    Each call queries the instrument for current values (not cached).
    """
    resp = await self.send_command(b"\x05\x21\x00\x00\x00\x00\x00\x00")
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

  # # # Setup Requirement # # #

  async def initialize(self):
    command_response = await self.send_command(b"\x01\x00\x00\x10\x02\x00")
    return await self._wait_for_ready_and_return(command_response)

  # # # Temperature Features # # #

  _MAX_TEMPERATURE: float = 45.0

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

  async def start_temperature_control(self, temperature: float) -> None:
    """Start active temperature control (incubation).

    This immediately activates the heater and begins regulating to the target.
    The CLARIOstar has no active cooling — it can only heat above ambient.

    Args:
      temperature: Target temperature in °C (0-45). Pass 0 to switch off the
        incubator and temperature monitoring.

    Raises:
      ValueError: If temperature is outside the 0-45 °C range.
    """
    if not 0 <= temperature <= self._MAX_TEMPERATURE:
      raise ValueError(
        f"Temperature must be between 0 and {self._MAX_TEMPERATURE} °C, got {temperature}."
      )

    if temperature > 0:
      current = await self.measure_temperature(sensor="bottom")
      heater_overshoot_tolerance = 0.5
      if temperature < current - heater_overshoot_tolerance:
        warnings.warn(
          f"Target {temperature} °C is below the current bottom plate temperature "
          f"({current} °C). The CLARIOstar has no active cooling and will not reach "
          f"this target unless the ambient temperature drops.",
          stacklevel=2,
        )

    self._incubation_target = temperature
    temp_raw = round(temperature * 10)
    payload = b"\x06" + temp_raw.to_bytes(2, "big") + b"\x00\x00"
    await self.send_command(payload, single_byte_checksum=True)

  async def enable_temperature_monitoring(self) -> None:
    """Enable temperature sensor monitoring without heating.

    Sends the "monitor only" command (``\\x06\\x00\\x01\\x00\\x00``) which keeps
    the temperature sensors active so that subsequent measurement responses
    include an embedded pre-measurement temperature reading.

    This is called automatically by ``stop_temperature_control`` to prevent the
    firmware from dropping embedded temperature data after incubation is turned
    off. It can also be called standalone if temperature monitoring was never
    activated and you want embedded temperatures in measurement responses.
    """
    await self.send_command(b"\x06\x00\x01\x00\x00", single_byte_checksum=True)

  async def stop_temperature_control(self) -> None:
    """Switch off the incubator and re-enable passive temperature monitoring.

    Turns the heater off, then sends the "monitor only" command so that the
    firmware continues to embed pre-measurement temperature readings in
    subsequent measurement responses.
    """
    await self.start_temperature_control(0.0)
    await self.enable_temperature_monitoring()

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
      await self.send_command(b"\x06" + temp_raw.to_bytes(2, "big") + b"\x00\x00",
                      single_byte_checksum=True)
    else:
      await self.enable_temperature_monitoring()
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

  # # #  Drawer Features # # #

  async def open(self):
    open_response = await self.send_command(b"\x03\x01\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(open_response)

  async def close(self, plate: Optional[Plate] = None):
    close_response = await self.send_command(b"\x03\x00\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(close_response)

  # # # Shared measurement infrastructure # # #

  async def _mp_and_focus_height_value(self):
    mp_and_focus_height_value_response = await self.send_command(b"\x05\x0f\x00\x00\x00\x00\x00\x00")
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
      # Selective wells: encode specific well indices into the bitmask.
      # The firmware uses row-major ordering (A1,A2,...,A12,B1,...) but PLR
      # get_all_items() is column-major (A1,B1,...,H1,A2,...). Convert each
      # well's (row, col) to a row-major index for the firmware.
      mask = bytearray(48)
      for well in wells:
        row = well.get_row()
        col = well.get_column()
        idx = row * plate_cols + col  # row-major index for firmware
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
    vertical: bool = True,
    flying_mode: bool = False,
  ) -> bytes:
    """Encode plate geometry + well selection + scan mode byte.

    This corresponds to Go `plateBytes()` which includes the 0x04 prefix, geometry, wells,
    and scan mode byte. Returns 64 bytes total.
    """
    pb = self._plate_bytes(plate, wells)
    scan = _scan_mode_byte(start_corner, unidirectional, vertical, flying_mode)
    return pb + bytes([scan])

  @staticmethod
  def _readings_to_grid(
    readings: List[Optional[float]],
    plate: Plate,
    wells: List[Well],
    scan_order: Optional[List[Tuple[int, int]]] = None,
  ) -> List[List[Optional[float]]]:
    """Map a flat list of per-well readings onto a 2D plate grid.

    Args:
      readings: Flat list of measurement values in the instrument's read order.
      plate: The plate that was measured.
      wells: The wells that were selected for measurement.
      scan_order: List of (row, col) tuples from ``_read_order_values``,
        indicating the order in which readings were taken. When provided,
        each reading is placed at the corresponding (row, col) position.
        When None, falls back to assuming readings match ``wells`` order.
    """
    rows, cols = plate.num_items_y, plate.num_items_x
    grid: List[List[Optional[float]]] = [[None] * cols for _ in range(rows)]

    if scan_order is not None:
      for reading, (r, c) in zip(readings, scan_order):
        grid[r][c] = reading
      return grid

    # Fallback: firmware returns values in row-major order of the selected wells
    # (A1, A2, ..., B1, B3, ...), NOT in the order of the `wells` list (which may
    # be column-major from PLR's get_all_items()). Sort wells by (row, col) to
    # match firmware ordering.
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())
    if all_wells:
      return utils.reshape_2d(readings, (rows, cols))
    sorted_wells = sorted(wells, key=lambda w: (w.get_row(), w.get_column()))
    for reading, well in zip(readings, sorted_wells):
      grid[well.get_row()][well.get_column()] = reading
    return grid

  async def _read_order_values(self, plate: Plate) -> Optional[List[Tuple[int, int]]]:
    """Query the instrument for the read order of the last measurement.

    Sends command ``0x05 0x1d`` and parses the response. The response has a
    19-byte header followed by N × 2-byte ``(col_1based, row_1based)`` pairs
    and a trailing ``0x00``.

    .. note::

       For partial-well reads, the firmware returns the first N positions of
       the *general* scan pattern, not filtered to selected wells. Use
       ``_compute_scan_order`` for actual grid placement.

    Returns a list of (row, col) tuples (0-based), or None if parsing fails.
    """
    resp = await self.send_command(b"\x05\x1d\x00\x00\x00\x00\x00\x00")

    try:
      payload = _unframe(resp)
    except FrameError:
      payload = resp

    rows = plate.num_items_y
    cols = plate.num_items_x

    # Header layout (19 bytes):
    #   byte 0: 0x1d (subcommand echo)
    #   byte 1: 0x05 (command family echo)
    #   bytes 6-7: num_cols, num_rows
    #   bytes 17-18: uint16 BE well count
    if len(payload) < 19:
      logger.warning(
        "Read order response too short (%d bytes). Raw: %s",
        len(payload), payload.hex(),
      )
      return None

    n_entries = int.from_bytes(payload[17:19], "big")
    data = payload[19:]

    if len(data) < n_entries * 2:
      logger.warning(
        "Read order data too short: expected %d entries (%d bytes), got %d bytes. Raw: %s",
        n_entries, n_entries * 2, len(data), payload.hex(),
      )
      return None

    positions: List[Tuple[int, int]] = []
    for i in range(n_entries):
      col_1 = data[i * 2]      # 1-based column
      row_1 = data[i * 2 + 1]  # 1-based row
      r = row_1 - 1
      c = col_1 - 1
      if r < 0 or r >= rows or c < 0 or c >= cols:
        logger.warning(
          "Read order entry %d: col=%d row=%d out of range for %dx%d plate. Raw: %s",
          i, col_1, row_1, rows, cols, payload.hex(),
        )
        return None
      positions.append((r, c))

    logger.debug("Read order: %d positions, first 10: %s", len(positions), positions[:10])
    return positions

  @staticmethod
  def _compute_scan_order(
    plate: Plate,
    wells: List[Well],
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = False,
    vertical: bool = True,
  ) -> List[Tuple[int, int]]:
    """Compute the read order for a measurement from scan parameters.

    The CLARIOstar scans wells according to ``start_corner``, ``vertical``,
    and ``unidirectional`` settings. For partial-well reads the instrument
    still traverses in the same pattern but only visits selected wells.

    Returns (row, col) tuples (0-based) in the order readings are produced.
    """
    rows, cols = plate.num_items_y, plate.num_items_x

    # Determine traversal directions from start corner.
    row_forward = start_corner in (StartCorner.TOP_LEFT, StartCorner.TOP_RIGHT)
    col_forward = start_corner in (StartCorner.TOP_LEFT, StartCorner.BOTTOM_LEFT)

    row_seq = list(range(rows) if row_forward else range(rows - 1, -1, -1))
    col_seq = list(range(cols) if col_forward else range(cols - 1, -1, -1))

    selected = {(w.get_row(), w.get_column()) for w in wells}

    order: List[Tuple[int, int]] = []

    if vertical:
      # Primary axis: columns, secondary axis: rows.
      for i, c in enumerate(col_seq):
        secondary = row_seq if (unidirectional or i % 2 == 0) else row_seq[::-1]
        for r in secondary:
          if (r, c) in selected:
            order.append((r, c))
    else:
      # Primary axis: rows, secondary axis: columns.
      for i, r in enumerate(row_seq):
        secondary = col_seq if (unidirectional or i % 2 == 0) else col_seq[::-1]
        for c in secondary:
          if (r, c) in selected:
            order.append((r, c))

    return order

  async def _status_hw(self):
    status_hw_response = await self.send_command(b"\x81\x00")
    return await self._wait_for_ready_and_return(status_hw_response)

  async def _get_measurement_values(self):
    """Fetch final measurement data after a measurement has completed.

    Uses a 30-second read timeout because the firmware can take 20+ seconds to
    respond to the first final-getData of a session.
    """
    return await self.send_command(b"\x05\x02\x00\x00\x00\x00\x00\x00", read_timeout=30)

  async def _get_progressive_measurement_values(self, read_timeout: float = 1):
    """Fetch partial measurement data during an active measurement.

    Uses the ``$FF $FF $FF $FF`` variant of getData which returns available
    data with zeros for wells not yet measured. The response structure is
    identical to the final getData (1612B frame for a full 96-well plate),
    but unmeasured wells are zero-filled.

    This can be called while the instrument is BUSY (measurement in progress).

    Args:
      read_timeout: Seconds to wait for a response. Short (1s) because the
        firmware doesn't respond to progressive getData during its initial
        setup phase (~6s of optics homing / filter wheel rotation).  The
        polling loop simply retries on the next iteration.
    """
    return await self.send_command(
      b"\x05\x02\xff\xff\xff\xff\x00\x00", read_timeout=read_timeout,
    )

  @staticmethod
  def _parse_run_response(response: bytes) -> dict:
    """Parse the 'Time Values Response' returned immediately after a run command.

    The firmware returns a ~53-byte framed response when a measurement command
    is accepted. The unframed payload contains:

    - Byte 0: ``$03`` — echo of the run command type
    - Bytes 1-3: status bytes (BUSY + accepted flags)
    - Bytes 12-13: total measurement values (uint16 BE). This count is
      consistently 4 higher than the ``total`` field in progressive getData
      responses — the firmware likely includes 4 header/metadata slots that
      the progressive response excludes. Used for logging only; the
      authoritative total comes from ``_parse_progress_from_data_response``.

    Returns dict with:
      - ``accepted``: bool — True if the command was accepted (byte 0 == 0x03)
      - ``total_values``: int — expected total measurement values (firmware count),
        or -1 if the response was truncated (serial timeout delivered a partial
        frame).  Used for logging only.
      - ``status_bytes``: bytes — raw status bytes for debugging

    Raises ValueError if the response is too short to extract even the
    accepted flag (< 4 payload bytes).
    """
    try:
      payload = _unframe(response)
    except FrameError:
      if len(response) >= 7 and response[0] == 0x02 and response[-1] == 0x0D:
        payload = response[4:-3]
      else:
        payload = response

    if len(payload) < 4:
      raise ValueError(
        f"Run response too short ({len(payload)} bytes, need >= 4). "
        f"Raw: {response.hex()}"
      )

    command_echo = payload[0]
    accepted = command_echo == 0x03
    status_bytes = payload[1:4]

    if len(payload) >= 14:
      total_values = int.from_bytes(payload[12:14], "big")
    else:
      total_values = -1
      logger.warning(
        "Truncated run response (%d payload bytes, expected >= 14). "
        "The firmware accepted the command but the serial link dropped bytes. "
        "Raw: %s",
        len(payload), response.hex(),
      )

    return {
      "accepted": accepted,
      "total_values": total_values,
      "status_bytes": status_bytes,
    }

  @staticmethod
  def _parse_progress_from_data_response(response: bytes) -> dict:
    """Parse progress metadata from a progressive getData response.

    The progressive getData response has the same structure as the final
    response. Key fields in the unframed payload:

    - Byte 6: schema (``$A9`` for absorbance, ``$21`` for fluorescence)
    - Bytes 7-8: total values expected (uint16 BE)
    - Bytes 9-10: complete count — number of values measured so far (uint16 BE)

    Returns dict with:
      - ``complete``: int — number of values measured so far
      - ``total``: int — total values expected
      - ``schema``: int — response schema byte

    Raises ValueError if the response is too short to parse.
    """
    try:
      payload = _unframe(response)
    except FrameError:
      if len(response) >= 7 and response[0] == 0x02 and response[-1] == 0x0D:
        payload = response[4:-3]
      else:
        payload = response

    if len(payload) < 11:
      raise ValueError(
        f"Data response too short ({len(payload)} bytes, need >= 11). "
        f"Raw: {response.hex()}"
      )

    schema = payload[6]
    total = int.from_bytes(payload[7:9], "big")
    complete = int.from_bytes(payload[9:11], "big")

    return {
      "complete": complete,
      "total": total,
      "schema": schema,
    }

  # # # Luminescence # # #

  async def _start_luminescence_measurement(
    self,
    focal_height: float,
    plate: Plate,
    wells: Optional[List[Well]] = None,
    shake_type: ShakerType = ShakerType.ORBITAL,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = False,
    vertical: bool = True,
    wait: bool = True,
  ):
    """Run a plate reader luminescence run."""

    assert 0 <= focal_height <= 25, "focal height must be between 0 and 25 mm"

    self._last_scan_params = {
      "start_corner": start_corner,
      "unidirectional": unidirectional,
      "vertical": vertical,
    }

    focal_height_data = int(focal_height * 100).to_bytes(2, byteorder="big")
    plate_and_wells = self._plate_bytes(plate, wells)
    scan = _scan_mode_byte(start_corner, unidirectional, vertical, flying_mode=False)

    shaker = (
      _shaker_bytes(shake_type, shake_speed_rpm, shake_duration_s)
      if shake_duration_s > 0
      else b"\x00\x00\x00\x00"
    )

    # Payload layout: plate(63) + scan(1) + optic(1) + zeros(3) + shaker(4)
    # + [extended(5) if 0x0026] + separator(4) + mode(1) + ...
    payload = bytearray()
    payload += plate_and_wells
    payload += bytes([scan])
    payload += b"\x01"
    payload += b"\x00\x00\x00"
    payload += shaker
    if self._uses_extended_separator:
      payload += b"\x00\x20\x04\x00\x1e"
    payload += b"\x27\x0f\x27\x0f\x01"
    payload += focal_height_data
    payload += b"\x00\x00\x01\x00\x00\x0e\x10\x00\x01\x00\x01\x00"
    payload += b"\x01\x00\x01\x00\x01\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x01"
    payload += b"\x00\x00\x00\x01\x00\x64\x00\x20\x00\x00"

    run_response = await self.send_command(bytes(payload))
    if wait:
      return await self._wait_for_ready_and_return(run_response)
    return run_response

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

    # OEM firmware never sends _mp_and_focus_height_value ($05 $0F) before
    # measurements — verified via USB pcap analysis.  Removed to match OEM flow.

    await self._start_luminescence_measurement(
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
    # Match the Go/OEM flow: send getData directly.
    # See collect_absorbance_measurement for why extra commands are skipped.
    vals = await self._get_measurement_values()
    logger.info("Luminescence response: %d bytes", len(vals))

    scan_order = self._compute_scan_order(
      plate, wells,
      start_corner=self._last_scan_params.get("start_corner", StartCorner.TOP_LEFT),
      unidirectional=self._last_scan_params.get("unidirectional", False),
      vertical=self._last_scan_params.get("vertical", True),
    )

    num_read = len(wells)
    fl_values, temperature, overflow = self._parse_fluorescence_response(vals)

    # POST-measurement fallback: see comment in collect_absorbance_measurement.
    if temperature is None:
      warnings.warn(
        "The measurement response did not contain an embedded temperature "
        "(this happens after incubation is turned off). Falling back to a "
        "post-measurement sensor query — the reported temperature was read "
        "after the measurement finished, not at the start.",
        stacklevel=2,
      )
      temperature = await self.measure_temperature()

    readings = [float(v) for v in fl_values[:num_read]]

    return [
      {
        "data": self._readings_to_grid(readings, plate, wells, scan_order=scan_order),
        "temperature": temperature,
        "time": time.time(),
      }
    ]

  # # # Absorbance # # #

  async def _start_absorbance_measurement(
    self,
    wavelengths: List[int],
    plate: Plate,
    wells: Optional[List[Well]] = None,
    pause_time_per_well: int = 0,
    # shake during measurement
    shake_type: ShakerType = ShakerType.ORBITAL,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    settling_time_before_measurement: int = 0,
    # scan pattern
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = True,
    vertical: bool = True,
    flying_mode: bool = False,
    well_scan: Literal["point", "orbital", "spiral", "matrix"] = "point",
    well_scan_width: Optional[float] = None,
    matrix_size: Optional[int] = None,
    optic: Literal["bottom", "top"] = "top",
    flashes_per_well: int = 5,
  ) -> bytes:
    """Send an absorbance measurement command and return the run response immediately.

    This is an atomic operation: it sends the command payload and returns the
    firmware's ~53-byte run response without waiting for the measurement to complete.
    The caller (``read_absorbance``) is responsible for orchestrating the wait/progress
    polling loop.

    Args:
      wavelengths: List of wavelengths in nm (1-8 wavelengths, 200-1000 nm each).
      pause_time_per_well: Per-well pause in deciseconds (0-10). Encoded as
        ``(pause_time_per_well * 10) // 2`` (1 when 0). The optics head waits
        this long after moving to each well position before firing the xenon
        flash. Empirically adds ~0.1 s per well per decisecond. The OEM default
        byte ``0x19`` corresponds to pause_time_per_well=5.
      flying_mode: If True, the plate moves continuously during measurement.
      well_scan: Well scanning pattern. ``"orbital"`` is wired; ``"spiral"`` and
        ``"matrix"`` are validated but not yet encoded.
      well_scan_width: Width in mm of the scan pattern. For orbital/spiral: 1-15 mm.
        For matrix: 1-22 mm (side length of the square scan area).
        Only used when ``well_scan`` is not ``"point"``.
      matrix_size: Grid size for matrix well scan. The OEM software exposes
        3, 7, 8, 9, 10, 15, 20, 25, 30 (i.e. 3x3 to 30x30), but direct firmware
        control may accept other values.
        Only used when ``well_scan`` is ``"matrix"``.
      optic: Read from top or bottom optic. TODO: not yet wired into the command payload.
      settling_time_before_measurement: Once-per-run settling delay in seconds
        (uint16 BE, 0-65535). Applied before the optics head starts reading —
        primarily useful when shaking is part of the measurement cycle, to let
        the liquid settle after shaking. When non-zero, a flag byte ``0x01`` is
        set. Empirically adds ~1.1 s per unit (linear). No effect on OD accuracy.
      flashes_per_well: Number of xenon lamp flashes averaged per well (1-200).
        Encoded as uint16 BE. OEM defaults: 5 (point), 7 (orbital). Empirically,
        values >= 5 produce converged OD readings; additional flashes give
        marginal precision gains at ~12 ms per flash per well.

    Returns:
      The raw ~53-byte framed run response from the firmware.
    """
    if not 1 <= len(wavelengths) <= 8:
      raise ValueError("Must specify 1-8 wavelengths")
    if pause_time_per_well > 10:
      raise ValueError("pause_time_per_well must be 0-10 deciseconds")
    for w in wavelengths:
      if not 220 <= w <= 1000:
        raise ValueError(f"Wavelength {w} nm out of range (220-1000)")

    # Validate well_scan parameters against well geometry.
    if well_scan in ("orbital", "spiral", "matrix"):
      if well_scan_width is None:
        raise ValueError(f"well_scan_width is required when well_scan={well_scan!r}")
      sample_well = plate.get_all_items()[0]
      well_diameter = min(sample_well.get_size_x(), sample_well.get_size_y())
      if well_scan_width > well_diameter:
        raise ValueError(
          f"well_scan_width ({well_scan_width} mm) exceeds well diameter ({well_diameter} mm)"
        )
    if well_scan == "matrix" and matrix_size is None:
      raise ValueError("matrix_size is required when well_scan='matrix'")

    self._last_scan_params = {
      "start_corner": start_corner,
      "unidirectional": unidirectional,
      "vertical": vertical,
    }

    plate_and_wells = self._plate_bytes(plate, wells)
    scan = _scan_mode_byte(start_corner, unidirectional, vertical, flying_mode=flying_mode)

    shaker = (
      _shaker_bytes(shake_type, shake_speed_rpm, shake_duration_s)
      if shake_duration_s > 0
      else b"\x00\x00\x00\x00"
    )

    # Payload layout (Go reference verified):
    # plate(63) + scan(1) + optic(1) + zeros(3) + shaker(4)
    # + [extended(5) if 0x0026] + separator(4) + [orbital(5) if orbital] + ...
    payload = bytearray()
    payload += plate_and_wells
    payload += bytes([scan])

    # Optic config byte — base 0x02 for absorbance top-optic, OR'd with
    # orbital averaging flags when well_scan != "point".
    optic_config = 0x02 | _well_scan_optic_flags(well_scan)
    payload += bytes([optic_config])
    payload += b"\x00\x00\x00"

    payload += shaker

    # Machine type 0x0026 has 5 extra bytes before the separator.
    # Type 0x0024 (Go reference) omits them.
    if self._uses_extended_separator:
      payload += b"\x00\x20\x04\x00\x1e"
    payload += b"\x27\x0f\x27\x0f"

    # Orbital scan parameters (0 or 5 bytes after separator).
    payload += _well_scan_orbital_bytes(
      _ORBITAL_MEAS_CODE["absorbance"], well_scan, well_scan_width, plate,
    )
    # Per-well pause + wavelength count + wavelength data (per Go absDiscreteBytes)
    # Encoding: 1 if pause_time_per_well==0, else (pause_time_per_well * 10) // 2.
    # Default 0x19 (=25) in OEM captures corresponds to pause_time_per_well=5 (0.5s).
    settling_byte = 1 if pause_time_per_well == 0 else (pause_time_per_well * 10) // 2
    payload += bytes([settling_byte, len(wavelengths)])
    for w in wavelengths:
      payload += (w * 10).to_bytes(2, "big")
    # Fixed bytes
    payload += b"\x00\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00\x64\x00"
    # Settling time before measurement (once-per-run, post-shake delay)
    if settling_time_before_measurement != 0:
      payload += b"\x01"
    else:
      payload += b"\x00"
    payload += settling_time_before_measurement.to_bytes(2, "big")
    # Fixed trailer
    payload += b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01"
    # Flashes per well — uint16 BE. OEM uses 5 for point, 7 for orbital;
    # any value 1-200 is accepted by the firmware.
    payload += flashes_per_well.to_bytes(2, "big")
    payload += b"\x00\x01\x00\x00"

    run_response = await self.send_command(bytes(payload))

    # Verify the firmware accepted the command
    run_info = self._parse_run_response(run_response)
    logger.info(
      "Run command %s: total_values=%d, status=%s",
      "accepted" if run_info["accepted"] else "REJECTED",
      run_info["total_values"],
      run_info["status_bytes"].hex(),
    )
    if not run_info["accepted"]:
      raise RuntimeError(
        f"Absorbance run command rejected by firmware. "
        f"Status bytes: {run_info['status_bytes'].hex()}, "
        f"raw response: {run_response.hex()}"
      )

    return run_response

  @staticmethod
  def _parse_absorbance_response(
    resp: bytes, num_wavelengths: int
  ) -> Tuple[List[List[float]], Optional[float], Dict]:
    """Parse an absorbance measurement response.

    Returns (transmission_per_well_per_wavelength, temperature_celsius, raw).

    ``transmission[well_idx][wavelength_idx]`` = percent transmission.

    ``raw`` is a dict with the unprocessed detector counts::

        {
          "samples": [float, ...],        # wells*wavelengths raw counts
          "references": [float, ...],      # per-well reference counts
          "chromatic_cal": [(hi, lo), ...], # per-wavelength calibration bounds
          "reference_cal": (hi, lo),        # reference channel calibration bounds
        }

    The instrument response contains 4 groups of per-well uint32 BE data
    (one per detector channel) followed by calibration values:

    - Group 0: chromatic 1 detector counts (wells × wavelengths entries)
    - Group 1: chromatic 2 detector counts (wells entries)
    - Group 2: chromatic 3 detector counts (wells entries)
    - Group 3: reference detector counts (wells entries)
    - Calibration: always 4 pairs of (hi, lo) uint32 BE values — one per
      detector channel (chromatic 1, 2, 3, reference). Values are raw counts
      on the same scale as the data groups (no /256 encoding).

    Transmittance uses reference-corrected formula (no dark subtraction)::

      T = (sample / c_hi) × (r_hi / ref)
      T% = T × 100
      OD = -log10(T)

    The c_lo/r_lo dark values are embedded in the response but NOT used in the
    OD calculation — c_hi already includes the dark baseline, so subtracting
    c_lo would double-count it.  Verified against OEM MARS software output:
    all 96 wells of a test plate match within ±0.001 OD.

    Data is always in row-major plate order (A1–A12, B1–B12, …, H1–H12)
    regardless of the physical scan pattern.
    """
    try:
      payload = _unframe(resp)
    except FrameError:
      # If checksum or framing validation fails but the response looks like a
      # valid frame, strip framing manually so we can still parse the data.
      if len(resp) >= 7 and resp[0] == 0x02 and resp[-1] == 0x0D:
        payload = resp[4:-3]
      else:
        payload = resp

    if len(payload) < 36:
      raise ValueError(f"Absorbance response too short ({len(payload)} bytes)")

    schema = payload[6]
    if schema & 0x7F != 0x29:
      raise ValueError(f"Incorrect schema byte for abs data: 0x{schema:02x}, expected 0x29")

    wavelengths_in_resp = int.from_bytes(payload[18:20], "big")
    wells = int.from_bytes(payload[20:22], "big")

    # The firmware embeds a pre-measurement temperature (sampled at the start of
    # the read) at one of two offsets in the 36-byte header:
    #   bytes 23-24: used when incubation has never been active (schema 0x29)
    #   bytes 34-35: used when incubation is/was active (schema 0xa9, high bit set)
    # After incubation is turned off the schema stays 0xa9 but both offsets drop
    # to ~0 — the firmware simply stops embedding temperature. Return None so the
    # caller can fall back to a post-measurement dedicated sensor query.
    min_plausible_raw = 50  # 5.0 °C — below any realistic lab ambient
    temp_at_23 = int.from_bytes(payload[23:25], "big")
    temp_at_34 = int.from_bytes(payload[34:36], "big")

    if schema & 0x80:
      temp_raw = temp_at_34 if temp_at_34 >= min_plausible_raw else temp_at_23
    else:
      temp_raw = temp_at_23 if temp_at_23 >= min_plausible_raw else temp_at_34

    temperature: Optional[float] = temp_raw / 10.0 if temp_raw >= min_plausible_raw else None

    # --- Data groups ---
    # The firmware returns 1 + N groups of per-well uint32 BE data:
    #   group 0: chromatic 1 (sample) — wells × wavelengths entries
    #   extra groups 1..N: secondary detectors + reference (wells entries each)
    # After the groups: (1 + N) calibration pairs (hi, lo) uint32 BE — one per
    # group — then 0 or 1 trailing bytes.
    #
    # Layout:  [header 36B] [group0] [N extra groups] [(1+N)×8B cal] [0-1 trail]
    #
    # Solve for N from the payload size:
    #   bytes_after_group0 = N × (wells×4) + (1+N) × 8 + trailing
    #                      = N × (wells×4 + 8) + 8 + trailing
    #   N = (bytes_after_group0 - 8 - trailing) / (wells×4 + 8)
    offset = 36
    group0_size = wells * wavelengths_in_resp * 4
    bytes_after_group0 = len(payload) - 36 - group0_size
    W4 = wells * 4
    extra_groups = 0
    if W4 > 0:
      for trailing in (1, 0):
        n_float = (bytes_after_group0 - 8 - trailing) / (W4 + 8)
        if n_float >= 0 and abs(n_float - round(n_float)) < 0.01:
          extra_groups = int(round(n_float))
          break
    cal_size = (1 + extra_groups) * 8

    def _read_group(count):
      nonlocal offset
      group = []
      for _ in range(count):
        group.append(float(struct.unpack(">I", payload[offset : offset + 4])[0]))
        offset += 4
      return group

    # Group 0: chromatic 1 = sample detector counts (wells * wavelengths)
    vals = _read_group(wells * wavelengths_in_resp)
    # Read all extra groups sequentially, then assign by position:
    # 3 extra → chromatic2, chromatic3, reference
    # 2 extra → chromatic2, reference (skip chromatic3)
    # 1 extra → reference only
    # 0 extra → no secondary channels
    extra = [_read_group(wells) for _ in range(extra_groups)]
    zeros = [0.0] * wells
    if extra_groups >= 3:
      chromatic2, chromatic3, ref = extra[0], extra[1], extra[2]
    elif extra_groups == 2:
      chromatic2, chromatic3, ref = extra[0], zeros, extra[1]
    elif extra_groups == 1:
      chromatic2, chromatic3, ref = zeros, zeros, extra[0]
    else:
      chromatic2, chromatic3, ref = zeros, zeros, zeros

    # --- Calibration ---
    # One (hi, lo) uint32 BE pair per data group: chromat1, [chromat2, chromat3,] ref.
    # Number of pairs = 1 + extra_groups.
    def _read_cal_pair():
      nonlocal offset
      hi = float(struct.unpack(">I", payload[offset : offset + 4])[0])
      lo = float(struct.unpack(">I", payload[offset + 4 : offset + 8])[0])
      offset += 8
      return (hi, lo)

    num_cal_pairs = 1 + extra_groups
    cal_pairs = [_read_cal_pair() for _ in range(num_cal_pairs)]
    # First pair = chromat1 (sample), last pair = reference, middle = chromat2/3
    chromat1_cal = cal_pairs[0]
    ref_cal = cal_pairs[-1] if num_cal_pairs >= 2 else (0.0, 0.0)
    chromat2_cal = cal_pairs[1] if num_cal_pairs >= 3 else (0.0, 0.0)
    chromat3_cal = cal_pairs[2] if num_cal_pairs >= 4 else (0.0, 0.0)

    chromats = [chromat1_cal] * wavelengths_in_resp

    logger.info(
      "Abs parser: schema=0x%02x, wells=%d, wl=%d, groups=%d (1+%d), "
      "payload=%d B, cal_pairs=%d, sample[0]=%.0f, ref[0]=%.0f, "
      "c1_cal=(%.0f, %.0f), ref_cal=(%.0f, %.0f), temp=%s",
      schema, wells, wavelengths_in_resp, 1 + extra_groups, extra_groups,
      len(payload), num_cal_pairs,
      vals[0] if vals else 0, ref[0] if ref else 0,
      chromat1_cal[0], chromat1_cal[1], ref_cal[0], ref_cal[1],
      f"{temperature:.1f}" if temperature is not None else "None",
    )

    raw: Dict = {
      "samples": list(vals),
      "references": list(ref),
      "chromatic_cal": list(chromats),
      "reference_cal": ref_cal,
      "chromatic2": list(chromatic2),
      "chromatic3": list(chromatic3),
      "chromatic2_cal": chromat2_cal,
      "chromatic3_cal": chromat3_cal,
    }

    # Reference-corrected transmittance (no dark subtraction):
    #   T = (sample / c_hi) * (r_hi / ref)
    r_hi, _ = ref_cal
    transmission: List[List[float]] = []
    for i in range(wells):
      well_trans = []
      for j in range(wavelengths_in_resp):
        c_hi, _ = chromats[j]
        sample = vals[i + j * wells]
        if c_hi <= 0:
          well_trans.append(0.0)
          continue
        ref_well = ref[i]
        T = (sample / c_hi) * (r_hi / ref_well) if ref_well > 0 else 0.0
        well_trans.append(T * 100)
      transmission.append(well_trans)

    return transmission, temperature, raw

  async def read_absorbance(
    self,
    plate: Plate,
    wells: List[Well],
    wavelength: int,
    report: Literal["OD", "transmittance", "raw"] = "OD",
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    """Read absorbance values from the device.

    Orchestrates the full OEM-style measurement sequence:

    0. Enable temperature monitoring (ensures embedded temp in response).
    1. Send the absorbance run command (atomic ``_start_absorbance_measurement``).
    2. Check if BUSY already cleared (fast measurements with few wells).
    3. If ``wait=False``, return ``None`` immediately.
    4. If ``wait=True``, progressive polling loop at ``data_retrieval_rate``.
    5. After BUSY clears, collect final measurement data.

    Args:
      wavelength: wavelength to read absorbance at, in nanometers.
      report: whether to report absorbance as optical depth (OD) or transmittance.
      **backend_kwargs: Additional keyword arguments:
        wavelengths: List[int] - multiple wavelengths (overrides ``wavelength``).
        flashes_per_well: int - number of flashes per well (0-200).
        pause_time_per_well: int - per-well pause in deciseconds (0-10).
        settling_time_before_measurement: int - once-per-run post-shake delay in seconds.
        shake_type, shake_speed_rpm, shake_duration_s: shaker config.
        start_corner, unidirectional, vertical, flying_mode: scan config.
        well_scan: Literal["point", "orbital", "spiral", "matrix"] - well scan pattern.
        well_scan_width: float - width in mm of scan pattern (orbital/spiral: 1-15, matrix: 1-22).
        matrix_size: int - grid size for matrix well scan (3-30, meaning 3x3 to 30x30).
        optic: Literal["bottom", "top"] - read from bottom or top optic.
        wait: bool - if False, start measurement and return None immediately.
          Use ``collect_absorbance_measurement`` to retrieve results later.
        data_retrieval_rate: float - seconds between progressive data polls (default 0.5).
        on_progress: async callback ``(complete, total, raw_response)`` called
          each time progressive data is fetched during the polling loop.
    """
    wait = backend_kwargs.pop("wait", True)
    data_retrieval_rate: float = backend_kwargs.pop("data_retrieval_rate", 0.5)
    on_progress: Optional[Callable[[int, int, Optional[bytes]], Awaitable[None]]] = \
      backend_kwargs.pop("on_progress", None)
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())

    # Support multi-wavelength via backend_kwargs
    wavelengths = backend_kwargs.pop("wavelengths", [wavelength])
    if isinstance(wavelengths, int):
      wavelengths = [wavelengths]

    # OEM firmware never sends _mp_and_focus_height_value ($05 $0F) before
    # measurements — verified via USB pcap analysis.  Removed to match OEM flow.

    # Step 0: Ensure temperature monitoring is active so the firmware embeds
    # a pre-measurement temperature reading in the response.
    await self.enable_temperature_monitoring()

    # Step 1: Send command, verify accepted, return run response
    run_response = await self._start_absorbance_measurement(
      wavelengths=wavelengths,
      plate=plate,
      wells=None if all_wells else wells,
      **backend_kwargs,
    )

    # Step 2: Check if measurement already completed (fast measurements
    # with few wells finish before we even get to progressive polling).
    await asyncio.sleep(0.1)
    command_status = await self._request_command_status()
    flags = self._parse_status_response(command_status)
    already_done = not flags["busy"]

    if already_done:
      logger.info("Measurement already complete (BUSY cleared), skipping progressive polling")

    # Step 3: Early exit if not waiting
    if not wait:
      return None

    # Step 4: Progressive polling loop (skipped if already done)
    #
    # Value accounting: the firmware reports progress as raw value counts.
    # For each wavelength it measures: sample + reference per well, plus
    # 4 calibration values. So:
    #   total = n_wells * 2 * n_wl + n_wl * 4
    #   wells_measured = (complete - n_wl * 4) / (2 * n_wl)
    # Calibration values fill first, then wells fill in scan order.
    n_wells = len(wells)
    n_wl = len(wavelengths)
    cal_overhead = n_wl * 4  # calibration values per wavelength

    if not already_done:
      timeout = self.timeout
      t_start = time.time()
      while time.time() - t_start < timeout:
        await asyncio.sleep(data_retrieval_rate)

        # Check if BUSY has cleared FIRST — avoids sending progressive
        # getData to a firmware that's already idle (which may not respond
        # or may return stale data).
        command_status = await self._request_command_status()
        flags = self._parse_status_response(command_status)
        if not flags["busy"]:
          logger.info("BUSY cleared, measurement complete")
          break

        # Fetch progressive data (only while still BUSY).
        # The firmware may send an unsolicited status notification (24 bytes,
        # RUNNING + UNREAD_DATA) when the measurement finishes.  read_resp
        # can pick this up instead of the real progressive data response.
        # Detect it by size: data responses are >100 bytes; status
        # notifications are exactly 24 bytes with payload[0] in the status
        # command family (0x00 or 0x01).
        await self._drain_buffer()
        try:
          progressive_resp = await self._get_progressive_measurement_values()

          # Check if we received an unsolicited status notification instead
          # of progressive data.  These are ~24 bytes; real data responses
          # for even the smallest plate (8 wells) are 124+ bytes.
          try:
            resp_payload = _unframe(progressive_resp)
          except FrameError:
            resp_payload = progressive_resp[4:-2] if len(progressive_resp) >= 7 else progressive_resp
          if len(resp_payload) >= 5 and resp_payload[0] in (0x00, 0x01):
            notif_flags = _parse_status(resp_payload[:5])
            logger.info(
              "Received unsolicited status notification: %s",
              {k: v for k, v in notif_flags.items() if v},
            )
            if not notif_flags.get("busy", False):
              logger.info("Firmware reports measurement complete via notification")
              break
            continue

          progress = self._parse_progress_from_data_response(progressive_resp)
          wells_done = max(0, (progress["complete"] - cal_overhead)) // (2 * n_wl)
          logger.info(
            "Progressive: %d/%d wells measured (%d/%d values)",
            wells_done, n_wells, progress["complete"], progress["total"],
          )
          if on_progress is not None:
            await on_progress(progress["complete"], progress["total"], progressive_resp)
        except (ValueError, FrameError) as e:
          logger.debug("Progressive poll failed: %s", e)
      else:
        elapsed = time.time() - t_start
        raise TimeoutError(
          f"Plate reader still busy after {elapsed:.1f}s (timeout={timeout}s). "
          f"Increase timeout via CLARIOstarBackend(timeout=...) for long-running operations."
        )

    # Step 5: Collect final data — drain any stale bytes from progressive
    # polling and give the firmware a moment to prepare the final data buffer.
    # The firmware can take 20+ seconds on the first measurement of a session;
    # draining + sleeping here reduces the chance of a truncated read.
    await self._drain_buffer()
    await asyncio.sleep(0.5)
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
    # Match the Go/OEM collection flow: send getData (0x05 0x02) immediately.
    # Do NOT send _read_order_values (0x05 0x1d) or _status_hw (0x81) first —
    # any 0x05-family command invalidates the measurement buffer (all-None).
    # Do NOT drain the FTDI buffer — the measurement data response is already
    # queued there after _wait_for_ready_and_return completes.
    vals = await self._get_measurement_values()

    logger.info(
      "Absorbance response: %d bytes",
      len(vals),
    )

    # NOTE: for partial-well reads the firmware returns exactly N values for N
    # selected wells, in the row-major scan order of those wells (A1, A2, ...,
    # B1, B3, ...). _readings_to_grid sorts wells by (row, col) to match.

    num_wells = len(wells)
    transmission_data, temperature, raw = self._parse_absorbance_response(vals, len(wavelengths))

    # Normally the firmware embeds a temperature in the measurement response,
    # sampled at the start of the measurement (pre-measurement). When
    # incubation has been used and then turned off, the firmware keeps the
    # 0xa9 schema but writes ~0 to both temperature offsets — the embedded
    # temperature is simply unavailable. In that case, query the sensor
    # directly. Note: this is a POST-measurement reading (taken now, after the
    # measurement has finished) and may differ slightly from the actual plate
    # temperature during the read.
    if temperature is None:
      warnings.warn(
        "The measurement response did not contain an embedded temperature "
        "(this happens after incubation is turned off). Falling back to a "
        "post-measurement sensor query — the reported temperature was read "
        "after the measurement finished, not at the start.",
        stacklevel=2,
      )
      temperature = await self.measure_temperature()

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

  # # # Fluorescence # # #

  async def _start_fluorescence_measurement(
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
    pause_time_per_well: int = 0,
    bottom_optic: bool = False,
    shake_type: ShakerType = ShakerType.ORBITAL,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    settling_time_before_measurement: int = 0,
    start_corner: StartCorner = StartCorner.TOP_LEFT,
    unidirectional: bool = False,
    vertical: bool = True,
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
      pause_time_per_well: Per-well pause delay in deciseconds (0-10). Encoded as
        ``(pause_time_per_well * 10) // 2`` (1 when 0). The optics head waits this
        long after moving to each well position before firing. Adds ~0.1 s per well
        per decisecond.
      bottom_optic: Use bottom optic instead of top.
      settling_time_before_measurement: Once-per-run settling delay in seconds
        (uint16 BE, 0-65535). Primarily useful as a post-shake settling delay when
        shaking is part of the measurement cycle. When non-zero, a flag byte
        ``0x01`` is set. Adds ~1.2 s per unit for small values; non-linear at
        higher values. Not per-well. No effect on accuracy.
    """
    if flashes > 200:
      raise ValueError("Flashes per well must be <= 200")
    if flying_mode and flashes > 3:
      raise ValueError("Cannot do more than 3 flashes in flying mode")

    self._last_scan_params = {
      "start_corner": start_corner,
      "unidirectional": unidirectional,
      "vertical": vertical,
    }

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

    # Per-well pause time
    if pause_time_per_well == 0:
      payload += bytes([1])
    else:
      payload += bytes([(pause_time_per_well * 10) // 2])

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

    # Settling time before measurement (once-per-run, post-shake delay)
    if settling_time_before_measurement != 0:
      payload += b"\x01"
    else:
      payload += b"\x00"
    payload += settling_time_before_measurement.to_bytes(2, "big")

    # Fixed trailer
    payload += b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01"

    # Flashes
    payload += flashes.to_bytes(2, "big")
    payload += b"\x00\x4b\x00\x00"

    run_response = await self.send_command(bytes(payload))
    if wait:
      return await self._wait_for_ready_and_return(run_response)
    return run_response

  @staticmethod
  def _parse_fluorescence_response(resp: bytes) -> Tuple[List[int], Optional[float], int]:
    """Parse a fluorescence measurement response using fixed offsets per the Go reference.

    Returns (values, temperature_celsius, overflow_value).
    """
    try:
      payload = _unframe(resp)
    except FrameError:
      payload = resp

    if len(payload) < 34:
      raise ValueError(f"Fluorescence response too short ({len(payload)} bytes)")

    schema = payload[6]
    if schema & 0x7F != 0x21:
      raise ValueError(f"Incorrect schema byte for fl data: 0x{schema:02x}, expected 0x21")


    complete = int.from_bytes(payload[9:11], "big")
    overflow = struct.unpack(">I", payload[11:15])[0]
    temp_raw = int.from_bytes(payload[25:27], "big")
    min_plausible_raw = 50  # 5.0 °C — below any realistic lab ambient
    temperature: Optional[float] = temp_raw / 10.0 if temp_raw >= min_plausible_raw else None

    values = []
    offset = 34
    for _ in range(complete):
      if offset + 4 > len(payload):
        raise ValueError("Expected fluorescence data, but response truncated")
      values.append(struct.unpack(">I", payload[offset : offset + 4])[0])
      offset += 4

    return values, temperature, overflow

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
        pause_time_per_well: int - per-well pause in deciseconds (0-10).
        settling_time_before_measurement: int - once-per-run post-shake delay in seconds.
        bottom_optic: bool - use bottom optic.
        shake_type, shake_speed_rpm, shake_duration_s: shaker config.
        start_corner, unidirectional, vertical, flying_mode: scan config.
        wait: bool - if False, start measurement and return None immediately.
          Use ``collect_fluorescence_measurement`` to retrieve results later.
    """
    wait = backend_kwargs.pop("wait", True)
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())

    # OEM firmware never sends _mp_and_focus_height_value ($05 $0F) before
    # measurements — verified via USB pcap analysis.  Removed to match OEM flow.

    await self._start_fluorescence_measurement(
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
    # Match the Go/OEM flow: send getData directly.
    # See collect_absorbance_measurement for why extra commands are skipped.
    vals = await self._get_measurement_values()
    logger.info("Fluorescence response: %d bytes", len(vals))

    scan_order = self._compute_scan_order(
      plate, wells,
      start_corner=self._last_scan_params.get("start_corner", StartCorner.TOP_LEFT),
      unidirectional=self._last_scan_params.get("unidirectional", False),
      vertical=self._last_scan_params.get("vertical", True),
    )

    num_read = len(wells)
    fl_values, temperature, overflow = self._parse_fluorescence_response(vals)

    # POST-measurement fallback: see comment in collect_absorbance_measurement.
    if temperature is None:
      warnings.warn(
        "The measurement response did not contain an embedded temperature "
        "(this happens after incubation is turned off). Falling back to a "
        "post-measurement sensor query — the reported temperature was read "
        "after the measurement finished, not at the start.",
        stacklevel=2,
      )
      temperature = await self.measure_temperature()

    readings = [float(v) for v in fl_values[:num_read]]

    return [
      {
        "ex_wavelength": excitation_wavelength,
        "em_wavelength": emission_wavelength,
        "data": self._readings_to_grid(readings, plate, wells, scan_order=scan_order),
        "temperature": temperature,
        "time": time.time(),
      }
    ]
