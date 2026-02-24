"""BMG CLARIOstar Plus plate reader backend.

Lifecycle: initialize, open/close drawer, status polling, EEPROM/firmware
identification, machine type auto-detection.
Measurement: absorbance, fluorescence, luminescence (not yet implemented).
"""

import asyncio
import enum
import logging
import time
from typing import Dict, List, Literal, Optional

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
  frame.append(0x02)  # STX
  frame.extend(frame_size.to_bytes(2, "big"))  # size
  frame.append(0x0C)  # header
  frame.extend(payload)  # payload
  checksum = sum(frame) & 0xFFFFFF
  frame.extend(checksum.to_bytes(3, "big"))  # checksum
  frame.append(0x0D)  # CR
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


# 0x0024: verified on CLARIOstar Plus hardware (serial 430-2621).
# 0x0026: from vibed code, unverified on real hardware.
_MODEL_LOOKUP: Dict[int, str] = {
  0x0024: "CLARIOstar Plus",
  0x0026: "CLARIOstar Plus",
}

# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class CLARIOstarPlusBackend(PlateReaderBackend):
  """BMG CLARIOstar Plus plate reader backend.

  Lifecycle: initialize, open/close drawer, status polling, device identification.
  Measurement: absorbance, fluorescence, luminescence (not yet implemented).
  """

  # -- Command enums (CLARIOstar-specific, to our knowledge)------------------

  class CommandFamily(enum.IntEnum):
    """Command group byte (payload byte 0)."""

    INITIALIZE = 0x01
    TRAY = 0x03
    RUN = 0x04
    REQUEST = 0x05
    TEMPERATURE_CONTROLLER = 0x06
    POLL = 0x08
    STATUS = 0x80
    HW_STATUS = 0x81

  class Command:
    """Command byte constants (payload byte 1).

    Grouped by CommandFamily. Values are plain ints rather than IntEnum because
    multiple groups reuse the same byte value (e.g. INIT, TRAY_CLOSE, and POLL
    are all 0x00) and IntEnum would silently alias them.
    """

    # INITIALIZE
    INIT = 0x00
    # TRAY
    TRAY_CLOSE = 0x00
    TRAY_OPEN = 0x01
    # RUN
    MEASUREMENT = 0x31
    # REQUEST
    DATA = 0x02
    EEPROM = 0x07
    FIRMWARE_INFO = 0x09
    FOCUS_HEIGHT = 0x0F
    READ_ORDER = 0x1D
    USAGE_COUNTERS = 0x21
    # POLL
    POLL = 0x00

  _VALID_COMMANDS = {
    CommandFamily.INITIALIZE: {Command.INIT},
    CommandFamily.TRAY: {Command.TRAY_CLOSE, Command.TRAY_OPEN},
    CommandFamily.RUN: {Command.MEASUREMENT},
    CommandFamily.REQUEST: {
      Command.DATA,
      Command.EEPROM,
      Command.FIRMWARE_INFO,
      Command.FOCUS_HEIGHT,
      Command.READ_ORDER,
      Command.USAGE_COUNTERS,
    },
    CommandFamily.POLL: {Command.POLL},
  }
  _NO_COMMAND_FAMILIES = {
    CommandFamily.STATUS,
    CommandFamily.HW_STATUS,
    CommandFamily.TEMPERATURE_CONTROLLER,
  }

  # -- Status flags (CLARIOstar-specific bit positions) ---------------------

  # (flag_name, byte_index_in_5-byte_status, bitmask)
  _STATUS_FLAGS = [
    ("standby", 0, 1 << 1),
    ("busy", 1, 1 << 5),
    ("running", 1, 1 << 4),
    ("unread_data", 2, 1),
    ("initialized", 3, 1 << 5),
    ("drawer_open", 3, 1),
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

  _PACKET_READ_TIMEOUT: float = 3  # seconds; max wait for a single serial frame

  # --------------------------------------------------------------------------
  # Constructor
  # --------------------------------------------------------------------------

  def __init__(
    self,
    device_id: Optional[str] = None,
    read_timeout: float = 120,
    max_temperature: float = 45,
  ):
    """Create a new CLARIOstar Plus backend.

    Args:
      device_id: FTDI serial number / device ID. Only needed if multiple FTDI
        devices are connected.
      read_timeout: timeout in seconds for reading a full response. For commands
        with ``wait=True`` (open, close, initialize) this bounds the total time
        including busy-polling. Can be overridden per-command via
        ``send_command(read_timeout=...)``.
      max_temperature: Maximum allowed target temperature in °C. Standard
        incubator range is 0-45°C; extended incubator supports 10-65°C.
    """
    self.io = FTDI(device_id=device_id, vid=0x0403, pid=0xBB68)
    self.read_timeout = read_timeout

    self.configuration: Dict = {
      "serial_number": "",
      "firmware_version": "",
      "firmware_build_timestamp": "",
      "model_name": "",
      "machine_type_code": 0,
      "max_temperature": max_temperature,
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
    self._target_temperature: Optional[float] = None

  # --------------------------------------------------------------------------
  # Life cycle
  # --------------------------------------------------------------------------

  async def setup(self) -> None:
    """Configure FTDI serial link (125 kBaud, 8N1), initialize the reader, and read EEPROM/firmware."""
    await self.io.setup()
    await self.io.set_baudrate(125000)
    await self.io.set_line_property(8, 0, 0)  # 8N1
    await self.io.set_latency_timer(2)

    await self.initialize()

    # Flush residual POLL (0x08) firmware state.  If the device was previously
    # addressed with POLL -- by Voyager or a prior session -- byte 3 of ALL
    # responses is set to 0x04, corrupting status flags (initialized, drawer_open,
    # plate_detected) and machine_type detection.  Sending STATUS_QUERY (0x80)
    # frames resets byte 3 to the real value.  In normal operation (no prior POLL)
    # this exits on the first iteration (~37 ms).
    for _ in range(50):
      await self._write_frame(self._STATUS_FRAME)
      resp = await self._read_frame()
      try:
        _validate_frame(resp)
      except FrameError:
        continue
      payload = _extract_payload(resp)
      if len(payload) >= 4 and payload[3] != 0x04:
        break

    # Populate configuration from EEPROM + firmware info.
    eeprom_info = await self.request_eeprom_data()
    self.configuration.update(eeprom_info)

    fw_info = await self.request_firmware_info()
    self.configuration.update(fw_info)

    # Serial number from FTDI descriptor.
    if self.io.device_id:
      self.configuration["serial_number"] = self.io.device_id

    modes = [
      m
      for m, key in [
        ("absorbance", "has_absorbance"),
        ("fluorescence", "has_fluorescence"),
        ("luminescence", "has_luminescence"),
        ("alpha_technology", "has_alpha_technology"),
      ]
      if self.configuration.get(key)
    ]
    logger.info(
      "%s (0x%04x) fw %s (%s) -- detection: %s",
      self.configuration["model_name"],
      self.configuration["machine_type_code"],
      self.configuration["firmware_version"] or "firmware version ?",
      self.configuration["firmware_build_timestamp"] or "unknown build",
      ", ".join(modes) if modes else "none",
    )

  async def stop(self, accept_plate_left_in_device: bool = False) -> None:
    """Close the FTDI connection. Requires a new ``setup()`` call to use the reader again.

    Shuts down temperature control and closes the drawer before disconnecting.
    If a plate is still detected inside the device, the drawer is reopened and
    a ``RuntimeError`` is raised so the user can retrieve it.

    Args:
      accept_plate_left_in_device: If True, skip the plate-presence check and
        disconnect even if a plate is still inside.

    Raises:
      RuntimeError: If a plate is detected and *accept_plate_left_in_device* is False.
    """
    self._target_temperature = None
    if await self._request_temperature_monitoring_on():
      await self._stop_temperature_monitoring()

    if await self.sense_drawer_open():
      await self.close()

    if not accept_plate_left_in_device and await self.sense_plate_present():
      await self.open()
      raise RuntimeError(
        "A plate is still present in the device. Remove it before stopping, "
        "or set accept_plate_left_in_device=True to skip this check."
      )

    await self.io.stop()

  async def initialize(self, wait: bool = True, poll_interval: float = 0.0) -> None:
    """Send the hardware init sequence and poll until ready.

    Args:
      wait: If True, block until the device is no longer busy.
      poll_interval: Seconds between status polls while waiting.
    """
    await self.send_command(
      command_family=self.CommandFamily.INITIALIZE,
      command=self.Command.INIT,
      payload=b"\x00\x10\x02\x00",
      wait=wait,
      poll_interval=poll_interval,
    )

  # --------------------------------------------------------------------------
  # Low-level I/O
  # --------------------------------------------------------------------------

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
      timeout = self._PACKET_READ_TIMEOUT

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
        # Empty read after we already saw CR → done,
        # but only if we have all bytes the size field promised.
        # 0x0D can appear mid-frame (e.g. in checksum bytes),
        # so end_byte_found alone is not sufficient.
        if end_byte_found and (expected_size is None or len(d) >= expected_size):
          break

        if time.time() - t > timeout:
          logger.warning("timed out reading response")
          break

        await asyncio.sleep(0.0001)

    if d and logger.isEnabledFor(logging.INFO):
      logger.info("read %d bytes: %s", len(d), d.hex())

    return d

  # Pre-cached status frame: STATUS_QUERY (0x80).
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
      read_timeout: timeout in seconds for reading a full response. For
        commands with ``wait=True`` this bounds the total time including
        busy-polling. Defaults to ``self.read_timeout``.
      wait: If True, poll status after the initial response until the device
        is no longer busy. Used by commands that trigger physical actions
        (initialize, open, close, etc.).
      poll_interval: Seconds to sleep between status polls when *wait* is True.
        Default 0.0 (no sleep, paced by I/O roundtrip alone, ~37 ms/poll).

    Returns:
      Validated response payload (frame overhead stripped).

    Raises:
      ValueError: If *command* is missing, unexpected, or not valid for the group.
      FrameError: If the response frame structure is invalid.
      ChecksumError: If the response checksum does not match.
      TimeoutError: If *wait* is True and the device stays busy beyond
        *read_timeout*.
    """
    CF = self.CommandFamily
    if command_family in self._NO_COMMAND_FAMILIES:
      if command is not None:
        raise ValueError(f"{CF(command_family).name} does not accept a command")
      data = bytes([command_family]) + payload
    else:
      if command is None:
        raise ValueError(f"{CF(command_family).name} requires a command")
      valid = self._VALID_COMMANDS.get(command_family, set())
      if command not in valid:
        raise ValueError(f"command 0x{command:02x} is not valid for {CF(command_family).name}")
      data = bytes([command_family, command]) + payload

    frame = _wrap_payload(data)
    await self._write_frame(frame)
    resp = await self._read_frame()
    _validate_frame(resp)
    ret = _extract_payload(resp)

    if wait:
      await self._wait_until_machine_ready(read_timeout=read_timeout, poll_interval=poll_interval)

    return ret

  # --------------------------------------------------------------------------
  # Status
  # --------------------------------------------------------------------------

  async def request_machine_status(self, retries: int = 3) -> Dict:
    """Query device status and return parsed flags.

    Bypasses ``send_command`` to avoid infinite recursion with
    ``_wait_until_machine_ready``. Retries on transient ``FrameError``
    up to *retries* times before raising.

    Args:
      retries: Number of attempts before raising on repeated frame errors.

    Returns:
      Dict with bool flags (``standby``, ``busy``, ``running``, ``unread_data``,
      ``initialized``, ``drawer_open``, ``plate_detected``),
      ``Optional[float]`` temperatures (``temperature_bottom``,
      ``temperature_top``) in °C. Temperatures are ``None`` when monitoring
      is inactive.
    """
    last_err: Optional[FrameError] = None
    for attempt in range(retries):
      await self._write_frame(self._STATUS_FRAME)
      resp = await self._read_frame()
      try:
        _validate_frame(resp)
      except FrameError as e:
        last_err = e
        logger.warning("status request: bad frame on attempt %d/%d (%s)", attempt + 1, retries, e)
        continue
      payload = _extract_payload(resp)
      status: Dict = self._parse_status(payload[:5])
      if len(payload) >= 15:
        raw_bottom = int.from_bytes(payload[11:13], "big")
        raw_top = int.from_bytes(payload[13:15], "big")
        status["temperature_bottom"] = raw_bottom / 10.0 if raw_bottom else None
        status["temperature_top"] = raw_top / 10.0 if raw_top else None
      else:
        status["temperature_bottom"] = None
        status["temperature_top"] = None
      return status
    assert last_err is not None
    raise last_err

  async def is_ready(self) -> bool:
    """Return True if the device is ready to accept commands.

    Delegates to ``request_machine_status()`` (fixed-length 16-byte response).
    """
    return not (await self.request_machine_status())["busy"]

  async def _wait_until_machine_ready(
    self, read_timeout: Optional[float] = None, poll_interval: float = 0.0
  ) -> None:
    """Poll ``request_machine_status`` until the device is no longer busy.

    Checks the same ``busy`` flag as ``is_ready`` but adds timeout-bounded
    polling, ``FrameError`` retry, and per-poll status logging.

    Args:
      read_timeout: Max seconds to wait. ``None`` waits indefinitely.
      poll_interval: Seconds to sleep between polls. Default 0.0 (no sleep,
        paced by I/O roundtrip alone, ~37 ms/poll).
    """
    if read_timeout is None:
      logger.warning("_wait_until_machine_ready called without read_timeout, waiting indefinitely")
      read_timeout = float("inf")
    t = time.time()
    while time.time() - t < read_timeout:
      try:
        flags = await self.request_machine_status()
      except FrameError as e:
        logger.warning("status poll: bad frame (%s), retrying", e)
        continue

      if logger.isEnabledFor(logging.INFO):
        logger.info("status: %s", flags)

      if not flags["busy"]:
        return

      if poll_interval > 0:
        await asyncio.sleep(poll_interval)

    elapsed = time.time() - t
    raise TimeoutError(
      f"Plate reader still busy after {elapsed:.1f}s (read_timeout={read_timeout}s). "
      f"Increase timeout via CLARIOstarPlusBackend(read_timeout=...) or per-command read_timeout=."
    )

  async def sense_plate_present(self) -> bool:
    """Return True if a plate is currently detected in the drawer.

    Delegates to ``request_machine_status()`` (fixed-length 16-byte response).
    """
    return bool((await self.request_machine_status())["plate_detected"])

  # --------------------------------------------------------------------------
  # Device info
  # --------------------------------------------------------------------------

  async def request_eeprom_data(self) -> Dict:
    """Fetch and parse the EEPROM payload.

    Response is 264 bytes (observed on CLARIOstar Plus, type 0x0024).

    EEPROM Byte Map -- Full 264-Byte Analysis
    ==========================================
    Source: real capture from CLARIOstar Plus.
    Reference hex (first 48 bytes):
      07 05 00 24 00 00 00 01  00 00 0a 01 01 01 01 00
      00 01 00 ee 02 00 00 0f  00 b0 03 00 00 00 00 00
      00 03 04 00 00 01 00 00  01 02 00 00 00 00 00 00

    Section 1 -- Header & Command Echo (bytes 0-3) [CONFIRMED]
      [0]     subcommand echo (0x07)
      [1]     command family echo (0x05)
      [2:4]   machine_type code (u16 BE). 0x0024/0x0026 = CLARIOstar Plus.

    Section 2 -- Board Info (bytes 4-10) [HYPOTHESES]
      [4:6]   always 0x0000 -- padding or reserved
      [7]     0x01 -- possibly BoardNum main board version (ActiveX: "1/3" format)
      [10]    0x0a (10) -- possibly BoardNum measurement board version or hw revision

    Section 3 -- Detection Mode Flags (bytes 11-17) [11-14 CONFIRMED]
      [11]    has_absorbance (bool)     -- ActiveX: AbsOptionIn
      [12]    has_fluorescence (bool)   -- standard on all CLARIOstar Plus
      [13]    has_luminescence (bool)   -- ActiveX: LumiOptionIn
      [14]    has_alpha_technology (bool) -- requires optional 680nm laser
      [15]    0x00 -- HYPOTHESIS: has_trf (ActiveX: TRFOptionIn) or has_dual_pmt
      [16]    0x00 -- unknown flag
      [17]    0x01 -- unknown flag (always 1 on test unit; maybe has_spectrometer
              or microplate_sensor_enabled)

    Section 4 -- Monochromator & Optics (bytes 18-34) [19-20,25-26,33,34 CONFIRMED]
      [18]    0x00 -- padding
      [19:21] excitation monochromator max nm (u16 LE). 0x02ee = 750 nm.
      [21:22] 0x0000
      [23]    0x0f (15) -- unknown; possibly default bandwidth nm or step size
      [24]    0x00
      [25:27] emission monochromator max nm (u16 LE). 0x03b0 = 944 nm.
              (Note: spec sheet says 840nm LVF range; 944 is physical slide limit)
      [27:32] 0x00 x 5
      [33]    dichroic filter slots (u8) = 3 (manual: positions A,B,C on 1 slide)
      [34]    excitation/emission filter slots (u8) = 4 (manual: 4 per side, 2 slides x 2)
              Note: min monochromator nm is NOT in EEPROM. 320nm is a hardware constant
              of the LVF design per BMG spec sheets.

    Section 5 -- Hardware Options (bytes 35-52) [HYPOTHESES]
      ActiveX EEPROM-derived items not yet mapped: Pump1In, Pump2In, IncubIn,
      ExtIncubator, ApertureType. Test unit has no pumps, has standard incubator.
      [35]    0x00 -- HYPOTHESIS: Pump1In (no pump → 0)
      [36]    0x00 -- HYPOTHESIS: Pump2In (no pump → 0)
      [37]    0x01 -- HYPOTHESIS: IncubIn (standard incubator → 1)
      [38]    0x00 -- HYPOTHESIS: ExtIncubator (not extended → 0; extended = 10-65°C)
              If confirmed, this could drive max_temperature (45°C vs 65°C)
              automatically. Needs a second unit with extended incubator to verify.
      [40]    0x01 -- unknown flag
      [41]    0x02 -- HYPOTHESIS: ApertureType (ActiveX: 'none'=0, '96/384'=1, '1536'=2)
      [52]    0x32 (50) -- unknown; maybe default shake speed or settling time

    Section 6 -- Sparse Region (bytes 53-95) [UNKNOWN]
      Mostly zeros with isolated non-zero bytes:
      [73]=0x74('t'), [75]=0x6f('o'), [83]=0x65('e') -- fragment of old string?
      [87]=0xdc(220) -- tempting as UV spectrometer min nm, but unconfirmed
      [88]=0x05 -- could be filter slide count (5 slides per manual)

    Section 7 -- Calibration Block A (bytes 96-111) [UNKNOWN]
      8 x u16 LE values: 500, 776, 1191, 1800, 2400, 2266, 3500
      Mostly monotonically increasing. Likely LVF motor step positions or
      wavelength calibration reference points. Could also be usage counters
      (compare with cmd 0x05 0x21 response to distinguish).

    Section 8 -- Zero Region (bytes 112-134)
      23 bytes of 0x00. Clear section boundary.

    Section 9 -- Boolean Flag Block (bytes 135-152) [UNKNOWN]
      6 x 0x01 flags at offsets 135, 139, 140, 149, 150 + one more.
      Possibly: has_barcode_reader (left/right), has_gas_control (O2/CO2 ACU),
      has_stacker, microplate_sensor_enabled, etc.

    Section 10 -- Serial + Calibration Block B (bytes 153-263)
      [161:163] serial number prefix (u16 LE) = 430   [CONFIRMED]
      [163:165] serial number suffix (u16 LE) = 2621  [CONFIRMED]
      [165:167] firmware version (u16 LE) = 1350 → v1.350  [CONFIRMED]
      Remaining: signed int16 LE pairs (range -168 to +6799).
      Mix of positive (100-6800) and small negative (-5, -160, -166, -168)
      values = optical calibration data. Likely per-unit factory-calibrated
      LVF monochromator slide motor positions + correction offsets for the
      5 slides (2 Ex LVLP+LVSP, 2 Em LVLP+LVSP, 1 LVDM).
      Repeated values (1688x2, 4437x2) suggest paired top/bottom calibration.
      Bytes 217-224 contain repeated 0x46 ('F') -- possibly filter ID codes.

    Decode Summary: 20/264 bytes confirmed (7.6%), ~40/264 with hypotheses (15%).
    To confirm more: need a second unit with different options (pumps, ext incubator),
    or query ActiveX GetInfo("Pump1In") etc. while comparing raw EEPROM bytes.

    ActiveX EEPROM-derived items (from BMG ActiveX/DDE Manual 0430N0003I):
      AbsOptionIn, LumiOptionIn, TRFOptionIn, Pump1In, Pump2In, IncubIn,
      ExtIncubator, ApertureType ('none'/'96/384'/'1536'), BoardNum, EPROMNum.

    Hardware specs (from BMG Operating Manual 0430B0006B):
      LVF Monochromator range: 320-840nm (bandwidth 8-100nm, 0.1nm steps)
      LVDM (dichroic mirror): 340-760nm
      Physical filters: 240-900nm (4 Ex + 4 Em + 3 dichroic = 11 positions, 5 slides)
      UV/Vis spectrometer: 220-1000nm (bandwidth 3nm, 1-10nm steps)
      Optional hardware: 1-2 reagent pumps, stacker (50 plates), ACU (O2/CO2),
        AlphaScreen laser (680nm), Dual-PMT, extended incubator (10-65°C).

    Returns:
      Dict with parsed EEPROM fields.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.EEPROM,
      payload=b"\x00\x00\x00\x00\x00",
    )
    if logger.isEnabledFor(logging.INFO):
      logger.info(
        "EEPROM: %d bytes, head=%s",
        len(payload),
        payload[:16].hex() if len(payload) >= 16 else payload.hex(),
      )

    result: Dict = {
      "machine_type_code": 0,
      "model_name": "",
      "has_absorbance": False,
      "has_fluorescence": False,
      "has_luminescence": False,
      "has_alpha_technology": False,
      "excitation_monochromator_max_nm": 0,
      "emission_monochromator_max_nm": 0,
      "dichroic_filter_slots": 0,
      "excitation_filter_slots": 0,
      "emission_filter_slots": 0,
    }
    if len(payload) < 15:
      return result

    machine_type = int.from_bytes(payload[2:4], "big")
    result["machine_type_code"] = machine_type
    result["model_name"] = _MODEL_LOOKUP.get(
      machine_type, f"Unknown BMG reader (type 0x{machine_type:04x})"
    )

    result["has_absorbance"] = bool(payload[11])
    result["has_fluorescence"] = bool(payload[12])
    result["has_luminescence"] = bool(payload[13])
    result["has_alpha_technology"] = bool(payload[14])

    if len(payload) >= 35:
      result["excitation_monochromator_max_nm"] = int.from_bytes(payload[19:21], "little")
      result["emission_monochromator_max_nm"] = int.from_bytes(payload[25:27], "little")
      result["dichroic_filter_slots"] = payload[33]
      # Excitation and emission filter slides share the same slot count (4 per side,
      # 2 slides x 2), both read from byte 34. Confirmed on unit 430-2621.
      result["excitation_filter_slots"] = payload[34]
      result["emission_filter_slots"] = payload[34]

    return result

  async def request_firmware_info(self) -> Dict[str, str]:
    """Request firmware version and build date/time.

    Response payload is fixed-length: 32 bytes.

    Payload byte map:
      [0] subcommand echo
      [1] command family echo
      [2:4] machine_type (u16 BE)
      [4:6] unknown
      [6:8] version x1000 (u16 BE)
      [8:20] build date (cstring)
      [20:28] build time (cstring)
      [28:32] unknown

    Returns:
      Dict with ``firmware_version`` (str, e.g. ``"1.35"``) and
      ``firmware_build_timestamp`` (str, e.g. ``"Nov 20 2020 11:51:21"``).
      Values are empty strings if the response is too short to parse.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.FIRMWARE_INFO,
      payload=b"\x00\x00\x00\x00\x00",
    )

    result: Dict[str, str] = {"firmware_version": "", "firmware_build_timestamp": ""}
    if len(payload) < 28:
      logger.warning(
        "Firmware info payload too short (%d bytes, need 28): %s",
        len(payload),
        payload.hex(),
      )
      return result

    version_raw = int.from_bytes(payload[6:8], "big")
    result["firmware_version"] = f"{version_raw / 1000:.2f}"

    build_date = payload[8:20].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    build_time = payload[20:28].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    result["firmware_build_timestamp"] = f"{build_date} {build_time}".strip()
    return result

  async def request_available_detection_modes(self) -> List[str]:
    """Fetch EEPROM data and return the list of detection modes available on this device."""
    eeprom = await self.request_eeprom_data()
    return [
      mode
      for mode, key in [
        ("absorbance", "has_absorbance"),
        ("absorbance_spectrum", "has_absorbance"),
        ("fluorescence", "has_fluorescence"),
        ("luminescence", "has_luminescence"),
        ("alpha_technology", "has_alpha_technology"),
      ]
      if eeprom.get(key)
    ]

  # --------------------------------------------------------------------------
  # Usage counters
  # --------------------------------------------------------------------------

  async def request_usage_counters(self) -> Dict[str, int]:
    """Fetch lifetime usage counters.

    Response payload is fixed-length: 43 bytes (nine u32 BE fields at
    offsets 6-41).

    Returns:
      Dict with int values: flashes, testruns, wells, well_movements,
      active_time_s, shake_time_s, pump1_usage, pump2_usage, alpha_time.
      ``wells`` and ``well_movements`` are stored /100 in firmware and
      multiplied back here.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.USAGE_COUNTERS,
      payload=b"\x00\x00\x00\x00\x00",
    )

    def _u32(off: int) -> int:
      return int.from_bytes(payload[off : off + 4], "big")

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

  # --------------------------------------------------------------------------
  # Feature: Temperature Control
  # --------------------------------------------------------------------------
  #
  # Temperature commands use standard framing with a 3-byte payload:
  #   [0x06, temp_hi, temp_lo]
  # where temp_raw = (temp_hi << 8) | temp_lo is the target in 0.1°C units.
  #   OFF:     temp_raw = 0x0000
  #   MONITOR: temp_raw = 0x0001
  #   SET:     temp_raw = target_celsius * 10  (e.g. 30.0°C → 0x012C)
  #
  # The device does not send a dedicated temperature response; the regular
  # status response (cmd 0x80, 24-byte frame / 16-byte payload) carries
  # temperature readings at payload bytes 11-14.
  #
  # The set target temperature is fire-and-forget -- it is NOT echoed back
  # in the status response. The host must track it locally.
  #
  # Heating state tracking: the firmware does not expose a reliable
  # "heating active" flag. STATUS_QUERY (0x80) byte 15 is always 0xe0.
  # POLL (0x08 0x00) byte 15 varies in K01 pcap captures from Voyager
  # but is also always 0xe0 when sent from this backend (likely requires
  # additional Voyager init commands to enable). Therefore, heating state
  # is tracked in software via ``_target_temperature``.
  #
  # Wire format confirmed in K01 pcap (monitor -> set 30 degC -> off -> monitor -> off).

  _TEMP_OFF = b"\x00\x00"  # 0x0000: disable sensors + heating
  _TEMP_MONITOR = b"\x00\x01"  # 0x0001: sensors only, no heating

  async def _request_temperature_monitoring_on(self) -> bool:
    """Check whether temperature sensors are currently reporting.

    Returns:
      ``True`` if heating or monitoring is active (status payload bytes
      11-14 carry non-zero temperature values), ``False`` otherwise.
    """
    status = await self.request_machine_status()
    return status["temperature_bottom"] is not None

  async def request_temperature_control_on(self) -> bool:
    """Check whether the backend has an active heating setpoint.

    Tracked in software: set by ``start_temperature_control`` and cleared
    by ``stop_temperature_control`` / ``_stop_temperature_monitoring``.

    Returns:
      ``True`` if heating was started and not yet stopped, ``False`` otherwise.
    """
    return self._target_temperature is not None

  def get_target_temperature(self) -> Optional[float]:
    """Return the current heating target in °C, or ``None`` if not heating."""
    return self._target_temperature

  async def _start_temperature_monitoring(self) -> None:
    """Enable temperature readout without heating.

    Safe to call while heating is active: skips the monitor command if sensors
    are already reporting, because sending MONITOR would overwrite the active
    heating setpoint (firmware treats the temperature register as single-state).
    """
    if await self._request_temperature_monitoring_on():
      return
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      payload=self._TEMP_MONITOR,
    )

  async def start_temperature_control(self, target_celsius: float) -> None:
    """Set target temperature and enable heating.

    Args:
      target_celsius: Target in degrees C (e.g. 37.0). Increments of 0.1°C.

    Raises:
      ValueError: If target exceeds ``max_temperature``.
    """
    if target_celsius > self.configuration["max_temperature"]:
      raise ValueError(
        f"Target {target_celsius}°C exceeds max {self.configuration['max_temperature']}°C"
      )
    raw = int(round(target_celsius * 10))
    hi = (raw >> 8) & 0xFF
    lo = raw & 0xFF
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      payload=bytes([hi, lo]),
    )
    self._target_temperature = target_celsius
    # Firmware needs ~200ms to populate temperature sensors after a SET command.
    # Without this, an immediate status poll sees zeros and
    # _start_temperature_monitoring would send MONITOR, overwriting the setpoint.
    await asyncio.sleep(0.3)

  async def stop_temperature_control(self) -> None:
    """Stop heating but keep temperature sensors active.

    Downgrades from SET to MONITOR. Use ``_stop_temperature_monitoring`` to
    turn off everything (sensors + heating).
    """
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      payload=self._TEMP_MONITOR,
    )
    self._target_temperature = None
    # Firmware briefly zeros temperature readings during SET -> MONITOR transition.
    # Without this, an immediate status poll sees zeros and reports sensors as inactive.
    await asyncio.sleep(0.3)

  async def _stop_temperature_monitoring(self) -> None:
    """Disable temperature monitoring and heating."""
    logger.warning("_stop_temperature_monitoring sends OFF -- this also disables heating")
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      payload=self._TEMP_OFF,
    )
    self._target_temperature = None

  async def measure_temperature(
    self,
    sensor: Literal["bottom", "top", "mean"] = "bottom",
  ) -> float:
    """Return the current incubator temperature, activating sensors if needed.

    Calls ``_start_temperature_monitoring`` which is idempotent -- it checks
    ``_request_temperature_monitoring_on`` and only sends MONITOR when the
    sensors are not yet populated, so it will never overwrite an active
    heating setpoint from ``start_temperature_control``.

    Then polls ``request_machine_status`` until both bottom and top plate
    temperatures are reported.

    Args:
      sensor: Which heating plate to read. ``"bottom"`` (below microplate,
        tracks setpoint), ``"top"`` (above microplate, ~0.5 degC above setpoint
        to prevent condensation), or ``"mean"`` (average of both).

    Returns:
      Temperature in degC.

    Raises:
      TimeoutError: If the sensor does not populate within
        ``_PACKET_READ_TIMEOUT`` (3 s).

    Note:
      Uses ``_PACKET_READ_TIMEOUT`` (3 s) rather than ``read_timeout`` because
      sensor warm-up is bounded by hardware latency (~200 ms), not by command
      processing time.
    """
    await self._start_temperature_monitoring()
    t = time.time()
    timeout = self._PACKET_READ_TIMEOUT
    while time.time() - t < timeout:
      status = await self.request_machine_status()
      bottom = status["temperature_bottom"]
      top = status["temperature_top"]
      if bottom is not None and top is not None:
        if sensor == "bottom":
          return float(bottom)
        if sensor == "top":
          return float(top)
        return round((float(bottom) + float(top)) / 2, 1)
    raise TimeoutError(f"Temperature sensor did not populate within {timeout}s")

  # --------------------------------------------------------------------------
  # Feature: Drawer Control
  # --------------------------------------------------------------------------

  async def sense_drawer_open(self) -> bool:
    """Return True if the plate drawer is currently open."""
    return bool((await self.request_machine_status())["drawer_open"])

  async def open(self, wait: bool = True, poll_interval: float = 0.1) -> None:
    """Extend the plate drawer. Motor takes ~4.3 s.

    Args:
      wait: If True, block until the device is no longer busy.
      poll_interval: Seconds between status polls while waiting.
    """
    await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_OPEN,
      payload=b"\x00\x00\x00\x00",
      wait=wait,
      poll_interval=poll_interval,
    )

  async def close(
    self,
    plate: Optional[Plate] = None,
    *,
    wait: bool = True,
    poll_interval: float = 0.1,
  ) -> None:
    """Retract the plate drawer. Motor takes ~8 s.

    Args:
      plate: Unused (present for PlateReaderBackend interface compatibility).
      wait: If True, block until the device is no longer busy.
      poll_interval: Seconds between status polls while waiting.
    """
    await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_CLOSE,
      payload=b"\x00\x00\x00\x00",
      wait=wait,
      poll_interval=poll_interval,
    )

  # --------------------------------------------------------------------------
  # Feature: Absorbance Measurement (not yet implemented)
  # --------------------------------------------------------------------------

  async def read_absorbance(
    self, plate: Plate, wells: List[Well], wavelength: int, wavelengths: Optional[List[int]] = None
  ) -> List[Dict]:
    raise NotImplementedError("Absorbance not yet implemented for CLARIOstar Plus.")

  # --------------------------------------------------------------------------
  # Feature: Fluorescence Measurement (not yet implemented)
  # --------------------------------------------------------------------------

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
  ) -> List[Dict]:
    raise NotImplementedError("Fluorescence not yet implemented for CLARIOstar Plus.")

  # --------------------------------------------------------------------------
  # Feature: Luminescence Measurement (not yet implemented)
  # --------------------------------------------------------------------------

  async def read_luminescence(
    self, plate: Plate, wells: List[Well], focal_height: float
  ) -> List[Dict]:
    raise NotImplementedError("Luminescence not yet implemented for CLARIOstar Plus.")
