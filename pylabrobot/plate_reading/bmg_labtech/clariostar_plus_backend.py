"""BMG CLARIOstar Plus plate reader backend.

Lifecycle: initialize, open/close drawer, status polling, EEPROM/firmware
identification, machine type auto-detection.
Measurement: discrete absorbance (1-8 wavelengths), fluorescence (stub),
luminescence (stub).
"""

import asyncio
import enum
import logging
import math
import time
import warnings
from typing import Dict, List, Literal, Optional, Tuple

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
#
# Payload hierarchy:
#
#   Command:
#     frame  →  payload  →  command_family + [command] + parameters
#                                                           ↓
#                                                     fields (plate, wells,
#                                                     wavelengths, flashes, ...)
#
#   Response:
#     frame  →  payload  →  response_type + status_flags + parameters
#                                                              ↓
#                                                        fields (schema, values_expected,
#                                                        values_written, wavelengths, wells,
#                                                        temperature, data groups, cal pairs)
#
#   response_type (byte 0): identifies the kind of response.
#     0x01 = status/state report (POLL, STATUS, TRAY, TEMP_CTRL)
#     0x03 = RUN acknowledgment
#     0x09 = hardware info (HW_STATUS)
#     For REQUEST family: usually echoes the subcommand byte (0x02, 0x07, 0x08, …)
#       Exception: FIRMWARE_INFO (0x09) responds with 0x0a (subcommand + 1).
#
#   status_flags (bytes 0-4): device state bits.
#     12 flags across 5 bytes — see _STATUS_FLAGS and request_machine_status().

# ---------------------------------------------------------------------------
# Confirmed firmware versions
# ---------------------------------------------------------------------------
# Firmware versions verified against pcap ground truth, mapped to build year.
# Used during setup() to warn when the connected device runs untested firmware.
# Add entries here as new versions are verified.
# If year granularity proves insufficient, switch values to (year, month) tuples.

CONFIRMED_FIRMWARE_VERSIONS: Dict[str, int] = {
  "1.35": 2020,  # pre-dates Enhanced Dynamic Range (EDR); no auto-gain support
}

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


# 0x0024: verified on CLARIOstar Plus hardware.
# 0x0026: from vibed code, unverified on real hardware.
_MODEL_LOOKUP: Dict[int, str] = {
  0x0024: "CLARIOstar Plus",
  0x0026: "CLARIOstar Plus",
}

# Constant blocks verified identical across all 38 absorbance pcap captures.
_SEPARATOR = b"\x27\x0f\x27\x0f"
_TRAILER = b"\x02\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01"
# The 13-byte reference block is actually two parts:
#   _PRE_REFERENCE (4 bytes): context-dependent. 0x00000064 for discrete/filter mode;
#     repurposed as end_wl(2 BE) + 0x00 + step(1) in spectroscopy mode (n_wl=0).
#   _CORE_REFERENCE (9 bytes): constant across all 38 pcap captures.
_PRE_REFERENCE = b"\x00\x00\x00\x64"
_CORE_REFERENCE = b"\x23\x28\x26\xca\x00\x00\x00\x64\x00"
_REFERENCE_BLOCK = _PRE_REFERENCE + _CORE_REFERENCE

# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class CLARIOstarPlusBackend(PlateReaderBackend):
  """BMG CLARIOstar Plus plate reader backend.

  Lifecycle: initialize, open/close drawer, status polling, device identification.
  Measurement: absorbance (implemented), fluorescence and luminescence (stubs).
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
    CommandFamily.RUN,
  }

  # -- Optic byte flags (bit field, OR'd together) -------------------------

  class Modality(enum.IntEnum):
    """Measurement modality (base value for the optic config byte)."""

    FLUORESCENCE = 0x00
    ABSORBANCE = 0x02
    # LUMINESCENCE = 0x??  # TODO: determine from captures

  class WellScanMode(enum.IntEnum):
    """Well scan mode flags OR'd into the optic config byte."""

    POINT = 0x00
    SPIRAL = 0x04
    ORBITAL = 0x30

  class OpticPosition(enum.IntEnum):
    """Optic position flag OR'd into the optic config byte (fluorescence only)."""

    TOP = 0x00
    BOTTOM = 0x40

  # -- Status flags (CLARIOstar-specific bit positions) ---------------------

  # (flag_name, byte_index_in_5-byte_status, bitmask)
  # Sorted by byte index, then by bit position descending.
  _STATUS_FLAGS = [
    ("standby", 0, 1 << 1),
    ("busy", 1, 1 << 5),
    ("running", 1, 1 << 4),
    ("valid", 1, 1 << 0),
    ("unread_data", 2, 1 << 0),
    ("lid_open", 3, 1 << 6),
    ("initialized", 3, 1 << 5),
    ("reading_wells", 3, 1 << 3),
    ("z_probed", 3, 1 << 2),
    ("plate_detected", 3, 1 << 1),
    ("drawer_open", 3, 1 << 0),
    ("filter_cover_open", 4, 1 << 6),
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
    read_timeout: float = 120.0,
    max_temperature: float = 45.0,
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
    if read_timeout <= 0:
      raise ValueError(f"read_timeout must be > 0, got {read_timeout}.")
    if not 0 < max_temperature <= 65:
      raise ValueError(f"max_temperature must be between 0 and 65 °C, got {max_temperature}.")

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
    # TODO: keep searching for a way to retrieve target temp from device

  # --------------------------------------------------------------------------
  # Life cycle
  # --------------------------------------------------------------------------

  async def setup(self) -> None:
    """Configure FTDI serial link (125 kBaud, 8N1), initialize the reader, and read EEPROM/firmware."""
    await self.io.setup()
    await self.io.set_baudrate(125000)
    await self.io.set_line_property(8, 0, 0)  # 8N1
    await self.io.set_latency_timer(2)

    # Drain any residual bytes left in the FTDI RX buffer (e.g. a trailing 0x0D
    # from a previous session or power cycle).  Without this, the first command's
    # _read_frame picks up stale data and _validate_frame fails.
    await self.io.usb_purge_rx_buffer()

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

    fw_ver = self.configuration["firmware_version"]
    if fw_ver and fw_ver not in CONFIRMED_FIRMWARE_VERSIONS:
      warnings.warn(
        f"Firmware version {fw_ver!r} has not been tested with this driver. "
        f"Confirmed versions: {', '.join(sorted(CONFIRMED_FIRMWARE_VERSIONS))}. "
        f"Proceed with caution — please report issues.",
        stacklevel=2,
      )

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

  async def initialize(self) -> None:
    """Send the hardware init sequence and poll until ready.

    After a power cycle the FTDI RX buffer may contain residual bytes or the
    firmware may not yet be ready to respond.  Retries up to 5 times with a
    brief delay, purging the RX buffer between attempts.
    """
    last_err: Optional[FrameError] = None
    for attempt in range(5):
      try:
        await self.send_command(
          command_family=self.CommandFamily.INITIALIZE,
          command=self.Command.INIT,
          parameters=b"\x00\x10\x02\x00",
          wait=True,
        )
        return
      except FrameError as e:
        last_err = e
        logger.warning("initialize: bad frame on attempt %d/5 (%s), retrying", attempt + 1, e)
        await self.io.usb_purge_rx_buffer()
        await asyncio.sleep(0.5)
    assert last_err is not None
    raise last_err

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

  async def send_command(
    self,
    command_family: "CLARIOstarPlusBackend.CommandFamily",
    command: Optional[int] = None,
    *,
    parameters: bytes = b"",
    read_timeout: Optional[float] = None,
    wait: bool = False,
    poll_interval: float = 0.0,
  ) -> bytes:
    """Build a frame, send it, and return the validated response payload.

    Steps:
      1. Validate command_family / command against _VALID_COMMANDS tables
      2. Assemble payload bytes: ``[group, cmd] + parameters``
      3. _wrap_payload  → full frame (STX + size + 0x0C + payload + checksum + CR)
      4. _write_frame   → io.write
      5. _read_frame    → io.read (fast-path: short read ending in 0x0D + size check)
      6. _validate_frame → verify STX, CR, 0x0C, size field, 24-bit checksum
      7. _extract_payload → strip framing, return inner bytes
      8. If wait=True   → _wait_until_machine_ready (status loop until not busy)

    Args:
      command_family: Command group byte (payload byte 0).
      command: Command byte (payload byte 1). Required for all groups
        except STATUS, HW_STATUS, TEMPERATURE_CONTROLLER, and RUN.
      parameters: Command-specific fields after command_family and command.
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
      payload = bytes([command_family]) + parameters
    else:
      if command is None:
        raise ValueError(f"{CF(command_family).name} requires a command")
      valid = self._VALID_COMMANDS.get(command_family, set())
      if command not in valid:
        raise ValueError(f"command 0x{command:02x} is not valid for {CF(command_family).name}")
      payload = bytes([command_family, command]) + parameters

    frame = _wrap_payload(payload)
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

  # Pre-cached status frame: STATUS_QUERY (0x80).
  _STATUS_FRAME = _wrap_payload(b"\x80")

  async def request_machine_status(self, retries: int = 5) -> Dict:
    """Query device status and return parsed flags.

    Bypasses ``send_command`` to avoid infinite recursion with
    ``_wait_until_machine_ready``. Retries on transient ``FrameError``
    up to *retries* times before raising.

    Args:
      retries: Number of attempts before raising on repeated frame errors.

    Returns:
      Dict keyed by flag name. Only HIGH confidence fields are parsed.
      Verified across 7,927 STATUS responses in 40 pcap captures.

      Confidence: HIGH = parsed into dict, MEDIUM = observed pattern but
      not yet parsed, UNKNOWN = no clear interpretation.

      16-byte response payload map::

        Byte 0  — response type (always 0x01)
          bit 1  HIGH    ``standby``        power-saving / pre-init state.
                                            Never observed True; may need a
                                            specific power mode to trigger.
          bits 7-2,0                        always 0. Reserved.

        Byte 1  — activity flags
          bit 5  HIGH    ``busy``           device is occupied (measuring,
                                            initializing, moving drawer, or
                                            any other command). Primary flag
                                            for is_ready(), polling loops.
          bit 4  HIGH    ``running``        fleeting transitional state at
                                            measurement completion (3 of
                                            7,927 responses). Not actionable;
                                            busy is the reliable indicator.
          bit 0  HIGH    ``valid``          status response validity. Set in
                                            all normal operation responses.
          bit 2          UNKNOWN            always set (0x05 base). Likely
                                            protocol/device-type identifier.
          bits 7,6,3,1                      always 0. Reserved.

          busy and running are mutually exclusive in all captures.

        Byte 2  — data flags
          bit 2  MEDIUM                     set ~87%, clear only during early
                                            boot. Possibly protocol-ready.
          bit 1  MEDIUM                     anti-correlated with busy. Set
                                            when idle, clear when busy or
                                            during early boot.
          bit 0  HIGH    ``unread_data``    measurement results available but
                                            not yet fetched.

        Byte 3  — hardware and measurement state
          bit 6  HIGH    ``lid_open``       instrument lid (top cover) is
                                            open. Distinct from drawer.
          bit 5  HIGH    ``initialized``    device has completed init (motor
                                            homing, self-test). Always True
                                            after setup() returns.
          bit 4                             always 0. Reserved.
          bit 3  HIGH    ``reading_wells``  optic head is actively scanning
                                            wells. Sub-state of busy: when
                                            reading_wells is True, busy is
                                            always True too, but busy can be
                                            True without reading_wells (e.g.
                                            during drawer close after RUN).
          bit 2  HIGH    ``z_probed``       z-stage mechanical probe has made
                                            contact with plate after loading.
          bit 1  HIGH    ``plate_detected`` microplate in drawer (optical
                                            sensor). Used by
                                            sense_plate_present().
          bit 0  HIGH    ``drawer_open``    drawer is extended. Used by
                                            sense_drawer_open() and setup().

        Byte 4  — filter / optical path
          bit 6  HIGH    ``filter_cover_open`` filter cover underneath lid is
                                            open.

        Bytes 5–10            MEDIUM        operation sub-state (not parsed).
                                            Bytes 5,8,9 always 0x00.
                                            Bytes 6,7,10 form a triple:
                                              00 00 .. 00 = idle
                                              03 00 .. 00 = mechanical op
                                              04 01 .. 04 = measurement setup
                                              04 01 .. 03 = well reading

        Bytes 11–12  HIGH    ``temperature_bottom``
                                            bottom heater °C (u16 BE ÷10),
                                            or None if monitoring inactive.
        Bytes 13–14  HIGH    ``temperature_top``
                                            top heater °C (u16 BE ÷10),
                                            or None if monitoring inactive.

          Both None until measure_temperature() or
          start_temperature_control() activates sensors.
          Resolution: 0.1 °C.

        Byte 15               MEDIUM        temperature/heater sub-state (not
                                            parsed). 0xC0 = not at target or
                                            off, 0xE0 = ramping, 0x40 =
                                            approaching setpoint, 0x00 = at
                                            setpoint. Characterized from one
                                            temperature-control capture only.
    """
    if retries < 1:
      raise ValueError(f"retries must be >= 1, got {retries}.")
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
      if len(payload) >= 16:
        raw_bottom = int.from_bytes(payload[11:13], "big")
        raw_top = int.from_bytes(payload[13:15], "big")
        status["temperature_bottom"] = raw_bottom / 10.0 if raw_bottom else None
        status["temperature_top"] = raw_top / 10.0 if raw_top else None
      else:
        status["temperature_bottom"] = None
        status["temperature_top"] = None
      return status
    assert last_err is not None  # loop only exits here via continue, which sets last_err
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

    Response is 263 bytes (observed on CLARIOstar Plus, type 0x0024).

    EEPROM Byte Map -- Full 263-Byte Analysis
    ==========================================
    Source: real capture from CLARIOstar Plus.
    Reference hex (first 48 bytes):
      07 05 00 24 00 00 00 01  00 00 0a 01 01 01 01 00
      00 01 00 ee 02 00 00 0f  00 e2 03 00 00 00 00 00
      00 03 04 00 00 01 00 00  01 02 00 00 00 00 00 00

    Section 1 -- Header & Command Echo (bytes 0-3) [CONFIRMED]
      [0]     response_type (0x07 = echoes EEPROM subcommand)
      [1]     status_flags (0x05 = not busy, standby)
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
      [21:23] 0x0000
      [23]    0x0f (15) -- unknown; possibly default bandwidth nm or step size
      [24]    0x00
      [25:27] emission monochromator max nm (u16 LE). 0x03e2 = 994 nm.
              (Note: LVF spec range is 320-840nm for fluorescence/luminescence;
              994 is the physical slide limit. Absorbance uses a separate UV/Vis
              spectrometer with 220-1000nm range — not encoded here.)
      [27:32] 0x00 x 5
      [33]    dichroic filter slots (u8) = 3 (manual: positions A,B,C on 1 slide)
      [34]    excitation/emission filter slots (u8) = 4 (manual: 4 per side, 2 slides x 2)
              Note: min LVF monochromator nm is NOT in EEPROM. 320nm is a hardware
              constant of the LVF design (fluorescence/luminescence only).

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
      [87]=0xdc(220) -- tempting as UV/Vis absorbance spectrometer min nm, but unconfirmed
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

    Section 10 -- Serial + Calibration Block B (bytes 153-262)
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

    Hardware specs (from BMG Operating Manual 0430B0006B, p.4):
      Two independent optical systems:
        UV/Vis Absorbance Spectrometer: 220-1000nm, bandwidth 3nm.
          → used for absorbance (discrete [1-8 wavelengths] & spectral [220-1000nm]).
        Dual LVF Monochromator: 320-840nm, bandwidth 8-100nm, 0.1nm steps
          → used for fluorescence & luminescence (top/bottom, incl. spectral scanning)
      LVDM (dichroic mirror): 340-760nm
      Physical filters: 240-900nm (4 Ex + 4 Em + 3 dichroic = 11 positions, 5 slides)
      Optional hardware: 1-2 reagent pumps, stacker (50 plates), ACU (O2/CO2),
        AlphaScreen laser (680nm), Dual-PMT, extended incubator (10-65°C).

    Returns:
      Dict with parsed EEPROM fields.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.EEPROM,
      parameters=b"\x00\x00\x00\x00\x00",
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
      # 2 slides x 2), both read from byte 34. Confirmed on hardware.
      result["excitation_filter_slots"] = payload[34]
      result["emission_filter_slots"] = payload[34]

    return result

  async def request_firmware_info(self) -> Dict[str, str]:
    """Request firmware version and build date/time.

    Response payload is fixed-length: 32 bytes.

    Payload byte map:
      [0] response_type (echoes subcommand for REQUEST family)
      [1] status_flags
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
      parameters=b"\x00\x00\x00\x00\x00",
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
      parameters=b"\x00\x00\x00\x00\x00",
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
  # "heating active" flag. Byte 15 of the status response takes multiple
  # values (0xC0, 0xE0, 0x40, 0x00) but the pattern does not correlate
  # clearly with heating state. Therefore, heating state is tracked in
  # software via ``_target_temperature``.
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

  def get_target_temperature(self) -> Optional[float]:
    """Return the current heating target in °C, or ``None`` if not heating."""
    return self._target_temperature

  async def _start_temperature_monitoring(self) -> None:
    """Send the MONITOR command to enable temperature readout without heating.

    Warning:
      Sending MONITOR while heating is active will overwrite the active
      setpoint (firmware treats the temperature register as single-state).
      Callers must check ``_request_temperature_monitoring_on()`` first
      and skip this call if sensors are already reporting.
    """
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      parameters=self._TEMP_MONITOR,
    )

  async def start_temperature_control(self, temperature: float) -> None:
    """Set target temperature and enable heating.

    Args:
      temperature: Target in degrees C (e.g. 37.0). Increments of 0.1°C.

    Raises:
      ValueError: If target exceeds ``max_temperature``.
    """

    max_temp = self.configuration["max_temperature"]
    if not 0 <= temperature <= max_temp:
      raise ValueError(f"Temperature must be between 0 and {max_temp} °C, got {temperature}.")

    current = await self.measure_temperature(sensor="bottom")
    heater_overshoot_tolerance = 0.5
    if temperature < current - heater_overshoot_tolerance:
      warnings.warn(
        f"Target {temperature} °C is below the current bottom plate temperature "
        f"({current} °C). The CLARIOstar has no active cooling and will not reach "
        f"this target unless the ambient temperature drops.",
        stacklevel=2,
      )

    raw = int(round(temperature * 10))
    hi = (raw >> 8) & 0xFF
    lo = raw & 0xFF
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      parameters=bytes([hi, lo]),
    )
    self._target_temperature = temperature
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
      parameters=self._TEMP_MONITOR,
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
      parameters=self._TEMP_OFF,
    )
    self._target_temperature = None

  async def measure_temperature(
    self,
    sensor: Literal["bottom", "top", "mean"] = "bottom",
  ) -> float:
    """Return the current incubator temperature, activating sensors if needed.

    Checks ``_request_temperature_monitoring_on`` first and only calls
    ``_start_temperature_monitoring`` when sensors are not yet populated,
    so it will never overwrite an active heating setpoint from
    ``start_temperature_control``.

    Then polls ``request_machine_status`` until both bottom and top plate
    temperatures are reported.

    Args:
      sensor: Which heating plate to read. ``"bottom"`` (below microplate,
        tracks setpoint), ``"top"`` (above microplate, ~0.5 degC above setpoint
        to prevent condensation), or ``"mean"`` (average of both).

    Returns:
      Temperature in degree C.

    Raises:
      TimeoutError: If the sensor does not populate within
        ``_PACKET_READ_TIMEOUT`` (3 s).

    Note:
      Uses ``_PACKET_READ_TIMEOUT`` (3 s) rather than ``read_timeout`` because
      sensor warm-up is bounded by hardware latency (~200 ms), not by command
      processing time.
    """

    valid_sensors = ("bottom", "top", "mean")
    if sensor not in valid_sensors:
      raise ValueError(f"sensor must be one of {valid_sensors}, got {sensor!r}.")

    if not await self._request_temperature_monitoring_on():
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

  async def open(self) -> None:
    """Extend the plate drawer. Motor takes ~4.3 s."""
    await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_OPEN,
      parameters=b"\x00\x00\x00\x00",
      wait=True,
    )

  async def close(self, plate: Optional[Plate] = None) -> None:
    """Retract the plate drawer. Motor takes ~8 s.

    Args:
      plate: Unused (present for PlateReaderBackend interface compatibility).
    """
    await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_CLOSE,
      parameters=b"\x00\x00\x00\x00",
      wait=True,
    )

  # --------------------------------------------------------------------------
  # Common Reading Preparations
  # --------------------------------------------------------------------------

  def _plate_field(self, plate: Plate, wells: List[Well]) -> bytes:
    """Encode plate geometry + well mask as 63 bytes for the MEASUREMENT_RUN payload.

    The leading CommandFamily.RUN (0x04) byte is added by send_command, so this
    method returns only the plate data that follows it.

    Byte layout (all multi-byte values big-endian u16, mm×100):
      [0:2]     plate_length (size_x)
      [2:4]     plate_width (size_y)
      [4:6]     well_A1_center_x
      [6:8]     well_A1_center_y  (Y inverted: plate_width - absolute_y)
      [8:10]    last_well_center_x (plate_length - A1_x)
      [10:12]   last_well_center_y (plate_width - A1_y)
      [12]      num_cols
      [13]      num_rows
      [14]      0x00  (extra byte, constant across all 38 captures)
      [15:63]   48-byte well mask (384 bits, row-major, MSB first)

    NOTE: The 48-byte mask covers up to 384 wells. The operating manual (0430B0006B,
    p.4, dated 2019-04-01) lists 1536-well support — predating our firmware v1.35
    (Nov 2020). 1536 wells would require 192 bytes (1536 bits), so the command format
    likely differs for 1536 plates (larger payload, or byte [14] signals an extended
    mask, or per-well selection is unavailable). All 38 pcap captures used 96-well
    plates. TODO: capture a 1536-well protocol via OEM software to determine encoding.
    """
    all_wells = plate.get_all_items()
    if not all_wells:
      raise ValueError("Plate has no wells")

    num_cols = plate.num_items_x
    num_rows = plate.num_items_y
    plate_length = plate.get_size_x()
    plate_width = plate.get_size_y()

    # A1 is at index 0 in column-major order
    well_0 = all_wells[0]
    loc = well_0.location
    assert loc is not None, f"Well {well_0.name} has no location"
    a1_x = loc.x + well_0.center().x
    a1_y = plate_width - (loc.y + well_0.center().y)

    last_well_x = plate_length - a1_x
    last_well_y = plate_width - a1_y

    buf = bytearray(63)
    buf[0:2] = int(round(plate_length * 100)).to_bytes(2, "big")
    buf[2:4] = int(round(plate_width * 100)).to_bytes(2, "big")
    buf[4:6] = int(round(a1_x * 100)).to_bytes(2, "big")
    buf[6:8] = int(round(a1_y * 100)).to_bytes(2, "big")
    buf[8:10] = int(round(last_well_x * 100)).to_bytes(2, "big")
    buf[10:12] = int(round(last_well_y * 100)).to_bytes(2, "big")
    buf[12] = num_cols
    buf[13] = num_rows
    buf[14] = 0x00

    # Well mask: 48 bytes (384 bits). Bit index = row * num_cols + col.
    # get_all_items returns column-major: A1,B1,...,H1,A2,...,H12
    # so index i maps to row=i%num_rows, col=i//num_rows
    well_set = set(id(w) for w in wells)
    mask = bytearray(48)
    for i, w in enumerate(all_wells):
      if id(w) in well_set:
        row = i % num_rows
        col = i // num_rows
        idx = row * num_cols + col
        mask[idx // 8] |= 1 << (7 - (idx % 8))
    buf[15:63] = mask

    return bytes(buf)

  @staticmethod
  def _scan_direction_byte(
    unidirectional: bool = True,
    vertical: bool = True,
    corner: str = "TL",
  ) -> int:
    """Encode the scan direction byte.

    Bit layout: | uni(7) | corner(6:5) | 0(4) | vert(3) | 0(2) | always_set(1) | 0(0) |

    Ground truth values verified across all 38 captures:
      0x8A: uni=1, TL, vert=1    0x0A: uni=0, TL, vert=1
      0x2A: TR                   0x4A: BL
      0x6A: BR                   0x02: horizontal (vert=0)
    """
    corner_map = {"TL": 0, "TR": 1, "BL": 2, "BR": 3}
    b = 0
    if unidirectional:
      b |= 1 << 7
    b |= corner_map[corner] << 5
    if vertical:
      b |= 1 << 3
    b |= 1 << 1  # always set
    return b

  @staticmethod
  def _pre_separator_block(
    modality: "CLARIOstarPlusBackend.Modality",
    well_scan_mode: "CLARIOstarPlusBackend.WellScanMode",
    shake_mode: Optional[str] = None,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    optic_position: Optional["CLARIOstarPlusBackend.OpticPosition"] = None,
  ) -> bytes:
    """Build the 31-byte block between scan direction byte and separator.

    Args:
      modality: Measurement modality (ABSORBANCE, FLUORESCENCE).
      well_scan_mode: Well scan mode (POINT, ORBITAL, SPIRAL).
      shake_mode: None, "orbital", "linear", or "double_orbital".
      shake_speed_rpm: Shake speed in RPM (100-800, multiples of 100).
      shake_duration_s: Shake duration in seconds.
      optic_position: Optic position (TOP, BOTTOM). Fluorescence only.
    """
    optic_config = int(modality) | int(well_scan_mode)
    if optic_position is not None:
      optic_config |= int(optic_position)

    buf = bytearray(31)
    buf[0] = optic_config

    if shake_mode is not None and shake_duration_s > 0:
      buf[12] = 0x02  # mixer_action
      shake_pattern_map = {"orbital": 0, "linear": 1, "double_orbital": 2}
      buf[17] = shake_pattern_map[shake_mode]
      buf[18] = (shake_speed_rpm // 100) - 1  # speed index
      buf[20:22] = shake_duration_s.to_bytes(2, "little")

    return bytes(buf)

  @staticmethod
  def _well_scan_field(
    well_scan_mode: "CLARIOstarPlusBackend.WellScanMode",
    modality: "CLARIOstarPlusBackend.Modality",
    scan_diameter_mm: int,
    well_diameter_mm_100: int,
  ) -> bytes:
    """Build 0 or 5 bytes for non-point well scan modes.

    For point scans, returns empty bytes.
    For orbital/spiral: [modality, scan_width_mm, well_diam_hi, well_diam_lo, 0x00]

    NOTE: buf[0] uses int(modality) which is correct for absorbance (0x02) but
    DESIGN.md says fluorescence well scan code should be 0x03, not 0x00
    (Modality.FLUORESCENCE). Fix when implementing fluorescence.
    """
    WSM = CLARIOstarPlusBackend.WellScanMode
    if well_scan_mode == WSM.POINT:
      return b""
    buf = bytearray(5)
    buf[0] = int(modality)
    buf[1] = scan_diameter_mm
    buf[2:4] = well_diameter_mm_100.to_bytes(2, "big")
    buf[4] = 0x00
    return bytes(buf)

  @staticmethod
  def _map_readings_to_plate_grid(
    readings: List[float],
    wells: List[Well],
    plate: Plate,
  ) -> List[List[Optional[float]]]:
    """Map flat readings (row-major firmware order) to a 2D grid [rows][cols].

    For all wells (96 on a 96-well plate): simple reshape.
    For partial wells: sort by (row, col), place each reading at its grid position.
    Unread wells are None.
    """
    num_cols = plate.num_items_x
    num_rows = plate.num_items_y
    all_wells = plate.get_all_items()

    grid: List[List[Optional[float]]] = [[None] * num_cols for _ in range(num_rows)]

    # Build a lookup from well id to (row, col) using column-major indexing
    well_index_map = {}
    for i, w in enumerate(all_wells):
      row = i % num_rows
      col = i // num_rows
      well_index_map[id(w)] = (row, col)

    if len(wells) == len(all_wells):
      # All wells: firmware sends row-major (A1, A2, ..., A12, B1, ...)
      for i, val in enumerate(readings):
        row = i // num_cols
        col = i % num_cols
        grid[row][col] = val
    else:
      # Partial: sort wells by row-major index to match firmware order
      well_positions = []
      for w in wells:
        rc = well_index_map[id(w)]
        well_positions.append(rc)
      well_positions.sort(key=lambda rc: rc[0] * num_cols + rc[1])
      for i, (row, col) in enumerate(well_positions):
        if i < len(readings):
          grid[row][col] = readings[i]

    return grid

  async def _request_measurement_data(self, progressive: bool = False) -> bytes:
    """Retrieve measurement data from the device buffer (internal).

    Sends REQUEST/DATA (0x05 0x02) and returns the raw response payload.
    Used internally by all measurement types (absorbance, fluorescence,
    luminescence). Users should call the typed collection methods instead
    (e.g. ``request_absorbance_results``).

    Two parameter variants exist (observed in Voyager pcap captures):
      - **Standard** (``00 00 00 00 00``): used after the measurement has
        finished (``busy`` flag cleared). Returns the final complete dataset.
      - **Progressive** (``ff ff ff ff 00``): used *during* the measurement
        while the device is still busy. The response contains partially-filled
        data with ``values_written < values_expected`` in the header at
        response payload offsets [7:9] and [9:11] (u16 BE).

    Args:
      progressive: If True, use the progressive parameter variant. Default False
        (standard variant).

    Returns:
      Raw response payload bytes. Parse with ``_parse_absorbance_response``
      (or future fluorescence/luminescence parsers).
    """
    params = b"\xff\xff\xff\xff\x00" if progressive else b"\x00\x00\x00\x00\x00"
    return await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.DATA,
      parameters=params,
    )

  @staticmethod
  def _measurement_progress(payload: bytes) -> Tuple[int, int]:
    """Extract (values_written, values_expected) from a DATA response header.

    During a measurement, the firmware fills u32 entries (raw 4-byte detector
    counts and calibration integers) into its data buffer one at a time.
    This method reads two counters from the response header:

    - ``values_expected`` (payload bytes [7:9], u16 BE): total number of u32
      entries the device will produce when the measurement is complete.
    - ``values_written`` (payload bytes [9:11], u16 BE): how many u32 entries
      have been written so far.

    The measurement is complete when ``values_written >= values_expected``.

    ``values_expected`` counts *every* u32 in the response — 4 data groups
    (sample, chrom2, chrom3, reference) × wells each, plus 4 calibration
    pairs × 2 u32s each:

    - **Single wavelength:**
      ``values_expected = wells × 4 + 8``
    - **Multi-wavelength (W > 1):**
      ``values_expected = wells × 4 + 8 + (W − 1) × (wells + 2)``
      (each extra wavelength adds one group of ``wells`` values + 1 cal pair)

    Examples from real pcap captures (values_expected / values_written):
      - A05 (1 well, 1 WL):  expected = 1×4 + 8 = 12;   written = 0→12
      - A03 (8 wells, 1 WL): expected = 8×4 + 8 = 40;   written = 0→40
      - A01 (96 wells, 1 WL): expected = 96×4 + 8 = 392; written = 0→392
      - D02 (96 wells, 2 WL): expected = 96×4 + 8 + 1×(96+2) = 490
      - D03 (96 wells, 3 WL): expected = 96×4 + 8 + 2×(96+2) = 588

    Returns:
      (values_written, values_expected) tuple.

    Raises:
      FrameError: If the payload is too short to contain the header fields.
    """
    if len(payload) < 11:
      raise FrameError(f"DATA response too short for progress header: {len(payload)} bytes")
    values_expected = int.from_bytes(payload[7:9], "big")
    values_written = int.from_bytes(payload[9:11], "big")
    return values_written, values_expected

  # --------------------------------------------------------------------------
  # Feature: Absorbance Measurement
  # --------------------------------------------------------------------------

  def _build_absorbance_payload(
    self,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    flashes: int = 5,
    well_scan: str = "point",
    scan_diameter_mm: int = 3,
    unidirectional: bool = True,
    vertical: bool = True,
    corner: str = "TL",
    shake_mode: Optional[str] = None,
    shake_speed_rpm: int = 0,
    shake_duration_s: int = 0,
    settling_time_s: float = 0.0,
    pause_time: Optional[int] = None,
  ) -> bytes:
    """Build the payload for a MEASUREMENT_RUN absorbance command.

    These parameters are passed to send_command(CommandFamily.RUN, parameters=...),
    which prepends the 0x04 command family byte to produce the full frame payload.

    Args:
      settling_time_s: Wait time after shaking (0.0-1.0 s). Encoded as the
        pause_time byte via ``int(settling_time_s * 50)``. Verified for 0.1 s → 5
        and 0.5 s → 25 (pcap F01, G01). TODO: confirm with M-series captures.
      pause_time: Override the pause_time byte directly (for pcap ground truth
        tests). When None (default), computed from settling_time_s.

    Returns:
      Payload bytes (135 for point/1wl, 140 for orbital/1wl, +2 per extra wl).
    """
    # 1. Plate geometry + well mask (63 bytes)
    plate_bytes = self._plate_field(plate, wells)

    # 2. Scan direction (1 byte)
    scan_byte = bytes([self._scan_direction_byte(unidirectional, vertical, corner)])

    # 3. Pre-separator block (31 bytes)
    scan_mode_map = {
      "point": self.WellScanMode.POINT,
      "orbital": self.WellScanMode.ORBITAL,
      "spiral": self.WellScanMode.SPIRAL,
    }
    wsm = scan_mode_map[well_scan]
    pre_sep = self._pre_separator_block(
      modality=self.Modality.ABSORBANCE,
      well_scan_mode=wsm,
      shake_mode=shake_mode,
      shake_speed_rpm=shake_speed_rpm,
      shake_duration_s=shake_duration_s,
    )

    # 4. Separator (4 bytes)
    sep = _SEPARATOR

    # 5. Well scan field (0 or 5 bytes)
    well_0 = plate.get_all_items()[0]
    well_diam_100 = int(round(min(well_0.get_size_x(), well_0.get_size_y()) * 100))
    wsf = self._well_scan_field(wsm, self.Modality.ABSORBANCE, scan_diameter_mm, well_diam_100)

    # 6. Pause time (1 byte)
    # OEM encodes settling delay as pause_time = int(settling_s * 50).
    # Verified: 0.1s→0x05 (F01), 0.5s→0x19 (G01). G02 (1.0s) anomalous.
    # TODO: confirm formula with M-series captures.
    if pause_time is None:
      pause_time = max(int(settling_time_s * 50), 1) if settling_time_s > 0 else 0x05
    pause = bytes([pause_time])

    # 7. Num wavelengths (1 byte) + wavelength data (2 bytes × N, nm×10 u16 BE)
    num_wl = bytes([len(wavelengths)])
    wl_data = b""
    for wl in wavelengths:
      wl_data += (wl * 10).to_bytes(2, "big")

    # 8. Reference block (13 bytes)
    ref = _REFERENCE_BLOCK

    # 9. Settling fields (1 + 2 bytes): always 0x00 in all OEM captures.
    # Actual settling is encoded via pause_time (step 6 above).
    settling_flag = b"\x00"
    settling_time = b"\x00\x00"

    # 10. Trailer (11 bytes)
    trailer = _TRAILER

    # 11. Flashes (2 bytes u16 BE)
    flash_bytes = flashes.to_bytes(2, "big")

    # 12. Final bytes
    final = b"\x00\x01\x00"

    payload = (
      plate_bytes
      + scan_byte
      + pre_sep
      + sep
      + wsf
      + pause
      + num_wl
      + wl_data
      + ref
      + settling_flag
      + settling_time
      + trailer
      + flash_bytes
      + final
    )

    return payload

  # -- Absorbance response parsing (decomposed into 4 steps) ----------------

  @staticmethod
  def _parse_response_header(
    payload: bytes,
  ) -> Tuple[int, int, int, Optional[float]]:
    """Extract metadata from the 36-byte absorbance response header.

    Returns:
      (schema, num_wl_resp, num_wells, temperature).
      temperature is None when the raw sensor value is ≤ 1 (inactive).
    """
    if len(payload) < 36:
      raise FrameError(f"Absorbance response too short: {len(payload)} bytes")

    schema = payload[6]
    num_wl_resp = int.from_bytes(payload[18:20], "big")
    num_wells = int.from_bytes(payload[20:22], "big")

    temp: Optional[float] = None
    if schema == 0x29:
      raw_temp = int.from_bytes(payload[23:25], "big")
      if raw_temp > 1:
        temp = raw_temp / 10.0
    elif schema == 0xA9:
      raw_temp = int.from_bytes(payload[34:36], "big")
      if raw_temp > 1:
        temp = raw_temp / 10.0

    return schema, num_wl_resp, num_wells, temp

  @staticmethod
  def _detect_group_layout(payload_len: int, num_wells: int, num_wl_resp: int) -> int:
    """Determine how many extra groups follow group 0 in the data section.

    Layout: [header 36B] [group0] [N extra groups] [(1+N) × 8B cal] [0–1 trail]

    Solves for N from payload size::

      bytes_after_group0 = N × (wells×4) + (1+N) × 8 + trailing
                         = N × (wells×4 + 8) + 8 + trailing
      N = (bytes_after_group0 - 8 - trailing) / (wells×4 + 8)

    General pattern for W wavelengths: W + 2 extra groups (W + 3 total),
    W + 3 cal pairs. Reference is always the last group with the last
    cal pair.

    Returns:
      Number of extra groups (0 if detection fails).
    """
    group0_size = num_wells * num_wl_resp * 4
    bytes_after_group0 = payload_len - 36 - group0_size
    w4 = num_wells * 4
    if w4 <= 0:
      return 0
    for trailing in (1, 0):
      n_float = (bytes_after_group0 - 8 - trailing) / (w4 + 8)
      if n_float >= 0 and abs(n_float - round(n_float)) < 0.01:
        return int(round(n_float))
    return 0

  @staticmethod
  def _extract_groups(
    payload: bytes,
    num_wells: int,
    num_wl_resp: int,
    extra_groups: int,
  ) -> Tuple[List[int], List[List[int]], List[Tuple[int, int]]]:
    """Read group 0, extra groups, and calibration pairs from the data section.

    Returns:
      (group0, extras, cal_pairs) where group0 is a flat list of u32 values,
      extras is a list of per-group u32 lists, and cal_pairs is a list of
      (hi, lo) tuples.
    """
    offset = 36

    def _read_u32s(count: int) -> List[int]:
      nonlocal offset
      end = offset + count * 4
      if end > len(payload):
        raise ValueError(
          f"payload too short: need {end} bytes for {count} u32s at offset {offset}, "
          f"but payload is {len(payload)} bytes"
        )
      values = []
      for _ in range(count):
        values.append(int.from_bytes(payload[offset : offset + 4], "big"))
        offset += 4
      return values

    group0 = _read_u32s(num_wells * num_wl_resp)
    extras = [_read_u32s(num_wells) for _ in range(extra_groups)]

    num_cal_pairs = 1 + extra_groups
    cal_pairs: List[Tuple[int, int]] = []
    for _ in range(num_cal_pairs):
      hi = int.from_bytes(payload[offset : offset + 4], "big")
      offset += 4
      lo = int.from_bytes(payload[offset : offset + 4], "big")
      offset += 4
      cal_pairs.append((hi, lo))

    return group0, extras, cal_pairs

  def _compute_results(
    self,
    group0: List[int],
    extras: List[List[int]],
    cal_pairs: List[Tuple[int, int]],
    num_wells: int,
    temp: Optional[float],
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"],
  ) -> List[Dict]:
    """Convert extracted groups into per-wavelength result dicts.

    Assigns groups by position:
      Single WL (3 extras): chrom2, chrom3, ref
      Dual WL   (4 extras): WL2, chrom2, chrom3, ref
      Triple WL (5 extras): WL2, WL3, chrom2, chrom3, ref

    Transmittance formula (no dark subtraction)::

      T = (sample / c_hi) × (r_hi / ref)
      T% = T × 100
      OD = -log10(T)
    """
    num_extra_wl = max(0, len(extras) - 3)

    # Concatenate all WL sample values: group0 + extra WL groups
    samples = list(group0)
    for wl_extra_idx in range(num_extra_wl):
      samples.extend(extras[wl_extra_idx])

    # Reference is always the LAST extra group
    refs = extras[-1] if extras else [0] * num_wells

    # Reference calibration is always the LAST cal pair
    ref_cal = cal_pairs[-1] if len(cal_pairs) >= 2 else (0, 0)
    r_hi = ref_cal[0]
    now = time.time()

    results: List[Dict] = []
    for wl_idx, wl_nm in enumerate(wavelengths):
      wl_cal = cal_pairs[wl_idx] if wl_idx < len(cal_pairs) else cal_pairs[0]
      c_hi = wl_cal[0]

      if report == "raw":
        raw_flat: List[float] = [
          float(samples[i + wl_idx * num_wells]) for i in range(num_wells)
        ]
        grid = self._map_readings_to_plate_grid(raw_flat, wells, plate)
        results.append(
          {
            "wavelength": wl_nm,
            "time": now,
            "temperature": temp,
            "data": grid,
            "references": list(refs),
            "chromatic_cal": wl_cal,
            "reference_cal": ref_cal,
          }
        )
      else:
        values: List[float] = []
        for i in range(num_wells):
          sample_val = samples[i + wl_idx * num_wells]
          ref_val = refs[i]
          if c_hi > 0 and ref_val > 0:
            t = (sample_val / c_hi) * (r_hi / ref_val)
          else:
            t = 0.0
          if report == "transmittance":
            values.append(t * 100)
          else:
            values.append(-math.log10(t) if t > 0 else float("inf"))

        grid = self._map_readings_to_plate_grid(values, wells, plate)
        results.append(
          {
            "wavelength": wl_nm,
            "time": now,
            "temperature": temp,
            "data": grid,
          }
        )

    return results

  def _parse_absorbance_response(
    self,
    payload: bytes,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
  ) -> List[Dict]:
    """Parse an ABS_DATA_RESPONSE payload into per-wavelength result dicts.

    Delegates to four steps:
      1. ``_parse_response_header`` — validate & extract metadata
      2. ``_detect_group_layout`` — determine extra group count from payload size
      3. ``_extract_groups`` — read u32 arrays and calibration pairs
      4. ``_compute_results`` — apply OD/transmittance/raw formula per wavelength

    See ``_detect_group_layout`` for the dynamic group layout documentation.
    """
    schema, num_wl_resp, num_wells, temp = self._parse_response_header(payload)
    extra_groups = self._detect_group_layout(len(payload), num_wells, num_wl_resp)
    if extra_groups == 0 and len(payload) > 36 + num_wells * num_wl_resp * 4 + 8 + 1:
      logger.warning(
        "Could not determine group layout for %d-byte response (%d wells, %d wl_resp); "
        "results may be invalid (all-zero references produce OD=inf)",
        len(payload),
        num_wells,
        num_wl_resp,
      )
    group0, extras, cal_pairs = self._extract_groups(payload, num_wells, num_wl_resp, extra_groups)
    return self._compute_results(
      group0, extras, cal_pairs, num_wells, temp, plate, wells, wavelengths, report
    )

  async def request_absorbance_results(
    self,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
  ) -> List[Dict]:
    """Retrieve and parse completed absorbance data from the device buffer.

    Combines ``_request_measurement_data()`` (wire-level MEM-READ) with
    ``_parse_absorbance_response()`` (binary parsing + OD/T%/raw conversion)
    into a single public call.

    This method exists for the ``wait=False`` workflow: after
    ``read_absorbance(..., wait=False)`` fires the measurement, call this
    once the device is no longer busy to collect the parsed results.
    ``read_absorbance(..., wait=True)`` calls this internally after its
    polling loop completes.

    Args:
      plate: The plate used for the measurement.
      wells: Wells that were measured.
      wavelengths: Wavelengths (nm) that were measured.
      report: Output format — see ``read_absorbance`` docstring.

    Returns:
      List of result dicts, one per wavelength (same format as
      ``read_absorbance``).
    """
    response = await self._request_measurement_data(progressive=False)
    return self._parse_absorbance_response(response, plate, wells, wavelengths, report=report)

  async def read_absorbance(
    self,
    plate: Plate,
    wells: List[Well],
    wavelength: int,
    *,
    # --- wavelength & output ---
    # TODO: ask community to abolish wavelength: int for wavelengths: List[int]
    #   expected behaviour: execute [wfl_0, wfl_1, ..., wfl_n] / well if possible
    #   (e.g. CLARIOstar, Tecan Spark) else sequentially (e.g. Byonoy A96A)
    wavelengths: Optional[List[int]] = None,  # wire protocol encodes nm×10 (u16 BE),
    # so 0.1nm precision is possible — may need changing to float if fractional nm
    # are confirmed on hardware.
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
    # --- optics ---
    flashes: int = 10,
    well_scan: str = "point",
    scan_diameter_mm: int = 3,
    # --- scan direction ---
    unidirectional: bool = True,
    vertical: bool = True,
    corner: str = "TL",
    # --- shaking ---
    shake_mode: Optional[str] = None,
    shake_speed_rpm: Optional[int] = None,
    shake_duration_s: Optional[int] = None,
    settling_time_s: Optional[float] = None,
    # --- execution ---
    read_timeout: Optional[float] = None,
    wait: bool = True,
  ) -> List[Dict]:
    """Measure discrete absorbance at one or more wavelengths.

    This is the top-level orchestrator. It builds the measurement payload,
    sends the RUN command, optionally polls for completion, and returns
    parsed results. It delegates to ``_build_absorbance_payload``,
    ``_request_measurement_data``, ``_measurement_progress``, and
    ``request_absorbance_results`` — all defined above.

    Two modes of operation:

    **wait=True** (default): Sends the RUN command, then polls
    ``_request_measurement_data(progressive=True)`` in a loop until all
    values are collected (``values_written >= values_expected``). Status queries
    are interleaved between data polls, matching the Voyager protocol.
    Returns parsed results in the format specified by ``report``.

    **wait=False**: Sends the RUN command only and returns an empty list
    immediately. The measurement runs asynchronously on the device. Use
    ``request_absorbance_results()`` to retrieve and parse results once
    the device is no longer busy.

    Args:
      plate: The plate to measure.
      wells: Wells to measure.
      wavelength: Single wavelength in nm. Provide this or *wavelengths*.
      wavelengths: List of wavelengths in nm (1-8). Provide this or *wavelength*.
      report: Output format for the measurement data:

        - ``"optical_density"`` (default): OD = -log10(T), where
          T = (sample / c_hi) * (r_hi / ref). Verified ±0.001 OD vs OEM MARS.
        - ``"transmittance"``: Percent transmittance T% = T * 100.
        - ``"raw"``: Unprocessed detector counts. Each result dict includes
          extra keys ``"references"``, ``"chromatic_cal"``, and
          ``"reference_cal"`` alongside the per-well sample counts in
          ``"data"``.
      flashes: Flashes per well (default 10). Limits depend on well_scan mode:
        point 1-200, orbital 1-44, spiral 1-127, matrix 1-200.
      well_scan: ``"point"``, ``"orbital"``, ``"spiral"``, or ``"matrix"``
        (matrix not yet implemented).
      scan_diameter_mm: Scan diameter in mm for orbital/spiral modes.
      unidirectional: If True, scan wells in one direction only. If False,
        bidirectional (serpentine) scanning.
      vertical: If True, scan columns first (top→bottom). If False, scan
        rows first (left→right).
      corner: Starting corner: ``"TL"``, ``"TR"``, ``"BL"``, or ``"BR"``.
      shake_mode: Shake plate before reading. ``None`` (default) = no shake,
        ``"orbital"``, ``"linear"``, or ``"double_orbital"``. When set, requires
        ``shake_speed_rpm``, ``shake_duration_s``, and ``settling_time_s``.
      shake_speed_rpm: Shake speed in RPM (multiples of 100, 100-700). Required
        when ``shake_mode`` is set.
      shake_duration_s: Shake duration in seconds (> 0). Required when
        ``shake_mode`` is set.
      settling_time_s: Wait time in seconds after shaking before reading
        (0.0-1.0). Required when ``shake_mode`` is set.
      read_timeout: Timeout for the measurement. Defaults to self.read_timeout.
      wait: If True, poll until measurement completes and return results.
        If False, fire the measurement and return an empty list immediately.

    Returns:
      List of dicts when wait=True, one per wavelength. Each dict has keys:
        "wavelength": int (nm),
        "time": float (epoch seconds),
        "temperature": Optional[float] (°C or None),
        "data": List[List[Optional[float]]] (2D grid, rows×cols, None for unread wells)
      When report="raw", each dict also includes:
        "references": List[int] (per-well reference detector counts),
        "chromatic_cal": Tuple[int, int] (hi, lo calibration for this wavelength),
        "reference_cal": Tuple[int, int] (hi, lo reference calibration)
      Empty list when wait=False.
    """
    # --- input validation ---
    # When both are provided, wavelengths takes priority (the PlateReader frontend
    # always passes wavelength as a required positional, so both arrive together).
    wls = wavelengths if wavelengths is not None else [wavelength]

    if not 1 <= len(wls) <= 8:
      raise ValueError(f"wavelengths must contain 1-8 entries, got {len(wls)}.")
    for wl in wls:
      if not 220 <= wl <= 1000:
        raise ValueError(
          f"Wavelength must be 220-1000 nm (UV/Vis absorbance spectrometer range), got {wl}."
        )

    _flash_limits = {"point": (1, 200), "orbital": (1, 44), "spiral": (1, 127), "matrix": (1, 200)}
    valid_well_scans = tuple(_flash_limits)
    if well_scan not in valid_well_scans:
      raise ValueError(f"well_scan must be one of {valid_well_scans}, got {well_scan!r}.")

    lo, hi = _flash_limits[well_scan]
    if not lo <= flashes <= hi:
      raise ValueError(f"flashes must be {lo}-{hi} for {well_scan} mode, got {flashes}.")

    if well_scan == "matrix":
      raise NotImplementedError("matrix well scan is not yet implemented.")

    if well_scan not in ("point", "matrix") and not 1 <= scan_diameter_mm <= 6:
      raise ValueError(
        f"scan_diameter_mm must be 1-6 for {well_scan} mode, got {scan_diameter_mm}."
      )

    valid_corners = ("TL", "TR", "BL", "BR")
    if corner not in valid_corners:
      raise ValueError(f"corner must be one of {valid_corners}, got {corner!r}.")

    valid_reports = ("optical_density", "transmittance", "raw")
    if report not in valid_reports:
      raise ValueError(f"report must be one of {valid_reports}, got {report!r}.")

    valid_shake_modes = (None, "orbital", "linear", "double_orbital")
    if shake_mode not in valid_shake_modes:
      raise ValueError(f"shake_mode must be one of {valid_shake_modes}, got {shake_mode!r}.")
    if shake_mode is not None:
      if shake_speed_rpm is None:
        raise ValueError("shake_speed_rpm is required when shake_mode is set.")
      if shake_duration_s is None:
        raise ValueError("shake_duration_s is required when shake_mode is set.")
      if settling_time_s is None:
        raise ValueError("settling_time_s is required when shake_mode is set.")
      if shake_speed_rpm < 100 or shake_speed_rpm > 700 or shake_speed_rpm % 100 != 0:
        raise ValueError(
          f"shake_speed_rpm must be a multiple of 100 in range 100-700, got {shake_speed_rpm}."
        )
      if not 0 < shake_duration_s <= 65535:
        raise ValueError(
          f"shake_duration_s must be 1-65535 when shake_mode is set, got {shake_duration_s}."
        )
      if not 0 <= settling_time_s <= 1:
        raise ValueError(
          f"settling_time_s must be 0-1 (MARS range 0.0-1.0 s), got {settling_time_s}."
        )
    else:
      if shake_speed_rpm is not None:
        raise ValueError("shake_speed_rpm must be None when shake_mode is None.")
      if shake_duration_s is not None:
        raise ValueError("shake_duration_s must be None when shake_mode is None.")
      if settling_time_s is not None:
        raise ValueError("settling_time_s must be None when shake_mode is None.")

    if read_timeout is not None and read_timeout <= 0:
      raise ValueError(f"read_timeout must be > 0, got {read_timeout}.")

    timeout = read_timeout if read_timeout is not None else self.read_timeout

    # 1. Build and send measurement parameters via send_command(RUN)
    measurement_params = self._build_absorbance_payload(
      plate,
      wells,
      wls,
      flashes=flashes,
      well_scan=well_scan,
      scan_diameter_mm=scan_diameter_mm,
      unidirectional=unidirectional,
      vertical=vertical,
      corner=corner,
      shake_mode=shake_mode,
      shake_speed_rpm=shake_speed_rpm if shake_speed_rpm is not None else 0,
      shake_duration_s=shake_duration_s if shake_duration_s is not None else 0,
      settling_time_s=settling_time_s if settling_time_s is not None else 0.0,
    )
    await self.send_command(
      command_family=self.CommandFamily.RUN,
      parameters=measurement_params,
    )

    if not wait:
      return []

    # 2. Poll incrementally: request data (progressive), check progress,
    #    interleave status queries — matches Voyager protocol pattern.
    #
    # The firmware reports (values_written, values_expected) in each progressive
    # data response.  Normally the loop breaks when written >= expected.  However,
    # the firmware resets both counters to 0 once the measurement finishes, so it
    # is possible to go from e.g. 364/392 directly to 0/0 without ever seeing
    # 392/392.  When progress reports 0/0 we fall through to the interleaved
    # status query and check the busy flag — if the device is no longer busy
    # the measurement is complete.
    t0 = time.time()
    response = b""
    while True:
      if time.time() - t0 > timeout:
        raise TimeoutError(
          f"Measurement not complete after {timeout:.1f}s. Increase timeout via read_timeout=."
        )

      # Progressive data request (ff ff ff ff 00)
      try:
        response = await self._request_measurement_data(progressive=True)
      except FrameError as e:
        logger.warning("data poll: bad frame (%s), retrying", e)
        continue

      written, expected = self._measurement_progress(response)
      if logger.isEnabledFor(logging.INFO):
        logger.info("measurement progress: %d/%d", written, expected)

      if expected > 0 and written >= expected:
        break

      # Interleave a status query between data polls (matches Voyager pattern).
      # When the firmware resets counters to 0/0 after completing, the busy flag
      # clears — use it as the definitive completion signal.
      try:
        status = await self.request_machine_status()
        if not status["busy"]:
          logger.info("measurement complete (device no longer busy)")
          break
      except FrameError as e:
        logger.debug("interleaved status poll: bad frame (%s), ignoring", e)

    # 3. Retrieve final results via the public collection method
    return await self.request_absorbance_results(plate, wells, wls, report=report)

  # Absorbance Spectrum Measurement (not yet implemented)

  async def read_absorbance_spectrum(
    self,
    plate: Plate,
    wells: List[Well],
    start_wavelength: int,
    end_wavelength: int,
    step_size: int,
  ) -> List[Dict]:
    raise NotImplementedError("Absorbance spectrum not yet implemented for CLARIOstar Plus.")

  # --------------------------------------------------------------------------
  # Feature: Fluorescence Measurement (not yet implemented)
  # --------------------------------------------------------------------------
  # NOTE: Gain must be set explicitly. Firmware 1.35 (Nov 2020) pre-dates
  # Enhanced Dynamic Range (EDR), so auto-gain is not available. A `gain`
  # parameter will be required when this stub is implemented.

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    *,
    excitation_width: int = 10,
    emission_width: int = 10,
    optical_path: Literal["monochromator", "filter"] = "monochromator",
    mode: Literal["top", "bottom"] = "bottom",
  ) -> List[Dict]:
    raise NotImplementedError("Fluorescence not yet implemented for CLARIOstar Plus.")

  # --------------------------------------------------------------------------
  # Feature: Luminescence Measurement (not yet implemented)
  # --------------------------------------------------------------------------
  # NOTE: Same gain caveat as fluorescence — no EDR on firmware 1.35.

  async def read_luminescence(
    self, plate: Plate, wells: List[Well], focal_height: float
  ) -> List[Dict]:
    raise NotImplementedError("Luminescence not yet implemented for CLARIOstar Plus.")
