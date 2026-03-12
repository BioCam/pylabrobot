"""BMG CLARIOstar Plus plate reader backend.

Core: connection, hardware init, status polling, EEPROM/firmware
identification, machine type auto-detection.
Measurement: discrete absorbance (1-8 wavelengths), absorbance spectrum,
fluorescence, fluorescence spectrum, luminescence (stub).

Package layout:
  _framing.py ................. frame encoding/validation, protocol exceptions, payload byte blocks
  backend.py (this file) ...... class definition, connection, I/O, status, device info
  _drawer.py .................. drawer open/close/sense
  _temperature_control.py ..... temperature monitoring and heating control
  _shaker.py .................. standalone shaking and idle movement
  _measurement_common.py ...... plate encoding, validation, polling (shared)
  _absorbance.py .............. discrete + spectrum absorbance
  _fluorescence.py ............ discrete + spectrum fluorescence, filter auto-detection
  _focus.py ................... focus_well (Z-scan), auto_focus (deprecated)
  _luminescence.py ............ luminescence (stub)
"""

import asyncio
import enum
import logging
import time
import warnings
from typing import Dict, List, Optional

from pylabrobot.io import LOG_LEVEL_IO
from pylabrobot.io.ftdi import FTDI

from ...backend import PlateReaderBackend
from ..optical_elements import (
  _FilterBase,
  OpticalFilter,
  DichroicFilter,
  _FilterSlideBase,
  ExcitationFilterSlide,
  EmissionFilterSlide,
  DichroicFilterSlide,
)

from ._absorbance import _AbsorbanceMixin
from ._drawer import _DrawerMixin
from ._fluorescence import _FluorescenceMixin
from ._focus import _FocusMixin
from ._luminescence import _LuminescenceMixin
from ._measurement_common import _MeasurementCommonMixin
from ._plate_mapping import _PlateMappingMixin
from ._shaker import _ShakerMixin
from ._temperature_control import _TemperatureControlMixin

from ._framing import (
  ChecksumError,
  FrameError,
  MeasurementInterrupted,
  _extract_payload,
  _validate_frame,
  _wrap_payload,
)

logger = logging.getLogger("pylabrobot")

# ---------------------------------------------------------------------------
# Confirmed firmware versions
# ---------------------------------------------------------------------------
# Firmware versions verified against hardware ground truth, mapped to build year.
# Used during setup() to warn when the connected device runs untested firmware.
# Add entries here as new versions are verified.
# If year granularity proves insufficient, switch values to (year, month) tuples.

CONFIRMED_FIRMWARE_VERSIONS: Dict[str, int] = {
  "1.35": 2020,  # supports EDR (verified via capture F-P01); no auto-gain support
}

# ---------------------------------------------------------------------------
# Model lookup
# ---------------------------------------------------------------------------
# Same machine (serial 430-2621) reports different EEPROM type bytes across reads.
# High byte varies (0x00, 0x06, 0x07), low byte varies (0x21, 0x24, 0x26).
# Full cross-product of observed variants:
# 0x0024: verified on CLARIOstar Plus hardware (initial USB captures).
# 0x0026: from vibed code, unverified on real hardware.
# 0x0621: verified on CLARIOstar Plus hardware (live trace, serial 430-2621).
# 0x0626: verified on CLARIOstar Plus hardware (live trace, serial 430-2621).
_MODEL_LOOKUP: Dict[int, str] = {
  0x0021: "CLARIOstar Plus",
  0x0024: "CLARIOstar Plus",
  0x0026: "CLARIOstar Plus",
  0x0621: "CLARIOstar Plus",
  0x0624: "CLARIOstar Plus",
  0x0626: "CLARIOstar Plus",
  0x0721: "CLARIOstar Plus",
  0x0724: "CLARIOstar Plus",
  0x0726: "CLARIOstar Plus",
}


class CLARIOstarPlusBackend(
  _PlateMappingMixin,
  _FocusMixin,
  _LuminescenceMixin,
  _DrawerMixin,
  _FluorescenceMixin,
  _AbsorbanceMixin,
  _ShakerMixin,
  _TemperatureControlMixin,
  _MeasurementCommonMixin,
  PlateReaderBackend,
):
  """BMG CLARIOstar Plus plate reader backend.

  Core: connection, hardware init, status polling, device identification.
  Features:
  - drawer
  - temperature control (monitoring + heating)
  - absorbance (discrete + spectrum)
  - fluorescence (discrete + spectrum)
  - luminescence (stub)

  Sections:
    Core (this file):
      Constructor .................... __init__
      Connection & init .............. setup, stop, initialize
      Low-level I/O .................. _write_frame, _read_frame, send_command
      Status ......................... request_machine_status, is_ready,
                                      sense_plate_present
      Device info .................... request_eeprom_data, request_firmware_info,
                                      request_available_detection_modes
      Usage counters ................. request_usage_counters
    _drawer.py:
      Drawer control ................. open, close, sense_drawer_open
    _temperature_control.py:
      Temperature .................... start/stop_temperature_control,
                                      measure_temperature
    _shaker.py:
      Shaking ........................ start/stop_shaking, start/stop_idle_movement
    _measurement_common.py:
      Common reading helpers ......... _plate_field, _pre_separator_block, polling
      Shared validation .............. _validate_well_scan_params, _normalize_corner
      Measurement control ............ pause, resume, stop measurement
    _absorbance.py:
      Absorbance (discrete) ......... read_absorbance
      Absorbance (spectrum) ......... read_absorbance_spectrum
    _fluorescence.py:
      Fluorescence (discrete) ....... read_fluorescence
      Fluorescence (spectrum) ....... read_fluorescence_spectrum
      Filter auto-detection ......... detect_all_filters
    _focus.py:
      Focus well (Z-scan) .......... focus_well
      Auto-focus (deprecated) ...... auto_focus
    _plate_mapping.py:
      Plate mapping ................ scan_plate_mapping, request_plate_map_xy,
                                     request_plate_map_config
    _luminescence.py:
      Luminescence .................. read_luminescence (stub)
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
    FOCUS_WELL = 0x09    # R_FocusWell: single-well Z-scan (51B frame, 45B payload)
    STOP = 0x0B
    AUTO_FOCUS = 0x0C    # R_FocusPlate: multi-well search + Z-scan (97B frame, 91B payload)
    PAUSE_RESUME = 0x0D
    CMD_0x0E = 0x0E
    SHAKE = 0x1D           # R_Shake: standalone shaking (17B frame, 11B payload)
    FILTER_SCAN = 0x24
    PLATE_MAP_SCAN = 0x07  # XY raster scan of corner wells (41B FI / 40B ABS payload)
    IDLE_MOVE = 0x27       # R_IdleMove: continuous/periodic shaking (17B frame, 11B payload)
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
    PLATE_MAP_XY = 0x04       # GET calibrated XY positions from plate mapping scan
    FOCUS_RESULT = 0x05
    EEPROM = 0x07
    FIRMWARE_INFO = 0x09
    PLATE_MAP_CONFIG = 0x0D   # GET plate mapping metadata/config
    FOCUS_HEIGHT = 0x0F
    SPECTRAL_DATA = 0x11
    FILTER_RESULT = 0x1B
    READ_ORDER = 0x1D
    USAGE_COUNTERS = 0x21
    # FILTER_SCAN (subcmds for CommandFamily.FILTER_SCAN)
    FILTER_SCAN_EXCITATION = 0x20
    FILTER_SCAN_EMISSION = 0x21
    FILTER_SCAN_DICHROIC = 0x23
    # POLL
    POLL = 0x00

  _VALID_COMMANDS = {
    CommandFamily.INITIALIZE: {Command.INIT},
    CommandFamily.TRAY: {Command.TRAY_CLOSE, Command.TRAY_OPEN},
    CommandFamily.REQUEST: {
      Command.DATA,
      Command.PLATE_MAP_XY,
      Command.FOCUS_RESULT,
      Command.EEPROM,
      Command.FIRMWARE_INFO,
      Command.PLATE_MAP_CONFIG,
      Command.FOCUS_HEIGHT,
      Command.SPECTRAL_DATA,
      Command.FILTER_RESULT,
      Command.READ_ORDER,
      Command.USAGE_COUNTERS,
    },
    CommandFamily.FILTER_SCAN: {
      Command.FILTER_SCAN_EXCITATION,
      Command.FILTER_SCAN_EMISSION,
      Command.FILTER_SCAN_DICHROIC,
    },
    CommandFamily.POLL: {Command.POLL},
  }
  _NO_COMMAND_FAMILIES = {
    CommandFamily.STATUS,
    CommandFamily.HW_STATUS,
    CommandFamily.TEMPERATURE_CONTROLLER,
    CommandFamily.RUN,
    CommandFamily.PLATE_MAP_SCAN,
    CommandFamily.FOCUS_WELL,
    CommandFamily.AUTO_FOCUS,
    CommandFamily.STOP,
    CommandFamily.PAUSE_RESUME,
    CommandFamily.CMD_0x0E,
    CommandFamily.SHAKE,
    CommandFamily.IDLE_MOVE,
  }

  # -- Optic byte flags (bit field, OR'd together) -------------------------

  class DetectionMode(enum.IntEnum):
    """Detection mode (base value for the optic config byte)."""

    FLUORESCENCE = 0x00
    LUMINESCENCE = 0x01
    ABSORBANCE = 0x02

  class WellScanMode(enum.IntEnum):
    """Well scan mode flags OR'd into the optic config byte."""

    POINT = 0x00
    SPIRAL = 0x04
    MATRIX = 0x10
    ORBITAL = 0x30

  class OpticPosition(enum.IntEnum):
    """Optic position flag OR'd into the optic config byte (fluorescence only)."""

    TOP = 0x00
    BOTTOM = 0x40

  # -- Filter / Filter slide (imported from optical_elements.py) ------------

  _FilterBase = _FilterBase
  OpticalFilter = OpticalFilter
  DichroicFilter = DichroicFilter
  _FilterSlideBase = _FilterSlideBase
  ExcitationFilterSlide = ExcitationFilterSlide
  EmissionFilterSlide = EmissionFilterSlide
  DichroicFilterSlide = DichroicFilterSlide

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

  # Pre-cached status frame: STATUS_QUERY (0x80).
  _STATUS_FRAME = _wrap_payload(b"\x80")

  _PACKET_READ_TIMEOUT: float = 1.0  # seconds; base timeout for a single serial frame
  # At 125 kBaud a 1612-byte frame takes ~130 ms; a 52 KB spectrum page takes
  # ~4.2 s.  _read_frame dynamically extends the timeout once it parses the
  # size field from the header, so this base value only needs to cover small
  # frames and the initial header read of large ones.
  _BAUD_RATE: int = 125_000  # baud; used to compute wire-time-scaled timeouts

  # Validation constants
  _FLASH_LIMITS = {"point": (1, 200), "orbital": (1, 44), "spiral": (1, 127), "matrix": (1, 200)}
  _VALID_CORNERS = ("TL", "TR", "BL", "BR")
  _CORNER_ALIASES = {
    "TL": "TL", "tl": "TL", "top_left": "TL", "TOP_LEFT": "TL",
    "TR": "TR", "tr": "TR", "top_right": "TR", "TOP_RIGHT": "TR",
    "BL": "BL", "bl": "BL", "bottom_left": "BL", "BOTTOM_LEFT": "BL",
    "BR": "BR", "br": "BR", "bottom_right": "BR", "BOTTOM_RIGHT": "BR",
  }
  _VALID_ABSORBANCE_REPORTS = ("optical_density", "transmittance", "raw")
  _VALID_OPTIC_POSITIONS = ("top", "bottom")

  # Hardware range constants
  _ABS_WAVELENGTH_RANGE = (220, 1000)
  _FL_WAVELENGTH_RANGE = (320, 840)
  _FOCAL_HEIGHT_RANGE = (0, 25)
  _PMT_GAIN_RANGE = (0, 4095)
  _MATRIX_SIZE_RANGE = (2, 11)
  _SCAN_DIAMETER_RANGE = (1, 6)

  # Plate encoding constants (standard 384-well configuration).
  # 1536-well instruments likely use a larger mask (192 bytes / 1536 bits);
  # update these when a 1536-well USB capture is available.
  _WELL_MASK_BYTES = 48                        # 384 wells max (48 × 8 bits)
  _PLATE_FIELD_SIZE = 15 + _WELL_MASK_BYTES    # 15-byte geometry header + mask

  # Mode→wire-byte mapping for R_Shake (0x1D).
  _SHAKE_MODES = {
    "orbital": 0x00,
    "linear": 0x01,
    "double_orbital": 0x02,
    "meander": 0x03,
  }

  # Mode→wire-byte mapping for R_IdleMove (0x27).
  # Confirmed via DDE USB capture: arg 1→0x01, arg 2→0x02, arg 3→0x06.
  # DDE args 4-7 are rejected. Wire bytes 0x03-0x05 were NEVER observed.
  # The names for 0x03-0x05 below are speculative (from Go reference).
  _IDLE_MOVE_MODES = {
    "linear_corner": 0x01,    # capture-confirmed (IM-01)
    "incubation": 0x02,       # capture-confirmed (IM-02)
    "meander_corner": 0x03,   # speculative -- never seen on wire
    "orbital_corner": 0x04,   # speculative -- never seen on wire
    "orbital": 0x05,          # capture-confirmed (IM-04)
    "double_orbital": 0x06,   # capture-confirmed (IM-06, also DDE arg 3)
  }

  # --------------------------------------------------------------------------
  # Constructor
  # --------------------------------------------------------------------------

  def __init__(
    self,
    device_id: Optional[str] = None,
    read_timeout: float = 120.0,
    max_temperature: float = 45.0,
    measurement_poll_interval: float = 0.25,
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
      measurement_poll_interval: Seconds to sleep between measurement polling
        cycles. Default 0.25 s; combined with the ~35 ms I/O round-trip this
        yields ~285 ms per poll cycle, matching the OEM software cadence
        (~280-300 ms) observed in USB captures. Also applied before retrying
        after a bad frame. Set to 0.0 for maximum throughput (I/O-paced only).

    Attributes:
      pause_on_interrupt: If False (default), a user interrupt (Ctrl+C / Jupyter
        stop) during a measurement stops the device. If True, the device is
        paused instead, allowing ``resume_measurement_and_collect_data()`` to continue.
    """
    if read_timeout <= 0:
      raise ValueError(f"read_timeout must be > 0, got {read_timeout}.")
    if not 0 < max_temperature <= 65:
      raise ValueError(f"max_temperature must be between 0 and 65 °C, got {max_temperature}.")
    if measurement_poll_interval < 0:
      raise ValueError(f"measurement_poll_interval must be >= 0, got {measurement_poll_interval}.")

    self.io = FTDI(human_readable_device_name="CLARIOstar Plus", device_id=device_id, vid=0x0403, pid=0xBB68)
    self.read_timeout = read_timeout
    self.measurement_poll_interval = measurement_poll_interval
    self.pause_on_interrupt: bool = False

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
    self._resume_context: Optional[dict] = None
    # TODO: keep searching for a way to retrieve target temp from device
    self.excitation_filter_slide = self.ExcitationFilterSlide()
    self.emission_filter_slide = self.EmissionFilterSlide()
    self.dichroic_filter_slide = self.DichroicFilterSlide()

  # --------------------------------------------------------------------------
  # Connection & init
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

    # Device identity handshake: EEPROM and firmware queries serve as an
    # implicit identity check. Both must return valid, parseable responses
    # using our wire protocol — a non-CLARIOstar device would fail here
    # (wrong framing, bad checksum, or unrecognised machine type code).
    eeprom_info = await self.request_eeprom_data()
    self.configuration.update(eeprom_info)

    fw_info = await self.request_firmware_info()
    self.configuration.update(fw_info)

    # CMD_0x0E: observed in every OEM USB capture (both normal boot and recovery
    # from stuck running=True).  Clears stuck running state as a side effect.
    await self._send_cmd_0x0e()

    # Update filter slide slot counts from EEPROM.
    self.excitation_filter_slide._update_max_slots(
      self.configuration.get("excitation_filter_slots", 0))
    self.emission_filter_slide._update_max_slots(
      self.configuration.get("emission_filter_slots", 0))
    self.dichroic_filter_slide._update_max_slots(
      self.configuration.get("dichroic_filter_slots", 0))

    fw_ver = self.configuration["firmware_version"]
    if fw_ver and fw_ver not in CONFIRMED_FIRMWARE_VERSIONS:
      warnings.warn(
        f"Firmware version {fw_ver!r} has not been tested with this driver. "
        f"Confirmed versions: {', '.join(sorted(CONFIRMED_FIRMWARE_VERSIONS))}. "
        f"Proceed with caution -- please report issues.",
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

    If a measurement is still running, it is stopped first via
    ``stop_measurement()``. Then shuts down temperature control and closes the
    drawer before disconnecting. If a plate is still detected inside the device,
    the drawer is reopened and a ``RuntimeError`` is raised so the user can
    retrieve it.

    Args:
      accept_plate_left_in_device: If True, skip the plate-presence check and
        disconnect even if a plate is still inside.

    Raises:
      RuntimeError: If a plate is detected and *accept_plate_left_in_device* is False.
    """
    try:
      status = await self.request_machine_status()
      if status.get("reading_wells"):
        logger.info("Measurement still running during stop(), sending stop_measurement()")
        await self.stop_measurement()
    except Exception:
      logger.warning("Could not check measurement status during stop()", exc_info=True)

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
          poll_interval=0.1,
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
    if logger.isEnabledFor(LOG_LEVEL_IO):
      logger.log(LOG_LEVEL_IO, "sent %d bytes: %s", len(frame), frame.hex())

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
          # Scale timeout to match wire time.  At 125 kBaud, each byte takes
          # 80 µs (10 bits/byte); a 52 KB spectrum page needs ~4.2 s on the
          # wire.  OEM software captures show ~6.2 s for 52 KB including firmware
          # processing.  Use 2.5× wire time (matches OEM overhead) with a
          # floor of the base _PACKET_READ_TIMEOUT.
          wire_time = expected_size * 10 / self._BAUD_RATE
          timeout = max(timeout, wire_time * 2.5)
          t = time.time()  # reset: measure wire time from first data, not from entry

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

        # Mid-frame 0x0D: the FTDI event character can split one serial
        # frame into two USB transfers.  We know exactly how many bytes
        # are missing -- ask for them now instead of waiting for the next
        # bulk loop iteration (which may return empty and sleep).
        if expected_size is not None and len(d) < expected_size:
          gap = await self.io.read(expected_size - len(d))
          if gap:
            d += gap
            end_byte_found = d[-1] == 0x0D
            if len(d) >= expected_size:
              break
      else:
        # Empty read after we already saw CR → done,
        # but only if we have all bytes the size field promised.
        # 0x0D can appear mid-frame (e.g. in checksum bytes),
        # so end_byte_found alone is not sufficient.
        if end_byte_found and (expected_size is None or len(d) >= expected_size):
          break

        if time.time() - t > timeout:
          if expected_size is not None and 0 < len(d) < expected_size:
            last_chance = await self.io.read(expected_size - len(d))
            if last_chance:
              d += last_chance
              if len(d) >= expected_size:
                break
          logger.debug("timed out reading response (%d/%s bytes)",
                       len(d), expected_size)
          break

        await asyncio.sleep(0.0001)

    if d and logger.isEnabledFor(LOG_LEVEL_IO):
      logger.log(LOG_LEVEL_IO, "read %d bytes: %s", len(d), d.hex())

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
    retries: int = 3,
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
      retries: Number of send/read attempts before raising FrameError.
        Default 3. Use 1 for progressive data polling where empty responses
        are expected and the caller handles FrameError directly.

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
    last_err: Optional[FrameError] = None
    for attempt in range(retries):
      await self._write_frame(frame)
      resp = await self._read_frame()
      try:
        _validate_frame(resp)
      except FrameError as e:
        last_err = e
        if len(resp) == 0:
          # Empty response -- the device may not have replied yet.  Try reading
          # unread data from the RX buffer before re-sending, in case the
          # response arrived after _read_frame's timeout expired.
          unread = await self._read_frame()
          if unread:
            try:
              _validate_frame(unread)
              resp = unread
              break
            except FrameError:
              pass
          logger.debug("send_command: no response on attempt %d/%d", attempt + 1, retries)
        else:
          logger.warning("send_command: bad frame on attempt %d/%d (%s)", attempt + 1, retries, e)
        await self.io.usb_purge_rx_buffer()
        continue
      break
    else:
      assert last_err is not None
      raise last_err
    ret = _extract_payload(resp)

    if wait:
      effective_timeout = read_timeout if read_timeout is not None else self.read_timeout
      await self._wait_until_machine_ready(read_timeout=effective_timeout, poll_interval=poll_interval)

    return ret

  # --------------------------------------------------------------------------
  # Status
  # --------------------------------------------------------------------------

  async def request_machine_status(self, retries: int = 5) -> Dict:
    """Query device status and return parsed flags.

    Bypasses ``send_command`` to avoid infinite recursion with
    ``_wait_until_machine_ready``. Retries on transient ``FrameError``
    up to *retries* times before raising.

    Args:
      retries: Number of attempts before raising on repeated frame errors.

    Returns:
      Dict keyed by flag name. Only HIGH confidence fields are parsed.
      Verified across 7,927 STATUS responses in 40 USB captures.

      Confidence: HIGH = parsed into dict, MEDIUM = observed pattern but
      not yet parsed, UNKNOWN = no clear interpretation.

      16-byte response payload map::

        Byte 0  -- response type (always 0x01)
          bit 1  HIGH    ``standby``        power-saving / pre-init state.
                                            Never observed True; may need a
                                            specific power mode to trigger.
          bits 7-2,0                        always 0. Reserved.

        Byte 1  -- activity flags
          bit 5  HIGH    ``busy``           device is occupied (measuring,
                                            initializing, moving drawer, or
                                            any other command). Primary flag
                                            for is_ready(), polling loops.
          bit 4  HIGH    ``running``        active measurement in progress,
                                            or residual state from an
                                            interrupted measurement.  Can
                                            persist across power cycles.
                                            Cleared by fetching measurement
                                            data (GET_DATA 0x05 0x02).
          bit 0  HIGH    ``valid``          status response validity. Set in
                                            all normal operation responses.
          bit 2          UNKNOWN            always set (0x05 base). Likely
                                            protocol/device-type identifier.
          bits 7,6,3,1                      always 0. Reserved.

          busy and running are mutually exclusive in all captures.

        Byte 2  -- data flags
          bit 2  MEDIUM                     set ~87%, clear only during early
                                            boot. Possibly protocol-ready.
          bit 1  MEDIUM                     anti-correlated with busy. Set
                                            when idle, clear when busy or
                                            during early boot.
          bit 0  HIGH    ``unread_data``    measurement results available but
                                            not yet fetched.

        Byte 3  -- hardware and measurement state
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

        Byte 4  -- filter / optical path
          bit 6  HIGH    ``filter_cover_open`` filter cover underneath lid is
                                            open.

        Bytes 5-10            MEDIUM        operation sub-state (not parsed).
                                            Bytes 5,8,9 always 0x00.
                                            Bytes 6,7,10 form a triple:
                                              00 00 .. 00 = idle
                                              03 00 .. 00 = mechanical op
                                              04 01 .. 04 = measurement setup
                                              04 01 .. 03 = well reading

        Bytes 11-12  HIGH    ``temperature_bottom``
                                            bottom heater °C (u16 BE ÷10),
                                            or None if monitoring inactive.
        Bytes 13-14  HIGH    ``temperature_top``
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
        if len(resp) == 0:
          logger.debug("status request: no response on attempt %d/%d", attempt + 1, retries)
        else:
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

      if logger.isEnabledFor(logging.DEBUG):
        logger.debug("status: %s", flags)

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
              spectrometer with 220-1000nm range -- not encoded here.)
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
    if logger.isEnabledFor(logging.DEBUG):
      logger.debug(
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

  # Filter auto-detection lives in _fluorescence.py (fluorescence optical path).
