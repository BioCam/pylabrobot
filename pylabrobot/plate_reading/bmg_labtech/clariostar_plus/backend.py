"""BMG CLARIOstar Plus plate reader backend.

Lifecycle: initialize, open/close drawer, status polling, EEPROM/firmware
identification, machine type auto-detection.
Measurement: discrete absorbance (1-8 wavelengths), absorbance spectrum,
fluorescence, fluorescence spectrum, luminescence (stub).

The class is assembled from feature mixins:
  _lifecycle.py ............... constructor, setup/stop, I/O, status, device info,
                                filter detection, usage counters
  _drawer.py .................. drawer open/close/sense
  _temperature_control.py ..... temperature monitoring and heating control
  _shaker.py .................. standalone shaking and idle movement
  _measurement_common.py ...... plate encoding, validation, polling (shared)
  _absorbance.py .............. discrete + spectrum absorbance
  _fluorescence.py ............ discrete + spectrum fluorescence
  _focus.py ................... focus_well (Z-scan), auto_focus (deprecated)
  _luminescence.py ............ luminescence (stub)
"""

import enum
from typing import Dict, List

from ...backend import PlateReaderBackend
from ._protocol import _wrap_payload
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
from ._lifecycle import _LifecycleMixin
from ._measurement_common import _MeasurementCommonMixin
from ._shaker import _ShakerMixin
from ._temperature_control import _TemperatureControlMixin


class CLARIOstarPlusBackend(
  _FocusMixin,
  _LuminescenceMixin,
  _DrawerMixin,
  _FluorescenceMixin,
  _AbsorbanceMixin,
  _ShakerMixin,
  _TemperatureControlMixin,
  _MeasurementCommonMixin,
  _LifecycleMixin,
  PlateReaderBackend,
):
  """BMG CLARIOstar Plus plate reader backend.

  Lifecycle: initialize, open/close drawer, status polling, device identification.
  Measurement: absorbance (discrete + spectrum), fluorescence (discrete + spectrum).
  Luminescence (stub).

  Sections (in mixin source files):
    _lifecycle.py:
      Constructor .................... __init__
      Life cycle ..................... setup, stop, initialize, recovery
      Low-level I/O .................. _write_frame, _read_frame, send_command
      Status ......................... request_machine_status, is_ready, sense_plate
      Device info .................... request_eeprom_data, firmware, detection modes
      Usage counters ................. request_usage_counters
      Filter auto-detection ......... detect_all_filters, _parse_filter_result
      Temperature control ........... start/stop_temperature_control, measure
    _drawer.py:
      Drawer control ................. open, close, sense_drawer_open
    _measurement_common.py:
      Common reading helpers ......... _plate_field, _pre_separator_block, polling
      Shared validation .............. _validate_well_scan_params, _normalize_corner, etc.
      Measurement control ............ pause, resume, stop measurement
      Shaking / idle movement ........ start/stop_shaking, start/stop_idle_movement
    _absorbance.py:
      Absorbance (discrete) ......... read_absorbance, _build/_parse_absorbance_*
      Absorbance (spectrum) ......... read_absorbance_spectrum, _retrieve/_parse_abs_*
    _fluorescence.py:
      Fluorescence (discrete) ....... read_fluorescence, _build/_parse_fluorescence_*
      Fluorescence (spectrum) ....... read_fluorescence_spectrum, _build/_parse_fl_*
    _focus.py:
      Focus well (Z-scan) .......... focus_well, _build_focus_well_payload
      Auto-focus (deprecated) ...... auto_focus, _build_autofocus_payload
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
    EEPROM = 0x07
    FIRMWARE_INFO = 0x09
    FOCUS_RESULT = 0x05
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
      Command.FOCUS_RESULT,
      Command.EEPROM,
      Command.FIRMWARE_INFO,
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
