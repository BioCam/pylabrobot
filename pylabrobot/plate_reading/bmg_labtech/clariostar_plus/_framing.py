"""CLARIOstar Plus frame encoding, validation, protocol exceptions, and payload byte blocks."""

from typing import Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FrameError(Exception):
  """Raised when a response frame is malformed."""


class ChecksumError(FrameError):
  """Raised when the frame checksum does not match."""


class MeasurementInterrupted(Exception):
  """Raised when a measurement is interrupted by the user (Ctrl+C / Jupyter stop).

  By default the device has been stopped. If ``pause_on_interrupt`` was True,
  the device is paused instead and can be resumed via
  ``resume_measurement_and_collect_data()``.

  Partial data (if any) is available via ``partial_data``.
  """
  def __init__(self, message: str, partial_data: Optional[bytes] = None):
    super().__init__(message)
    self.partial_data = partial_data


# ---------------------------------------------------------------------------
# Wire-protocol framing
# ---------------------------------------------------------------------------
#
# Frame format (8-byte overhead):
#   STX (1) | size (2 BE) | 0x0C (1) | payload (n) | checksum (3 BE) | CR (1)
#
# Checksum = sum(frame[:-4]) & 0xFFFFFF
# Verified against 6,780 USB capture frames with zero failures.
#
# Payload hierarchy:
#
#   Command:
#     frame  ->  payload  ->  command_family + [command] + parameters
#                                                           |
#                                                     fields (plate, wells,
#                                                     wavelengths, flashes, ...)
#
#   Response:
#     frame  ->  payload  ->  response_type + status_flags + parameters
#                                                              |
#                                                        fields (schema, values_expected,
#                                                        values_written, wavelengths, wells,
#                                                        temperature, data groups, cal pairs)
#
#   response_type (byte 0): identifies the kind of response.
#     0x01 = status/state report (POLL, STATUS, TRAY, TEMP_CTRL)
#     0x03 = RUN acknowledgment
#     0x09 = hardware info (HW_STATUS)
#     For REQUEST family: usually echoes the subcommand byte (0x02, 0x07, 0x08, ...)
#       Exception: FIRMWARE_INFO (0x09) responds with 0x0a (subcommand + 1).
#
#   status_flags (bytes 0-4): device state bits.
#     12 flags across 5 bytes -- see _STATUS_FLAGS and request_machine_status().

# ---------------------------------------------------------------------------
# Response-parsing flow
# ---------------------------------------------------------------------------
#
# Commands with wait=True follow a two-phase path:
#
#   Phase A (once): send_command -> _wrap_payload -> _write_frame -> _read_frame
#                   -> _validate_frame -> _extract_payload
#
#   Phase B (loop): _wait_until_machine_ready -> request_machine_status
#                   -> flags["busy"] check -> return or retry
#
# _read_frame terminates on: short FTDI read (<25 bytes) ending in 0x0D,
# guarded by the size field to avoid false termination on mid-payload 0x0D.
#
# Pre-cached _STATUS_FRAME avoids per-poll frame construction.
# .hex() in I/O methods guarded by isEnabledFor() to skip eager string allocation.
#
# ~37 ms/poll. Open ~ 4.3 s, close ~ 8 s, dominated by physical motor speed.
#

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
# Payload constant blocks
# ---------------------------------------------------------------------------
# Verified identical across all 38 absorbance USB captures + 9 DOE captures.

# Mechanical/optical boundary marker: separates the plate geometry + movement
# configuration (plate_field, scan_direction, pre_separator) from the optical
# measurement configuration (wavelengths, flashes, kinetic timing, etc.).
# Invariant across all 135 MEASUREMENT_RUN payloads (ABS + FL, all scan modes).
#
# TODO: Use this marker to locate the optical config section when parsing
#   response payloads, instead of relying on hardcoded byte offsets. The
#   well_scan_field before it is variable-length (0B for point, 5B for
#   orbital/spiral), so delimiter-based parsing would be more robust than
#   fixed offsets if the firmware ever changes the layout.
_MEAS_BOUNDARY = b"\x27\x0f\x27\x0f"

# The 11-byte "trailer" is actually: trailer_prefix(10) + kinetic_cycles(1).
# For endpoint mode (1 cycle), the last byte is 0x01. For kinetic mode, it is
# the cycle count.  Similarly, "final" = kinetic_cycle_time_s(u16 BE) + 0x00;
# endpoint uses 0x0001 (1 second).
#
# Shake-between-readings mode overrides trailer_prefix (DOE_SPC04/SPC05):
#   [0] = mode flag: 0x02=normal, 0x08=orbital+between, 0x09=dbl_orbital+between
#         (bit 3: shake-between enable; bit 0: 0=orbital, 1=double_orbital)
#   [1] = speed: (RPM / 100) - 1.  0x02→300rpm, 0x04→500rpm.
#   [3] = shake enable: 0x01 when active
#   [4:6] = 0x003b (constant across all captures)
#
# Fluorescence uses 0x00 at [0] instead of 0x02 (DOE_REF01, 2026-03-09).
_TRAILER_PREFIX = b"\x02\x00\x00\x00\x00\x00\x01\x00\x00\x00"
_TRAILER = _TRAILER_PREFIX + b"\x01"  # endpoint default: 1 cycle

# The 13-byte reference block is actually two parts:
#   _PRE_REFERENCE (4 bytes): context-dependent. 0x00000064 for discrete/filter mode;
#     repurposed as end_wl(2 BE) + 0x00 + step(1) in spectroscopy mode (n_wl=0).
#   _CORE_REFERENCE (9 bytes): last byte (_CORE_REFERENCE[8]) is overloaded as
#     pause-before-cycle mode flag when pause is enabled (0xff=each, DOE_SPC06).
#     The settling_flag byte immediately after is overloaded as pause target
#     (0xff=each, or cycle number 1-indexed, DOE_SPC07).
_PRE_REFERENCE = b"\x00\x00\x00\x64"
_CORE_REFERENCE = b"\x23\x28\x26\xca\x00\x00\x00\x64\x00"
_REFERENCE_BLOCK = _PRE_REFERENCE + _CORE_REFERENCE
