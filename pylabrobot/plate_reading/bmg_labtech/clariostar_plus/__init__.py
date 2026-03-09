"""CLARIOstar Plus plate reader backend package."""

from .backend import CLARIOstarPlusBackend, CONFIRMED_FIRMWARE_VERSIONS
from ._framing import (
  ChecksumError,
  FrameError,
  MeasurementInterrupted,
  _CORE_REFERENCE,
  _MEAS_BOUNDARY,
  _REFERENCE_BLOCK,
  _TRAILER,
  _TRAILER_PREFIX,
  _extract_payload,
  _validate_frame,
  _wrap_payload,
)

__all__ = [
  "CLARIOstarPlusBackend",
  "CONFIRMED_FIRMWARE_VERSIONS",
  "ChecksumError",
  "FrameError",
  "MeasurementInterrupted",
  "_CORE_REFERENCE",
  "_MEAS_BOUNDARY",
  "_REFERENCE_BLOCK",
  "_TRAILER",
  "_TRAILER_PREFIX",
  "_extract_payload",
  "_validate_frame",
  "_wrap_payload",
]
