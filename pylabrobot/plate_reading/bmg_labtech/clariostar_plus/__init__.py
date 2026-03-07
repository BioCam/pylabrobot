"""CLARIOstar Plus plate reader backend package."""

from .backend import CLARIOstarPlusBackend
from ._protocol import (
  CONFIRMED_FIRMWARE_VERSIONS,
  ChecksumError,
  FrameError,
  MeasurementInterrupted,
  _CORE_REFERENCE,
  _REFERENCE_BLOCK,
  _SEPARATOR,
  _TRAILER,
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
  "_REFERENCE_BLOCK",
  "_SEPARATOR",
  "_TRAILER",
  "_extract_payload",
  "_validate_frame",
  "_wrap_payload",
]
