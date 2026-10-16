"""CLARIOstar error types."""

from typing import Dict, Tuple


class FrameError(Exception):
  """A reply frame is malformed, truncated, or missing."""


class ChecksumError(FrameError):
  """An FTDI reply frame's checksum does not match its bytes."""


# What the first quit code means, for the codes seen in replies from a reader.
QUIT_CODE_DESCRIPTIONS: Dict[int, str] = {
  65: "the kinetic cycle time is too short",
  110: "the target temperature is out of range",
  202: "the reader is busy",
  213: "no measurement results are available",
  214: "no test run is active",
}


class CommandRefusedError(Exception):
  """The reader refused a command and answered with quit codes."""

  def __init__(self, payload: bytes, quit_codes: Tuple[int, int, int, int, int]):
    """
    Args:
      payload: the logical payload that was refused.
      quit_codes: the five quit codes from the reply; the first names the reason.
    """
    self.payload = payload
    self.quit_codes = quit_codes
    description = QUIT_CODE_DESCRIPTIONS.get(quit_codes[0], "no description known")
    super().__init__(
      f"CLARIOstar refused {payload.hex()}: quit code {quit_codes[0]} ({description}), "
      f"quit codes {'/'.join(str(q) for q in quit_codes)}"
    )
