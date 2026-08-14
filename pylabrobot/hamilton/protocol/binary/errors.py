"""Errors reported over the binary packet protocol."""

from dataclasses import dataclass

from pylabrobot.io.binary import Reader


@dataclass
class HamiltonError:
  """Hamilton error response."""

  error_code: int
  error_message: str
  interface_id: int
  action_id: int


class ErrorParser:
  """Parse Hamilton error responses."""

  @staticmethod
  def parse_error(data: bytes) -> HamiltonError:
    """Parse error response from Hamilton instrument."""
    # Error responses have a specific format
    # This is a simplified implementation - real errors may vary
    if len(data) < 8:
      raise ValueError("Error response too short")

    # Parse error structure (simplified)
    error_code = Reader(data).u32()
    error_message = data[4:].decode("utf-8", errors="replace")

    return HamiltonError(
      error_code=error_code, error_message=error_message, interface_id=0, action_id=0
    )
