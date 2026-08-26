"""STAR V firmware errors.

A STAR V reports the failing command's own code in `er`, and appends its modules' codes as a
string parameter `es`, tagged with each node's abbreviation. A faulty parameter's name comes back
in `ep`. What each code means is not ported yet, so a failure carries the machine's own text.
"""

import re
from typing import Optional


class STARVFirmwareError(Exception):
  """An error reported by a STAR V."""

  def __init__(self, error_code: int, node_errors: Optional[str], raw_response: str):
    self.error_code = error_code
    self.node_errors = node_errors
    self.raw_response = raw_response
    detail = f", nodes {node_errors!r}" if node_errors else ""
    super().__init__(f"error {error_code:02}{detail}, in reply {raw_response!r}")


def check_fw_string_error(resp: str) -> None:
  """Raise if a reply reports an error.

  Args:
    resp: The reply as received from the machine.

  Raises:
    STARVFirmwareError: If the reply reports a non-zero error.
  """
  match = re.search(r"er(\d{2})", resp)
  if match is None:
    return

  error_code = int(match.group(1))
  if error_code == 0:
    return

  node_errors = re.search(r'es"([^"]*)"', resp)
  raise STARVFirmwareError(
    error_code=error_code,
    node_errors=node_errors.group(1) if node_errors is not None else None,
    raw_response=resp,
  )
