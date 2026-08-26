"""Vantage firmware errors.

A Vantage reports failures in an `es` string parameter listing a module identifier and a code per
failing module, rather than in the positional `er<code>/<trace>` fields a STAR uses. What each
code means is not ported yet, so a failure is raised with the machine's own text.
"""

import re
from typing import Optional


class VantageFirmwareError(Exception):
  """An error reported by a Vantage."""

  def __init__(self, message: str, raw_response: str):
    self.message = message
    self.raw_response = raw_response
    super().__init__(f"{message}, {raw_response}")


def find_error_string(resp: str) -> Optional[str]:
  """Return the contents of the reply's `es` parameter, or None if it carries none."""
  match = re.search(r'es"([^"]*)"', resp)
  return match.group(1) if match is not None else None


def check_fw_string_error(resp: str) -> None:
  """Raise if a reply reports an error.

  Args:
    resp: The reply as received from the machine.

  Raises:
    VantageFirmwareError: If the reply reports a non-zero error.
  """
  if "er" not in resp or "er0" in resp:
    return
  raise VantageFirmwareError(message=find_error_string(resp) or "Unknown error", raw_response=resp)
