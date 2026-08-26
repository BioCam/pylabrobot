"""Heater shaker firmware errors.

A heater shaker is addressed as module `T<index>` and reports failures in the module form,
`er<trace>`. What each trace number means is not documented here yet, so a failure carries the
number and the reply it came from.
"""

from pylabrobot.hamilton.protocol.text.framing import find_error_fields

MODULE_ID_LENGTH = 2
MASTER_MODULE_ID = "C0"


class HeaterShakerFirmwareError(Exception):
  """An error reported by a heater shaker."""

  def __init__(self, module: str, trace_information: int, raw_response: str):
    self.module = module
    self.trace_information = trace_information
    self.raw_response = raw_response
    super().__init__(f"{module} reported error {trace_information:02}, in reply {raw_response!r}")


def check_fw_string_error(resp: str) -> None:
  """Raise if a reply reports an error.

  Args:
    resp: The reply as received from the machine.

  Raises:
    HeaterShakerFirmwareError: If the reply reports a non-zero error.
  """
  fields = find_error_fields(
    resp,
    module_id_length=MODULE_ID_LENGTH,
    master_module_id=MASTER_MODULE_ID,
    other_module_ids=(),
  )
  for module, field in fields.items():
    raise HeaterShakerFirmwareError(
      module=module,
      trace_information=int(field.split("/")[-1]),
      raw_response=resp,
    )
