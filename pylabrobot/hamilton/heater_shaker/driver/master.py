"""The heater shaker box: the connection, and the shakers addressed over it.

Several shakers share one box and one wire, each addressed as module `T<index>`. A shaker can
also be reached through a STAR, which routes to the same module identifier - so a shaker takes the
reply router it should speak over rather than opening one of its own.
"""

from typing import Optional

from pylabrobot.hamilton.heater_shaker.driver.errors import (
  MODULE_ID_LENGTH,
  check_fw_string_error,
)
from pylabrobot.hamilton.protocol.text.framing import assemble_command, parse_fw_string
from pylabrobot.hamilton.protocol.text.router import ReplyRouter
from pylabrobot.io.io import IOBase
from pylabrobot.io.usb import USB

ID_VENDOR = 0x08AF
ID_PRODUCT = 0x8002


def get_id_from_fw_response(resp: str) -> Optional[int]:
  """Get the id from a firmware response."""
  parsed = parse_fw_string(resp, "id####")
  if "id" in parsed and parsed["id"] is not None:
    return int(parsed["id"])
  return None


class HeaterShakerBox:
  """The control box several heater shakers are connected to."""

  def __init__(
    self,
    device_address: Optional[int] = None,
    serial_number: Optional[str] = None,
    packet_read_timeout: int = 3,
    read_timeout: int = 30,
    write_timeout: int = 30,
    io: Optional[IOBase] = None,
  ):
    """Create a new heater shaker box interface.

    Args:
      device_address: the USB device address. Only useful if using more than one Hamilton machine
        over USB.
      serial_number: the serial number. Only useful if using more than one Hamilton machine over
        USB.
      packet_read_timeout: timeout in seconds for reading a single packet.
      read_timeout: timeout in seconds for reading a full response.
      write_timeout: timeout in seconds for writing a command.
      io: an already-built transport handle to use instead of opening one.
    """
    self.io: IOBase = io or USB(
      human_readable_device_name="Hamilton Heater Shaker Box",
      id_vendor=ID_VENDOR,
      id_product=ID_PRODUCT,
      device_address=device_address,
      write_timeout=write_timeout,
      serial_number=serial_number,
    )

    self.replies = ReplyRouter(
      io=self.io,
      module_id_length=MODULE_ID_LENGTH,
      parse_id=get_id_from_fw_response,
      raise_for_error=check_fw_string_error,
      packet_read_timeout=packet_read_timeout,
      read_timeout=read_timeout,
    )

  async def setup(self):
    await self.io.setup()
    self.replies.start()

  async def stop(self):
    self.replies.stop()
    await self.io.stop()


class HeaterShakerDriver:
  """One heater shaker, addressed over a reply router it does not own.

  The router belongs to whatever the shaker is plugged into - its own box, or a STAR that routes
  to the same module identifier.
  """

  def __init__(self, index: int, replies: ReplyRouter):
    """
    Args:
      index: the shaker's index on the box it is connected to, addressed as module `T<index>`.
      replies: the reply router to speak over, from a `HeaterShakerBox` or a STAR.
    """
    if index < 0:
      raise ValueError("Shaker index must be non-negative")
    self.index = index
    self.replies = replies

  @property
  def module(self) -> str:
    """The module identifier this shaker answers to."""
    return f"T{self.index}"

  async def send_command(
    self,
    command: str,
    auto_id: bool = True,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
    **kwargs,
  ) -> Optional[str]:
    """Assemble a firmware command for this shaker and send it, returning the reply."""
    id_ = self.replies.next_id() if auto_id else None
    cmd = assemble_command(
      module=self.module,
      command=command,
      id_=id_,
      **kwargs,
    )
    return await self.replies.send(
      cmd=cmd,
      id_=id_,
      write_timeout=write_timeout,
      read_timeout=read_timeout,
      wait=wait,
    )
