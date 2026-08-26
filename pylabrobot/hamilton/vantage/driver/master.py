"""The Vantage master module: the connection and the firmware protocol spoken over it."""

import re
from typing import List, Optional

from pylabrobot.hamilton.protocol.text.framing import assemble_channel_command
from pylabrobot.hamilton.protocol.text.router import ReplyRouter
from pylabrobot.hamilton.vantage.driver.errors import check_fw_string_error
from pylabrobot.io.io import IOBase
from pylabrobot.io.usb import USB

MODULE_ID_LENGTH = 4

ID_VENDOR = 0x08AF
ID_PRODUCT = 0x8003


class VantageDriver:
  """Interface for the Hamilton Vantage."""

  def __init__(
    self,
    device_address: Optional[int] = None,
    serial_number: Optional[str] = None,
    packet_read_timeout: int = 3,
    read_timeout: int = 30,
    write_timeout: int = 30,
    io: Optional[IOBase] = None,
  ):
    """Create a new Vantage interface.

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
      human_readable_device_name="Hamilton Vantage",
      id_vendor=ID_VENDOR,
      id_product=ID_PRODUCT,
      device_address=device_address,
      write_timeout=write_timeout,
      serial_number=serial_number,
    )

    self._replies = ReplyRouter(
      io=self.io,
      module_id_length=MODULE_ID_LENGTH,
      parse_id=self.get_id_from_fw_response,
      raise_for_error=check_fw_string_error,
      packet_read_timeout=packet_read_timeout,
      read_timeout=read_timeout,
    )

    self._num_channels: Optional[int] = None

  async def setup(self):
    await self.io.setup()
    self._replies.start()

  async def stop(self):
    self._replies.stop()
    await self.io.stop()

  @property
  def num_channels(self) -> int:
    """The number of pipette channels present on the robot."""
    if self._num_channels is None:
      raise RuntimeError("has not loaded num_channels, forgot to call `setup`?")
    return self._num_channels

  async def send_command(
    self,
    module: str,
    command: str,
    auto_id: bool = True,
    tip_pattern: Optional[List[bool]] = None,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
    **kwargs,
  ) -> Optional[str]:
    """Assemble a firmware command and send it, returning the reply."""
    id_ = self._replies.next_id() if auto_id else None
    # Always the channel-aware assembler: a list parameter has to be terminated against the
    # machine's channel count whether or not the caller named which channels are involved, and
    # `tip_pattern=None` means each list already holds one value per channel it names.
    #
    # The count is only read when there is a list to terminate. Discovery has to send commands
    # before it knows the count, and asking for it there would refuse the reads that establish it.
    carries_a_list = any(isinstance(value, list) for value in kwargs.values())
    cmd = assemble_channel_command(
      module=module,
      command=command,
      id_=id_,
      tip_pattern=tip_pattern,
      num_channels=self.num_channels if carries_a_list else 0,
      **kwargs,
    )
    return await self._replies.send(
      cmd=cmd,
      id_=id_,
      write_timeout=write_timeout,
      read_timeout=read_timeout,
      wait=wait,
    )

  def get_id_from_fw_response(self, resp: str) -> Optional[int]:
    """Get the id from a firmware response."""
    match = re.search(r"id(\d+)", resp)
    return int(match.group(1)) if match is not None else None
