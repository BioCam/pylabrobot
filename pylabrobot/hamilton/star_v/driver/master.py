"""The STAR V master module: the connection and the firmware protocol spoken over it.

A STAR V is reached over the network rather than over USB. Its gateway answers to `C0` and routes
to the instrument's modules, which are addressed by a longer, node-structured identifier than the
one a STAR uses.
"""

import re
from typing import Optional

from pylabrobot.hamilton.protocol.text.framing import assemble_command
from pylabrobot.hamilton.protocol.text.router import ReplyRouter
from pylabrobot.hamilton.star_v.driver.errors import check_fw_string_error
from pylabrobot.io.io import IOBase
from pylabrobot.io.socket import Socket

# The gateway ships with this address when its rotary switch selects a fixed IP.
DEFAULT_HOST = "192.168.1.1"

# A node identifier is longer than a STAR's two characters. Confirm against hardware before
# relying on reply matching for commands sent without an id.
MODULE_ID_LENGTH = 4

# The machine reserves id 0 for messages it sends unprompted, so ids start at 1.
MAX_ID = 2_147_483_647


class STARVDriver:
  """Interface for the Hamilton STAR V."""

  def __init__(
    self,
    host: str = DEFAULT_HOST,
    port: Optional[int] = None,
    read_timeout: int = 30,
    write_timeout: int = 30,
    io: Optional[IOBase] = None,
  ):
    """Create a new STAR V interface.

    Args:
      host: the instrument's IP address.
      port: the port its gateway listens on.
      read_timeout: timeout in seconds for reading a full response.
      write_timeout: timeout in seconds for writing a command.
      io: an already-built transport handle to use instead of opening one.

    Raises:
      ValueError: If neither a port nor a transport handle is given.
    """
    if io is None and port is None:
      raise ValueError("a port is required to reach a STAR V, or pass an already-built io")

    self.io: IOBase = io or Socket(
      human_readable_device_name="Hamilton STAR V",
      host=host,
      port=port,  # type: ignore[arg-type]
      read_timeout=read_timeout,
      write_timeout=write_timeout,
    )

    self._replies = ReplyRouter(
      io=self.io,
      module_id_length=MODULE_ID_LENGTH,
      parse_id=self.get_id_from_fw_response,
      raise_for_error=check_fw_string_error,
      read_timeout=read_timeout,
    )

  async def setup(self):
    await self.io.setup()
    self._replies.start()

  async def stop(self):
    self._replies.stop()
    await self.io.stop()

  async def send_command(
    self,
    module: str,
    command: str,
    auto_id: bool = True,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
    **kwargs,
  ) -> Optional[str]:
    """Assemble a firmware command and send it, returning the reply."""
    id_ = self._replies.next_id() if auto_id else None
    cmd = assemble_command(
      module=module,
      command=command,
      id_=id_,
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
    match = re.search(r"id(-?\d+)", resp)
    return int(match.group(1)) if match is not None else None
