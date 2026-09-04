"""The front cover: the hinged window over the deck, and whether the machine may move with it open."""

import logging
from typing import TYPE_CHECKING, Dict, Literal, cast

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

# Whether the cover is shut, as the master answers.
CoverPosition = Literal["open", "closed"]

# What the master answers for each position. The master's own protocol rather than anything the
# cover reports: it has no module of its own, so there is nothing to read and nothing to vary.
COVER_POSITION_CODES: Dict[CoverPosition, int] = {"open": 0, "closed": 1}


class FrontCover:
  """The front cover.

  Reached as `driver.front_cover`.

  Control module(s): `C0`/master only (no module of its own and no firmware version to report).
  """

  def __init__(self, driver: "STARDriver"):
    """
    Args:
      driver: the driver to send commands through.
    """
    self._driver = driver

  # -- position --------------------------------------------------------------

  async def request_state(self) -> CoverPosition:
    """Request whether the cover is open or shut.

    Returns:
      Which one, as named in `COVER_POSITION_CODES`.
    """
    resp = await self._driver.send_command(module="C0", command="QC", fmt="qc#")
    code = cast(int, resp["qc"])
    return "closed" if code == COVER_POSITION_CODES["closed"] else "open"

  # -- the lock --------------------------------------------------------------
  # TODO: verify whether lock mentioned in firmware actually exists on hardware
  # async def lock(self):
  #   """Lock the cover.

  #   Raises:
  #     STARFirmwareError: If it is not shut, which the master answers as a cover close error.
  #   """
  #   return await self._driver.send_command(module="C0", command="CO", subsystem="C0")

  # async def unlock(self):
  #   """Unlock the cover."""
  #   return await self._driver.send_command(module="C0", command="HO", subsystem="C0")

  # -- firmware-based enforcement of cover being closed during operation ------

  async def enable_control(self):
    """Enable cover control: the interlock.

    With it enabled, a motion command sent while the cover is open is refused. Nothing reports
    whether it is on, so a caller that needs to know has to track what it set.
    """
    return await self._driver.send_command(module="C0", command="CE", subsystem="C0")

  async def disable_control(self):
    """Disable cover control, so motion is no longer refused while the cover is open.

    This removes the interlock, and nothing reports that it is gone.
    """
    return await self._driver.send_command(module="C0", command="CD", subsystem="C0")
