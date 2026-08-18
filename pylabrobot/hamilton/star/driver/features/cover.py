"""The front cover: the hinged window over the deck, and whether the machine may move with it open."""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Literal, Optional, cast

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

# Whether the cover is shut, as the master answers.
CoverPosition = Literal["open", "closed"]


@dataclass
class FrontCoverConfiguration:
  """Device facts for the front cover.

  Whether a cover, a lock and their monitoring are fitted is not here: the master reports that in
  its own configuration, as `left_cover_installed`, `right_cover_installed`,
  `main_front_cover_monitoring_installed` and `additional_front_cover_monitoring_installed`.
  """

  positions: Dict[CoverPosition, int] = field(default_factory=lambda: {"open": 0, "closed": 1})


class FrontCover:
  """The front cover.

  Reached as `driver.front_cover`. It is the master's own, with no module of its own and no
  firmware version to report, so there is nothing to discover: every command below goes to `C0`.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[FrontCoverConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the front cover's device facts. Defaults to `FrontCoverConfiguration()`.
    """
    self._driver = driver
    self.configuration = configuration or FrontCoverConfiguration()

  async def request_presence_of_front_cover(self) -> bool:
    """Request the cover input, the first of the three on the cover connector.

    The master documents it only as set or not set, so what it reports - a cover fitted, a cover
    shut, a lock engaged - is not stated. `request_position` is the one that says open or shut.

    Returns:
      Whether the input is set.

    Raises:
      ValueError: If the machine answered with fewer than three inputs.
    """
    resp = cast(str, await self._driver.send_command(module="C0", command="RW"))
    read = resp.split("rw", 1)[-1].strip().strip("'")
    if len(read) < 3:
      raise ValueError(f"expected three inputs in the reply: {resp!r}")
    return read[0] == "1"

  # -- position --------------------------------------------------------------

  async def request_position(self) -> CoverPosition:
    """Request whether the cover is open or shut.

    Returns:
      Which one, as named in `configuration.positions`.
    """
    resp = await self._driver.send_command(module="C0", command="QC", fmt="qc#")
    code = cast(int, resp["qc"])
    return "closed" if code == self.configuration.positions["closed"] else "open"

  # -- the lock --------------------------------------------------------------
  # TODO: verify whether lock mentioned in firmware actually exists on hardware
  # async def lock(self):
  #   """Lock the cover.

  #   Raises:
  #     STARFirmwareError: If it is not shut, which the master answers as a cover close error.
  #   """
  #   return await self._driver.send_command(module="C0", command="CO")

  # async def unlock(self):
  #   """Unlock the cover."""
  #   return await self._driver.send_command(module="C0", command="HO")

  # -- firmware-based enforcement of cover being closed during operation ------

  async def enable_control(self):
    """Enable cover control: the interlock.

    With it enabled, a motion command sent while the cover is open is refused. Nothing reports
    whether it is on, so a caller that needs to know has to track what it set.
    """
    return await self._driver.send_command(module="C0", command="CE")

  async def disable_control(self):
    """Disable cover control, so motion is no longer refused while the cover is open.

    This removes the interlock, and nothing reports that it is gone.
    """
    return await self._driver.send_command(module="C0", command="CD")
