"""The drawer: carries a plate in and out of the reader."""

import logging
from typing import TYPE_CHECKING, Optional

from pylabrobot.resources import Coordinate, PlateHolder

from ..commands import Command, CommandFamily

if TYPE_CHECKING:
  from ..driver import CLARIOstarDriver

logger = logging.getLogger(__name__)


class Drawer:
  """The drawer (DRAWER command family, 0x03).

  Reached as `driver.drawer`. With `plate_holder`, `location_in` and `location_out` set, every move
  and every `request_open` records on the plate holder where the drawer is.
  """

  # Seconds a move may take: about 2.5x the slowest close measured (7.9 s); an open takes 4.2 s.
  _MOVE_TIMEOUT = 20.0

  def __init__(self, driver: "CLARIOstarDriver"):
    """
    Args:
      driver: the driver to send commands through.
    """
    self._driver = driver
    self.plate_holder: Optional[PlateHolder] = None
    self.location_in: Optional[Coordinate] = None
    self.location_out: Optional[Coordinate] = None

  def _record_position(self, drawer_open: bool) -> None:
    """Move the plate holder to where the drawer is; does nothing until all three are set."""
    if self.plate_holder is None or self.location_in is None or self.location_out is None:
      return
    self.plate_holder.location = self.location_out if drawer_open else self.location_in

  async def request_open(self) -> bool:
    """Request whether the drawer is out, and record it on the plate holder."""
    drawer_open = bool((await self._driver.request_status())["drawer_open"])
    self._record_position(drawer_open)
    return drawer_open

  async def _record_where_it_stopped(self) -> None:
    """Read where the drawer is after a move, for the move's `finally`.

    Its own failure is logged and swallowed: it must not replace the move's exception.
    """
    try:
      await self.request_open()
    except Exception:
      logger.warning("could not read whether the CLARIOstar drawer is open; its model is stale")

  async def _move(self, open_drawer: bool) -> None:
    """Move the drawer, wait until it is where it was told to go, then record where it is.

    A move is done when the device is idle and `drawer_open` reads the target: `busy` alone is
    shared with measurements, and `drawer_open` reaches the target before the drawer comes to rest.

    Raises:
      TimeoutError: if the drawer is not there within `_MOVE_TIMEOUT` seconds.
    """
    try:
      await self._driver.send_command(
        CommandFamily.DRAWER,
        Command.DRAWER_OPEN if open_drawer else Command.DRAWER_CLOSE,
        parameters=b"\x00\x00\x00\x00",
      )
      await self._driver._wait_until_ready(
        timeout=self._MOVE_TIMEOUT,
        poll_interval=0.1,
        until=lambda status: not status["busy"] and status["drawer_open"] == open_drawer,
      )
    finally:
      # Whether the move succeeded or not: one that stopped part way left the drawer anywhere.
      await self._record_where_it_stopped()

  async def open(self) -> None:
    """Move the drawer out (about 4 s)."""
    await self._move(open_drawer=True)
    logger.info("CLARIOstar drawer open")

  async def close(self) -> None:
    """Move the drawer in (about 8 s)."""
    await self._move(open_drawer=False)
    logger.info("CLARIOstar drawer closed")

  async def request_plate_detected(self) -> bool:
    """Request whether the reader detects a plate."""
    return bool((await self._driver.request_status())["plate_detected"])
