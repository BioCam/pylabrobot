"""The autoload: the belt and wheel that pull carriers onto the deck and push them back out."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver


@dataclass
class AutoloadConfiguration:
  """Device facts for the installed autoload."""

  firmware_version: Optional[str] = None
  """The autoload's firmware version, as reported."""


class Autoload:
  """The autoload.

  Reached as `driver.autoload`, on a machine that has one. It is addressed as `I0`, but the
  commands that raise its wheel go to the master, so this capability speaks to both.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[AutoloadConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the autoload's device facts. Defaults to `AutoloadConfiguration()`.
    """
    self._driver = driver
    self.configuration = configuration or AutoloadConfiguration()

  @property
  def track_range(self) -> range:
    """The tracks it can be moved to, which is the deck it runs along.

    Raises:
      RuntimeError: If setup has not run, so the deck size is not known.
    """
    if self._driver.configuration is None:
      raise RuntimeError("no configuration read; forgot to call `setup`?")
    return range(1, self._driver.configuration.instrument_size_slots + 1)

  # -- queries: one command each, reads only ---------------------------------

  async def request_firmware_version(self) -> str:
    """Request the autoload's firmware version.

    Returns:
      The version string, as reported.
    """
    resp: str = await self._driver.send_command(module="I0", command="RF")
    return resp.split("rf")[-1]

  # -- moves: one command each, moves the autoload ---------------------------

  async def initialize(self):
    """Initialize the autoload. This moves it."""
    return await self._driver.send_command(module="C0", command="II")

  async def move_to_safe_z(self):
    """Raise the carrier-handling wheel to its safe Z.

    Nothing may travel along the deck with the wheel down, so this comes before any move along
    the tracks.
    """
    return await self._driver.send_command(module="C0", command="IV")

  async def move_to_track(self, track: int):
    """Move the autoload along the deck to a track, raising the wheel first.

    Args:
      track: which track to move to, counted from 1.

    Raises:
      ValueError: If the track is not one this machine has.
      RuntimeError: If setup has not run.
    """
    tracks = self.track_range
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")
    await self.move_to_safe_z()
    return await self._driver.send_command(module="I0", command="XP", xp=f"{track:02}")

  # -- routines: composed of the above ---------------------------------------

  async def discover(self):
    """Read what autoload this is. Read-only: nothing moves."""
    self.configuration.firmware_version = await self.request_firmware_version()

  async def park(self):
    """Move the autoload out of the way, to the far end of the deck."""
    await self.move_to_track(self.track_range[-1])
