"""The pipetting channels: the row of independently driven pipettes on an arm."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver


@dataclass
class PipettesConfiguration:
  """Device facts for the pipetting channels.

  The encoder resolutions convert between the units a command carries on the wire (increments)
  and the units the driver speaks (mm, uL). They are properties of the channel hardware, so they
  are defaulted here and can be overridden per machine.
  """

  y_drive_mm_per_increment: float = 0.046302083
  z_drive_mm_per_increment: float = 0.01072765
  dispensing_drive_mm_per_increment: float = 0.002734375
  dispensing_drive_uL_per_increment: float = 0.046876


class Pipettes:
  """The pipetting channels.

  Reached as `driver.pipettes`. Individual channels are addressed as `P1`..`PG`, but the commands
  that act on all of them at once go to the master, so this capability speaks to both.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[PipettesConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the channels' device facts. Defaults to `PipettesConfiguration()`.
    """
    self._driver = driver
    self.configuration = configuration or PipettesConfiguration()

  @property
  def num_channels(self) -> int:
    """How many channels are fitted, as counted at setup."""
    return self._driver.num_channels

  async def move_all_to_z_safety(self):
    """Move every channel up to its Z safety position.

    Nothing may move in X or Y while a channel is low, so this is the precondition for any
    lateral move. The instrument's initialization procedure does it as a side effect; on a
    machine that is already initialized it has to be asked for.
    """
    return await self._driver.send_command(module="C0", command="ZA")
