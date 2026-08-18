"""The STAR: the instrument, and what it knows about its own deck."""

import logging
from typing import Optional

from pylabrobot.hamilton.star.driver.features.autoload import Autoload
from pylabrobot.hamilton.star.driver.features.cover import FrontCover
from pylabrobot.hamilton.star.driver.features.head96 import Head96
from pylabrobot.hamilton.star.driver.features.iswap import iSWAP
from pylabrobot.hamilton.star.driver.features.pipettes import Pipettes
from pylabrobot.hamilton.star.driver.features.x_arm import XArm
from pylabrobot.hamilton.star.driver.master import STARDriver
from pylabrobot.hamilton.star.driver.simulator import STARSimulationDriver
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.hamilton import HamiltonSTARDeck, STARDeck, STARLetDeck
from pylabrobot.resources.resource import Resource

logger = logging.getLogger(__name__)

# Where the deck sits in the instrument. It is placed at the instrument's origin, and the
# instrument is given the deck's own footprint, until something needs either to be more than that.
# Where the deck sits inside the instrument. Provisional, pending measurement on a rig:
#   x  the chassis' left face read against the iSWAP's kinematic reach, 13.2 mm wider than the
#      drawing's iSWAP areas allow, so good to about a centimetre
#   y  the deck origin behind the front face, on the reading that a carrier's back edge meets the
#      back of the iSWAP area: 795 - 119 - 560 on a STAR, 790 - 124 - 560 on a STARlet
#   z  the deck work surface sits 100 mm above the instrument origin, which the manual states; this
#      is the origin's own height above the instrument's base, and is not sourced
STAR_DECK_LOCATION = Coordinate(121.8, 116.0, 78.5)
STARLET_DECK_LOCATION = Coordinate(121.8, 106.0, 78.5)


class STARDevice(Resource):
  """The complete modelling and control interface for a Hamilton Microlab STAR.

  The instrument is itself a resource and its deck is its child, so everything on the deck is a
  descendant of the machine carrying it: one tree, rooted here.

  Two tiers over one driver. `star.driver` speaks to the machine in its own terms - tracks,
  positions, millimetres - and stays reachable whatever is built on top of it. The device adds
  what the driver cannot know: where things are, and so which of them a command is about.
  """

  def __init__(
    self,
    deck: HamiltonSTARDeck,
    simulation: bool = False,
    driver: Optional[STARDriver] = None,
    name: str = "Generic STAR Device",
    size_x: Optional[float] = None,
    size_y: Optional[float] = None,
    size_z: Optional[float] = None,
    deck_location: Optional[Coordinate] = None,
    model: Optional[str] = None,
  ):
    """
    Args:
      deck: the deck this instrument carries. It becomes a child of the instrument, so everything
        assigned to it is a descendant of this device.
      simulation: whether to build a simulated instrument, which answers without one being plugged
        in. Superseded by `driver`, which says exactly what to drive.
      driver: the driver to drive the instrument through.
      name: what to call this instrument in the resource tree.
      size_x: how wide the instrument is, in mm. Defaults to the deck's own width.
      size_y: how deep it is, in mm. Defaults to the deck's own depth.
      size_z: how tall it is, in mm. Defaults to the deck's own height.
      deck_location: where the deck sits inside it. Defaults to the instrument's own origin.
      model: which machine this is. Defaults to the class name, which says only that it is a STAR.

    Raises:
      ValueError: If neither a driver nor simulation is given, since there is then nothing to
        drive.
    """
    if driver is None and not simulation:
      raise ValueError("pass a driver, or `simulation=True` to build a simulated one")
    if driver is not None and simulation:
      logger.warning("both a driver and simulation given; driving the driver")

    super().__init__(
      name=name,
      size_x=deck.get_absolute_size_x() if size_x is None else size_x,
      size_y=deck.get_absolute_size_y() if size_y is None else size_y,
      size_z=deck.get_absolute_size_z() if size_z is None else size_z,
      category="device",
      model=model if model is not None else self.__class__.__name__,
    )
    self.driver = driver if driver is not None else STARSimulationDriver()
    self.assign_child_resource(
      deck, location=deck_location if deck_location is not None else Coordinate(0, 0, 0)
    )

  @property
  def deck(self) -> HamiltonSTARDeck:
    """The deck this instrument carries.
    All capability resources are children of the deck, so they are descendants of the instrument.
    The deck is a child of the instrument, so the instrument is the root of the tree of all resources on it.

    Raises:
      RuntimeError: If it carries anything other than exactly one.
    """
    decks = [child for child in self.children if isinstance(child, HamiltonSTARDeck)]
    if len(decks) != 1:
      raise RuntimeError(f"{self.name} carries {len(decks)} decks, expected one")
    return decks[0]

  # -- what the instrument carries ------------------------------------------------------------
  # Read through: the optional ones do not exist until discovery says what is fitted.

  @property
  def left_x_arm(self) -> Optional[XArm]:
    """The left X-arm, on a machine that has one."""
    return self.driver.left_x_arm

  @property
  def right_x_arm(self) -> Optional[XArm]:
    """The right X-arm, on a machine that has one."""
    return self.driver.right_x_arm

  @property
  def x_arm(self) -> XArm:
    """The X-arm, on a machine that has only one.

    Raises:
      RuntimeError: If setup has not run.
      ValueError: If the machine has more than one arm.
    """
    return self.driver.x_arm

  @property
  def pipettes(self) -> Optional[Pipettes]:
    """The pipetting channels, on a machine that has some."""
    return self.driver.pipettes

  @property
  def front_cover(self) -> Optional[FrontCover]:
    """The front cover, on a machine whose configuration has its monitoring installed."""
    return self.driver.front_cover

  @property
  def head96(self) -> Optional[Head96]:
    """The 96-head, on a machine that has one."""
    return self.driver.head96

  @property
  def iswap(self) -> Optional[iSWAP]:
    """The iSWAP, on a machine that has one."""
    return self.driver.iswap

  @property
  def autoload(self) -> Optional[Autoload]:
    """The autoload, on a machine that has one."""
    return self.driver.autoload

  # -- session ---------------------------------------------------------------

  async def setup(self):
    """Bring the instrument up."""
    await self.driver.setup()

  async def stop(self):
    """Put the instrument down."""
    await self.driver.stop()

  def __str__(self) -> str:
    return f"{self.name}({self.driver.__class__.__name__}, {self.deck.num_rails}-track deck)"


# # # # Complete STAR Devices Factory Functions, for convenience in building a configuration.


def STAR(
  deck: Optional[HamiltonSTARDeck] = None,
  simulation: bool = False,
  driver: Optional[STARDriver] = None,
  name: str = "Hamilton Microlab STAR",
  size_x: float = 1_664.0,
  size_y: float = 795.0,
  size_z: float = 903.0,
) -> STARDevice:
  """A full-size STAR, on a full-size STAR deck."""
  return STARDevice(
    deck=deck if deck is not None else STARDeck(),
    simulation=simulation,
    driver=driver,
    name=name,
    size_x=size_x,
    size_y=size_y,
    size_z=size_z,
    deck_location=STAR_DECK_LOCATION,
    model=STAR.__name__,
  )


def STAR_with_extension_housing(
  deck: Optional[HamiltonSTARDeck] = None,
  simulation: bool = False,
  driver: Optional[STARDriver] = None,
  name: str = "Hamilton Microlab STAR (left extension housing)",
  size_x: float = 1_664.0 + 245.0,
  size_y: float = 795.0,
  size_z: float = 903.0,
) -> STARDevice:
  """A full-size STAR with the 245 mm extension housing on its left, on a full-size STAR deck.

  The housing extends the instrument to the left, so the deck sits that much further into it.
  """
  return STARDevice(
    deck=deck if deck is not None else STARDeck(),
    simulation=simulation,
    driver=driver,
    name=name,
    size_x=size_x,
    size_y=size_y,
    size_z=size_z,
    deck_location=STAR_DECK_LOCATION + Coordinate(245.0, 0.0, 0.0),
    model=STAR_with_extension_housing.__name__,
  )


def STARLet(
  deck: Optional[HamiltonSTARDeck] = None,
  simulation: bool = False,
  driver: Optional[STARDriver] = None,
  name: str = "Hamilton Microlab STARlet",
  size_x: float = 1_124.0,
  size_y: float = 790.0,
  size_z: float = 903.0,
) -> STARDevice:
  """A STARlet, on a STARlet deck."""
  return STARDevice(
    deck=deck if deck is not None else STARLetDeck(),
    simulation=simulation,
    driver=driver,
    name=name,
    size_x=size_x,
    size_y=size_y,
    size_z=size_z,
    deck_location=STARLET_DECK_LOCATION,
    model=STARLet.__name__,
  )


# TODO: STARPlus, once there is one to read a configuration off.
