"""The X-arm: the carriage that runs along a rail and carries whatever is mounted on it."""

import datetime
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Literal, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import parse_firmware_version_date
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

# The command set splits at firmware 5.0: the ranges and encodings below were recorded from an arm
# below it, which is the generation this driver has been driven against. A 5.0 or higher arm takes
# a wider current limiter, written in two digits rather than one, and has moves this one does not.
RECORDED_FIRMWARE_BELOW_MAJOR = 5


@dataclass
class XArmConfiguration:
  """Configuration and geometry for an X drive (left or right).

  The installed-module bits combine byte 1 (xl/xr) and byte 2 (xn/xo). The arm
  geometry - width, travel range, workspace range - comes from the X-drive range (RU)
  and working-envelope (UA) queries, so it is None on a drive built from the module
  bits alone (e.g. a simulated configuration) and populated when
  `request_extended_configuration` builds the drive. `model` and `reference_point`
  follow from `width`.

  Note: the installed modules on left and right drives must be different.
  """

  pip_installed: bool = False
  iswap_installed: bool = False
  head96_installed: bool = False
  nano_pipettor_installed: bool = False
  dispensing_head_384_installed: bool = False
  xl_channels_installed: bool = False
  tube_gripper_installed: bool = False
  imaging_channel_installed: bool = False
  robotic_channel_installed: bool = False

  width: Optional[float] = None
  x_range: Optional[Tuple[float, float]] = None
  workspace_range: Optional[Tuple[float, float]] = None
  wrap_size: Optional[float] = None  # zero when no arm is installed
  firmware_version: Optional[str] = None

  # -- device facts of the drive, the same for every arm of this generation --
  x_mm_per_increment: float = 0.1
  x_increment_range: Tuple[int, int] = (0, 30_000)  # what the move accepts; x_range is narrower
  acceleration_level_range: Tuple[int, int] = (1, 5)  # index into five curves, not a rate
  acceleration_level_default: int = 4
  current_limit_range: Tuple[int, int] = (0, 7)
  current_limit_default: int = 7

  # -- conversions: the wire counts in steps, the driver speaks mm ---------------------------

  def x_increments_to_mm(self, increments: int) -> float:
    """Where along its rail the arm is, in mm, from the steps the drive counts in."""
    return round(increments * self.x_mm_per_increment, 2)

  def x_mm_to_increments(self, mm: float) -> int:
    """An arm position in steps, from mm."""
    return round(mm / self.x_mm_per_increment)

  @property
  def model(self) -> str:
    """Arm variant derived from `width`: wide arms span both rails, narrow arms one."""
    if self.width is None:
      raise RuntimeError("arm geometry not resolved")
    if self.width > 300:
      return "hamilton_legacy_star_dual_rail_arm"
    return "hamilton_legacy_star_single_right_rail_arm"

  @property
  def reference_point(self) -> Literal["center", "right"]:
    """Where along the arm's width the tracked X refers to: the arm center for a
    dual-rail arm, the right edge for a single-rail arm."""
    if self.width is None:
      raise RuntimeError("arm geometry not resolved")
    return "center" if self.width > 300 else "right"


# Where along an arm's width its x refers to, as the anchor `Resource.get_anchor` takes.
REFERENCE_ANCHORS: Dict[Literal["center", "right"], Literal["l", "c", "r"]] = {
  "center": "c",
  "right": "r",
}


class XArm:
  """One X-arm, on the left or the right rail.

  Reached as `driver.left_x_arm` / `driver.right_x_arm`. Its `configuration` is the arm's own
  slice of what the driver read off the machine at setup: what is mounted on the arm, how wide it
  is, how far it travels, and the workspace that travel reaches.
  """

  def __init__(self, driver: "STARDriver", side: Literal["left", "right"] = "left"):
    """
    Args:
      driver: the driver to send commands through.
      side: which rail this arm runs on. A STAR always has a left arm; a right arm is an option.
    """
    self._driver = driver
    # The arm on the deck, when the driver was given one. Setup puts it there; moves keep it in
    # step. Without a deck it stays None and nothing is modelled.
    self.resource: Optional[Resource] = None
    self.side = side

  @property
  def parameter_prefix(self) -> str:
    """The letter every parameter to this arm's drive starts with: `l` on the left, `s` on the
    right. The X-drive board carries a drive per arm, each with its own commands."""
    return "l" if self.side == "left" else "s"

  # -- session / discovery ---------------------------------------------------

  @property
  def configuration(self) -> XArmConfiguration:
    """This arm's configuration and geometry.

    Raises:
      RuntimeError: If setup has not run, so no configuration has been read yet.
      ValueError: If no arm is installed on this rail.
    """
    configuration = self._driver.configuration
    if configuration is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    arm = configuration.left_arm if self.side == "left" else configuration.right_arm
    if arm is None:
      raise ValueError(f"no {self.side} X-arm is installed")
    return arm

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    """Request the X-drive board's firmware version and build date.

    Both arms run off the same board, so this reports the same for either side.

    Returns:
      The version string and its build date, e.g. `("1.4S 2012-04-25", date(2012, 4, 25))`.
    """
    resp = await self._driver.send_command(module="X0", command="RF")
    return resp.split("rf")[-1], parse_firmware_version_date(resp)

  async def request_initialization_status(self) -> bool:
    """Request whether this arm's drive reports itself initialized.

    Returns:
      Whether it is initialized.
    """
    resp = await self._driver.send_command(
      module="X0", command="QW", fmt="qw#", mn="1" if self.side == "left" else "2"
    )
    return cast(int, resp["qw"]) == 1

  async def discover(self):
    """Read what this arm is. Read-only: nothing moves."""
    version, _ = await self.request_firmware_version()
    self.configuration.firmware_version = version
    major = version.split(".", 1)[0]
    if major.isdigit() and int(major) >= RECORDED_FIRMWARE_BELOW_MAJOR:
      logger.warning(
        "this X-arm reports firmware %s; the ranges and encodings here were recorded from an arm "
        "below %d.0, so its current limiter and the moves it accepts may differ. Set them on "
        "XArmConfiguration to correct it.",
        version,
        RECORDED_FIRMWARE_BELOW_MAJOR,
      )

  # -- initialization --------------------------------------------------------

  async def initialize(self, current_limit: Optional[int] = None):
    """Initialize this arm's drive. This moves it.

    Args:
      current_limit: the motor current limit. Defaults to
        `configuration.current_limit_default`.

    Raises:
      ValueError: If the current limit is outside what the drive accepts.
    """
    c = self.configuration
    # The parameter is sent, so what the drive does is written here rather than left to the drive's
    # own default, which nothing would record.
    current_limit = c.current_limit_default if current_limit is None else current_limit
    low, high = c.current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    parameters: Dict[str, Any] = {f"{self.parameter_prefix}w": f"{current_limit:01}"}
    return await self._driver.send_command(
      module="X0", command="XI" if self.side == "left" else "SI", **parameters
    )

  # -- x motion --------------------------------------------------------------

  async def request_position(self) -> float:
    """Request where along its rail the arm is.

    Each drive has its own read, answering with the position twice - in tenths of a millimetre and
    in motor counts. The first is what this returns.

    The machine is the authority on where the arm is, so what it answers is recorded on the
    resource that models it.

    Returns:
      The position in mm.

    Raises:
      ValueError: If the machine answered without a position.
    """
    read_command = "RX" if self.side == "left" else "RS"
    resp = cast(str, await self._driver.send_command(module="X0", command=read_command))
    read = resp.split(read_command.lower(), 1)[-1].strip().strip("'\u201a\u201b").split()
    if not read:
      raise ValueError(f"no position in the reply: {resp!r}")
    x = self.configuration.x_increments_to_mm(int(read[0]))
    self.update_location_by_reference_point(x)
    return x

  async def move_x(
    self,
    x: float,
    acceleration_level: int = 3,
    current_limit: int = 7,
  ):
    """Move the arm to an absolute X position.

    Collision risk: this moves the arm and everything mounted on it, with no regard for what is
    in the way.

    Args:
      x: target X position in mm, at the arm's reference point. Must lie within the arm's travel
        range (`configuration.x_range`).
      acceleration_level: which acceleration curve to use. The drive's own default is
        `configuration.acceleration_level_default`; this is the gentler one legacy sends.
      current_limit: the motor current limit.

    Raises:
      ValueError: If `x` is outside the arm's travel range, or an argument is out of range.
      RuntimeError: If the arm's geometry was not resolved.
    """
    c = self.configuration
    self._check_reachable(x)
    low, high = c.acceleration_level_range
    if not low <= acceleration_level <= high:
      raise ValueError(
        f"acceleration_level must be between {low} and {high}, is {acceleration_level}"
      )
    low, high = c.current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    try:
      p = self.parameter_prefix
      parameters: Dict[str, Any] = {
        f"{p}a": f"{c.x_mm_to_increments(x):05}",
        f"{p}r": f"{acceleration_level:01}",
        f"{p}w": f"{current_limit:01}",
      }
      resp = await self._driver.send_command(
        module="X0", command="XP" if self.side == "left" else "SP", **parameters
      )
    except BaseException:
      # The arm stopped somewhere neither the old position nor the target describes, so ask the
      # machine where it ended up.
      try:
        await self.request_position()
      except BaseException:
        logger.warning("could not read where the %s X-arm stopped; its model is stale", self.side)
      raise

    # Where it was told to go, and then where it actually went: the drive settles short of the
    # target by an increment or two, so the machine's own read is what the model keeps.
    self.update_location_by_reference_point(x)
    x_reached = await self.request_settled_position()
    if x_reached != x:
      logger.debug(
        "the %s X-arm was sent to %s mm and came to rest at %s mm", self.side, x, x_reached
      )
    return resp

  @property
  def reference_anchor(self) -> Literal["l", "c", "r"]:
    """Where along its width this arm's x refers to, as a resource anchor."""
    return REFERENCE_ANCHORS[self.configuration.reference_point]

  async def request_settled_position(self, reads: int = 20) -> float:
    """Read where the arm is until it stops changing, and answer that.

    A move's reply arrives when the move ends, not when the arm stops: driven hard it overshoots
    and comes back, and read immediately it is out by up to 0.4 mm. Two reads that agree to within
    an increment mean it has stopped.

    Args:
      reads: how many reads to spend waiting. Each is a command round trip, about 10 ms, against a
        settle of 27 to 90 ms where this was measured - so the default gives up well past that
        rather than hanging on a drive that never stops.

    Returns:
      The position in mm, once two reads agree.
    """
    settled = await self.request_position()
    for _ in range(reads):
      again = await self.request_position()
      if abs(again - settled) <= self.configuration.x_mm_per_increment:
        return again
      settled = again
    logger.warning("the %s X-arm is still moving after %d reads", self.side, reads)
    return settled

  def update_location_by_reference_point(self, x: float) -> None:
    """Record where this arm is on the resource that models it.

    The machine positions the arm by its reference point - the centre of a dual-rail arm, the right
    edge of a single-rail one - while a resource is located by its left front bottom corner, so the
    two differ by the arm's own anchor. Does nothing when the driver was given no deck, and so has
    nothing to model.

    Args:
      x: where the reference point is now, in mm.
    """
    if self.resource is None or self.resource.location is None:
      return
    anchor = self.resource.get_anchor(x=self.reference_anchor)
    self.resource.location = Coordinate(
      x - anchor.x, self.resource.location.y, self.resource.location.z
    )

  async def move_x_relative(
    self,
    distance: float,
    acceleration_level: int = 3,
    current_limit: int = 7,
  ):
    """Move the arm by a distance from where it is now.

    Collision risk: this moves the arm and everything mounted on it, with no regard for what is
    in the way.

    Where the arm is is read from the machine and the distance added to it, so a relative move is
    an absolute move to a place worked out here - and is bounded by the arm's travel range like any
    other.

    Args:
      distance: how far to move, in mm. Positive moves along the rail towards higher x, negative
        towards lower.
      acceleration_level: which acceleration curve to use.
      current_limit: the motor current limit.

    Raises:
      ValueError: If the arm would end up outside its travel range, or an argument is outside what
        the drive accepts.
      RuntimeError: If the arm's geometry was not resolved.
    """
    return await self.move_x(
      await self.request_position() + distance,
      acceleration_level=acceleration_level,
      current_limit=current_limit,
    )

  async def switch_drive_power_off(self):
    """Switch this arm's drive power off, leaving it free to be pushed by hand."""
    return await self._driver.send_command(
      module="X0", command="XO" if self.side == "left" else "SO"
    )

  def _check_reachable(self, x: float) -> None:
    """Raise if `x` is outside this arm's travel range.

    `x` is the arm's position at its reference point - its center on a dual-rail arm, its right
    edge on a single-rail arm - so the bound is that point's travel, not the wider workspace the
    arm reaches around it.

    Args:
      x: target X position in mm.

    Raises:
      RuntimeError: If the arm's geometry was not resolved.
      ValueError: If `x` is outside the travel range.
    """
    x_range = self.configuration.x_range
    if x_range is None:
      raise RuntimeError(f"{self.side} X-arm geometry not resolved")
    x_min, x_max = x_range
    if not x_min <= x <= x_max:
      raise ValueError(
        f"{self.side} X-arm x={x}mm is outside its drive travel range [{x_min}, {x_max}]."
      )
