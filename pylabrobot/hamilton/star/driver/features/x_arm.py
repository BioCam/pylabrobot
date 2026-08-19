"""The X-arm: the carriage that runs along a rail and carries whatever is mounted on it."""

import datetime
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import parse_firmware_version_date
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.hamilton.hamilton_decks import X_ARM_REFERENCE_ANCHORS
from pylabrobot.resources.resource import Resource

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

# The command set splits at firmware 5.0: the ranges and encodings below were recorded from an arm
# below it, which is the generation this driver has been driven against. A 5.0 or higher arm takes
# a wider current limiter, written in two digits rather than one, and has moves this one does not.
RECORDED_FIRMWARE_BELOW_MAJOR = 5

# Which way a relative move goes, and the code the command takes for each.
XDirection = Literal["positive", "negative"]


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
  x_relative_increment_range: Tuple[int, int] = (1, 30_000)
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

    Raises:
      NotImplementedError: If this is the right arm.
    """
    self._require_left()
    resp = await self._driver.send_command(module="X0", command="QW", fmt="qw#", mn="1")
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

  def _require_left(self) -> None:
    """Raise if this is the right arm, whose drive is a command family nothing has driven."""
    if self.side != "left":
      raise NotImplementedError("driving the right X-arm is not ported yet")

  # -- initialization --------------------------------------------------------

  async def initialize(self, current_limit: Optional[int] = None):
    """Initialize this arm's drive. This moves it.

    Args:
      current_limit: the motor current limit. Defaults to
        `configuration.current_limit_default`.

    Raises:
      ValueError: If the current limit is outside what the drive accepts.
      NotImplementedError: If this is the right arm.
    """
    self._require_left()
    c = self.configuration
    # The parameter is sent, so what the drive does is written here rather than left to the drive's
    # own default, which nothing would record.
    current_limit = c.current_limit_default if current_limit is None else current_limit
    low, high = c.current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    return await self._driver.send_command(module="X0", command="XI", lw=f"{current_limit:01}")

  # -- x motion --------------------------------------------------------------

  async def request_position(self) -> float:
    """Request where along its rail the arm is.

    The left arm is read from the X-drive board, which answers with the position twice, in tenths
    of a millimetre and in motor counts; the first is what this returns. The right arm has no such
    read of its own and is asked of the master instead.

    Returns:
      The position in mm.

    Raises:
      ValueError: If the machine answered without a position.
    """
    if self.side == "left":
      resp = cast(str, await self._driver.send_command(module="X0", command="RX"))
    else:
      resp = cast(str, await self._driver.send_command(module="C0", command="QX"))
    read = resp.split("rx", 1)[-1].strip().strip("'\u201a\u201b").split()
    if not read:
      raise ValueError(f"no position in the reply: {resp!r}")
    return self.configuration.x_increments_to_mm(int(read[0]))

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
      NotImplementedError: If this is the right arm.
    """
    self._require_left()
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

    resp = await self._driver.send_command(
      module="X0",
      command="XP",
      la=f"{c.x_mm_to_increments(x):05}",
      lr=f"{acceleration_level:01}",
      lw=f"{current_limit:01}",
    )
    # Only once the machine has answered: a move that raised leaves the arm somewhere unknown, and
    # a resource that says otherwise would be worse than one that is stale.
    self.update_location_by_reference_point(x)
    return resp

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
    anchor = self.resource.get_anchor(x=X_ARM_REFERENCE_ANCHORS[self.configuration.reference_point])
    self.resource.location = Coordinate(
      x - anchor.x, self.resource.location.y, self.resource.location.z
    )

  async def move_x_relative(
    self,
    distance: float,
    direction: XDirection = "positive",
    acceleration_level: int = 3,
    current_limit: int = 7,
  ):
    """Move the arm by a distance from where it is.

    Collision risk: this moves the arm and everything mounted on it, with no regard for what is
    in the way. Where it ends up is not checked against the arm's travel range, since where it
    starts is only known by asking.

    Args:
      distance: how far to move, in mm.
      direction: which way to go along the rail.
      acceleration_level: which acceleration curve to use.
      current_limit: the motor current limit.

    Raises:
      ValueError: If an argument is outside what the drive accepts.
      NotImplementedError: If this is the right arm.
    """
    self._require_left()
    c = self.configuration
    increments = c.x_mm_to_increments(distance)
    low, high = c.x_relative_increment_range
    if not low <= increments <= high:
      raise ValueError(
        f"distance must be between {c.x_increments_to_mm(low)} and {c.x_increments_to_mm(high)} "
        f"mm, is {distance}"
      )
    low, high = c.acceleration_level_range
    if not low <= acceleration_level <= high:
      raise ValueError(
        f"acceleration_level must be between {low} and {high}, is {acceleration_level}"
      )
    low, high = c.current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    return await self._driver.send_command(
      module="X0",
      command="XR",
      ls=f"{increments:05}",
      lt="0" if direction == "positive" else "1",
      lr=f"{acceleration_level:01}",
      lw=f"{current_limit:01}",
    )

  async def switch_drive_power_off(self):
    """Switch this arm's drive power off, leaving it free to be pushed by hand.

    Raises:
      NotImplementedError: If this is the right arm.
    """
    self._require_left()
    return await self._driver.send_command(module="X0", command="XO")

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
