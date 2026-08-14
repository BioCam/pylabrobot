"""The X-arm: the carriage that runs along a rail and carries whatever is mounted on it."""

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Optional, Tuple

from pylabrobot.hamilton.protocol.text.framing import parse_firmware_version_date

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver


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
  """Arm width (mm), from the machine configuration."""
  x_range: Optional[Tuple[float, float]] = None
  """Drive travel `(min, max)` in mm."""
  workspace_range: Optional[Tuple[float, float]] = None
  """Reachable X workspace `(min, max)` in mm."""
  wrap_size: Optional[float] = None
  """Arm wrap size in mm, from the working-envelope query. Zero means the arm is not installed,
  so a resolved arm always has a non-zero wrap."""

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
    self.side = side

  @property
  def configuration(self) -> XArmConfiguration:
    """This arm's configuration and geometry.

    Raises:
      RuntimeError: If setup has not run, so no configuration has been read yet.
      ValueError: If no arm is installed on this rail.
    """
    configuration = self._driver.configuration
    if configuration is None:
      raise RuntimeError("no configuration read; forgot to call `setup`?")
    arm = configuration.left_arm if self.side == "left" else configuration.right_arm
    if arm is None:
      raise ValueError(f"no {self.side} X-arm is installed")
    return arm

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    """Request the X-drive board's firmware version and build date.

    Both arms run off the same board, so this reports the same for either side.

    Returns:
      The version string and its build date, e.g. `("1.4S", date(2012, 4, 25))`.
    """
    resp = await self._driver.send_command(module="X0", command="RF")
    return resp.split("rf")[-1].split(" ")[0], parse_firmware_version_date(resp)

  async def move_x(
    self,
    x: float,
    acceleration_level: int = 3,
    current_protection_limiter: int = 7,
  ):
    """Move the arm to an absolute X position.

    Collision risk: this moves the arm and everything mounted on it, with no regard for what is
    in the way.

    Args:
      x: target X position in mm, at the arm's reference point. Must lie within the arm's travel
        range (`configuration.x_range`).
      acceleration_level: acceleration index, 1 to 5.
      current_protection_limiter: motor current limit, 0 to 7.

    Raises:
      ValueError: If `x` is outside the arm's travel range, or an argument is out of range.
      RuntimeError: If the arm's geometry was not resolved.
      NotImplementedError: If this is the right arm.
    """
    if self.side != "left":
      raise NotImplementedError("moving the right X-arm is not ported yet")
    self._check_reachable(x)
    if not 1 <= acceleration_level <= 5:
      raise ValueError(f"acceleration_level must be between 1 and 5, is {acceleration_level}")
    if not 0 <= current_protection_limiter <= 7:
      raise ValueError(
        f"current_protection_limiter must be between 0 and 7, is {current_protection_limiter}"
      )

    return await self._driver.send_command(
      module="X0",
      command="XP",
      la=f"{round(x * 10):05}",
      lr=str(acceleration_level),
      lw=str(current_protection_limiter),
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
