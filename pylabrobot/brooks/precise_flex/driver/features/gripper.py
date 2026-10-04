"""The PreciseFlex gripper: the end-effector fitted at the arm's wrist, driven through the controller.

Reached as `driver.gripper`. The jaws are the controller's gripper axis (`Axis.GRIPPER`), commanded
through their open and close positions; a force-controlled grasp for `pickplate` is set up here.
Every move that closes the jaws senses force unless the caller passes `force_sensing=False`.
"""

import dataclasses
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from pylabrobot.events import evented_operation

from ...kinematics import Axis
from ..errors import PreciseFlexError

if TYPE_CHECKING:
  from ..master import PreciseFlex

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class PreciseFlexGripperConfiguration:
  """The gripper axis's facts, read at setup."""

  soft_limit_range: tuple
  hard_limit_range: tuple
  max_speed: float
  max_acceleration: float
  max_deceleration: float
  is_dual_gripper: bool = False


class PreciseFlexGripper:
  """The gripper fitted to a PreciseFlex arm: a servoed single gripper, or a dual one.

  Reached as `driver.gripper`. Sends through the driver's `send_command`.
  """

  # What the driver sends when a caller leaves the value out. Tune one gripper by assigning on the
  # instance, or every gripper by assigning on the class.
  default_finger_speed_percent: float = 50.0
  default_grasp_force: float = 10.0

  # Physical jaw range for the PF400 servoed gripper. Overridden at setup from the
  # gripper-axis soft limits (DataIDs 16078/16077, Axis.GRIPPER) when discoverable.
  jaw_width_range: Tuple[float, float] = (60.0, 145.0)
  # Gripper-axis soft limits (GripOpenPos/GripClosePos units), read at setup; None until then.
  _gripper_soft_min: Optional[float] = None
  _gripper_soft_max: Optional[float] = None

  def __init__(
    self, driver: "PreciseFlex", closed_gripper_position: float, is_dual_gripper: bool = False
  ) -> None:
    """
    Args:
      driver: the driver to send commands through.
      closed_gripper_position: firmware-unit value (passed to ``GripClosePos`` /
        ``GripOpenPos``) at which the jaws are at the narrow end of :attr:`jaw_width_range`.
      is_dual_gripper: whether two grippers are fitted. Discovery overrides it at setup.
    """
    self._driver = driver
    self.configuration: Optional[PreciseFlexGripperConfiguration] = None
    self.closed_gripper_position = closed_gripper_position
    self._is_dual_gripper = is_dual_gripper

  # -- session / discovery -------------------------------------------------------------------------

  def _adopt_configuration(self, configuration: PreciseFlexGripperConfiguration) -> None:
    """Take the jaw range from the gripper-axis soft limits, and whether two are fitted."""
    self.configuration = configuration
    gmin, gmax = configuration.soft_limit_range
    self._gripper_soft_min, self._gripper_soft_max = gmin, gmax
    self.jaw_width_range = (gmin, gmax)
    self._is_dual_gripper = configuration.is_dual_gripper

  # -- open and close positions --------------------------------------------------------------------

  async def _request_close_position(self) -> float:
    """Get the gripper close position for the servoed gripper.

    Returns:
      float: The current gripper close position.
    """
    data = await self._driver.send_command("GripClosePos")
    return float(data)

  async def _set_close_position(self, close_position: float) -> None:
    """Set the gripper close position for the servoed gripper.

    The close position may be changed by a force-controlled grip operation.

    Args:
      close_position: The new gripper close position.
    """
    await self._driver.send_command(f"GripClosePos {close_position}")

  async def _request_open_position(self) -> float:
    """Get the gripper open position for the servoed gripper.

    Returns:
      float: The current gripper open position.
    """
    data = await self._driver.send_command("GripOpenPos")
    return float(data)

  async def _set_open_position(self, open_position: float) -> None:
    """Set the gripper open position for the servoed gripper.

    Args:
      open_position: The new gripper open position.
    """
    await self._driver.send_command(f"GripOpenPos {open_position}")

  # -- grasp, for the force-controlled pickplate ---------------------------------------------------

  async def _request_grasp_data(self) -> tuple[float, float, float]:
    """Get the data to be used for the next force-controlled PickPlate command grip operation.

    Returns:
      A tuple containing (plate_width_mm, finger_speed_percent, grasp_force)
    """
    data = await self._driver.send_command("GraspData")
    parts = data.split()
    if len(parts) != 3:
      raise PreciseFlexError(-1, "Unexpected response format from GraspData command.")
    return (float(parts[0]), float(parts[1]), float(parts[2]))

  async def _set_grasp_data(
    self, plate_width: float, finger_speed_percent: float, grasp_force: float
  ) -> None:
    """Set the data to be used for the next force-controlled PickPlate command grip operation.

    This data remains in effect until the next GraspData command or the system is restarted.

    Args:
      plate_width: The plate width in mm.
      finger_speed_percent: The finger speed during grasp as a percentage (0-100). 100 = full speed.
      grasp_force: The gripper squeezing force, in Newtons.
      A positive value indicates the fingers must close to grasp.
      A negative value indicates the fingers must open to grasp.

    Raises:
      ValueError: If finger_speed_percent is not between 0 and 100.
    """
    if not 0 <= finger_speed_percent <= 100:
      raise ValueError(
        f"finger_speed_percent must be between 0 and 100, got {finger_speed_percent}"
      )
    await self._driver.send_command(f"GraspData {plate_width} {finger_speed_percent} {grasp_force}")

  # -- conversions: the wire counts in the axis's units, the driver speaks mm ----------------------

  def _mm_to_firmware_units(self, width_mm: float) -> float:
    """Convert a jaw width (mm) to the firmware's native position unit.

    Anchored at :attr:`closed_gripper_position`, which is the firmware value
    when the jaws are at the narrow end of :attr:`jaw_width_range`. Slope is 1 (1 mm = 1 unit).
    """
    return self.closed_gripper_position + (width_mm - self.jaw_width_range[0])

  # -- jaw motion: closing senses force unless asked not to ----------------------------------------

  async def _closes(self, units: float) -> bool:
    """Whether driving the jaws to `units` closes them, against the live gripper axis."""
    return units < (await self._driver.arm.request_joint_state())[Axis.GRIPPER]

  async def _move_jaws(self, units: float, force_sensing: Optional[bool]) -> None:
    """The one path that drives the jaws: to `units` on the gripper axis.

    Args:
      units: the gripper axis position, in the controller's units.
      force_sensing: None senses force when the move closes the jaws and not when it opens them.
    """
    if force_sensing is None:
      force_sensing = await self._closes(units)
    if force_sensing:
      await self._set_close_position(units)
      await self._driver.send_command("gripper 2")
    else:
      await self._set_open_position(units)
      await self._driver.send_command("gripper 1")

  @evented_operation(
    "precise_flex.move_gripper",
    lambda self, width, force_sensing=None: {
      "device": self._driver._controller_reference(),
      "width": float(width),
      "force_sensing": force_sensing,
    },
  )
  async def move_to_jaw_position(
    self,
    width: float,
    force_sensing: Optional[bool] = None,
  ):
    """Move the PreciseFlex gripper jaws.

    With force sensing the jaws drive to the close position with force feedback (``gripper 2``),
    which may stop short of ``width`` on contact; without it they drive to the open position
    (``gripper 1``) whichever way that is.

    Args:
      width: the jaw width to move to, in mm.
      force_sensing: None senses force when the move closes the jaws, read against the live
        gripper axis, and not when it opens them. Pass False only to close without it on purpose.

    Not interruptible: the ``gripper`` firmware command blocks the controller's command interpreter
    until the jaws finish (hardware-verified, like ``waitForEom``), so a user interrupt cannot halt it
    mid-travel - it is intentionally not wrapped by the motion-wait interrupt guard. The move is short
    and force-limited, so this is a documented limitation rather than a hazard.
    """
    logger.info(
      "[PreciseFlex %s] move_to_jaw_position: width_mm=%s force_sensing=%s",
      self._driver.io._host,
      width,
      force_sensing,
    )
    units = self._mm_to_firmware_units(width)
    if (
      self._gripper_soft_min is not None
      and self._gripper_soft_max is not None
      and not (self._gripper_soft_min <= units <= self._gripper_soft_max)
    ):
      raise ValueError(
        f"gripper width {width} mm maps to firmware units {units:.1f}, outside the gripper "
        f"axis range [{self._gripper_soft_min}, {self._gripper_soft_max}] - check "
        f"closed_gripper_position (currently {self.closed_gripper_position})."
      )
    await self._move_jaws(units, force_sensing)

  @evented_operation(
    "precise_flex.move_gripper_joint_position",
    lambda self, position, force_sensing=None: {
      "device": self._driver._controller_reference(),
      "gripper_joint_position": float(position),
      "force_sensing": force_sensing,
    },
  )
  async def move_to_jaw_position_firmware_units(
    self,
    position: float,
    force_sensing: Optional[bool] = None,
  ) -> None:
    """Move the gripper to a controller-native joint position.

    This is the counterpart to :meth:`move_to_jaw_position` for integrations with
    taught joint-space routes. The caller owns the joint calibration.

    Args:
      position: the gripper axis position, in the controller's units.
      force_sensing: None senses force when the move closes the jaws and not when it opens them.
        Pass False only to close without it on purpose.
    """
    await self._move_jaws(position, force_sensing)

  # -- sensors -------------------------------------------------------------------------------------

  async def sense_fully_closed(self) -> bool:
    """(Single Gripper Only) Tests if the gripper is fully closed by checking the end-of-travel sensor.

    Returns:
      For standard gripper: True if the gripper is within 2mm of fully closed, otherwise False.
    """
    if self._is_dual_gripper:
      raise ValueError("IsGripperClosed command is only valid for single gripper robots.")
    response = await self._driver.send_command("IsFullyClosed")
    return int(response) == -1

  async def sense_each_fully_closed(self) -> tuple[bool, bool]:
    """(Dual Gripper Only) Tests if each gripper is fully closed by checking the end-of-travel sensors."""
    if not self._is_dual_gripper:
      raise ValueError("AreGrippersClosed command is only valid for dual gripper robots.")
    response = await self._driver.send_command("IsFullyClosed")
    ret_int = int(response)
    gripper_1_closed = (ret_int & 1) != 0
    gripper_2_closed = (ret_int & 2) != 0
    return (gripper_1_closed, gripper_2_closed)
