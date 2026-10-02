"""The PreciseFlex gripper: the end-effector fitted at the arm's wrist, driven through the controller.

Reached as `driver.gripper`. The jaws are the controller's gripper axis (`Axis.GRIPPER`), commanded
through their open and close positions; a force-controlled grasp for `pickplate` is set up here.
"""

import logging
from typing import TYPE_CHECKING, Optional

from pylabrobot.events import evented_operation

from ._references import _controller_reference
from .errors import PreciseFlexError

if TYPE_CHECKING:
  from .config import PreciseFlexConfiguration
  from .precise_flex import PreciseFlex

logger = logging.getLogger(__name__)


class PreciseFlexGripper:
  """The gripper fitted to a PreciseFlex arm: a servoed single gripper, or a dual one.

  Reached as `driver.gripper`. Sends through the driver's `send_command`.
  """

  # What the driver sends when a caller leaves the value out. Tune one gripper by assigning on the
  # instance, or every gripper by assigning on the class.
  default_finger_speed_pct: float = 50.0
  default_grasp_force: float = 10.0

  # Physical jaw range for the PF400 servoed gripper. Overridden at setup from the
  # gripper-axis soft limits (DataIDs 16078/16077, Axis.GRIPPER) when discoverable.
  min_gripper_width: float = 60.0
  max_gripper_width: float = 145.0
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
        ``GripOpenPos``) at which the jaws are at :attr:`min_gripper_width`.
      is_dual_gripper: whether two grippers are fitted. Discovery overrides it at setup.
    """
    self._driver = driver
    self.closed_gripper_position = closed_gripper_position
    self._is_dual_gripper = is_dual_gripper

  def _adopt_configuration(self, config: "PreciseFlexConfiguration") -> None:
    """Take the jaw range from the gripper-axis soft limits, and whether two are fitted."""
    gmin, gmax = config.gripper_width_range
    self._gripper_soft_min, self._gripper_soft_max = gmin, gmax
    self.min_gripper_width, self.max_gripper_width = gmin, gmax
    self._is_dual_gripper = config.is_dual_gripper

  async def _request_grip_close_pos(self) -> float:
    """Get the gripper close position for the servoed gripper.

    Returns:
      float: The current gripper close position.
    """
    data = await self._driver.send_command("GripClosePos")
    return float(data)

  async def _set_grip_close_pos(self, close_position: float) -> None:
    """Set the gripper close position for the servoed gripper.

    The close position may be changed by a force-controlled grip operation.

    Args:
      close_position: The new gripper close position.
    """
    await self._driver.send_command(f"GripClosePos {close_position}")

  async def _request_grip_open_pos(self) -> float:
    """Get the gripper open position for the servoed gripper.

    Returns:
      float: The current gripper open position.
    """
    data = await self._driver.send_command("GripOpenPos")
    return float(data)

  async def _set_grip_open_pos(self, open_position: float) -> None:
    """Set the gripper open position for the servoed gripper.

    Args:
      open_position: The new gripper open position.
    """
    await self._driver.send_command(f"GripOpenPos {open_position}")

  async def _request_grasp_data(self) -> tuple[float, float, float]:
    """Get the data to be used for the next force-controlled PickPlate command grip operation.

    Returns:
      A tuple containing (plate_width_mm, finger_speed_pct, grasp_force)
    """
    data = await self._driver.send_command("GraspData")
    parts = data.split()
    if len(parts) != 3:
      raise PreciseFlexError(-1, "Unexpected response format from GraspData command.")
    return (float(parts[0]), float(parts[1]), float(parts[2]))

  async def _set_grasp_data(
    self, plate_width: float, finger_speed_pct: float, grasp_force: float
  ) -> None:
    """Set the data to be used for the next force-controlled PickPlate command grip operation.

    This data remains in effect until the next GraspData command or the system is restarted.

    Args:
      plate_width: The plate width in mm.
      finger_speed_pct: The finger speed during grasp as a percentage (0-100). 100 = full speed.
      grasp_force: The gripper squeezing force, in Newtons.
      A positive value indicates the fingers must close to grasp.
      A negative value indicates the fingers must open to grasp.

    Raises:
      ValueError: If finger_speed_pct is not between 0 and 100.
    """
    if not 0 <= finger_speed_pct <= 100:
      raise ValueError(f"finger_speed_pct must be between 0 and 100, got {finger_speed_pct}")
    await self._driver.send_command(f"GraspData {plate_width} {finger_speed_pct} {grasp_force}")

  def _mm_to_firmware_units(self, width_mm: float) -> float:
    """Convert a jaw width (mm) to the firmware's native position unit.

    Anchored at :attr:`closed_gripper_position`, which is the firmware value
    when the jaws are at :attr:`min_gripper_width`. Slope is 1 (1 mm = 1 unit).
    """
    return self.closed_gripper_position + (width_mm - self.min_gripper_width)

  @evented_operation(
    "precise_flex.move_gripper",
    lambda self, width, force_sensing=False: {
      "device": _controller_reference(self._driver),
      "width": float(width),
      "force_sensing": force_sensing,
    },
  )
  async def move_gripper(
    self,
    width: float,
    force_sensing: bool = False,
  ):
    """Move the PreciseFlex gripper jaws.

    ``force_sensing=False`` drives to the open position (``gripper 1``);
    ``force_sensing=True`` drives to the close position with force feedback
    (``gripper 2``), which may stop short of ``width`` on contact.

    Not interruptible: the ``gripper`` firmware command blocks the controller's command interpreter
    until the jaws finish (hardware-verified, like ``waitForEom``), so a user interrupt cannot halt it
    mid-travel - it is intentionally not wrapped by the motion-wait interrupt guard. The move is short
    and force-limited, so this is a documented limitation rather than a hazard.
    """
    logger.info(
      "[PreciseFlex %s] move_gripper: width_mm=%s force_sensing=%s",
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
    if force_sensing:
      await self._set_grip_close_pos(units)
      await self._driver.send_command("gripper 2")
    else:
      await self._set_grip_open_pos(units)
      await self._driver.send_command("gripper 1")

  @evented_operation(
    "precise_flex.move_gripper_joint_position",
    lambda self, position, force_sensing=False: {
      "device": _controller_reference(self._driver),
      "gripper_joint_position": float(position),
      "force_sensing": force_sensing,
    },
  )
  async def move_gripper_joint_position(
    self,
    position: float,
    force_sensing: bool = False,
  ) -> None:
    """Move the gripper to a controller-native joint position.

    This is the counterpart to :meth:`move_gripper` for integrations with
    taught joint-space routes. The caller owns the joint calibration.
    """
    if force_sensing:
      await self._set_grip_close_pos(position)
      await self._driver.send_command("gripper 2")
    else:
      await self._set_grip_open_pos(position)
      await self._driver.send_command("gripper 1")

  async def is_gripper_closed(self) -> bool:
    """(Single Gripper Only) Tests if the gripper is fully closed by checking the end-of-travel sensor.

    Returns:
      For standard gripper: True if the gripper is within 2mm of fully closed, otherwise False.
    """
    if self._is_dual_gripper:
      raise ValueError("IsGripperClosed command is only valid for single gripper robots.")
    response = await self._driver.send_command("IsFullyClosed")
    return int(response) == -1

  async def are_grippers_closed(self) -> tuple[bool, bool]:
    """(Dual Gripper Only) Tests if each gripper is fully closed by checking the end-of-travel sensors."""
    if not self._is_dual_gripper:
      raise ValueError("AreGrippersClosed command is only valid for dual gripper robots.")
    response = await self._driver.send_command("IsFullyClosed")
    ret_int = int(response)
    gripper_1_closed = (ret_int & 1) != 0
    gripper_2_closed = (ret_int & 2) != 0
    return (gripper_1_closed, gripper_2_closed)
