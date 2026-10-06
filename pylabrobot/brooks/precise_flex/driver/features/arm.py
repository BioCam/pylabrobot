"""The PreciseFlex arm: its joints and how they move, driven through the controller.

Reached as `driver.arm`. Reads the joint state, moves in joint space and in Cartesian space through
one guarded path, and brings out-of-range axes back inside their soft limits.
"""

import asyncio
import contextlib
import dataclasses
import logging
import math
import time
import warnings
from typing import (
  TYPE_CHECKING,
  AsyncIterator,
  Callable,
  ClassVar,
  Dict,
  List,
  Literal,
  NamedTuple,
  Optional,
  Sequence,
  Tuple,
  cast,
)

from pylabrobot.events import coordinate_reference, evented_operation
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.manipulator import LinkBody
from pylabrobot.resources.resource import Resource
from pylabrobot.resources.rotation import Rotation

from ... import kinematics
from ...data_ids import DataID, _parse_per_axis, _parse_scalar, _zip_axis_ranges
from ...interrupt import halt_and_resync, halt_on_interrupt
from ...kinematics import (
  Axis,
  ElbowOrientation,
  JointState,
  PreciseFlexCartesianPose,
  PreciseFlexPose,
  WorkEnvelope,
  Wrist,
)
from ...resource_model.pf400_chassis import (
  Z_CARRIAGE_REFERENCE_POINT,
  Z_COLUMN_OUTLINE,
  z_carriage_location,
)
from ...resource_model.pf400_end_effector import GRIPPER_BODY_OUTLINE
from ..errors import OperationInterrupted, OutOfRangeOfMotionError, PreciseFlexError
from .rail import PreciseFlexRail

if TYPE_CHECKING:
  from ..master import PreciseFlexDriver

logger = logging.getLogger(__name__)

# InRange sentinel that lets the controller blend through waypoints instead of stopping at each one.
BLEND_IN_RANGE = -1
# How near the column the gripper may be sent, in mm, seen from above.
_COLUMN_CLEARANCE = 5.0


def _snap_to_current(
  ik_joints: JointState, current: JointState, wrist: Optional[Wrist]
) -> JointState:
  """Shift each rotary joint by 360° multiples toward `current`, then re-enforce
  the wrist-sign half on J4 so the result still matches `wrist`. Avoids
  gratuitous full-turn moves when multiple IK solutions are equivalent.
  """
  out = dict(ik_joints)
  for axis in (Axis.SHOULDER, Axis.ELBOW, Axis.WRIST):
    out[axis] += 360 * round((current[axis] - out[axis]) / 360)
  if wrist == "ccw" and out[Axis.WRIST] < 0:
    out[Axis.WRIST] += 360
  elif wrist == "cw" and out[Axis.WRIST] > 0:
    out[Axis.WRIST] -= 360
  return out


def _joint_state_reference(position: JointState) -> dict[str, float]:
  """Convert a joint state into a JSON-friendly target description."""
  return {
    (axis.name.lower() if isinstance(axis, Axis) else str(axis)): float(value)
    for axis, value in position.items()
  }


def _cartesian_target_reference(
  location: Coordinate,
  direction: float,
  *,
  orientation: Optional["ElbowOrientation"] = None,
  wrist: Optional["Wrist"] = None,
  rail_position: Optional[float] = None,
) -> dict[str, object]:
  """Describe a Cartesian controller target without serializing a full pose object."""
  return {
    "location": coordinate_reference(location),
    "direction": float(direction),
    "orientation": orientation,
    "wrist": wrist,
    "rail_position": rail_position,
  }


@dataclasses.dataclass(frozen=True)
class PreciseFlexArmConfiguration:
  """The arm's facts, read at setup: limits and maxima of Z, shoulder, elbow and wrist, and its
  kinematics."""

  soft_limits: Dict[Axis, tuple]
  hard_limits: Dict[Axis, tuple]
  # Effective per-joint maxima (reference x the global percent cap, already applied).
  max_joint_speed: Dict[Axis, float]
  max_joint_acceleration: Dict[Axis, float]
  max_joint_deceleration: Dict[Axis, float]
  max_cartesian_speed: float
  max_cartesian_acceleration: float
  kinematics: "kinematics.PF400Params" = dataclasses.field(default_factory=kinematics.PF400Params)
  kinematics_source: Literal["device", "provided", "default"] = "default"
  # "unknown" if the controller-read link lengths match neither known arm; defaults to "extended"
  # to match the default PF400Params (the extended/XR link lengths)
  reach_class: Literal["standard", "extended", "unknown"] = "extended"

  @property
  def z_range(self) -> tuple:
    return self.soft_limits[Axis.BASE]

  @property
  def work_envelope(self) -> WorkEnvelope:
    """Reachable tool-tip annulus, swept from the shoulder/elbow soft limits.

    Sweeps the two planar joints across their soft-limit range (Z held constant -
    it is an independent axis on a SCARA), takes the base->wrist radius at each
    sample, and brackets it by +/- the tool length (the wrist can orient the tool
    radially either way). This respects the joint limits rather than assuming full
    extension, so the outer radius is the real reach, not l1 + l2 + tool.
    """
    wrist_only = dataclasses.replace(self.kinematics, gripper_length=0.0)
    tool = self.kinematics.gripper_length
    sh_lo, sh_hi = self.soft_limits[Axis.SHOULDER]
    el_lo, el_hi = self.soft_limits[Axis.ELBOW]
    steps = 60
    outer, inner = 0.0, float("inf")
    for i in range(steps + 1):
      shoulder = sh_lo + (sh_hi - sh_lo) * i / steps
      for j in range(steps + 1):
        elbow = el_lo + (el_hi - el_lo) * j / steps
        joints: JointState = {
          Axis.BASE: 0.0,
          Axis.SHOULDER: shoulder,
          Axis.ELBOW: elbow,
          Axis.WRIST: 0.0,
          Axis.GRIPPER: 0.0,
          Axis.RAIL: 0.0,
        }
        wrist = kinematics.fk(joints, wrist_only).location
        radius = (wrist.x * wrist.x + wrist.y * wrist.y) ** 0.5
        outer = max(outer, radius + tool)
        inner = min(inner, abs(radius - tool))
    zmin, zmax = self.z_range
    return WorkEnvelope(inner=inner, outer=outer, zmin=zmin, zmax=zmax)


class MotionProfile(NamedTuple):
  """A controller motion profile, as reported by ``Profile <n>`` (field order matches the wire)."""

  profile: int
  speed: float
  speed2: float
  acceleration: float
  deceleration: float
  acceleration_ramp: float
  deceleration_ramp: float
  in_range: float  # -1 (BLEND_IN_RANGE) to 100; -1 blends, 0 stops, >0 enforces position accuracy
  straight: bool  # True = straight-line path, False = joint-based path


class PreciseFlexArm:
  """The arm of a PreciseFlex: its joints, read and moved through the controller.

  Reached as `driver.arm`. Sends through the driver's `send_command`; every commanded joint move
  goes through `_guarded_move_j`.
  """

  # What the driver sends when a caller leaves the value out. Tune one arm by assigning on the
  # instance, or every arm by assigning on the class.
  default_recovery_speed_percent: float = 20.0

  # Parked orientations: planar folds, named for the way the gripper points. Z, gripper and rail are
  # left out: ``park()`` fills Z from the travel, and a held plate or a rail is not disturbed.
  PARKING_POSITION_BACK: ClassVar[JointState] = {
    Axis.SHOULDER: 90.0,
    Axis.ELBOW: 180.0,
    Axis.WRIST: 90.0,
  }
  PARKING_POSITION_RIGHT: ClassVar[JointState] = {
    Axis.SHOULDER: 0.0,
    Axis.ELBOW: 180.0,
    Axis.WRIST: 180.0,
  }
  PARKING_POSITION_FRONT: ClassVar[JointState] = {
    Axis.SHOULDER: -90.0,
    Axis.ELBOW: 180.0,
    Axis.WRIST: 270.0,
  }

  def __init__(self, driver: "PreciseFlexDriver") -> None:
    """
    Args:
      driver: the driver to send commands through.
    """
    self._driver = driver
    self.configuration: Optional[PreciseFlexArmConfiguration] = None
    # What models the arm: the carriage on the column and the two links. None until setup hangs
    # them, which it does only for a driver given a workspace.
    self.resource: Optional[Resource] = None
    self.link_1: Optional[LinkBody] = None
    self.link_2: Optional[LinkBody] = None
    self.profile_index: int = 1
    self.station_index: int = 1
    self.horizontal_compliance: bool = False
    self.horizontal_compliance_torque: int = 0

  # -- joint state ---------------------------------------------------------------------------------

  def _parse_angles_response(self, parts: List[str]) -> JointState:
    """Parse angle values from a response string.

    For self._driver._has_rail=True:  wire order is [base, shoulder, elbow, wrist, gripper, rail]
    For self._driver._has_rail=False: wire order is [base, shoulder, elbow, wrist, gripper]
    """
    if len(parts) < 3:
      raise PreciseFlexError(-1, "Unexpected response format for angles.")
    if self._driver._has_rail:
      return {
        Axis.RAIL: float(parts[5]) if len(parts) > 5 else 0.0,
        Axis.BASE: float(parts[0]),
        Axis.SHOULDER: float(parts[1]),
        Axis.ELBOW: float(parts[2]),
        Axis.WRIST: float(parts[3]) if len(parts) > 3 else 0.0,
        Axis.GRIPPER: float(parts[4]) if len(parts) > 4 else 0.0,
      }
    return {
      Axis.RAIL: 0.0,
      Axis.BASE: float(parts[0]),
      Axis.SHOULDER: float(parts[1]),
      Axis.ELBOW: float(parts[2]) if len(parts) > 2 else 0.0,
      Axis.WRIST: float(parts[3]) if len(parts) > 3 else 0.0,
      Axis.GRIPPER: float(parts[4]) if len(parts) > 4 else 0.0,
    }

  async def _wait_for_eom(
    self, poll_interval: float = 0.05, settle: float = 0.02, timeout: float = 60.0
  ) -> None:
    """Wait (non-blocking) until the arm has stopped moving, keeping the connection responsive.

    Polls the live joint position (``wherej``) and returns once three samples in a row agree (every
    axis moving less than ``settle``) - i.e. end of motion. Two are not enough: right after a
    ``moveJ`` is accepted the arm creeps under ``settle`` for about 0.1 s (seen in the IO logs).
    It returns promptly when the arm is already stationary, including when it was stopped short of
    its last commanded target (after a halt/interrupt or a hand-move), so it never hangs waiting to
    reach a target that will not be reached.

    This deliberately avoids the firmware ``waitForEom``: that command parks the controller's single
    command interpreter and makes it ignore everything else on the connection - including ``halt`` -
    until the move ends (hardware-verified). Polling instead leaves the connection free between
    samples, so a user interrupt can stop the move mid-flight via ``halt`` and other controller
    commands (status, vision, barcode) can run during motion.

    That free connection is also the hazard, so every command that starts motion waits here first:
    the gripper and the rail directly, joint and Cartesian moves through ``request_joint_state``.
    ``moveJ`` returns once accepted, so without it a grip after an approach closes mid-descent.

    Raises:
      TimeoutError: if the arm never settles within ``timeout`` seconds.
      OperationInterrupted: on a user interrupt (the arm is halted and the connection kept).
    """

    def _floats(reply: str) -> list[float]:
      return [float(x) for x in reply.split()]

    # On interrupt, `halt` stops the move and the link is resynchronised and kept. It is sent
    # outside `_io_lock`: an emergency halt must not wait on another caller's read.
    async with halt_on_interrupt(lambda: halt_and_resync(self._driver.io, b"halt")):
      previous = _floats(await self._driver.send_command("wherej"))
      deadline = time.monotonic() + timeout
      still = 0
      while True:
        await asyncio.sleep(poll_interval)
        current = _floats(await self._driver.send_command("wherej"))
        still = still + 1 if all(abs(c - p) < settle for c, p in zip(current, previous)) else 0
        if still == 2:
          return  # three samples agree: stopped moving
        if time.monotonic() > deadline:
          raise TimeoutError(f"motion did not settle within {timeout:.0f}s (current={current})")
        previous = current

  def update_joint_state(self, joints: JointState) -> None:
    """Record where every joint is on the resources that model the arm.

    The carriage is stood where the Z drive is, and each member is turned about the joint it turns
    on to the angle that joint reports. Does nothing until there are resources to record it on.

    Args:
      joints: the joint state, as ``request_joint_state`` returns it.
    """
    if self.resource is None or self.link_1 is None or self.link_2 is None:
      return
    self.resource.location = z_carriage_location(joints[Axis.BASE])
    self.link_1.rotate_to(z=joints[Axis.SHOULDER], pivot_coordinate=self.link_1.proximal_joint)
    self.link_2.rotate_to(z=joints[Axis.ELBOW], pivot_coordinate=self.link_2.proximal_joint)
    gripper = self._driver.gripper.resource
    if gripper is not None:
      gripper.rotate_to(z=joints[Axis.WRIST], pivot_coordinate=gripper.proximal_joint)

  async def request_joint_state(self) -> JointState:
    """Get the current joint position of the arm."""
    await self._wait_for_eom()
    num_tries = 2
    for _ in range(num_tries):
      data = await self._driver.send_command("wherej")
      parts = data.split()
      if len(parts) > 0:
        break
    else:
      raise PreciseFlexError(-1, "Unexpected response format from wherej command.")
    joints = self._parse_angles_response(parts)
    self.update_joint_state(joints)
    self._driver.gripper.update_width(
      self._driver.gripper._firmware_units_to_mm(joints[Axis.GRIPPER])
    )
    return joints

  async def _request_joint_state_after_move(self) -> None:
    """Wait for the arm to stop and read where it did, on a move's success and its failure alike.

    A failure of its own is logged and swallowed: it must not replace the error that says what went
    wrong with the move. An interrupt is not a failure, and is passed on.
    """
    try:
      await self.request_joint_state()
    except OperationInterrupted:
      raise
    except Exception:
      logger.warning(
        "[PreciseFlex %s] could not read where the arm stopped; its model is stale",
        self._driver.io._host,
      )

  async def request_state(self) -> str:
    """Return state of motion.

    This value indicates the state of the currently executing or last completed robot motion.
    For additional information, please see 'Robot.TrajState' in the GPL reference manual.

    Returns:
      str: The current motion state.
    """
    return await self._driver.send_command("state")

  def _parse_xyz_response(
    self, parts: List[str]
  ) -> tuple[float, float, float, float, float, float]:
    if len(parts) != 6:
      raise PreciseFlexError(-1, "Unexpected response format for Cartesian coordinates.")
    return (
      float(parts[0]),
      float(parts[1]),
      float(parts[2]),
      float(parts[3]),
      float(parts[4]),
      float(parts[5]),
    )

  async def _request_state(
    self,
  ) -> tuple[JointState, PreciseFlexCartesianPose]:
    """Single-query snapshot of joint state and the derived Cartesian pose."""
    joints = await self.request_joint_state()
    pose = kinematics.fk(joints, self._driver._kinematics_params)
    # PF400 gripper stays level: pitch=90, roll=-180.
    pose = dataclasses.replace(pose, rotation=Rotation(x=-180, y=90, z=pose.rotation.yaw))
    return joints, pose

  # -- motion primitives ---------------------------------------------------------------------------

  async def _unchecked_fw_move_j(self, profile_index: int, joint_coords: JointState) -> None:
    """Move the robot using joint coordinates, handling rail configuration. Raw moveJ - the
    out-of-range guard lives in the caller (``_guarded_move_j``), not in this primitive."""
    if self._driver._has_rail:
      angles_str = (
        f"{joint_coords[Axis.BASE]} {joint_coords[Axis.SHOULDER]} "
        f"{joint_coords[Axis.ELBOW]} {joint_coords[Axis.WRIST]} "
        f"{joint_coords[Axis.GRIPPER]} {joint_coords[Axis.RAIL]} "
      )
    else:
      angles_str = (
        f"{joint_coords[Axis.BASE]} {joint_coords[Axis.SHOULDER]} "
        f"{joint_coords[Axis.ELBOW]} {joint_coords[Axis.WRIST]} "
        f"{joint_coords[Axis.GRIPPER]}"
      )
    await self._driver.send_command(f"moveJ {profile_index} {angles_str}")

  async def _unchecked_fw_move_one_axis(self, axis: Axis, position: float) -> None:
    """Move a single axis to an absolute position (firmware ``MoveOneAxis``).

    Used for recovery: the controller blocks a normal move while an axis is out of
    range, but allows a single-axis move heading back into range. Does not wait for
    the motion to complete.
    """
    await self._driver.send_command(f"MoveOneAxis {int(axis)} {position} {self.profile_index}")

  async def _unchecked_fw_set_joint_angles(
    self,
    station_index: int,
    joint_position: JointState,
  ) -> None:
    """Set joint angles for a station, handling rail configuration."""
    if self._driver._has_rail:
      await self._driver.send_command(
        f"locAngles {station_index} {joint_position[Axis.RAIL]} "
        f"{joint_position[Axis.BASE]} {joint_position[Axis.SHOULDER]} "
        f"{joint_position[Axis.ELBOW]} {joint_position[Axis.WRIST]} "
        f"{joint_position[Axis.GRIPPER]}"
      )
    else:
      await self._driver.send_command(
        f"locAngles {station_index} {joint_position[Axis.BASE]} "
        f"{joint_position[Axis.SHOULDER]} {joint_position[Axis.ELBOW]} "
        f"{joint_position[Axis.WRIST]} {joint_position[Axis.GRIPPER]}"
      )

  async def _cart_to_joints(self, cart: PreciseFlexCartesianPose) -> JointState:
    """Convert a Cartesian location into a full joint dict using our IK.

    Any of cart.orientation, cart.wrist, and cart.rail_position left as None
    default to the current pose - picks the configuration closest to where the
    arm is now. Fetches current joint state for the gripper and rail axes so
    callers get a complete joint dict, ready for `_guarded_move_j`.
    """
    joints, current = await self._request_state()
    cart = dataclasses.replace(
      cart,
      orientation=current.orientation if cart.orientation is None else cart.orientation,
      wrist=current.wrist if cart.wrist is None else cart.wrist,
      rail_position=current.rail_position if cart.rail_position is None else cart.rail_position,
    )
    ik_joints = _snap_to_current(
      kinematics.ik(cart, p=self._driver._kinematics_params), joints, cart.wrist
    )
    # IK only solves the arm axes; gripper and rail keep their current values.
    for axis in (Axis.BASE, Axis.SHOULDER, Axis.ELBOW, Axis.WRIST):
      joints[axis] = ik_joints[axis]
    if cart.rail_position is not None:
      joints[Axis.RAIL] = cart.rail_position
    return joints

  # -- speed and motion profiles -------------------------------------------------------------------

  async def request_monitor_speed(self) -> int:
    """Get the global system (monitor) speed.

    Returns:
      Current monitor speed as a percentage (0-100)
    """
    response = await self._driver.send_command("mspeed")
    return int(response)

  async def set_monitor_speed(
    self, speed_percent: Optional[int] = None, *, speed_pct: Optional[int] = None
  ) -> None:
    """Set the global system (monitor) speed.

    Args:
      speed_percent: Speed percentage between 0 and 100, where 100 means full speed.
      speed_pct: deprecated, use `speed_percent`.

    Raises:
      ValueError: If speed_percent is not between 0 and 100.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=2
      )
      speed_percent = speed_pct
    if speed_percent is None:
      raise TypeError("set_monitor_speed() missing required argument: 'speed_percent'")
    if not 0 <= speed_percent <= 100:
      raise ValueError(f"speed_percent must be between 0 and 100, got {speed_percent}")
    await self._driver.send_command(f"mspeed {speed_percent}")

  async def request_payload(self) -> int:
    """Get the payload percent value for the current robot.

    Returns:
      Current payload as a percentage of maximum (0-100)
    """
    response = await self._driver.send_command("payload")
    return int(response)

  async def set_payload(
    self, payload_percent: Optional[int] = None, *, payload_pct: Optional[int] = None
  ) -> None:
    """Set the payload percent of maximum for the currently selected or attached robot.

    Args:
      payload_percent: Payload percentage from 0 to 100 indicating the percent of the maximum
        payload the robot is carrying.
      payload_pct: deprecated, use `payload_percent`.

    Raises:
      ValueError: If payload_percent is not between 0 and 100.

    Note:
      If the robot is moving, waits for the robot to stop before setting a value.
    """
    if payload_pct is not None:
      warnings.warn(
        "`payload_pct` is deprecated, use `payload_percent`.", DeprecationWarning, stacklevel=2
      )
      payload_percent = payload_pct
    if payload_percent is None:
      raise TypeError("set_payload() missing required argument: 'payload_percent'")
    if not (0 <= payload_percent <= 100):
      raise ValueError("Payload percent must be between 0 and 100")
    await self._driver.send_command(f"payload {payload_percent}")

  async def request_profile_speed(self, profile_index: int) -> float:
    """Get the speed property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current speed as a percentage. 100 = full speed.
    """
    response = await self._driver.send_command(f"Speed {profile_index}")
    profile, speed = response.split()
    return float(speed)

  async def set_profile_speed(
    self,
    profile_index: int,
    speed_percent: Optional[float] = None,
    *,
    speed_pct: Optional[float] = None,
  ) -> None:
    """Set the speed property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      speed_percent: The new speed as a percentage (0-100). 100 = full speed.
      speed_pct: deprecated, use `speed_percent`.

    Raises:
      ValueError: If speed_percent is not between 0 and 100.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=2
      )
      speed_percent = speed_pct
    if speed_percent is None:
      raise TypeError("set_profile_speed() missing required argument: 'speed_percent'")
    if not 0 <= speed_percent <= 100:
      raise ValueError(f"speed_percent must be between 0 and 100, got {speed_percent}")
    await self._driver.send_command(f"Speed {profile_index} {speed_percent}")

  async def request_profile_speed2(self, profile_index: int) -> float:
    """Get the speed2 property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current speed2 as a percentage. Used for Cartesian moves.
    """
    response = await self._driver.send_command(f"Speed2 {profile_index}")
    profile, speed2 = response.split()
    return float(speed2)

  async def set_profile_speed2(
    self,
    profile_index: int,
    speed2_percent: Optional[float] = None,
    *,
    speed2_pct: Optional[float] = None,
  ) -> None:
    """Set the speed2 property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      speed2_percent: The new speed2 as a percentage (0-100). 100 = full speed.
        Used for Cartesian moves. Normally set to 0.
      speed2_pct: deprecated, use `speed2_percent`.

    Raises:
      ValueError: If speed2_percent is not between 0 and 100.
    """
    if speed2_pct is not None:
      warnings.warn(
        "`speed2_pct` is deprecated, use `speed2_percent`.", DeprecationWarning, stacklevel=2
      )
      speed2_percent = speed2_pct
    if speed2_percent is None:
      raise TypeError("set_profile_speed2() missing required argument: 'speed2_percent'")
    if not 0 <= speed2_percent <= 100:
      raise ValueError(f"speed2_percent must be between 0 and 100, got {speed2_percent}")
    await self._driver.send_command(f"Speed2 {profile_index} {speed2_percent}")

  async def request_profile_acceleration(self, profile_index: int) -> float:
    """Get the acceleration property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current acceleration as a percentage. 100 = maximum acceleration.
    """
    response = await self._driver.send_command(f"Accel {profile_index}")
    profile, acceleration = response.split()
    return float(acceleration)

  async def set_profile_acceleration(
    self,
    profile_index: int,
    acceleration_percent: Optional[float] = None,
    *,
    acceleration_pct: Optional[float] = None,
  ) -> None:
    """Set the acceleration property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      acceleration_percent: The new acceleration as a percentage (0-100). 100 = maximum
        acceleration.
      acceleration_pct: deprecated, use `acceleration_percent`.

    Raises:
      ValueError: If acceleration_percent is not between 0 and 100.
    """
    if acceleration_pct is not None:
      warnings.warn(
        "`acceleration_pct` is deprecated, use `acceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      acceleration_percent = acceleration_pct
    if acceleration_percent is None:
      raise TypeError(
        "set_profile_acceleration() missing required argument: 'acceleration_percent'"
      )
    if not 0 <= acceleration_percent <= 100:
      raise ValueError(
        f"acceleration_percent must be between 0 and 100, got {acceleration_percent}"
      )
    await self._driver.send_command(f"Accel {profile_index} {acceleration_percent}")

  async def request_profile_acceleration_ramp(self, profile_index: int) -> float:
    """Get the acceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current acceleration ramp time in seconds.
    """
    response = await self._driver.send_command(f"AccRamp {profile_index}")
    profile, acceleration_ramp = response.split()
    return float(acceleration_ramp)

  async def set_profile_acceleration_ramp(
    self, profile_index: int, acceleration_ramp_seconds: float
  ) -> None:
    """Set the acceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      acceleration_ramp_seconds: The new acceleration ramp time in seconds.
    """
    await self._driver.send_command(f"AccRamp {profile_index} {acceleration_ramp_seconds}")

  async def request_profile_deceleration(self, profile_index: int) -> float:
    """Get the deceleration property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current deceleration as a percentage. 100 = maximum deceleration.
    """
    response = await self._driver.send_command(f"Decel {profile_index}")
    profile, deceleration = response.split()
    return float(deceleration)

  async def set_profile_deceleration(
    self,
    profile_index: int,
    deceleration_percent: Optional[float] = None,
    *,
    deceleration_pct: Optional[float] = None,
  ) -> None:
    """Set the deceleration property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      deceleration_percent: The new deceleration as a percentage (0-100). 100 = maximum
        deceleration.
      deceleration_pct: deprecated, use `deceleration_percent`.

    Raises:
      ValueError: If deceleration_percent is not between 0 and 100.
    """
    if deceleration_pct is not None:
      warnings.warn(
        "`deceleration_pct` is deprecated, use `deceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      deceleration_percent = deceleration_pct
    if deceleration_percent is None:
      raise TypeError(
        "set_profile_deceleration() missing required argument: 'deceleration_percent'"
      )
    if not 0 <= deceleration_percent <= 100:
      raise ValueError(
        f"deceleration_percent must be between 0 and 100, got {deceleration_percent}"
      )
    await self._driver.send_command(f"Decel {profile_index} {deceleration_percent}")

  async def request_profile_deceleration_ramp(self, profile_index: int) -> float:
    """Get the deceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current deceleration ramp time in seconds.
    """
    response = await self._driver.send_command(f"DecRamp {profile_index}")
    profile, deceleration_ramp = response.split()
    return float(deceleration_ramp)

  async def set_profile_deceleration_ramp(
    self, profile_index: int, deceleration_ramp_seconds: float
  ) -> None:
    """Set the deceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      deceleration_ramp_seconds: The new deceleration ramp time in seconds.
    """
    await self._driver.send_command(f"DecRamp {profile_index} {deceleration_ramp_seconds}")

  async def request_profile_in_range(self, profile_index: int) -> float:
    """Get the InRange property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current InRange value (-1 to 100).
      -1 = do not stop at end of motion if blending is possible
      0 = always stop but do not check end point error
      > 0 = wait until close to end point (larger numbers mean less position error allowed)
    """
    response = await self._driver.send_command(f"InRange {profile_index}")
    profile, in_range = response.split()
    return float(in_range)

  async def set_profile_in_range(self, profile_index: int, in_range_value: float) -> None:
    """Set the InRange property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      in_range_value: The new InRange value from -1 to 100.
      -1 = do not stop at end of motion if blending is possible
      0 = always stop but do not check end point error
      > 0 = wait until close to end point (larger numbers mean less position error allowed)

    Raises:
      ValueError: If in_range_value is not between -1 and 100.
    """
    if not (-1 <= in_range_value <= 100):
      raise ValueError("InRange value must be between -1 and 100")
    await self._driver.send_command(f"InRange {profile_index} {in_range_value}")

  async def request_profile_straight(self, profile_index: int) -> bool:
    """Get the Straight property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      The current Straight property value.
      True = follow a straight-line path
      False = follow a joint-based path (coordinated axes movement)
    """
    response = await self._driver.send_command(f"Straight {profile_index}")
    profile, straight = response.split()
    return straight == "True"

  async def set_profile_straight(self, profile_index: int, straight_mode: bool) -> None:
    """Set the Straight property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      straight_mode: The path type to use.
      True = follow a straight-line path
      False = follow a joint-based path (robot axes move in coordinated manner)

    Raises:
      ValueError: If straight_mode is not True or False.
    """
    straight_int = 1 if straight_mode else 0
    await self._driver.send_command(f"Straight {profile_index} {straight_int}")

  async def request_motion_profile_values(self, profile: int) -> MotionProfile:
    """
    Get the current motion profile values for the specified profile index on the PreciseFlex robot.

    Args:
      profile: Profile index to get values for.

    Returns:
      A :class:`MotionProfile` with the profile's speed, acceleration, ramps, InRange and path mode.
    """
    data = await self._driver.send_command(f"Profile {profile}")
    parts = data.split(" ")
    if len(parts) != 9:
      raise PreciseFlexError(-1, "Unexpected response format from device.")
    return MotionProfile(
      int(parts[0]),
      float(parts[1]),
      float(parts[2]),
      float(parts[3]),
      float(parts[4]),
      float(parts[5]),
      float(parts[6]),
      float(parts[7]),
      int(parts[8]) != 0,
    )

  async def set_motion_profile_values(
    self,
    profile: int,
    speed_percent: Optional[float] = None,
    speed2_percent: Optional[float] = None,
    acceleration_percent: Optional[float] = None,
    deceleration_percent: Optional[float] = None,
    acceleration_ramp: Optional[float] = None,
    deceleration_ramp: Optional[float] = None,
    in_range: Optional[float] = None,
    straight: Optional[bool] = None,
    *,
    speed_pct: Optional[float] = None,
    speed2_pct: Optional[float] = None,
    acceleration_pct: Optional[float] = None,
    deceleration_pct: Optional[float] = None,
  ):
    """
    Set motion profile values for the specified profile index on the PreciseFlex robot.

    Args:
      profile: Profile index to set values for.
      speed_percent: Percentage of maximum speed (0-100). 100 = full speed.
      speed2_percent: Secondary speed setting (0-100), typically for Cartesian moves. Normally 0.
      acceleration_percent: Percentage of maximum acceleration (0-100). 100 = full acceleration.
      deceleration_percent: Percentage of maximum deceleration (0-100). 100 = full deceleration.
      acceleration_ramp: Acceleration ramp time in seconds.
      deceleration_ramp: Deceleration ramp time in seconds.
      in_range: InRange value, from -1 to 100. -1 = allow blending, 0 = stop without checking, >0 =
        enforce position accuracy.
      straight: If True, follow a straight-line path (-1). If False, follow a joint-based path (0).
      speed_pct: deprecated, use `speed_percent`.
      speed2_pct: deprecated, use `speed2_percent`.
      acceleration_pct: deprecated, use `acceleration_percent`.
      deceleration_pct: deprecated, use `deceleration_percent`.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=2
      )
      speed_percent = speed_pct
    if speed2_pct is not None:
      warnings.warn(
        "`speed2_pct` is deprecated, use `speed2_percent`.", DeprecationWarning, stacklevel=2
      )
      speed2_percent = speed2_pct
    if acceleration_pct is not None:
      warnings.warn(
        "`acceleration_pct` is deprecated, use `acceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      acceleration_percent = acceleration_pct
    if deceleration_pct is not None:
      warnings.warn(
        "`deceleration_pct` is deprecated, use `deceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      deceleration_percent = deceleration_pct
    if (
      speed_percent is None
      or speed2_percent is None
      or acceleration_percent is None
      or deceleration_percent is None
      or acceleration_ramp is None
      or deceleration_ramp is None
      or in_range is None
      or straight is None
    ):
      arguments = {
        "speed_percent": speed_percent,
        "speed2_percent": speed2_percent,
        "acceleration_percent": acceleration_percent,
        "deceleration_percent": deceleration_percent,
        "acceleration_ramp": acceleration_ramp,
        "deceleration_ramp": deceleration_ramp,
        "in_range": in_range,
        "straight": straight,
      }
      missing = [name for name, value in arguments.items() if value is None]
      raise TypeError(f"set_motion_profile_values() missing required arguments: {missing}")
    if not 0 <= speed_percent <= 100:
      raise ValueError(f"speed_percent must be between 0 and 100, got {speed_percent}")
    if not 0 <= speed2_percent <= 100:
      raise ValueError(f"speed2_percent must be between 0 and 100, got {speed2_percent}")
    if not 0 <= acceleration_percent <= 100:
      raise ValueError(
        f"acceleration_percent must be between 0 and 100, got {acceleration_percent}"
      )
    if not 0 <= deceleration_percent <= 100:
      raise ValueError(
        f"deceleration_percent must be between 0 and 100, got {deceleration_percent}"
      )
    if acceleration_ramp < 0:
      raise ValueError("acceleration_ramp must be >= 0 (seconds).")
    if deceleration_ramp < 0:
      raise ValueError("deceleration_ramp must be >= 0 (seconds).")
    if not (-1 <= in_range <= 100):
      raise ValueError("InRange must be between -1 and 100.")
    straight_int = -1 if straight else 0
    await self._driver.send_command(
      f"Profile {profile} {speed_percent} {speed2_percent} {acceleration_percent} "
      f"{deceleration_percent} {acceleration_ramp} {deceleration_ramp} {in_range} {straight_int}"
    )

  async def _set_speed(self, speed_percent: float):
    """Set the speed percentage of the arm's movement (0-100)."""
    await self.set_profile_speed(self.profile_index, speed_percent)

  async def _request_speed(self) -> float:
    """Get the current speed percentage of the arm's movement."""
    return await self.request_profile_speed(self.profile_index)

  @contextlib.asynccontextmanager
  async def at_speed(self, speed_percent: Optional[float]) -> AsyncIterator[None]:
    """Run the moves inside at their own speed, then put the profile speed back.

    The restore runs in a ``finally``, so a fault mid-move cannot leave the arm slow. None changes
    nothing, so a caller can pass a speed straight through.

    Args:
      speed_percent: Movement speed as a percentage (0-100), or None to keep the current one.
    """
    if speed_percent is None:
      yield
      return
    prior = await self._request_speed()
    await self._set_speed(speed_percent)
    try:
      yield
    finally:
      try:
        await self._set_speed(prior)
      except Exception:
        # Raising here replaces the move's own error, so say plainly what the arm is left at.
        logger.error(
          "[PreciseFlex %s] could not restore profile speed to %s; the arm is still at %s",
          self._driver.io._host,
          prior,
          speed_percent,
        )
        raise

  # -- brakes, torque and freedrive ----------------------------------------------------------------

  async def release_brake(self, axis: int) -> None:
    """Release the axis brake.

    Overrides the normal operation of the brake. It is important that the brake not be set
    while a motion is being performed. This feature is used to lock an axis to prevent
    motion or jitter.

    Args:
      axis: The number of the axis whose brake should be released.
    """
    await self._driver.send_command(f"releaseBrake {axis}")

  async def reengage_brake(self, axis: int) -> None:
    """Re-engage the axis brake.

    Overrides the normal operation of the brake. It is important not to set a brake on an
    axis that is moving as it may damage the brake or damage the motor.

    Args:
      axis: The number of the axis whose brake should be set.
    """
    await self._driver.send_command(f"setBrake {axis}")

  async def _unchecked_fw_start_zero_torque(self, axis_mask: int) -> None:
    """Place the axes of ``axis_mask`` in zero torque mode. Nothing is guarded."""
    await self._driver.send_command(f"zeroTorque 1 {axis_mask}")

  async def start_zero_torque(self, axis_mask: int = 1) -> None:
    """Place axes of the selected robot in zero torque mode.

    Individual axes may be placed into zero torque mode while the remaining axes are servoing.

    Args:
      axis_mask: The bit mask specifying the axes to be placed in torque mode. The mask is computed
        by OR'ing the axis bits: 1 = axis 1, 2 = axis 2, 4 = axis 3, 8 = axis 4, etc.

    Raises:
      ValueError: If ``axis_mask`` names no axis.
    """
    if axis_mask <= 0:
      raise ValueError(f"axis_mask must be greater than 0, is {axis_mask}")
    await self._unchecked_fw_start_zero_torque(axis_mask)

  async def stop_zero_torque(self) -> None:
    """Take the entire robot out of zero torque mode."""
    await self._driver.send_command("zeroTorque 0")

  @evented_operation(
    "precise_flex.start_freedrive",
    lambda self, free_axes=None: {
      "device": self._driver._controller_reference(),
      "free_axes": [int(axis) for axis in free_axes] if free_axes is not None else None,
    },
  )
  async def start_freedrive_mode(self, free_axes: Optional[List[int]] = None) -> None:
    """Enter freedrive mode, allowing manual movement of the specified joints.

    The robot must be attached to enter free mode.

    Args:
      free_axes: List of joint indices to free. Use [0] for all axes.
    """
    if free_axes is None:
      # The positioning axes that exist: freemode on an absent rail returns -2800.
      free_axes = [Axis.BASE, Axis.SHOULDER, Axis.ELBOW, Axis.WRIST]
      if self._driver.rail is not None:
        free_axes.append(Axis.RAIL)
    for axis in free_axes:
      await self._driver.send_command(f"freemode {axis}")

  @evented_operation(
    "precise_flex.stop_freedrive",
    lambda self: {"device": self._driver._controller_reference()},
  )
  async def stop_freedrive_mode(self) -> None:
    """Exit freedrive mode for all axes."""
    await self._driver.send_command("freemode -1")

  @evented_operation(
    "precise_flex.halt",
    lambda self: {"device": self._driver._controller_reference()},
  )
  async def halt(self):
    """Stops the current robot immediately but leaves power on."""
    await self._driver.send_command("halt")

  # -- limits and kinematics -----------------------------------------------------------------------

  async def request_joint_limits(self, hard: bool = False) -> Dict[Axis, tuple[float, float]]:
    """Per-axis travel limits as {Axis: (min, max)}.

    Returns the soft limits by default; pass ``hard=True`` for the hard limits.
    """
    min_id = DataID.HARD_LIMIT_MIN if hard else DataID.SOFT_LIMIT_MIN
    max_id = DataID.HARD_LIMIT_MAX if hard else DataID.SOFT_LIMIT_MAX
    return _zip_axis_ranges(
      _parse_per_axis(await self._driver.request_parameter(min_id)),
      _parse_per_axis(await self._driver.request_parameter(max_id)),
    )

  async def request_reference_speed(self) -> Dict[Axis, float]:
    """Per-axis rated speed at 100%; J1/J5 in mm/s, J2-J4 in deg/s."""
    return _parse_per_axis(await self._driver.request_parameter(DataID.REFERENCE_SPEED))

  async def request_reference_acceleration(self) -> Dict[Axis, float]:
    """Per-axis rated acceleration at 100%."""
    return _parse_per_axis(await self._driver.request_parameter(DataID.REFERENCE_ACCEL))

  async def request_link_lengths(self) -> tuple[float, float]:
    """(l1, l2) SCARA link lengths in mm: shoulder->elbow, elbow->wrist."""
    per_axis = _parse_per_axis(await self._driver.request_parameter(DataID.LINK_LENGTHS))
    return per_axis[Axis.SHOULDER], per_axis[Axis.ELBOW]

  async def request_tool_length(self) -> float:
    """Wrist->TCP distance in mm (z of the tool-offset transform)."""
    values = [
      float(v) for v in (await self._driver.request_parameter(DataID.TOOL_OFFSET)).split(",")
    ]
    return values[2]

  async def request_kinematic_parameters(self) -> "kinematics.PF400Params":
    """Build PF400Params from the controller's stored geometry.

    Link lengths and tool length come from the device; gripper_z_offset is not on
    the controller, so it is carried over from the constructor params.
    """
    l1, l2 = await self.request_link_lengths()
    return dataclasses.replace(
      self._driver._kinematics_params,
      l1=l1,
      l2=l2,
      gripper_length=await self.request_tool_length(),
    )

  async def request_reference_cartesian_speed(self) -> float:
    """Rated Cartesian (translational) speed at 100%, in mm/s."""
    return _parse_scalar(await self._driver.request_parameter(DataID.REFERENCE_CARTESIAN_SPEED))

  async def request_reference_cartesian_acceleration(self) -> float:
    """Rated Cartesian (translational) acceleration at 100%, in mm/s^2."""
    return _parse_scalar(await self._driver.request_parameter(DataID.REFERENCE_CARTESIAN_ACCEL))

  async def request_max_speed_percent(self) -> float:
    """Global cap on the speed percentage (one value, applies to all joints)."""
    return _parse_scalar(await self._driver.request_parameter(DataID.MAX_SPEED_PERCENT))

  async def request_max_acceleration_percent(self) -> float:
    """Global cap on the acceleration percentage (one value, applies to all joints)."""
    return _parse_scalar(await self._driver.request_parameter(DataID.MAX_ACCEL_PERCENT))

  async def request_max_deceleration_percent(self) -> float:
    """Global cap on the deceleration percentage (one value, applies to all joints)."""
    return _parse_scalar(await self._driver.request_parameter(DataID.MAX_DECEL_PERCENT))

  # -- base and tool frames ------------------------------------------------------------------------

  async def request_base(self) -> tuple[float, float, float, float]:
    """Get the robot base offset.

    Returns:
      A tuple containing (x_offset, y_offset, z_offset, z_rotation)
    """
    data = await self._driver.send_command("base")
    parts = data.split()
    if len(parts) != 4:
      raise PreciseFlexError(-1, "Unexpected response format from base command.")
    return (float(parts[0]), float(parts[1]), float(parts[2]), float(parts[3]))

  async def set_base(
    self, x_offset: float, y_offset: float, z_offset: float, z_rotation: float
  ) -> None:
    """Set the robot base offset.

    Args:
      x_offset: Base X offset
      y_offset: Base Y offset
      z_offset: Base Z offset
      z_rotation: Base Z rotation

    Note:
      The robot must be attached to set the base.
      Setting the base pauses any robot motion in progress.
    """
    await self._driver.send_command(f"base {x_offset} {y_offset} {z_offset} {z_rotation}")

  async def request_tool_transformation_values(
    self,
  ) -> tuple[float, float, float, float, float, float]:
    """Get the current tool transformation values.

    Returns:
      A tuple containing (X, Y, Z, yaw, pitch, roll) for the tool transformation.
    """
    data = await self._driver.send_command("tool")
    if data.startswith("tool: "):
      data = data[6:]
    parts = data.split()
    if len(parts) != 6:
      raise PreciseFlexError(-1, "Unexpected response format from tool command.")
    x, y, z, yaw, pitch, roll = self._parse_xyz_response(parts)
    return (x, y, z, yaw, pitch, roll)

  async def _set_tool_transformation_values(
    self, x: float, y: float, z: float, yaw: float, pitch: float, roll: float
  ) -> None:
    """Set the robot tool transformation (private).

    Private because the client kinematics read the tool once at setup into the frozen configuration;
    changing it live desyncs `request_gripper_pose` from the controller's `wherec` until the
    configuration is rebuilt. The robot must be attached to set the tool, and setting it pauses any
    robot motion in progress.

    Args:
      x: Tool X coordinate.
      y: Tool Y coordinate.
      z: Tool Z coordinate.
      yaw: Tool yaw rotation.
      pitch: Tool pitch rotation.
      roll: Tool roll rotation.
    """
    await self._driver.send_command(f"tool {x} {y} {z} {yaw} {pitch} {roll}")

  # -- range checks and recovery -------------------------------------------------------------------

  def _get_soft_limits(self) -> Dict[Axis, tuple]:
    """Every axis's soft limits - the arm's joints, the gripper and the rail; empty before setup."""
    gripper, rail = self._driver.gripper.configuration, self._driver.rail
    if self.configuration is None or gripper is None:
      return {}
    soft_limits = {**self.configuration.soft_limits, Axis.GRIPPER: gripper.soft_limit_range}
    if rail is not None and rail.configuration is not None:
      soft_limits[Axis.RAIL] = rail.configuration.soft_limit_range
    return soft_limits

  # Axes recovered when out of range, safest first: the jaws, the Z column, the shoulder, the elbow.
  # Not the wrist, which can turn the gripper into the arm, nor the rail: setup raises on those.
  _RECOVERY_ORDER = (Axis.GRIPPER, Axis.BASE, Axis.SHOULDER, Axis.ELBOW)

  def _axes_outside_soft_limits(self, joints: JointState) -> Dict[Axis, tuple]:
    """Axes whose value lies outside their soft limit, as ``axis -> (value, (lo, hi))``.

    Iterates the soft-limit set (keyed by :class:`Axis`) and looks each axis up in
    ``joints`` so the comparison stays Axis-typed. Empty until the configuration has
    been discovered.
    """
    outside: Dict[Axis, tuple] = {}
    for axis, (lo, hi) in self._get_soft_limits().items():
      value = joints.get(axis)
      if value is not None and not (lo <= value <= hi):
        outside[axis] = (value, (lo, hi))
    return outside

  @staticmethod
  def _fmt_axes(axes: Dict[Axis, tuple]) -> str:
    """Format ``{axis: (value, (lo, hi))}`` for logs/errors, e.g.
    ``BASE at 0.959 (soft limit (1.5, 401.5))``."""
    return "; ".join(
      f"{axis.name} at {value} (soft limit {limit})" for axis, (value, limit) in axes.items()
    )

  async def recover_axes_within_limits(
    self,
    speed_percent: Optional[float] = None,
    max_distance: Optional[float] = 5.0,
    *,
    speed_pct: Optional[float] = None,
  ) -> Dict[Axis, float]:
    """Bring out-of-range axes back inside their soft limits, one axis at a time.

    While an axis is outside its soft limit the controller rejects every commanded
    coordinated move (-1012), and homing does not help on the absolute rotary axes.
    A single-axis move is the documented exception: it may move an axis toward the
    in-range region. Each recoverable offender is driven to just inside its nearest
    soft limit, slowly, waiting for each to finish, in :attr:`_RECOVERY_ORDER`.

    Args:
      speed_percent: Profile speed for the recovery moves, in percent; deliberately slow.
        ``default_recovery_speed_percent`` when None.
      max_distance: only move an axis that is out of range by at most this much (deg
        for the rotary axes, mm for base/gripper). An axis further out is left in place:
        a large unattended single-axis sweep risks a collision, so it is left for the
        caller to recover manually (e.g. by freedriving). Pass None to move regardless.
      speed_pct: deprecated, use `speed_percent`.

    Returns:
      The axes moved, as ``axis -> recovered target``. Empty when nothing recoverable
      is out of range or the configuration was not discovered. The wrist and rail are
      never auto-recovered (see :attr:`_RECOVERY_ORDER`), nor a gripper open past its limit,
      since bringing it in would close it without sensing force.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=2
      )
      speed_percent = speed_pct
    if speed_percent is None:
      speed_percent = self.default_recovery_speed_percent
    outside = self._axes_outside_soft_limits(await self.request_joint_state())
    if not outside:
      return {}
    prior_speed = await self._request_speed()
    await self._set_speed(speed_percent)
    recovered: Dict[Axis, float] = {}
    try:
      for axis in self._RECOVERY_ORDER:
        if axis not in outside:
          continue
        value, (lo, hi) = outside[axis]
        above = value > hi  # which limit is violated; both moves below hinge on this
        overshoot = (value - hi) if above else (lo - value)
        if max_distance is not None and overshoot > max_distance:
          continue  # too far out to move unattended; left for the post-condition to raise
        if axis == Axis.GRIPPER and above:
          continue  # bringing it in would close it without force sensing; left for the caller
        # Land just inside the violated limit. The 1-unit margin is at most half the range, so the
        # target stays inside a range narrower than the margin.
        margin = min(1.0, (hi - lo) / 2.0)
        target = (hi - margin) if above else (lo + margin)
        logger.warning(
          "[PreciseFlex %s] recovering %s from %s into soft limit [%s, %s] -> %s",
          self._driver.io._host,
          axis.name,
          value,
          lo,
          hi,
          target,
        )
        await self._unchecked_fw_move_one_axis(axis, target)
        await self._wait_for_eom()
        recovered[axis] = target
    finally:
      await self._set_speed(prior_speed)  # don't leave the profile at the slow recovery speed
    return recovered

  async def _handle_out_of_range_axes(self) -> None:
    """Warn about every out-of-range axis, then correct what is recoverable, or raise.

    An axis out of range (its current position outside its soft limit) makes the arm unusable - the
    controller rejects every commanded move with -1012. Setup logs the full set first (either way),
    then, with ``recover_out_of_range`` on (the default), drives each recoverable offender back into
    range. If recovery is off or leaves any axis out, setup raises with explicit recovery steps
    rather than leaving a dead arm.

    No-op until the robot is homed: an unhomed incremental axis reads a meaningless ~0
    (so the check would false-positive), and the controller blocks the recovery move with
    -1021 anyway. Homing is the prerequisite, so the check waits for it.
    """
    if not await self._driver._is_robot_homed():
      logger.warning(
        "[PreciseFlex %s] robot not homed; skipping the out-of-range check until it is "
        "(home() first - unhomed positions are unreliable and commanded moves are blocked).",
        self._driver.io._host,
      )
      return

    outside = self._axes_outside_soft_limits(await self.request_joint_state())
    if not outside:
      return
    logger.warning(
      "[PreciseFlex %s] axes out of soft limit at setup: %s",
      self._driver.io._host,
      self._fmt_axes(outside),
    )
    if self._driver._recover_out_of_range:
      await self.recover_axes_within_limits()
      outside = self._axes_outside_soft_limits(await self.request_joint_state())
    if outside:
      raise OutOfRangeOfMotionError(
        f"axis outside its soft limit after setup: {self._fmt_axes(outside)}. The controller "
        "rejects all commanded moves in this state. Recover with recover_axes_within_limits(), "
        "or freedrive the axis back into range manually (required for the wrist, or when an axis "
        "is far past its limit).",
        axes=outside,
      )

  def _assert_within_soft_limits(self, current: JointState, target: JointState) -> None:
    """Guard a commanded move. The controller rejects every move with -1012 while an axis is out of
    range - whether that is the *current* pose or the commanded *target*. They are distinct failures
    with distinct types:

    - an axis whose *current* position is out of range is a recoverable arm *state* (e.g. it lost
      power and drifted past its limit) -> ``OutOfRangeOfMotionError``, which the caller can recover
      and retry. Homing will not fix it (the rotary axes are absolute); call
      ``recover_axes_within_limits()`` to drive it back into range.
    - an axis whose *target* is out of range is a bad request (freedrive can hand-move an axis past
      a soft limit, so a taught pose can land outside the commandable envelope) -> ``ValueError``;
      re-teach the pose.

    No-op until the configuration is discovered.
    """
    out_of_range = self._axes_outside_soft_limits(current)
    if out_of_range:
      raise OutOfRangeOfMotionError(
        f"axis out of range: {self._fmt_axes(out_of_range)}. The controller rejects every "
        "commanded move while an axis is out of range. Homing will not recover it (the rotary "
        "axes are absolute); call recover_axes_within_limits() to drive it back into range.",
        axes=out_of_range,
      )
    for axis, (value, limit) in self._axes_outside_soft_limits(target).items():
      raise ValueError(
        f"{axis.name} target {value} is outside its soft limit {limit}; the controller "
        f"would reject the move (-1012). Re-teach this pose within the envelope."
      )

  def _refuse_closing_the_gripper(self, current: JointState, target: JointState) -> None:
    """Refuse a joint move that would close the jaws: a joint move senses no force.

    Raises:
      ValueError: If the target's gripper axis is below the live one.
    """
    if target[Axis.GRIPPER] < current[Axis.GRIPPER]:
      raise ValueError(
        f"the joint move would close the gripper from {current[Axis.GRIPPER]} to "
        f"{target[Axis.GRIPPER]} without sensing force; close it with "
        f"gripper.move_to_jaw_position, or pass close_gripper_without_force_sensing=True"
      )

  def _forward_kinematics(self, joints: JointState) -> PreciseFlexPose:
    """Where a joint state puts every joint of the arm and its gripper. Nothing is read.

    Args:
      joints: the joint state, as ``request_joint_state`` returns it.
    """
    p = self._driver._kinematics_params
    link_1 = math.radians(joints[Axis.SHOULDER])
    link_2 = link_1 + math.radians(joints[Axis.ELBOW])
    shoulder = Coordinate(x=joints.get(Axis.RAIL, 0.0), y=0.0, z=joints[Axis.BASE])
    elbow = Coordinate(
      x=shoulder.x + p.l1 * math.cos(link_1), y=shoulder.y + p.l1 * math.sin(link_1), z=shoulder.z
    )
    wrist = Coordinate(
      x=elbow.x + p.l2 * math.cos(link_2), y=elbow.y + p.l2 * math.sin(link_2), z=shoulder.z
    )
    return PreciseFlexPose(
      shoulder_joint_location=shoulder,
      elbow_joint_location=elbow,
      wrist_joint_location=wrist,
      gripper_pose=kinematics.fk(joints, p),
      joints=dict(joints),
    )

  def _get_column_clearance(self, joints: JointState) -> Optional[Tuple[str, float]]:
    """Which part of the gripper would stand nearest the column at this joint state, and how near.

    Worked out from the joint state and the resource model, seen from above; nothing is read and the
    model is not moved.

    Args:
      joints: the joint state to work it out at.

    Returns:
      The part's name and its clearance in mm, negative when it overlaps. None when the arm is not
      modelled.
    """
    gripper = self._driver.gripper.resource
    if self.resource is None or gripper is None:
      return None
    pose = self._forward_kinematics(joints)
    # From the shoulder axis, which the rail carries along with the column.
    wrist = pose.wrist_joint_location - pose.shoulder_joint_location
    yaw = math.radians(pose.gripper_pose.rotation.z)
    joint = gripper.proximal_joint

    def from_shoulder_axis(points: Sequence[Tuple[float, float]]) -> List[Tuple[float, float]]:
      """Points in the gripper's own frame, as they would stand about the shoulder axis."""
      return [
        (
          wrist.x + (x - joint.x) * math.cos(yaw) - (y - joint.y) * math.sin(yaw),
          wrist.y + (x - joint.x) * math.sin(yaw) + (y - joint.y) * math.cos(yaw),
        )
        for x, y in points
      ]

    # The shoulder axis within the column, which the carriage rides and the reference point states.
    axis = cast(Coordinate, self.resource.location) + Z_CARRIAGE_REFERENCE_POINT
    column_outline = [(x - axis.x, y - axis.y) for x, y in Z_COLUMN_OUTLINE]

    half_width = self._driver.gripper._firmware_units_to_mm(joints[Axis.GRIPPER]) / 2
    parts = {gripper.body.name: list(GRIPPER_BODY_OUTLINE)}
    for finger, jaw, side in zip(gripper.fingers, gripper.jaws, (1.0, -1.0)):
      # The finger's facing surface stands half the width from the grip centre, and its jaw stands
      # where that puts it: both as a rectangle along the gripper, about the wrist joint's y.
      bolted, stood = cast(Coordinate, finger.location), cast(Coordinate, jaw.location)
      facing = joint.y + side * half_width
      corner = facing if side > 0 else facing - finger.get_size_y()
      for part, x, y in ((finger, stood.x + bolted.x, corner), (jaw, stood.x, corner - bolted.y)):
        x_2, y_2 = x + part.get_size_x(), y + part.get_size_y()
        parts[part.name] = [(x, y), (x_2, y), (x_2, y_2), (x, y_2)]
    return min(
      (
        (name, kinematics.compute_outline_clearance(from_shoulder_axis(outline), column_outline))
        for name, outline in parts.items()
      ),
      key=lambda nearest: nearest[1],
    )

  def _check_pose_reachable(self, joints: JointState) -> None:
    """Raise if the gripper would stand in or against the column at this joint state.

    One pose only: what the arm sweeps through on the way to it is `_check_path_reachable`. Skipped
    when the arm is not modelled - a check that cannot be made must not look like one that passed.

    Args:
      joints: the joint state the arm is being sent to.

    Raises:
      ValueError: If the gripper's body, a jaw or a finger would come within `_COLUMN_CLEARANCE`
        of the column.
    """
    nearest = self._get_column_clearance(joints)
    if nearest is not None and nearest[1] < _COLUMN_CLEARANCE:
      raise ValueError(
        f"{nearest[0]} would stand {nearest[1]:.1f} mm from the column, nearer than the "
        f"{_COLUMN_CLEARANCE} mm kept clear of it"
      )

  def _check_path_reachable(self, current: JointState, target: JointState) -> None:
    """Raise if a joint move would carry the gripper in or against the column on its way.

    A joint move turns every joint from where it is to its target together, so the path is taken as
    the straight line between the two joint states and checked at steps along it. A step is short
    enough that the gripper moves less than `_COLUMN_CLEARANCE` between two of them. An arm that
    starts nearer the column than that may move away from it, and no nearer. Skipped when the arm
    is not modelled.

    Args:
      current: the joint state the arm stands at.
      target: the joint state it is being sent to.

    Raises:
      ValueError: If the gripper's body, a jaw or a finger would come within `_COLUMN_CLEARANCE`
        of the column anywhere along the move.
    """
    nearest = self._get_column_clearance(current)
    if nearest is None:
      return
    p = self._driver._kinematics_params
    # How far the far end of a finger can travel: each joint's turn, by its distance from that end.
    reach = p.gripper_length + p.l2 + p.l1
    travel = sum(
      math.radians(abs(target[axis] - current[axis])) * radius
      for axis, radius in (
        (Axis.SHOULDER, reach),
        (Axis.ELBOW, reach - p.l1),
        (Axis.WRIST, reach - p.l1 - p.l2),
      )
    ) + abs(target[Axis.GRIPPER] - current[Axis.GRIPPER])
    steps = max(1, math.ceil(travel / _COLUMN_CLEARANCE))
    leaving = nearest[1] < _COLUMN_CLEARANCE
    for step in range(1, steps + 1):
      on_the_way = {
        axis: current[axis] + (target[axis] - current[axis]) * step / steps for axis in target
      }
      name, clearance = cast(Tuple[str, float], self._get_column_clearance(on_the_way))
      if clearance >= _COLUMN_CLEARANCE:
        leaving = False
      elif not leaving or clearance < nearest[1]:
        raise ValueError(
          f"on the way, with the shoulder at {on_the_way[Axis.SHOULDER]:.1f}, the elbow at "
          f"{on_the_way[Axis.ELBOW]:.1f} and the wrist at {on_the_way[Axis.WRIST]:.1f}, {name} "
          f"would stand {clearance:.1f} mm from the column, nearer than the {_COLUMN_CLEARANCE} mm "
          f"kept clear of it"
        )
      nearest = (name, clearance)

  async def _guarded_move_j(
    self,
    build_target: Callable[[JointState], JointState],
    close_gripper_without_force_sensing: bool = False,
  ) -> None:
    """The single guarded path to the raw ``_unchecked_fw_move_j`` primitive: read the live pose,
    check it and the target against the soft limits, check the way between them against the
    column, send the move, read where the arm stopped, and on out-of-range recover once and retry.
    Both ``move_to_joint_state`` (a partial spec merged over the live pose) and
    ``move_to_location`` (a full pose from IK) funnel through here, so no commanded move reaches
    ``_unchecked_fw_move_j`` unchecked.

    ``build_target`` maps the freshly-read pose to the full target joints - the only part that
    differs between the two callers. It re-runs each attempt, so a recovery move that shifts an
    unspecified axis is reflected in the next merge. A target that closes the gripper is refused
    unless ``close_gripper_without_force_sensing`` is set.

    When an axis is out of range the controller blocks the move (-1012). With
    ``recover_out_of_range`` set, this drives the offending axes back into range once
    (``recover_axes_within_limits``) and retries; otherwise the ``OutOfRangeOfMotionError``
    propagates. Recovery uses ``_unchecked_fw_move_one_axis``, a different primitive, so it cannot
    recurse here.
    """

    async def attempt() -> None:
      current = await self.request_joint_state()
      target = build_target(current)
      if not close_gripper_without_force_sensing:
        self._refuse_closing_the_gripper(current, target)
      self._assert_within_soft_limits(current, target)
      self._check_path_reachable(current, target)
      try:
        # Where the move is going, written as it is sent. The read below has the last word.
        self.update_joint_state(target)
        await self._unchecked_fw_move_j(profile_index=self.profile_index, joint_coords=target)
      finally:
        # `moveJ` returns once accepted: this waits for the arm to stop, then reads where it did.
        await self._request_joint_state_after_move()

    try:
      await attempt()
    except OutOfRangeOfMotionError as exc:
      if not self._driver._recover_out_of_range:
        raise
      host = self._driver.io._host
      logger.warning(
        "[PreciseFlex %s] commanded move blocked - %s; auto-recovery on -> recovering and retrying",
        host,
        self._fmt_axes(exc.axes),
      )
      await self.recover_axes_within_limits()
      try:
        await attempt()  # re-reads the live pose - recovery just moved an axis
      except OutOfRangeOfMotionError as exc2:
        logger.error(
          "[PreciseFlex %s] auto-recovery did not clear %s - freedrive/manual recovery needed",
          host,
          self._fmt_axes(exc2.axes),
        )
        raise
      logger.info("[PreciseFlex %s] out-of-range axes recovered; move retried successfully", host)

  # -- joint-space motion --------------------------------------------------------------------------

  @evented_operation(
    "precise_flex.move_to_joint_position",
    lambda self, joint_state, speed_percent=None: {
      "device": self._driver._controller_reference(),
      "target_joint_position": _joint_state_reference(joint_state),
      "speed_percent": speed_percent,
    },
  )
  async def move_to_joint_state(
    self,
    joint_state: JointState,
    speed_percent: Optional[float] = None,
    *,
    close_gripper_without_force_sensing: bool = False,
  ) -> None:
    """Move the arm to the specified joint state. A partial spec is merged over the live pose;
    the move is guarded against out-of-range axes (see ``_guarded_move_j``).

    Args:
      joint_state: Target joint state. Omitted axes keep their live values.
      speed_percent: Movement speed override as a percentage (0-100). If None, uses the current
        speed setting. It stays set afterwards; use ``at_speed`` to scope a speed to one move.
      close_gripper_without_force_sensing: allow a gripper axis below the live one. A joint move
        senses no force, so it is refused otherwise.
    """
    if speed_percent is not None:
      await self._set_speed(speed_percent)
    await self._guarded_move_j(
      lambda current: {**current, **joint_state},
      close_gripper_without_force_sensing=close_gripper_without_force_sensing,
    )

  async def request_gripper_pose(self) -> PreciseFlexCartesianPose:
    """Get the current pose using our kinematics model (no firmware `wherec`)."""
    _, pose = await self._request_state()
    return pose

  async def request_pose(self) -> PreciseFlexPose:
    """Where every joint of the arm is, worked out from the joint state; nothing else is asked."""
    return self._forward_kinematics(await self.request_joint_state())

  # -- cartesian motion ----------------------------------------------------------------------------

  def _require_rail(self) -> PreciseFlexRail:
    """The rail, on an arm that has one.

    Raises:
      RuntimeError: If the arm does not have a rail.
    """
    if self._driver.rail is None:
      raise RuntimeError("This arm does not have a rail.")
    return self._driver.rail

  @evented_operation(
    "precise_flex.move_to_location",
    lambda self, location, direction, speed_percent=None, orientation=None, wrist=None, rail_position=None, speed_pct=None: {
      "device": self._driver._controller_reference(),
      "target": _cartesian_target_reference(
        location,
        direction,
        orientation=orientation,
        wrist=wrist,
        rail_position=rail_position,
      ),
      "speed_percent": speed_percent if speed_pct is None else speed_pct,
    },
  )
  async def move_to_location(
    self,
    location: Coordinate,
    direction: float,
    speed_percent: Optional[float] = None,
    orientation: Optional[ElbowOrientation] = None,
    wrist: Optional[Wrist] = None,
    rail_position: Optional[float] = None,
    *,
    speed_pct: Optional[float] = None,
  ) -> None:
    """Move the arm to the specified Cartesian location. The IK target is guarded against
    out-of-range axes (see ``_guarded_move_j``).

    Args:
      location: Target Cartesian location.
      direction: Approach direction, applied as the pose's z rotation in degrees.
      speed_percent: Movement speed override as a percentage (0-100). If None, uses the current
        speed setting. It stays set afterwards; use ``at_speed`` to scope a speed to one move.
      orientation: Elbow orientation (``"lefty"`` or ``"righty"``). If None, the robot
        picks the closest configuration.
      wrist: Wrist configuration. If None, the robot picks the closest configuration.
      rail_position: Linear rail position in mm. Required when the arm has a rail.
      speed_pct: deprecated, use `speed_percent`.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=3
      )
      speed_percent = speed_pct
    if speed_percent is not None:
      await self._set_speed(speed_percent)

    if rail_position is not None:
      await self._require_rail().move_rail(rail_position)
    elif self._driver._has_rail:
      raise ValueError(
        "Rail position must be specified for move_to_location when using a rail-equipped arm."
      )

    coords = PreciseFlexCartesianPose(
      location=location,
      rotation=Rotation(x=-180, y=90, z=direction),
      orientation=orientation,
      wrist=wrist,
    )
    joints = await self._cart_to_joints(coords)
    await self._guarded_move_j(lambda _current: joints)

  async def _plan_cartesian_pose_route(
    self, poses: Sequence[PreciseFlexCartesianPose]
  ) -> List[JointState]:
    """Plan a Cartesian pose route into joint targets, snapshotting state once.

    Unlike :meth:`_cart_to_joints`, this does not query the controller for every waypoint: it
    reads the current state once and resolves each waypoint's IK from the previous waypoint's
    result. Omitted pose fields inherit from the previous pose so IK branch selection remains
    continuous across the route.
    """
    prev_joints, prev_pose = await self._request_state()
    targets: List[JointState] = []
    for pose in poses:
      cart = dataclasses.replace(
        pose,
        orientation=prev_pose.orientation if pose.orientation is None else pose.orientation,
        wrist=prev_pose.wrist if pose.wrist is None else pose.wrist,
        # PF400 IK expects a shoulder/reference rail position even on rail-less arms.
        # Mirror _cart_to_joints(): omitted pose fields inherit from the previous pose.
        rail_position=prev_pose.rail_position if pose.rail_position is None else pose.rail_position,
      )
      ik_joints = _snap_to_current(
        kinematics.ik(cart, p=self._driver._kinematics_params),
        prev_joints,
        cart.wrist,
      )
      # IK only solves the arm axes; gripper and rail keep the previous values.
      target = dict(prev_joints)
      for axis in (Axis.BASE, Axis.SHOULDER, Axis.ELBOW, Axis.WRIST):
        target[axis] = ik_joints[axis]
      if self._driver._has_rail and cart.rail_position is not None:
        target[Axis.RAIL] = cart.rail_position

      self._assert_within_soft_limits(prev_joints, target)
      targets.append(target)
      prev_joints = target
      prev_pose = cart
    return targets

  @evented_operation(
    "precise_flex.move_through_cartesian_poses",
    lambda self, poses, speed_percent=None, blend=True, speed_pct=None: {
      "device": self._driver._controller_reference(),
      "waypoint_count": len(poses),
      "start_target": (
        _cartesian_target_reference(
          poses[0].location,
          poses[0].rotation.z,
          orientation=poses[0].orientation,
          wrist=poses[0].wrist,
          rail_position=poses[0].rail_position,
        )
        if poses
        else None
      ),
      "end_target": (
        _cartesian_target_reference(
          poses[-1].location,
          poses[-1].rotation.z,
          orientation=poses[-1].orientation,
          wrist=poses[-1].wrist,
          rail_position=poses[-1].rail_position,
        )
        if poses
        else None
      ),
      "speed_percent": speed_percent if speed_pct is None else speed_pct,
      "blend": blend,
    },
  )
  async def move_through_cartesian_poses(
    self,
    poses: Sequence[PreciseFlexCartesianPose],
    speed_percent: Optional[float] = None,
    blend: bool = True,
    *,
    speed_pct: Optional[float] = None,
  ) -> None:
    """Move through a sequence of Cartesian poses using one planned IK route.

    The standard Cartesian move path snapshots the current state for each waypoint,
    which waits for end-of-motion between moves. For taught air-transit routes, this
    method snapshots state once, plans each subsequent IK target from the previous
    planned target, queues the joint moves, and waits only after the final waypoint.

    This is a PreciseFlex-specific primitive: intermediate waypoints may be blended
    by the controller and should not be used for operations that require an exact
    stop, gripper action, or physical contact at every pose.

    Args:
      poses: Cartesian waypoints to move through, in order.
      speed_percent: Movement speed override as a percentage (0-100). If None, uses the
        current speed setting. It stays set afterwards; use ``at_speed`` to scope a speed.
      blend: When True, temporarily set the active motion profile's ``InRange`` value to
        ``-1`` so the controller may blend through intermediate waypoints instead of stopping
        at each one. The original profile is restored after the final waypoint is reached.
      speed_pct: deprecated, use `speed_percent`.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=3
      )
      speed_percent = speed_pct
    if not poses:
      return
    if speed_percent is not None:
      await self._set_speed(speed_percent)

    targets = await self._plan_cartesian_pose_route(poses)

    profile_index = self.profile_index
    original_profile = None
    should_restore_profile = False
    if blend:
      original_profile = await self.request_motion_profile_values(profile_index)
      should_restore_profile = original_profile.in_range != BLEND_IN_RANGE
      if should_restore_profile:
        await self.set_motion_profile_values(*original_profile._replace(in_range=BLEND_IN_RANGE))

    try:
      for target in targets:
        await self._unchecked_fw_move_j(profile_index=profile_index, joint_coords=target)
    finally:
      # Let queued motion settle before returning or restoring the profile - restoring InRange
      # mid-move would change the in-flight blend.
      try:
        await self._wait_for_eom()
      finally:
        if should_restore_profile and original_profile is not None:
          await self.set_motion_profile_values(*original_profile)

  async def _unchecked_fw_request_cartesian_destination(
    self, mode: int = 0
  ) -> tuple[float, float, float, float, float, float, int]:
    """Ask the controller for its own Cartesian destination or current location.

    The controller computes this answer itself. `request_gripper_pose` reads the joints and runs
    PLR's kinematics, and is what anything relying on a Cartesian position should call.

    Args:
      mode: Selects return value. Defaults to 0.
      0 = Return current Cartesian location if robot is not moving
      1 = Return target Cartesian location of the previous or current move

    Returns:
      A tuple containing (X, Y, Z, yaw, pitch, roll, config)
      If mode = 1 or robot is moving, returns the target location.
      If mode = 0 and robot is not moving, returns the current location.
    """
    if mode == 0:
      data = await self._driver.send_command("destC")
    else:
      data = await self._driver.send_command(f"destC {mode}")
    parts = data.split()
    if len(parts) != 7:
      raise PreciseFlexError(-1, "Unexpected response format from destC command.")
    x, y, z, yaw, pitch, roll = self._parse_xyz_response(parts[:6])
    config = int(parts[6])
    return (x, y, z, yaw, pitch, roll, config)

  async def request_destination_joint_state(self, mode: int = 0) -> JointState:
    """Get the destination or current joint location of the robot.

    Args:
      mode: Selects return value. Defaults to 0.
      0 = Return current joint location if robot is not moving
      1 = Return target joint location of the previous or current move

    Returns:
      A dict mapping Axis to float values.
      If mode = 1 or robot is moving, returns the target joint positions.
      If mode = 0 and robot is not moving, returns the current joint positions.
    """
    if mode == 0:
      data = await self._driver.send_command("destJ")
    else:
      data = await self._driver.send_command(f"destJ {mode}")
    parts = data.split()
    if not parts:
      raise PreciseFlexError(-1, "Unexpected response format from destJ command.")
    return self._parse_angles_response(parts)

  async def set_station_to_current_joint_state(self, station_index: int) -> None:
    """Record the current position of the selected robot into the specified Location as angles.

    The Location is automatically set to type "angles".

    Args:
      station_index: The station index, from 1 to N_LOC.
    """
    await self._driver.send_command(f"hereJ {station_index}")

  async def _unchecked_fw_set_station_to_current_cartesian_location(
    self, station_index: int
  ) -> None:
    """Record the current position of the selected robot into the specified Location as Cartesian.

    The Location object is automatically set to type "Cartesian".
    Can be used to change the pallet origin (index 1,1,1) value.

    Args:
      station_index: The station index, from 1 to N_LOC.
    """
    await self._driver.send_command(f"hereC {station_index}")

  # -- elbow orientation change --------------------------------------------------------------------

  async def _unchecked_fw_change_elbow_orientation(self, grip_mode: int) -> None:
    """Change righty to lefty or back through the customizable locations. Nothing is guarded."""
    await self._driver.send_command(f"ChangeConfig {grip_mode}")

  async def change_elbow_orientation(
    self, grip_mode: int = 0, *, close_gripper_without_force_sensing: bool = False
  ) -> None:
    """Change Robot configuration from Righty to Lefty or vice versa using customizable locations.

    Uses customizable locations to avoid hitting robot during change.
    Does not include checks for collision inside work volume of the robot.
    Can be customized by user for their work cell configuration.

    Args:
      grip_mode: Gripper control mode.
      0 = do not change gripper (default)
      1 = open gripper
      2 = close gripper, which senses no force; refused unless
        ``close_gripper_without_force_sensing``.
      close_gripper_without_force_sensing: allow ``grip_mode=2``.

    Raises:
      ValueError: If ``grip_mode`` is 2 and closing without force sensing was not allowed.
    """
    if grip_mode == 2 and not close_gripper_without_force_sensing:
      raise ValueError(
        "grip_mode=2 closes the gripper without sensing force; close it with "
        "gripper.move_to_jaw_position, or pass close_gripper_without_force_sensing=True"
      )
    await self._unchecked_fw_change_elbow_orientation(grip_mode)

  async def _unchecked_fw_change_elbow_orientation_by_algorithm(self, grip_mode: int) -> None:
    """Change righty to lefty or back by the controller's algorithm. Nothing is guarded."""
    await self._driver.send_command(f"ChangeConfig2 {grip_mode}")

  async def change_elbow_orientation_by_algorithm(
    self, grip_mode: int = 0, *, close_gripper_without_force_sensing: bool = False
  ) -> None:
    """Change Robot configuration from Righty to Lefty or vice versa using algorithm.

    Uses an algorithm to avoid hitting robot during change.
    Does not include checks for collision inside work volume of the robot.
    Can be customized by user for their work cell configuration.

    Args:
      grip_mode: Gripper control mode.
      0 = do not change gripper (default)
      1 = open gripper
      2 = close gripper, which senses no force; refused unless
        ``close_gripper_without_force_sensing``.
      close_gripper_without_force_sensing: allow ``grip_mode=2``.

    Raises:
      ValueError: If ``grip_mode`` is 2 and closing without force sensing was not allowed.
    """
    if grip_mode == 2 and not close_gripper_without_force_sensing:
      raise ValueError(
        "grip_mode=2 closes the gripper without sensing force; close it with "
        "gripper.move_to_jaw_position, or pass close_gripper_without_force_sensing=True"
      )
    await self._unchecked_fw_change_elbow_orientation_by_algorithm(grip_mode)

  # -- pick and place ------------------------------------------------------------------------------

  async def _unchecked_fw_set_grip_detail(self):
    """Configure a default vertical station type for pick/place operations."""
    await self._driver.send_command(f"StationType {self.station_index} 1 0 100 0 10")

  async def _pick_plate_j(self, joint_position: JointState):
    """Pick a plate from the specified position using joint coordinates."""
    await self._unchecked_fw_set_joint_angles(self.station_index, joint_position)
    await self._unchecked_fw_set_grip_detail()
    horizontal_compliance_int = 1 if self.horizontal_compliance else 0
    ret_code = await self._driver.send_command(
      f"pickplate {self.station_index} {horizontal_compliance_int} "
      f"{self.horizontal_compliance_torque}"
    )
    if ret_code == "0":
      raise PreciseFlexError(-1, "the force-controlled gripper detected no plate present.")

  async def _place_plate_j(self, joint_position: JointState):
    """Place a plate at the specified position using joint coordinates."""
    await self._unchecked_fw_set_joint_angles(self.station_index, joint_position)
    await self._unchecked_fw_set_grip_detail()
    horizontal_compliance_int = 1 if self.horizontal_compliance else 0
    await self._driver.send_command(
      f"placeplate {self.station_index} {horizontal_compliance_int} "
      f"{self.horizontal_compliance_torque}"
    )

  async def _pick_plate_c(self, cartesian_position: PreciseFlexCartesianPose):
    """Pick a plate at a Cartesian position via IK + joint-space pickplate."""
    joints = await self._cart_to_joints(cartesian_position)
    await self._pick_plate_j(joints)

  async def _place_plate_c(self, cartesian_position: PreciseFlexCartesianPose):
    """Place a plate at a Cartesian position via IK + joint-space placeplate."""
    joints = await self._cart_to_joints(cartesian_position)
    await self._place_plate_j(joints)

  @evented_operation(
    "precise_flex.pick_up_at_joint_position",
    lambda self, joint_state, resource_width, finger_speed_percent=None, grasp_force=None: {
      "device": self._driver._controller_reference(),
      "target_joint_position": _joint_state_reference(joint_state),
      "resource_width": float(resource_width),
      "finger_speed_percent": float(
        self._driver.gripper.default_finger_speed_percent
        if finger_speed_percent is None
        else finger_speed_percent
      ),
      "grasp_force": float(
        self._driver.gripper.default_grasp_force if grasp_force is None else grasp_force
      ),
    },
  )
  async def pick_up_at_joint_state(
    self,
    joint_state: JointState,
    resource_width: float,
    finger_speed_percent: Optional[float] = None,
    grasp_force: Optional[float] = None,
  ) -> None:
    """Pick up at the specified joint state.

    Args:
      joint_state: Joint state to pick from.
      resource_width: Width of the resource to grasp, in mm.
      finger_speed_percent: Finger closing speed as a percentage (0-100).
        ``default_finger_speed_percent`` when None.
      grasp_force: Grasp force in Newtons. ``default_grasp_force`` when None.
    """
    if finger_speed_percent is None:
      finger_speed_percent = self._driver.gripper.default_finger_speed_percent
    if grasp_force is None:
      grasp_force = self._driver.gripper.default_grasp_force
    logger.info(
      "[PreciseFlex %s] pick_up: joints=%s, resource_width_mm=%s",
      self._driver.io._host,
      joint_state,
      resource_width,
    )
    await self._driver.gripper._set_grasp_data(
      plate_width=resource_width,
      finger_speed_percent=finger_speed_percent,
      grasp_force=grasp_force,
    )
    await self._pick_plate_j(joint_state)

  @evented_operation(
    "precise_flex.drop_at_joint_position",
    lambda self, joint_state, resource_width: {
      "device": self._driver._controller_reference(),
      "target_joint_position": _joint_state_reference(joint_state),
      "resource_width": float(resource_width),
    },
  )
  async def drop_at_joint_state(
    self,
    joint_state: JointState,
    resource_width: float,
  ) -> None:
    """Drop at the specified joint state.

    Args:
      joint_state: Joint state to drop at.
      resource_width: Width of the held resource, in mm.
    """
    logger.info(
      "[PreciseFlex %s] drop: joints=%s, resource_width_mm=%s",
      self._driver.io._host,
      joint_state,
      resource_width,
    )
    await self._place_plate_j(joint_state)

  @evented_operation(
    "precise_flex.pick_up_at_location",
    lambda self, location, direction, resource_width, finger_speed_percent=None, grasp_force=None, orientation=None, wrist=None, rail_position=None, finger_speed_pct=None: {
      "device": self._driver._controller_reference(),
      "target": _cartesian_target_reference(
        location,
        direction,
        orientation=orientation,
        wrist=wrist,
        rail_position=rail_position,
      ),
      "resource_width": float(resource_width),
      "finger_speed_percent": float(
        next(
          value
          for value in (
            finger_speed_pct,
            finger_speed_percent,
            self._driver.gripper.default_finger_speed_percent,
          )
          if value is not None
        )
      ),
      "grasp_force": float(
        self._driver.gripper.default_grasp_force if grasp_force is None else grasp_force
      ),
    },
  )
  async def pick_up_at_location(
    self,
    location: Coordinate,
    direction: float,
    resource_width: float,
    finger_speed_percent: Optional[float] = None,
    grasp_force: Optional[float] = None,
    orientation: Optional[ElbowOrientation] = None,
    wrist: Optional[Wrist] = None,
    rail_position: Optional[float] = None,
    *,
    finger_speed_pct: Optional[float] = None,
  ) -> None:
    """Pick up at the specified Cartesian location.

    Args:
      location: Cartesian location to pick from.
      direction: Approach direction, applied as the pose's z rotation in degrees.
      resource_width: Width of the resource to grasp, in mm.
      finger_speed_percent: Finger closing speed as a percentage (0-100).
        ``default_finger_speed_percent`` when None.
      grasp_force: Grasp force in Newtons. ``default_grasp_force`` when None.
      orientation: Elbow orientation (``"lefty"`` or ``"righty"``). If None, the robot
        picks the closest configuration.
      wrist: Wrist configuration. If None, the robot picks the closest configuration.
      rail_position: Linear rail position in mm. Required when the arm has a rail.
      finger_speed_pct: deprecated, use `finger_speed_percent`.
    """
    if finger_speed_pct is not None:
      warnings.warn(
        "`finger_speed_pct` is deprecated, use `finger_speed_percent`.",
        DeprecationWarning,
        stacklevel=3,
      )
      finger_speed_percent = finger_speed_pct
    if finger_speed_percent is None:
      finger_speed_percent = self._driver.gripper.default_finger_speed_percent
    if grasp_force is None:
      grasp_force = self._driver.gripper.default_grasp_force
    logger.info(
      "[PreciseFlex %s] pick_up: x=%s, y=%s, z=%s, direction=%s, resource_width_mm=%s",
      self._driver.io._host,
      location.x,
      location.y,
      location.z,
      direction,
      resource_width,
    )
    if rail_position is not None:
      await self._require_rail().move_rail(rail_position)
    elif self._driver._has_rail:
      raise ValueError(
        "rail_position must be specified for pick_up_at_location when using a rail-equipped arm."
      )
    coords = PreciseFlexCartesianPose(
      location=location,
      rotation=Rotation(z=direction),
      orientation=orientation,
      wrist=wrist,
    )
    await self._driver.gripper._set_grasp_data(
      plate_width=resource_width,
      finger_speed_percent=finger_speed_percent,
      grasp_force=grasp_force,
    )
    await self._pick_plate_c(cartesian_position=coords)

  @evented_operation(
    "precise_flex.drop_at_location",
    lambda self, location, direction, resource_width, orientation=None, wrist=None, rail_position=None: {
      "device": self._driver._controller_reference(),
      "target": _cartesian_target_reference(
        location,
        direction,
        orientation=orientation,
        wrist=wrist,
        rail_position=rail_position,
      ),
      "resource_width": float(resource_width),
    },
  )
  async def drop_at_location(
    self,
    location: Coordinate,
    direction: float,
    resource_width: float,
    orientation: Optional[ElbowOrientation] = None,
    wrist: Optional[Wrist] = None,
    rail_position: Optional[float] = None,
  ) -> None:
    """Drop at the specified Cartesian location.

    Args:
      location: Cartesian location to drop at.
      direction: Approach direction, applied as the pose's z rotation in degrees.
      resource_width: Width of the held resource, in mm.
      orientation: Elbow orientation (``"lefty"`` or ``"righty"``). If None, the robot
        picks the closest configuration.
      wrist: Wrist configuration. If None, the robot picks the closest configuration.
      rail_position: Linear rail position in mm. Required when the arm has a rail.
    """
    logger.info(
      "[PreciseFlex %s] drop: x=%s, y=%s, z=%s, direction=%s, resource_width_mm=%s",
      self._driver.io._host,
      location.x,
      location.y,
      location.z,
      direction,
      resource_width,
    )
    if rail_position is not None:
      await self._require_rail().move_rail(rail_position)
    elif self._driver._has_rail:
      raise ValueError(
        "rail_position must be specified for drop_at_location when using a rail-equipped arm."
      )
    coords = PreciseFlexCartesianPose(
      location=location,
      rotation=Rotation(z=direction),
      orientation=orientation,
      wrist=wrist,
    )
    await self._place_plate_c(cartesian_position=coords)

  # -- parking -------------------------------------------------------------------------------------

  def _validate_parking_position(self, position: JointState) -> None:
    """Reject anything that is not a JointState of in-range axes (limits checked once known)."""
    if not isinstance(position, dict) or not position:
      raise ValueError(f"parking_position must be a non-empty JointState, got {position!r}")
    for axis, value in position.items():
      if not isinstance(axis, Axis):
        raise ValueError(f"parking_position keys must be Axis members, got {axis!r}")
      if not isinstance(value, (int, float)):
        raise ValueError(f"parking_position[{axis.name}] must be a number, got {value!r}")
      soft_limits = self._get_soft_limits()
      if soft_limits:
        lo, hi = soft_limits[axis]
        if not lo <= value <= hi:
          raise ValueError(
            f"parking_position[{axis.name}]={value} is outside the soft limits [{lo}, {hi}]"
          )

  def _parking_pose_with_default_z(self, position: JointState) -> JointState:
    """Fill the Z column (``Axis.BASE``) at 3/4 of the discovered travel when the pose omits it."""
    if Axis.BASE in position or self.configuration is None:
      return position
    _, z_max = self.configuration.z_range
    return {Axis.BASE: 0.75 * z_max, **position}

  @property
  def parking_position(self) -> Optional[JointState]:
    """The pose ``park()`` moves to. Assign one of the ``PARKING_POSITION_BACK/RIGHT/FRONT`` class
    constants or any JointState; the assignment is validated (keys must be ``Axis`` members, values
    must be within the soft limits once the configuration is known). None until setup, where it
    defaults to ``PARKING_POSITION_RIGHT``. A pose that omits ``Axis.BASE`` has its Z filled at park
    time."""
    return self._parking_position

  @parking_position.setter
  def parking_position(self, position: Optional[JointState]) -> None:
    if position is not None:
      self._validate_parking_position(position)
    self._parking_position: Optional[JointState] = dict(position) if position is not None else None

  async def _unchecked_fw_park(self) -> None:
    """Move to the controller's own safe position (``movetosafe``). Nothing is guarded."""
    await self._driver.send_command("movetosafe")

  @evented_operation(
    "precise_flex.park",
    lambda self: {"device": self._driver._controller_reference()},
  )
  async def park(self) -> None:
    """Move to ``self.parking_position``; defaults at setup, reassignable at runtime.

    ``parking_position`` is filled at setup with ``PARKING_POSITION_RIGHT`` (a planar fold facing
    right, Z column at 3/4 of its discovered travel); assign one of the ``PARKING_POSITION_*`` class
    constants or any JointState to park elsewhere. Falls back to the firmware ``movetosafe`` while
    it is unset. No collision checks against 3rd-party obstacles.

    A parking pose says which way the gripper faces, and the wrist reaches that every full turn. On
    an arm that is modelled, a pose whose way there is refused is tried a full turn either side,
    the shorter turn first; the pose as written is taken whenever its way is clear.
    """
    if self.parking_position is None:
      await self._unchecked_fw_park()
      return
    pose = self._parking_pose_with_default_z(self.parking_position)
    if self.resource is not None and Axis.WRIST in pose:
      current = await self.request_joint_state()
      low, high = self._get_soft_limits().get(Axis.WRIST, (-math.inf, math.inf))
      turns = [pose[Axis.WRIST] + 360.0 * turn for turn in range(-3, 4)]
      # As written first, then the others by how far the wrist would have to turn.
      turns.sort(key=lambda wrist: (wrist != pose[Axis.WRIST], abs(wrist - current[Axis.WRIST])))
      for wrist in turns:
        if not low <= wrist <= high:
          continue
        try:
          self._check_path_reachable(current, {**current, **pose, Axis.WRIST: wrist})
        except ValueError:
          continue
        if wrist != pose[Axis.WRIST]:
          logger.info(
            "[PreciseFlex %s] parking with the wrist at %s, not %s: the way to it is clear",
            self._driver.io._host,
            wrist,
            pose[Axis.WRIST],
          )
        pose = {**pose, Axis.WRIST: wrist}
        break
    # A pose no turn of which is clear is sent as written, and refused there with where it fails.
    await self.move_to_joint_state(joint_state=pose)
