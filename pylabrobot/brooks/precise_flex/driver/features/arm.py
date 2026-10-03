"""The PreciseFlex arm: its joints and how they move, driven through the controller.

Reached as `driver.arm`. Reads the joint state, moves in joint space and in Cartesian space through
one guarded path, and brings out-of-range axes back inside their soft limits.
"""

import asyncio
import dataclasses
import logging
import time
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Sequence

from pylabrobot.events import coordinate_reference, evented_operation
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.rotation import Rotation

from ... import kinematics
from ...interrupt import halt_and_resync, halt_on_interrupt
from ...kinematics import Axis, ElbowOrientation, JointState, PreciseFlexCartesianPose, Wrist
from ..errors import OutOfRangeOfMotionError, PreciseFlexError
from .rail import PreciseFlexRail

if TYPE_CHECKING:
  from ..master import PreciseFlex

logger = logging.getLogger(__name__)

# InRange sentinel that lets the controller blend through waypoints instead of stopping at each one.
BLEND_IN_RANGE = -1


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


class PreciseFlexArm:
  """The arm of a PreciseFlex: its joints, read and moved through the controller.

  Reached as `driver.arm`. Sends through the driver's `send_command`; every commanded joint move goes
  through `_guarded_move_j`.
  """

  # What the driver sends when a caller leaves the value out. Tune one arm by assigning on the
  # instance, or every arm by assigning on the class.
  default_recovery_speed_pct: float = 20.0

  def __init__(self, driver: "PreciseFlex") -> None:
    """
    Args:
      driver: the driver to send commands through.
    """
    self._driver = driver

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

    Polls the live joint position (``wherej``) and returns once it stops changing between samples
    (every axis moving less than ``settle``) - i.e. end of motion. It returns promptly when the arm
    is already stationary, including when it was stopped short of its last commanded target (after a
    halt/interrupt or a hand-move), so it never hangs waiting to reach a target that will not be
    reached.

    This deliberately avoids the firmware ``waitForEom``: that command parks the controller's single
    command interpreter and makes it ignore everything else on the connection - including ``halt`` -
    until the move ends (hardware-verified). Polling instead leaves the connection free between
    samples, so a user interrupt can stop the move mid-flight via ``halt`` and other controller
    commands (status, vision, barcode) can run during motion.

    Raises:
      TimeoutError: if the arm never settles within ``timeout`` seconds.
      OperationInterrupted: on a user interrupt (the arm is halted and the connection kept).
    """

    def _floats(reply: str) -> list[float]:
      return [float(x) for x in reply.split()]

    # On interrupt, `halt` stops the move on the now-free connection and we resync; the connection is
    # kept open. Hardware-verified: a clean halt keeps power, attach, and the link (only a collision
    # trips -3122 and drops power, which needs explicit recovery). The halt is deliberately NOT taken
    # under `_io_lock`: the interrupted poll releases the lock as it unwinds, so today (single task)
    # there is no contention, and an emergency halt must not wait on another caller's in-flight read.
    # When concurrent socket users are introduced, the halt should pre-empt them (cancel peers) or
    # take the lock with a short timeout rather than block on a slow transaction.
    async with halt_on_interrupt(lambda: halt_and_resync(self._driver.io, b"halt")):
      previous = _floats(await self._driver.send_command("wherej"))
      deadline = time.monotonic() + timeout
      while True:
        await asyncio.sleep(poll_interval)
        current = _floats(await self._driver.send_command("wherej"))
        if all(abs(c - p) < settle for c, p in zip(current, previous)):
          return  # stopped moving
        if time.monotonic() > deadline:
          raise TimeoutError(f"motion did not settle within {timeout:.0f}s (current={current})")
        previous = current

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
    return self._parse_angles_response(parts)

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

  async def _move_j(self, profile_index: int, joint_coords: JointState) -> None:
    """Move the robot using joint coordinates, handling rail configuration. Raw moveJ - the
    out-of-range guard lives in the caller (``_guarded_move_j``), not in this primitive."""
    if self._driver._has_rail:
      angles_str = (
        f"{joint_coords[Axis.BASE]} "
        f"{joint_coords[Axis.SHOULDER]} "
        f"{joint_coords[Axis.ELBOW]} "
        f"{joint_coords[Axis.WRIST]} "
        f"{joint_coords[Axis.GRIPPER]} "
        f"{joint_coords[Axis.RAIL]} "
      )
    else:
      angles_str = (
        f"{joint_coords[Axis.BASE]} "
        f"{joint_coords[Axis.SHOULDER]} "
        f"{joint_coords[Axis.ELBOW]} "
        f"{joint_coords[Axis.WRIST]} "
        f"{joint_coords[Axis.GRIPPER]}"
      )
    await self._driver.send_command(f"moveJ {profile_index} {angles_str}")

  async def _move_one_axis(self, axis: Axis, position: float) -> None:
    """Move a single axis to an absolute position (firmware ``MoveOneAxis``).

    Used for recovery: the controller blocks a normal move while an axis is out of
    range, but allows a single-axis move heading back into range. Does not wait for
    the motion to complete.
    """
    await self._driver.send_command(
      f"MoveOneAxis {int(axis)} {position} {self._driver.profile_index}"
    )

  async def _move_to_stored_location(self, location_index: int, profile_index: int) -> None:
    """Move to the location specified by the station index using the specified profile.

    Args:
      location_index: The index of the location to which the robot moves.
      profile_index: The profile index for this move.

    Note:
      Requires that the robot be attached.
    """
    await self._driver.send_command(f"move {location_index} {profile_index}")

  async def _move_to_stored_location_appro(self, location_index: int, profile_index: int) -> None:
    """Approach the location specified by the station index using the specified profile.

    This is similar to `_move_to_stored_location` except that the Z clearance value is included.

    Args:
      location_index: The index of the location to which the robot moves.
      profile_index: The profile index for this move.

    Note:
      Requires that the robot be attached.
    """
    await self._driver.send_command(f"moveAppro {location_index} {profile_index}")

  async def _set_joint_angles(
    self,
    location_index: int,
    joint_position: JointState,
  ) -> None:
    """Set joint angles for stored location, handling rail configuration."""
    if self._driver._has_rail:
      await self._driver.send_command(
        f"locAngles {location_index} "
        f"{joint_position[Axis.RAIL]} "
        f"{joint_position[Axis.BASE]} "
        f"{joint_position[Axis.SHOULDER]} "
        f"{joint_position[Axis.ELBOW]} "
        f"{joint_position[Axis.WRIST]} "
        f"{joint_position[Axis.GRIPPER]}"
      )
    else:
      await self._driver.send_command(
        f"locAngles {location_index} "
        f"{joint_position[Axis.BASE]} "
        f"{joint_position[Axis.SHOULDER]} "
        f"{joint_position[Axis.ELBOW]} "
        f"{joint_position[Axis.WRIST]} "
        f"{joint_position[Axis.GRIPPER]}"
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

  # -- range checks and recovery -------------------------------------------------------------------

  # Axes auto-recovered when out of range, in a deliberately safe order: the
  # gripper jaw first (no arm motion), then the Z column (vertical clearance), then
  # the rotary links shoulder -> elbow (smallest swept volume last to first).
  # The wrist is intentionally absent: rotating it back to +/-180 can self-collide, so
  # it needs the other links first driven to minimal clearance from the origin - a
  # maneuver not implemented here. The rail (gross lateral travel) is likewise left out.
  # TODO: clearance-aware wrist recovery (and rail). An out-of-range wrist or rail is
  # left for the setup post-condition to raise on.
  _RECOVERY_ORDER = (Axis.GRIPPER, Axis.BASE, Axis.SHOULDER, Axis.ELBOW)

  def _axes_outside_soft_limits(self, joints: JointState) -> Dict[Axis, tuple]:
    """Axes whose value lies outside their soft limit, as ``axis -> (value, (lo, hi))``.

    Iterates the soft-limit set (keyed by :class:`Axis`) and looks each axis up in
    ``joints`` so the comparison stays Axis-typed. Empty until the configuration has
    been discovered.
    """
    if self._driver._configuration is None:
      return {}
    outside: Dict[Axis, tuple] = {}
    for axis, (lo, hi) in self._driver._configuration.soft_limits.items():
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
    self, speed_pct: Optional[float] = None, max_distance: Optional[float] = 5.0
  ) -> Dict[Axis, float]:
    """Bring out-of-range axes back inside their soft limits, one axis at a time.

    While an axis is outside its soft limit the controller rejects every commanded
    coordinated move (-1012), and homing does not help on the absolute rotary axes.
    A single-axis move is the documented exception: it may move an axis toward the
    in-range region. Each recoverable offender is driven to just inside its nearest
    soft limit, slowly, waiting for each to finish, in :attr:`_RECOVERY_ORDER`.

    Args:
      speed_pct: Profile speed for the recovery moves, in percent; deliberately slow.
        ``default_recovery_speed_pct`` when None.
      max_distance: only move an axis that is out of range by at most this much (deg
        for the rotary axes, mm for base/gripper). An axis further out is left in place:
        a large unattended single-axis sweep risks a collision, so it is left for the
        caller to recover manually (e.g. by freedriving). Pass None to move regardless.

    Returns:
      The axes moved, as ``axis -> recovered target``. Empty when nothing recoverable
      is out of range or the configuration was not discovered. The wrist and rail are
      never auto-recovered (see :attr:`_RECOVERY_ORDER`), nor a gripper open past its limit,
      since bringing it in would close it without sensing force.
    """
    if speed_pct is None:
      speed_pct = self.default_recovery_speed_pct
    outside = self._axes_outside_soft_limits(await self.request_joint_state())
    if not outside:
      return {}
    prior_speed = await self._driver._request_speed()
    await self._driver._set_speed(speed_pct)
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
        # Land just inside the violated limit, toward the in-range region. Clamp the
        # 1-unit margin to half the range so the target stays within [lo, hi] even if
        # the range is narrower than the margin (degenerate, but keeps direction sound).
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
        await self._move_one_axis(axis, target)
        await self._wait_for_eom()
        recovered[axis] = target
    finally:
      await self._driver._set_speed(
        prior_speed
      )  # don't leave the profile at the slow recovery speed
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
        f"axis outside its soft limit after setup: {self._fmt_axes(outside)}. The controller rejects all "
        f"commanded moves in this state. Recover with recover_axes_within_limits(), or freedrive "
        f"the axis back into range manually (required for the wrist, or when an axis is far past "
        f"its limit).",
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
    - an axis whose *target* is out of range is a bad request (freedrive can hand-move an axis past a
      soft limit, so a taught pose can land outside the commandable envelope) -> ``ValueError``;
      re-teach the pose.

    No-op until the configuration is discovered.
    """
    out_of_range = self._axes_outside_soft_limits(current)
    if out_of_range:
      raise OutOfRangeOfMotionError(
        f"axis out of range: {self._fmt_axes(out_of_range)}. The controller rejects every commanded "
        f"move while an axis is out of range. Homing will not recover it (the rotary axes are "
        f"absolute); call recover_axes_within_limits() to drive it back into range.",
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
        f"{target[Axis.GRIPPER]} without sensing force; close it with gripper.move_to_jaw_position, or "
        f"pass close_gripper_without_force_sensing=True"
      )

  async def _guarded_move_j(
    self,
    build_target: Callable[[JointState], JointState],
    close_gripper_without_force_sensing: bool = False,
  ) -> None:
    """The single guarded path to the raw ``_move_j`` primitive: read the live pose, check it and
    the target against the soft limits, send the move, and on out-of-range recover once and retry.
    Both ``move_to_joint_position`` (a partial spec merged over the live pose) and
    ``move_to_location`` (a full pose from IK) funnel through here, so no commanded move reaches
    ``_move_j`` unchecked.

    ``build_target`` maps the freshly-read pose to the full target joints - the only part that
    differs between the two callers. It re-runs each attempt, so a recovery move that shifts an
    unspecified axis is reflected in the next merge. A target that closes the gripper is refused
    unless ``close_gripper_without_force_sensing`` is set.

    When an axis is out of range the controller blocks the move (-1012). With ``recover_out_of_range``
    set, this drives the offending axes back into range once (``recover_axes_within_limits``) and
    retries; otherwise the ``OutOfRangeOfMotionError`` propagates. Recovery uses ``_move_one_axis``, a
    different primitive, so it cannot recurse here.
    """

    async def attempt() -> None:
      current = await self.request_joint_state()
      target = build_target(current)
      if not close_gripper_without_force_sensing:
        self._refuse_closing_the_gripper(current, target)
      self._assert_within_soft_limits(current, target)
      await self._move_j(profile_index=self._driver.profile_index, joint_coords=target)

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
    lambda self, position, speed_pct=None: {
      "device": self._driver._controller_reference(),
      "target_joint_position": _joint_state_reference(position),
      "speed_pct": speed_pct,
    },
  )
  async def move_to_joint_position(
    self,
    position: JointState,
    speed_pct: Optional[float] = None,
    *,
    close_gripper_without_force_sensing: bool = False,
  ) -> None:
    """Move the arm to the specified joint position. A partial spec is merged over the live pose;
    the move is guarded against out-of-range axes (see ``_guarded_move_j``).

    Args:
      position: Target joint state. Omitted axes keep their live values.
      speed_pct: Movement speed override as a percentage (0-100). If None, uses the current
        speed setting.
      close_gripper_without_force_sensing: allow a gripper axis below the live one. A joint move
        senses no force, so it is refused otherwise.
    """
    if speed_pct is not None:
      await self._driver._set_speed(speed_pct)
    await self._guarded_move_j(
      lambda current: {**current, **position},
      close_gripper_without_force_sensing=close_gripper_without_force_sensing,
    )

  async def request_gripper_pose(self) -> PreciseFlexCartesianPose:
    """Get the current pose using our kinematics model (no firmware `wherec`)."""
    _, pose = await self._request_state()
    return pose

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
    lambda self, location, direction, speed_pct=None, orientation=None, wrist=None, rail_position=None: {
      "device": self._driver._controller_reference(),
      "target": _cartesian_target_reference(
        location,
        direction,
        orientation=orientation,
        wrist=wrist,
        rail_position=rail_position,
      ),
      "speed_pct": speed_pct,
    },
  )
  async def move_to_location(
    self,
    location: Coordinate,
    direction: float,
    speed_pct: Optional[float] = None,
    orientation: Optional[ElbowOrientation] = None,
    wrist: Optional[Wrist] = None,
    rail_position: Optional[float] = None,
  ) -> None:
    """Move the arm to the specified Cartesian location. The IK target is guarded against
    out-of-range axes (see ``_guarded_move_j``).

    Args:
      location: Target Cartesian location.
      direction: Approach direction, applied as the pose's z rotation in degrees.
      speed_pct: Movement speed override as a percentage (0-100). If None, uses the current
        speed setting.
      orientation: Elbow orientation (``"lefty"`` or ``"righty"``). If None, the robot
        picks the closest configuration.
      wrist: Wrist configuration. If None, the robot picks the closest configuration.
      rail_position: Linear rail position in mm. Required when the arm has a rail.
    """
    if speed_pct is not None:
      await self._driver._set_speed(speed_pct)

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
    lambda self, poses, speed_pct=None, blend=True: {
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
      "speed_pct": speed_pct,
      "blend": blend,
    },
  )
  async def move_through_cartesian_poses(
    self,
    poses: Sequence[PreciseFlexCartesianPose],
    speed_pct: Optional[float] = None,
    blend: bool = True,
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
      speed_pct: Movement speed override as a percentage (0-100). If None, uses the
        current speed setting.
      blend: When True, temporarily set the active motion profile's ``InRange`` value to
        ``-1`` so the controller may blend through intermediate waypoints instead of stopping
        at each one. The original profile is restored after the final waypoint is reached.
    """
    if not poses:
      return
    if speed_pct is not None:
      await self._driver._set_speed(speed_pct)

    targets = await self._plan_cartesian_pose_route(poses)

    profile_index = self._driver.profile_index
    original_profile = None
    should_restore_profile = False
    if blend:
      original_profile = await self._driver.request_motion_profile_values(profile_index)
      should_restore_profile = original_profile.in_range != BLEND_IN_RANGE
      if should_restore_profile:
        await self._driver.set_motion_profile_values(
          *original_profile._replace(in_range=BLEND_IN_RANGE)
        )

    try:
      for target in targets:
        await self._move_j(profile_index=profile_index, joint_coords=target)
    finally:
      # Let queued motion settle before returning or restoring the profile - restoring InRange
      # mid-move would change the in-flight blend.
      try:
        await self._wait_for_eom()
      finally:
        if should_restore_profile and original_profile is not None:
          await self._driver.set_motion_profile_values(*original_profile)

  async def dest_c(self, arg1: int = 0) -> tuple[float, float, float, float, float, float, int]:
    """Get the destination or current Cartesian location of the robot.

    Args:
      arg1: Selects return value. Defaults to 0.
      0 = Return current Cartesian location if robot is not moving
      1 = Return target Cartesian location of the previous or current move

    Returns:
      A tuple containing (X, Y, Z, yaw, pitch, roll, config)
      If arg1 = 1 or robot is moving, returns the target location.
      If arg1 = 0 and robot is not moving, returns the current location.
    """
    if arg1 == 0:
      data = await self._driver.send_command("destC")
    else:
      data = await self._driver.send_command(f"destC {arg1}")
    parts = data.split()
    if len(parts) != 7:
      raise PreciseFlexError(-1, "Unexpected response format from destC command.")
    x, y, z, yaw, pitch, roll = self._parse_xyz_response(parts[:6])
    config = int(parts[6])
    return (x, y, z, yaw, pitch, roll, config)

  async def dest_j(self, arg1: int = 0) -> JointState:
    """Get the destination or current joint location of the robot.

    Args:
      arg1: Selects return value. Defaults to 0.
      0 = Return current joint location if robot is not moving
      1 = Return target joint location of the previous or current move

    Returns:
      A dict mapping Axis to float values.
      If arg1 = 1 or robot is moving, returns the target joint positions.
      If arg1 = 0 and robot is not moving, returns the current joint positions.
    """
    if arg1 == 0:
      data = await self._driver.send_command("destJ")
    else:
      data = await self._driver.send_command(f"destJ {arg1}")
    parts = data.split()
    if not parts:
      raise PreciseFlexError(-1, "Unexpected response format from destJ command.")
    return self._parse_angles_response(parts)

  async def here_j(self, location_index: int) -> None:
    """Record the current position of the selected robot into the specified Location as angles.

    The Location is automatically set to type "angles".

    Args:
      location_index: The station index, from 1 to N_LOC.
    """
    await self._driver.send_command(f"hereJ {location_index}")

  async def here_c(self, location_index: int) -> None:
    """Record the current position of the selected robot into the specified Location as Cartesian.

    The Location object is automatically set to type "Cartesian".
    Can be used to change the pallet origin (index 1,1,1) value.

    Args:
      location_index: The station index, from 1 to N_LOC.
    """
    await self._driver.send_command(f"hereC {location_index}")
