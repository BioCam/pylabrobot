"""The iSWAP: the arm that picks plates up and puts them down."""

import enum
import logging
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, cast

from pylabrobot.hamilton.star.resource_model import iSWAPChannel
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.rotation import Rotation

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.features.x_arm import XArm
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

# What the rotation drive's stored position table holds, slot by slot. The tenth slot is the arm
# length, read separately. The extra slots are addressable but have no documented meaning.
ROTATION_DRIVE_SLOTS = (
  "home",
  "left",
  "front",
  "right",
  "parking",
  "extra_1",
  "extra_2",
  "extra_3",
  "extra_4",
)

# The same for the wrist twist drive.
WRIST_DRIVE_SLOTS = (
  "home",
  "right",
  "straight",
  "left",
  "reverse",
  "extra_1",
  "extra_2",
  "extra_3",
  "extra_4",
)

# And for the Y carriage, whose table is all position and has no arm length.
Y_SLOTS = (
  "home",
  "lower_limit",
  "upper_limit",
  "parking",
  "pre_parking",
  "extra_1",
  "extra_2",
  "extra_3",
  "extra_4",
  "extra_5",
)

# What the arm the device facts below were recorded from reports for its firmware version. An arm
# reporting something else is a generation those values were not taken from.
RECORDED_FIRMWARE_PREFIX = "4."

# Where the arm is left when parked, in mm: it travels at this height on the way there.
PARK_TRAVERSAL_HEIGHT = 280.0


@dataclass
class CartesianPose:
  """Location and rotation of the gripper."""

  location: Coordinate
  rotation: Rotation


class iSWAPAxis(enum.IntEnum):
  """The iSWAP's addressable axes, as `request_joint_state` keys.

  Units are the axis's own: the prismatic axes and the gripper in mm, the two revolute drives in
  degrees. `Z` is the rotation drive's bottom, which sits above the gripper finger plane by
  `iSWAPConfiguration.rotation_drive_z_offset_above_finger`, so it is not the grip centre's Z.
  """

  X = 1
  Y = 2
  Z = 3
  ROTATION = 4
  WRIST = 5
  GRIPPER = 6

  @property
  def is_in_kinematic_chain(self) -> bool:
    """Whether the axis moves the gripper frame.

    The gripper is driven, but opening it changes what is held rather than where the gripper is.
    """
    return self is not iSWAPAxis.GRIPPER


@dataclass
class iSWAPConfiguration:
  """Device parameters for the installed iSWAP.

  Ported from the legacy `iSWAPInformation`. Two kinds of value: per-machine calibration read from
  the machine at setup - link lengths, calibrated stops, offsets - which is None until read; and
  device facts of the 4th-generation iSWAP, the only generation supported, which are defaulted.
  Neither changes at runtime.
  """

  firmware_version: Optional[str] = None
  firmware_date: Optional[str] = None

  # -- X --
  rotation_drive_x_offset: Optional[float] = None
  """Deck X distance from the X-arm carriage center to the rotation drive (mm). Stored in master
  EEPROM. The Hamilton factory default is 34.0 mm."""

  # -- Y --
  rotation_drive_predefined_y_positions_increments: Optional[Dict[str, int]] = None
  """Each Y stop the carriage is calibrated against, in increments, keyed as `Y_SLOTS` names them.

  The whole stored table rather than the one stop the driver bounds moves by, so what this holds is
  what the drive reports: a recording of it answers every Y read, not just the parking one."""

  # -- rotation drive --
  rotation_drive_predefined_increments: Optional[Dict[str, int]] = None
  link_1_length: Optional[float] = None
  """rotation joint (joint 1) to the wrist joint (joint 2); default: 138.0 mm."""

  # -- wrist drive --
  wrist_drive_predefined_increments: Optional[Dict[str, int]] = None
  link_2_length: Optional[float] = None
  """wrist joint (joint 2) to the gripper finger center, in mm. default: 138.0 mm."""

  # === Device facts of the 4th-generation iSWAP: per-drive area-of-operation ranges and encoder
  # resolutions. The same across units of a generation, so they are defaulted - but only that
  # generation's are held. On an arm of another generation every conversion below would be wrong,
  # so discovery says so when the arm reports a firmware version these were not taken from. ===

  # -- Y --
  y_increment_range: Tuple[int, int] = (0, 14_000)
  y_mm_per_increment: float = 0.046302083
  y_speed_increment_range: Tuple[int, int] = (50, 8_000)  # increments/sec
  rotation_drive_diameter: float = 30.5
  """How wide the rotation drive is, in mm."""

  rotation_drive_safety_radius: float = 90.0
  """How far past the drive's own edge anything it carries can reach, in mm. Link 1 and what
  stands proud of it sweep this circle as the drive turns, so a clearance that holds at every
  rotation angle is measured against the drive's radius plus this."""

  rotation_drive_size_z: float = 120.0
  """How tall to model the rotation drive, in mm. Not read from anywhere: how far the drive extends
  is not something the machine reports."""

  # -- Z --
  z_increment_range: Tuple[int, int] = (-187, 26_661)
  z_mm_per_increment: float = 0.01072765
  z_speed_increment_range: Tuple[int, int] = (50, 15_000)  # increments/sec
  z_acceleration_increment_range: Tuple[int, int] = (5, 999)  # 1000 increments/sec^2
  rotation_drive_z_offset_above_finger: float = 13.0
  """How far the rotation drive's lowest point sits above the gripper finger plane, in mm. The Z
  drive is calibrated to the finger plane, so a position read or commanded here is that plane's
  plus this."""

  # -- rotation drive (joint 1) --
  rotation_increment_range: Tuple[int, int] = (-30_032, 30_032)
  rotation_deg_per_increment: float = 0.00309619077

  # -- wrist drive (joint 2) --
  wrist_increment_range: Tuple[int, int] = (-30_000, 30_000)
  wrist_deg_per_increment: float = 0.00507968798

  # -- gripper --
  gripper_increment_range: Tuple[int, int] = (12_780, 24_120)  # jaw width
  gripper_mm_per_increment: float = 0.00554337

  # -- conversions: the wire counts in increments, the driver speaks mm and degrees ----------

  @property
  def rotation_drive_y_max(self) -> Optional[float]:
    """How far back the carriage may be sent, in mm: the parking stop it is calibrated against.

    Returns:
      The parking stop in mm, or None until the stored Y table has been read.
    """
    stops = self.rotation_drive_predefined_y_positions_increments
    if stops is None:
      return None
    return self.y_increments_to_mm(stops["parking"])

  def y_increments_to_mm(self, increments: int) -> float:
    """A Y-carriage position in mm, from the increments the drive counts in."""
    return round(increments * self.y_mm_per_increment, 1)

  def y_mm_to_increments(self, mm: float) -> int:
    """A Y-carriage position in increments, from mm."""
    return round(mm / self.y_mm_per_increment)

  def z_increments_to_mm(self, increments: int) -> float:
    """A Z position in mm, from increments."""
    return round(increments * self.z_mm_per_increment, 1)

  def z_mm_to_increments(self, mm: float) -> int:
    """A Z position in increments, from mm."""
    return round(mm / self.z_mm_per_increment)

  def rotation_increments_to_deg(self, increments: int) -> float:
    """A rotation-drive angle in degrees, from increments."""
    return increments * self.rotation_deg_per_increment

  def rotation_deg_to_increments(self, deg: float) -> int:
    """A rotation-drive angle in increments, from degrees."""
    return round(deg / self.rotation_deg_per_increment)

  @property
  def rotation_drive_z_range(self) -> Tuple[float, float]:
    """How far the rotation drive's bottom travels along Z, in mm, lowest first.

    Derived from the drive's documented area of operation, not probed: unlike a head, the iSWAP
    has no command that finds its own limit.
    """
    return (
      round(
        self.z_increments_to_mm(self.z_increment_range[0])
        + self.rotation_drive_z_offset_above_finger,
        1,
      ),
      round(
        self.z_increments_to_mm(self.z_increment_range[1])
        + self.rotation_drive_z_offset_above_finger,
        1,
      ),
    )

  @property
  def rotation_drive_swept_radius(self) -> float:
    """How far from the rotation drive's centre anything it carries can reach, in mm.

    The drive and its arm are treated as one circle, so a clearance measured against it holds
    whichever way the arm happens to be turned.
    """
    return self.rotation_drive_diameter / 2 + self.rotation_drive_safety_radius

  def rotation_drive_increments_to_angle(self, increments: int) -> float:
    """A rotation-drive angle in degrees, from increments, against the calibrated stops.

    Piecewise linear rather than one slope: `left` to `front` spans -90 to 0 degrees and `front`
    to `right` spans 0 to +90, each against the stops this machine reports. So the stops read back
    as exactly -90, 0 and +90 however far the machine's own calibration has drifted, and a
    position beyond them extrapolates on its segment's slope.

    Args:
      increments: what the drive reports.

    Returns:
      The angle in degrees, signed from the calibrated front stop.

    Raises:
      RuntimeError: If the stored stops were not read.
    """
    stops = self.rotation_drive_predefined_increments
    if stops is None:
      raise RuntimeError(
        "the rotation drive's stops were not read; have you called `star.setup()`?"
      )
    front = stops["front"]
    if increments < front:
      return -90.0 * (front - increments) / (front - stops["left"])
    return 90.0 * (increments - front) / (stops["right"] - front)

  def wrist_increments_to_deg(self, increments: int) -> float:
    """A wrist-drive angle in degrees, from increments."""
    return increments * self.wrist_deg_per_increment

  def wrist_deg_to_increments(self, deg: float) -> int:
    """A wrist-drive angle in increments, from degrees."""
    return round(deg / self.wrist_deg_per_increment)

  def gripper_increments_to_mm(self, increments: int) -> float:
    """A gripper jaw width in mm, from increments. One decimal, as the machine resolves it."""
    return round(increments * self.gripper_mm_per_increment, 1)

  def gripper_mm_to_increments(self, mm: float) -> int:
    """A gripper jaw width in increments, from mm."""
    return round(mm / self.gripper_mm_per_increment)


class iSWAP:
  """The internal Swivel Arm Plate (iSWAP) handler.

  Reached as `driver.iswap`, on a machine that has one. It is addressed as `R0`, but the commands
  that move it go to the master, so this feature speaks to both.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[iSWAPConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the iSWAP's device facts. Defaults to `iSWAPConfiguration()`.
    """
    self._driver = driver
    self.configuration = configuration or iSWAPConfiguration()
    self.resource: Optional[iSWAPChannel] = None

  # -- session / discovery ---------------------------------------------------

  async def request_firmware_version(self) -> str:
    """Request the iSWAP's firmware version.

    Returns:
      The version string, as reported.
    """
    resp: str = await self._driver.send_command(module="R0", command="RF")
    return resp.split("rf")[-1]

  async def request_rotation_drive_x_offset(self) -> float:
    """Request the X distance from the X-arm carriage center to the rotation drive.

    Stored in the master's own memory, as the 96-head's offset is.

    Returns:
      The offset in mm.
    """
    resp = await self._driver.send_command(module="C0", command="RA", ra="kg", fmt="kg###")
    return cast(int, resp["kg"]) / 10.0

  async def request_rotation_drive_positions(self) -> Dict[str, int]:
    """Request the rotation drive's stored position table.

    The machine returns ten signed slots; the nine position slots are returned here, and the tenth
    is the arm length, which `request_link_1_length` reads.

    Returns:
      Each named stop's motor increments.
    """
    return dict(zip(ROTATION_DRIVE_SLOTS, await self._request_slots("pw")))

  async def request_wrist_drive_positions(self) -> Dict[str, int]:
    """Request the wrist twist drive's stored position table.

    Returns:
      Each named stop's motor increments.
    """
    return dict(zip(WRIST_DRIVE_SLOTS, await self._request_slots("pt")))

  async def rotation_drive_request_y_stops(self) -> Dict[str, float]:
    """Request the stored Y stops the carriage is calibrated against.

    The stored table, not where the carriage is now: `rotation_drive_request_y_position` is what
    reads that.

    Returns:
      Each named stop in mm.
    """
    slots = await self._request_slots("py")
    return {name: self.configuration.y_increments_to_mm(slot) for name, slot in zip(Y_SLOTS, slots)}

  async def request_link_1_length(self) -> float:
    """Request the distance from the rotation joint to the wrist joint.

    Returns:
      The length in mm.
    """
    return round((await self._request_slots("pw"))[9] / 10, 1)

  async def request_link_2_length(self) -> float:
    """Request the distance from the wrist joint to the gripper finger center.

    Returns:
      The length in mm.
    """
    return round((await self._request_slots("pt"))[9] / 10, 1)

  async def _request_slots(self, table: str) -> List[int]:
    """One of the iSWAP's stored tables, as the ten signed slots the machine returns."""
    resp = await self._driver.send_command(
      module="R0", command="RA", ra=table, fmt=f"{table}##### (n)"
    )
    return cast(List[int], resp[table])

  async def discover(self):
    """Read this iSWAP's calibration. Read-only: nothing moves."""
    c = self.configuration
    c.firmware_version = await self.request_firmware_version()
    if not c.firmware_version.startswith(RECORDED_FIRMWARE_PREFIX):
      logger.warning(
        "this iSWAP reports firmware %s; the ranges and resolutions here were recorded from an arm "
        "reporting %sx, so every position, angle and width converted from them may be wrong. Set "
        "them on iSWAPConfiguration to correct it.",
        c.firmware_version,
        RECORDED_FIRMWARE_PREFIX,
      )
    c.rotation_drive_x_offset = await self.request_rotation_drive_x_offset()
    c.rotation_drive_predefined_y_positions_increments = dict(
      zip(Y_SLOTS, await self._request_slots("py"))
    )

    rotation = await self._request_slots("pw")
    c.rotation_drive_predefined_increments = dict(zip(ROTATION_DRIVE_SLOTS, rotation))
    c.link_1_length = round(rotation[9] / 10, 1)

    wrist = await self._request_slots("pt")
    c.wrist_drive_predefined_increments = dict(zip(WRIST_DRIVE_SLOTS, wrist))
    c.link_2_length = round(wrist[9] / 10, 1)

  # -- initialization --------------------------------------------------------

  async def initialize(self):
    """Initialize the iSWAP. This moves it."""
    return await self._driver.send_command(module="C0", command="FI", subsystem="R0")

  # -- where it is -----------------------------------------------------------

  def update_location_by_reference_point(
    self, y: Optional[float] = None, z: Optional[float] = None
  ) -> None:
    """Record where the rotation drive is on the resource that models it.

    Y and Z only: the drive rides the arm, so its resource is a child of the arm's and follows it
    in X without anything having to record that. The drives report the point the resource states as
    its `reference_point`, and a resource is located by its left front bottom corner, so that point
    is taken out before either value is recorded.

    Both drives answer in the deck's frame, while a resource's location is measured from its
    parent, which here is the arm. The arm's own position is taken out too. Does nothing when the
    driver was given no deck, and so has nothing to model.

    Args:
      y: where the drive is now, in mm on the deck. Left as it was when None.
      z: where its bottom is now, in mm on the deck. Left as it was when None.
    """
    deck = self._driver.deck
    if self.resource is None or self.resource.location is None or deck is None:
      return
    arm = self.resource.parent
    if arm is None:
      return
    here, on_the_arm = self.resource.location, arm.get_location_wrt(deck)
    anchor = self.resource.reference_point
    self.resource.location = Coordinate(
      here.x,
      here.y if y is None else y - on_the_arm.y - anchor.y,
      here.z if z is None else z - on_the_arm.z - anchor.z,
    )

  def _check_reachable(
    self,
    axis: Literal["x", "y", "z"],
    value: float,
    frame: Literal["rotation_drive", "gripper"] = "rotation_drive",
  ) -> None:
    """Raise if the iSWAP cannot be sent where it is being asked to go.

    The one gate every position passes through. What the iSWAP is allowed to do is decided in one
    place: travel limits now, and whatever else has to hold before it moves as it is added.

    Two frames, because the arm reaches past the drive that carries it. `rotation_drive` is the
    carriage the Y and Z drives position, which is what every move here commands. `gripper` is the
    grip centre `request_pose` reports, which the two links carry away from that carriage.

    Along Z the two differ by a fixed offset, so the gripper's window is exact. Along X and Y the
    links can point in any direction, so the gripper's window is the drive's widened by their
    combined length: a value outside it is certainly out of reach, one inside it may still be,
    depending on where the joints are. Bounding those exactly needs the joint state.

    Args:
      axis: which axis - `x` along the rail, `y` across the deck, `z` up.
      value: where it would be sent, in mm.
      frame: whether `value` is the rotation drive's position or the grip centre's.

    Raises:
      ValueError: If the iSWAP cannot reach it.
      RuntimeError: If the limits were not read, so how far it reaches is unknown.
    """
    c = self.configuration
    machine = self._driver.configuration
    if machine is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")

    if axis == "x":
      x_range = self.arm.configuration.x_range
      if x_range is None:
        raise RuntimeError("the arm's X travel is not known; have you called `star.setup()`?")
      if c.rotation_drive_x_offset is None:
        raise RuntimeError("the drive's X offset was not read; have you called `star.setup()`?")
      low = x_range[0] - c.rotation_drive_x_offset
      high = x_range[1] - c.rotation_drive_x_offset
    elif axis == "y":
      if c.rotation_drive_y_max is None:
        raise RuntimeError("the drive's Y limit was not read; have you called `star.setup()`?")
      low = (
        machine.left_arm_min_y_position
        if self.arm.side == "left"
        else machine.right_arm_min_y_position
      )
      high = c.rotation_drive_y_max
    else:
      low, high = c.rotation_drive_z_range

    if frame == "gripper":
      if axis == "z":
        low -= c.rotation_drive_z_offset_above_finger
        high -= c.rotation_drive_z_offset_above_finger
      else:
        if c.link_1_length is None or c.link_2_length is None:
          raise RuntimeError("the link lengths were not read; have you called `star.setup()`?")
        reach = c.link_1_length + c.link_2_length
        low -= reach
        high += reach

    if not low <= value <= high:
      raise ValueError(
        f"{axis} must be between {round(low, 1)} and {round(high, 1)} mm for the "
        f"{frame.replace('_', ' ')}, is {value}"
      )

  @property
  def arm(self) -> "XArm":
    """The arm carrying this iSWAP.

    It has no X drive of its own: it rides the arm, offset from the carriage reference point by
    `configuration.rotation_drive_x_offset`.

    Returns:
      The arm.
    """
    return next(a for a in self._driver.arms if a.iswap is self)

  # ----------------------------------------
  # Movement
  # ----------------------------------------

  # -- x position --------------------------------------------------------------------------------

  async def rotation_drive_request_x_position(self) -> float:
    """Read where the rotation drive is along X, in deck mm.

    Returns:
      The rotation drive's X in mm.

    Raises:
      RuntimeError: If the drive's X offset was not read.
    """
    offset = self.configuration.rotation_drive_x_offset
    if offset is None:
      raise RuntimeError(
        "the rotation drive's X offset was not read; have you called `star.setup()`?"
      )
    return round(await self.arm.request_position() - offset, 2)

  # -- y position --------------------------------------------------------------------------------

  async def rotation_drive_request_y_position(self) -> float:
    """Read where the rotation drive is along Y, in deck mm.

    The Y carriage the rotation joint is mounted on, not the gripper finger's Y: where the finger
    is depends on the rotation and wrist angles as well. `request_pose` is what resolves those.

    Returns:
      The rotation drive's Y in mm.
    """
    resp = await self._driver.send_command(module="R0", command="RY", fmt="ry##### (n)")
    # Two counters come back, the firmware's and the hardware's. The hardware one is read.
    y = round(self.configuration.y_increments_to_mm(cast(List[int], resp["ry"])[1]), 1)
    self.update_location_by_reference_point(y=y)
    return y

  async def rotation_drive_move_to_y_position(
    self,
    y: float,
    make_space: bool = False,
    speed: float = 220.0,
    acceleration_level: int = 2,
    current_limit: int = 7,
  ):
    """Move the rotation drive along Y. This moves it.

    The backmost channel is what the drive can run into, so how far back it may go depends on
    where that channel is. The drive and its arm are treated as one circle of
    `configuration.rotation_drive_swept_radius`, which keeps the clearance true whichever way the
    arm is turned.

    Args:
      y: where to put the rotation drive, in mm.
      make_space: whether the channels may be moved out of the way when the backmost one is where
        the drive needs to be. Off by default, so a move that does not fit raises and the caller
        decides. Making space raises the channels to Z safety first, since it moves them in Y.
      speed: how fast, in mm/s.
      acceleration_level: how hard to accelerate, 1 or 2.
      current_limit: the motor current limit, 0 to 7.

    Raises:
      ValueError: If the drive cannot reach it, if any of the drive parameters is outside what it
        accepts, or if the channels are in the way and may not be moved.
      RuntimeError: If the machine's configuration or the drive's Y limit was not read.
    """
    c = self.configuration
    machine = self._driver.configuration
    if machine is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    self._check_reachable("y", y)

    await self._clear_channels_for_y(y, make_space=make_space)

    speed_increments = c.y_mm_to_increments(speed)
    speed_low, speed_high = c.y_speed_increment_range
    if not speed_low <= speed_increments <= speed_high:
      raise ValueError(
        f"speed must be between {c.y_increments_to_mm(speed_low)} and "
        f"{c.y_increments_to_mm(speed_high)} mm/s, is {speed}"
      )
    if not 1 <= acceleration_level <= 2:
      raise ValueError(f"acceleration_level must be 1 or 2, is {acceleration_level}")
    if not 0 <= current_limit <= 7:
      raise ValueError(f"current_limit must be between 0 and 7, is {current_limit}")

    try:
      resp = await self._driver.send_command(
        module="R0",
        command="YA",
        ya=f"{c.y_mm_to_increments(y):05}",
        yv=f"{speed_increments:04}",
        yr=f"{acceleration_level}",
        yw=f"{current_limit}",
      )
    except BaseException:
      # A failed move leaves the drive at an unknown y, so re-read to refresh the model. The
      # read is wrapped: its own failure must not replace the move's exception.
      try:
        await self.rotation_drive_request_y_position()
      except BaseException:
        logger.warning("could not read where the rotation drive stopped; its model is stale")
      raise

    self.update_location_by_reference_point(y=y)
    return resp

  async def _clear_channels_for_y(self, y: float, make_space: bool) -> None:
    """Make sure the backmost channel is out of the way before the drive travels to `y`.

    Args:
      y: where the rotation drive is going, in mm.
      make_space: whether the channels may be moved to clear it.

    Raises:
      ValueError: If the channel is in the way and either may not be moved, or cannot move far
        enough to clear it.
    """
    pipettes = self.arm.pipettes
    if pipettes is None:
      return

    machine = self._driver.configuration
    if machine is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")

    widths = [channel.width for channel in pipettes.configuration.channels]
    if any(width is None for width in widths):
      raise RuntimeError("the channels have no width read yet; have you called `star.setup()`?")

    # Where the backmost channel would have to be for the drive to reach `y`, and the furthest
    # back it can get: every channel behind it packed against the front of their travel.
    backmost_y = await pipettes.request_y_position(0)
    target_y = y - cast(float, widths[0]) / 2 - self.configuration.rotation_drive_swept_radius
    furthest_back = machine.left_arm_min_y_position + sum(cast(List[float], widths[1:]))

    if backmost_y <= target_y:
      return
    if target_y < furthest_back:
      raise ValueError(
        f"y={y} mm is out of reach: it needs the backmost channel at {round(target_y, 1)} mm, and "
        f"the channels do not fit behind {round(furthest_back, 1)} mm"
      )
    if not make_space:
      raise ValueError(
        f"y={y} mm needs the backmost channel at {round(target_y, 1)} mm or further front, and it "
        f"is at {backmost_y} mm. Pass make_space=True to move the channels out of the way"
      )
    # Nothing may move in Y while a channel is low.
    await pipettes.move_to_safe_z()
    await pipettes.move_to_y_positions({0: target_y}, make_space=True)

  # -- z position --------------------------------------------------------------------------------

  async def rotation_drive_request_z_position(self) -> float:
    """Read where the rotation drive's lowest point is along Z.

    The drive reports two counters, the firmware's and the hardware's. The hardware counter is
    the one read, as legacy reads it.

    Returns:
      The rotation drive's bottom Z in mm.
    """
    resp = await self._driver.send_command(module="R0", command="RZ", fmt="rz##### (n)")
    finger_plane = self.configuration.z_increments_to_mm(cast(List[int], resp["rz"])[1])
    z = round(finger_plane + self.configuration.rotation_drive_z_offset_above_finger, 1)
    self.update_location_by_reference_point(z=z)
    return z

  async def rotation_drive_move_to_z_position(
    self,
    z: float,
    speed: float = 118.0,
    acceleration: float = 643.66,
    current_limit: int = 6,
  ):
    """Move the rotation drive's lowest point to a Z position. This moves it.

    Args:
      z: where to put the rotation drive's bottom, in mm.
      speed: how fast, in mm/s.
      acceleration: how hard, in mm/s2.
      current_limit: the motor current limit, 0 to 7.

    Raises:
      ValueError: If any of them is outside what the drive accepts.
    """
    c = self.configuration
    self._check_reachable("z", z)

    speed_increments = c.z_mm_to_increments(speed)
    speed_low, speed_high = c.z_speed_increment_range
    if not speed_low <= speed_increments <= speed_high:
      raise ValueError(
        f"speed must be between {c.z_increments_to_mm(speed_low)} and "
        f"{c.z_increments_to_mm(speed_high)} mm/s, is {speed}"
      )

    # The drive counts acceleration in thousands of increments per second squared.
    acceleration_increments = c.z_mm_to_increments(acceleration / 1000)
    acceleration_low, acceleration_high = c.z_acceleration_increment_range
    if not acceleration_low <= acceleration_increments <= acceleration_high:
      raise ValueError(
        f"acceleration must be between {c.z_increments_to_mm(acceleration_low * 1000)} and "
        f"{c.z_increments_to_mm(acceleration_high * 1000)} mm/s2, is {acceleration}"
      )

    if not 0 <= current_limit <= 7:
      raise ValueError(f"current_limit must be between 0 and 7, is {current_limit}")

    finger_plane = z - c.rotation_drive_z_offset_above_finger
    try:
      resp = await self._driver.send_command(
        module="R0",
        command="ZA",
        za=f"{c.z_mm_to_increments(finger_plane):+06}",
        zv=f"{speed_increments:05}",
        zr=f"{acceleration_increments:03}",
        zw=f"{current_limit}",
      )
    except BaseException:
      # A failed move leaves the drive at an unknown z, so re-read to refresh the model. The
      # read is wrapped: its own failure must not replace the move's exception.
      try:
        await self.rotation_drive_request_z_position()
      except BaseException:
        logger.warning("could not read where the rotation drive stopped; its model is stale")
      raise

    self.update_location_by_reference_point(z=z)
    return resp

  async def rotation_drive_move_to_safe_z_height(
    self,
    speed: float = 118.0,
    acceleration: float = 643.66,
    current_limit: int = 6,
  ) -> float:
    """Move the iSWAP up to the top of its Z travel, and read where that put it. This moves it.

    The precondition for any lateral move, as it is for the channels and the heads. The iSWAP has
    no Z-safety command of its own, so this is an ordinary Z move to the top of `configuration.rotation_drive_z_range`.

    Args:
      speed: how fast, in mm/s.
      acceleration: how hard, in mm/s2.
      current_limit: the motor current limit, 0 to 7.

    Returns:
      The rotation drive's bottom Z once there, in mm.
    """
    await self.rotation_drive_move_to_z_position(
      self.configuration.rotation_drive_z_range[1],
      speed=speed,
      acceleration=acceleration,
      current_limit=current_limit,
    )
    return await self.rotation_drive_request_z_position()

  # -- rotation, wrist and gripper --------------------------------------------

  async def request_rotation_drive_angle(self) -> float:
    """Read the rotation drive's angle, signed from the calibrated front stop.

    Returns:
      The angle in degrees.
    """
    resp = await self._driver.send_command(module="R0", command="RW", fmt="rw######")
    return self.configuration.rotation_drive_increments_to_angle(cast(int, resp["rw"]))

  async def request_wrist_drive_angle(self) -> float:
    """Read the wrist drive's angle, signed from the motor's own zero.

    That zero sits between the straight and left stops, which keeps the reachable range symmetric
    about it rather than anchoring it on a stop.

    Returns:
      The angle in degrees.
    """
    resp = await self._driver.send_command(module="R0", command="RT", fmt="rt######")
    return self.configuration.wrist_increments_to_deg(cast(int, resp["rt"]))

  async def request_gripper_width(self) -> float:
    """Read how far the gripper jaws are open.

    Returns:
      The jaw width in mm.
    """
    resp = await self._driver.send_command(module="R0", command="RG", fmt="rg##### (n)")
    # A target and an actual come back, in that order. The actual is read.
    return self.configuration.gripper_increments_to_mm(cast(List[int], resp["rg"])[1])

  # -- pose ------------------------------------------------------------------

  async def request_joint_state(self) -> Dict[iSWAPAxis, float]:
    """Read every axis at once, as the joint state the kinematics run on.

    Returns:
      Each axis's position, in that axis's own units.
    """
    return {
      iSWAPAxis.X: await self.rotation_drive_request_x_position(),
      iSWAPAxis.Y: await self.rotation_drive_request_y_position(),
      iSWAPAxis.Z: await self.rotation_drive_request_z_position(),
      iSWAPAxis.ROTATION: await self.request_rotation_drive_angle(),
      iSWAPAxis.WRIST: await self.request_wrist_drive_angle(),
      iSWAPAxis.GRIPPER: await self.request_gripper_width(),
    }

  @staticmethod
  def _forward_kinematics(
    joints: Dict[iSWAPAxis, float],
    link_1_length: float,
    link_2_length: float,
    wrist_straight_angle: float,
    rotation_drive_z_offset_above_finger: float,
  ) -> CartesianPose:
    """Where a joint state puts the gripper. Pure arithmetic: nothing is read.

    Two links off the rotation drive. Link 1 leaves it at the rotation angle, link 2 leaves the
    wrist at that plus however far the wrist is turned from straight. Angles are signed
    counter-clockwise seen from above, and a yaw of 0 points along +x, deck-right.

    Args:
      joints: the joint state, as `request_joint_state` returns it.
      link_1_length: rotation joint to wrist joint, in mm.
      link_2_length: wrist joint to gripper finger centre, in mm.
      wrist_straight_angle: what the wrist reports when it is straight, in degrees.
      rotation_drive_z_offset_above_finger: how far the drive's bottom sits above the fingers.

    Returns:
      The grip centre, and the yaw link 2 lies along.
    """
    link_1_deck_angle = joints[iSWAPAxis.ROTATION] - 90.0
    link_2_deck_angle = link_1_deck_angle + (joints[iSWAPAxis.WRIST] - wrist_straight_angle)

    alpha_1 = math.radians(link_1_deck_angle)
    alpha_2 = math.radians(link_2_deck_angle)

    return CartesianPose(
      location=Coordinate(
        x=joints[iSWAPAxis.X]
        + link_1_length * math.cos(alpha_1)
        + link_2_length * math.cos(alpha_2),
        y=joints[iSWAPAxis.Y]
        + link_1_length * math.sin(alpha_1)
        + link_2_length * math.sin(alpha_2),
        z=joints[iSWAPAxis.Z] - rotation_drive_z_offset_above_finger,
      ),
      rotation=Rotation(z=link_2_deck_angle),
    )

  async def request_pose(self) -> CartesianPose:
    """Where the gripper is, worked out from the joint state.

    Read and computed rather than asked for: the master answers a gripper position of its own, but
    only correctly after certain commands have run. This reads each drive and runs the kinematics,
    so it holds whenever it is called.

    Returns:
      The grip centre in deck mm, and the gripper's yaw in degrees. Only yaw is set: the gripper
      plane stays parallel to the deck.

    Raises:
      RuntimeError: If the link lengths or the wrist's stops were not read.
    """
    c = self.configuration
    if c.link_1_length is None or c.link_2_length is None:
      raise RuntimeError("the arm's link lengths were not read; have you called `star.setup()`?")
    if c.wrist_drive_predefined_increments is None:
      raise RuntimeError("the wrist drive's stops were not read; have you called `star.setup()`?")

    return self._forward_kinematics(
      joints=await self.request_joint_state(),
      link_1_length=c.link_1_length,
      link_2_length=c.link_2_length,
      wrist_straight_angle=c.wrist_increments_to_deg(
        c.wrist_drive_predefined_increments["straight"]
      ),
      rotation_drive_z_offset_above_finger=c.rotation_drive_z_offset_above_finger,
    )

  # -- parking ---------------------------------------------------------------

  async def park(self, traversal_height: float = PARK_TRAVERSAL_HEIGHT):
    """Close the gripper and park the arm. This moves it.

    Args:
      traversal_height: the minimum height to travel at on the way, in mm.
    Raises:
      ValueError: If the traversal height is outside what the command accepts.
    """
    if not 0 <= traversal_height <= 360:
      raise ValueError(f"traversal_height must be between 0 and 360 mm, is {traversal_height}")
    return await self._driver.send_command(
      module="C0", command="PG", subsystem="R0", th=round(traversal_height * 10)
    )
