"""The iSWAP: a P(x)+P(y)+P(z)+R(elbow)+R(wrist) SCARA
with a mechanical gripper as end-effector that moves resources.
"""

import dataclasses
import enum
import logging
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, Union, cast

from pylabrobot.hamilton.star.driver.errors import NoElementError, STARFirmwareError
from pylabrobot.hamilton.star.resource_model import iSWAPChannel
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper
from pylabrobot.resources.manipulator import Link
from pylabrobot.resources.rotation import Rotation

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.features.x_arm import XArm
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)


RECORDED_FIRMWARE_PREFIX = "4."


@dataclass
class CartesianPose:
  """Location and rotation of the gripper.

  In the STAR's deck frame: mm from the deck's origin, and degrees counter-clockwise seen from
  above with 0 along +x. Named as the other arms name theirs, since it is the same thing.
  """

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


JointState = Dict[iSWAPAxis, float]
"""Where every axis is, in its own units: the prismatic axes and the gripper in mm, the two
revolute drives in degrees. What the arm is, rather than anything worked out from it."""


@dataclasses.dataclass(frozen=True)
class iSWAPPose:
  """Where every joint of the arm is, and which way the gripper faces.

  One answer for the whole arm rather than for its end. The two links are what put the gripper
  where it is, so a caller asking whether the arm clears something needs the joint between them as
  much as the point at the end of it: a wrist folded back swings link 2 the opposite way to the
  turn, and only the middle joint shows that.

  Every coordinate and rotation here is in the STAR's deck frame, as `CartesianPose` states it.
  """

  rotation_joint_location: Coordinate
  """Where the rotation drive is: the joint link 1 turns about."""
  wrist_joint_location: Coordinate
  """Link 1's far end, which is the joint link 2 turns about. Which way link 1 lies is not stated:
  it is the direction from `rotation_joint_location` to here, and nothing has needed it."""
  gripper_center_location: Coordinate
  """Link 2's far end, between the fingers: the point a grip is programmed against."""
  gripper_deck_orientation: Rotation
  """Which way the gripper faces, in the deck frame - the yaw link 2 lies along, since the gripper
  is bolted to it. Degrees counter-clockwise seen from above, 0 along +x."""
  joints: JointState
  """What each drive reported, in its own units, as `request_joint_state` returns it."""


@dataclass
class iSWAPConfiguration:
  """Device parameters for the installed iSWAP.

  Ported from the legacy `iSWAPInformation`. Two kinds of value: per-device calibration read from
  the device at setup - link lengths, calibrated stops, offsets - which is None until read; and
  device facts of the 4th-generation iSWAP, the only generation supported, which are defaulted.
  Neither changes at runtime.
  """

  firmware_version: Optional[str] = None
  firmware_date: Optional[str] = None

  link_1_length: Optional[float] = None
  """rotation joint (joint 1) to the wrist joint (joint 2); default: 138.0 mm."""
  link_2_length: Optional[float] = None
  """wrist joint (joint 2) to the gripper finger centre, in mm. default: 138.0 mm."""

  # -- X --
  rotation_drive_x_offset: Optional[float] = None
  """Deck X distance from the X-arm carriage reference point to the rotation drive (mm). Stored in
  master EEPROM. The Hamilton factory default is 34.0 mm."""

  # -- Y --
  rotation_drive_y_slots: Tuple[str, ...] = (
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
  """What the Y carriage's stored table holds, slot by slot. All position, and no arm length."""

  rotation_drive_predefined_y_positions_increments: Optional[Dict[str, int]] = None
  """Each Y stop the carriage is calibrated against, in increments, keyed as
  `configuration.rotation_drive_y_slots` names them. The whole stored table, not just the parking
  stop."""

  # -- Z --
  rotation_drive_z_slots: Tuple[str, ...] = (
    "home",
    "parking",
    "extra_1",
    "extra_2",
    "extra_3",
    "extra_4",
    "extra_5",
    "extra_6",
    "extra_7",
    "extra_8",
  )
  """The same for the rotation drive's Z: ten stops, all position, no arm length."""

  rotation_drive_predefined_z_positions_increments: Optional[Dict[str, int]] = None
  """Each Z stop the rotation drive is calibrated against, in increments of the finger plane,
  keyed as `configuration.rotation_drive_z_slots` names them. Read by discovery; the defaults are
  factory values, not one unit's calibration."""

  # -- rotation drive --
  rotation_drive_slots: Tuple[str, ...] = (
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
  """What the rotation drive's stored table holds, slot by slot. The tenth slot is the arm length,
  read separately. The extra slots are addressable but have no documented meaning."""

  rotation_drive_predefined_increments: Optional[Dict[str, int]] = None

  # -- wrist drive --
  wrist_drive_slots: Tuple[str, ...] = (
    "home",
    "right",
    "straight",
    "left",
    "reverse",
    "parking",
    "extra_1",
    "extra_2",
    "extra_3",
  )
  """The same for the wrist twist drive."""

  wrist_drive_predefined_increments: Optional[Dict[str, int]] = None
  # -- gripper drive --
  gripper_drive_slots: Tuple[str, ...] = (
    "home",
    "extra_1",
    "closed",
    "plate_type_1",
    "plate_type_2",
    "plate_type_3",
    "plate_type_4",
    "plate_type_5",
    "plate_type_6",
    "plate_type_7",
  )
  """What the gripper drive's stored table holds, slot by slot: all jaw width, no arm length. One
  slot stands for both home and parking, seven are the widths a plate type is gripped at, and the
  second has no documented meaning - its default is the top of the drive's range."""

  gripper_drive_predefined_increments: Optional[Dict[str, int]] = None
  """Each jaw width the gripper is calibrated against, in increments, keyed as
  `configuration.gripper_drive_slots` names them. Read by discovery; the defaults are factory
  values, not one unit's calibration."""

  # === Device facts of the 4th-generation iSWAP: per-drive area-of-operation ranges and encoder
  # resolutions. The same across units of a generation, so they are defaulted - but only that
  # generation's are held. On an arm of another generation every conversion below would be wrong,
  # so discovery says so when the arm reports a firmware version these were not taken from. ===

  # -- Y --
  y_range_increments: Tuple[int, int] = (0, 14_000)
  y_mm_per_increment: float = 0.046302083
  y_speed_range_increments: Tuple[int, int] = (50, 8_000)  # increments/sec
  # Speeds run under the documented defaults - Y 68%, rotation 44%, wrist 41% - these swing a plate.
  y_speed_default_increments: int = 4_751
  y_current_limit_default: int = 7
  y_acceleration_level_default: int = 2
  rotation_drive_diameter: float = 30.5
  """How wide the rotation drive is, in mm."""

  rotation_drive_safety_radius: float = 90.0
  """How far past the drive's own edge anything it carries reaches, in mm. A clearance that holds
  at every rotation angle is the drive's radius plus this."""

  rotation_drive_size_z: float = 120.0
  """How tall to model the rotation drive, in mm. Not read from anywhere: how far the drive extends
  is not something the device reports."""

  # -- Z --
  z_range_increments: Tuple[int, int] = (-187, 26_661)
  z_mm_per_increment: float = 0.01072765
  z_speed_range_increments: Tuple[int, int] = (50, 15_000)  # increments/sec
  z_acceleration_range_increments: Tuple[int, int] = (5, 999)  # 1000 increments/sec^2
  z_speed_default_increments: int = 11_000
  z_acceleration_default_increments: int = 60
  z_current_limit_default: int = 6
  rotation_drive_z_offset_above_finger: float = 13.0
  """How far the rotation drive's lowest point sits above the finger plane, in mm. Z is calibrated
  to the finger plane, so a position read or commanded is that plane's plus this."""

  # -- rotation drive (joint 1) --
  rotation_range_increments: Tuple[int, int] = (-30_032, 30_032)
  rotation_deg_per_increment: float = 0.00309619077
  rotation_speed_range_increments: Tuple[int, int] = (20, 75_000)  # increments/sec
  rotation_acceleration_range_increments: Tuple[int, int] = (5, 200)  # 1000 increments/sec^2
  rotation_speed_default_increments: int = 24_223
  rotation_acceleration_default_increments: int = 161
  rotation_current_limit_default: int = 5

  # -- wrist drive (joint 2) --
  wrist_range_increments: Tuple[int, int] = (-30_000, 30_000)
  wrist_deg_per_increment: float = 0.00507968798
  wrist_speed_range_increments: Tuple[int, int] = (20, 65_000)  # increments/sec
  wrist_acceleration_range_increments: Tuple[int, int] = (5, 200)  # 1000 increments/sec^2
  wrist_speed_default_increments: int = 19_686
  wrist_acceleration_default_increments: int = 143
  wrist_current_limit_default: int = 5

  # -- gripper --
  gripper_range_increments: Tuple[int, int] = (12_780, 24_120)  # jaw width
  gripper_mm_per_increment: float = 0.00554337
  gripper_speed_range_increments: Tuple[int, int] = (20, 9_999)  # increments/sec
  gripper_acceleration_range_increments: Tuple[int, int] = (5, 150)  # 1000 increments/sec^2
  gripper_current_limit_range: Tuple[int, int] = (0, 15)
  gripper_speed_default_increments: int = 8_659
  gripper_acceleration_default_increments: int = 75
  gripper_current_limit_default: int = 15
  gripper_stop_band_range_increments: Tuple[int, int] = (80, 1_800)
  """How wide a window the drive accepts around the width a close is aimed at, in its own steps."""
  gripper_counter_drift_increments: int = 50
  """How far the drive's two counters may sit apart before the gap means lost steps rather than
  the ordinary lag between commanding a move and finishing it."""

  # -- conversions: the wire counts in increments, the driver speaks mm and degrees ----------

  @property
  def rotation_drive_y_max(self) -> Optional[float]:
    """How far back the carriage may be sent, in mm: the parking stop it is calibrated against.

    Returns:
      The parking stop in mm, or None until the stored Y table has been read.
    """
    predefined_y_positions = self.rotation_drive_predefined_y_positions_increments
    if predefined_y_positions is None:
      return None
    return self.y_increments_to_mm(predefined_y_positions["parking"])

  def y_increments_to_mm(self, increments: int) -> float:
    """A Y-carriage position in mm, from the increments the drive counts in."""
    return round(increments * self.y_mm_per_increment, 2)

  def y_mm_to_increments(self, mm: float) -> int:
    """A Y-carriage position in increments, from mm."""
    return round(mm / self.y_mm_per_increment)

  def z_increments_to_mm(self, increments: int) -> float:
    """A Z position in mm, from increments."""
    return round(increments * self.z_mm_per_increment, 3)

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
        self.z_increments_to_mm(self.z_range_increments[0])
        + self.rotation_drive_z_offset_above_finger,
        1,
      ),
      round(
        self.z_increments_to_mm(self.z_range_increments[1])
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
    """A rotation-drive angle in degrees, from increments, against the calibrated predefined_positions.

    Piecewise linear rather than one slope: `left` to `front` spans -90 to 0 degrees and `front`
    to `right` spans 0 to +90, each against the predefined_positions this device reports. So the predefined_positions read back
    as exactly -90, 0 and +90 however far the device's own calibration has drifted, and a
    position beyond them extrapolates on its segment's slope.

    Args:
      increments: what the drive reports.

    Returns:
      The angle in degrees, signed from the calibrated front stop.

    Raises:
      RuntimeError: If the stored predefined_positions were not read.
    """
    predefined_positions = self.rotation_drive_predefined_increments
    if predefined_positions is None:
      raise RuntimeError(
        "the rotation drive's predefined_positions were not read; have you called `star.setup()`?"
      )
    front = predefined_positions["front"]
    if increments < front:
      return -90.0 * (front - increments) / (front - predefined_positions["left"])
    return 90.0 * (increments - front) / (predefined_positions["right"] - front)

  def rotation_drive_angle_to_increments(self, angle: float) -> int:
    """A rotation-drive angle in increments, from degrees against the calibrated predefined_positions.

    The inverse of `rotation_drive_increments_to_angle`, piecewise on the same two segments, so
    -90, 0 and +90 land exactly on the predefined_positions this device reports and an angle beyond them
    extrapolates on its segment's slope.

    Args:
      angle: degrees, signed from the calibrated front stop.

    Returns:
      What to send the drive.

    Raises:
      RuntimeError: If the stored predefined_positions were not read.
    """
    predefined_positions = self.rotation_drive_predefined_increments
    if predefined_positions is None:
      raise RuntimeError(
        "the rotation drive's predefined_positions were not read; have you called `star.setup()`?"
      )
    front = predefined_positions["front"]
    if angle < 0:
      return round(front - (angle / -90.0) * (front - predefined_positions["left"]))
    return round(front + (angle / 90.0) * (predefined_positions["right"] - front))

  def wrist_increments_to_deg(self, increments: int) -> float:
    """A wrist-drive angle in degrees, from increments."""
    return increments * self.wrist_deg_per_increment

  def wrist_deg_to_increments(self, deg: float) -> int:
    """A wrist-drive angle in increments, from degrees."""
    return round(deg / self.wrist_deg_per_increment)

  # A rate is a plain division by the drive's resolution, unlike a rotation-drive position, which
  # is piecewise against the stops. Acceleration is counted in thousands of increments.

  def rotation_deg_per_sec_to_increments(self, deg_per_sec: float) -> int:
    """A rotation-drive speed in increments/s, from degrees/s."""
    return round(deg_per_sec / self.rotation_deg_per_increment)

  def rotation_increments_to_deg_per_sec(self, increments: int) -> float:
    """A rotation-drive speed in degrees/s, from increments/s."""
    return round(increments * self.rotation_deg_per_increment, 2)

  def rotation_deg_per_sec2_to_increments(self, deg_per_sec2: float) -> int:
    """A rotation-drive acceleration in thousands of increments/s2, from degrees/s2."""
    return round(deg_per_sec2 / self.rotation_deg_per_increment / 1000)

  def rotation_increments_to_deg_per_sec2(self, increments: int) -> float:
    """A rotation-drive acceleration in degrees/s2, from thousands of increments/s2."""
    return round(increments * 1000 * self.rotation_deg_per_increment, 2)

  def wrist_deg_per_sec_to_increments(self, deg_per_sec: float) -> int:
    """A wrist-drive speed in increments/s, from degrees/s."""
    return round(deg_per_sec / self.wrist_deg_per_increment)

  def wrist_increments_to_deg_per_sec(self, increments: int) -> float:
    """A wrist-drive speed in degrees/s, from increments/s."""
    return round(increments * self.wrist_deg_per_increment, 2)

  def wrist_deg_per_sec2_to_increments(self, deg_per_sec2: float) -> int:
    """A wrist-drive acceleration in thousands of increments/s2, from degrees/s2."""
    return round(deg_per_sec2 / self.wrist_deg_per_increment / 1000)

  def wrist_increments_to_deg_per_sec2(self, increments: int) -> float:
    """A wrist-drive acceleration in degrees/s2, from thousands of increments/s2."""
    return round(increments * 1000 * self.wrist_deg_per_increment, 2)

  @property
  def y_speed_default(self) -> float:
    """Y speed a move uses when the caller names none (mm/s)."""
    return self.y_increments_to_mm(self.y_speed_default_increments)

  @property
  def z_speed_default(self) -> float:
    """Z speed a move uses when the caller names none (mm/s)."""
    return self.z_increments_to_mm(self.z_speed_default_increments)

  @property
  def z_acceleration_default(self) -> float:
    """Z acceleration a move uses when the caller names none (mm/s2)."""
    return round(self.z_acceleration_default_increments * 1000 * self.z_mm_per_increment, 2)

  @property
  def rotation_speed_default(self) -> float:
    """Rotation-drive speed a move uses when the caller names none (deg/s)."""
    return self.rotation_increments_to_deg_per_sec(self.rotation_speed_default_increments)

  @property
  def rotation_acceleration_default(self) -> float:
    """Rotation-drive acceleration a move uses when the caller names none (deg/s2)."""
    return self.rotation_increments_to_deg_per_sec2(self.rotation_acceleration_default_increments)

  @property
  def wrist_speed_default(self) -> float:
    """Wrist-drive speed a move uses when the caller names none (deg/s)."""
    return self.wrist_increments_to_deg_per_sec(self.wrist_speed_default_increments)

  @property
  def wrist_acceleration_default(self) -> float:
    """Wrist-drive acceleration a move uses when the caller names none (deg/s2)."""
    return self.wrist_increments_to_deg_per_sec2(self.wrist_acceleration_default_increments)

  @property
  def gripper_speed_default(self) -> float:
    """Gripper speed a move uses when the caller names none (mm/s)."""
    return self.gripper_increments_to_mm_per_sec(self.gripper_speed_default_increments)

  @property
  def gripper_acceleration_default(self) -> float:
    """Gripper acceleration a move uses when the caller names none (mm/s2)."""
    return self.gripper_increments_to_mm_per_sec2(self.gripper_acceleration_default_increments)

  def gripper_increments_to_mm(self, increments: int) -> float:
    """A gripper jaw width in mm, from increments."""
    return round(increments * self.gripper_mm_per_increment, 3)

  def gripper_mm_to_increments(self, mm: float) -> int:
    """A gripper jaw width in increments, from mm."""
    return round(mm / self.gripper_mm_per_increment)

  def gripper_mm_per_sec_to_increments(self, mm_per_sec: float) -> int:
    """A gripper-drive speed in increments/s, from mm/s."""
    return round(mm_per_sec / self.gripper_mm_per_increment)

  def gripper_increments_to_mm_per_sec(self, increments: int) -> float:
    """A gripper-drive speed in mm/s, from increments/s."""
    return round(increments * self.gripper_mm_per_increment, 2)

  def gripper_mm_per_sec2_to_increments(self, mm_per_sec2: float) -> int:
    """A gripper-drive acceleration in thousands of increments/s2, from mm/s2."""
    return round(mm_per_sec2 / self.gripper_mm_per_increment / 1000)

  def gripper_increments_to_mm_per_sec2(self, increments: int) -> float:
    """A gripper-drive acceleration in mm/s2, from thousands of increments/s2."""
    return round(increments * 1000 * self.gripper_mm_per_increment, 2)


class iSWAP:
  """The internal Swivel Arm Plate (iSWAP) handler.

  Reached as `driver.iswap`, on a device that has one. It is addressed as `R0`, but the commands
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
    self.gripped: Optional[bool] = None
    """Whether the arm is holding something, as it last reported.

    None until anything has asked. Set by `request_plate_gripped`, which is the only thing that
    knows: the arm reports it from the fingers themselves, so a plate is not something this driver
    can infer from the commands it sent."""
    self.link_1: Optional[Link] = None
    self.link_2: Optional[Link] = None

  @property
  def arm(self) -> "XArm":
    """The arm carrying this iSWAP.

    It has no X drive of its own: it rides the arm, offset from the carriage reference point by
    `configuration.rotation_drive_x_offset`.

    Returns:
      The arm.
    """
    return next(a for a in self._driver.arms if a.iswap is self)

  # -- session / discovery ---------------------------------------------------

  async def request_firmware_version(self) -> str:
    """Request the iSWAP's firmware version.

    Returns:
      The version string, as reported.
    """
    resp: str = await self._driver.send_command(module="R0", command="RF")
    return resp.split("rf")[-1]

  async def rotation_drive_request_x_offset(self) -> float:
    """Request the X distance from the X-arm carriage centre to the rotation drive.

    Stored in the master's own memory, as the 96-head's offset is.

    Returns:
      The offset in mm.
    """
    resp = await self._driver.send_command(module="C0", command="RA", ra="kg", fmt="kg###")
    return cast(int, resp["kg"]) / 10.0

  async def rotation_drive_request_positions(self) -> Dict[str, int]:
    """Request the rotation drive's stored position table.

    The device returns ten signed slots; the nine position slots are returned here, and the tenth
    is the arm length, which `request_link_1_length` reads.

    Returns:
      Each named stop's motor increments.
    """
    return dict(zip(self.configuration.rotation_drive_slots, await self._request_slots("pw")))

  async def wrist_drive_request_positions(self) -> Dict[str, int]:
    """Request the wrist twist drive's stored position table.

    Returns:
      Each named stop's motor increments.
    """
    return dict(zip(self.configuration.wrist_drive_slots, await self._request_slots("pt")))

  async def rotation_drive_request_y_stops(self) -> Dict[str, float]:
    """Request the stored Y stops the carriage is calibrated against.

    The stored table, not where the carriage is now: `rotation_drive_request_y_position` is what
    reads that.

    Returns:
      Each named stop in mm.
    """
    c = self.configuration
    slots = await self._request_slots("py")
    return {name: c.y_increments_to_mm(slot) for name, slot in zip(c.rotation_drive_y_slots, slots)}

  async def request_link_1_length(self) -> float:
    """Request the distance from the rotation joint to the wrist joint.

    Returns:
      The length in mm.
    """
    return round((await self._request_slots("pw"))[9] / 10, 1)

  async def request_link_2_length(self) -> float:
    """Request the distance from the wrist joint to the gripper finger centre.

    Returns:
      The length in mm.
    """
    return round((await self._request_slots("pt"))[9] / 10, 1)

  async def rotation_drive_request_predefined_z_positions(self) -> Dict[str, float]:
    """Read the Z stops the rotation drive is calibrated against, in mm on the deck.

    The stored table rather than where the drive is now. Its ten slots are all positions, unlike
    the rotation and wrist tables whose tenth slot carries an arm length. The device holds them as
    the finger plane, so each is offset to the drive's bottom the way
    `rotation_drive_request_z_position` reports it, and the two are then in the same terms.

    Beyond home and parking the slots are extra ones, addressable through `R0 ZP` but with no
    documented meaning.

    Records what came back on the configuration, as the other stored tables are recorded, so a
    device read for it once carries the table from then on.

    Returns:
      Each stop in mm, keyed as `configuration.rotation_drive_z_slots` names them.
    """
    c = self.configuration
    slots = await self._request_slots("pz")
    c.rotation_drive_predefined_z_positions_increments = dict(zip(c.rotation_drive_z_slots, slots))
    return {
      name: round(c.z_increments_to_mm(increments) + c.rotation_drive_z_offset_above_finger, 1)
      for name, increments in zip(c.rotation_drive_z_slots, slots)
    }

  async def gripper_drive_request_widths(self) -> Dict[str, float]:
    """Read the jaw widths the gripper drive is calibrated against, in mm.

    The stored table rather than how far the jaws stand now, which `gripper_request_width` reads.
    Its ten slots are all widths: the one the jaws home and park at, one with no documented
    meaning, the width the drive treats as closed, and seven a plate type is gripped at.

    Records what came back on the configuration, as the other stored tables are recorded, so an
    arm read for it once carries the table from then on.

    Returns:
      Each width in mm, keyed as `configuration.gripper_drive_slots` names them.
    """
    c = self.configuration
    slots = await self._request_slots("pg")
    c.gripper_drive_predefined_increments = dict(zip(c.gripper_drive_slots, slots))
    return {
      name: c.gripper_increments_to_mm(increments)
      for name, increments in zip(c.gripper_drive_slots, slots)
    }

  async def _request_slots(self, table: str) -> List[int]:
    """One of the iSWAP's stored tables, as the ten signed slots the device returns."""
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
    c.rotation_drive_x_offset = await self.rotation_drive_request_x_offset()
    c.rotation_drive_predefined_y_positions_increments = dict(
      zip(c.rotation_drive_y_slots, await self._request_slots("py"))
    )

    rotation = await self._request_slots("pw")
    c.rotation_drive_predefined_increments = dict(
      zip(self.configuration.rotation_drive_slots, rotation)
    )
    c.link_1_length = round(rotation[9] / 10, 1)

    wrist = await self._request_slots("pt")
    c.wrist_drive_predefined_increments = dict(zip(self.configuration.wrist_drive_slots, wrist))
    c.link_2_length = round(wrist[9] / 10, 1)

    # The Z stops and the gripper widths are read here too, so a configuration saved after setup
    # carries every stored table. Left out, they save as nothing, and a simulated arm built from
    # that file cannot answer where its Z drive or its jaws are.
    c.rotation_drive_predefined_z_positions_increments = dict(
      zip(c.rotation_drive_z_slots, await self._request_slots("pz"))
    )
    c.gripper_drive_predefined_increments = dict(
      zip(c.gripper_drive_slots, await self._request_slots("pg"))
    )

  # -- initialization --------------------------------------------------------

  async def initialize(self):
    """Initialize the iSWAP. This moves it."""
    return await self._driver.send_command(module="C0", command="FI", subsystem="R0")

  # -- where it is -----------------------------------------------------------

  def rotation_drive_update_angle(self, angle: float) -> None:
    """Record which way the arm points on the resource that models it.

    The carriage is what the arm is mounted on, so the arm's angle is carried there and anything
    hung off it - the links, and what they hold - turns with it. Stated as the deck angle link 1
    lies along, which is the rotation drive's own angle less ninety degrees, so a resource's
    rotation reads in the frame every other resource is placed in.

    Does nothing when the driver was given no deck, and so has nothing to model.

    Args:
      angle: the rotation drive's angle, in degrees, as it reports it.
    """
    if self.resource is None or self._driver.deck is None:
      return
    self.resource.rotation_drive_angle = angle
    if self.link_1 is not None:
      # The carriage does not turn; the arm mounted on it does. Link 1 leaves the drive at the
      # drive's own angle less ninety degrees, which is the deck angle it lies along.
      self.link_1.turn_to(angle - 90.0, about=self.resource.reference_point)

  def rotation_drive_get_reference_point_location(self) -> Optional[Coordinate]:
    """Where the model has the rotation drive's reference point, in mm on the deck.

    The inverse of `update_location_by_reference_point`: it converts a reported position into a
    location, and this converts a location back into the position that would be reported. X is
    the arm's, so it is carried through unread.

    Returns:
      Where the model has it, or None when there is nothing modelling it yet.
    """
    deck = self._driver.deck
    if self.resource is None or self.resource.location is None or deck is None:
      return None
    arm = self.resource.parent
    if arm is None:
      return None
    return self.resource.location + arm.get_location_wrt(deck) + self.resource.reference_point

  def wrist_drive_get_angle(self) -> Optional[float]:
    """Which way the model has the wrist turned, as its drive reports it.

    Read from what the drive last reported, as `rotation_drive_get_angle` is: link 2's own rotation is an
    angle from link 1 about a different axis, so recovering a drive angle from it would be
    inverting a rendering rather than reading a fact.

    Returns:
      The angle in degrees, or None while nothing has read it yet.
    """
    if self.resource is None or self._driver.deck is None:
      return None
    return self.resource.wrist_drive_angle

  def rotation_drive_get_angle(self) -> Optional[float]:
    """Which way the model has the arm pointing, as the rotation drive reports it.

    Read from what the drive last reported, not converted back out of the resource's `rotation`:
    that is a deck angle about a different axis, so recovering a drive angle from it would be
    inverting a rendering rather than reading a fact.

    Returns:
      The angle in degrees, or None while nothing has read it yet.
    """
    if self.resource is None or self._driver.deck is None:
      return None
    return self.resource.rotation_drive_angle

  def wrist_drive_update_angle(self, angle: float) -> None:
    """Record which way the wrist is turned on the resource that models it.

    Link 2 turns on the wrist, which link 1 carries, so its angle is measured from link 1 rather
    than from the deck: a resource's rotation adds to its parent's, and link 1 is its parent. What
    the wrist reports when it is straight is where link 2 continues link 1, so the angle here is
    however far the wrist has turned from that.

    Does nothing until the links are modelled.

    Args:
      angle: the wrist drive's angle, in degrees, as it reports it.
    """
    c = self.configuration
    if self.resource is not None:
      self.resource.wrist_drive_angle = angle
    if self.link_1 is None or self.link_2 is None or c.wrist_drive_predefined_increments is None:
      return
    straight = c.wrist_increments_to_deg(c.wrist_drive_predefined_increments["straight"])
    self.link_2.turn_to(angle - straight, about=self.link_1.far_joint)

  def gripper_update_width(self, width: float) -> None:
    """Record how far apart the jaws stand on the resource that models them.

    Does nothing until the gripper is modelled, and nothing when the width is outside what the
    model says the fingers do - it says so instead, because the two disagreeing is a question
    about the geometry rather than something to paper over.

    Args:
      width: how far apart the jaws stand, in mm, as the drive reports it.
    """
    gripper = self.link_2
    if not isinstance(gripper, MechanicalGripper):
      return
    low, high = gripper.jaw_range
    if not low <= width <= high:
      logger.warning(
        "the gripper reports its jaws %.1f mm apart, outside the %.1f to %.1f mm the model says "
        "they travel, so the model is left where it is",
        width,
        low,
        high,
      )
      return
    gripper.jaw_width = width

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
    device = self._driver.configuration
    if device is None:
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
        device.left_arm_min_y_position
        if self.arm.side == "left"
        else device.right_arm_min_y_position
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

  # ----------------------------------------
  # Linear Movement
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

  async def _record_where_it_stopped(self, axis: Literal["y", "z", "gripper"]) -> None:
    """Read where a drive came to rest, and record it.

    For a move's failure path. A move that stopped part way left the drive somewhere no target
    describes. Its own failure is logged and swallowed: it must not replace the move's exception,
    which is the one that says what went wrong.

    Args:
      axis: which drive the move drove - `y` across the deck, `z` up and down, `gripper` the jaws.
    """
    try:
      if axis == "y":
        await self.rotation_drive_request_y_position()
      elif axis == "z":
        await self.rotation_drive_request_z_position()
      else:
        await self.gripper_request_width()
    except Exception:
      logger.warning("could not read where the iSWAP stopped along %s; its model is stale", axis)

  async def _unchecked_fw_rotation_drive_move_to_y_position_increments(
    self,
    y_increments: int,
    speed_increments: Optional[int] = None,
    acceleration_level: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Drive the rotation drive to an absolute Y. Nothing is guarded and nothing is recorded.

    Args:
      y_increments: where the drive is to go, in the increments it counts in.
      speed_increments: max velocity, in increments/s.
      acceleration_level: which acceleration curve to use, 1 or 2.
      current_limit: the motor current limit, 0 to 7.
    """
    c = self.configuration
    if speed_increments is None:
      speed_increments = c.y_speed_default_increments
    if acceleration_level is None:
      acceleration_level = c.y_acceleration_level_default
    if current_limit is None:
      current_limit = c.y_current_limit_default
    return await self._driver.send_command(
      module="R0",
      command="YA",
      ya=f"{y_increments:05}",
      yv=f"{speed_increments:04}",
      yr=f"{acceleration_level}",
      yw=f"{current_limit}",
    )

  async def rotation_drive_move_to_y_position(
    self,
    y: float,
    make_space: bool = False,
    speed: Optional[float] = None,
    acceleration_level: Optional[int] = None,
    current_limit: Optional[int] = None,
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
      RuntimeError: If the device's configuration or the drive's Y limit was not read.
    """
    c = self.configuration
    if speed is None:
      speed = c.y_speed_default
    if acceleration_level is None:
      acceleration_level = c.y_acceleration_level_default
    if current_limit is None:
      current_limit = c.y_current_limit_default
    device = self._driver.configuration
    if device is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    self._check_reachable("y", y)

    await self._make_space_for_y(y, make_space=make_space)

    speed_increments = c.y_mm_to_increments(speed)
    speed_low, speed_high = c.y_speed_range_increments
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
      resp = await self._unchecked_fw_rotation_drive_move_to_y_position_increments(
        y_increments=c.y_mm_to_increments(y),
        speed_increments=speed_increments,
        acceleration_level=acceleration_level,
        current_limit=current_limit,
      )
      # What was asked for, recorded as soon as the move answers, so the model holds it even if
      # the read below cannot be taken.
      self.update_location_by_reference_point(y=y)
      return resp
    finally:
      # And then what the drive says, which is the last word either way. A move that stopped part
      # way left the carriage somewhere no target describes, and a move that answered has still
      # only answered.
      await self._record_where_it_stopped("y")

  async def _unchecked_fw_position_components_for_free_y_range(self):
    """Position all components so that there is maximum free Y range for the iSWAP. Nothing is
    guarded and nothing is recorded. This moves the channels.
    """
    return await self._driver.send_command(module="C0", command="FY")

  async def _unchecked_fw_release_brake(self):
    """Release the arm's brake. Nothing is guarded and nothing is recorded.

    Dangerous: the brake is what holds the arm up, so releasing it drops whatever it is holding.
    """
    return await self._driver.send_command(module="R0", command="BA")

  async def _unchecked_fw_reengage_brake(self):
    """Re-engage the arm's brake. Nothing is guarded and nothing is recorded."""
    return await self._driver.send_command(module="R0", command="BO")

  async def make_space(self) -> None:
    """Move everything else out of the arm's Y range. This moves the channels.

    The master's own, which positions every component for the widest free Y range there is, rather
    than this driver working out where each channel should stand. It does not say where it left
    them, so they are read back either way.
    """
    pipettes = self.arm.pipettes
    try:
      await self._unchecked_fw_position_components_for_free_y_range()
    finally:
      if pipettes is not None:
        await pipettes.request_y_positions()

  async def _make_space_for_y(self, y: float, make_space: bool) -> None:
    """Make sure the backmost channel is out of the way before the drive travels to `y`.

    Args:
      y: where the rotation drive is going, in mm.
      make_space: whether the channels may be moved to make that space.

    Raises:
      ValueError: If the channel is in the way and either may not be moved, or cannot move far
        enough to clear it.
    """
    pipettes = self.arm.pipettes
    if pipettes is None:
      return

    device = self._driver.configuration
    if device is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")

    widths = [channel.width for channel in pipettes.configuration.channels]
    if any(width is None for width in widths):
      raise RuntimeError("the channels have no width read yet; have you called `star.setup()`?")

    # Where the backmost channel would have to be for the drive to reach `y`, and the furthest
    # back it can get: every channel behind it packed against the front of their travel.
    backmost_y = await pipettes.request_y_position(0)
    target_y = y - cast(float, widths[0]) / 2 - self.configuration.rotation_drive_swept_radius
    furthest_back = device.left_arm_min_y_position + sum(cast(List[float], widths[1:]))

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
    await self.make_space()

  async def _make_space_for_pose(
    self, rotation_angle: float, wrist_angle: float, make_space: bool
  ) -> None:
    """Make sure the channels are out of the way of where the arm is about to reach.

    `_make_space_for_y` does this for the drive travelling across the deck, where the arm is a
    circle about it. Here the pose is known, so the arm is where the forward kinematics say it is:
    the frontmost of its two moving joints is what would meet a channel, and the channels have to
    stand in front of that.

    Does nothing when the arm is not modelled or the numbers it needs have not been read - a check
    that cannot be made must not look like one that passed.

    Args:
      rotation_angle: where the rotation drive is being sent, in degrees.
      wrist_angle: where the wrist is being sent, in degrees.
      make_space: whether the channels may be moved to make that space.

    Raises:
      ValueError: If the arm would reach into the channels and either they may not be moved, or
        they cannot move far enough to clear it.
    """
    pipettes = self.arm.pipettes
    device = self._driver.configuration
    if pipettes is None or device is None:
      return
    pose = self._compute_pose_at_angles(rotation_angle, wrist_angle)

    widths = [channel.width for channel in pipettes.configuration.channels]
    if any(width is None for width in widths):
      return

    # The frontmost point the arm would put anywhere, and where that leaves the backmost channel:
    # it has to stand in front of the arm by its own half width.
    reaches_to = min(pose.wrist_joint_location.y, pose.gripper_center_location.y)
    target_y = reaches_to - cast(float, widths[0]) / 2
    backmost_y = await pipettes.request_y_position(0)
    furthest_back = device.left_arm_min_y_position + sum(cast(List[float], widths[1:]))

    if backmost_y <= target_y:
      return
    if target_y < furthest_back:
      raise ValueError(
        f"rotation {rotation_angle:.2f} deg with the wrist at {wrist_angle:.2f} reaches to y "
        f"{reaches_to:.1f} mm, which needs the backmost channel at {target_y:.1f} mm - and the "
        f"channels do not fit behind {furthest_back:.1f} mm"
      )
    if not make_space:
      raise ValueError(
        f"rotation {rotation_angle:.2f} deg with the wrist at {wrist_angle:.2f} reaches to y "
        f"{reaches_to:.1f} mm, which needs the backmost channel at {target_y:.1f} mm or further "
        f"front, and it is at {backmost_y:.1f} mm. Pass make_space=True to move the channels out "
        f"of the way"
      )
    await self.make_space()

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

  async def _unchecked_fw_rotation_drive_move_to_z_position_increments(
    self,
    z_increments: int,
    speed_increments: Optional[int] = None,
    acceleration_increments: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Drive the rotation drive to an absolute Z. Nothing is guarded and nothing is recorded.

    The drive is calibrated to the gripper finger plane, so what it counts is that plane's height
    rather than the drive's own: `rotation_drive_move_to_z_position` is what takes the offset out.

    Args:
      z_increments: where the finger plane is to go, in the increments the drive counts in.
      speed_increments: max velocity, in increments/s.
      acceleration_increments: in thousands of increments/s2.
      current_limit: the motor current limit, 0 to 7.
    """
    c = self.configuration
    if speed_increments is None:
      speed_increments = c.z_speed_default_increments
    if acceleration_increments is None:
      acceleration_increments = c.z_acceleration_default_increments
    if current_limit is None:
      current_limit = c.z_current_limit_default
    return await self._driver.send_command(
      module="R0",
      command="ZA",
      za=f"{z_increments:+06}",
      zv=f"{speed_increments:05}",
      zr=f"{acceleration_increments:03}",
      zw=f"{current_limit}",
    )

  async def rotation_drive_move_to_z_position(
    self,
    z: float,
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: Optional[int] = None,
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
    if speed is None:
      speed = c.z_speed_default
    if acceleration is None:
      acceleration = c.z_acceleration_default
    if current_limit is None:
      current_limit = c.z_current_limit_default
    self._check_reachable("z", z)

    speed_increments = c.z_mm_to_increments(speed)
    speed_low, speed_high = c.z_speed_range_increments
    if not speed_low <= speed_increments <= speed_high:
      raise ValueError(
        f"speed must be between {c.z_increments_to_mm(speed_low)} and "
        f"{c.z_increments_to_mm(speed_high)} mm/s, is {speed}"
      )

    # The drive counts acceleration in thousands of increments per second squared.
    acceleration_increments = c.z_mm_to_increments(acceleration / 1000)
    acceleration_low, acceleration_high = c.z_acceleration_range_increments
    if not acceleration_low <= acceleration_increments <= acceleration_high:
      raise ValueError(
        f"acceleration must be between {c.z_increments_to_mm(acceleration_low * 1000)} and "
        f"{c.z_increments_to_mm(acceleration_high * 1000)} mm/s2, is {acceleration}"
      )

    if not 0 <= current_limit <= 7:
      raise ValueError(f"current_limit must be between 0 and 7, is {current_limit}")

    finger_plane = z - c.rotation_drive_z_offset_above_finger
    try:
      resp = await self._unchecked_fw_rotation_drive_move_to_z_position_increments(
        z_increments=c.z_mm_to_increments(finger_plane),
        speed_increments=speed_increments,
        acceleration_increments=acceleration_increments,
        current_limit=current_limit,
      )
      # What was asked for, recorded as soon as the move answers, so the model holds it even if
      # the read below cannot be taken.
      self.update_location_by_reference_point(z=z)
      return resp
    finally:
      # And then what the drive says, which is the last word either way.
      await self._record_where_it_stopped("z")

  async def rotation_drive_move_to_safe_z_height(
    self,
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: Optional[int] = None,
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
    c = self.configuration
    if speed is None:
      speed = c.z_speed_default
    if acceleration is None:
      acceleration = c.z_acceleration_default
    if current_limit is None:
      current_limit = c.z_current_limit_default
    await self.rotation_drive_move_to_z_position(
      self.configuration.rotation_drive_z_range[1],
      speed=speed,
      acceleration=acceleration,
      current_limit=current_limit,
    )
    return await self.rotation_drive_request_z_position()

  # ----------------------------------------
  # Rotational Movement
  # ----------------------------------------

  # -- rotation, wrist and gripper --------------------------------------------
  # -- both joints, which the drive command carries together -----------------------

  async def _unchecked_fw_rotation_drive_rotate_increments(
    self,
    rotation_increments: int,
    wrist_increments: int,
    rotation_speed_increments: Optional[int] = None,
    wrist_speed_increments: Optional[int] = None,
    rotation_acceleration_increments: Optional[int] = None,
    wrist_acceleration_increments: Optional[int] = None,
    rotation_current_limit: Optional[int] = None,
    wrist_current_limit: Optional[int] = None,
  ):
    """Drive both joints to absolute increments. Nothing is guarded and nothing is recorded.

    The lowest command there is here: it takes what the drives count in and sends it. Both joints
    go in one command because they move together - the wrist rides the rotation drive, so sending
    them separately turns the arm and then corrects the wrist, sweeping a path neither target
    describes. A caller that means to move one holds the other at where it already is.

    Args:
      rotation_increments: where the rotation drive is to go, signed.
      wrist_increments: where the wrist drive is to go, signed.
      rotation_speed_increments: max velocity of the rotation drive, in increments/s.
      wrist_speed_increments: max velocity of the wrist drive, in increments/s.
      rotation_acceleration_increments: for the rotation drive, in thousands of increments/s2.
      wrist_acceleration_increments: for the wrist drive, in thousands of increments/s2.
      rotation_current_limit: the rotation motor's current limit.
      wrist_current_limit: the wrist motor's current limit.
    """
    c = self.configuration
    if rotation_speed_increments is None:
      rotation_speed_increments = c.rotation_speed_default_increments
    if wrist_speed_increments is None:
      wrist_speed_increments = c.wrist_speed_default_increments
    if rotation_acceleration_increments is None:
      rotation_acceleration_increments = c.rotation_acceleration_default_increments
    if wrist_acceleration_increments is None:
      wrist_acceleration_increments = c.wrist_acceleration_default_increments
    if rotation_current_limit is None:
      rotation_current_limit = c.rotation_current_limit_default
    if wrist_current_limit is None:
      wrist_current_limit = c.wrist_current_limit_default
    return await self._driver.send_command(
      module="R0",
      command="PA",
      wa=f"{rotation_increments:+06}",
      wv=f"{rotation_speed_increments:05}",
      wr=f"{rotation_acceleration_increments:03}",
      ww=f"{rotation_current_limit}",
      ta=f"{wrist_increments:+06}",
      tv=f"{wrist_speed_increments:05}",
      tr=f"{wrist_acceleration_increments:03}",
      tw=f"{wrist_current_limit}",
    )

  def _resolve_rotation_increments(self, angle: Union[str, float]) -> int:
    """A rotation stop's name or an angle, as the increments the drive counts in.

    Args:
      angle: a stop in `configuration.rotation_drive_slots`, or degrees from the calibrated front stop.

    Returns:
      Where the drive is to go, in increments.

    Raises:
      ValueError: If the name is not a stop, or the angle is outside the drive's travel.
      RuntimeError: If the stored predefined_positions have not been read.
    """
    c = self.configuration
    if isinstance(angle, str):
      predefined_positions = c.rotation_drive_predefined_increments
      if predefined_positions is None:
        raise RuntimeError(
          "the rotation drive's predefined_positions were not read; have you called `setup()`?"
        )
      if angle not in predefined_positions:
        raise ValueError(
          f"{angle!r} is not one of the predefined_positions {tuple(predefined_positions)}"
        )
      increments = predefined_positions[angle]
    else:
      increments = c.rotation_drive_angle_to_increments(angle)
    low, high = c.rotation_range_increments
    if not low <= increments <= high:
      raise ValueError(
        f"{angle} is {increments} increments, outside the {low} to {high} the drive travels"
      )
    return increments

  def _resolve_wrist_increments(self, angle: Union[str, float]) -> int:
    """A wrist stop's name or an angle, as the increments the drive counts in.

    Args:
      angle: a stop in `configuration.wrist_drive_slots`, or degrees from the drive's own zero.

    Returns:
      Where the drive is to go, in increments.

    Raises:
      ValueError: If the name is not a stop, or the angle is outside the drive's travel.
      RuntimeError: If the stored predefined_wrist_positions have not been read.
    """
    c = self.configuration
    if isinstance(angle, str):
      predefined_wrist_positions = c.wrist_drive_predefined_increments
      if predefined_wrist_positions is None:
        raise RuntimeError(
          "the wrist's stored predefined_wrist_positions were not read; have you called `setup()`?"
        )
      if angle not in predefined_wrist_positions:
        raise ValueError(
          f"{angle!r} is not one of the predefined_wrist_positions {tuple(predefined_wrist_positions)}"
        )
      increments = predefined_wrist_positions[angle]
    else:
      increments = c.wrist_deg_to_increments(angle)
    low, high = c.wrist_range_increments
    if not low <= increments <= high:
      raise ValueError(
        f"{angle} is {increments} increments, outside the {low} to {high} the wrist travels"
      )
    return increments

  async def rotate_to_angles(
    self,
    rotation_angle: Optional[Union[str, float]] = None,
    wrist_angle: Optional[Union[str, float]] = None,
    make_space: bool = False,
    rotation_speed: Optional[float] = None,
    wrist_speed: Optional[float] = None,
    rotation_acceleration: Optional[float] = None,
    wrist_acceleration: Optional[float] = None,
    rotation_current_limit: Optional[int] = None,
    wrist_current_limit: Optional[int] = None,
  ):
    """Rotate one or both iSWAP joints to absolute angles in a single motion. This moves the arm.

    When both angles are supplied, both joints arrive together under a single motion plan so the
    gripper sweeps a straight joint-space path; enables IK-driven trajectory execution.

    When only one angle is supplied, the other drive is requested from device (i.e. single-axis
    rotation is covered as well). At least one of `rotation_angle` or `wrist_angle` must be
    provided.

    Each angle is either the enum stop, which lands on the increment this arm stores for it, or a
    float in degrees: rotation floats interpolate piecewise-linearly between the LEFT / FRONT /
    RIGHT stops, so -90, 0 and +90 land on them exactly; wrist floats are linear from motor zero.

    Collision risk: the whole arm sweeps, and the path is neither joint's alone.

    Args:
      rotation_angle [deg]: a stop in `configuration.rotation_drive_slots`, or float signed from
        FRONT, or None to hold current.
      wrist_angle [deg]: a stop in `configuration.wrist_drive_slots`, or float signed from motor zero,
        or None to hold current.
      make_space: whether the channels may be moved out of the way when the arm would end up
        reaching into them. Off by default, so a pose that does not fit raises and the caller
        decides. Making space raises the channels to Z safety first, since it moves them in Y.
      rotation_speed [deg/sec]: max angular velocity, within what
        `configuration.rotation_speed_range_increments` accepts.
      wrist_speed [deg/sec]: max angular velocity, within what
        `configuration.wrist_speed_range_increments` accepts.
      rotation_acceleration [deg/sec^2]: max angular acceleration, within what
        `configuration.rotation_acceleration_range_increments` accepts.
      wrist_acceleration [deg/sec^2]: max angular acceleration, within what
        `configuration.wrist_acceleration_range_increments` accepts.
      rotation_current_limit: motor current protection limiter, 0..7.
      wrist_current_limit: motor current protection limiter, 0..7.

    Raises:
      RuntimeError: if `setup()` has not populated the predefined-stop tables.
      ValueError: if neither angle is provided, or if either resolved target increment is outside
        the hardware range.
    """
    c = self.configuration
    if rotation_speed is None:
      rotation_speed = c.rotation_speed_default
    if wrist_speed is None:
      wrist_speed = c.wrist_speed_default
    if rotation_acceleration is None:
      rotation_acceleration = c.rotation_acceleration_default
    if wrist_acceleration is None:
      wrist_acceleration = c.wrist_acceleration_default
    if rotation_current_limit is None:
      rotation_current_limit = c.rotation_current_limit_default
    if wrist_current_limit is None:
      wrist_current_limit = c.wrist_current_limit_default
    if rotation_angle is None and wrist_angle is None:
      raise ValueError("pass a rotation_angle, a wrist_angle, or both; both are None")
    # Held in the drive's own increments rather than through its angle, so a joint that is holding
    # is sent exactly where it already is.
    rotation = (
      await self._rotation_drive_request_increments()
      if rotation_angle is None
      else self._resolve_rotation_increments(rotation_angle)
    )
    wrist = (
      await self._wrist_drive_request_increments()
      if wrist_angle is None
      else self._resolve_wrist_increments(wrist_angle)
    )
    rotation_speed_increments = c.rotation_deg_per_sec_to_increments(rotation_speed)
    wrist_speed_increments = c.wrist_deg_per_sec_to_increments(wrist_speed)
    rotation_acceleration_increments = c.rotation_deg_per_sec2_to_increments(rotation_acceleration)
    wrist_acceleration_increments = c.wrist_deg_per_sec2_to_increments(wrist_acceleration)
    for name, asked, increments, (low, high), in_degrees in (
      (
        "rotation_speed",
        rotation_speed,
        rotation_speed_increments,
        c.rotation_speed_range_increments,
        c.rotation_increments_to_deg_per_sec,
      ),
      (
        "wrist_speed",
        wrist_speed,
        wrist_speed_increments,
        c.wrist_speed_range_increments,
        c.wrist_increments_to_deg_per_sec,
      ),
      (
        "rotation_acceleration",
        rotation_acceleration,
        rotation_acceleration_increments,
        c.rotation_acceleration_range_increments,
        c.rotation_increments_to_deg_per_sec2,
      ),
      (
        "wrist_acceleration",
        wrist_acceleration,
        wrist_acceleration_increments,
        c.wrist_acceleration_range_increments,
        c.wrist_increments_to_deg_per_sec2,
      ),
    ):
      if not low <= increments <= high:
        raise ValueError(
          f"{name} must be between {in_degrees(low)} and {in_degrees(high)}, is {asked}"
        )
    for name, value in (
      ("rotation_current_limit", rotation_current_limit),
      ("wrist_current_limit", wrist_current_limit),
    ):
      if not 0 <= value <= 7:
        raise ValueError(f"{name} must be between 0 and 7, is {value}")

    rotation_target = c.rotation_drive_increments_to_angle(rotation)
    wrist_target = c.wrist_increments_to_deg(wrist)
    self._check_pose_reachable(rotation_target, wrist_target)
    await self._make_space_for_pose(rotation_target, wrist_target, make_space)
    try:
      resp = await self._unchecked_fw_rotation_drive_rotate_increments(
        rotation_increments=rotation,
        wrist_increments=wrist,
        rotation_speed_increments=rotation_speed_increments,
        wrist_speed_increments=wrist_speed_increments,
        rotation_acceleration_increments=rotation_acceleration_increments,
        wrist_acceleration_increments=wrist_acceleration_increments,
        rotation_current_limit=rotation_current_limit,
        wrist_current_limit=wrist_current_limit,
      )
      # What was asked for, recorded before anything is read: a move that answered has arrived,
      # and the model says so even if the reads below cannot be taken.
      self.rotation_drive_update_angle(c.rotation_drive_increments_to_angle(rotation))
      self.wrist_drive_update_angle(c.wrist_increments_to_deg(wrist))
      return resp
    finally:
      # And then what the drives say, which is the last word either way. A move that stopped part
      # way left the arm somewhere no target describes, and this is the only thing that finds it.
      await self._record_where_the_joints_stopped()

  def _compute_pose_at_angles(self, rotation_angle: float, wrist_angle: float) -> iSWAPPose:
    """Where the arm would be with its joints at these angles. Nothing is read or moved.

    Worked from where the model has the drive, so it costs no commands, and it is what both of the
    checks below a move ask. None when the arm is not modelled or the numbers the kinematics need
    have not been read.

    Args:
      rotation_angle: the rotation drive's angle, in degrees.
      wrist_angle: the wrist drive's angle, in degrees.

    Returns:
      The pose.

    Raises:
      RuntimeError: If the arm is not modelled, its gripper is not, or the kinematics' numbers
        have not been read.
    """
    c = self.configuration
    predefined_wrist_positions = c.wrist_drive_predefined_increments
    drive = self.rotation_drive_get_reference_point_location()
    gripper = self.link_2
    if drive is None:
      raise RuntimeError("the iSWAP's arm is not modelled; the driver was given no deck")
    if not isinstance(gripper, MechanicalGripper):
      raise RuntimeError("the iSWAP's arm is modelled but its gripper is not")
    if c.link_1_length is None or predefined_wrist_positions is None:
      raise RuntimeError("the arm's link length or the wrist's stops were not read")
    return self._forward_kinematics(
      joints={
        iSWAPAxis.X: drive.x,
        iSWAPAxis.Y: drive.y,
        iSWAPAxis.Z: drive.z,
        iSWAPAxis.ROTATION: rotation_angle,
        iSWAPAxis.WRIST: wrist_angle,
      },
      link_1_length=c.link_1_length,
      # Asked of the tool, not taken off the arm: the gripper knows how far its grip centre sits
      # from the wrist, and a different end-effector would answer differently.
      tool_center_point_distance=gripper.tool_center_point.x,
      wrist_straight_angle=c.wrist_increments_to_deg(predefined_wrist_positions["straight"]),
      rotation_drive_z_offset_above_finger=c.rotation_drive_z_offset_above_finger,
    )

  def _check_pose_reachable(self, rotation_angle: float, wrist_angle: float) -> None:
    """Raise if the arm cannot put its gripper where these angles would.

    Not what `_check_reachable` answers: that bounds one value on one axis.

    The X-arm is a rail across the back of the deck, behind the drive's own Y travel, so nothing
    the arm carries may stand further back than the drive itself reaches. A pose is worked out
    before it is commanded rather than discovered on the way into the rail.

    The crudest check there is: two points, at the end of the move, against one bound. It says
    nothing about what the arm sweeps through on the way, nor about anything else standing on the
    deck. Skipped entirely when the arm is not modelled or the numbers it needs have not been
    read - a check that cannot be made must not look like one that passed.

    Args:
      rotation_angle: where the rotation drive is being sent, in degrees.
      wrist_angle: where the wrist is being sent, in degrees.

    Raises:
      ValueError: If the grip centre would land behind the drive's own back stop.
    """
    y_max = self.configuration.rotation_drive_y_max
    if y_max is None:
      return
    pose = self._compute_pose_at_angles(rotation_angle, wrist_angle)
    # Both moving joints, not only the far one: link 1 is long enough to put the wrist behind the
    # rail while the grip centre is still clear of it.
    for what, point in (
      ("wrist joint", pose.wrist_joint_location),
      ("grip centre", pose.gripper_center_location),
    ):
      if point.y > y_max:
        raise ValueError(
          f"rotation {rotation_angle:.2f} deg with the wrist at {wrist_angle:.2f} would put the "
          f"{what} at y {point.y:.1f} mm, behind the {y_max:.1f} mm the rotation drive itself "
          f"reaches - the X-arm runs across the back of the deck there. Turn the arm the other "
          f"way, or move the drive forward first"
        )

  async def _record_where_the_joints_stopped(self) -> None:
    """Read both joints and record them on the model.

    Its own failure is logged and swallowed: it runs on a move's failure path as well as its
    success, and it must not replace the exception that says what went wrong.
    """
    try:
      await self.rotation_drive_request_angle()
      await self.wrist_drive_request_angle()
    except Exception:
      logger.warning("could not read where the iSWAP's joints stopped; its model is stale")

  # -- rotation drive --------------------------------------------------------------

  async def rotation_drive_request_angle(self) -> float:
    """Read the rotation drive's angle, signed from the calibrated front stop.

    Returns:
      The angle in degrees.
    """
    angle = self.configuration.rotation_drive_increments_to_angle(
      await self._rotation_drive_request_increments()
    )
    self.rotation_drive_update_angle(angle)
    return angle

  async def _rotation_drive_request_increments(self) -> int:
    """Reads the rotation drive's position in the increments the drive counts in.

    Returns:
      int: The drive's position, in increments.
    """
    resp = await self._driver.send_command(module="R0", command="RW", fmt="rw######")
    return cast(int, resp["rw"])

  async def rotation_drive_rotate_to_angle(
    self,
    angle: Union[str, float],
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: Optional[int] = None,
  ):
    """Turn the rotation drive to an angle, holding the wrist where it is. This moves the arm.

    A caller for `rotate_to_angles`, which is where the move and the model update live. The wrist
    is left to hold where it is, so one command carries both joints.

    Args:
      angle: one of the stops in `configuration.rotation_drive_slots` - `left`, `front`, `right`, `parking` -
        which goes to the increment this arm stores for it, or degrees signed from the calibrated
        front stop.
      speed [deg/sec]: max angular velocity.
      acceleration [deg/sec^2]: max angular acceleration.
      current_limit: motor current protection limiter, 0..7.

    Raises:
      ValueError: If the angle lands outside the drive's travel, or an argument is out of range.
    """
    c = self.configuration
    if speed is None:
      speed = c.rotation_speed_default
    if acceleration is None:
      acceleration = c.rotation_acceleration_default
    if current_limit is None:
      current_limit = c.rotation_current_limit_default
    return await self.rotate_to_angles(
      rotation_angle=angle,
      rotation_speed=speed,
      rotation_acceleration=acceleration,
      rotation_current_limit=current_limit,
    )

  # -- wrist drive -----------------------------------------------------------------

  async def wrist_drive_request_angle(self) -> float:
    """Read the wrist drive's angle, signed from the motor's own zero.

    That zero sits between the straight and left stops, which keeps the reachable range symmetric
    about it rather than anchoring it on a stop.

    Returns:
      The angle in degrees.
    """
    angle = self.configuration.wrist_increments_to_deg(await self._wrist_drive_request_increments())
    self.wrist_drive_update_angle(angle)
    return angle

  async def _wrist_drive_request_increments(self) -> int:
    """Reads the wrist drive's position in the increments the drive counts in.

    Returns:
      int: The drive's position, in increments.
    """
    resp = await self._driver.send_command(module="R0", command="RT", fmt="rt######")
    return cast(int, resp["rt"])

  async def wrist_drive_rotate_to_angle(
    self,
    angle: Union[str, float],
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: Optional[int] = None,
  ):
    """Turn the wrist to an angle, holding the rotation drive where it is. This moves the arm.

    The mirror of `rotation_drive_rotate_to_angle`, and the same one move underneath.

    Args:
      angle: one of the stops in `configuration.wrist_drive_slots` - `straight`, `left`, `right`, `reverse`,
        `parking` - which goes to the increment this arm stores for it, or degrees signed from the
        drive's own zero.
      speed [deg/sec]: max angular velocity.
      acceleration [deg/sec^2]: max angular acceleration.
      current_limit: motor current protection limiter, 0..7.

    Raises:
      ValueError: If the angle lands outside the drive's travel, or an argument is out of range.
    """
    c = self.configuration
    if speed is None:
      speed = c.wrist_speed_default
    if acceleration is None:
      acceleration = c.wrist_acceleration_default
    if current_limit is None:
      current_limit = c.wrist_current_limit_default
    return await self.rotate_to_angles(
      wrist_angle=angle,
      wrist_speed=speed,
      wrist_acceleration=acceleration,
      wrist_current_limit=current_limit,
    )

  # -- gripper drive ---------------------------------------------------------------

  async def gripper_request_counters(self) -> Tuple[int, int]:
    """Read both counters the gripper drive keeps, in its own increments.

    The drive answers what the firmware believes it commanded and what the encoder reads back.
    They part when the drive has lost steps - jammed against something, or driven into its own
    stop - and the gap is the only sign of it: a single width read cannot show it, and a drive
    whose counters have parted will refuse to initialize until it has been freed.

    Returns:
      The firmware's counter and the hardware's, in that order.
    """
    resp = await self._driver.send_command(module="R0", command="RG", fmt="rg##### (n)")
    firmware, hardware = cast(List[int], resp["rg"])
    if abs(firmware - hardware) > self.configuration.gripper_counter_drift_increments:
      logger.warning(
        "the gripper drive's counters are %d increments apart (firmware %d, hardware %d), which is "
        "a drive that has lost steps rather than one that has moved",
        abs(firmware - hardware),
        firmware,
        hardware,
      )
    return firmware, hardware

  async def gripper_request_latest_force_applied(self) -> Dict[str, int]:
    """Read what the gripper's force sensor and motor current did during the last movement.

    All of it is the arm's own raw measurement, and the last entry is the only one in engineering
    units - the arm converts it with a divisor it keeps in its own memory.

    Returns:
      The peak drive current and peak force during the last movement, the sensor's idle offset,
      its last reading, all in the sensor's own counts, and that last reading in millinewtons.
    """
    resp = await self._driver.send_command(module="R0", command="RH", fmt="rh#### (n)")
    current, peak, idle, last, millinewtons = cast(List[int], resp["rh"])
    return {
      "peak_current": current,
      "peak_force": peak,
      "idle_offset": idle,
      "last_force": last,
      "last_force_millinewtons": millinewtons,
    }

  async def gripper_request_width(self) -> float:
    """Read how far the gripper jaws are open.

    Where the fingers are, which after a grip is not how wide the thing between them is: a close
    stops by pressing into what it meets, so it leaves them nearer together than the object stands.

    Returns:
      The jaw width in mm.
    """
    resp = await self._driver.send_command(module="R0", command="RG", fmt="rg##### (n)")
    # A target and an actual come back, in that order. The actual is read.
    width = self.configuration.gripper_increments_to_mm(cast(List[int], resp["rg"])[1])
    self.gripper_update_width(width)
    return width

  async def request_plate_gripped(self) -> bool:
    """Read whether the arm is holding something between its fingers.

    The arm's own answer, not the model's: the gripper reports it, so a plate taken or dropped by
    anything other than this driver still shows up. `gripped` is what the model says, and the two
    disagreeing means the model has lost track of what the arm is carrying.

    Returns:
      True while it holds something.
    """
    resp = await self._driver.send_command(module="C0", command="QP", subsystem="R0", fmt="ph#")
    gripped = cast(int, resp["ph"]) == 1
    self.gripped = gripped
    return gripped

  async def _unchecked_fw_gripper_move_to_jaw_position_increments(
    self,
    increments: int,
    speed_increments: Optional[int] = None,
    acceleration_increments: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Drive the jaws to an absolute width. Nothing is guarded and nothing is recorded.

    The lowest command there is here: it takes what the drive counts in and sends it. It feels
    nothing on the way - the drive pushes to where it is told with whatever the current limit
    allows, and says so only once it has locked. What checks, chooses and records is
    `gripper_move_to_jaw_position`; the drive's own knobs are here for a caller that needs them.

    Args:
      increments: where the jaws are to go, in the drive's own steps.
      speed_increments: max velocity, in increments/s. The drive's own default when None.
      acceleration_increments: in thousands of increments/s2. The drive's own default when None.
      current_limit: the motor current limit. The drive's own default when None.
    """
    c = self.configuration
    if speed_increments is None:
      speed_increments = c.gripper_speed_default_increments
    if acceleration_increments is None:
      acceleration_increments = c.gripper_acceleration_default_increments
    if current_limit is None:
      current_limit = c.gripper_current_limit_default
    return await self._driver.send_command(
      module="R0",
      command="GA",
      ga=f"{increments:05}",
      gv=f"{speed_increments:04}",
      gr=f"{acceleration_increments:03}",
      gw=f"{current_limit:02}",
    )

  async def gripper_move_to_jaw_position(
    self,
    width: float,
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: Optional[int] = None,
  ):
    """Open the jaws to a width. This moves them.

    A position, driven: the jaws go where they are told whether or not something is in the way, and
    the drive says nothing until it has locked. It feels nothing on the way, so closing onto a
    thing is `gripper_close_with_force_sensed_width_window`, which watches the force sensor and
    reports what it met.

    The jaws are read first, so which way this move goes is known rather than assumed. A close the
    caller named no speed for is driven at half the configured default, since whatever the jaws
    meet is met at whatever they were driven at.

    Args:
      width: how far apart to stand the jaws, in mm.
      speed: how fast to drive them, in mm/s. `configuration.gripper_speed_default_increments`
        when None, halved for a close.
      acceleration: how hard to accelerate, in mm/s2.
        `configuration.gripper_acceleration_default_increments` when None.
      current_limit: the motor current limit, 0 the weakest and 15 the strongest.
        `configuration.gripper_current_limit_default` when None.

    Raises:
      ValueError: If the width is outside the drive's travel, or the speed, acceleration or
        current limit is outside what the drive accepts.
    """
    c = self.configuration
    # Compared in mm rather than in increments: a width read off the drive and sent straight back
    # loses a fraction of an increment on the way, and the ends of the travel are exactly the
    # widths a caller asks for when it wants the jaws shut or wide open.
    low = c.gripper_increments_to_mm(c.gripper_range_increments[0])
    high = c.gripper_increments_to_mm(c.gripper_range_increments[1])
    if not low <= width <= high:
      raise ValueError(f"width must be between {low} and {high} mm, is {width}")
    increments = min(
      max(c.gripper_mm_to_increments(width), c.gripper_range_increments[0]),
      c.gripper_range_increments[1],
    )

    # Read the jaws before anything is chosen: which way this move goes decides what it is driven
    # at, and a width that happens to equal the default is not the same as a caller naming none.
    closing = width < await self.gripper_request_width()

    if current_limit is None:
      current_limit = c.gripper_current_limit_default
    limit_low, limit_high = c.gripper_current_limit_range
    if not limit_low <= current_limit <= limit_high:
      raise ValueError(
        f"current_limit must be between {limit_low} and {limit_high}, is {current_limit}"
      )

    if speed is not None:
      speed_increments = c.gripper_mm_per_sec_to_increments(speed)
    else:
      # Half speed into a close the caller did not set a speed for: this command feels nothing, so
      # whatever the jaws meet is met at whatever they were driven at.
      speed_increments = c.gripper_speed_default_increments
      if closing:
        speed_increments //= 2
    acceleration_increments = (
      c.gripper_acceleration_default_increments
      if acceleration is None
      else c.gripper_mm_per_sec2_to_increments(acceleration)
    )
    for name, asked, increments, (limit_low, limit_high), in_mm in (
      (
        "speed",
        speed,
        speed_increments,
        c.gripper_speed_range_increments,
        c.gripper_increments_to_mm_per_sec,
      ),
      (
        "acceleration",
        acceleration,
        acceleration_increments,
        c.gripper_acceleration_range_increments,
        c.gripper_increments_to_mm_per_sec2,
      ),
    ):
      if not limit_low <= increments <= limit_high:
        raise ValueError(
          f"{name} must be between {in_mm(limit_low)} and {in_mm(limit_high)}, is {asked}"
        )

    try:
      resp = await self._unchecked_fw_gripper_move_to_jaw_position_increments(
        increments=increments,
        speed_increments=speed_increments,
        acceleration_increments=acceleration_increments,
        current_limit=current_limit,
      )
      # What was asked for, recorded as soon as the move answers, so the model holds it even if
      # the read below cannot be taken.
      self.gripper_update_width(width)
      return resp
    finally:
      # And then what the drive says, which is the last word. This one stalls: sent the full sweep
      # from its open end it has locked part way and answered an error, leaving the jaws nowhere
      # the target described - which a model taking only the target would have denied.
      await self._record_where_it_stopped("gripper")

  async def gripper_open(self):
    """Open the jaws all the way. This moves them.

    Opening cannot close on anything, so it is a plain move to the far end of the drive's travel.
    What clears the jaws of whatever they are about to take hold of.
    """
    c = self.configuration
    return await self.gripper_move_to_jaw_position(
      c.gripper_increments_to_mm(c.gripper_range_increments[1])
    )

  async def gripper_close(self):
    """Close the jaws all the way. This moves them.

    Shut, which is below the width the master's own close will be aimed at, so it is a plain move
    too. Closing onto something and holding it is what `gripper_move_to_jaw_position` does at any
    width above that floor.
    """
    c = self.configuration
    return await self.gripper_move_to_jaw_position(
      c.gripper_increments_to_mm(c.gripper_range_increments[0])
    )

  async def _unchecked_fw_gripper_close_with_force_sensed_width_window_increments(
    self,
    grip_strength: int,
    width_increments: int,
    width_tolerance_increments: int,
  ):
    """Close the jaws onto an object, feeling for it. Nothing is guarded and nothing is recorded.

    Unchecked here means unchecked by this driver: what is skipped is the guarding of arguments
    and the recording of the model. The arm still feels. This is the lower of the two commands the
    jaws take and the one that senses - the master closes until the force sensor says it has met
    something, and answers an error when it meets nothing. What guards and records is
    `gripper_close_with_force_sensed_width_window`.

    Both widths are in the tenths of a millimetre the master counts in, which is not what the
    drive counts in: a grip is stated to the master, and a position to the drive.

    Args:
      grip_strength: how hard to hold, 0 the weakest and 9 the strongest.
      width_increments: how wide the thing between the jaws is said to be, in tenths of a
        millimetre.
      width_tolerance_increments: how far off that width the thing may be and still count as the
        thing, in tenths of a millimetre. It sets the window the close searches in: meeting
        something inside it is a grip, and closing past it without meeting anything is what the
        arm reports as finding nothing. The jaws also have to start further apart than the width
        and this tolerance together.
    """
    return await self._driver.send_command(
      module="C0",
      command="GC",
      subsystem="R0",
      gw=f"{grip_strength}",
      gb=f"{width_increments:04}",
      gt=f"{width_tolerance_increments:02}",
    )

  async def gripper_close_with_force_sensed_width_window(
    self,
    width: float,
    grip_strength: int = 5,
    width_tolerance: float = 2.0,
  ):
    """Close the jaws onto whatever is between them and hold it. This moves them.

    They stop on what they meet, where `gripper_move_to_jaw_position` drives to a width whatever is
    in the way. So the width is where to look, not where the jaws end up: they end inside the thing,
    and a plate stated at 85.5 mm was held at 80.3 mm. The jaws have to start clear of it.

    Args:
      width: how wide the thing between the jaws is said to be, in mm.
      grip_strength: how hard to hold, 0 the weakest and 9 the strongest.
      width_tolerance: how far off that width the thing may be, in mm. Something met inside that
        window is gripped; a close that runs past it reports finding nothing.

    Raises:
      ValueError: If any of them is outside what the command accepts.
    """
    c = self.configuration
    if not 0 <= grip_strength <= 9:
      raise ValueError(f"grip_strength must be between 0 and 9, is {grip_strength}")
    # The master's own floor: below it the closing ramp would run past the drive's minimum.
    high = c.gripper_increments_to_mm(c.gripper_range_increments[1])
    if not 76.0 < width <= high:
      raise ValueError(f"width must be between 76.0 and {high} mm, is {width}")
    if not 0.5 <= width_tolerance <= 9.9:
      raise ValueError(f"width_tolerance must be between 0.5 and 9.9 mm, is {width_tolerance}")
    # TODO: compute what is actually between the fingers before closing, and refuse a width that
    # does not describe it. Doing that needs a `Resource.contains(point)` that respects rotation
    # - the arm turns, and a corner plus a bounding-box extent is not a rotated box - and a deck
    # query that answers it without sweeping every well and tip. Neither exists yet, and the
    # version removed here was wrong on rotated resources, silently skipped unless the fingers
    # lay within a few degrees of a deck axis, and cost 72 ms per grip on a loaded deck.

    try:
      resp = await self._unchecked_fw_gripper_close_with_force_sensed_width_window_increments(
        grip_strength=grip_strength,
        width_increments=round(width * 10),
        width_tolerance_increments=round(width_tolerance * 10),
      )
      return resp
    finally:
      # Where the jaws stopped is the only word on it: a close has no target / is a probing action,
      # so nothing here knows the width until the drive is read.
      await self._record_where_it_stopped("gripper")

  async def _unchecked_fw_gripper_close_to_object_increments(
    self,
    destination_increments: int,
    stop_band_increments: int,
    stop_trigger: int = 200,
    speed_increments: int = 5_000,
    current_limit: int = 15,
    low_pass_filter: bool = True,
  ):
    """Close the jaws toward a width, stopping on whatever they meet, without checking or
    recording.

    The drive's own version of the master's close, with the two things the master hides under a
    dial: the band around the destination in which meeting something counts, and the force at
    which meeting is declared. Unchecked here means unchecked by this driver - the arm still feels,
    and still answers an error when it reaches the end of the band having met nothing.

    It has a destination, which is what makes it safe to point at an unknown object: it stops
    there whatever happens, rather than closing until something stops it.

    Args:
      destination_increments: where the jaws are expected to meet the object, in the drive's steps.
      stop_band_increments: how far either side of that still counts, in the drive's steps.
      stop_trigger: how hard a push counts as meeting something, in the sensor's own counts.
      speed_increments: max gripping velocity, in increments/s.
      current_limit: the motor current limit, 0 to 15.
      low_pass_filter: whether to filter the current signal the trigger is read from.
    """
    return await self._driver.send_command(
      module="R0",
      command="GB",
      gb=f"{destination_increments:05}",
      gu=f"{speed_increments:04}",
      gd=f"{stop_band_increments:04}",
      gw=f"{current_limit:02}",
      gi=f"{stop_trigger:03}",
      fi=f"{int(low_pass_filter)}",
    )

  async def gripper_probe_for_object(
    self,
    expected_width: float,
    band: float = 9.9,
    stop_trigger: int = 200,
    current_limit: int = 15,
  ) -> Optional[float]:
    """Close the jaws toward a width and report what they met on the way. This moves them.

    What the master's close cannot do, because its band is fixed at a couple of millimetres: this
    one opens the window as wide as the drive allows, so something several millimetres off the
    width expected is still found rather than reported missing.

    It stops at the width given whether or not it meets anything, which is what keeps it away from
    the drive's own stop - a close with no destination runs the jaws into it and latches the drive.

    The jaws are left where they stopped. What was found is being held, and letting go is the
    caller's decision.

    Args:
      expected_width: roughly how wide the thing between the jaws is, in mm.
      band: how far either side of that to accept, in mm.
      stop_trigger: how hard a push counts as meeting something, in the sensor's own counts.
      current_limit: the motor current limit, 0 to 15.

    Returns:
      How far apart the jaws stopped, in mm, or None when they reached the width given without
      meeting anything within the band.

      A width is where the fingers stopped pushing, not how wide what they met is: this stops on a
      lighter push than a grip does and so stops nearer the object, but it still stops inside it.
      A plate 85.5 mm across was found at 82.1 mm by this and held at 80.3 mm by a grip.

      None is not a promise that the jaws are empty: something far enough outside the band is met
      without being reported, and the arm has answered "plate not found" with its force sensor
      reading twenty times its idle value.

    Raises:
      ValueError: If any argument is outside what the drive accepts.
    """
    c = self.configuration
    low = c.gripper_increments_to_mm(c.gripper_range_increments[0])
    high = c.gripper_increments_to_mm(c.gripper_range_increments[1])
    if not low <= expected_width <= high:
      raise ValueError(f"expected_width must be between {low} and {high} mm, is {expected_width}")
    band_increments = c.gripper_mm_to_increments(band)
    band_low, band_high = c.gripper_stop_band_range_increments
    if not band_low <= band_increments <= band_high:
      raise ValueError(
        f"band must be between {c.gripper_increments_to_mm(band_low)} and "
        f"{c.gripper_increments_to_mm(band_high)} mm, is {band}"
      )
    if not 0 <= stop_trigger <= 999:
      raise ValueError(f"stop_trigger must be between 0 and 999, is {stop_trigger}")
    if not 0 <= current_limit <= 15:
      raise ValueError(f"current_limit must be between 0 and 15, is {current_limit}")

    destination = min(
      max(c.gripper_mm_to_increments(expected_width), c.gripper_range_increments[0]),
      c.gripper_range_increments[1],
    )
    found = True
    try:
      await self._unchecked_fw_gripper_close_to_object_increments(
        destination_increments=destination,
        stop_band_increments=band_increments,
        stop_trigger=stop_trigger,
        current_limit=current_limit,
      )
    except STARFirmwareError as error:
      # An error is one per module, so the arm's own part is what says it met nothing: the master
      # reports a failure alongside it, and the dict is keyed by display name rather than by id.
      met_nothing = any(
        part.raw_module == "R0" and isinstance(part, NoElementError)
        for part in error.errors.values()
      )
      if not met_nothing:
        raise
      found = False
    finally:
      # Where the jaws stopped is the answer, and it can only be read: a probe has no target.
      await self._record_where_it_stopped("gripper")

    return await self.gripper_request_width() if found else None

  async def initialize_gripper_drive(self, current_limit: int = 15):
    """Bring the gripper drive back to its own reference. This moves the jaws.

    The arm's own initialize brings every drive up and swings the whole arm to do it. This is the
    one drive, which is what a gripper that has lost its reference needs - and what it refuses
    while it is jammed, since it cannot travel to find its sensor edge. `_unchecked_fw_gripper_move_relative_increments`
    is what frees it first.

    Args:
      current_limit: the motor current limit, 0 to 15.

    Raises:
      ValueError: If the current limit is outside what the drive accepts.
    """
    if not 0 <= current_limit <= 15:
      raise ValueError(f"current_limit must be between 0 and 15, is {current_limit}")
    return await self._driver.send_command(module="R0", command="GI", gw=f"{current_limit:02}")

  async def _unchecked_fw_gripper_move_relative_increments(
    self,
    distance_increments: int,
    opening: bool,
    speed_increments: int = 2_000,
    acceleration_increments: int = 75,
    current_limit: int = 15,
  ):
    """Move the jaws a distance, unsupervised, without checking or recording.

    The one movement the drive accepts while it is uninitialized, and the only way out of a jam:
    everything else is refused until the drive has a reference, and the initialize cannot give it
    one while it cannot move. Unsupervised means the drive reports nothing about whether it
    arrived, so the counters have to be read after each attempt - and a nudge that changes nothing
    is a drive still stuck rather than one that had nowhere to go.

    Args:
      distance_increments: how far to travel, in the drive's own steps.
      opening: whether to travel the way that opens the jaws.
      speed_increments: max velocity, in increments/s. Slower than a normal move by default,
        since this is used against something that is stuck.
      acceleration_increments: in thousands of increments/s2.
      current_limit: the motor current limit, 0 to 15.
    """
    return await self._driver.send_command(
      module="R0",
      command="GS",
      gs=f"{distance_increments:04}",
      gt=f"{0 if opening else 1}",
      gv=f"{speed_increments:04}",
      gr=f"{acceleration_increments:03}",
      gw=f"{current_limit:02}",
    )

  async def _switch_gripper_drive_off(self):
    """Cut the current to the gripper drive, so the jaws can be moved by hand.

    What the arm does to itself on any gripper error, and what a jam is freed by when the drive
    cannot free itself. Whatever is held is released, and the drive keeps no reference through it -
    `initialize_gripper_drive` is what gives it one back.
    """
    return await self._driver.send_command(module="R0", command="GO")

  async def recover_gripper_drive(
    self,
    attempts: int = 4,
    nudge_increments: int = 200,
    current_limit: int = 15,
  ) -> bool:
    """Get a stuck gripper drive moving again, and back onto its own reference. This moves it.

    A drive that has run into something it cannot pass stops reporting where it is: its two
    counters part, every ordinary move answers that it is locked, and the initialize that would
    fix the reference cannot run, because it has to travel to find its sensor edge and it cannot
    travel. That is a state the arm cannot leave on its own.

    So this works outwards. It reads the counters, tries the initialize, and when that is refused
    it nudges the jaws open by the one movement an uninitialized drive accepts, checking after each
    nudge whether anything actually moved - unsupervised means the drive answers whether the
    command was taken, not whether it went anywhere. A nudge that moves nothing is met by cutting
    the drive's current and letting it go slack before trying again, which is what frees a drive
    holding itself against its own stop.

    Args:
      attempts: how many times to nudge and retry the initialize.
      nudge_increments: how far to open the jaws on each nudge, in the drive's own steps.
      current_limit: the motor current limit, 0 to 15.

    Returns:
      True when the drive initialized, False when it is still stuck and needs freeing by hand.

    Raises:
      ValueError: If any argument is outside what the drive accepts.
    """
    if attempts < 1:
      raise ValueError(f"attempts must be at least 1, is {attempts}")
    if not 0 < nudge_increments <= 9_999:
      raise ValueError(f"nudge_increments must be between 1 and 9999, is {nudge_increments}")
    if not 0 <= current_limit <= 15:
      raise ValueError(f"current_limit must be between 0 and 15, is {current_limit}")

    for attempt in range(attempts):
      firmware, hardware = await self.gripper_request_counters()
      try:
        await self.initialize_gripper_drive(current_limit=current_limit)
      except STARFirmwareError:
        logger.info(
          "the gripper drive will not initialize (counters %d and %d); freeing it, attempt %d of %d",
          firmware,
          hardware,
          attempt + 1,
          attempts,
        )
      else:
        _, hardware = await self.gripper_request_counters()
        logger.info("the gripper drive is back on its reference, reading %d", hardware)
        return True

      before = hardware
      try:
        await self._unchecked_fw_gripper_move_relative_increments(
          distance_increments=nudge_increments, opening=True, current_limit=current_limit
        )
      except STARFirmwareError:
        # Even unsupervised, a drive that cannot turn at all says so. That is not a reason to
        # stop: what comes next is cutting its current, which is the thing that frees it.
        logger.debug("the nudge was refused as well")
      _, after = await self.gripper_request_counters()

      if after == before:
        # It did not move, so it is holding itself somewhere. Letting go is the only thing left
        # to try, and the drive keeps no reference through it - which the initialize above will
        # give back on the next turn of this loop.
        logger.info("the nudge moved nothing, so the drive is being switched off to let it go")
        await self._switch_gripper_drive_off()

    firmware, hardware = await self.gripper_request_counters()
    logger.warning(
      "the gripper drive is still stuck after %d attempts, reading %d and %d. Its jaws have to be "
      "freed by hand, and `initialize_gripper_drive` run afterwards",
      attempts,
      firmware,
      hardware,
    )
    return False

  # -- pose ------------------------------------------------------------------

  async def request_joint_state(self) -> JointState:
    """Read every axis, one after another, as the joint state the kinematics run on.

    Each read records what it answered, so this is also what brings the whole model back in step
    with the arm - which is what a move touching more than one drive reads in its `finally`.

    Returns:
      Each axis's position, in that axis's own units.
    """
    return {
      iSWAPAxis.X: await self.rotation_drive_request_x_position(),
      iSWAPAxis.Y: await self.rotation_drive_request_y_position(),
      iSWAPAxis.Z: await self.rotation_drive_request_z_position(),
      iSWAPAxis.ROTATION: await self.rotation_drive_request_angle(),
      iSWAPAxis.WRIST: await self.wrist_drive_request_angle(),
      iSWAPAxis.GRIPPER: await self.gripper_request_width(),
    }

  @staticmethod
  def _forward_kinematics(
    joints: JointState,
    link_1_length: float,
    tool_center_point_distance: float,
    wrist_straight_angle: float,
    rotation_drive_z_offset_above_finger: float,
  ) -> iSWAPPose:
    """Where a joint state puts the gripper. Pure arithmetic: nothing is read.

    One link off the rotation drive, and whatever is bolted to its far end. Link 1 leaves the drive
    at the rotation angle; the tool leaves the wrist at that plus however far the wrist is turned
    from straight. Angles are signed
    counter-clockwise seen from above, and a yaw of 0 points along +x, deck-right.

    Args:
      joints: the joint state, as `request_joint_state` returns it.
      link_1_length: rotation joint to wrist joint, in mm - the arm's own.
      tool_center_point_distance: wrist joint to the point the end-effector is programmed against,
        in mm - the tool's own, which the gripper reports as its `tool_center_point`.
      wrist_straight_angle: what the wrist reports when it is straight, in degrees.1
      rotation_drive_z_offset_above_finger: how far the drive's bottom sits above the fingers.

    Returns:
      Every joint of the arm, and the deck angle the gripper faces along.
    """
    link_1_deck_angle = joints[iSWAPAxis.ROTATION] - 90.0
    link_2_deck_angle = link_1_deck_angle + (joints[iSWAPAxis.WRIST] - wrist_straight_angle)

    alpha_1 = math.radians(link_1_deck_angle)
    alpha_2 = math.radians(link_2_deck_angle)

    # Both joints sit at the drive's own height; the fingers hang below its bottom.
    base = Coordinate(x=joints[iSWAPAxis.X], y=joints[iSWAPAxis.Y], z=joints[iSWAPAxis.Z])
    wrist = Coordinate(
      x=base.x + link_1_length * math.cos(alpha_1),
      y=base.y + link_1_length * math.sin(alpha_1),
      z=base.z,
    )
    return iSWAPPose(
      rotation_joint_location=base,
      wrist_joint_location=wrist,
      gripper_center_location=Coordinate(
        x=wrist.x + tool_center_point_distance * math.cos(alpha_2),
        y=wrist.y + tool_center_point_distance * math.sin(alpha_2),
        z=base.z - rotation_drive_z_offset_above_finger,
      ),
      gripper_deck_orientation=Rotation(z=link_2_deck_angle),
      joints=joints,
    )

  async def request_pose(self) -> iSWAPPose:
    """Where the gripper is, worked out from the joint state.

    Read and computed rather than asked for: the master answers a gripper position of its own, but
    only correctly after certain commands have run. This reads each drive and runs the kinematics,
    so it holds whenever it is called.

    Returns:
      Every joint of the arm and where its tool ends up, in one answer: what a caller needs to say
      whether the arm clears something is where its middle joint is as much as where its end is.

    Raises:
      RuntimeError: If the arm's link length or the wrist's stops were not read, or the gripper is
        not modelled.
    """
    c = self.configuration
    gripper = self.link_2
    if c.link_1_length is None:
      raise RuntimeError("the arm's link length was not read; have you called `star.setup()`?")
    if not isinstance(gripper, MechanicalGripper):
      raise RuntimeError("the gripper is not modelled, so how far it reaches is unknown")
    if c.wrist_drive_predefined_increments is None:
      raise RuntimeError("the wrist drive's stops were not read; have you called `star.setup()`?")

    return self._forward_kinematics(
      joints=await self.request_joint_state(),
      link_1_length=c.link_1_length,
      tool_center_point_distance=gripper.tool_center_point.x,
      wrist_straight_angle=c.wrist_increments_to_deg(
        c.wrist_drive_predefined_increments["straight"]
      ),
      rotation_drive_z_offset_above_finger=c.rotation_drive_z_offset_above_finger,
    )

  # -- parking ---------------------------------------------------------------

  async def _unchecked_fw_park(self):
    """Close the gripper and park the arm. Nothing is guarded and nothing is recorded.

    No traversal height is sent, so the master travels at its own.
    """
    return await self._driver.send_command(module="C0", command="PG", subsystem="R0")

  async def park(self):
    """Close the gripper and park the arm. This moves it.

    It travels at the master's own traversal height, which is where the arm is safe.

    Every axis moves, so every axis is read back afterwards, whether or not the park answered.
    """
    try:
      return await self._unchecked_fw_park()
    finally:
      # Parking drives every axis, so every axis is read back: each read records what it answered,
      # and one command answering does not say where the others stopped. Its own failure is logged
      # and swallowed, so it cannot replace the exception that says what went wrong.
      try:
        await self.request_joint_state()
      except Exception:
        logger.warning("could not read where the iSWAP parked; its model is stale")
