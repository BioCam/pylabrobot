"""The iSWAP: the arm that picks plates up and puts them down."""

import dataclasses
import enum
import logging
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, Union, cast

from pylabrobot.hamilton.star.driver.errors import STARFirmwareError
from pylabrobot.hamilton.star.resource_model import iSWAPChannel
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper
from pylabrobot.resources.manipulator import Link
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
  "parking",
  "extra_1",
  "extra_2",
  "extra_3",
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

# And for the rotation drive's Z, whose table is all position too: ten stops, no arm length.
Z_SLOTS = (
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


def _nothing_was_gripped(error: STARFirmwareError) -> bool:
  """Whether a firmware error is the arm saying it closed and met nothing.

  Args:
    error: what a command raised.

  Returns:
    True when the arm reported that it found nothing between its fingers.
  """
  return any(
    part.raw_module == "R0" and part.trace_information == NOTHING_GRIPPED
    for part in error.errors.values()
  )


# What the arm answers when it closed on nothing: the error its own table calls "plate not found",
# raised off the force sensor rather than off a position.
NOTHING_GRIPPED = 94

# How wide a window the drive will accept around the width a close is aimed at, in its own steps.
GRIPPER_STOP_BAND_RANGE = (80, 1_800)

# How far the gripper drive's two counters may sit apart before the gap is a drive that has lost
# steps rather than the ordinary lag between commanding a move and finishing it, in increments.
GRIPPER_COUNTER_DRIFT = 50

# Which way the gripper drive counts when it closes: its increments fall as the jaws come
# together, so a probe that closes travels the drive's negative direction.
GRIPPER_CLOSING_DIRECTION = 1

# How close to their own shut position the jaws may stop and still be said to have found nothing,
# in mm. A probe that runs the whole way has met nothing rather than met something that narrow.
PROBE_FOUND_NOTHING_MARGIN = 0.5

# The narrowest the master's own close will be sent, in mm. It closes onto a plate, so it will not
# be aimed below one - which makes shutting the jaws entirely a move rather than a grip.
MASTER_CLOSE_FLOOR = 76.0

# And for the gripper drive, whose table is all jaw width: ten slots, no arm length. One slot
# stands for both home and parking, seven are the widths a plate type is gripped at, and the
# second has no documented meaning - its default is the top of the drive's range.
GRIPPER_DRIVE_SLOTS = (
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

# What the arm the device facts below were recorded from reports for its firmware version. An arm
# reporting something else is a generation those values were not taken from.
RECORDED_FIRMWARE_PREFIX = "4."

# Where the arm is left when parked, in mm: it travels at this height on the way there.
PARK_TRAVERSAL_HEIGHT = 280.0


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
  """Where every joint of the arm is, and which way each link lies.

  One answer for the whole arm rather than for its end. The two links are what put the gripper
  where it is, so a caller asking whether the arm clears something needs the joint between them as
  much as the point at the end of it: a wrist folded back swings link 2 the opposite way to the
  turn, and only the middle joint shows that.

  Every coordinate and rotation here is in the STAR's deck frame, as `CartesianPose` states it.
  """

  rotation_joint: Coordinate
  """Where the rotation drive is: the joint link 1 turns about."""
  wrist_joint: Coordinate
  """Link 1's far end, which is the joint link 2 turns about."""
  gripper: CartesianPose
  """Link 2's far end, between the fingers, and the yaw link 2 lies along."""
  link_1_rotation: Rotation
  """Which way link 1 lies, from the rotation joint to the wrist joint. Link 2's is the
  gripper's."""
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

  # -- X --
  rotation_drive_x_offset: Optional[float] = None
  """Deck X distance from the X-arm carriage reference point to the rotation drive (mm). Stored in
  master EEPROM. The Hamilton factory default is 34.0 mm."""

  # -- Y --
  rotation_drive_predefined_y_positions_increments: Optional[Dict[str, int]] = None
  """Each Y stop the carriage is calibrated against, in increments, keyed as `Y_SLOTS` names them.

  The whole stored table rather than the one stop the driver bounds moves by, so what this holds is
  what the drive reports: a recording of it answers every Y read, not just the parking one."""

  rotation_drive_predefined_z_positions_increments: Optional[Dict[str, int]] = None
  """Each Z stop the rotation drive is calibrated against, in increments of the finger plane,
  keyed as `Z_SLOTS` names them.

  Read by discovery, and again by `rotation_drive_request_predefined_z_positions`, which returns
  the stops in mm. No arm has been read for it yet, so what a recording carries are the documented
  factory values rather than one unit's calibration."""

  # -- rotation drive --
  rotation_drive_predefined_increments: Optional[Dict[str, int]] = None
  link_1_length: Optional[float] = None
  """rotation joint (joint 1) to the wrist joint (joint 2); default: 138.0 mm."""

  # -- gripper drive --
  gripper_drive_predefined_increments: Optional[Dict[str, int]] = None
  """Each jaw width the gripper is calibrated against, in increments, keyed as
  `GRIPPER_DRIVE_SLOTS` names them.

  Read by discovery, and again by `request_gripper_drive_widths`, which returns the widths in mm.
  No arm has been read for it yet, so what a recording carries are the documented factory values
  rather than one unit's calibration."""

  # -- wrist drive --
  wrist_drive_predefined_increments: Optional[Dict[str, int]] = None
  link_2_length: Optional[float] = None
  """wrist joint (joint 2) to the gripper finger centre, in mm. default: 138.0 mm."""

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
  is not something the device reports."""

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
  gripper_speed_increment_range: Tuple[int, int] = (20, 9_999)  # increments/sec
  gripper_acceleration_increment_range: Tuple[int, int] = (5, 150)  # 1000 increments/sec^2

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
    to `right` spans 0 to +90, each against the stops this device reports. So the stops read back
    as exactly -90, 0 and +90 however far the device's own calibration has drifted, and a
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

  def rotation_drive_angle_to_increments(self, angle: float) -> int:
    """A rotation-drive angle in increments, from degrees against the calibrated stops.

    The inverse of `rotation_drive_increments_to_angle`, piecewise on the same two segments, so
    -90, 0 and +90 land exactly on the stops this device reports and an angle beyond them
    extrapolates on its segment's slope.

    Args:
      angle: degrees, signed from the calibrated front stop.

    Returns:
      What to send the drive.

    Raises:
      RuntimeError: If the stored stops were not read.
    """
    stops = self.rotation_drive_predefined_increments
    if stops is None:
      raise RuntimeError(
        "the rotation drive's stops were not read; have you called `star.setup()`?"
      )
    front = stops["front"]
    if angle < 0:
      return round(front - (angle / -90.0) * (front - stops["left"]))
    return round(front + (angle / 90.0) * (stops["right"] - front))

  def wrist_increments_to_deg(self, increments: int) -> float:
    """A wrist-drive angle in degrees, from increments."""
    return increments * self.wrist_deg_per_increment

  def wrist_deg_to_increments(self, deg: float) -> int:
    """A wrist-drive angle in increments, from degrees."""
    return round(deg / self.wrist_deg_per_increment)

  def gripper_increments_to_mm(self, increments: int) -> float:
    """A gripper jaw width in mm, from increments. One decimal, as the device resolves it."""
    return round(increments * self.gripper_mm_per_increment, 1)

  def gripper_mm_to_increments(self, mm: float) -> int:
    """A gripper jaw width in increments, from mm."""
    return round(mm / self.gripper_mm_per_increment)


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

  # -- session / discovery ---------------------------------------------------

  async def request_firmware_version(self) -> str:
    """Request the iSWAP's firmware version.

    Returns:
      The version string, as reported.
    """
    resp: str = await self._driver.send_command(module="R0", command="RF")
    return resp.split("rf")[-1]

  async def request_rotation_drive_x_offset(self) -> float:
    """Request the X distance from the X-arm carriage centre to the rotation drive.

    Stored in the master's own memory, as the 96-head's offset is.

    Returns:
      The offset in mm.
    """
    resp = await self._driver.send_command(module="C0", command="RA", ra="kg", fmt="kg###")
    return cast(int, resp["kg"]) / 10.0

  async def request_rotation_drive_positions(self) -> Dict[str, int]:
    """Request the rotation drive's stored position table.

    The device returns ten signed slots; the nine position slots are returned here, and the tenth
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
      Each stop in mm, keyed as `Z_SLOTS` names them.
    """
    c = self.configuration
    slots = await self._request_slots("pz")
    c.rotation_drive_predefined_z_positions_increments = dict(zip(Z_SLOTS, slots))
    return {
      name: round(c.z_increments_to_mm(increments) + c.rotation_drive_z_offset_above_finger, 1)
      for name, increments in zip(Z_SLOTS, slots)
    }

  async def request_gripper_drive_widths(self) -> Dict[str, float]:
    """Read the jaw widths the gripper drive is calibrated against, in mm.

    The stored table rather than how far the jaws stand now, which `request_gripper_width` reads.
    Its ten slots are all widths: the one the jaws home and park at, one with no documented
    meaning, the width the drive treats as closed, and seven a plate type is gripped at.

    Records what came back on the configuration, as the other stored tables are recorded, so an
    arm read for it once carries the table from then on.

    Returns:
      Each width in mm, keyed as `GRIPPER_DRIVE_SLOTS` names them.
    """
    c = self.configuration
    slots = await self._request_slots("pg")
    c.gripper_drive_predefined_increments = dict(zip(GRIPPER_DRIVE_SLOTS, slots))
    return {
      name: c.gripper_increments_to_mm(increments)
      for name, increments in zip(GRIPPER_DRIVE_SLOTS, slots)
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

    # The Z stops and the gripper widths are read here too, so a configuration saved after setup
    # carries every stored table. Left out, they save as nothing, and a simulated arm built from
    # that file cannot answer where its Z drive or its jaws are.
    c.rotation_drive_predefined_z_positions_increments = dict(
      zip(Z_SLOTS, await self._request_slots("pz"))
    )
    c.gripper_drive_predefined_increments = dict(
      zip(GRIPPER_DRIVE_SLOTS, await self._request_slots("pg"))
    )

  # -- initialization --------------------------------------------------------

  async def initialize(self):
    """Initialize the iSWAP. This moves it."""
    return await self._driver.send_command(module="C0", command="FI", subsystem="R0")

  # -- where it is -----------------------------------------------------------

  def update_rotation(self, angle: float) -> None:
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

  def modelled_reference_point(self) -> Optional[Coordinate]:
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

  def modelled_wrist(self) -> Optional[float]:
    """Which way the model has the wrist turned, as its drive reports it.

    Read from what the drive last reported, as `modelled_rotation` is: link 2's own rotation is an
    angle from link 1 about a different axis, so recovering a drive angle from it would be
    inverting a rendering rather than reading a fact.

    Returns:
      The angle in degrees, or None while nothing has read it yet.
    """
    if self.resource is None or self._driver.deck is None:
      return None
    return self.resource.wrist_drive_angle

  def modelled_rotation(self) -> Optional[float]:
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

  def update_wrist(self, angle: float) -> None:
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

  def update_jaw_width(self, width: float) -> None:
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
        await self.request_gripper_width()
    except Exception:
      logger.warning("could not read where the iSWAP stopped along %s; its model is stale", axis)

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
      RuntimeError: If the device's configuration or the drive's Y limit was not read.
    """
    c = self.configuration
    device = self._driver.configuration
    if device is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    self._check_reachable("y", y)

    await self._make_space_for_y(y, make_space=make_space)

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
      # What was asked for, recorded as soon as the move answers, so the model holds it even if
      # the read below cannot be taken.
      self.update_location_by_reference_point(y=y)
      return resp
    finally:
      # And then what the drive says, which is the last word either way. A move that stopped part
      # way left the carriage somewhere no target describes, and a move that answered has still
      # only answered.
      await self._record_where_it_stopped("y")

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
    # Nothing may move in Y while a channel is low.
    await pipettes.move_to_safe_z()
    await pipettes.move_to_y_positions({0: target_y}, make_space=True)

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
    pose = self._pose_at(rotation_angle, wrist_angle)
    if pipettes is None or device is None or pose is None:
      return

    widths = [channel.width for channel in pipettes.configuration.channels]
    if any(width is None for width in widths):
      return

    # The frontmost point the arm would put anywhere, and where that leaves the backmost channel:
    # it has to stand in front of the arm by its own half width.
    reaches_to = min(pose.wrist_joint.y, pose.gripper.location.y)
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
      # What was asked for, recorded as soon as the move answers, so the model holds it even if
      # the read below cannot be taken.
      self.update_location_by_reference_point(z=z)
      return resp
    finally:
      # And then what the drive says, which is the last word either way.
      await self._record_where_it_stopped("z")

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

  # ----------------------------------------
  # Rotational Movement
  # ----------------------------------------

  # -- rotation, wrist and gripper --------------------------------------------

  async def _unchecked_fw_rotation_drive_rotate_increments(
    self,
    rotation_increments: int,
    wrist_increments: int,
    rotation_speed: int = 25_000,
    wrist_speed: int = 20_000,
    rotation_acceleration: int = 170,
    wrist_acceleration: int = 145,
    rotation_current_limit: int = 5,
    wrist_current_limit: int = 5,
  ):
    """Drive both joints to absolute increments. Nothing is guarded and nothing is recorded.

    The lowest command there is here: it takes what the drives count in and sends it. Both joints
    go in one command because they move together - the wrist rides the rotation drive, so sending
    them separately turns the arm and then corrects the wrist, sweeping a path neither target
    describes. A caller that means to move one holds the other at where it already is.

    Args:
      rotation_increments: where the rotation drive is to go, signed.
      wrist_increments: where the wrist drive is to go, signed.
      rotation_speed: max velocity of the rotation drive, in increments/s.
      wrist_speed: max velocity of the wrist drive, in increments/s.
      rotation_acceleration: for the rotation drive, in thousands of increments/s2.
      wrist_acceleration: for the wrist drive, in thousands of increments/s2.
      rotation_current_limit: the rotation motor's current limit.
      wrist_current_limit: the wrist motor's current limit.
    """
    return await self._driver.send_command(
      module="R0",
      command="PA",
      wa=f"{rotation_increments:+06}",
      wv=f"{rotation_speed:05}",
      wr=f"{rotation_acceleration:03}",
      ww=f"{rotation_current_limit}",
      ta=f"{wrist_increments:+06}",
      tv=f"{wrist_speed:05}",
      tr=f"{wrist_acceleration:03}",
      tw=f"{wrist_current_limit}",
    )

  async def request_rotation_drive_angle(self) -> float:
    """Read the rotation drive's angle, signed from the calibrated front stop.

    Returns:
      The angle in degrees.
    """
    resp = await self._driver.send_command(module="R0", command="RW", fmt="rw######")
    angle = self.configuration.rotation_drive_increments_to_angle(cast(int, resp["rw"]))
    self.update_rotation(angle)
    return angle

  async def request_wrist_drive_angle(self) -> float:
    """Read the wrist drive's angle, signed from the motor's own zero.

    That zero sits between the straight and left stops, which keeps the reachable range symmetric
    about it rather than anchoring it on a stop.

    Returns:
      The angle in degrees.
    """
    resp = await self._driver.send_command(module="R0", command="RT", fmt="rt######")
    angle = self.configuration.wrist_increments_to_deg(cast(int, resp["rt"]))
    self.update_wrist(angle)
    return angle

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

  async def request_gripper_counters(self) -> Tuple[int, int]:
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
    if abs(firmware - hardware) > GRIPPER_COUNTER_DRIFT:
      logger.warning(
        "the gripper drive's counters are %d increments apart (firmware %d, hardware %d), which is "
        "a drive that has lost steps rather than one that has moved",
        abs(firmware - hardware),
        firmware,
        hardware,
      )
    return firmware, hardware

  async def request_gripper_force(self) -> Dict[str, int]:
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

  async def request_gripper_width(self) -> float:
    """Read how far the gripper jaws are open.

    Returns:
      The jaw width in mm.
    """
    resp = await self._driver.send_command(module="R0", command="RG", fmt="rg##### (n)")
    # A target and an actual come back, in that order. The actual is read.
    width = self.configuration.gripper_increments_to_mm(cast(List[int], resp["rg"])[1])
    self.update_jaw_width(width)
    return width

  async def _unchecked_fw_gripper_move_to_jaw_position(
    self,
    increments: int,
    speed_increments: int = 9_002,
    acceleration_increments: int = 75,
    current_limit: int = 15,
  ):
    """Drive the jaws to an absolute width. Nothing is guarded and nothing is recorded.

    The lowest command there is here: it takes what the drive counts in and sends it. It feels
    nothing on the way - the drive pushes to where it is told with whatever the current limit
    allows, and says so only once it has locked. What checks, chooses and records is
    `gripper_move_to_jaw_position`; the drive's own knobs are here for a caller that needs them.

    Args:
      increments: where the jaws are to go, in the drive's own steps.
      speed_increments: max velocity, in increments/s.
      acceleration_increments: in thousands of increments/s2.
      current_limit: the motor current limit, 0 to 15.
    """
    return await self._driver.send_command(
      module="R0",
      command="GA",
      ga=f"{increments:05}",
      gv=f"{speed_increments:04}",
      gr=f"{acceleration_increments:03}",
      gw=f"{current_limit:02}",
    )

  async def gripper_move_to_jaw_position(self, width: float, grip_strength: int = 5):
    """Put the jaws at a width. This moves them.

    The one place the jaws are driven, and it picks its command from the way they are about to
    travel. The width they stand at now is read first - read rather than modelled, because being
    behind here means closing blind. Opening cannot close on anything, so it is driven. Closing is
    felt for instead, through the master's own close, which stops on whatever is between the jaws:
    the difference between putting them somewhere and crushing what is already there.

    Shutting them entirely is the one close that cannot be felt, since the master will not aim its
    close below a plate's width. There is nothing to feel for by then.

    A close that reports finding nothing raises, rather than falling back to driving the jaws
    there. The arm says "plate not found" when it met nothing *inside the window it was given* -
    which it also says when it met something well outside it, and the force sensor proves it did.
    Treating that as an empty gap and driving through it is how a plate gets crushed.

    Only what applies whichever way the jaws go is taken here. The drive's speed, acceleration and
    current limit belong to `_unchecked_fw_gripper_move_to_jaw_position`, and the tolerance a grip
    allows to `gripper_close_with_force_sensing`.

    Args:
      width: how far apart to stand the jaws, in mm.
      grip_strength: how hard to hold what it closes on, 0 the weakest and 9 the strongest.

    Raises:
      ValueError: If the width is outside what the drive travels.
    """
    c = self.configuration
    # Compared in mm rather than in increments: a width read off the drive and sent straight back
    # loses a fraction of an increment on the way, and the ends of the travel are exactly the
    # widths a caller asks for when it wants the jaws shut or wide open.
    low = c.gripper_increments_to_mm(c.gripper_increment_range[0])
    high = c.gripper_increments_to_mm(c.gripper_increment_range[1])
    if not low <= width <= high:
      raise ValueError(f"width must be between {low} and {high} mm, is {width}")
    increments = min(
      max(c.gripper_mm_to_increments(width), c.gripper_increment_range[0]),
      c.gripper_increment_range[1],
    )

    closing = width < await self.request_gripper_width()
    try:
      if closing and width > MASTER_CLOSE_FLOOR:
        # Whatever comes back, comes back. A close that reports finding nothing is not a promise
        # that nothing is there: an arm asked for 86 mm with a plate held the long way across its
        # fingers answered "plate not found" while its force sensor read twenty times its idle
        # value. Driving to the width after that answer would have taken the jaws from 133.7 mm
        # through a plate 127.8 mm wide.
        return await self.gripper_close_with_force_sensing(grip_strength=grip_strength, width=width)
      resp = await self._unchecked_fw_gripper_move_to_jaw_position(increments=increments)
      # What was asked for, recorded as soon as the move answers, so the model holds it even if
      # the read below cannot be taken.
      self.update_jaw_width(width)
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
      c.gripper_increments_to_mm(c.gripper_increment_range[1])
    )

  async def gripper_close(self):
    """Close the jaws all the way. This moves them.

    Shut, which is below the width the master's own close will be aimed at, so it is a plain move
    too. Closing onto something and holding it is what `gripper_move_to_jaw_position` does at any
    width above that floor.
    """
    c = self.configuration
    return await self.gripper_move_to_jaw_position(
      c.gripper_increments_to_mm(c.gripper_increment_range[0])
    )

  async def _unchecked_fw_gripper_close_with_force_sensing(
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
    `gripper_close_with_force_sensing`.

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

  async def initialize_gripper_drive(self, current_limit: int = 15):
    """Bring the gripper drive back to its own reference. This moves the jaws.

    The arm's own initialize brings every drive up and swings the whole arm to do it. This is the
    one drive, which is what a gripper that has lost its reference needs - and what it refuses
    while it is jammed, since it cannot travel to find its sensor edge. `_unchecked_fw_gripper_move_relative`
    is what frees it first.

    Args:
      current_limit: the motor current limit, 0 to 15.

    Raises:
      ValueError: If the current limit is outside what the drive accepts.
    """
    if not 0 <= current_limit <= 15:
      raise ValueError(f"current_limit must be between 0 and 15, is {current_limit}")
    return await self._driver.send_command(module="R0", command="GI", gw=f"{current_limit:02}")

  async def _unchecked_fw_gripper_move_relative(
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
      gt=f"{0 if opening else GRIPPER_CLOSING_DIRECTION}",
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
      firmware, hardware = await self.request_gripper_counters()
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
        _, hardware = await self.request_gripper_counters()
        logger.info("the gripper drive is back on its reference, reading %d", hardware)
        return True

      before = hardware
      try:
        await self._unchecked_fw_gripper_move_relative(
          distance_increments=nudge_increments, opening=True, current_limit=current_limit
        )
      except STARFirmwareError:
        # Even unsupervised, a drive that cannot turn at all says so. That is not a reason to
        # stop: what comes next is cutting its current, which is the thing that frees it.
        logger.debug("the nudge was refused as well")
      _, after = await self.request_gripper_counters()

      if after == before:
        # It did not move, so it is holding itself somewhere. Letting go is the only thing left
        # to try, and the drive keeps no reference through it - which the initialize above will
        # give back on the next turn of this loop.
        logger.info("the nudge moved nothing, so the drive is being switched off to let it go")
        await self._switch_gripper_drive_off()

    firmware, hardware = await self.request_gripper_counters()
    logger.warning(
      "the gripper drive is still stuck after %d attempts, reading %d and %d. Its jaws have to be "
      "freed by hand, and `initialize_gripper_drive` run afterwards",
      attempts,
      firmware,
      hardware,
    )
    return False

  async def _unchecked_fw_gripper_close_to_object(
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
      meeting anything within the band. None is not a promise that the jaws are empty: something
      far enough outside the band is met without being reported, and the arm has answered "plate
      not found" with its force sensor reading twenty times its idle value.

    Raises:
      ValueError: If any argument is outside what the drive accepts.
    """
    c = self.configuration
    low = c.gripper_increments_to_mm(c.gripper_increment_range[0])
    high = c.gripper_increments_to_mm(c.gripper_increment_range[1])
    if not low <= expected_width <= high:
      raise ValueError(f"expected_width must be between {low} and {high} mm, is {expected_width}")
    band_increments = c.gripper_mm_to_increments(band)
    band_low, band_high = GRIPPER_STOP_BAND_RANGE
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
      max(c.gripper_mm_to_increments(expected_width), c.gripper_increment_range[0]),
      c.gripper_increment_range[1],
    )
    found = True
    try:
      await self._unchecked_fw_gripper_close_to_object(
        destination_increments=destination,
        stop_band_increments=band_increments,
        stop_trigger=stop_trigger,
        current_limit=current_limit,
      )
    except STARFirmwareError as error:
      if not _nothing_was_gripped(error):
        raise
      found = False
    finally:
      # Where the jaws stopped is the answer, and it can only be read: a probe has no target.
      await self._record_where_it_stopped("gripper")

    return await self.request_gripper_width() if found else None

  async def gripper_close_with_force_sensing(
    self,
    width: float,
    grip_strength: int = 5,
    width_tolerance: float = 2.0,
  ):
    """Close the jaws onto whatever is between them, and hold it. This moves them.

    Unlike `gripper_move_to_jaw_position`, which drives to a width and stops there whatever is or
    is not in the way, this stops on what it meets and holds it at the strength given. The jaws
    have to start clear of it - `gripper_open` is what puts them there.

    Args:
      grip_strength: how hard to hold, 0 the weakest and 9 the strongest.
      width: how wide the thing between the jaws is said to be, in mm.
      width_tolerance: how far off that width the thing may be and still count as the thing, in
        mm. The close searches a window that wide around the width, so something met inside it is
        gripped and a close that runs past it reports finding nothing.

    Raises:
      ValueError: If any of them is outside what the command accepts.
    """
    c = self.configuration
    if not 0 <= grip_strength <= 9:
      raise ValueError(f"grip_strength must be between 0 and 9, is {grip_strength}")
    # The master's own floor: below it the closing ramp would run past the drive's minimum.
    high = c.gripper_increments_to_mm(c.gripper_increment_range[1])
    if not 76.0 < width <= high:
      raise ValueError(f"width must be between 76.0 and {high} mm, is {width}")
    if not 0.5 <= width_tolerance <= 9.9:
      raise ValueError(f"width_tolerance must be between 0.5 and 9.9 mm, is {width_tolerance}")

    try:
      resp = await self._unchecked_fw_gripper_close_with_force_sensing(
        grip_strength=grip_strength,
        width_increments=round(width * 10),
        width_tolerance_increments=round(width_tolerance * 10),
      )
      # The width asked for, so the model holds something even if the read below cannot be taken.
      self.update_jaw_width(width)
      return resp
    finally:
      # And then where the jaws actually stopped, which is what they met rather than what was
      # asked - and on the failure path, where a close that found nothing left them.
      await self._record_where_it_stopped("gripper")

  def _resolve_rotation_increments(self, angle: Union[str, float]) -> int:
    """A rotation stop's name or an angle, as the increments the drive counts in.

    Args:
      angle: a stop in `ROTATION_DRIVE_SLOTS`, or degrees from the calibrated front stop.

    Returns:
      Where the drive is to go, in increments.

    Raises:
      ValueError: If the name is not a stop, or the angle is outside the drive's travel.
      RuntimeError: If the stored stops have not been read.
    """
    c = self.configuration
    if isinstance(angle, str):
      stops = c.rotation_drive_predefined_increments
      if stops is None:
        raise RuntimeError("the rotation drive's stops were not read; have you called `setup()`?")
      if angle not in stops:
        raise ValueError(f"{angle!r} is not one of the stops {tuple(stops)}")
      increments = stops[angle]
    else:
      increments = c.rotation_drive_angle_to_increments(angle)
    low, high = c.rotation_increment_range
    if not low <= increments <= high:
      raise ValueError(
        f"{angle} is {increments} increments, outside the {low} to {high} the drive travels"
      )
    return increments

  def _resolve_wrist_increments(self, angle: Union[str, float]) -> int:
    """A wrist stop's name or an angle, as the increments the drive counts in.

    Args:
      angle: a stop in `WRIST_DRIVE_SLOTS`, or degrees from the drive's own zero.

    Returns:
      Where the drive is to go, in increments.

    Raises:
      ValueError: If the name is not a stop, or the angle is outside the drive's travel.
      RuntimeError: If the stored stops have not been read.
    """
    c = self.configuration
    if isinstance(angle, str):
      stops = c.wrist_drive_predefined_increments
      if stops is None:
        raise RuntimeError("the wrist's stored stops were not read; have you called `setup()`?")
      if angle not in stops:
        raise ValueError(f"{angle!r} is not one of the stops {tuple(stops)}")
      increments = stops[angle]
    else:
      increments = c.wrist_deg_to_increments(angle)
    low, high = c.wrist_increment_range
    if not low <= increments <= high:
      raise ValueError(
        f"{angle} is {increments} increments, outside the {low} to {high} the wrist travels"
      )
    return increments

  async def rotate_to_angles(
    self,
    rotation_angle: Union[str, float],
    wrist_angle: Union[str, float],
    make_space: bool = False,
    rotation_speed: int = 25_000,
    wrist_speed: int = 20_000,
    rotation_acceleration: int = 170,
    wrist_acceleration: int = 145,
    rotation_current_limit: int = 5,
    wrist_current_limit: int = 5,
  ):
    """Turn both joints, each to its own angle. This moves the arm.

    The only place either joint is turned. They go in one command because they move together - the
    wrist rides the rotation drive, so turning them one after the other sweeps a path neither
    target describes, out through a pose nobody asked for. A caller that means to move one holds
    the other where it is, which is what `rotation_drive_rotate_to_angle` and
    `wrist_drive_rotate_to_angle` do.

    Where the joints end up is read back rather than taken from the target, whether the move
    succeeded or not: a move that stopped part way left the arm somewhere no target describes, and
    the model has to follow the arm rather than the intention.

    Collision risk: the whole arm sweeps, and the path is neither joint's alone.

    Args:
      rotation_angle: a stop in `ROTATION_DRIVE_SLOTS`, or degrees from the calibrated front stop.
      wrist_angle: a stop in `WRIST_DRIVE_SLOTS`, or degrees from the drive's own zero.
      make_space: whether the channels may be moved out of the way when the arm would end up
        reaching into them. Off by default, so a pose that does not fit raises and the caller
        decides. Making space raises the channels to Z safety first, since it moves them in Y.
      rotation_speed: max velocity of the rotation drive, in increments/s.
      wrist_speed: max velocity of the wrist drive, in increments/s.
      rotation_acceleration: for the rotation drive, in thousands of increments/s2.
      wrist_acceleration: for the wrist drive, in thousands of increments/s2.
      rotation_current_limit: the rotation motor's current limit, 0 to 7.
      wrist_current_limit: the wrist motor's current limit, 0 to 7.

    Raises:
      ValueError: If either angle lands outside its drive's travel, or an argument is out of range.
    """
    rotation = self._resolve_rotation_increments(rotation_angle)
    wrist = self._resolve_wrist_increments(wrist_angle)
    if not 20 <= rotation_speed <= 75_000:
      raise ValueError(
        f"rotation_speed must be between 20 and 75000 increments/s, is {rotation_speed}"
      )
    if not 20 <= wrist_speed <= 65_000:
      raise ValueError(f"wrist_speed must be between 20 and 65000 increments/s, is {wrist_speed}")
    for name, value in (
      ("rotation_acceleration", rotation_acceleration),
      ("wrist_acceleration", wrist_acceleration),
    ):
      if not 5 <= value <= 200:
        raise ValueError(f"{name} must be between 5 and 200 thousand increments/s2, is {value}")
    for name, value in (
      ("rotation_current_limit", rotation_current_limit),
      ("wrist_current_limit", wrist_current_limit),
    ):
      if not 0 <= value <= 7:
        raise ValueError(f"{name} must be between 0 and 7, is {value}")

    c = self.configuration
    rotation_target = c.rotation_drive_increments_to_angle(rotation)
    wrist_target = c.wrist_increments_to_deg(wrist)
    self._check_gripper_reachable(rotation_target, wrist_target)
    await self._make_space_for_pose(rotation_target, wrist_target, make_space)
    try:
      resp = await self._unchecked_fw_rotation_drive_rotate_increments(
        rotation_increments=rotation,
        wrist_increments=wrist,
        rotation_speed=rotation_speed,
        wrist_speed=wrist_speed,
        rotation_acceleration=rotation_acceleration,
        wrist_acceleration=wrist_acceleration,
        rotation_current_limit=rotation_current_limit,
        wrist_current_limit=wrist_current_limit,
      )
      # What was asked for, recorded before anything is read: a move that answered has arrived,
      # and the model says so even if the reads below cannot be taken.
      self.update_rotation(c.rotation_drive_increments_to_angle(rotation))
      self.update_wrist(c.wrist_increments_to_deg(wrist))
      return resp
    finally:
      # And then what the drives say, which is the last word either way. A move that stopped part
      # way left the arm somewhere no target describes, and this is the only thing that finds it.
      await self._record_where_the_joints_stopped()

  def _pose_at(self, rotation_angle: float, wrist_angle: float) -> Optional[iSWAPPose]:
    """Where the arm would be with its joints at these angles. Nothing is read or moved.

    Worked from where the model has the drive, so it costs no commands, and it is what both of the
    checks below a move ask. None when the arm is not modelled or the numbers the kinematics need
    have not been read.

    Args:
      rotation_angle: the rotation drive's angle, in degrees.
      wrist_angle: the wrist drive's angle, in degrees.

    Returns:
      The pose, or None when it cannot be worked out.
    """
    c = self.configuration
    stops = c.wrist_drive_predefined_increments
    drive = self.modelled_reference_point()
    if stops is None or drive is None or c.link_1_length is None or c.link_2_length is None:
      return None
    return self._forward_kinematics(
      joints={
        iSWAPAxis.X: drive.x,
        iSWAPAxis.Y: drive.y,
        iSWAPAxis.Z: drive.z,
        iSWAPAxis.ROTATION: rotation_angle,
        iSWAPAxis.WRIST: wrist_angle,
      },
      link_1_length=c.link_1_length,
      link_2_length=c.link_2_length,
      wrist_straight_angle=c.wrist_increments_to_deg(stops["straight"]),
      rotation_drive_z_offset_above_finger=c.rotation_drive_z_offset_above_finger,
    )

  def _check_gripper_reachable(self, rotation_angle: float, wrist_angle: float) -> None:
    """Raise if the arm cannot put its gripper where these angles would.

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
    pose = self._pose_at(rotation_angle, wrist_angle)
    if y_max is None or pose is None:
      return
    # Both moving joints, not only the far one: link 1 is long enough to put the wrist behind the
    # rail while the grip centre is still clear of it.
    for what, point in (
      ("wrist joint", pose.wrist_joint),
      ("grip centre", pose.gripper.location),
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
      await self.request_rotation_drive_angle()
      await self.request_wrist_drive_angle()
    except Exception:
      logger.warning("could not read where the iSWAP's joints stopped; its model is stale")

  async def rotation_drive_rotate_to_angle(
    self,
    angle: Union[str, float],
    speed: int = 25_000,
    acceleration: int = 170,
    current_limit: int = 5,
  ):
    """Turn the rotation drive to an angle, holding the wrist where it is. This moves the arm.

    A caller for `rotate_to_angles`, which is where the move and the model update live: the wrist
    is read first and sent back to itself, so one command carries both and the arm sweeps the path
    that was asked for.

    Args:
      angle: one of the stops in `ROTATION_DRIVE_SLOTS` - `left`, `front`, `right`, `parking` -
        which goes to the increment this arm stores for it, or degrees signed from the calibrated
        front stop.
      speed: max velocity, in increments/s.
      acceleration: in thousands of increments/s2.
      current_limit: the motor current limit, 0 to 7.

    Raises:
      ValueError: If the angle lands outside the drive's travel, or an argument is out of range.
    """
    return await self.rotate_to_angles(
      rotation_angle=angle,
      wrist_angle=await self.request_wrist_drive_angle(),
      rotation_speed=speed,
      rotation_acceleration=acceleration,
      rotation_current_limit=current_limit,
    )

  async def wrist_drive_rotate_to_angle(
    self,
    angle: Union[str, float],
    speed: int = 20_000,
    acceleration: int = 145,
    current_limit: int = 5,
  ):
    """Turn the wrist to an angle, holding the rotation drive where it is. This moves the arm.

    The mirror of `rotation_drive_rotate_to_angle`, and the same one move underneath.

    Args:
      angle: one of the stops in `WRIST_DRIVE_SLOTS` - `straight`, `left`, `right`, `reverse`,
        `parking` - which goes to the increment this arm stores for it, or degrees signed from the
        drive's own zero.
      speed: max velocity, in increments/s.
      acceleration: in thousands of increments/s2.
      current_limit: the motor current limit, 0 to 7.

    Raises:
      ValueError: If the angle lands outside the drive's travel, or an argument is out of range.
    """
    return await self.rotate_to_angles(
      rotation_angle=await self.request_rotation_drive_angle(),
      wrist_angle=angle,
      wrist_speed=speed,
      wrist_acceleration=acceleration,
      wrist_current_limit=current_limit,
    )

  # -- pose ------------------------------------------------------------------

  async def request_joint_state(self) -> JointState:
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
    joints: JointState,
    link_1_length: float,
    link_2_length: float,
    wrist_straight_angle: float,
    rotation_drive_z_offset_above_finger: float,
  ) -> iSWAPPose:
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
      Every joint of the arm, and the deck angle of each link.
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
      rotation_joint=base,
      wrist_joint=wrist,
      gripper=CartesianPose(
        location=Coordinate(
          x=wrist.x + link_2_length * math.cos(alpha_2),
          y=wrist.y + link_2_length * math.sin(alpha_2),
          z=base.z - rotation_drive_z_offset_above_finger,
        ),
        rotation=Rotation(z=link_2_deck_angle),
      ),
      link_1_rotation=Rotation(z=link_1_deck_angle),
      joints=joints,
    )

  async def request_pose(self) -> iSWAPPose:
    """Where the gripper is, worked out from the joint state.

    Read and computed rather than asked for: the master answers a gripper position of its own, but
    only correctly after certain commands have run. This reads each drive and runs the kinematics,
    so it holds whenever it is called.

    Returns:
      Every joint of the arm and the deck angle of each link, in one answer: what a caller needs
      to say whether the arm clears something is where its middle joint is as much as where its
      end is.

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
