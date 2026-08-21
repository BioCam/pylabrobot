"""The 96-head: the block of 96 pipettes that works a whole plate at once."""

import datetime
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import parse_firmware_version_date
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

StopDiscType = Literal["core_i", "core_ii"]
InstrumentType = Literal["legacy", "FM-STAR"]
HeadType = Literal["Low volume head", "High volume head", "96 head II", "96 head TADM", "unknown"]

HEAD_TYPES: Dict[int, HeadType] = {
  0: "Low volume head",
  1: "High volume head",
  2: "96 head II",
  3: "96 head TADM",
}

# The generation the dispensing and squeezer resolutions below were taken from. A head older than
# this has different ones, and nothing here resolves them per generation.
RESOLUTIONS_FIRST_YEAR = 2010

# The drive parameters the head stores: each drive's speed and acceleration.
DRIVE_PARAMETERS = ("yv", "yr", "zv", "zr")

# The firmware's own retract drives the head to its Z-safety height, which takes a while.
RETRACT_READ_TIMEOUT = 20

# Channel A1 sits at the back left of the array, so the drive's Y is the resource's back edge.
HEAD96_REFERENCE_ANCHOR = "b"
# The stop disk is the head's lowest fixed feature, so the Z drive reports the resource's bottom.
HEAD96_Z_REFERENCE_ANCHOR = "b"


@dataclass
class Head96Configuration:
  """Device facts for the installed 96-head.

  Ported from the legacy `Head96Information`. Two kinds of value: what the head reports about
  itself, which is None until read; and device facts that are defaulted, of which the
  firmware-derived windows are computed from `firmware_date` on access rather than stored.
  """

  firmware_version: Optional[str] = None
  firmware_date: Optional[datetime.date] = None
  x_offset: Optional[float] = None
  """Deck X distance from the X-arm carriage center to head channel A1 (mm), read from
  master EEPROM at setup. Mirrors the iSWAP's rotation-drive x-offset."""

  channel_pitch: float = 9.0
  channel_columns: int = 12
  channel_rows: int = 8
  body_size_z: float = 140.0  # size of modelled head body; stop disk to the top of the head (mm).
  min_x_clear_of_left_side_panel: float = -100.0
  """The leftmost channel A1 may go without the head striking the left side panel, in deck mm.

  A judgement about clearance rather than a measurement, and not read from anywhere: the panel is
  bolted on and off in seconds, so whether one is fitted is declared, and how close the head may
  come to it is ours to choose."""

  supports_clot_monitoring_clld: Optional[bool] = None
  stop_disc_type: Optional[StopDiscType] = None
  instrument_type: Optional[InstrumentType] = None
  head_type: Optional[HeadType] = None

  tip_discard_location: Optional[Coordinate] = None
  """Where the head ejects when it is initialized: head channel A1, in deck mm. Initializing
  throws off whatever is mounted, so this has to be somewhere tips may be dropped - which depends
  on where the waste sits on the deck, and so has no default."""

  z_range: Optional[Tuple[float, float]] = None
  """Z-drive position window (mm); FM-STAR extends it. Resolved by `probe_z_max`: the min is
  variant-derived, the max is read from a hardware probe."""

  z_increment_range: Tuple[int, int] = (36100, 68500)
  z_increment_range_fm_star: Tuple[int, int] = (24200, 76200)  # increase for FM-STAR
  z_speed_range: Tuple[float, float] = (0.25, 100.0)
  z_acceleration_range: Tuple[float, float] = (25.0, 500.0)  # units: mm/s**2

  # Encoder resolutions (defaulted device facts). Y/Z are unchanged across firmware; the
  # dispensing and squeezer resolutions are the 2013-or-later generation's values, and a 2008-era
  # head's differ.
  z_drive_mm_per_increment: float = 0.005
  y_drive_mm_per_increment: float = 0.015625
  dispensing_drive_mm_per_increment: float = 0.001025641026
  dispensing_drive_uL_per_increment: float = 0.019340933
  squeezer_drive_mm_per_increment: float = 0.0002086672009

  # Per-drive speed and acceleration, read off the machine at setup, so a run can override
  # them from what the machine currently holds.
  y_drive_speed_default: Optional[float] = None
  y_drive_acceleration_default: Optional[float] = None
  z_drive_speed_default: Optional[float] = None
  z_drive_acceleration_default: Optional[float] = None

  @property
  def z_range_by_variant(self) -> Tuple[float, float]:
    """The Z window this variant documents, in mm.

    What the drive says it reaches, which is not the same as what a given unit does - the top is
    probed at setup and replaces this one. Pure: it reads nothing and changes nothing.
    """
    low, high = (
      self.z_increment_range_fm_star
      if self.instrument_type == "FM-STAR"
      else self.z_increment_range
    )
    return (self.z_drive_increments_to_mm(low), self.z_drive_increments_to_mm(high))

  @property
  def channel_array_size_x(self) -> float:
    """How wide the channel array is: the first column's centre to the last's, in mm.

    What the resource modelling the head spans, so that channel A1 lands on its left back corner.
    The body around the channels is larger, and by how much is not read from anywhere.
    """
    return (self.channel_columns - 1) * self.channel_pitch

  @property
  def channel_array_size_y(self) -> float:
    """How deep the channel array is: the first row's centre to the last's, in mm."""
    return (self.channel_rows - 1) * self.channel_pitch

  # -- conversions: the wire counts in increments, the driver speaks mm and uL -------------------

  def y_drive_increments_to_mm(self, increments: int) -> float:
    """A Y-drive position in mm, from the increments the drive counts in."""
    return round(increments * self.y_drive_mm_per_increment, 2)

  def y_drive_mm_to_increments(self, mm: float) -> int:
    """A Y-drive position in increments, from mm."""
    return round(mm / self.y_drive_mm_per_increment)

  def z_drive_increments_to_mm(self, increments: int) -> float:
    """A Z-drive position in mm, from increments."""
    return round(increments * self.z_drive_mm_per_increment, 2)

  def z_drive_mm_to_increments(self, mm: float) -> int:
    """A Z-drive position in increments, from mm."""
    return round(mm / self.z_drive_mm_per_increment)

  def dispensing_drive_increments_to_uL(self, increments: int) -> float:
    """A dispensing-drive position as the volume it holds, from increments."""
    return round(increments * self.dispensing_drive_uL_per_increment, 2)

  def dispensing_drive_uL_to_increments(self, uL: float) -> int:
    """A dispensing-drive position in increments, from the volume to hold."""
    return round(uL / self.dispensing_drive_uL_per_increment)

  def dispensing_drive_increments_to_mm(self, increments: int) -> float:
    """A dispensing-drive position as how far the piston has travelled, from increments."""
    return round(increments * self.dispensing_drive_mm_per_increment, 2)

  def dispensing_drive_mm_to_increments(self, mm: float) -> int:
    """A dispensing-drive position in increments, from how far the piston should travel."""
    return round(mm / self.dispensing_drive_mm_per_increment)

  def squeezer_drive_increments_to_mm(self, increments: int) -> float:
    """A squeezer-drive position in mm, from increments."""
    return round(increments * self.squeezer_drive_mm_per_increment, 2)

  def squeezer_drive_mm_to_increments(self, mm: float) -> int:
    """A squeezer-drive position in increments, from mm."""
    return round(mm / self.squeezer_drive_mm_per_increment)

  @property
  def firmware_year(self) -> int:
    """The year the head's firmware was built, which resolves the windows below.

    Raises:
      RuntimeError: If the firmware version has not been read.
    """
    if self.firmware_date is None:
      raise RuntimeError("96-head firmware version not read; have you called `star.setup()`?")
    return self.firmware_date.year

  # Firmware/variant-derived area-of-operation windows (standard units). Pure functions of
  # the firmware date and the encoder resolutions above, so they are computed on access.
  @property
  def y_range(self) -> Tuple[float, float]:
    """Y-drive position window (mm); 2013 firmware shifted it from the 2008 range.

    What the command accepts, which is wider than what a given machine allows: a move to the low
    end of this window was refused as outside the permitted area on a machine whose channels share
    the arm.
    """
    min_inc, max_inc = (6000, 36000) if self.firmware_year >= 2010 else (7000, 36200)
    return (self.y_drive_increments_to_mm(min_inc), self.y_drive_increments_to_mm(max_inc))

  @property
  def y_speed_range(self) -> Tuple[float, float]:
    """Y-drive speed window (mm/s). The pre-2021 max (390.625 = the firmware default, 25000 inc) is
    an empirical, deck-tested cap; per firmware version the maxima are 312.5 (2008) and 625 (2013+).
    Verify on a pre-2021 head before raising it."""
    return (0.78125, 390.625 if self.firmware_year <= 2021 else 625.0)

  @property
  def y_acceleration_range(self) -> Tuple[float, float]:
    """Y-drive acceleration window (mm/s2). The min (5000 inc) is constant; the max rose from 32000
    inc (2008) to 50000 inc (2013+), so it tracks firmware like the Y range / speed."""
    max_inc = 50000 if self.firmware_year >= 2010 else 32000
    return (self.y_drive_increments_to_mm(5000), self.y_drive_increments_to_mm(max_inc))

  @property
  def dispensing_drive_range(self) -> Tuple[float, float]:
    """Aspirate/dispense piston volume window (uL); applies to both aspirate and dispense. 2013
    firmware widened the max from 62130 inc."""
    max_inc = 64350 if self.firmware_year >= 2010 else 62130
    return (0.0, self.dispensing_drive_increments_to_uL(max_inc))

  @property
  def dispensing_drive_speed_range(self) -> Tuple[float, float]:
    """Dispensing-drive speed window (uL/s); 2013 firmware widened the max from 52000 inc."""
    min_inc = 5  # firmware dv minimum (00005 increments/second)
    max_inc = 55000 if self.firmware_year >= 2010 else 52000
    return (
      self.dispensing_drive_increments_to_uL(min_inc),
      self.dispensing_drive_increments_to_uL(max_inc),
    )

  @property
  def dispensing_drive_speed_default(self) -> float:
    """Dispensing-drive default speed (uL/s); constant across firmware."""
    return 261.1

  @property
  def dispensing_drive_acceleration_default(self) -> float:
    """Dispensing-drive default acceleration (uL/s2); 2013 firmware raised it."""
    increments = 900000 if self.firmware_year >= 2010 else 150000
    return self.dispensing_drive_increments_to_uL(increments)

  @property
  def squeezer_drive_speed_default(self) -> float:
    """Squeezer-drive default speed (mm/s); 2013 firmware raised it."""
    increments = 76000 if self.firmware_year >= 2010 else 16000
    return self.squeezer_drive_increments_to_mm(increments)

  @property
  def squeezer_drive_acceleration_default(self) -> float:
    """Squeezer-drive default acceleration (mm/s2); 2013 firmware raised it."""
    increments = 300000 if self.firmware_year >= 2010 else 100000
    return self.squeezer_drive_increments_to_mm(increments)


def require_drive_parameter(parameter: str) -> None:
  """Raise unless this is one of the drive parameters the head stores.

  Args:
    parameter: `yv` or `yr` for the Y drive's speed and acceleration, `zv` or `zr` for the Z
      drive's.

  Raises:
    ValueError: If it is not one of those four.
  """
  if parameter not in DRIVE_PARAMETERS:
    raise ValueError(f"unknown drive parameter {parameter!r}, expected one of {DRIVE_PARAMETERS}")


class Head96:
  """The 96-head.

  Reached as `driver.head96`, on a machine that has one. It is addressed as `H0`, but the
  commands that move it go to the master, so this capability speaks to both.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[Head96Configuration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the head's device facts. Defaults to `Head96Configuration()`.
    """
    self._driver = driver
    # The head on the deck, when the driver was given one. Setup puts it there, as a child of the
    # arm it rides; moves keep it in step. Without a deck it stays None and nothing is modelled.
    self.resource: Optional[Resource] = None
    self.configuration = configuration or Head96Configuration()

  # ----------------------------------------
  # Setup
  # ----------------------------------------

  # -- discovery ---------------------------------------------------------------------------------

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    """Request the head's firmware version and build date.

    Returns:
      The version string and its build date.
    """
    resp = await self._driver.send_command(module="H0", command="RF")
    return resp.split("rf")[-1], parse_firmware_version_date(resp)

  async def request_hardware(self) -> List[str]:
    """Request the head's configuration, undecoded.

    The head returns ten blank-separated decimal values. The indices currently understood are
    0: clot monitoring with cLLD, 1: stop disc type (0 = core_i, 1 = core_ii), 2: instrument type
    (0 = legacy, 1 = FM-STAR); 3 to 9 are reserve.

    Index 1 is populated on firmware at least back to 2021. Whether index 2 is reliably populated
    on every build, or on some falls back to reserve (read back as 0 -> legacy), is unverified;
    confirm on an FM-STAR head before relying on it to unlock the FM-STAR z-range extension.

    Returns:
      The positional tokens, as reported.
    """
    resp: str = await self._driver.send_command(module="H0", command="QU")
    return resp.split("au")[-1].split()

  async def request_head_type(self) -> HeadType:
    """Request which 96-head is fitted.

    Returns:
      The head type, or "unknown" for a code this driver does not know.
    """
    resp = await self._driver.send_command(module="H0", command="QG", fmt="qg#")
    return HEAD_TYPES.get(cast(int, resp["qg"]), "unknown")

  async def request_x_offset(self) -> float:
    """Request the X distance from the X-arm carriage center to head channel A1.

    Stored in the master EEPROM and read with the generic master-EEPROM read, mirroring the
    iSWAP's rotation-drive offset. Needed to derive the carriage X from a target A1 X.

    Returns:
      The offset in mm.
    """
    # 4-digit field: the head96 offset is ~10x the iSWAP's (~368 mm vs ~34 mm), so it exceeds
    # 3 digits in 0.1 mm units - a 3-digit field silently truncates 3684 -> 368.
    resp = await self._driver.send_command(module="C0", command="RA", ra="kf", fmt="kf####")
    return cast(int, resp["kf"]) / 10.0

  async def request_drive_parameter(self, parameter: str) -> float:
    """Request one of the head's stored drive parameters.

    Args:
      parameter: the parameter to read - `yv` and `yr` for Y-drive speed and acceleration, `zv`
        and `zr` for the Z drive.

    Returns:
      The value in mm/s or mm/s2, converted from the increments the drive counts in.

    Raises:
      ValueError: If the parameter is not one of the four drive parameters.
    """
    require_drive_parameter(parameter)
    c = self.configuration
    to_mm = c.y_drive_increments_to_mm if parameter[0] == "y" else c.z_drive_increments_to_mm
    resp = await self._driver.send_command(
      module="H0", command="RA", ra=parameter, fmt=f"{parameter}#####"
    )
    return to_mm(cast(int, resp[parameter]))

  async def discover(self):
    """Read what head this is and what it can do. Read-only: nothing moves."""
    c = self.configuration
    c.firmware_version, c.firmware_date = await self.request_firmware_version()
    if c.firmware_year < RESOLUTIONS_FIRST_YEAR:
      logger.warning(
        "this 96-head reports %s firmware, older than the generation the dispensing and squeezer "
        "resolutions here were taken from. Volumes and squeezer distances it reports, and the "
        "windows derived from them, may be wrong. Set them on Head96Configuration to correct it.",
        c.firmware_date,
      )

    hardware = await self.request_hardware()
    c.supports_clot_monitoring_clld = bool(int(hardware[0]))
    c.stop_disc_type = "core_i" if hardware[1] == "0" else "core_ii"
    c.instrument_type = "legacy" if hardware[2] == "0" else "FM-STAR"
    c.head_type = await self.request_head_type()
    c.x_offset = await self.request_x_offset()

    # Seed the drive defaults from what the machine currently holds.
    c.y_drive_speed_default = await self.request_drive_parameter("yv")
    c.y_drive_acceleration_default = await self.request_drive_parameter("yr")
    c.z_drive_speed_default = await self.request_drive_parameter("zv")
    c.z_drive_acceleration_default = await self.request_drive_parameter("zr")

  # -- initialization ----------------------------------------------------------------------------

  async def initialize(
    self,
    tip_discard_location: Optional[Coordinate] = None,
    z_position_at_the_command_end: float = 245.0,
    read_timeout: int = 60,
  ):
    """Initialize the head, discarding whatever is mounted on it.

    This moves the head: it travels to the position given and ejects there, so that position must
    be somewhere tips may be dropped. The firmware wants the location of the head's channel A1.

    Args:
      tip_discard_location: where to eject, in deck mm, at head channel A1. Defaults to
        `configuration.tip_discard_location`.
      z_position_at_the_command_end: Z to leave the head at, in mm.

    Raises:
      ValueError: If no position was given and none is configured.
    """
    if tip_discard_location is None:
      tip_discard_location = self.configuration.tip_discard_location
    if tip_discard_location is None:
      raise ValueError(
        "nowhere to discard tips: initializing the head throws off whatever is mounted, so it "
        "needs somewhere tips may be dropped. Pass `tip_discard_location`, or set it on the "
        "configuration."
      )
    return await self._driver.send_command(
      module="C0",
      command="EI",
      read_timeout=read_timeout,
      xs=f"{abs(round(tip_discard_location.x * 10)):05}",
      xd=0 if tip_discard_location.x >= 0 else 1,
      yh=f"{abs(round(tip_discard_location.y * 10)):04}",
      za=f"{round(tip_discard_location.z * 10):04}",
      ze=f"{round(z_position_at_the_command_end * 10):04}",
    )

  # ----------------------------------------
  # Movement
  # ----------------------------------------

  # -- x position, carried by the arm the head rides ---------------------------------------------

  async def request_x_position(self) -> float:
    """Request where along X channel A1 is, in deck mm.

    The head has no X drive of its own: it rides the arm, and sits `configuration.x_offset` left of
    the carriage reference point. So this asks the arm and applies the offset, rather than reading a
    drive. Nothing is recorded either - the resource modelling the head is a child of the arm's, so
    its X follows the arm without anything having to write it.

    Returns:
      The position in mm.

    Raises:
      RuntimeError: If no arm is installed, or the head's X offset was not read at discovery.
    """
    # The arm carrying this head, not whichever arm is present: on a machine with two, the head
    # is on one of them and its X is that one's.
    arm = next((a for a in self._driver.arms if a.head96 is self), None)
    if arm is None:
      raise RuntimeError("this head is not on either arm; have you called `star.setup()`?")
    if self.configuration.x_offset is None:
      raise RuntimeError("the 96-head's X offset was not read; have you called `star.setup()`?")
    return round(await arm.request_position() - self.configuration.x_offset, 2)

  # -- y position --------------------------------------------------------------------------------

  async def request_y_position(self) -> float:
    """Request where along Y the head is.

    The drive answers with two counters, the firmware's and the hardware's; the hardware's is what
    this returns, as the Z read does.

    Returns:
      The position in mm.
    """
    resp = await self._driver.send_command(module="H0", command="RY", fmt="ry##### (n)")
    increments = cast(List[int], resp["ry"])[1]
    y = self.configuration.y_drive_increments_to_mm(increments)
    self.update_location_by_reference_point(y=y)
    return y

  async def request_predefined_y_positions(self) -> List[float]:
    """Request the Y positions the head has stored, in mm.

    The head keeps ten of them in non-volatile memory. The first is the home position the Y drive
    parks at; the rest are further slots this capability sends no command against, so they are
    returned as read rather than named.

    Returns:
      The ten stored positions in mm, the first being home.
    """
    resp = await self._driver.send_command(module="H0", command="RA", ra="py", fmt="py##### (n)")
    increments = cast(List[int], resp["py"])
    return [self.configuration.y_drive_increments_to_mm(i) for i in increments]

  async def set_drive_parameter(self, parameter: str, value: float) -> None:
    """Write one of the head's stored drive parameters.

    Args:
      parameter: the parameter to write, named as `request_drive_parameter` names it.
      value: the value in mm/s or mm/s2, converted to the increments the drive counts in.

    Raises:
      ValueError: If the parameter is not one of the four drive parameters.
    """
    require_drive_parameter(parameter)
    c = self.configuration
    to_increments = (
      c.y_drive_mm_to_increments if parameter[0] == "y" else c.z_drive_mm_to_increments
    )
    written: Dict[str, Any] = {parameter: f"{to_increments(value):05}"}
    await self._driver.send_command(module="H0", command="AA", **written)

  async def park(self, read_timeout: int = 30):
    """Send the head to its home position. This moves it in Y and in Z.

    Uses the drive's own speeds and accelerations, as legacy does, rather than writing any into the
    register. Where it comes to rest is read back afterwards.
    """
    await self._driver.send_command(module="H0", command="MO", read_timeout=read_timeout)
    await self.request_y_position()

  def update_location_by_reference_point(
    self, y: Optional[float] = None, z: Optional[float] = None
  ) -> None:
    """Record where the head is on the resource that models it.

    Y and Z only: the head rides the arm, so its resource is a child of the arm's and follows it in
    X without anything having to record that. Each axis has its own reference point, and a resource
    is located by its left front bottom corner, so the two differ by the head's own anchor: the
    drive positions the head along Y by channel A1, at the array's back edge, and along Z by the
    stop disk, at its bottom.

    Both drives answer in the deck's frame, and a resource's location is measured from its parent -
    which for the head is the arm, not the deck. The two differ by wherever the arm sits, so the
    arm's own position is taken out before either value is recorded. Does nothing when the driver
    was given no deck, and so has nothing to model.

    Args:
      y: where channel A1 is now, in mm on the deck. Left as it was when None.
      z: where the stop disk is now, in mm on the deck. Left as it was when None.
    """
    deck = self._driver.deck
    if self.resource is None or self.resource.location is None or deck is None:
      return
    arm = self.resource.parent
    if arm is None:
      return
    here, on_the_arm = self.resource.location, arm.get_location_wrt(deck)
    anchor = self.resource.get_anchor(y=HEAD96_REFERENCE_ANCHOR, z=HEAD96_Z_REFERENCE_ANCHOR)
    self.resource.location = Coordinate(
      here.x,
      here.y if y is None else y - on_the_arm.y - anchor.y,
      here.z if z is None else z - on_the_arm.z - anchor.z,
    )

  def _check_reachable(self, axis: Literal["y", "z"], value: float) -> None:
    """Raise if a drive cannot be sent where it is being asked to go.

    Each axis is bounded at its own reference point: channel A1 along Y, the stop disk along Z.

    Args:
      axis: which drive - `y` across the arm, `z` up and down.
      value: where it would be sent, in mm.

    Raises:
      ValueError: If the drive's travel does not reach it.
      RuntimeError: If the Z window was not resolved, so how far this unit reaches is unknown.
    """
    if axis == "y":
      low, high = self.configuration.y_range
    else:
      z_range = self.configuration.z_range
      if z_range is None:
        raise RuntimeError("the head's Z window was not probed; have you called `star.setup()`?")
      low, high = z_range
    if not low <= value <= high:
      raise ValueError(f"{axis} must be between {low} and {high}, is {value}")

  async def move_y(
    self,
    y: float,
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: int = 15,
    read_timeout: int = 30,
  ):
    """Move the head along Y. This moves it, and nothing else on the arm.

    The move writes its speed and acceleration into the drive's volatile register, where later
    moves would inherit them, so what was there is read first and put back afterwards - skipping
    the write where the move's value already matches.

    Args:
      y: where to move to, in mm.
      speed: how fast, in mm/s. Defaults to `configuration.y_drive_speed_default`.
      acceleration: how hard, in mm/s2. Defaults to `configuration.y_drive_acceleration_default`.
      current_limit: the motor current limit.

    Raises:
      ValueError: If an argument is outside what the drive accepts.
      RuntimeError: If the head's drive defaults were not read at discovery.
    """
    c = self.configuration
    if speed is None:
      speed = c.y_drive_speed_default
    if acceleration is None:
      acceleration = c.y_drive_acceleration_default
    if speed is None or acceleration is None:
      raise RuntimeError("the head's drive defaults were not read; have you called `star.setup()`?")

    self._check_reachable("y", y)
    for value, (low, high), name in (
      (speed, c.y_speed_range, "speed"),
      (acceleration, c.y_acceleration_range, "acceleration"),
    ):
      if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}, is {value}")
    if not 0 <= current_limit <= 15:
      raise ValueError(f"current_limit must be between 0 and 15, is {current_limit}")

    was_speed = await self.request_drive_parameter("yv")
    was_acceleration = await self.request_drive_parameter("yr")
    try:
      return await self._driver.send_command(
        module="H0",
        command="YA",
        ya=f"{c.y_drive_mm_to_increments(y):05}",
        yv=f"{c.y_drive_mm_to_increments(speed):05}",
        yr=f"{c.y_drive_mm_to_increments(acceleration):05}",
        yw=f"{current_limit:02}",
        read_timeout=read_timeout,
      )
    finally:
      # Where the drive says it went, which the read records. Asked whether the move succeeded or
      # not: a move that failed part way left the head somewhere neither position describes.
      await self.request_y_position()
      if c.y_drive_mm_to_increments(speed) != c.y_drive_mm_to_increments(was_speed):
        await self.set_drive_parameter("yv", was_speed)
      if c.y_drive_mm_to_increments(acceleration) != c.y_drive_mm_to_increments(was_acceleration):
        await self.set_drive_parameter("yr", was_acceleration)

  # -- z position --------------------------------------------------------------------------------

  async def request_stop_disk_z(self) -> float:
    """Request the head's Z-drive (stop disk) position.

    This is the raw drive position regardless of tip state, not the tip bottom.

    Returns:
      The stop-disk Z position in mm.
    """
    resp = await self._driver.send_command(module="H0", command="RZ", fmt="rz##### (n)")
    increments = cast(List[int], resp["rz"])[1]  # [0] = firmware counter, [1] = hardware counter
    z = self.configuration.z_drive_increments_to_mm(increments)
    self.update_location_by_reference_point(z=z)
    return z

  async def request_predefined_z_positions(self) -> List[float]:
    """Request the Z positions the head has stored, in mm.

    The head keeps ten of them in non-volatile memory. The first is the home position the Z drive
    parks at; the rest are further slots this capability sends no command against, so they are
    returned as read rather than named. These are stop-disk positions, as `request_stop_disk_z` is.

    Returns:
      The ten stored positions in mm, the first being home.
    """
    resp = await self._driver.send_command(module="H0", command="RA", ra="pz", fmt="pz##### (n)")
    increments = cast(List[int], resp["pz"])
    return [self.configuration.z_drive_increments_to_mm(i) for i in increments]

  async def probe_z_max(self, read_timeout: int = RETRACT_READ_TIMEOUT) -> float:
    """Find out how high this head reaches. Retracts the head.

    Not something it reports: the command range can exceed what a given unit reaches, so the top is
    driven to and read back, using the firmware's own retract. Setup calls this once, before any
    window exists - which is why the retract here is that command rather than `move_to_safe_z`,
    whose target this establishes. What it finds becomes the top of `configuration.z_range`, whose
    floor comes from what instrument this is.

    Args:
      read_timeout: how long to wait for the retract, in seconds. It drives the head the length of
        its travel, so it takes a while.

    Returns:
      The highest stop-disk Z this head reaches, in mm.
    """
    await self._driver.send_command(module="C0", command="EV", read_timeout=read_timeout)
    z_max = await self.request_stop_disk_z()
    c = self.configuration
    c.z_range = (c.z_range_by_variant[0], z_max)
    return z_max

  async def move_z(
    self,
    z: float,
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: int = 15,
    read_timeout: int = 30,
  ):
    """Move the head along Z. This moves it, and nothing else on the arm.

    The move writes its speed and acceleration into the drive's volatile register, where later
    moves would inherit them, so what was there is read first and put back afterwards - skipping
    the write where the move's value already matches.

    Args:
      z: where to move the stop disk to, in mm.
      speed: how fast, in mm/s. Defaults to `configuration.z_drive_speed_default`.
      acceleration: how hard, in mm/s2. Defaults to `configuration.z_drive_acceleration_default`.
      current_limit: the motor current limit.

    Raises:
      ValueError: If an argument is outside what the drive accepts.
      RuntimeError: If the head's drive defaults were not read at discovery.
    """
    c = self.configuration
    if speed is None:
      speed = c.z_drive_speed_default
    if acceleration is None:
      acceleration = c.z_drive_acceleration_default
    if speed is None or acceleration is None:
      raise RuntimeError("the head's drive defaults were not read; have you called `star.setup()`?")

    self._check_reachable("z", z)
    for value, (low, high), name in (
      (speed, c.z_speed_range, "speed"),
      (acceleration, c.z_acceleration_range, "acceleration"),
    ):
      if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}, is {value}")
    if not 0 <= current_limit <= 15:
      raise ValueError(f"current_limit must be between 0 and 15, is {current_limit}")

    was_speed = await self.request_drive_parameter("zv")
    was_acceleration = await self.request_drive_parameter("zr")
    try:
      return await self._driver.send_command(
        module="H0",
        command="ZA",
        za=f"{c.z_drive_mm_to_increments(z):05}",
        zv=f"{c.z_drive_mm_to_increments(speed):05}",
        zr=f"{c.z_drive_mm_to_increments(acceleration):06}",
        zw=f"{current_limit:02}",
        read_timeout=read_timeout,
      )
    finally:
      # Where the drive says it went, which the read records. Asked whether the move succeeded or
      # not: a move that failed part way left the head somewhere neither position describes.
      await self.request_stop_disk_z()
      if c.z_drive_mm_to_increments(speed) != c.z_drive_mm_to_increments(was_speed):
        await self.set_drive_parameter("zv", was_speed)
      if c.z_drive_mm_to_increments(acceleration) != c.z_drive_mm_to_increments(was_acceleration):
        await self.set_drive_parameter("zr", was_acceleration)

  async def move_to_safe_z(
    self,
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
  ) -> float:
    """Move the head up to its safe Z: the top of the window `probe_z_max` probed.

    The precondition for any lateral move, so it runs often. An ordinary Z move to a known height,
    not a command of its own - so it is bounded, and its speed and acceleration are the caller's
    like any other move. The firmware's own retract runs once, inside `probe_z_max`, which is
    what establishes the height this moves to.

    Args:
      speed: how fast, in mm/s. Defaults to `configuration.z_drive_speed_default`.
      acceleration: how hard, in mm/s2. Defaults to `configuration.z_drive_acceleration_default`.

    Returns:
      The stop-disk Z position at the safety height, in mm.

    Raises:
      RuntimeError: If the Z window was not probed, so the safe height is unknown.
    """
    z_range = self.configuration.z_range
    if z_range is None:
      raise RuntimeError("the head's Z window was not probed; have you called `star.setup()`?")
    await self.move_z(z_range[1], speed=speed, acceleration=acceleration)
    return await self.request_stop_disk_z()

  # -- dispensing drive ----------------------------------------------------------------------

  # ----------------------------------------
  # Tip pickup and drop
  # ----------------------------------------

  # ----------------------------------------
  # Pipetting
  # ----------------------------------------
