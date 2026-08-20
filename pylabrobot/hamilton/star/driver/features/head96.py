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

# The retract drives the head to its Z-safety height, which takes a while.
RETRACT_READ_TIMEOUT = 20

# The drive parameters the head stores: each drive's speed and acceleration.
DRIVE_PARAMETERS = ("yv", "yr", "zv", "zr")

# The head's channels sit on a 9 mm grid, 12 across and 8 deep, so the array they cover is this
# wide and this deep. The body around them is larger, and how much is not read from anywhere.
CHANNEL_PITCH = 9.0
HEAD96_SIZE_X = 11 * CHANNEL_PITCH
HEAD96_SIZE_Y = 7 * CHANNEL_PITCH
# How tall to draw it. Not sourced: the head's own extent is not something the machine reports.
HEAD96_SIZE_Z = 140.0
# Channel A1 sits at the back left of the array, so the drive's Y is the resource's back edge.
HEAD96_REFERENCE_ANCHOR = "b"
# What the head is called on the arm that carries it.
HEAD96_NAME = "head96"

# How long a Y move may take before the reply is given up on, in seconds. The drive crosses its
# whole travel in a few seconds at the slowest acceleration the firmware accepts.
Y_MOVE_READ_TIMEOUT = 30
INITIALIZE_READ_TIMEOUT = 60

# Where the head is left when initialization finishes, in mm.
INITIALIZE_Z_POSITION_AT_END = 245.0


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
  supports_clot_monitoring_clld: Optional[bool] = None
  stop_disc_type: Optional[StopDiscType] = None
  instrument_type: Optional[InstrumentType] = None
  head_type: Optional[HeadType] = None

  initialize_position: Optional[Tuple[float, float, float]] = None
  """Where the head ejects when it is initialized: head channel A1, in deck mm. Initializing
  throws off whatever is mounted, so this has to be somewhere tips may be dropped - which depends
  on where the waste sits on the deck, and so has no default. Setup initializes the head when this
  is set, and reports that it cannot when it is not."""

  z_range: Optional[Tuple[float, float]] = None
  """Z-drive position window (mm); FM-STAR extends it. Resolved at setup: the min is
  variant-derived, the max is read from a hardware probe."""

  z_speed_range: Tuple[float, float] = (0.25, 100.0)
  """Z-drive speed window (mm/s); unchanged across the 2008/2013/2025 firmware, unlike the
  version-resolved `y_speed_range`."""
  z_acceleration_range: Tuple[float, float] = (25.0, 500.0)
  """Z-drive acceleration window (mm/s2); unchanged across the 2008/2013/2025 firmware (the
  pre-2010 encoding differs, the physical range does not)."""

  # === Encoder resolutions (defaulted device facts). Y/Z are unchanged across firmware; the
  # dispensing and squeezer resolutions are the 2013-or-later generation's values, and a 2008-era
  # head's differ. Nothing resolves them per generation, so on such a head every volume and
  # squeezer conversion here - and the windows derived from them - would be wrong. Discovery says
  # so when it finds one. ===
  z_drive_mm_per_increment: float = 0.005
  y_drive_mm_per_increment: float = 0.015625
  dispensing_drive_mm_per_increment: float = 0.001025641026
  dispensing_drive_uL_per_increment: float = 0.019340933
  squeezer_drive_mm_per_increment: float = 0.0002086672009

  # === Per-drive speed and acceleration, read off the machine at setup, so a run can override
  # them from what the machine currently holds. ===
  y_drive_speed_default: Optional[float] = None
  y_drive_acceleration_default: Optional[float] = None
  z_drive_speed_default: Optional[float] = None
  z_drive_acceleration_default: Optional[float] = None

  # -- conversions: the wire counts in increments, the driver speaks mm and uL ---------------

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

  # === Firmware/variant-derived area-of-operation windows (standard units). Pure functions of
  # the firmware date and the encoder resolutions above, so they are computed on access. ===
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


def get_or_create_head96(arm: Resource, x_offset: Optional[float]) -> Resource:
  """Get, or create once, the 96-head resource on the arm that carries it.

  The head is a child of the arm, so it follows it along the rail. Where it sits across the arm is
  fixed: the machine reports how far channel A1 is from the carriage centre.

  Args:
    arm: the resource modelling the arm this head rides.
    x_offset: how far channel A1 sits from the carriage centre, in mm, as the machine reports it.

  Returns:
    The head resource, whether it was just created or already there.

  Raises:
    RuntimeError: If the offset was not read, so where the head sits across the arm is unknown.
  """
  existing = next((child for child in arm.children if child.name == HEAD96_NAME), None)
  if existing is not None:
    return existing
  if x_offset is None:
    raise RuntimeError("the 96-head's X offset was not read; have you called `star.setup()`?")
  head = Resource(
    name=HEAD96_NAME,
    size_x=HEAD96_SIZE_X,
    size_y=HEAD96_SIZE_Y,
    size_z=HEAD96_SIZE_Z,
    category="head96",
    model="hamilton_star_core_96_head",
  )
  # Channel A1 sits `x_offset` left of the carriage centre, and the arm is located by its own left
  # edge, so A1 lands that far left of the arm's centre. Y is set from the drive once it is read.
  arm.assign_child_resource(
    head, location=Coordinate(arm.get_absolute_size_x() / 2 - x_offset, 0.0, 0.0)
  )
  return head


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

  # -- session / discovery ---------------------------------------------------

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

  # -- y position ------------------------------------------------------------

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

  async def park(self):
    """Send the head to its home position. This moves it in Y and in Z.

    Uses the drive's own speeds and accelerations, as legacy does, rather than writing any into the
    register. Where it comes to rest is read back afterwards.
    """
    await self._driver.send_command(module="H0", command="MO", read_timeout=Y_MOVE_READ_TIMEOUT)
    await self.request_y_position()

  def update_location_by_reference_point(self, y: float) -> None:
    """Record where the head is on the resource that models it.

    Only Y: the head rides the arm, so its resource is a child of the arm's and follows it in X.
    The drive positions the head by channel A1, while a resource is located by its left front
    bottom corner, so the two differ by the head's own anchor. Does nothing when the driver was
    given no deck, and so has nothing to model.

    Args:
      y: where channel A1 is now, in mm.
    """
    if self.resource is None or self.resource.location is None:
      return
    anchor = self.resource.get_anchor(y=HEAD96_REFERENCE_ANCHOR)
    self.resource.location = Coordinate(
      self.resource.location.x, y - anchor.y, self.resource.location.z
    )

  async def move_y(
    self,
    y: float,
    speed: Optional[float] = None,
    acceleration: Optional[float] = None,
    current_limit: int = 15,
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

    for value, (low, high), name in (
      (y, c.y_range, "y"),
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
        read_timeout=Y_MOVE_READ_TIMEOUT,
      )
    finally:
      # Where it was told to go, then where the drive says it went.
      self.update_location_by_reference_point(y)
      await self.request_y_position()
      if c.y_drive_mm_to_increments(speed) != c.y_drive_mm_to_increments(was_speed):
        await self.set_drive_parameter("yv", was_speed)
      if c.y_drive_mm_to_increments(acceleration) != c.y_drive_mm_to_increments(was_acceleration):
        await self.set_drive_parameter("yr", was_acceleration)

  # -- z position ------------------------------------------------------------

  async def request_stop_disk_z(self) -> float:
    """Request the head's Z-drive (stop disk) position.

    This is the raw drive position regardless of tip state, not the tip bottom.

    Returns:
      The stop-disk Z position in mm.
    """
    resp = await self._driver.send_command(module="H0", command="RZ", fmt="rz##### (n)")
    increments = cast(List[int], resp["rz"])[1]  # [0] = firmware counter, [1] = hardware counter
    return self.configuration.z_drive_increments_to_mm(increments)

  async def move_to_z_safety(self) -> float:
    """Drive the head to its Z-safety height and read where that put it.

    Doubles as the probe for how far this unit actually reaches: the generic command range can
    exceed it, so the top is read off the hardware rather than assumed.

    Returns:
      The stop-disk Z position at the safety height, in mm.
    """
    await self._driver.send_command(module="C0", command="EV", read_timeout=RETRACT_READ_TIMEOUT)
    return await self.request_stop_disk_z()

  def resolve_z_range(self, z_max: float) -> Tuple[float, float]:
    """The Z window this head reaches: a variant-derived floor, and a probed ceiling.

    Args:
      z_max: the top the hardware actually reached, from `move_to_z_safety`.

    Returns:
      The `(min, max)` window in mm, also recorded on the configuration.
    """
    c = self.configuration
    min_increments = 24200 if c.instrument_type == "FM-STAR" else 36100
    c.z_range = (c.z_drive_increments_to_mm(min_increments), z_max)
    return c.z_range

  # -- initialization --------------------------------------------------------

  async def initialize(
    self,
    x: Optional[float] = None,
    y: Optional[float] = None,
    z: Optional[float] = None,
    z_position_at_the_command_end: float = INITIALIZE_Z_POSITION_AT_END,
  ):
    """Initialize the head, discarding whatever is mounted on it.

    This moves the head: it travels to the position given and ejects there, so that position must
    be somewhere tips may be dropped. The firmware wants the location of the head's channel A1.

    Args:
      x: X to eject at, in mm, at head channel A1. Defaults to `configuration.initialize_position`.
      y: Y to eject at, in mm, at head channel A1. Defaults to the same.
      z: Z to eject at, in mm. Defaults to the same.
      z_position_at_the_command_end: Z to leave the head at, in mm.

    Raises:
      ValueError: If no position was given and none is configured.
    """
    if x is None or y is None or z is None:
      configured = self.configuration.initialize_position
      if configured is None:
        raise ValueError(
          "no position to eject at: initializing the head throws off whatever is mounted, so it "
          "needs somewhere tips may be dropped. Pass x, y and z, or set "
          "`configuration.initialize_position`."
        )
      x, y, z = configured
    return await self._driver.send_command(
      module="C0",
      command="EI",
      read_timeout=INITIALIZE_READ_TIMEOUT,
      xs=f"{abs(round(x * 10)):05}",
      xd=0 if x >= 0 else 1,
      yh=f"{abs(round(y * 10)):04}",
      za=f"{round(z * 10):04}",
      ze=f"{round(z_position_at_the_command_end * 10):04}",
    )
