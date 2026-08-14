"""The 96-head: the block of 96 pipettes that works a whole plate at once."""

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import parse_firmware_version_date

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

StopDiscType = Literal["core_i", "core_ii"]
InstrumentType = Literal["legacy", "FM-STAR"]
HeadType = Literal["Low volume head", "High volume head", "96 head II", "96 head TADM", "unknown"]

HEAD_TYPES: Dict[int, HeadType] = {
  0: "Low volume head",
  1: "High volume head",
  2: "96 head II",
  3: "96 head TADM",
}

# The retract drives the head to its Z-safety height, which takes a while.
RETRACT_READ_TIMEOUT = 20
INITIALIZE_READ_TIMEOUT = 60


@dataclass
class Head96Configuration:
  """Device facts for the installed 96-head.

  Ported from the legacy `Head96Information`. Two kinds of value: what the head reports about
  itself, which is None until read; and device facts that are defaulted, of which the
  firmware-derived windows are computed from `firmware_date` on access rather than stored.
  """

  firmware_version: Optional[str] = None
  """The head's firmware version, as reported."""
  firmware_date: Optional[datetime.date] = None
  """Its build date. The area-of-operation windows below are resolved from it."""
  x_offset: Optional[float] = None
  """Deck X distance from the X-arm carriage center to head channel A1 (mm), read from
  master EEPROM at setup. Mirrors the iSWAP's rotation-drive x-offset."""
  supports_clot_monitoring_clld: Optional[bool] = None
  stop_disc_type: Optional[StopDiscType] = None
  instrument_type: Optional[InstrumentType] = None
  head_type: Optional[HeadType] = None

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
  # dispensing/squeezer resolutions are the 2013+ generation values (2008-era heads differ). ===
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

  @property
  def firmware_year(self) -> int:
    """The year the head's firmware was built, which resolves the windows below.

    Raises:
      RuntimeError: If the firmware version has not been read.
    """
    if self.firmware_date is None:
      raise RuntimeError("96-head firmware version not read; forgot to call `setup`?")
    return self.firmware_date.year

  # === Firmware/variant-derived area-of-operation windows (standard units). Pure functions of
  # the firmware date and the encoder resolutions above, so they are computed on access. ===
  @property
  def y_range(self) -> Tuple[float, float]:
    """Y-drive position window (mm); 2013 firmware shifted it from the 2008 range."""
    min_inc, max_inc = (6000, 36000) if self.firmware_year >= 2010 else (7000, 36200)
    return (
      round(min_inc * self.y_drive_mm_per_increment, 2),
      round(max_inc * self.y_drive_mm_per_increment, 2),
    )

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
    return (
      round(5000 * self.y_drive_mm_per_increment, 2),
      round(max_inc * self.y_drive_mm_per_increment, 2),
    )

  @property
  def dispensing_drive_range(self) -> Tuple[float, float]:
    """Aspirate/dispense piston volume window (uL); applies to both aspirate and dispense. 2013
    firmware widened the max from 62130 inc."""
    max_inc = 64350 if self.firmware_year >= 2010 else 62130
    return (0.0, round(max_inc * self.dispensing_drive_uL_per_increment, 2))

  @property
  def dispensing_drive_speed_range(self) -> Tuple[float, float]:
    """Dispensing-drive speed window (uL/s); 2013 firmware widened the max from 52000 inc."""
    min_inc = 5  # firmware dv minimum (00005 increments/second)
    max_inc = 55000 if self.firmware_year >= 2010 else 52000
    return (
      round(min_inc * self.dispensing_drive_uL_per_increment, 2),
      round(max_inc * self.dispensing_drive_uL_per_increment, 2),
    )

  @property
  def dispensing_drive_speed_default(self) -> float:
    """Dispensing-drive default speed (uL/s); constant across firmware."""
    return 261.1

  @property
  def dispensing_drive_acceleration_default(self) -> float:
    """Dispensing-drive default acceleration (uL/s2); 2013 firmware raised it."""
    increments = 900000 if self.firmware_year >= 2010 else 150000
    return round(increments * self.dispensing_drive_uL_per_increment, 2)

  @property
  def squeezer_drive_speed_default(self) -> float:
    """Squeezer-drive default speed (mm/s); 2013 firmware raised it."""
    increments = 76000 if self.firmware_year >= 2010 else 16000
    return round(increments * self.squeezer_drive_mm_per_increment, 2)

  @property
  def squeezer_drive_acceleration_default(self) -> float:
    """Squeezer-drive default acceleration (mm/s2); 2013 firmware raised it."""
    increments = 300000 if self.firmware_year >= 2010 else 100000
    return round(increments * self.squeezer_drive_mm_per_increment, 2)


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
    self.configuration = configuration or Head96Configuration()

  # -- queries: one command each, reads only ---------------------------------

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

  async def request_stop_disk_z(self) -> float:
    """Request the head's Z-drive (stop disk) position.

    This is the raw drive position regardless of tip state, not the tip bottom.

    Returns:
      The stop-disk Z position in mm.
    """
    resp = await self._driver.send_command(module="H0", command="RZ", fmt="rz##### (n)")
    increments = cast(List[int], resp["rz"])[1]  # [0] = firmware counter, [1] = hardware counter
    return round(increments * self.configuration.z_drive_mm_per_increment, 2)

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
    resolutions = {
      "yv": self.configuration.y_drive_mm_per_increment,
      "yr": self.configuration.y_drive_mm_per_increment,
      "zv": self.configuration.z_drive_mm_per_increment,
      "zr": self.configuration.z_drive_mm_per_increment,
    }
    if parameter not in resolutions:
      raise ValueError(
        f"unknown drive parameter {parameter!r}, expected one of {sorted(resolutions)}"
      )
    resp = await self._driver.send_command(
      module="H0", command="RA", ra=parameter, fmt=f"{parameter}#####"
    )
    return round(cast(int, resp[parameter]) * resolutions[parameter], 2)

  # -- moves: one command each, moves the head -------------------------------

  async def retract(self) -> float:
    """Drive the head to its Z-safety height and read where that put it.

    Doubles as the probe for how far this unit actually reaches: the generic command range can
    exceed it, so the top is read off the hardware rather than assumed.

    Returns:
      The stop-disk Z position at the safety height, in mm.
    """
    await self._driver.send_command(module="C0", command="EV", read_timeout=RETRACT_READ_TIMEOUT)
    return await self.request_stop_disk_z()

  async def initialize(
    self,
    x: float,
    y: float,
    z: float,
    z_position_at_the_command_end: float = 245.0,
  ):
    """Initialize the head, discarding whatever is mounted on it.

    This moves the head: it travels to the position given and ejects there, so that position must
    be somewhere tips may be dropped. The firmware wants the location of the head's channel A1.

    Args:
      x: X to eject at, in mm, at head channel A1.
      y: Y to eject at, in mm, at head channel A1.
      z: Z to eject at, in mm.
      z_position_at_the_command_end: Z to leave the head at, in mm.
    """
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

  # -- routines: composed of the above ---------------------------------------

  async def discover(self):
    """Read what head this is and what it can do. Read-only: nothing moves."""
    c = self.configuration
    c.firmware_version, c.firmware_date = await self.request_firmware_version()

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

  def resolve_z_range(self, z_max: float) -> Tuple[float, float]:
    """The Z window this head reaches: a variant-derived floor, and a probed ceiling.

    Args:
      z_max: the top the hardware actually reached, from `retract`.

    Returns:
      The `(min, max)` window in mm, also recorded on the configuration.
    """
    c = self.configuration
    min_increments = 24200 if c.instrument_type == "FM-STAR" else 36100
    c.z_range = (round(min_increments * c.z_drive_mm_per_increment, 2), z_max)
    return c.z_range
