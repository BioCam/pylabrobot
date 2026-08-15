"""The autoload: the belt and wheel that pull carriers onto the deck and push them back out."""

import string
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, cast

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

# What kind of autoload is fitted, by the code the master answers with. Codes outside this are
# variants that have not been seen, and are returned as they came.
AUTOLOAD_TYPES: Dict[int, str] = {
  0: "1D barcode scanner",
  1: "XRP Lite",
  2: "2D barcode scanner",
}


def _tracks_from_presence_mask(mask: str) -> List[int]:
  """The tracks a carrier-presence mask marks as occupied.

  Args:
    mask: the mask as the machine writes it, one hexadecimal digit per four tracks, the rightmost
      digit holding tracks 1 to 4.

  Returns:
    The occupied tracks, counted from 1, in order.

  Raises:
    ValueError: If the mask is not hexadecimal.
  """
  mask = mask.strip()
  if mask == "" or any(character not in string.hexdigits for character in mask):
    raise ValueError(f"not a hexadecimal carrier presence mask: {mask!r}")
  return [
    digit_index * 4 + bit + 1
    for digit_index, digit in enumerate(reversed(mask))
    for bit in range(4)
    if int(digit, 16) & (1 << bit)
  ]


@dataclass
class AutoloadConfiguration:
  """Device facts for the installed autoload.

  Three drives: the scanner, which runs along the deck; the carrier Y drive, which pulls a carrier
  in and pushes it out; and the carrier Z drive, which raises and lowers the handling wheel. The
  ranges below are what each drive's move commands accept, in the steps they count in, and the
  defaults are what the commands use when a field is not given. They are the same across the 2015,
  2017, 2022 and 2025 firmware.
  """

  firmware_version: Optional[str] = None
  """The autoload's firmware version, as reported."""
  autoload_type: Optional[str] = None
  """Which kind of autoload is fitted, as named in `AUTOLOAD_TYPES`."""

  # -- scanner X drive (along the deck) --
  x_drive_mm_per_increment: float = 0.1
  """How far one step moves the scanner, in mm. Which of the two resolutions a unit has is held in
  its own memory: 0.1 as here, or 0.125 on a pilot-lot scanner."""
  x_drive_increment_range: Tuple[int, int] = (0, 12_500)
  """Absolute position range the scanner move accepts, in steps."""
  x_drive_speed_increment_range: Tuple[int, int] = (20, 3_000)
  """Speed range, in steps per second."""
  x_drive_speed_default: int = 2_500
  x_drive_acceleration_ramp_range: Tuple[int, int] = (1, 3)
  """Acceleration ramp range, in multiples of the shared ramp unit."""
  x_drive_acceleration_ramp_default: int = 3

  # -- carrier Z drive (the handling wheel, down or up) --
  z_drive_mm_per_increment: float = 0.004166666666666667
  """How far one step raises or lowers the handling wheel, in mm. The specification gives it as a
  repeating decimal, 0.0041666..., which is 1/240 exactly; this is that value."""
  z_drive_speed_increment_range: Tuple[int, int] = (20, 2_000)
  z_drive_speed_default: int = 1_750
  z_drive_acceleration_ramp_range: Tuple[int, int] = (1, 4)
  z_drive_acceleration_ramp_default: int = 4

  # -- carrier Y drive (in and out of the deck) --
  y_drive_mm_per_increment: float = 0.06404424
  """How far one step moves a carrier in or out, in mm."""
  y_drive_increment_range: Tuple[int, int] = (0, 9_999)
  """Absolute position range the carrier move accepts, in steps."""
  y_drive_speed_increment_range: Tuple[int, int] = (20, 2_500)
  y_drive_speed_default: int = 2_000
  y_drive_acceleration_ramp_range: Tuple[int, int] = (1, 6)
  y_drive_acceleration_ramp_default: int = 6

  # -- shared by all three drives --
  current_limit_range: Tuple[int, int] = (0, 7)
  """Motor current limit range, the same for every drive."""
  acceleration_ramp_increments_per_second_squared: int = 2_500
  """What one step of an acceleration ramp is worth, so a ramp setting can be read as an
  acceleration."""

  # -- conversions: the wire counts in steps, the driver speaks mm ---------------------------

  def x_drive_increments_to_mm(self, increments: int) -> float:
    """How far along the deck the scanner is, in mm, from the steps the drive counts in."""
    return round(increments * self.x_drive_mm_per_increment, 2)

  def x_drive_mm_to_increments(self, mm: float) -> int:
    """A scanner position in steps, from mm."""
    return round(mm / self.x_drive_mm_per_increment)

  def z_drive_increments_to_mm(self, increments: int) -> float:
    """How high the handling wheel is, in mm, from steps."""
    return round(increments * self.z_drive_mm_per_increment, 2)

  def z_drive_mm_to_increments(self, mm: float) -> int:
    """A wheel position in steps, from mm."""
    return round(mm / self.z_drive_mm_per_increment)

  def y_drive_increments_to_mm(self, increments: int) -> float:
    """How far in or out a carrier is, in mm, from the steps the drive counts in."""
    return round(increments * self.y_drive_mm_per_increment, 2)

  def y_drive_mm_to_increments(self, mm: float) -> int:
    """A carrier position in steps, from mm."""
    return round(mm / self.y_drive_mm_per_increment)


class Autoload:
  """The autoload.

  Reached as `driver.autoload`, on a machine that has one. It is addressed as `I0`, but the
  commands that raise its wheel go to the master, so this capability speaks to both.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[AutoloadConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the autoload's device facts. Defaults to `AutoloadConfiguration()`.
    """
    self._driver = driver
    self.configuration = configuration or AutoloadConfiguration()

  # -- session / discovery ---------------------------------------------------

  async def request_firmware_version(self) -> str:
    """Request the autoload's firmware version.

    Returns:
      The version string, as reported.
    """
    resp: str = await self._driver.send_command(module="I0", command="RF")
    return resp.split("rf")[-1]

  async def request_autoload_type(self) -> str:
    """Request which kind of autoload is fitted.

    Returns:
      What it is, as named in `AUTOLOAD_TYPES`, or the code it answered with when that is not one
      of them.
    """
    resp = await self._driver.send_command(module="C0", command="CQ", fmt="cq#")
    code = cast(int, resp["cq"])
    return AUTOLOAD_TYPES.get(code, str(code))

  async def discover(self):
    """Read what autoload this is. Read-only: nothing moves."""
    c = self.configuration
    c.firmware_version = await self.request_firmware_version()
    c.autoload_type = await self.request_autoload_type()

  # -- initialization --------------------------------------------------------

  async def initialize(self):
    """Initialize the autoload. This moves it."""
    return await self._driver.send_command(module="C0", command="II")

  # -- carrier handling ------------------------------------------------------

  @property
  def track_range(self) -> range:
    """The tracks it can be moved to, which is the deck it runs along.

    Raises:
      RuntimeError: If setup has not run, so the deck size is not known.
    """
    if self._driver.configuration is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    return range(1, self._driver.configuration.instrument_size_slots + 1)

  async def request_track(self) -> int:
    """Request which track the autoload is at.

    Returns:
      The track, counted from 1, or 0 when it is at neither end of a track.
    """
    resp = await self._driver.send_command(module="C0", command="QA", fmt="qa##")
    return cast(int, resp["qa"])

  async def request_x_position(self) -> float:
    """Request where along the deck the scanner is.

    Returns:
      The position in mm, from the drive's zero.
    """
    return self.configuration.x_drive_increments_to_mm(
      await self._request_drive_position("RX", digits=5)
    )

  async def request_y_position(self) -> float:
    """Request how far in or out the carrier drive is.

    Returns:
      The position in mm, from the drive's zero.
    """
    return self.configuration.y_drive_increments_to_mm(
      await self._request_drive_position("RY", digits=4)
    )

  async def request_z_position(self) -> float:
    """Request how high the carrier-handling wheel is.

    Returns:
      The position in mm, from the drive's zero.
    """
    return self.configuration.z_drive_increments_to_mm(
      await self._request_drive_position("RZ", digits=4)
    )

  async def _request_drive_position(self, command: str, digits: int) -> int:
    """Where one of the three drives is, in the steps it counts in.

    Each answers with two counters: the one the firmware keeps, and the one read off the hardware.
    The hardware counter is where the drive actually is, so that is the one returned, as the other
    position reads on this machine do.

    Args:
      command: the read to send, which names the drive.
      digits: how many digits each counter is written with.
    """
    field = command.lower()
    resp = await self._driver.send_command(
      module="I0", command=command, fmt=f"{field}{'#' * digits} (n)"
    )
    _firmware_counter, hardware_counter = cast(List[int], resp[field])
    return hardware_counter

  async def sense_carrier_presence_on_deck(self) -> List[int]:
    """Request which deck tracks hold a carrier, read by the sensors along the back of the deck.

    Nothing moves: the sensors see the whole deck at once.

    Returns:
      The tracks that hold a carrier, counted from 1.

    Raises:
      ValueError: If the machine answered without a presence mask.
    """
    resp = cast(str, await self._driver.send_command(module="C0", command="RC"))
    return _tracks_from_presence_mask(self._presence_mask(resp, "ce"))

  async def sense_carrier_presence_on_loading_tray(self) -> List[int]:
    """Request which loading-tray tracks hold a carrier.

    This moves: the autoload runs the length of the tray, reading the sensor on its front as it
    goes.

    Returns:
      The tracks that hold a carrier, counted from 1.

    Raises:
      ValueError: If the machine answered without a presence mask.
    """
    resp = cast(str, await self._driver.send_command(module="C0", command="CS"))
    return _tracks_from_presence_mask(self._presence_mask(resp, "cd"))

  async def request_carrier_on_loading_tray(self, track: int) -> bool:
    """Request whether one loading-tray track holds a carrier.

    This moves: the autoload travels to that track and reads the sensor on its front. Reading the
    whole tray in one pass is `request_carriers_on_loading_tray`.

    Args:
      track: which track to look at, counted from 1.

    Returns:
      True if a carrier is there.

    Raises:
      ValueError: If the track is not one this machine has.
      RuntimeError: If setup has not run.
    """
    tracks = self.track_range
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")
    resp = await self._driver.send_command(module="C0", command="CT", fmt="ct#", cp=f"{track:02}")
    return cast(int, resp["ct"]) == 1

  @staticmethod
  def _presence_mask(resp: str, marker: str) -> str:
    """The carrier-presence mask out of a reply, as the part written after `marker`."""
    if marker not in resp:
      raise ValueError(f"no `{marker}` carrier presence mask in the reply: {resp!r}")
    return resp.split(marker, 1)[1]

  async def move_to_safe_z(self):
    """Raise the carrier-handling wheel to its safe Z.

    Nothing may travel along the deck with the wheel down, so this comes before any move along
    the tracks.
    """
    return await self._driver.send_command(module="C0", command="IV")

  async def move_to_track(
    self,
    track: int,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the autoload along the deck to a track, raising the wheel first.

    Args:
      track: which track to move to, counted from 1.
      speed: how fast to travel, in steps per second. Left out of the command when not given, so
        the drive uses its own default.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Left out when not given.
      current_limit: the motor current limit. Left out when not given.

    Raises:
      ValueError: If the track is not one this machine has, or an argument is outside what the
        drive accepts.
      RuntimeError: If setup has not run.
    """
    c = self.configuration
    tracks = self.track_range
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")

    # Each field is sent only when it is given, so a plain move is the command the machine has
    # always been sent, and the drive applies its own defaults to the rest.
    fields: Dict[str, str] = {"xp": f"{track:02}"}
    for name, field, value, width, (low, high) in (
      ("speed", "xv", speed, 4, c.x_drive_speed_increment_range),
      ("acceleration_ramp", "xr", acceleration_ramp, 1, c.x_drive_acceleration_ramp_range),
      ("current_limit", "xw", current_limit, 1, c.current_limit_range),
    ):
      if value is None:
        continue
      if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}, is {value}")
      fields[field] = f"{value:0{width}}"

    await self.move_to_safe_z()
    # The fields are firmware parameters, not this method's own arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="XP", **fields)  # type: ignore[arg-type]

  async def park(self):
    """Move the autoload out of the way, to the far end of the deck."""
    await self.move_to_track(self.track_range[-1])
