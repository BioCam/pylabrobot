"""The autoload: the belt and wheel that pull carriers onto the deck and push them back out."""

import logging
import string
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, cast, get_args

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

# Where the carrier drive can be sent by name.
YPosition = Literal["loading_tray", "carrier_identification", "deck"]

ZPosition = Literal["below", "above"]

ScannerRotation = Literal["vertical", "horizontal", "undefined"]

BARCODE_TYPES: Dict[str, int] = {
  "isbt_standard": 0,
  "code_128": 1,
  "code_39": 2,
  "codabar": 3,
  "code_2of5_interleaved": 4,
  "upc_a_e": 5,
  "jan_ean_8": 6,
}

BarcodeReadingDirection = Literal["vertical", "horizontal"]

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
  defaults are what the commands use when a parameter is not given. They are the same across the
  2015, 2017, 2022 and 2025 firmware.
  """

  firmware_version: Optional[str] = None
  autoload_type: Optional[str] = None  # see AUTOLOAD_TYPES

  # -- scanner X drive (along the deck) --
  x_drive_mm_per_increment: float = 0.1
  """How far one step moves the scanner, in mm. Which of the two resolutions a unit has is held in
  its own memory: 0.1 as here, or 0.125 on a pilot-lot scanner."""
  x_drive_increment_range: Tuple[int, int] = (0, 12_500)
  x_drive_speed_increment_range: Tuple[int, int] = (20, 3_000)  # steps per second
  x_drive_speed_default: int = 2_500
  x_drive_acceleration_ramp_range: Tuple[int, int] = (1, 3)
  x_drive_acceleration_ramp_default: int = 3

  # -- carrier Z drive (the handling wheel, down or up) --
  z_drive_mm_per_increment: float = 0.004166666666666667
  z_drive_increment_range: Tuple[int, int] = (0, 3_000)
  z_drive_speed_increment_range: Tuple[int, int] = (20, 2_000)
  z_drive_speed_default: int = 1_750
  z_drive_acceleration_ramp_range: Tuple[int, int] = (1, 4)
  z_drive_acceleration_ramp_default: int = 4
  z_drive_safety_position: Optional[float] = None

  # -- carrier Y drive (in and out of the deck) --
  y_drive_mm_per_increment: float = 0.06404424
  y_drive_increment_range: Tuple[int, int] = (0, 9_999)
  y_drive_speed_increment_range: Tuple[int, int] = (20, 2_500)
  y_drive_speed_default: int = 2_000
  y_drive_acceleration_ramp_range: Tuple[int, int] = (1, 6)
  y_drive_acceleration_ramp_default: int = 6

  # -- shared by all three drives --
  motor_current_limit_range: Tuple[int, int] = (0, 7)  # same for every drive
  motor_current_limit_default: int = 7
  acceleration_ramp_increments_per_second_squared: int = 2_500

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
  commands that move it and the ones that read the deck go to the master, so this capability
  speaks to both.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[AutoloadConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the autoload's device facts. Defaults to `AutoloadConfiguration()`.
    """
    self._driver = driver
    self.configuration = configuration or AutoloadConfiguration()

  @property
  def track_range(self) -> range:
    """The tracks it can be moved to, one for each slot the instrument has.

    Raises:
      RuntimeError: If setup has not run, so the deck size is not known.
    """
    if self._driver.configuration is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    return range(1, self._driver.configuration.instrument_size_slots + 1)

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

  async def request_initialization_status(self) -> bool:
    """Request whether the autoload reports itself initialized.

    Returns:
      Whether it is initialized. It reports itself uninitialized again once the instrument's own
      initialization has run.
    """
    resp = await self._driver.send_command(module="I0", command="QW", fmt="qw#")
    return cast(int, resp["qw"]) == 1

  async def discover(self):
    """Read what autoload this is. Read-only: nothing moves."""
    c = self.configuration
    c.firmware_version = await self.request_firmware_version()
    c.autoload_type = await self.request_autoload_type()

  # -- initialization --------------------------------------------------------

  async def initialize(self):
    """Initialize the autoload and everything else that makes it operational. This moves it.

    Homing is skipped when it already reports itself initialized, so this can be called on any
    machine. The rest runs either way: the wheel goes to its safe Z, and the height it comes to
    rest at is read, which no command reports directly.
    """
    if not await self.request_initialization_status():
      logger.debug("autoload reports itself uninitialized - homing its drives")
      await self._driver.send_command(module="C0", command="II")
    await self.move_to_safe_z()
    self.configuration.z_drive_safety_position = await self.request_z_position()

  # -- carrier handling ------------------------------------------------------

  async def request_track(self) -> int:
    """Request the current track of the autoload's carrier handler.

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

  async def _request_drive_position(self, command: str, digits: int) -> int:
    """Where one of the three drives is, in the steps it counts in.

    Each answers with two counters: the one the firmware keeps, and the one read off the hardware.
    The hardware counter is the one returned.

    Args:
      command: the read to send, which names the drive.
      digits: how many digits each counter is written with.

    Returns:
      The hardware counter, in the drive's own steps.
    """
    field = command.lower()
    resp = await self._driver.send_command(
      module="I0", command=command, fmt=f"{field}{'#' * digits} (n)"
    )
    _firmware_counter, hardware_counter = cast(List[int], resp[field])
    return hardware_counter

  # -- (carrier) handling wheel --------------------------------------------------------------

  async def request_z_position(self) -> float:
    """Request how high the carrier-handling wheel is.

    Returns:
      The position in mm, from the drive's zero.
    """
    return self.configuration.z_drive_increments_to_mm(
      await self._request_drive_position("RZ", digits=4)
    )

  async def move_to_safe_z(self):
    """Move the carrier-handling wheel to its safe Z position."""
    return await self._driver.send_command(module="C0", command="IV")

  async def move_z(
    self,
    z: float,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the carrier-handling wheel to a Z position.

    Args:
      z: how high to move it, in mm from the drive's zero.
      speed: how fast to travel, in steps per second. Defaults to
        `configuration.z_drive_speed_default`.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Defaults to
        `configuration.z_drive_acceleration_ramp_default`.
      current_limit: the motor current limit. Defaults to
        `configuration.motor_current_limit_default`.

    Raises:
      ValueError: If the position, or an argument, is outside what the drive accepts.
    """
    c = self.configuration
    increments = c.z_drive_mm_to_increments(z)
    low, high = c.z_drive_increment_range
    if not low <= increments <= high:
      raise ValueError(
        f"z must be between {c.z_drive_increments_to_mm(low)} and "
        f"{c.z_drive_increments_to_mm(high)} mm, is {z}"
      )

    # Every parameter is sent, so what the drive does is written here rather than left to the
    # drive's own defaults, which nothing would record.
    speed = c.z_drive_speed_default if speed is None else speed
    acceleration_ramp = (
      c.z_drive_acceleration_ramp_default if acceleration_ramp is None else acceleration_ramp
    )
    current_limit = c.motor_current_limit_default if current_limit is None else current_limit

    low, high = c.z_drive_speed_increment_range
    if not low <= speed <= high:
      raise ValueError(f"speed must be between {low} and {high}, is {speed}")

    low, high = c.z_drive_acceleration_ramp_range
    if not low <= acceleration_ramp <= high:
      raise ValueError(
        f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
      )

    low, high = c.motor_current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    return await self._driver.send_command(
      module="I0",
      command="ZA",
      za=f"{increments:04}",
      zv=f"{speed:04}",
      zr=f"{acceleration_ramp:01}",
      zw=f"{current_limit:01}",
    )

  async def move_to_z_position(
    self,
    position: ZPosition,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the carrier-handling wheel to one of the two positions it knows.

    Args:
      position: which one: `below` or `above`.
      speed: how fast to travel, in steps per second. Defaults to
        `configuration.z_drive_speed_default`.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Defaults to
        `configuration.z_drive_acceleration_ramp_default`.
      current_limit: the motor current limit. Defaults to
        `configuration.motor_current_limit_default`.

    Raises:
      ValueError: If the position is not one it knows, or an argument is outside what the drive
        accepts.
    """
    c = self.configuration
    if position not in get_args(ZPosition):
      raise ValueError(f"position must be one of {list(get_args(ZPosition))}, is {position!r}")

    # Every parameter is sent, so what the drive does is written here rather than left to the
    # drive's own defaults, which nothing would record.
    speed = c.z_drive_speed_default if speed is None else speed
    acceleration_ramp = (
      c.z_drive_acceleration_ramp_default if acceleration_ramp is None else acceleration_ramp
    )
    current_limit = c.motor_current_limit_default if current_limit is None else current_limit

    low, high = c.z_drive_speed_increment_range
    if not low <= speed <= high:
      raise ValueError(f"speed must be between {low} and {high}, is {speed}")

    low, high = c.z_drive_acceleration_ramp_range
    if not low <= acceleration_ramp <= high:
      raise ValueError(
        f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
      )

    low, high = c.motor_current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    return await self._driver.send_command(
      module="I0",
      command="ZP",
      zp="0" if position == "below" else "1",
      zv=f"{speed:04}",
      zr=f"{acceleration_ramp:01}",
      zw=f"{current_limit:01}",
    )

  async def request_y_position(self) -> float:
    """Request how far in or out the carrier drive is.

    Returns:
      The position in mm, from the drive's zero.
    """
    return self.configuration.y_drive_increments_to_mm(
      await self._request_drive_position("RY", digits=4)
    )

  async def move_y(
    self,
    y: float,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the carrier drive to a Y position, pulling a carrier in or pushing it out.

    Args:
      y: how far to move it, in mm from the drive's zero.
      speed: how fast to travel, in steps per second. Defaults to
        `configuration.y_drive_speed_default`.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Defaults to
        `configuration.y_drive_acceleration_ramp_default`.
      current_limit: the motor current limit. Defaults to
        `configuration.motor_current_limit_default`.

    Raises:
      ValueError: If the position, or an argument, is outside what the drive accepts.
    """
    c = self.configuration
    increments = c.y_drive_mm_to_increments(y)
    low, high = c.y_drive_increment_range
    if not low <= increments <= high:
      raise ValueError(
        f"y must be between {c.y_drive_increments_to_mm(low)} and "
        f"{c.y_drive_increments_to_mm(high)} mm, is {y}"
      )

    # Every parameter is sent, so what the drive does is written here rather than left to the
    # drive's own defaults, which nothing would record.
    speed = c.y_drive_speed_default if speed is None else speed
    acceleration_ramp = (
      c.y_drive_acceleration_ramp_default if acceleration_ramp is None else acceleration_ramp
    )
    current_limit = c.motor_current_limit_default if current_limit is None else current_limit

    low, high = c.y_drive_speed_increment_range
    if not low <= speed <= high:
      raise ValueError(f"speed must be between {low} and {high}, is {speed}")

    low, high = c.y_drive_acceleration_ramp_range
    if not low <= acceleration_ramp <= high:
      raise ValueError(
        f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
      )

    low, high = c.motor_current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    return await self._driver.send_command(
      module="I0",
      command="YA",
      ya=f"{increments:04}",
      yv=f"{speed:04}",
      yr=f"{acceleration_ramp:01}",
      yw=f"{current_limit:01}",
    )

  async def move_to_y_position(
    self,
    position: YPosition,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the carrier drive to one of the three positions it knows.

    Args:
      position: which one: `loading_tray`, `carrier_identification` or `deck`.
      speed: how fast to travel, in steps per second. Defaults to
        `configuration.y_drive_speed_default`.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Defaults to
        `configuration.y_drive_acceleration_ramp_default`.
      current_limit: the motor current limit. Defaults to
        `configuration.motor_current_limit_default`.

    Raises:
      ValueError: If the position is not one it knows, or an argument is outside what the drive
        accepts.
    """
    c = self.configuration
    if position not in get_args(YPosition):
      raise ValueError(f"position must be one of {list(get_args(YPosition))}, is {position!r}")

    # Every parameter is sent, so what the drive does is written here rather than left to the
    # drive's own defaults, which nothing would record.
    speed = c.y_drive_speed_default if speed is None else speed
    acceleration_ramp = (
      c.y_drive_acceleration_ramp_default if acceleration_ramp is None else acceleration_ramp
    )
    current_limit = c.motor_current_limit_default if current_limit is None else current_limit

    low, high = c.y_drive_speed_increment_range
    if not low <= speed <= high:
      raise ValueError(f"speed must be between {low} and {high}, is {speed}")

    low, high = c.y_drive_acceleration_ramp_range
    if not low <= acceleration_ramp <= high:
      raise ValueError(
        f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
      )

    low, high = c.motor_current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")
    return await self._driver.send_command(
      module="I0",
      command="YP",
      yp="0"
      if position == "loading_tray"
      else "1"
      if position == "carrier_identification"
      else "2",
      yv=f"{speed:04}",
      yr=f"{acceleration_ramp:01}",
      yw=f"{current_limit:01}",
    )

  # -- scanner rotation drive ----------------------------------------------------------------

  async def request_scanner_rotation(self) -> ScannerRotation:
    """Request which way the scanner faces.

    Returns:
      Which way it faces, or `undefined` when it sits at neither of the two stops.
    """
    resp = await self._driver.send_command(module="I0", command="RS", fmt="rs#")
    code = cast(int, resp["rs"])
    return "vertical" if code == 0 else "horizontal" if code == 1 else "undefined"

  async def move_scanner_rotation(self, position: ScannerRotation, stop_torque: bool = False):
    """Rotate the scanner to face one way or the other.

    Args:
      position: which way to face. Only the two stops can be moved to, so `undefined` is refused.
      stop_torque: whether to hold the drive there once it arrives. The drive's own default is
        not to.

    Raises:
      ValueError: If the position is not one that can be moved to.
    """
    if position not in ("vertical", "horizontal"):
      raise ValueError(f"position must be 'vertical' or 'horizontal', is {position!r}")

    return await self._driver.send_command(
      module="I0",
      command="SP",
      sp="0" if position == "vertical" else "1",
      sh=f"{int(stop_torque):01}",
    )

  # -- barcode scanner -------------------------------------------------------------------------

  async def request_barcode(self) -> Optional[str]:
    """Request the barcode the scanner last read.

    Returns:
      What it read, or None when it read nothing.
    """
    resp = cast(str, await self._driver.send_command(module="I0", command="RB"))
    barcode = resp.split("rb", 1)[-1].strip().strip("'")
    return barcode or None

  async def set_barcode_scanner_enabled(
    self, enabled: bool, barcode_types: Optional[List[str]] = None
  ):
    """Switch the barcode scanner on or off. Switching it on is what reads a barcode.

    Args:
      enabled: whether to switch it on.
      barcode_types: which types to read, as named in `BARCODE_TYPES`. Defaults to
        `BARCODE_TYPES.keys()`.

    Raises:
      ValueError: If a type is not one it reads.
    """
    barcode_types = list(BARCODE_TYPES.keys()) if barcode_types is None else barcode_types
    unknown = [name for name in barcode_types if name not in BARCODE_TYPES]
    if unknown:
      raise ValueError(f"not barcode types the scanner reads: {unknown}")
    mask = sum(1 << BARCODE_TYPES[name] for name in barcode_types)

    return await self._driver.send_command(
      module="I0", command="AR", ar=f"{int(enabled):01}", bt=f"{mask:02X}"
    )

  async def reset_barcode_scanner(self):
    """Reset the barcode scanner."""
    return await self._driver.send_command(module="I0", command="AF")

  # -- carrier identification ------------------------------------------------------------------

  async def set_barcode_type(self, barcode_types: List[str]):
    """Set the barcode types for autoload barcode reading.

    Args:
      barcode_types: which types to read, as named in `BARCODE_TYPES`.

    Raises:
      ValueError: If a type is not one it reads.
    """
    unknown = [name for name in barcode_types if name not in BARCODE_TYPES]
    if unknown:
      raise ValueError(f"not barcode types the scanner reads: {unknown}")
    mask = sum(1 << BARCODE_TYPES[name] for name in barcode_types)
    return await self._driver.send_command(module="C0", command="CB", bt=f"{mask:02X}")

  async def load_carrier_from_tray_and_scan_carrier_barcode(
    self,
    track: int,
    barcode_position: float = 4.3,
    barcode_reading_window_width: float = 38.0,
    container_distance: float = 96.0,
    reading_speed: float = 128.1,
  ) -> Optional[str]:
    """Load a carrier from the loading tray and scan its barcode.

    `unload_carrier_after_carrier_barcode_scanning` puts it back on the tray.

    Args:
      track: the track the carrier ends at, counted from 1.
      barcode_position: where along the carrier its barcode sits, in mm.
      barcode_reading_window_width: how wide a window to read it in, in mm.
      container_distance: the spacing of the pattern to read, in mm.
      reading_speed: how fast to travel while reading, in mm/s.

    Returns:
      The barcode, or None when nothing was read.

    Raises:
      ValueError: If the track is not one this machine has, or an argument is outside what the
        command accepts.
      RuntimeError: If setup has not run.
    """
    tracks = self.track_range
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")
    if not 0 <= barcode_position <= 470:
      raise ValueError(f"barcode_position must be between 0 and 470 mm, is {barcode_position}")
    if not 0.1 <= barcode_reading_window_width <= 99.9:
      raise ValueError(
        "barcode_reading_window_width must be between 0.1 and 99.9 mm, is "
        f"{barcode_reading_window_width}"
      )
    if not 1.5 <= reading_speed <= 160.0:
      raise ValueError(f"reading_speed must be between 1.5 and 160.0 mm/s, is {reading_speed}")

    try:
      resp = cast(
        str,
        await self._driver.send_command(
          module="C0",
          command="CI",
          cp=f"{track:02}",
          bi=f"{round(barcode_position * 10):04}",
          bw=f"{round(barcode_reading_window_width * 10):03}",
          co=f"{round(container_distance * 10):04}",
          cv=f"{round(reading_speed * 10):04}",
        ),
      )
    except BaseException:
      # The wheel is left wherever the failure stopped it, and nothing may travel with it down.
      await self.move_to_safe_z()
      raise

    if "bb/" not in resp:
      return None
    # What follows the marker is the barcode's length written in two digits, then the barcode.
    read = resp.split("bb/", 1)[1].strip().strip("'")
    return read[2:] or None

  async def unload_carrier_after_carrier_barcode_scanning(self):
    """Unload the carrier currently engaged with the autoload sled, back to the loading tray.

    Sent after its barcode has been scanned.
    """
    try:
      return await self._driver.send_command(module="C0", command="CA")
    except BaseException:
      await self.move_to_safe_z()
      raise

  async def take_carrier_out_to_autoload_belt(self, track: int):
    """Take a carrier out to the identification position for barcode reading.

    The carrier is already on the deck.

    Args:
      track: the track the carrier sits at, counted from 1.

    Raises:
      ValueError: If the track is not one this machine has, or its carrier is on the loading tray
        rather than the deck.
      RuntimeError: If setup has not run.
    """
    tracks = self.track_range
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")
    if await self.request_carrier_on_loading_tray(track):
      raise ValueError(f"the carrier at track {track} is on the loading tray, not the deck")

    try:
      return await self._driver.send_command(module="C0", command="CN", cp=f"{track:02}")
    except BaseException:
      # The wheel is left wherever the failure stopped it, and nothing may travel with it down.
      await self.move_to_safe_z()
      raise

  async def load_carrier_from_autoload_belt(
    self,
    barcode_reading: bool = False,
    barcode_reading_direction: BarcodeReadingDirection = "horizontal",
    reading_position_of_first_barcode: float = 63.0,
    containers_per_carrier: int = 5,
    distance_between_containers: float = 96.0,
    width_of_reading_window: float = 38.0,
    reading_speed: float = 128.1,
    park_after: bool = True,
  ) -> Dict[int, Optional[str]]:
    """Finish loading the carrier currently engaged with the autoload sled.

    It is the one at the identification position. Which barcode types are read is whatever
    `set_barcode_type` last set.

    Args:
      barcode_reading: whether to read the containers at all. When False the scanner stays where it
        is and nothing is read.
      barcode_reading_direction: which way the scanner faces while reading: `vertical` or
        `horizontal`.
      reading_position_of_first_barcode: where along the carrier the first container's barcode
        sits, in mm.
      containers_per_carrier: how many containers to read.
      distance_between_containers: how far apart they sit, in mm.
      width_of_reading_window: how wide a window to read each in, in mm.
      reading_speed: how fast to travel while reading, in mm/s.
      park_after: whether to park the autoload once the carrier is in.

    Returns:
      Each container's barcode by position, counted from 0, and None where nothing was read. Empty
      when `barcode_reading` is False.

    Raises:
      ValueError: If an argument is outside what the command accepts, or fewer barcodes come back
        than were asked for.
      RuntimeError: If setup has not run and the autoload has to be parked.
    """
    if barcode_reading_direction not in get_args(BarcodeReadingDirection):
      raise ValueError(
        f"barcode_reading_direction must be one of {list(get_args(BarcodeReadingDirection))}, is "
        f"{barcode_reading_direction!r}"
      )
    if not 0 <= reading_position_of_first_barcode <= 470:
      raise ValueError(
        "reading_position_of_first_barcode must be between 0 and 470 mm, is "
        f"{reading_position_of_first_barcode}"
      )
    if not 0 <= containers_per_carrier <= 32:
      raise ValueError(
        f"containers_per_carrier must be between 0 and 32, is {containers_per_carrier}"
      )
    if not 0 <= distance_between_containers <= 470:
      raise ValueError(
        f"distance_between_containers must be between 0 and 470 mm, is {distance_between_containers}"
      )
    if not 0.1 <= width_of_reading_window <= 99.9:
      raise ValueError(
        f"width_of_reading_window must be between 0.1 and 99.9 mm, is {width_of_reading_window}"
      )
    if not 1.5 <= reading_speed <= 160.0:
      raise ValueError(f"reading_speed must be between 1.5 and 160.0 mm/s, is {reading_speed}")

    # Reading nothing is asked for by facing the scanner away and asking for no containers, so the
    # carrier travels in without the scanner moving.
    direction = "vertical" if not barcode_reading else barcode_reading_direction
    containers = containers_per_carrier if barcode_reading else 0

    try:
      resp = cast(
        str,
        await self._driver.send_command(
          module="C0",
          command="CL",
          bd="0" if direction == "vertical" else "1",
          bp=f"{round(reading_position_of_first_barcode * 10):04}",
          cn=f"{containers:02}",
          co=f"{round(distance_between_containers * 10):04}",
          cf=f"{round(width_of_reading_window * 10):03}",
          cv=f"{round(reading_speed * 10):04}",
        ),
      )
    except BaseException:
      await self.move_to_safe_z()
      raise

    if park_after:
      await self.park()

    if not barcode_reading:
      return {}

    read = resp.split("bb/")[-1].split("/")
    if len(read) < containers_per_carrier:
      raise ValueError(
        f"asked for {containers_per_carrier} barcodes, {len(read)} came back: {resp!r}"
      )
    return {
      position: None if read[position] == "00" else read[position]
      for position in range(containers_per_carrier)
    }

  async def unload_carrier(self, track: int, park_after: bool = True):
    """Use the autoload to unload the carrier at a track.

    Args:
      track: the track the carrier sits at, counted from 1.
      park_after: whether to park the autoload once the carrier is out.

    Raises:
      ValueError: If the track is not one this machine has.
      RuntimeError: If setup has not run.
    """
    tracks = self.track_range
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")

    resp = await self._driver.send_command(module="C0", command="CR", cp=f"{track:02}")
    if park_after:
      await self.park()
    return resp

  async def unload_carrier_finally(self, track: int, park_after: bool = True):
    """Unload the carrier at a track, from where it cannot be loaded again.

    Args:
      track: the track the carrier sits at, counted from 1.
      park_after: whether to park the autoload once the carrier is out.

    Raises:
      ValueError: If the track is not one this machine has.
      RuntimeError: If setup has not run.
    """
    tracks = self.track_range
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")

    resp = await self._driver.send_command(module="C0", command="CW", cp=f"{track:02}")
    if park_after:
      await self.park()
    return resp

  # TODO: port legacy's `load_carrier`, once the resource model is wired in. It is the sequence
  # below, in v1 terms, and every command it needs is already here. What is missing is the first
  # line: legacy works the end rail out of a `Carrier`'s position on the deck
  # (`_compute_end_rail_of_carrier`), and the driver has no resource model to ask.
  #
  # async def load_carrier(
  #   self,
  #   carrier,
  #   carrier_barcode_reading: bool = True,
  #   barcode_reading: bool = False,
  #   barcode_reading_direction: BarcodeReadingDirection = "horizontal",
  #   containers_per_carrier: int = 5,
  #   reading_position_of_first_barcode: float = 63.0,
  #   distance_between_containers: float = 96.0,
  #   width_of_reading_window: float = 38.0,
  #   reading_speed: float = 128.1,
  #   park_after: bool = True,
  # ) -> dict:
  #   """Use the autoload to load a carrier."""
  #   track = ...  # the rail the carrier ends at, from where it sits on the deck
  #   if not await self.request_carrier_on_loading_tray(track):
  #     raise ValueError(f"no carrier at track {track}; is it on the right loading tray position?")
  #
  #   carrier_barcode = None
  #   if carrier_barcode_reading:
  #     carrier_barcode = await self.load_carrier_from_tray_and_scan_carrier_barcode(track)
  #
  #   container_barcodes = await self.load_carrier_from_autoload_belt(
  #     barcode_reading=barcode_reading,
  #     barcode_reading_direction=barcode_reading_direction,
  #     reading_position_of_first_barcode=reading_position_of_first_barcode,
  #     containers_per_carrier=containers_per_carrier,
  #     distance_between_containers=distance_between_containers,
  #     width_of_reading_window=width_of_reading_window,
  #     reading_speed=reading_speed,
  #     park_after=False,
  #   )
  #
  #   if park_after:
  #     await self.park()
  #
  #   return {"carrier_barcode": carrier_barcode, "container_barcodes": container_barcodes}

  # -- loading indicators ----------------------------------------------------------------------

  async def set_loading_indicators(self, lit: List[bool], blinking: List[bool]):
    """Set the loading indicators (LEDs), one per track.

    Args:
      lit: whether each track's light is on, counted from track 1.
      blinking: whether each track's light blinks rather than stays steady.

    Raises:
      ValueError: If either pattern does not have one entry per track.
      RuntimeError: If setup has not run, so the deck size is not known.
    """
    tracks = len(self.track_range)
    for name, pattern in (("lit", lit), ("blinking", blinking)):
      if len(pattern) != tracks:
        raise ValueError(f"{name} must have {tracks} entries, one per track, has {len(pattern)}")

    def as_hex(pattern: List[bool]) -> str:
      bits = "".join("1" if on else "0" for on in pattern)
      return f"{int(bits, base=2):014X}"

    return await self._driver.send_command(
      module="C0", command="CP", cl=as_hex(lit), cb=as_hex(blinking)
    )

  # -- higher-level sled movement --------------------------------------------------------------

  async def move_to_track(
    self,
    track: int,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the autoload to a specific track position, raising the wheel first.

    Args:
      track: which track to move to, counted from 1.
      speed: how fast to travel, in steps per second. Defaults to
        `configuration.x_drive_speed_default`.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Defaults to
        `configuration.x_drive_acceleration_ramp_default`.
      current_limit: the motor current limit. Defaults to
        `configuration.motor_current_limit_default`.

    Raises:
      ValueError: If the track is not one this machine has, or an argument is outside what the
        drive accepts.
      RuntimeError: If setup has not run.
    """
    c = self.configuration
    tracks = self.track_range

    # -- precondition checks ----------------------------------------------------------------------
    if track not in tracks:
      raise ValueError(f"track must be between {tracks[0]} and {tracks[-1]}, is {track}")

    # -- parameter resolution ----------------------------------------------------------------------
    speed = c.x_drive_speed_default if speed is None else speed
    acceleration_ramp = (
      c.x_drive_acceleration_ramp_default if acceleration_ramp is None else acceleration_ramp
    )
    current_limit = c.motor_current_limit_default if current_limit is None else current_limit

    # -- parameter validation ----------------------------------------------------------------------
    low, high = c.x_drive_speed_increment_range
    if not low <= speed <= high:
      raise ValueError(f"speed must be between {low} and {high}, is {speed}")

    low, high = c.x_drive_acceleration_ramp_range
    if not low <= acceleration_ramp <= high:
      raise ValueError(
        f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
      )

    low, high = c.motor_current_limit_range
    if not low <= current_limit <= high:
      raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")

    # -- device preparation ----------------------------------------------------------------------
    current_wheel_z = await self.request_z_position()
    if c.z_drive_safety_position is not None and current_wheel_z < c.z_drive_safety_position:
      logger.debug(
        "retracting the handling wheel to its safe Z %.3f mm before moving to track %d",
        c.z_drive_safety_position,
        track,
      )
      await self.move_to_safe_z()

    return await self._driver.send_command(
      module="I0",
      command="XP",
      xp=f"{track:02}",
      xv=f"{speed:04}",
      xr=f"{acceleration_ramp:01}",
      xw=f"{current_limit:01}",
    )

  async def park(self):
    """Park the autoload at the last track this machine has.

    Raises:
      RuntimeError: If setup has not run, so the deck size is not known.
    """
    await self.move_to_safe_z()
    return await self._driver.send_command(
      module="I0", command="XP", xp=f"{self.track_range[-1]:02}"
    )

  # -- carrier presence sensing --------------------------------------------------------------

  @staticmethod
  def _presence_mask(resp: str, marker: str) -> str:
    """The carrier-presence mask in a reply: what is written after `marker`."""
    if marker not in resp:
      raise ValueError(f"no `{marker}` carrier presence mask in the reply: {resp!r}")
    return resp.split(marker, 1)[1]

  async def sense_carrier_presence_on_deck(self) -> List[int]:
    """Read the rear deck sensors and return the positions where carriers are detected.

    The autoload does not move.

    Returns:
      The tracks that hold a carrier, counted from 1.

    Raises:
      ValueError: If the machine answered without a presence mask.
    """
    resp = cast(str, await self._driver.send_command(module="C0", command="RC"))
    return _tracks_from_presence_mask(self._presence_mask(resp, "ce"))

  async def request_carrier_on_loading_tray(self, track: int) -> bool:
    """Check whether a specific loading-tray track contains a carrier.

    The sled moves to that track and reads its front-facing sensor.
    `sense_carrier_presence_on_loading_tray` scans the whole tray instead.

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

  async def sense_carrier_presence_on_loading_tray(self) -> List[int]:
    """Move the autoload sled across the loading tray and read its front-facing sensors.

    This determines which tray positions contain carriers.

    Returns:
      The tracks that hold a carrier, counted from 1.

    Raises:
      ValueError: If the machine answered without a presence mask.
    """
    resp = cast(str, await self._driver.send_command(module="C0", command="CS"))
    return _tracks_from_presence_mask(self._presence_mask(resp, "cd"))
