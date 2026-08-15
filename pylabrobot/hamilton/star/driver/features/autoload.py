"""The autoload: the belt and wheel that pull carriers onto the deck and push them back out."""

import logging
import string
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, cast

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

# Where the carrier drive can be sent by name, and the code the command takes for each. At the
# deck it stops on the sensor rail rather than at a distance, so it ends up in the same place
# whatever the carrier.
YPosition = Literal["loading_tray", "carrier_identification", "deck"]
Y_POSITIONS: Dict[str, int] = {"loading_tray": 0, "carrier_identification": 1, "deck": 2}

# Where the handling wheel can be sent by name, and the code the command takes for each.
ZPosition = Literal["below", "above"]
Z_POSITIONS: Dict[str, int] = {"below": 0, "above": 1}

# Which way the scanner faces, by the code the drive answers with. It reports itself undefined when
# it is at neither stop; the move only takes the other two.
ScannerRotation = Literal["vertical", "horizontal", "undefined"]
SCANNER_ROTATIONS: Dict[int, ScannerRotation] = {0: "vertical", 1: "horizontal", 2: "undefined"}

# Which barcode types the scanner will read, and the bit each holds in the mask that switching it
# on takes. Code 93 is read whether or not its bit is set.
BARCODE_TYPES: Dict[str, int] = {
  "isbt_standard": 0,
  "code_128": 1,
  "code_39": 2,
  "codabar": 3,
  "code_2of5_interleaved": 4,
  "upc_a_e": 5,
  "jan_ean_8": 6,
  "code_93": 7,
}

# Which way the scanner faces while it reads a carrier's containers, and the code the load takes.
BarcodeReadingDirection = Literal["vertical", "horizontal"]
BARCODE_READING_DIRECTIONS: Dict[str, int] = {"vertical": 0, "horizontal": 1}

# Which mode the scanner runs in, and the code the command takes for each.
BarcodeScannerMode = Literal["operating", "service"]
BARCODE_SCANNER_MODES: Dict[str, int] = {"operating": 0, "service": 1}

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
  """Acceleration ramp range, in multiples of the shared ramp unit."""
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
    """Raise the carrier-handling wheel to its safe Z.

    Every move along the tracks is preceded by this.
    """
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
      speed: how fast to travel, in steps per second. Left out of the command when not given, so
        the drive uses its own default.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Left out when not given.
      current_limit: the motor current limit. Left out when not given.

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

    parameters: Dict[str, str] = {"za": f"{increments:04}"}
    if speed is not None:
      low, high = c.z_drive_speed_increment_range
      if not low <= speed <= high:
        raise ValueError(f"speed must be between {low} and {high}, is {speed}")
      parameters["zv"] = f"{speed:04}"

    if acceleration_ramp is not None:
      low, high = c.z_drive_acceleration_ramp_range
      if not low <= acceleration_ramp <= high:
        raise ValueError(
          f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
        )
      parameters["zr"] = f"{acceleration_ramp:01}"

    if current_limit is not None:
      low, high = c.motor_current_limit_range
      if not low <= current_limit <= high:
        raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")
      parameters["zw"] = f"{current_limit:01}"

    # The parameters are the command's own, not this method's arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="ZA", **parameters)  # type: ignore[arg-type]

  async def move_to_z_position(
    self,
    position: ZPosition,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the carrier-handling wheel to one of the two positions it knows.

    Args:
      position: which one, as named in `Z_POSITIONS`.
      speed: how fast to travel, in steps per second. Left out of the command when not given, so
        the drive uses its own default.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Left out when not given.
      current_limit: the motor current limit. Left out when not given.

    Raises:
      ValueError: If the position is not one it knows, or an argument is outside what the drive
        accepts.
    """
    c = self.configuration
    if position not in Z_POSITIONS:
      raise ValueError(f"position must be one of {sorted(Z_POSITIONS)}, is {position!r}")

    parameters: Dict[str, str] = {"zp": f"{Z_POSITIONS[position]:01}"}
    if speed is not None:
      low, high = c.z_drive_speed_increment_range
      if not low <= speed <= high:
        raise ValueError(f"speed must be between {low} and {high}, is {speed}")
      parameters["zv"] = f"{speed:04}"

    if acceleration_ramp is not None:
      low, high = c.z_drive_acceleration_ramp_range
      if not low <= acceleration_ramp <= high:
        raise ValueError(
          f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
        )
      parameters["zr"] = f"{acceleration_ramp:01}"

    if current_limit is not None:
      low, high = c.motor_current_limit_range
      if not low <= current_limit <= high:
        raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")
      parameters["zw"] = f"{current_limit:01}"

    # The parameters are the command's own, not this method's arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="ZP", **parameters)  # type: ignore[arg-type]

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
      speed: how fast to travel, in steps per second. Left out of the command when not given, so
        the drive uses its own default.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Left out when not given.
      current_limit: the motor current limit. Left out when not given.

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

    parameters: Dict[str, str] = {"ya": f"{increments:04}"}
    if speed is not None:
      low, high = c.y_drive_speed_increment_range
      if not low <= speed <= high:
        raise ValueError(f"speed must be between {low} and {high}, is {speed}")
      parameters["yv"] = f"{speed:04}"

    if acceleration_ramp is not None:
      low, high = c.y_drive_acceleration_ramp_range
      if not low <= acceleration_ramp <= high:
        raise ValueError(
          f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
        )
      parameters["yr"] = f"{acceleration_ramp:01}"

    if current_limit is not None:
      low, high = c.motor_current_limit_range
      if not low <= current_limit <= high:
        raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")
      parameters["yw"] = f"{current_limit:01}"

    # The parameters are the command's own, not this method's arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="YA", **parameters)  # type: ignore[arg-type]

  async def move_to_y_position(
    self,
    position: YPosition,
    speed: Optional[int] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ):
    """Move the carrier drive to one of the three positions it knows.

    Args:
      position: which one, as named in `Y_POSITIONS`.
      speed: how fast to travel, in steps per second. Left out of the command when not given, so
        the drive uses its own default.
      acceleration_ramp: how hard to accelerate, in multiples of
        `configuration.acceleration_ramp_increments_per_second_squared`. Left out when not given.
      current_limit: the motor current limit. Left out when not given.

    Raises:
      ValueError: If the position is not one it knows, or an argument is outside what the drive
        accepts.
    """
    c = self.configuration
    if position not in Y_POSITIONS:
      raise ValueError(f"position must be one of {sorted(Y_POSITIONS)}, is {position!r}")

    parameters: Dict[str, str] = {"yp": f"{Y_POSITIONS[position]:01}"}
    if speed is not None:
      low, high = c.y_drive_speed_increment_range
      if not low <= speed <= high:
        raise ValueError(f"speed must be between {low} and {high}, is {speed}")
      parameters["yv"] = f"{speed:04}"

    if acceleration_ramp is not None:
      low, high = c.y_drive_acceleration_ramp_range
      if not low <= acceleration_ramp <= high:
        raise ValueError(
          f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
        )
      parameters["yr"] = f"{acceleration_ramp:01}"

    if current_limit is not None:
      low, high = c.motor_current_limit_range
      if not low <= current_limit <= high:
        raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")
      parameters["yw"] = f"{current_limit:01}"

    # The parameters are the command's own, not this method's arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="YP", **parameters)  # type: ignore[arg-type]

  # -- scanner rotation drive ----------------------------------------------------------------

  async def request_scanner_rotation(self) -> ScannerRotation:
    """Request which way the scanner faces.

    Returns:
      Its position, as named in `SCANNER_ROTATIONS`, which is `undefined` when it sits at neither
      of the two stops.
    """
    resp = await self._driver.send_command(module="I0", command="RS", fmt="rs#")
    return SCANNER_ROTATIONS[cast(int, resp["rs"])]

  async def move_scanner_rotation(
    self, position: ScannerRotation, stop_torque: Optional[bool] = None
  ):
    """Rotate the scanner to face one way or the other.

    Args:
      position: which way to face. Only the two stops can be moved to, so `undefined` is refused.
      stop_torque: whether to hold the drive there once it arrives. Left out of the command when
        not given, so the drive uses its own default.

    Raises:
      ValueError: If the position is not one that can be moved to.
    """
    if position not in ("vertical", "horizontal"):
      raise ValueError(f"position must be 'vertical' or 'horizontal', is {position!r}")

    parameters: Dict[str, str] = {"sp": "0" if position == "vertical" else "1"}
    if stop_torque is not None:
      parameters["sh"] = f"{int(stop_torque):01}"

    # The parameters are the command's own, not this method's arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="SP", **parameters)  # type: ignore[arg-type]

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
      barcode_types: which types to read, as named in `BARCODE_TYPES`. Left out of the command when
        not given, so the scanner uses its own set.

    Raises:
      ValueError: If a type is not one it reads.
    """
    parameters: Dict[str, str] = {"ar": f"{int(enabled):01}"}
    if barcode_types is not None:
      unknown = [name for name in barcode_types if name not in BARCODE_TYPES]
      if unknown:
        raise ValueError(f"not barcode types the scanner reads: {unknown}")
      mask = sum(1 << BARCODE_TYPES[name] for name in barcode_types)
      parameters["bt"] = f"{mask:02X}"

    # The parameters are the command's own, not this method's arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="AR", **parameters)  # type: ignore[arg-type]

  async def set_barcode_scanner_mode(self, mode: BarcodeScannerMode):
    """Set which mode the barcode scanner runs in.

    Args:
      mode: which one, as named in `BARCODE_SCANNER_MODES`.

    Raises:
      ValueError: If the mode is not one it has.
    """
    if mode not in BARCODE_SCANNER_MODES:
      raise ValueError(f"mode must be one of {sorted(BARCODE_SCANNER_MODES)}, is {mode!r}")
    return await self._driver.send_command(
      module="I0", command="AX", ax=f"{BARCODE_SCANNER_MODES[mode]:01}"
    )

  async def reset_barcode_scanner(self):
    """Reset the barcode scanner."""
    return await self._driver.send_command(module="I0", command="AF")

  # -- carrier identification ------------------------------------------------------------------

  async def set_barcode_type(self, barcode_types: List[str]):
    """Set which barcode types the carrier identification reads.

    This is the master's own setting, kept apart from the one the scanner is switched on with.

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
    """Pull a carrier off the loading tray and read its barcode on the way in.

    One command does both: the carrier travels in past the scanner, which reads it as it passes.
    `unload_carrier_after_carrier_barcode_scanning` pushes it back out again.

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
    """Push the carrier that was just identified back out to the loading tray."""
    try:
      return await self._driver.send_command(module="C0", command="CA")
    except BaseException:
      await self.move_to_safe_z()
      raise

  async def take_carrier_out_to_autoload_belt(self, track: int):
    """Take a carrier already on the deck back out to the identification position.

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
    """Finish loading the carrier at the identification position, reading its containers on the way.

    Which barcode types are read is whatever `set_barcode_type` last set.

    Args:
      barcode_reading: whether to read the containers at all. When False the scanner stays where it
        is and nothing is read.
      barcode_reading_direction: which way the scanner faces while reading, as named in
        `BARCODE_READING_DIRECTIONS`.
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
    if barcode_reading_direction not in BARCODE_READING_DIRECTIONS:
      raise ValueError(
        f"barcode_reading_direction must be one of {sorted(BARCODE_READING_DIRECTIONS)}, is "
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
          bd=f"{BARCODE_READING_DIRECTIONS[direction]:01}",
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
    """Unload the carrier at a track, back out to the loading tray.

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

  # -- deck watching ---------------------------------------------------------------------------

  async def set_carrier_monitoring(self, should_monitor: bool):
    """Set whether the instrument watches for carriers being taken off the deck.

    Args:
      should_monitor: whether to watch.
    """
    return await self._driver.send_command(
      module="C0", command="CU", cu=f"{int(should_monitor):01}"
    )

  async def set_loading_indicators(self, lit: List[bool], blinking: List[bool]):
    """Set the loading tray's indicator lights, one per track.

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
    """Move the autoload along the deck to a track, retracting the wheel first.

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

    parameters: Dict[str, str] = {"xp": f"{track:02}"}
    if speed is not None:
      low, high = c.x_drive_speed_increment_range
      if not low <= speed <= high:
        raise ValueError(f"speed must be between {low} and {high}, is {speed}")
      parameters["xv"] = f"{speed:04}"

    if acceleration_ramp is not None:
      low, high = c.x_drive_acceleration_ramp_range
      if not low <= acceleration_ramp <= high:
        raise ValueError(
          f"acceleration_ramp must be between {low} and {high}, is {acceleration_ramp}"
        )
      parameters["xr"] = f"{acceleration_ramp:01}"

    if current_limit is not None:
      low, high = c.motor_current_limit_range
      if not low <= current_limit <= high:
        raise ValueError(f"current_limit must be between {low} and {high}, is {current_limit}")
      parameters["xw"] = f"{current_limit:01}"

    current_wheel_z = await self.request_z_position()
    if c.z_drive_safety_position is not None and current_wheel_z < c.z_drive_safety_position:
      logger.debug(
        "retracting the handling wheel to its safe Z %.3f mm before moving to track %d",
        c.z_drive_safety_position,
        track,
      )
      await self.move_to_safe_z()
    # The parameters are the command's own, not this method's arguments, hence the splat.
    return await self._driver.send_command(module="I0", command="XP", **parameters)  # type: ignore[arg-type]

  async def park(self):
    """Move the autoload out of the way, to the last track this machine has.

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
    """Sense which deck tracks hold a carrier.

    Nothing moves: the sensors along the back of the deck see all of it at once.

    Returns:
      The tracks that hold a carrier, counted from 1.

    Raises:
      ValueError: If the machine answered without a presence mask.
    """
    resp = cast(str, await self._driver.send_command(module="C0", command="RC"))
    return _tracks_from_presence_mask(self._presence_mask(resp, "ce"))

  async def request_carrier_on_loading_tray(self, track: int) -> bool:
    """Request whether one loading-tray track holds a carrier.

    This moves: the autoload travels to that track and reads the sensor on its front. Reading the
    whole tray in one pass is `sense_carrier_presence_on_loading_tray`.

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
    """Sense which loading-tray tracks hold a carrier.

    This moves: the autoload runs the length of the tray, reading the sensor on its front as it
    goes.

    Returns:
      The tracks that hold a carrier, counted from 1.

    Raises:
      ValueError: If the machine answered without a presence mask.
    """
    resp = cast(str, await self._driver.send_command(module="C0", command="CS"))
    return _tracks_from_presence_mask(self._presence_mask(resp, "cd"))
