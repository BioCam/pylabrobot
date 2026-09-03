"""The pipetting channels: the row of independently driven pipettes on an arm."""

import asyncio
import datetime
import logging
import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import parse_firmware_version_date
from pylabrobot.hamilton.star.driver.lock import _FirmwareLock
from pylabrobot.hamilton.star.resource_model import TipMountingShaft
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

if TYPE_CHECKING:
  from pylabrobot.hamilton.star.driver.features.x_arm import XArm
  from pylabrobot.hamilton.star.driver.master import STARDriver

logger = logging.getLogger(__name__)

ChannelType = Literal["ML_STAR", "ML_STAR_RPC"]
HeadType = Literal["ML_STAR", "ML_STAR_PLE", "ML_STAR_RPC"]
StopDiscType = Literal["core_i", "core_ii"]
PressureADC = Literal["Renesas_X9268", "Analog_Devices_AD5263"]


@dataclass
class PipetteConfiguration:
  """The hardware fitted to a single pipetting channel.

  Read off the channel itself. Every field is None until it has been read.
  """

  channel_type: Optional[ChannelType] = None
  head_type: Optional[HeadType] = None
  stop_disc_type: Optional[StopDiscType] = None
  pressure_adc: Optional[PressureADC] = None
  firmware_version: Optional[str] = None
  width: Optional[float] = None
  """How wide the pipette is, in mm. Two channels cannot sit closer than this in Y."""


@dataclass
class PipettesConfiguration:
  """Configuration for the pipetting channels, and for each channel in turn.

  The encoder resolutions convert between the units a command carries on the wire (increments)
  and the units the driver speaks (mm, uL). They are properties of the channel drives and are
  identical across a machine's channels, so they are held once, not per channel.

  `channels` holds what each individual channel carries. It is empty until setup has counted the
  channels; only the machine reports how many there are.
  """

  hardware_query_first_year: int = 2017
  """Firmware from 2016 or older does not carry the hardware query."""

  initialize_y_range: Tuple[float, float] = (217.5, 405.0)
  """The Y band the channels spread across during the initialization procedure, in mm."""

  initialize_begin_of_tip_deposit: float = 245.0
  """Where the procedure begins depositing whatever is mounted, in mm."""

  initialize_end_of_tip_deposit: float = 122.0
  """Where it ends, in mm."""

  initialize_z_position_at_end: float = 360.0
  """Where the channels are left along Z when it finishes, in mm."""

  initialize_tip_type: int = 4
  initialize_discarding_method: int = 0

  initialize_read_timeout: int = 120
  """How long to wait for the procedure, in seconds. The channels travel to the waste and eject
  there, so the reply is a long time coming."""

  x_reference_anchor: str = "c"
  """Along X every channel sits at the arm's own reference point: the master and the X-drive board
  report the same position, so a channel's X is the arm's."""
  y_reference_anchor: str = "c"
  z_reference_anchor: str = "b"

  y_drive_mm_per_increment: float = 0.046302083
  z_drive_mm_per_increment: float = 0.01072765

  z_increment_range: Tuple[int, int] = (9_320, 31_200)
  """The Z travel the drive counts in, in increments, lowest first. The floor is the deck
  surface, which is as low as a stop disk goes."""

  z_range: Optional[Tuple[float, float]] = None
  """The Z window the channels reach, in mm, lowest first. Defaults to `z_range_documented`, which
  a caller may override before setup; `probe_z_max` then replaces the ceiling with what this
  machine's channels reached."""
  dispensing_drive_mm_per_increment: float = 0.002734375
  dispensing_drive_uL_per_increment: float = 0.046876

  channel_size_z: float = 140.0
  """How tall to model a channel, in mm. Not read from anywhere: how far a channel extends is not
  something the machine reports."""

  channels: List[PipetteConfiguration] = field(default_factory=list)
  """One entry per channel, in channel order."""

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
    return round(increments * self.dispensing_drive_uL_per_increment, 1)

  def dispensing_drive_uL_to_increments(self, uL: float) -> int:
    """A dispensing-drive position in increments, from the volume to hold."""
    return round(uL / self.dispensing_drive_uL_per_increment)

  def dispensing_drive_increments_to_mm(self, increments: int) -> float:
    """A dispensing-drive position as how far the piston has travelled, from increments."""
    return round(increments * self.dispensing_drive_mm_per_increment, 3)

  def dispensing_drive_mm_to_increments(self, mm: float) -> int:
    """A dispensing-drive position in increments, from how far the piston should travel."""
    return round(mm / self.dispensing_drive_mm_per_increment)

  @property
  def z_range_documented(self) -> Tuple[float, float]:
    """The Z window `z_increment_range` describes, in mm, lowest first.

    What the drive counts, which is not what a given machine's channels reach: the ceiling is
    probed at setup and replaces this one. Pure: it reads nothing and changes nothing.
    """
    low, high = self.z_increment_range
    return (self.z_drive_increments_to_mm(low), self.z_drive_increments_to_mm(high))

  def __post_init__(self):
    if self.z_range is None:
      self.z_range = self.z_range_documented

  def check_channels_agree(self) -> None:
    """Warn if the channels are not all running the same firmware.

    The resolutions above are held once for every channel, so they are one board's. Channels are
    replaced individually, and a channel on different firmware may not convert the same way. A
    machine repaired piecemeal is the case this catches.
    """
    by_version: Dict[str, List[int]] = {}
    for channel, entry in enumerate(self.channels):
      if entry.firmware_version is not None:
        by_version.setdefault(entry.firmware_version, []).append(channel)
    if len(by_version) <= 1:
      return
    reported = "; ".join(
      f"{version} on channel{'s' if len(channels) > 1 else ''} "
      f"{', '.join(str(c) for c in channels)}"
      for version, channels in by_version.items()
    )
    logger.warning(
      "the pipetting channels are not all on the same firmware (%s). The conversion factors here "
      "are held once for every channel, so a channel on different firmware may convert "
      "differently, and the version recorded for the feature is channel %d's.",
      reported,
      next(iter(by_version.values()))[0],
    )

  def resolve_channels(self, num_channels: int) -> None:
    """Size `channels` against the machine, once it has said how many channels it has.

    A list supplied up front is left as it is. A caller can configure channels before the machine
    is known, and it is then checked, not overwritten.

    Args:
      num_channels: how many channels the machine reported.

    Raises:
      ValueError: If a supplied list does not have one entry per channel.
    """
    if not self.channels:
      self.channels.extend(PipetteConfiguration() for _ in range(num_channels))
    elif len(self.channels) != num_channels:
      raise ValueError(f"configuration has {len(self.channels)} channels, expected {num_channels}")


class Pipettes:
  """The pipetting channels.

  Reached as `driver.pipettes`. Individual channels are addressed as `P1`..`PG`. The commands
  that act on all of them at once go to the master, so this feature speaks to both.

  `configuration` holds what every channel shares, and one entry per channel in
  `configuration.channels`.
  """

  def __init__(self, driver: "STARDriver", configuration: Optional[PipettesConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the channels' device facts. Defaults to `PipettesConfiguration()`.
    """
    self._driver = driver
    # One resource per channel, in channel order, when the driver was given a deck. Setup puts them
    # on the arm; the reads keep them in step. Without a deck the list stays empty.
    self.resources: List[Resource] = []
    self.configuration = configuration or PipettesConfiguration()

  # -- addressing ------------------------------------------------------------

  @staticmethod
  def channel_id(channel: int) -> str:
    """The module a channel is addressed by. Channel 0 is the one at the back."""
    return "P" + "123456789ABCDEFG"[channel]

  @property
  def num_channels(self) -> int:
    """How many channels are fitted, as counted at setup."""
    return self._driver.num_channels

  # -- session / discovery ---------------------------------------------------

  async def request_firmware_version(self, channel: int) -> Tuple[str, datetime.date]:
    """Request one channel's firmware version and build date.

    Args:
      channel: which channel to ask, 0-indexed from the back.

    Returns:
      The version string and its build date, e.g. `("4.0S j 2022-03-16", date(2022, 3, 16))`.
    """
    resp = await self._driver.send_command(module=self.channel_id(channel), command="RF")
    return resp.split("rf")[-1], parse_firmware_version_date(resp)

  async def request_min_pipette_width(self, channel: int) -> float:
    """Request how wide a pipette is.

    This is what bounds how close two channels can sit in Y: they cannot overlap.

    Args:
      channel: which channel to ask, 0-indexed from the back.

    Returns:
      The width in mm.
    """
    resp = await self._driver.send_command(
      module=self.channel_id(channel), command="VY", fmt="yc### (n)"
    )
    increments = cast(List[int], resp["yc"])[1]
    return self.configuration.y_drive_increments_to_mm(increments)

  async def request_pipette_configuration(self, channel: int) -> PipetteConfiguration:
    """Request what hardware is fitted to a pipette.

    Firmware from 2016 or older does not carry it.

    Args:
      channel: which channel to ask, 0-indexed from the back.

    Returns:
      What the channel reports about itself. The fields it does not report - its firmware version
      and its width - are left None, since they are separate queries.

    Raises:
      ValueError: If the reply carries no hardware fields at all.
    """
    resp = await self._driver.send_command(module=self.channel_id(channel), command="VW")
    fields = resp.split("vw")[-1].strip().split()
    if not fields:
      raise ValueError(f"no hardware fields in the reply from channel {channel}: {resp!r}")

    def field_at(index: int) -> Optional[str]:
      # The reply carries between two and four fields depending on firmware. A field that is not
      # there falls back to its baseline value instead of failing: these are descriptive, and no
      # pipetting decision reads them.
      return fields[index] if index < len(fields) else None

    return PipetteConfiguration(
      channel_type="ML_STAR_RPC" if field_at(0) == "1" else "ML_STAR",
      head_type=(
        "ML_STAR_PLE" if field_at(1) == "1" else "ML_STAR_RPC" if field_at(1) == "2" else "ML_STAR"
      ),
      stop_disc_type="core_i" if field_at(2) in ("0", None) else "core_ii",
      pressure_adc="Analog_Devices_AD5263" if field_at(3) == "1" else "Renesas_X9268",
    )

  async def discover(self):
    """Read what each channel is and what it can do.

    Read-only, and asks every channel at once. Fills in `configuration.channels`.
    """
    self.configuration.resolve_channels(self.num_channels)
    await asyncio.gather(*(self._discover_channel(ch) for ch in range(self.num_channels)))
    self.configuration.check_channels_agree()

  async def _discover_channel(self, channel: int):
    version, build_date = await self.request_firmware_version(channel)
    # On older firmware the hardware fields simply stay unread, rather than the query failing.
    pipette = (
      await self.request_pipette_configuration(channel)
      if build_date.year >= self.configuration.hardware_query_first_year
      else PipetteConfiguration()
    )
    pipette.firmware_version = version
    pipette.width = await self.request_min_pipette_width(channel)
    self.configuration.channels[channel] = pipette

  # -- where the channels are ------------------------------------------------

  def update_location_by_reference_point(
    self, channel: int, y: Optional[float] = None, z: Optional[float] = None
  ) -> None:
    """Record where a channel is on the resource that models it.

    Y and Z only. A channel rides the arm, so its resource is a child of the arm's and follows it
    in X with nothing recording that. A resource is located by its left front bottom corner, and
    each axis differs from the reported position by the channel's reference point.

    The channel states that point, because it is not a corner of the box: the drives report the
    stop disk, the shaft a tip mounts on, which hangs below the body. A channel stating nothing
    falls back to its anchors, the same point when it carries no shaft.

    Both drives answer in the deck's frame, while a resource's location is measured from its
    parent, the arm. The arm's position is taken out before either is recorded. Does nothing when
    the driver was given no deck to model into.

    Args:
      channel: which channel, 0-indexed from the back.
      y: where it is now, in mm on the deck. Left as it was when None.
      z: where its stop disk is now, in mm on the deck. Left as it was when None.
    """
    deck = self._driver.deck
    if channel >= len(self.resources) or deck is None:
      return
    resource = self.resources[channel]
    if resource.location is None or resource.parent is None:
      return
    here, on_the_arm = resource.location, resource.parent.get_location_wrt(deck)
    anchor = getattr(resource, "reference_point", None)
    if anchor is None:
      anchor = resource.get_anchor(
        y=self.configuration.y_reference_anchor, z=self.configuration.z_reference_anchor
      )
    resource.location = Coordinate(
      here.x,
      here.y if y is None else y - on_the_arm.y - anchor.y,
      here.z if z is None else z - on_the_arm.z - anchor.z,
    )

  @staticmethod
  def add_tip_mounting_shaft(channel: Resource) -> None:
    """Hang a tip mounting shaft off the lower end of a channel, and measure the channel from it.

    The shaft hangs its own length below the channel's bottom, not inside it, so it reaches
    lowest and the channel body starts clear of it. This is the arrangement a 96-head has, where
    the shafts define the bottom of the assembly. It is centred on the channel, the axis a tip is
    collected on. A shaft already there is left alone, and repeated setups do not duplicate it.

    The shaft is the stop disk the Z drive reports, and so is also where the channel is measured
    from. That is the reference point this states and `update_location_by_reference_point` reads
    back.

    Args:
      channel: the channel resource to hang it from.
    """
    name = f"{channel.name}_tip_mounting_shaft"
    if any(child.name == name for child in channel.children):
      return
    shaft = TipMountingShaft(name=name, tip_pickup_mode="core")
    channel.assign_child_resource(
      shaft,
      location=Coordinate(
        (channel.get_absolute_size_x() - shaft.get_absolute_size_x()) / 2,
        (channel.get_absolute_size_y() - shaft.get_absolute_size_y()) / 2,
        -shaft.get_absolute_size_z(),
      ),
    )
    # Stated on a plain `Resource`, which does not declare the field: a channel is not yet the
    # `NChannelPipette` that would, and that carries its own reference point as a `Coordinate`.
    channel.reference_point = Coordinate(  # type: ignore[attr-defined]
      channel.get_absolute_size_x() / 2,
      channel.get_absolute_size_y() / 2,
      -shaft.get_absolute_size_z(),
    )

  # -- channel initialization ------------------------------------------------

  def default_initialize_y_positions(self) -> List[float]:
    """Where each channel sits in Y during initialization, in mm, back to front.

    The channels spread evenly across the band the procedure uses, clear of one another whatever
    the channel count.

    Returns:
      One position per channel, in mm, back to front.
    """
    front, back = self.configuration.initialize_y_range
    spacing = round((back - front) * 10) // (self.num_channels - 1)
    return [(round(back * 10) - channel * spacing) / 10 for channel in range(self.num_channels)]

  async def sense_tip_presence(self) -> List[bool]:
    """Sense tip presence on every channel, from their sleeve sensors.

    Returns:
      One value per channel, True where a tip is mounted.
    """
    resp = await self._driver.send_command(module="C0", command="RT", fmt="rt# (n)")
    return [bool(v) for v in cast(List[int], resp.get("rt"))]

  async def initialize(
    self,
    x_position: Optional[float] = None,
    y_positions: Optional[List[float]] = None,
    begin_of_tip_deposit_process: Optional[float] = None,
    end_of_tip_deposit_process: Optional[float] = None,
    z_position_at_end_of_a_command: Optional[float] = None,
    tip_pattern: Optional[List[bool]] = None,
    tip_type: Optional[int] = None,
    discarding_method: Optional[int] = None,
  ):
    """Initialize the channels, discarding whatever is mounted on them.

    This moves the channels: they spread out across the Y band, travel to the tip waste, and
    eject. Anything on a channel, including a gripper, ends up in the waste.

    Args:
      x_position: X to eject at, in mm. Defaults to the instrument's tip waste position.
      y_positions: where to put each channel in Y, in mm, back to front. Defaults to spreading
        them evenly across the Y band the procedure uses.
      begin_of_tip_deposit_process: Z to start the eject from, in mm.
      end_of_tip_deposit_process: Z the eject ends at, in mm.
      z_position_at_end_of_a_command: Z to leave the channels at, in mm.
      tip_pattern: which channels take part. Defaults to all of them.
      tip_type: tip type table index.
      discarding_method: how tips are discarded.
    """
    c = self.configuration
    if x_position is None:
      if self._driver.configuration is None:
        raise RuntimeError("no configuration read; have you called `star.setup()`?")
      x_position = self._driver.configuration.tip_waste_x_position
    if y_positions is None:
      y_positions = self.default_initialize_y_positions()
    if tip_pattern is None:
      tip_pattern = [True] * self.num_channels
    if begin_of_tip_deposit_process is None:
      begin_of_tip_deposit_process = c.initialize_begin_of_tip_deposit
    if end_of_tip_deposit_process is None:
      end_of_tip_deposit_process = c.initialize_end_of_tip_deposit
    if z_position_at_end_of_a_command is None:
      z_position_at_end_of_a_command = c.initialize_z_position_at_end
    if tip_type is None:
      tip_type = c.initialize_tip_type
    if discarding_method is None:
      discarding_method = c.initialize_discarding_method

    return await self._driver.send_command(
      module="C0",
      command="DI",
      subsystem=_FirmwareLock.CHANNELS,
      read_timeout=c.initialize_read_timeout,
      xp=[f"{round(x_position * 10):05}"],
      yp=[f"{round(y * 10):04}" for y in y_positions],
      tp=f"{round(begin_of_tip_deposit_process * 10):04}",
      tz=f"{round(end_of_tip_deposit_process * 10):04}",
      te=f"{round(z_position_at_end_of_a_command * 10):04}",
      tm=[f"{tm:01}" for tm in tip_pattern],
      tt=f"{tip_type:02}",
      ti=discarding_method,
    )

  def _min_spacing_between(self, i: int, j: int) -> float:
    """The smallest Y gap two channels may sit at, in mm.

    Adjacent channels take the wider of the two, rounded up to 0.1 mm, since neither may overlap
    the other. Channels further apart take the sum of the pairs between them.

    Args:
      i: one channel, 0-indexed from the back.
      j: the other.

    Returns:
      The gap in mm.

    Raises:
      RuntimeError: If a channel's width has not been read yet.
    """
    lo, hi = min(i, j), max(i, j)
    if hi - lo > 1:
      return sum(self._min_spacing_between(k, k + 1) for k in range(lo, hi))
    widths = [self.configuration.channels[channel].width for channel in (lo, hi)]
    if any(width is None for width in widths):
      raise RuntimeError(f"channels {lo} and {hi} have no width read yet; run discovery first")
    return math.ceil(max(cast(List[float], widths)) * 10) / 10

  # ----------------------------------------
  # Movement
  # ----------------------------------------

  # -- x position --------------------------------------------------------------------------------

  @property
  def arm(self) -> "XArm":
    """The arm carrying these channels.

    The firmware keeps the two X-drives' feature bits disjoint: channels are on one arm or the
    other, never both. Discovery builds this feature on that arm; this finds it back by
    identity.

    Returns:
      The arm.
    """
    return next(a for a in self._driver.arms if a.pipettes is self)

  def _check_reachable(self, axis: Literal["x", "y", "z"], value: float) -> None:
    """Raise if the channels cannot be sent where they are being asked to go.

    The one gate every position passes through. What the channels are allowed to do is decided in
    one place: travel limits now, and whatever else has to hold before they move as it is added.

    X is the arm's travel as the arm reports it. A channel sits at the arm's reference point, with
    no offset to apply. Y is the band the machine states its channels reach, which differs by the
    side the arm is on.

    Args:
      axis: which axis - `x` along the rail, `y` across the arm.
      value: where it would be sent, in mm.

    Raises:
      ValueError: If the channels cannot reach it.
      RuntimeError: If the limits were not read, so how far they reach is unknown.
    """
    machine = self._driver.configuration
    if machine is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    if axis == "x":
      x_range = self.arm.configuration.x_range
      if x_range is None:
        raise RuntimeError("the arm's X travel is not known; have you called `star.setup()`?")
      low, high = x_range
    elif axis == "z":
      low, high = self.configuration.z_range or self.configuration.z_range_documented
    else:
      low = (
        machine.left_arm_min_y_position
        if self.arm.side == "left"
        else machine.right_arm_min_y_position
      )
      high = machine.pip_maximal_y_position
    if not low <= value <= high:
      raise ValueError(f"{axis} must be between {low} and {high} mm, is {value}")

  async def request_x_position(self) -> float:
    """Request where along X the channels are, in deck mm.

    The channels have no X drive. They ride the arm and sit at its reference point, and this asks
    the arm. Nothing is recorded: each channel's resource is a child of the arm's and follows it
    in X.

    Returns:
      The position in mm.
    """
    return await self.arm.request_position()

  async def move_to_x_position(
    self,
    x: float,
    acceleration_level: int = 3,
    current_limit: int = 7,
    settle_reads: int = 20,
  ):
    """Move the channels along X. The whole arm travels, with everything else it carries.

    Args:
      x: where to go, in mm.
      acceleration_level: how hard to accelerate, 1 to 4.
      current_limit: the motor current limit, 1 to 7.
      settle_reads: how many reads to take before calling the arm stopped.

    Raises:
      ValueError: If the channels cannot reach it.
    """
    self._check_reachable("x", x)
    return await self.arm.move_x(
      x,
      acceleration_level=acceleration_level,
      current_limit=current_limit,
      settle_reads=settle_reads,
    )

  # -- y position --------------------------------------------------------------------------------

  async def request_y_positions(self) -> List[float]:
    """Request where every channel is along Y, in one command.

    The master answers for all of them at once: one exchange, not one per channel. Each answer is
    recorded on the resource modelling that channel.

    Returns:
      The position of each channel in mm, back to front.
    """
    resp = await self._driver.send_command(module="C0", command="RY", fmt="ry#### (n)")
    positions = [increments / 10 for increments in cast(List[int], resp["ry"])]
    for channel, y in enumerate(positions):
      self.update_location_by_reference_point(channel, y=y)
    return positions

  async def request_y_position(self, channel: int) -> float:
    """Request where a specific channel is along Y.

    Args:
      channel: the channel to request the position of.

    Returns:
      The position of the requested channel in mm.
    """
    positions = await self.request_y_positions()
    return positions[channel]

  async def move_to_y_positions(self, ys: Dict[int, float], make_space: bool = False):
    """Move channels along Y.

    The channels not named stay where they are.

    TODO: park the iSWAP first when one is installed. Legacy does, skipping the move when its
    flag says it is already parked; v1 tracks no such state and has no query for it.

    Args:
      ys: where to put each named channel, in mm, keyed by channel, 0-indexed from the back.
      make_space: whether the channels not named may be moved, so that every pair meets its
        minimum Y spacing and the channels stay in order back to front. Off by default: nothing
        moves that the caller did not ask to move, and a request that will not fit raises instead.
        It can raise either way, since the requested positions may leave no room.
    """

    if self._driver.configuration is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    min_y = self._driver.configuration.left_arm_min_y_position

    # The frontmost channel parks a fraction ahead of the documented minimum. Tolerate 0.2 mm of
    # that and snap it up; refuse beyond, rather than guessing what the reading means.
    positions = await self.request_y_positions()
    if positions[-1] < min_y - 0.2:
      raise RuntimeError(
        f"the frontmost channel reports {positions[-1]}mm, more than 0.2mm in front of the "
        f"{min_y}mm the channels reach. Reported: {positions}"
      )
    positions[-1] = max(positions[-1], min_y)

    # Floating point error sometimes puts a reported pair a fraction below its minimum spacing,
    # which the check further down would then refuse. Walk front to back and conform each pair
    # against what it reported, as legacy does.
    for channel in range(len(positions) - 2, -1, -1):
      spacing = self._min_spacing_between(channel, channel + 1)
      if positions[channel] - positions[channel + 1] < spacing:
        positions[channel] = positions[channel + 1] + spacing

    # check that the locations of channels after the move will respect pairwise minimum
    # spacing and be in descending order
    channel_locations = dict(enumerate(positions))

    for channel_idx, y in ys.items():
      channel_locations[channel_idx] = y

    if make_space:
      # For the channels to the back of `back_channel`, make sure the space between them
      # meets the per-pair minimum. We start with the channel closest to `back_channel`, and
      # make sure the channel behind it is spaced correctly, updating if needed.
      use_channels = list(ys.keys())
      back_channel = min(use_channels)
      for channel_idx in range(back_channel, 0, -1):
        pair_spacing = self._min_spacing_between(channel_idx - 1, channel_idx)
        if (channel_locations[channel_idx - 1] - channel_locations[channel_idx]) < pair_spacing:
          channel_locations[channel_idx - 1] = channel_locations[channel_idx] + pair_spacing

      # Position intermediate channels between back_channel and front_channel.
      front_channel = max(use_channels)
      for intermediate_ch in range(back_channel + 1, front_channel):
        if intermediate_ch not in ys:
          pair_spacing = self._min_spacing_between(intermediate_ch - 1, intermediate_ch)
          channel_locations[intermediate_ch] = channel_locations[intermediate_ch - 1] - pair_spacing

      # Similarly for the channels to the front of `front_channel`, make sure they are all
      # spaced by the per-pair minimum. This time, we iterate from back (closest to
      # `front_channel`) to the frontmost channel.
      for channel_idx in range(front_channel, self.num_channels - 1):
        pair_spacing = self._min_spacing_between(channel_idx, channel_idx + 1)
        if (channel_locations[channel_idx] - channel_locations[channel_idx + 1]) < pair_spacing:
          channel_locations[channel_idx + 1] = channel_locations[channel_idx] - pair_spacing

    # Quick checks before movement. The channels stay in order, so the two ends bound the rest.
    for channel in (0, self.num_channels - 1):
      self._check_reachable("y", channel_locations[channel])

    for i in range(len(channel_locations) - 1):
      required = self._min_spacing_between(i, i + 1)
      actual = channel_locations[i] - channel_locations[i + 1]
      if round(actual * 1000) < round(required * 1000):  # compare in um to avoid float issues
        raise ValueError(
          f"Channels {i} and {i + 1} must be at least {required}mm apart, "
          f"but are {actual:.2f}mm apart."
        )

    yp = " ".join([f"{round(y * 10):04}" for y in channel_locations.values()])
    try:
      resp = await self._driver.send_command(
        module="C0", command="JY", subsystem=_FirmwareLock.CHANNELS, yp=yp
      )
    except BaseException:
      # A failed move leaves the channel Y positions unknown, so re-read them to refresh the
      # model. The read is wrapped: its own failure must not replace the move's exception.
      try:
        await self.request_y_positions()
      except BaseException:
        logger.warning("could not read where the channels stopped; their model is stale")
      raise

    for channel, y in channel_locations.items():
      self.update_location_by_reference_point(channel, y=y)
    return resp

  async def move_to_y_position(self, channel: int, y: float, make_space: bool = False):
    """Move one channel along Y.

    The other channels stay where they are, unless `make_space` says they may move to let this
    one through.

    Args:
      channel: which channel to move, 0-indexed from the back.
      y: where to put it, in mm.
      make_space: whether the other channels may be moved to make room. Off by default. See
        `move_to_y_positions`.

    Raises:
      ValueError: If the channel cannot reach it, or the others cannot make room.
    """
    return await self.move_to_y_positions({channel: y}, make_space=make_space)

  async def make_max_space_for_channel(self, channel: int):
    """Spread the channels to leave one of them as much free Y as the arm allows.

    What a caller reaches for before working a channel by hand, and the machine decides where the
    others go.

    TODO: park the iSWAP first when one is installed. Legacy does, skipping the move when its
    flag says it is already parked; v1 tracks no such state and has no query for it.

    Args:
      channel: which channel to free, 0-indexed from the back.

    Raises:
      ValueError: If the channel is not one this machine has.
    """
    if not 0 <= channel < self.num_channels:
      raise ValueError(f"channel must be between 0 and {self.num_channels - 1}, is {channel}")
    return await self._driver.send_command(
      module="C0",
      command="JP",
      subsystem=_FirmwareLock.CHANNELS,
      pn=f"{channel + 1:02}",  # the firmware counts channels from 1
    )

  # -- z position --------------------------------------------------------------------------------

  async def request_z_positions(self) -> Dict[int, float]:
    """Read where every channel is along Z.

    Returns:
      The position of each channel in mm, keyed by channel, 0-indexed from the back.
    """
    resp = await self._driver.send_command(module="C0", command="RZ", fmt="rz#### (n)")
    positions = {channel: increments / 10 for channel, increments in enumerate(resp["rz"])}
    for channel, z in positions.items():
      self.update_location_by_reference_point(channel, z=z)
    return positions

  async def request_z_position(self, channel: int) -> float:
    """Read where a channel is along Z.

    Args:
      channel: which channel to ask, 0-indexed from the back.

    Returns:
      The position of the channel in mm.
    """
    resp = await self.request_z_positions()
    return resp[channel]

  async def move_to_z_positions(self, zs: Dict[int, float]):
    """Move channels along Z.

    The channels not named stay where they are.

    Args:
      zs: where to put each named channel, in mm, keyed by channel, 0-indexed from the back.
    """
    for z in zs.values():
      self._check_reachable("z", z)

    channel_locations = await self.request_z_positions()

    for channel_idx, z in zs.items():
      channel_locations[channel_idx] = z

    return await self._driver.send_command(
      module="C0",
      command="JZ",
      subsystem=_FirmwareLock.CHANNELS,
      zp=[f"{round(z * 10):04}" for z in channel_locations.values()],
    )

  # -- z safety --------------------------------------------------------------

  async def move_to_z_position(self, channel: int, z: float):
    """Move one channel along Z.

    The other channels stay where they are.

    Args:
      channel: which channel to move, 0-indexed from the back.
      z: where to put it, in mm.
    """
    return await self.move_to_z_positions({channel: z})

  async def probe_z_max(self) -> float:
    """Find out how high the channels reach. Raises them to Z safety.

    Not something they report: no query carries the Z window, and the travel the drive counts can
    exceed what a given machine reaches. So the channels are sent to Z safety and read back, and
    what they report becomes the ceiling of `configuration.z_range`, whose floor is what the drive
    documents.

    One ceiling for every channel, since one window is what `_check_reachable` gates against. The
    channels have separate drives, so the lowest of what they reported is taken: a ceiling that
    holds for all of them is the one a shared check can use.

    Returns:
      The highest Z the channels reach, in mm.
    """
    positions = await self.move_to_safe_z()
    ceiling = min(positions)
    if max(positions) - ceiling > self.configuration.z_drive_increments_to_mm(1):
      logger.warning(
        "the channels came to rest at different heights (%s); the lowest is taken as the ceiling "
        "they all reach",
        positions,
      )
    c = self.configuration
    c.z_range = (c.z_range_documented[0], ceiling)
    return ceiling

  async def move_to_safe_z(self) -> List[float]:
    """Move every channel up to its safe Z, and read where that put them.

    Nothing may move in X or Y while a channel is low. This is the precondition for any lateral
    move. The instrument's initialization procedure does it as a side effect; on a machine that
    is already initialized it has to be asked for.

    Returns:
      Each channel's stop-disk Z, in mm, back to front.
    """
    await self._driver.send_command(module="C0", command="ZA", subsystem=_FirmwareLock.CHANNELS)
    return list((await self.request_z_positions()).values())
