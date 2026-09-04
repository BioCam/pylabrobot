"""A STAR that answers without being plugged in.

Each feature has a small subclass here that overrides the handful of methods which would
otherwise talk to a device, returning what one would have said. `STARSimulationDriver` swaps
those in, so everything above them - discovery, the initialization order, the configuration each
feature resolves - runs exactly as it does against hardware.

Nothing reaches the wire. `send_command` raises, which is how a command that has not been
simulated makes itself known: override the method that sends it, on the feature that owns it.
"""

import datetime
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import (
  assemble_channel_command,
  parse_firmware_version_date,
)
from pylabrobot.hamilton.star.driver.configuration import DeviceConfiguration
from pylabrobot.hamilton.star.driver.features.autoload import Autoload, AutoloadConfiguration
from pylabrobot.hamilton.star.driver.features.cover import (
  CoverPosition,
  FrontCover,
)
from pylabrobot.hamilton.star.driver.features.head import (
  HEAD_REFERENCE_SHAFT,
  Head,
  HeadConfiguration,
)
from pylabrobot.hamilton.star.driver.features.head96 import Head96, Head96Configuration
from pylabrobot.hamilton.star.driver.features.head384 import Head384, Head384Configuration
from pylabrobot.hamilton.star.driver.features.iswap import (
  ROTATION_DRIVE_SLOTS,
  WRIST_DRIVE_SLOTS,
  Y_SLOTS,
  iSWAP,
  iSWAPConfiguration,
)
from pylabrobot.hamilton.star.driver.features.pipettes import (
  PipetteConfiguration,
  Pipettes,
  PipettesConfiguration,
)
from pylabrobot.hamilton.star.driver.features.x_arm import XArm, XArmConfiguration
from pylabrobot.hamilton.star.driver.master import STARDriver
from pylabrobot.io.io import IOBase
from pylabrobot.io.validation_utils import LOG_LEVEL_IO
from pylabrobot.resources.hamilton.hamilton_decks import (
  HamiltonDeck,
)

logger = logging.getLogger(__name__)

# What each feature reports for its firmware. Read off a real device, so a simulated run
# resolves to a device that exists.
SIMULATED_FIRMWARE = {
  "master": "7.6S 25 2021_11_05 (GRU C0)",
  "pipettes": "4.0S j 2022-03-16",
  "x_arm": "1.4S 2012-04-25",
  "head96": "5.0S i 2021-10-22 (H0 XE167)",
  "iswap": "4.1S 2011-12-19",
  # No 384-head has been read, so this is marked as simulated rather than given a version that
  # would read as one taken off a device. The date is the specification's.
  "head384": "0.0S 2015-08-07 (D0 simulated)",
}

# Made up, so a simulator is never mistaken for a particular device.
SIMULATED_SERIAL_NUMBER = "SIM0"

# What stands where a transport's identity would be in the log, so simulated and recorded runs read
# the same way.
SIMULATED_LINK = "[simulation]"

# How wide a pipette is, in mm.
PIPETTE_WIDTH = 8.98

# Where the channels rest on a simulated device: the Y band the initialization procedure spreads
# them across, so a simulated device looks like one that has been set up rather than one with
# every channel on top of the next. Their Z-safety height comes from the configured Z window.

# Where a head parks along Y, and the nine further slots it stores beside that one. Read off a
# real 96-head; the 384-head documents the same two.
SIMULATED_HEAD_Y_PARK = 554.45
SIMULATED_HEAD_Y_PREDEFINED = 546.88

# Where its Z drive comes to rest when the firmware retracts it, in mm. Not a device fact but a
# probe result, so it stands apart from the configuration, as each drive's rest position does.
SIMULATED_HEAD96_Z_SAFETY = 336.97

# Where its Z drive rests after a retract. No unit has been probed, so this is the ceiling the drive
# documents rather than a measurement, as the 96-head's is.
SIMULATED_HEAD384_Z_SAFETY = 336.0


# Where its two undriven drives report themselves, in mm. Where they actually are is not modelled:
# each answers from its zero. X is not among them - it answers from the deck.
SIMULATED_AUTOLOAD_Y_POSITION = 0.0
SIMULATED_AUTOLOAD_Z_POSITION = 0.0

# What it says about its own adjustment, and the track its X drive homes against.
SIMULATED_AUTOLOAD_ADJUSTMENT_DATE = datetime.date(2017, 1, 9)
SIMULATED_AUTOLOAD_INIT_TRACK = 1

# The two diagnostic reads that exist to show what a real unit holds. A simulated one holds nothing,
# and says so rather than inventing a block for a caller to read meaning into.
SIMULATED_AUTOLOAD_ADJUSTMENT_VALUES = "[simulation] no adjustment values"
SIMULATED_AUTOLOAD_PARAMETER_VALUE = "[simulation]"

# Whether the front cover is shut. A simulated device is not being reached into.
SIMULATED_COVER_POSITION: CoverPosition = "closed"

# The three inputs on the cover connector: the cover input, and two whose meaning is not known.
SIMULATED_COVER_INPUTS = (True, False, False)

# What its scanner reads. A simulated deck holds no carriers, so nothing.
SIMULATED_BARCODE: Optional[str] = None

# Where the iSWAP's rotation drive has come to rest when a simulated device is switched on, in
# mm: at the top of its travel, where an initialized device leaves it.
SIMULATED_ISWAP_Z = 299.0

# The iSWAP's stored position tables, and where its rotation drive sits relative to the carriage.

# Where the iSWAP's rotation drive rests along Y when a simulated device is switched on, in mm:
# at its parking stop.
SIMULATED_ISWAP_Y = 627.4

# How far the simulated gripper's jaws stand open, in increments: fully.
SIMULATED_ISWAP_GRIPPER_WIDTH = 24_120

# An arm that carries nothing: the geometry of a STAR arm with none of its feature bits set.
# The firmware requires the two drives' bits to be disjoint, so a device with two arms has its
# features on one of them and an arm like this as the other.
BARE_X_ARM = XArmConfiguration(
  width=354.0,
  x_range=(95.0, 1340.2),
  workspace_range=(-323.2, 1517.2),
  wrap_size=595.2,
)

# Where the recordings this package ships live. `STARDriver.save_configuration` writes one, so
# recording another device is saving a file rather than editing code.
_RECORDINGS = os.path.join(os.path.dirname(__file__), "recordings")

# What each frame is taken to be when a simulated device is asked for one and nothing was declared.
# Only ever handed to a simulated device: a physical one is whatever it answers, and a declaration
# is cross-checked against it rather than standing in for it.
RECORDING_STAR = os.path.join(_RECORDINGS, "star_legacy_2021_8ch_head96_autoload1D.json")
RECORDING_STARLET = os.path.join(_RECORDINGS, "starlet_legacy_2021_8ch_head96_autoload1D.json")
RECORDING_STARPLUS = os.path.join(_RECORDINGS, "starplus_legacy_2021_8ch_head96.json")
# The 384-head a device configured for one has. Not in the recording above, because that device
# has none and no 384-head has been read off any: the offset and the drive defaults here are the
# ones the drives document. Replace this with a recording when there is one to take.
SIMULATED_HEAD384 = Head384Configuration(
  firmware_version=SIMULATED_FIRMWARE["head384"],
  firmware_date=parse_firmware_version_date(SIMULATED_FIRMWARE["head384"]),
  head_type="High volume head",
  x_offset=260.0,
  supports_clot_monitoring_clld=False,
  supports_lld_absolute_threshold_check=False,
)


class _UnusedTransport(IOBase):
  """Stands where the transport would be. Nothing should reach it."""

  async def setup(self, *args, **kwargs):
    pass

  async def stop(self):
    pass

  async def write(self, data: bytes, *args, **kwargs):
    raise RuntimeError(f"the simulator tried to write to a transport: {data!r}")

  async def read(self, *args, **kwargs) -> bytes:
    raise RuntimeError("the simulator tried to read from a transport")


class _Simulated:
  """Reaches the device behind a feature, which for a simulated one is the simulator."""

  _driver: STARDriver

  @property
  def device(self) -> "STARSimulationDriver":
    return cast("STARSimulationDriver", self._driver)


class SimulatedPipettes(_Simulated, Pipettes):
  """The pipetting channels, answering for themselves."""

  def __init__(self, driver: STARDriver, configuration: Optional[PipettesConfiguration] = None):
    """
    Args:
      driver: the driver to send commands through.
      configuration: the channels' device facts.
    """
    super().__init__(driver, configuration)
    # Where each channel's Z drive is held to be. Per device, not per class: two simulated devices
    # do not share where their channels are. Filled on first use, from the configured window.
    self._simulated_z: Dict[int, float] = {}

  async def sense_tip_presence(self) -> List[int]:
    return [int(mounted) for mounted in self.device.tips_mounted]

  async def request_firmware_version(self, channel: int) -> Tuple[str, datetime.date]:
    return self.device.reported("pipettes")

  def _declared_channel(self, channel: int) -> PipetteConfiguration:
    """What this device was told sits on a channel, or the channel this frame documents.

    Args:
      channel: which channel, 0-indexed from the back.

    Returns:
      The channel to answer from.
    """
    declared = self.device.simulated_pipettes
    if declared is not None and channel < len(declared.channels):
      return declared.channels[channel]
    return PipetteConfiguration()

  async def request_min_pipette_width(self, channel: int) -> float:
    width = self._declared_channel(channel).width
    return PIPETTE_WIDTH if width is None else width

  async def request_pipette_configuration(self, channel: int) -> PipetteConfiguration:
    # Only what the read reports: the rest of a channel's configuration is filled by discovery
    # from other reads, as it is on a device.
    channel_configuration = self._declared_channel(channel)
    return PipetteConfiguration(
      channel_type=channel_configuration.channel_type,
      head_type=channel_configuration.head_type,
      stop_disc_type=channel_configuration.stop_disc_type,
      pressure_adc=channel_configuration.pressure_adc,
    )

  async def initialize(self, *args, **kwargs):
    """Whatever was mounted on the channels comes off. Goes through the command path, so it is
    coordinated like the real one."""
    await super().initialize(*args, **kwargs)
    self.device.tips_mounted = [False] * len(self.device.tips_mounted)

  async def request_y_positions(self) -> List[float]:
    # Where initialization spread them, which is where a device that has been set up leaves
    # them and nothing here has since moved them. Answered from the procedure rather than from the
    # resources, so the model can be checked against this rather than derived from it.
    positions = self.default_initialize_y_positions()
    for channel, y in enumerate(positions):
      self.update_location_by_reference_point(channel, y=y)
    return positions

  @property
  def _z(self) -> Dict[int, float]:
    """Where each channel's drive is held to be, in mm.

    A move writes it and a read finds it there, as the head's Z does. Started at the top of the
    window the configuration carries, which is where Z safety puts them.

    Returns:
      Each channel's Z, keyed by channel.
    """
    if not self._simulated_z:
      self._simulated_z = {
        channel: self.configuration.z_range[1] for channel in range(self.num_channels)
      }
    return self._simulated_z

  async def _unchecked_fw_request_lowest_z_positions(self) -> Dict[int, float]:
    # Recorded as the real read records it, so a simulated channel is modelled at the height it
    # reports rather than at whatever the arm's own is.
    positions = dict(self._z)
    for channel, z in positions.items():
      self.update_location_by_reference_point(channel, z=z)
    return positions

  async def request_stop_disc_z_position(self, channel: int) -> float:
    # The channel's own drive rather than the master's read. A simulated channel carries no tip
    # geometry, so the two answer the same height here; on a device they part company the moment
    # a tip goes on, which is the whole reason the two reads exist.
    self._require_channel(channel)
    z = self._z[channel]
    self.update_location_by_reference_point(channel, z=z)
    return z

  async def probe_z_max(self) -> float:
    # The retract inside the probe is what puts the channels at their top. On a device that is
    # physical travel; here the configured ceiling stands for it, so a configured window is what a
    # simulated probe reads back. `_SimulatedHead.probe_z_max` does the same for a head.
    self._z.update({channel: self.configuration.z_range[1] for channel in range(self.num_channels)})
    return await super().probe_z_max()

  async def _unchecked_fw_move_lowest_point_to_z_positions(self, zs: Dict[int, float]):
    # A move is what puts a channel somewhere. Written after the move, not before: one the real
    # method refuses never happened.
    resp = await super()._unchecked_fw_move_lowest_point_to_z_positions(zs)
    self._z.update(zs)
    return resp

  async def move_stop_disc_to_z_position(self, channel: int, z: float, *args: Any, **kwargs: Any):
    resp = await super().move_stop_disc_to_z_position(channel, z, *args, **kwargs)
    self._z[channel] = z
    return resp


# Where the left arm has come to rest when a simulated device is switched on, in mm: far enough
# along the rail to sit within reach of any STAR deck. The right arm rests at the far end of its
# own travel instead, so the two do not overlap on a device that has both. Setup reads this once
# to seat each arm on the deck; every read after that answers from the deck.
SIMULATED_LEFT_X_ARM_POSITION = 362.9


class SimulatedXArm(_Simulated, XArm):
  """An X-arm, answering for itself."""

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    return self.device.reported("x_arm")

  async def request_position(self) -> float:
    # Where the arm is is what the model says: a simulated device has no drive to ask. Until setup
    # has put it on the deck there is nothing to read, and it answers where it powered up.
    if self.resource is not None and self.resource.location is not None:
      anchor = self.resource.get_anchor(x=self.reference_anchor)
      return self.resource.location.x + anchor.x
    if self.side == "left" or self.configuration.x_range is None:
      return SIMULATED_LEFT_X_ARM_POSITION
    return self.configuration.x_range[1]


class _SimulatedHead(_Simulated, Head):
  """What a head answers when there is no head: the same for either of them.

  Each head says which simulated configuration it answers from and where a retract leaves it; what
  its configuration bytes mean is its own, as on a device.
  """

  _z_safety: float
  _firmware_key: str
  _label: str

  @property
  def _declared(self) -> HeadConfiguration:
    """The head this device was told it has.

    Distinct from `configuration`, which discovery fills from these answers exactly as it would
    off an device.
    """
    raise NotImplementedError("a simulated head says which configuration it answers from")

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    return self.device.reported(self._firmware_key)

  async def request_head_type(self) -> str:
    head_type = self._declared.head_type
    if head_type is None:
      raise RuntimeError(f"the simulated {self._label} has no type; set it on its configuration")
    return head_type

  async def request_x_offset(self) -> float:
    x_offset = self._declared.x_offset
    if x_offset is None:
      raise RuntimeError(
        f"the simulated {self._label} has no X offset; set it on its configuration"
      )
    return x_offset

  async def request_z_position(self) -> float:
    # From the model where there is one, as the real read reports the drive, and in the deck's
    # frame as it answers in. Before setup has put the head on the arm, it rests where a retract
    # would leave it.
    deck = self.device.deck
    if self.resource is not None and self.resource.location is not None and deck is not None:
      shaft = self.resource.get_item(HEAD_REFERENCE_SHAFT)
      return round(shaft.get_location_wrt(deck).z, 2)
    return self._z_safety

  async def probe_z_max(self, *args: Any, **kwargs: Any) -> float:
    # The firmware retract inside the probe is what puts the head at its safety height. Its own
    # `move_to_safe_z` needs no such override: it is an ordinary move, which this already records.
    self.update_location_by_reference_point(z=self._z_safety)
    return await super().probe_z_max(*args, **kwargs)

  async def move_to_y_position(self, y: float, *args: Any, **kwargs: Any):
    # A move is what puts the head somewhere. On the device the drive holds that and the read
    # reports it; here the model holds it, so the move writes it and the read finds it there.
    # Written after the move, not before: one the real method refuses never happened, and a model
    # updated first would put the head where it was told to go rather than where it is.
    resp = await super().move_to_y_position(y, *args, **kwargs)
    self.update_location_by_reference_point(y=y)
    return resp

  async def move_stop_disc_to_z_position(self, z: float, *args: Any, **kwargs: Any):
    resp = await super().move_stop_disc_to_z_position(z, *args, **kwargs)
    self.update_location_by_reference_point(z=z)
    return resp

  async def request_drive_parameter(self, parameter: str) -> float:
    # Guarded as the real read guards it: a name the head does not store is a caller's mistake, and
    # should say so here as it would there rather than raising a lookup error.
    self.require_drive_parameter(parameter)
    head = self._declared
    if parameter == "yv":
      default = head.y_drive_speed_default
    elif parameter == "yr":
      default = head.y_drive_acceleration_default
    elif parameter == "zv":
      default = head.z_drive_speed_default
    else:
      default = head.z_drive_acceleration_default
    if default is None:
      raise RuntimeError(
        f"the simulated {self._label} has no {parameter} default; set it on its config"
      )
    return default

  async def initialize(self, *args, **kwargs):
    """Whatever was mounted on the head comes off, and it reports itself up. Goes through the
    command path, so it is coordinated like the real one."""
    await super().initialize(*args, **kwargs)
    self.device.initialized[self.configuration.module] = True

  async def request_predefined_y_positions(self) -> List[float]:
    # As a head holds them: the park position first, then nine slots nothing here commands against.
    return [SIMULATED_HEAD_Y_PARK] + [SIMULATED_HEAD_Y_PREDEFINED] * 9

  async def request_y_position(self) -> float:
    # From the model where there is one, as the real read reports the drive. The drive answers in
    # the deck's frame, so the model is read in the deck's too - the resource hangs off the arm,
    # whose own position would otherwise come through. Before setup has put the head on the arm
    # there is nothing to read, and it answers from the middle of its travel.
    deck = self.device.deck
    if self.resource is not None and self.resource.location is not None and deck is not None:
      shaft = self.resource.get_item(HEAD_REFERENCE_SHAFT)
      return round(shaft.get_location_wrt(deck).y, 2)
    return SIMULATED_HEAD_Y_PARK


class SimulatedHead96(_SimulatedHead, Head96):
  """The 96-head, answering for itself."""

  _firmware_key = "head96"
  _label = "96-head"
  _z_safety = SIMULATED_HEAD96_Z_SAFETY

  @property
  def _declared(self) -> Head96Configuration:
    return self.device.simulated_head96

  async def request_hardware(self) -> List[str]:
    # Rendered from what this head is, rather than written out separately: discovery parses these
    # three back out of the reply, so a head configured differently answers differently.
    head = self._declared
    return [
      "1" if head.supports_clot_monitoring_clld else "0",
      "0" if head.stop_disc_type == "core_i" else "1",
      "0" if head.instrument_type == "legacy" else "1",
    ] + ["0"] * 7

  async def request_drive_parameter(self, parameter: str) -> float:
    # No register to read, so it answers with what this head's firmware documents.
    head = self._declared
    if parameter == "dv":
      return head.dispensing_drive_speed_default
    if parameter == "dr":
      return head.dispensing_drive_acceleration_default
    if parameter == "sv":
      return head.squeezer_drive_speed_default
    if parameter == "sr":
      return head.squeezer_drive_acceleration_default
    return await super().request_drive_parameter(parameter)


class SimulatedHead384(_SimulatedHead, Head384):
  """The 384-head, answering for itself."""

  _firmware_key = "head384"
  _label = "384-head"
  _z_safety = SIMULATED_HEAD384_Z_SAFETY

  @property
  def _declared(self) -> Head384Configuration:
    return self.device.simulated_head384

  async def request_hardware(self) -> List[str]:
    # Rendered as the 96-head's is, from the two flags this head reports.
    head = self._declared
    return [
      "1" if head.supports_clot_monitoring_clld else "0",
      "1" if head.supports_lld_absolute_threshold_check else "0",
    ] + ["0"] * 8


class SimulatedISWAP(_Simulated, iSWAP):
  """The iSWAP, answering for itself."""

  # Where its rotation drive is held to be, in mm. The move writes it and the read finds it there,
  # as the head's Z does.
  _z: float = SIMULATED_ISWAP_Z
  _y: float = SIMULATED_ISWAP_Y

  async def request_firmware_version(self) -> str:
    return self.device.simulated_firmware["iswap"]

  async def rotation_drive_request_z_position(self) -> float:
    return self._z

  # A simulated device is switched on with its iSWAP parked: the Y carriage and the rotation
  # drive at their parking stops, the wrist straight, the gripper open. Answered from the same
  # stored tables the reads would have converted, so the conversions still run.
  async def rotation_drive_request_y_position(self) -> float:
    return self._y

  async def rotation_drive_move_to_y_position(self, y: float, *args: Any, **kwargs: Any):
    resp = await super().rotation_drive_move_to_y_position(y, *args, **kwargs)
    self._y = y
    return resp

  async def request_rotation_drive_angle(self) -> float:
    stops = (await self._request_slots("pw"))[: len(ROTATION_DRIVE_SLOTS)]
    parked = dict(zip(ROTATION_DRIVE_SLOTS, stops))["parking"]
    return self.configuration.rotation_drive_increments_to_angle(parked)

  async def request_wrist_drive_angle(self) -> float:
    stops = (await self._request_slots("pt"))[: len(WRIST_DRIVE_SLOTS)]
    straight = dict(zip(WRIST_DRIVE_SLOTS, stops))["straight"]
    return self.configuration.wrist_increments_to_deg(straight)

  async def request_gripper_width(self) -> float:
    return self.configuration.gripper_increments_to_mm(SIMULATED_ISWAP_GRIPPER_WIDTH)

  async def rotation_drive_move_to_z_position(self, z: float, *args: Any, **kwargs: Any):
    resp = await super().rotation_drive_move_to_z_position(z, *args, **kwargs)
    self._z = z
    return resp

  @property
  def _declared(self) -> iSWAPConfiguration:
    """The iSWAP this device was told it has.

    Distinct from `configuration`, which discovery fills from these answers exactly as it would
    off an device.
    """
    return self.device.simulated_iswap

  async def request_rotation_drive_x_offset(self) -> float:
    offset = self._declared.rotation_drive_x_offset
    if offset is None:
      raise RuntimeError("the simulated iSWAP has no X offset; set it on its configuration")
    return offset

  async def _request_slots(self, table: str) -> List[int]:
    # Rendered from what this iSWAP is, rather than written out separately: discovery reads these
    # tables back into the stops and link lengths, so an iSWAP configured differently answers
    # differently. Each table carries its drive's stops, then that link's length in tenths.
    declared = self._declared
    if table == "py":
      stops, length = declared.rotation_drive_predefined_y_positions_increments, None
      names: Tuple[str, ...] = Y_SLOTS
    elif table == "pw":
      stops, length = declared.rotation_drive_predefined_increments, declared.link_1_length
      names = ROTATION_DRIVE_SLOTS
    else:
      stops, length = declared.wrist_drive_predefined_increments, declared.link_2_length
      names = WRIST_DRIVE_SLOTS
    if stops is None:
      raise RuntimeError(f"the simulated iSWAP has no {table} table; set it on its configuration")
    rendered = [stops[name] for name in names]
    return rendered if length is None else rendered + [round(length * 10)]

  async def initialize(self):
    """Goes through the command path, so it is coordinated like the real one."""
    await super().initialize()
    self.device.initialized["R0"] = True


class SimulatedFrontCover(_Simulated, FrontCover):
  """The front cover, answering for itself: it is shut."""

  async def request_position(self) -> CoverPosition:
    return SIMULATED_COVER_POSITION


class SimulatedAutoload(_Simulated, Autoload):
  """The autoload, answering for itself. Its deck and its loading tray are empty."""

  track = 1
  """Where it last moved to."""

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    version = self.device.simulated_autoload.firmware_version
    if version is None:
      raise RuntimeError(
        "the simulated autoload has no firmware version; set it on its configuration"
      )
    return version, parse_firmware_version_date(version)

  async def request_module_configuration(self) -> Tuple[float, bool]:
    # What this device's own autoload answered: the 0.1 mm scanner, indicators fitted.
    declared = self.device.simulated_autoload
    return declared.x_drive_mm_per_increment, True

  async def request_autoload_type(self) -> str:
    autoload_type = self.device.simulated_autoload.autoload_type
    if autoload_type is None:
      raise RuntimeError("the simulated autoload has no type; set it on its configuration")
    return autoload_type

  async def request_initialization_status(self) -> bool:
    return self.device.initialized["I0"]

  async def request_latest_barcode_read(self) -> Optional[str]:
    return SIMULATED_BARCODE

  async def request_adjustment_status(self) -> Tuple[datetime.date, bool]:
    """Answer that this autoload is adjusted, so its stored values are its own."""
    return SIMULATED_AUTOLOAD_ADJUSTMENT_DATE, True

  async def request_init_slot(self) -> int:
    """Answer the track the X drive homes against."""
    return SIMULATED_AUTOLOAD_INIT_TRACK

  async def request_adjustment_values(self) -> str:
    """Answer the adjustment block, which a simulated unit does not hold."""
    return SIMULATED_AUTOLOAD_ADJUSTMENT_VALUES

  async def request_parameter(self, parameter: str) -> str:
    """Answer a stored parameter by name.

    Args:
      parameter: the name to read.

    Returns:
      The reply, as the module would write it.
    """
    return f"I0RAid0000{parameter}{SIMULATED_AUTOLOAD_PARAMETER_VALUE}"

  async def request_track(self) -> int:
    return self.track

  async def move_x(
    self,
    x: float,
    speed: Optional[float] = None,
    acceleration_ramp: Optional[int] = None,
    current_limit: Optional[int] = None,
  ) -> Any:
    # A simulated drive goes exactly where it is told. The real one is read back afterwards, which
    # is what `Autoload` relies on, so the position has to be true here before that read happens or
    # the read returns the position the sled started at and it never moves.
    resp = await super().move_x(
      x, speed=speed, acceleration_ramp=acceleration_ramp, current_limit=current_limit
    )
    self.update_location_by_reference_point(x)
    return resp

  async def request_x_position(self) -> float:
    # Where the sled is is what the model says: a simulated device has no drive to ask. The model
    # is placed around the carrier-handling wheel, so the wheel stands that far right of its left
    # edge. Before setup has put the sled on the deck there is no model to read, and the track it
    # is on is what it has instead - which is how a park during initialization survives long enough
    # to reach the resource that gets created after it.
    if self.resource is not None and self.resource.location is not None:
      return self.resource.location.x + self.configuration.reference_point_from_sled_left_edge
    return cast(HamiltonDeck, self.device.deck).track_to_location(self.track).x

  async def wheel_request_y_position(self) -> float:
    return SIMULATED_AUTOLOAD_Y_POSITION

  async def wheel_request_z_position(self) -> float:
    return SIMULATED_AUTOLOAD_Z_POSITION

  async def sense_carrier_presence_on_deck(self) -> List[int]:
    return []

  async def sense_carrier_presence_on_loading_tray(self) -> List[int]:
    return []

  async def sense_carrier_presence_on_single_loading_tray_track(
    self, track: int, park_after: bool = True
  ) -> bool:
    return False

  async def load_carrier_from_tray_and_scan_carrier_barcode(
    self, track: int, *args, **kwargs
  ) -> Optional[str]:
    return SIMULATED_BARCODE

  async def load_carrier_from_autoload_belt(
    self, barcode_reading: bool = False, *args, **kwargs
  ) -> Dict[int, Optional[str]]:
    """The containers read nothing, and there are as many as were asked for."""
    if not barcode_reading:
      return {}
    containers = kwargs.get("containers_per_carrier", 5)
    return {position: SIMULATED_BARCODE for position in range(containers)}

  async def initialize(self, park_after: bool = True):
    await super().initialize(park_after=park_after)
    self.device.initialized["I0"] = True

  async def move_to_track(self, track: int, *args, **kwargs):
    # As `move_x` records where a position move put the sled, so this records where a track move
    # did. The deck is what knows where a track is.
    await super().move_to_track(track, *args, **kwargs)
    # A simulated device is built with a deck or refuses to be built at all, so there is one.
    deck = cast(HamiltonDeck, self.device.deck)
    self.update_location_by_reference_point(deck.track_to_location(track).x)
    self.track = track

  async def park(self):
    await super().park()
    self.track = self.track_range[-1]


class STARSimulationDriver(STARDriver):
  """A simulated STAR, driven exactly like the real one."""

  def __init__(
    self,
    tips_mounted: Optional[List[bool]] = None,
    firmware: Optional[Dict[str, str]] = None,
    deck: Optional[HamiltonDeck] = None,
    serial_number: str = SIMULATED_SERIAL_NUMBER,
    initialized: bool = False,
    left_side_panel_installed: bool = False,
    declared_configuration_json: Optional[str] = None,
  ):
    """
    Args:
      tips_mounted: one entry per channel, `True` where a tip sits on the channel. Defaults to no
        tips on any of them.
      firmware: what each feature reports, keyed as `confirmed_firmware_versions` keys it.
        Defaults to `SIMULATED_FIRMWARE`.
      deck: the deck to reflect this device into. Required: a simulated device has no firmware
        to ask, so the resource model is the only thing it can answer from.
      serial_number: what this device calls itself.
      initialized: whether the device and its modules report themselves already initialized. One
        that has just been switched on does not.
      left_side_panel_installed: whether this device has its left side panel on. Declared rather
        than discovered, as on a real one: the panel comes off in seconds.
      declared_configuration_json: path to a declared configuration, which this device then answers
        as. What the arguments above name takes precedence over it, and what neither names falls
        back to what this frame documents.

    Raises:
      ValueError: If no deck is given, or `tips_mounted` does not have one entry per channel.
    """
    if deck is None:
      raise ValueError("a simulated STAR answers from its resource model, so it needs a deck")
    super().__init__(
      io=_UnusedTransport(),
      deck=deck,
      left_side_panel_installed=left_side_panel_installed,
      declared_configuration_json=declared_configuration_json,
    )

    # What the declaration says this device carries, whichever arm carries it. A simulated device
    # stands in for one of each, so the same feature on two arms is refused rather than half-read.
    carried: Dict[str, Any] = {}
    for side, features in self.declared.get("arms", {}).items():
      for name, feature in features.items():
        if name in carried:
          raise ValueError(
            f"the declared configuration has a {name} on more than one arm; a simulated device "
            f"stands in for one of each, so it cannot answer as this one (seen again on {side})"
          )
        carried[name] = feature

    configuration = self.declared.get("device")
    if configuration is None:
      raise ValueError(
        "a simulated device has to be told what it is simulating: pass "
        "`declared_configuration_json`, naming a file that records one"
      )
    self.simulated_configuration: DeviceConfiguration = configuration

    self.simulated_firmware = firmware or dict(SIMULATED_FIRMWARE)
    self.simulated_autoload: AutoloadConfiguration = (
      self.declared.get("autoload") or AutoloadConfiguration()
    )
    self.simulated_head96: Head96Configuration = carried.get("head96") or Head96Configuration()
    self.simulated_head384: Head384Configuration = carried.get("head384") or SIMULATED_HEAD384
    self.simulated_pipettes: Optional[PipettesConfiguration] = carried.get("pipettes")
    self.simulated_iswap: iSWAPConfiguration = carried.get("iswap") or iSWAPConfiguration()
    self.serial_number = serial_number

    channels = self.simulated_configuration.num_pip_channels
    if tips_mounted is None:
      tips_mounted = [False] * channels
    if len(tips_mounted) != channels:
      raise ValueError(f"tips_mounted has {len(tips_mounted)} entries, expected {channels}")
    self.tips_mounted = list(tips_mounted)

    # What each module says when asked whether it is initialized, and where things are.
    self.initialized = {module: initialized for module in ("C0", "I0", "R0", "H0")}

    # The features this device has, each answering for itself. Discovery builds only the ones
    # that are not already there, so these stand in for the real ones throughout.
    c = self.simulated_configuration
    if c.main_front_cover_monitoring_installed:
      self.front_cover = SimulatedFrontCover(self)
    if c.left_arm is not None:
      self.left_x_arm = SimulatedXArm(self, side="left")
    if c.right_arm is not None:
      self.right_x_arm = SimulatedXArm(self, side="right")
    if c.autoload_installed:
      self.autoload = SimulatedAutoload(self)

    # On the arm whose bits claim them, as discovery would put them. Read off the simulated
    # configuration rather than the arm's own: nothing has been discovered yet at this point.
    for arm, a in ((self.left_x_arm, c.left_arm), (self.right_x_arm, c.right_arm)):
      if arm is None or a is None:
        continue
      if a.pip_installed and c.num_pip_channels > 0:
        arm.pipettes = SimulatedPipettes(self)
      if a.head96_installed:
        arm.head96 = SimulatedHead96(self)
      if a.head384_installed:
        arm.head384 = SimulatedHead384(self)
      if a.iswap_installed:
        arm.iswap = SimulatedISWAP(self)

  def reported(self, feature: str) -> Tuple[str, datetime.date]:
    """What a feature reports for its firmware, and the date in it."""
    version = self.simulated_firmware[feature]
    return version, parse_firmware_version_date(version)

  # -- the device itself ----------------------------------------------------

  async def _open(self):
    """There is no link to open, and no replies to read."""

  async def _close(self):
    pass

  async def request_device_configuration(self) -> DeviceConfiguration:
    return self.simulated_configuration

  async def request_cover_input_status(self) -> Tuple[bool, bool, bool]:
    return SIMULATED_COVER_INPUTS

  def _check_declared_against(self, discovered: DeviceConfiguration) -> None:
    """Nothing to cross-check: a simulated device answers from the declaration.

    On a physical device the declaration is a claim about what is on the other end, and discovery
    tests it. Here it is where the answers come from, so it cannot disagree with itself. A
    `configuration` given outright is the caller saying to simulate that instead, which is a
    substitution rather than a disagreement.

    Args:
      discovered: what this device answered, which is what it was told to answer.
    """

  async def request_device_serial_number(self) -> str:
    # What it was told it is, or what it was told to call itself when the recording did not say.
    declared = self.simulated_configuration.serial_number
    return declared if declared is not None else self.serial_number

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    declared = self.simulated_configuration.firmware_version
    if declared is None:
      return self.reported("master")
    return declared, parse_firmware_version_date(declared)

  async def request_initialization_status(self, module: str = "C0") -> bool:
    return self.initialized.get(module, False)

  async def _pre_initialize(self, read_timeout: int = 300):
    """Home every drive. The modules it de-initializes then need their own.

    Goes through the command path, so it is coordinated like the real one.

    Args:
      read_timeout: how long the real procedure would be given, in seconds. Nothing waits here.
    """
    await super()._pre_initialize(read_timeout=read_timeout)
    self.initialized["C0"] = True

  def _describe_link(self) -> str:
    return "simulation (no link)"

  async def _send(
    self,
    module: str,
    command: str,
    auto_id=True,
    tip_pattern: Optional[List[bool]] = None,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait=True,
    fmt: Optional[Any] = None,
    **kwargs: Any,
  ) -> None:
    """Say what would have been sent, and answer nothing.

    A command that only moves needs no more than this. One whose answer is read is overridden on
    the feature that reads it, so it never gets here.

    What it logs is what a real link logs: the assembled command as a write, and the answer as a
    read, so a simulated run reads like a recorded one.

    Replacing `_send` rather than `send_command` leaves the coordination in place, so a simulated
    run serializes what a real one serializes.
    """
    self._log_exchange(
      assemble_channel_command(
        module=module,
        command=command,
        id_=None,
        tip_pattern=tip_pattern,
        num_channels=self.num_channels,
        **kwargs,
      ),
      None,
    )
    return None

  async def send_raw_command(self, command: str, *args: Any, **kwargs: Any) -> None:
    self._log_exchange(command, None)
    return None

  def _log_exchange(self, written: str, read: Optional[str]) -> None:
    """Log a command, and its answer where there is one, as the transport logs a real exchange.

    Nothing answers in simulation unless a feature says so, so most commands log a write alone.
    """
    logger.log(LOG_LEVEL_IO, "%s write: %s", SIMULATED_LINK, written)
    if read is not None:
      logger.log(LOG_LEVEL_IO, "%s read: %s", SIMULATED_LINK, read)
